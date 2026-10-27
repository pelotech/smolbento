//! End-to-end tests that boot real smolvm VMs. Ignored by default; run with `just e2e`.
//! Machines are small (1 CPU, 1 GiB) so they fit GitHub's private-repo runners.
//! The network policy test needs internet (example.com), the secrets test needs httpbin.org, and
//! the clone and fork tests need the Alpine package mirror, and the fork test needs httpbin.org.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

struct E2e {
    dir: tempfile::TempDir,
    name: String,
}

impl E2e {
    fn new(test: &str) -> E2e {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("ws")).unwrap();
        let e = E2e {
            dir,
            name: format!("e2e-{}-{test}", std::process::id()),
        };
        e.ok(&["policy", "init", "allow-all"]);
        e
    }

    fn workspace(&self) -> PathBuf {
        self.dir.path().join("ws").canonicalize().unwrap()
    }

    fn machine(&self) -> String {
        format!("sbx-{}", self.name)
    }

    fn sbt(&self, args: &[&str]) -> Output {
        self.env(Command::new(env!("CARGO_BIN_EXE_smolbento")).args(args))
            .output()
            .unwrap()
    }

    fn env<'a>(&self, cmd: &'a mut Command) -> &'a mut Command {
        cmd.current_dir(self.workspace())
            .env("SMOLBENTO_CONFIG_DIR", self.dir.path().join("config"))
            .env("SMOLBENTO_CACHE_DIR", self.dir.path().join("cache"))
            .env("SMOLBENTO_DOCKER", "false")
    }

    /// Host git in the workspace. The `sandbox-<name>` remote runs `smolbento _upload-pack`, so
    /// `smolbento` (a symlink to this build) goes first on `PATH`, with the same environment as
    /// [`E2e::sbt`].
    fn git(&self, args: &[&str]) -> Output {
        let bin = self.dir.path().join("bin");
        if !bin.exists() {
            std::fs::create_dir_all(&bin).unwrap();
            std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_smolbento"), bin.join("smolbento"))
                .unwrap();
        }
        let path = std::env::join_paths(
            std::iter::once(bin).chain(std::env::split_paths(&std::env::var_os("PATH").unwrap())),
        )
        .unwrap();
        self.env(
            Command::new("git")
                .args(["-c", "user.name=e2e", "-c", "user.email=e2e@example.com"])
                .args(["-c", "commit.gpgsign=false"])
                .args(args),
        )
        .env("PATH", path)
        .output()
        .unwrap()
    }

    fn git_ok(&self, args: &[&str]) -> String {
        let out = self.git(args);
        assert!(
            out.status.success(),
            "git {args:?} failed:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    fn ok(&self, args: &[&str]) -> String {
        let out = self.sbt(args);
        assert!(
            out.status.success(),
            "sbt {args:?} failed:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    /// Alpine has no `agent` user or bash; add them as root, straight through smolvm. The user
    /// gets the host uid, as smolbento's identity step does for sbx images.
    fn create_alpine(&self) {
        let ws = self.workspace();
        self.ok(&[
            "create",
            "shell",
            ws.to_str().unwrap(),
            "--name",
            &self.name,
            "-t",
            "alpine",
            "--cpus",
            "1",
            "-m",
            "1g",
        ]);
        let setup = format!(
            "adduser -D -u {} agent && apk add -q bash",
            smolbento::sandbox::host_uid()
        );
        smolvm(&[
            "machine",
            "exec",
            "--name",
            &self.machine(),
            "-u",
            "root",
            "--",
            "sh",
            "-c",
            &setup,
        ]);
    }

    fn state(&self) -> String {
        let ls: serde_json::Value = serde_json::from_str(&self.ok(&["ls", "--json"])).unwrap();
        ls.as_array()
            .unwrap()
            .iter()
            .find(|s| s["name"] == self.name.as_str())
            .map(|s| s["status"].as_str().unwrap().to_string())
            .unwrap_or_else(|| "absent".into())
    }
}

impl Drop for E2e {
    fn drop(&mut self) {
        let _ = Command::new("smolvm")
            .args(["machine", "delete", "-n", &self.machine(), "-f"])
            .output();
    }
}

/// Whether `smolvm args` succeeds.
fn smolvm_ok(args: &[&str]) -> bool {
    Command::new("smolvm")
        .args(args)
        .output()
        .unwrap()
        .status
        .success()
}

fn smolvm(args: &[&str]) {
    let out = Command::new("smolvm").args(args).output().unwrap();
    assert!(
        out.status.success(),
        "smolvm {args:?}:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
#[ignore = "boots real VMs; run with `just e2e`"]
fn lifecycle_exec_and_same_path_mount() {
    let e = E2e::new("life");
    e.create_alpine();
    assert_eq!(e.state(), "running");

    std::fs::write(e.workspace().join("from-host"), "hello").unwrap();
    assert_eq!(e.ok(&["exec", &e.name, "cat", "from-host"]), "hello");
    e.ok(&["exec", &e.name, "sh", "-c", "echo back > from-guest"]);
    assert_eq!(
        std::fs::read_to_string(e.workspace().join("from-guest")).unwrap(),
        "back\n"
    );
    assert_eq!(e.ok(&["exec", &e.name, "id", "-un"]).trim(), "agent");
    assert_eq!(
        e.ok(&["exec", "--privileged", &e.name, "id", "-un"]).trim(),
        "root"
    );

    e.ok(&["stop", &e.name]);
    assert_eq!(e.state(), "stopped");
    e.ok(&["rm", "-f", &e.name]);
    assert_eq!(e.state(), "absent");
}

#[test]
#[ignore = "boots real VMs; run with `just e2e`"]
fn run_attaches_then_stops_when_the_last_session_ends() {
    let e = E2e::new("run");
    e.create_alpine();
    let out = e.ok(&["run", "--name", &e.name, "--", "-c", "echo hello-from-run"]);
    assert!(out.contains("hello-from-run"), "{out}");
    assert_eq!(e.state(), "stopped");
}

#[test]
#[ignore = "boots real VMs; run with `just e2e`"]
fn cp_round_trip() {
    let e = E2e::new("cp");
    e.create_alpine();
    let src = e.dir.path().join("src.txt");
    std::fs::write(&src, "copied").unwrap();
    e.ok(&[
        "cp",
        src.to_str().unwrap(),
        &format!("{}:/tmp/in.txt", e.name),
    ]);
    let back = e.dir.path().join("back.txt");
    e.ok(&[
        "cp",
        &format!("{}:/tmp/in.txt", e.name),
        back.to_str().unwrap(),
    ]);
    assert_eq!(std::fs::read_to_string(Path::new(&back)).unwrap(), "copied");
}

#[test]
#[ignore = "boots real VMs; run with `just e2e`"]
fn diagnose_passes() {
    let e = E2e::new("diag");
    let out = e.ok(&["diagnose"]);
    assert!(!out.contains("FAIL"), "{out}");
}

fn reachable(e: &E2e, url: &str) -> bool {
    e.sbt(&[
        "exec",
        &e.name,
        "wget",
        "-q",
        "-T",
        "8",
        "-O",
        "/dev/null",
        url,
    ])
    .status
    .success()
}

#[test]
#[ignore = "boots real VMs; run with `just e2e`"]
fn policy_changes_apply_on_start_and_live() {
    let e = E2e::new("pol");
    e.create_alpine();
    e.ok(&["policy", "init", "deny-all"]);
    e.ok(&["stop", &e.name]); // allow-all -> restricted applies on the next start
    assert!(!reachable(&e, "https://example.com"), "deny-all blocks");
    e.ok(&["policy", "allow", "network", "example.com"]);
    assert!(reachable(&e, "https://example.com"), "live allow");
    e.ok(&["policy", "rm", "network", "--resource", "example.com"]);
    assert!(
        !reachable(&e, "https://www.wikipedia.org"),
        "still restricted"
    );
    e.ok(&["policy", "init", "balanced"]);
    assert!(
        reachable(&e, "https://dl-cdn.alpinelinux.org/"),
        "balanced allows alpine"
    );
    assert!(
        !reachable(&e, "https://example.com"),
        "balanced blocks example.com"
    );
    let log = e.ok(&["policy", "log", &e.name]);
    assert!(log.contains("example.com"), "{log}");
}

#[test]
#[ignore = "boots real VMs; run with `just e2e`"]
fn ports_publish_live() {
    use std::io::{Read, Write};
    use std::time::{Duration, Instant};
    let e = E2e::new("port");
    e.create_alpine();
    smolvm(&[
        "machine",
        "exec",
        "--name",
        &e.machine(),
        "-d",
        "--",
        "sh",
        "-c",
        "while true; do printf 'HTTP/1.0 200 OK\\r\\n\\r\\nhi-from-guest\\n' | nc -l -p 8000; done",
    ]);
    let port = smolbento::sandbox::options::free_port().unwrap();
    e.ok(&["ports", &e.name, "--publish", &format!("{port}:8000")]);
    // The guest's nc may not be listening yet: retry until it answers or the deadline passes.
    let fetch = || -> std::io::Result<String> {
        let timeout = Some(Duration::from_secs(10));
        let mut stream = std::net::TcpStream::connect(("127.0.0.1", port))?;
        stream.set_read_timeout(timeout)?;
        stream.set_write_timeout(timeout)?;
        stream.write_all(b"GET / HTTP/1.0\r\n\r\n")?;
        let mut body = String::new();
        stream.read_to_string(&mut body)?;
        Ok(body)
    };
    let deadline = Instant::now() + Duration::from_secs(30);
    let body = loop {
        let last = fetch();
        if last.as_ref().is_ok_and(|b| b.contains("hi-from-guest")) || Instant::now() > deadline {
            break last;
        }
        std::thread::sleep(Duration::from_millis(500));
    };
    let body = body.expect("published port answers");
    assert!(body.contains("hi-from-guest"), "{body}");
    e.ok(&["ports", &e.name, "--unpublish", &format!("{port}:8000")]);
}

#[test]
#[ignore = "boots real VMs and needs httpbin.org; run with `just e2e`"]
fn secrets_are_placeholders_in_the_guest() {
    let e = E2e::new("sec");
    e.ok(&["policy", "init", "balanced"]);
    e.ok(&[
        "secret",
        "set-custom",
        "--host",
        "httpbin.org",
        "--env",
        "TOK",
        "--command",
        "printf real-secret-xyz",
    ]);
    e.create_alpine();
    let seen = e.ok(&["exec", &e.name, "sh", "-c", "printf %s \"$TOK\""]);
    assert!(seen.starts_with("SMOL_PLACEHOLDER_"), "{seen}");
    smolvm(&[
        "machine",
        "exec",
        "--name",
        &e.machine(),
        "-u",
        "root",
        "--",
        "apk",
        "add",
        "-q",
        "curl",
    ]);
    let echoed = e.ok(&[
        "exec",
        &e.name,
        "sh",
        "-c",
        "curl -s -m 20 -H \"Authorization: Bearer $TOK\" https://httpbin.org/headers",
    ]);
    assert!(echoed.contains("Bearer real-secret-xyz"), "{echoed}");
}

/// Runs `script` as root in the guest, straight through smolvm.
fn guest_root(e: &E2e, script: &str) {
    smolvm(&[
        "machine",
        "exec",
        "--name",
        &e.machine(),
        "-u",
        "root",
        "--",
        "sh",
        "-c",
        script,
    ]);
}

#[test]
#[ignore = "boots real VMs; run with `just e2e`"]
fn clone_round_trip() {
    let e = E2e::new("clone");
    let ws = e.workspace();
    let ws = ws.to_str().unwrap();
    let remote = format!("sandbox-{}", e.name);
    std::fs::write(e.workspace().join("README"), "host\n").unwrap();
    e.git_ok(&["init", "-q", "-b", "main"]);
    e.git_ok(&["add", "README"]);
    e.git_ok(&["commit", "-q", "-m", "host commit"]);
    e.git_ok(&[
        "remote",
        "add",
        "origin",
        "https://u:tok@example.com/o/r.git",
    ]);
    e.ok(&[
        "secret",
        "set-custom",
        "--host",
        "example.com",
        "--env",
        "TOK",
        "--command",
        "printf real-secret-xyz",
    ]);

    // Alpine has no `agent` user or git, so the first-start clone fails and stops the machine.
    let out = e.sbt(&[
        "create", "--clone", "shell", ws, "--name", &e.name, "-t", "alpine", "--cpus", "1", "-m",
        "1g",
    ]);
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "create without git in the image fails"
    );
    assert!(err.contains("cloning the repo in the sandbox"), "{err}");
    assert!(
        e.git_ok(&["remote"]).lines().any(|r| r == remote),
        "remote kept"
    );

    smolvm(&["machine", "start", "-n", &e.machine()]);
    guest_root(
        &e,
        &format!(
            "adduser -D -u {} agent && apk add -q git",
            smolbento::sandbox::host_uid()
        ),
    );
    smolvm(&["machine", "stop", "-n", &e.machine()]);
    e.ok(&["start", &e.name]);

    let url = e.ok(&[
        "exec", &e.name, "git", "-C", ws, "remote", "get-url", "origin",
    ]);
    assert_eq!(
        url.trim(),
        "https://example.com/o/r.git",
        "userinfo stripped"
    );
    let tok = e.ok(&["exec", &e.name, "sh", "-c", "printf %s \"$TOK\""]);
    assert!(tok.starts_with("SMOL_PLACEHOLDER_"), "{tok}");
    let guest_commit = |msg: &str| {
        e.ok(&[
            "exec",
            &e.name,
            "sh",
            "-c",
            &format!(
                "echo {msg} >> README && git -c user.name=a -c user.email=a@a \
                 -c commit.gpgsign=false commit -q -am {msg}"
            ),
        ]);
    };
    guest_commit("guest-one");
    e.ok(&["exec", &e.name, "git", "-C", ws, "tag", "v9.9.9"]);
    assert_eq!(
        std::fs::read_to_string(e.workspace().join("README")).unwrap(),
        "host\n",
        "the host checkout is untouched"
    );
    e.git_ok(&["fetch", "-q", &remote]);
    let log = e.git_ok(&["log", "--format=%s", &format!("{remote}/main")]);
    assert_eq!(log, "guest-one\nhost commit\n");
    assert_eq!(
        e.git_ok(&["tag", "-l"]),
        "",
        "the agent's tags stay in the sandbox"
    );

    let touch = e.sbt(&["exec", &e.name, "touch", "/run/sandbox/source/x"]);
    assert!(!touch.status.success(), "/run/sandbox/source is read-only");
    // Known, as in sbx: the host repo's config, credentials included, is readable in the sandbox.
    let config = e.ok(&["exec", &e.name, "cat", "/run/sandbox/source/config"]);
    assert!(config.contains("u:tok@example.com"), "{config}");

    // Fetching a stopped sandbox starts it, fetches and stops it again; the clone survives.
    guest_commit("guest-two");
    e.ok(&["stop", &e.name]);
    e.git_ok(&["fetch", "-q", &remote]);
    assert_eq!(e.state(), "stopped");
    let log = e.git_ok(&["log", "--format=%s", "-1", &format!("{remote}/main")]);
    assert_eq!(log, "guest-two\n");

    e.ok(&["rm", "-f", &e.name]);
    assert!(
        !e.git_ok(&["remote"]).lines().any(|r| r == remote),
        "rm removes the remote"
    );
}

/// Deletes fork machines the test made, before the parent's `E2e` drops (declare it after).
struct Forks(Vec<String>);

impl Drop for Forks {
    fn drop(&mut self) {
        for n in &self.0 {
            let _ = Command::new("smolvm")
                .args(["machine", "delete", "-n", &format!("sbx-{n}"), "-f"])
                .output();
        }
    }
}

#[test]
#[ignore = "boots real VMs and needs httpbin.org; run with `just e2e`"]
fn fork_round_trip() {
    let e = E2e::new("fork");
    let ws = e.workspace();
    let ws = ws.to_str().unwrap();
    std::fs::write(e.workspace().join("README"), "host\n").unwrap();
    e.git_ok(&["init", "-q", "-b", "main"]);
    e.git_ok(&["add", "README"]);
    e.git_ok(&["commit", "-q", "-m", "host commit"]);
    e.ok(&["policy", "init", "balanced"]);
    e.ok(&[
        "secret",
        "set-custom",
        "--host",
        "httpbin.org",
        "--env",
        "TOK",
        "--command",
        "printf real-secret-xyz",
    ]);

    // As in clone_round_trip: the first-start clone fails on Alpine until git and agent exist.
    let out = e.sbt(&[
        "create", "--clone", "shell", ws, "--name", &e.name, "-t", "alpine", "--cpus", "1", "-m",
        "1g",
    ]);
    assert!(
        !out.status.success(),
        "create without git in the image fails"
    );
    smolvm(&["machine", "start", "-n", &e.machine()]);
    guest_root(
        &e,
        &format!(
            "adduser -D -u {} agent && apk add -q git",
            smolbento::sandbox::host_uid()
        ),
    );
    smolvm(&["machine", "stop", "-n", &e.machine()]);
    e.ok(&["start", &e.name]);

    let guest_commit = |sb: &str, msg: &str| {
        e.ok(&[
            "exec",
            sb,
            "sh",
            "-c",
            &format!(
                "echo {msg} >> README && git -c user.name=a -c user.email=a@a \
                 -c commit.gpgsign=false commit -q -am {msg}"
            ),
        ]);
    };
    guest_root(&e, "echo before > /root/before");
    guest_commit(&e.name, "before-fork");

    // Guard the predicted names first: a partial failure still cleans up the copy it made.
    let forks = Forks(vec![
        format!("{}-fork-1", e.name),
        format!("{}-fork-2", e.name),
    ]);
    let names: Vec<String> = e
        .ok(&["fork", &e.name, "--count", "2"])
        .lines()
        .map(str::to_string)
        .collect();
    assert_eq!(names, forks.0);
    let (f1, f2) = (&forks.0[0], &forks.0[1]);

    let ls: serde_json::Value = serde_json::from_str(&e.ok(&["ls", "--json"])).unwrap();
    let row = |n: &str| {
        ls.as_array()
            .unwrap()
            .iter()
            .find(|r| r["name"] == n)
            .unwrap_or_else(|| panic!("{n} listed: {ls}"))
            .clone()
    };
    let (parent_row, f1_row) = (row(&e.name), row(f1));
    assert_eq!(f1_row["fork_of"], e.name.as_str());
    assert!(
        f1_row["created_at"].as_str() > parent_row["created_at"].as_str(),
        "a fork's created time is its own: {f1_row} vs {parent_row}"
    );

    let root_test = |sb: &str, path: &str| {
        smolvm_ok(&[
            "machine",
            "exec",
            "--name",
            &format!("sbx-{sb}"),
            "-u",
            "root",
            "--",
            "test",
            "-e",
            path,
        ])
    };
    for f in [f1, f2] {
        assert!(root_test(f, "/root/before"), "{f} sees the parent's files");
        let log = e.ok(&["exec", f, "git", "-C", ws, "log", "--format=%s", "-1"]);
        assert_eq!(log, "before-fork\n", "{f} has the parent's commit");
    }
    smolvm(&[
        "machine",
        "exec",
        "--name",
        &format!("sbx-{f1}"),
        "-u",
        "root",
        "--",
        "touch",
        "/root/only-1",
    ]);
    assert!(root_test(f1, "/root/only-1"));
    assert!(!root_test(f2, "/root/only-1"), "forks don't share writes");
    assert!(
        !root_test(&e.name, "/root/only-1"),
        "the parent doesn't see fork writes"
    );

    let echo_tok = |sb: &str| {
        e.ok(&[
            "exec",
            sb,
            "sh",
            "-c",
            "wget -q -T 20 -O - --header \"Authorization: Bearer $TOK\" \
             https://httpbin.org/headers",
        ])
    };
    let echoed = echo_tok(f1);
    assert!(echoed.contains("Bearer real-secret-xyz"), "{echoed}");
    e.ok(&["stop", f1]);
    e.ok(&["start", f1]);
    let echoed = echo_tok(f1);
    assert!(
        echoed.contains("Bearer real-secret-xyz"),
        "after restart: {echoed}"
    );

    guest_commit(f1, "in-fork-1");
    e.git_ok(&["fetch", "-q", &format!("sandbox-{f1}")]);
    let log = e.git_ok(&["log", "--format=%s", "-1", &format!("sandbox-{f1}/main")]);
    assert_eq!(log, "in-fork-1\n");
    let parent_remote = format!("sandbox-{}", e.name);
    e.git_ok(&["fetch", "-q", &parent_remote]);
    let log = e.git_ok(&["log", "--format=%s", &format!("{parent_remote}/main")]);
    assert_eq!(
        log, "before-fork\nhost commit\n",
        "the parent doesn't have the fork's commit"
    );

    let out = e.sbt(&["rm", "-f", &e.name]);
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "rm of a parent with forks fails");
    assert!(err.contains("remove its forks first"), "{err}");
    e.ok(&["rm", "-f", f1, f2]);
    e.ok(&["rm", "-f", &e.name]);
    let remotes = e.git_ok(&["remote"]);
    for n in [f1, f2, &e.name] {
        let remote = format!("sandbox-{n}");
        assert!(!remotes.lines().any(|r| r == remote), "{remote} removed");
    }

    // A sandbox with a writable host folder can't be forked: the copies would share it.
    let m = E2e::new("forkmnt");
    m.create_alpine();
    let out = m.sbt(&["fork", &m.name]);
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "fork of a host-mounted sandbox fails"
    );
    assert!(err.contains("--clone"), "{err}");
}

/// smolvm dials host loopback when a guest connects to its gateway; smolbento denies that. Only
/// bytes arriving prove reachability: smolvm's stack accepts every SYN, so `nc -z` can't tell.
#[test]
#[ignore = "boots real VMs; run with `just e2e`"]
fn host_loopback_is_unreachable() {
    use std::io::Read;
    use std::time::{Duration, Instant};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    let received = std::thread::spawn(move || {
        let mut got = Vec::new();
        // Until the guest's probe is done, then 2s more for bytes in flight.
        let mut until = None;
        while until.is_none_or(|t| Instant::now() < t) {
            if until.is_none() && rx.try_recv().is_ok() {
                until = Some(Instant::now() + Duration::from_secs(2));
            }
            if let Ok((mut stream, _)) = listener.accept() {
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let mut buf = [0u8; 64];
                if let Ok(n) = stream.read(&mut buf) {
                    got.extend_from_slice(&buf[..n]);
                }
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        got
    });
    let e = E2e::new("lo");
    e.create_alpine();
    let probe = format!(
        "gw=$(ip route | awk '/default/ {{print $3}}'); echo probe | nc -w 3 \"$gw\" {port}; true"
    );
    e.sbt(&["exec", &e.name, "sh", "-c", &probe]);
    tx.send(()).unwrap();
    let got = received.join().unwrap();
    assert!(
        got.is_empty(),
        "the host's 127.0.0.1:{port} got {:?} from the sandbox",
        String::from_utf8_lossy(&got)
    );
}
