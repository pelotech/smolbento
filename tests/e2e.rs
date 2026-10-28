//! End-to-end tests that boot real smolvm VMs. Ignored by default; run with `just e2e`.
//! Machines are small (1 CPU, 1 GiB) so they fit GitHub's private-repo runners.
//! The network policy test needs internet (example.com), the secrets test needs httpbin.org, and
//! the clone and fork tests need the Alpine package mirror, and the fork test needs httpbin.org.
//! The kit tests pull `alpine`, `registry:2`, the shell-docker template and BuildKit images from
//! Docker Hub, and the install-phase tests need example.com and httpbin.org. Published-kit
//! fixtures go to a `registry:2` machine on a loopback port, pushed with `oci-client`.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

struct E2e {
    dir: tempfile::TempDir,
    name: String,
    /// Extra environment for every `sbt` call (e.g. `SMOLBENTO_DOCKER=true` for one test).
    vars: Vec<(&'static str, String)>,
}

impl E2e {
    fn new(test: &str) -> E2e {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("ws")).unwrap();
        let e = E2e {
            dir,
            name: format!("e2e-{}-{test}", std::process::id()),
            vars: Vec::new(),
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
            .envs(self.vars.iter().map(|(k, v)| (k, v)))
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
    let ip = e.ok(&[
        "exec",
        &e.name,
        "sh",
        "-c",
        "nslookup example.com 2>/dev/null | awk '/^Address/ && $NF !~ /:/ {print $NF}' | head -n 1",
    ]);
    let ip = ip.trim();
    assert!(!ip.is_empty(), "example.com resolved");
    let by_ip = |e: &E2e| {
        let probe = format!("wget -S -T 8 -O /dev/null http://{ip}/ 2>&1 | grep -q 'HTTP/'");
        e.sbt(&["exec", &e.name, "sh", "-c", &probe])
            .status
            .success()
    };
    assert!(by_ip(&e), "live allow reaches {ip}");
    // The last host leaves a host-less list: closed live, by name and by its IP (no restart).
    e.ok(&["policy", "rm", "network", "--resource", "example.com"]);
    assert!(!reachable(&e, "https://example.com"), "live rm");
    assert!(!by_ip(&e), "live rm closes {ip} (example.com's address)");
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
/// Runs `script` as root in sandbox `sb`, with smolvm (not sbt) so it works before setup.
fn root_sh(sb: &str, script: &str) -> std::process::Output {
    let machine = format!("sbx-{sb}");
    let args = [
        "machine", "exec", "--name", &machine, "-u", "root", "--", "sh", "-c", script,
    ];
    Command::new("smolvm").args(args).output().unwrap()
}

/// `root_sh` that must succeed.
fn guest_root(sb: &str, script: &str) {
    let out = root_sh(sb, script);
    assert!(
        out.status.success(),
        "{script} in {sb}:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
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
        &e.name,
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
        &e.name,
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
    guest_root(&e.name, "echo before > /root/before");
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

    let root_test = |sb: &str, path: &str| root_sh(sb, &format!("test -e {path}")).status.success();
    for f in [f1, f2] {
        assert!(root_test(f, "/root/before"), "{f} sees the parent's files");
        let log = e.ok(&["exec", f, "git", "-C", ws, "log", "--format=%s", "-1"]);
        assert_eq!(log, "before-fork\n", "{f} has the parent's commit");
    }
    guest_root(f1, "touch /root/only-1");
    assert!(root_test(f1, "/root/only-1"));
    // Positive controls: the exec works in these machines, so a missing file means missing.
    assert!(root_test(f2, "/root/before"), "{f2} is reachable");
    assert!(!root_test(f2, "/root/only-1"), "forks don't share writes");
    assert!(
        root_test(&e.name, "/root/before"),
        "the parent is reachable"
    );
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

/// Polls `check` every second until it returns true or `secs` pass.
fn wait_until(secs: u64, mut check: impl FnMut() -> bool) -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(secs);
    loop {
        if check() {
            return true;
        }
        if std::time::Instant::now() > deadline {
            return false;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}

/// The guest's startup log (empty until the startup runner first writes it).
fn startup_log(e: &E2e) -> String {
    let out = root_sh(&e.name, "cat /var/log/sbx-kit-startup.log 2>/dev/null");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Number of dockerd processes in the guest.
fn dockerds(e: &E2e) -> usize {
    let out = e.sbt(&["exec", &e.name, "sh", "-c", "pgrep -x dockerd || true"]);
    String::from_utf8_lossy(&out.stdout).lines().count()
}

/// Docker-in-sandbox is the shipped `docker` kit: its background startup hook starts dockerd in
/// its own session, inside the blocking startup runner's exec, so dockerd must outlive that exec.
/// A `--kit` mixin's blocking startup hook waits for it: the shipped kit comes before the user's
/// kits and hooks run in kit order, so it sees the daemon the earlier background hook started, and
/// `create` and `start` return only once it's up.
#[test]
#[ignore = "boots real VMs and pulls the shell-docker image; run with `just e2e`"]
fn docker_kit_runs_dockerd_across_restarts() {
    let mut e = E2e::new("dock");
    e.vars.push(("SMOLBENTO_DOCKER", "true".into()));
    let kit = e.dir.path().join("e2e-wait-docker");
    std::fs::create_dir_all(&kit).unwrap();
    std::fs::write(
        kit.join("spec.yaml"),
        r#"schemaVersion: "2"
kind: mixin
name: e2e-wait-docker
setup:
  startup:
    - command:
        - sh
        - -c
        - "i=0; until docker info >/dev/null 2>&1; do i=$((i+1)); [ $i -lt 90 ] || exit 9; sleep 1; done"
      user: "0"
"#,
    )
    .unwrap();
    let ws = e.workspace();
    e.ok(&[
        "create",
        "shell",
        ws.to_str().unwrap(),
        "--name",
        &e.name,
        "--kit",
        kit.to_str().unwrap(),
        "--cpus",
        "1",
        "-m",
        "1g",
    ]);
    assert_eq!(e.state(), "running");
    assert!(
        root_sh(&e.name, "command -v setsid").status.success(),
        "the shipped image has setsid"
    );
    let docker_info = || {
        e.sbt(&["exec", "--privileged", &e.name, "docker", "info"])
            .status
            .success()
    };
    // No waiting: the blocking hook already saw dockerd, and the exec that ran it has ended.
    assert!(
        docker_info(),
        "docker info right after create:\n{}\n{}",
        startup_log(&e),
        String::from_utf8_lossy(&root_sh(&e.name, "cat /var/log/dockerd.log; ps -ef").stdout)
    );
    assert_one_dockerd(&e, "dockerd survives the startup runner's exec");
    assert!(docker_info(), "docker info from a later exec");

    e.ok(&["stop", &e.name]);
    e.ok(&["start", &e.name]);
    assert!(docker_info(), "docker info right after a restart");
    assert_one_dockerd(&e, "exactly one dockerd after a restart");
    let log = startup_log(&e);
    let count = |line: &str| log.lines().filter(|l| l.trim() == line).count();
    assert!(
        count("ok /etc/smolbento/startup.d/01-docker.sh hook 1") >= 2,
        "dockerd started on both starts:\n{log}"
    );
    assert!(
        log.lines()
            .filter(|l| l.starts_with("ok ") && l.ends_with("-e2e-wait-docker.sh hook 1"))
            .count()
            >= 2,
        "the blocking hook finished on both starts:\n{log}"
    );
    assert!(
        log.matches("=== dispatcher run ").count() >= 2,
        "one dispatcher run per start:\n{log}"
    );
}

/// Checks the sandbox runs exactly one dockerd, again and again for about 5 s: a second one
/// started late (a duplicate start) shows up.
fn assert_one_dockerd(e: &E2e, what: &str) {
    let until = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        assert_eq!(dockerds(e), 1, "{what}");
        if std::time::Instant::now() >= until {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
}

/// A throwaway `registry:2` in its own smolvm machine on a free loopback port, for published-kit
/// fixtures. Each test starts its own: nextest runs every test in a process of its own. `start`
/// also lets `e` load kits from any registry (`kit.allowedSources=["*"]`).
struct Registry {
    machine: String,
    port: u16,
}

impl Registry {
    fn start(e: &E2e) -> Registry {
        e.ok(&["settings", "set", "kit.allowedSources", r#"["*"]"#]);
        let r = Registry {
            machine: format!("e2e-{}-registry", std::process::id()),
            port: smolbento::sandbox::options::free_port().unwrap(),
        };
        let publish = format!("{}:5000", r.port);
        smolvm(&[
            "machine",
            "run",
            "-d",
            "-n",
            &r.machine,
            "--image",
            "registry:2",
            "--cpus",
            "1",
            "--mem",
            "512",
            "--net",
            "-p",
            &publish,
        ]);
        assert!(wait_until(60, || r.answers()), "the local registry answers");
        r
    }

    fn answers(&self) -> bool {
        use std::io::{Read, Write};
        let Ok(mut s) = std::net::TcpStream::connect(("127.0.0.1", self.port)) else {
            return false;
        };
        let _ = s.set_read_timeout(Some(std::time::Duration::from_secs(5)));
        let mut body = String::new();
        s.write_all(b"GET /v2/ HTTP/1.0\r\n\r\n").is_ok()
            && s.read_to_string(&mut body).is_ok()
            && body.starts_with("HTTP/1.")
            && body.contains(" 200 ")
    }

    /// `localhost:<port>/e2e/<repo>:1`.
    fn reference(&self, repo: &str) -> String {
        format!("localhost:{}/e2e/{repo}:1", self.port)
    }

    /// Pushes `image` as a kit: the descriptor goes in the manifest annotation, as `sbx kit push`
    /// publishes it.
    fn push(&self, repo: &str, image: Image, descriptor: serde_json::Value) -> String {
        use oci_client::client::{ClientConfig, ClientProtocol, Config, ImageLayer};
        use oci_client::manifest::OciImageManifest;
        use oci_client::secrets::RegistryAuth;
        let reference = self.reference(repo);
        let _ = rustls::crypto::ring::default_provider().install_default();
        let client = oci_client::Client::new(ClientConfig {
            protocol: ClientProtocol::Http,
            ..Default::default()
        });
        let layers: Vec<ImageLayer> = image
            .layers
            .into_iter()
            .map(|(data, media)| ImageLayer::new(data, media, None))
            .collect();
        let config = Config::oci_v1(serde_json::to_vec(&image.config).unwrap(), None);
        let annotations = std::collections::BTreeMap::from([
            (
                "vnd.docker.sandbox.kit.descriptor".to_string(),
                descriptor.to_string(),
            ),
            (
                "vnd.docker.sandbox.kit.schema-version".to_string(),
                "3".to_string(),
            ),
        ]);
        let manifest = OciImageManifest::build(&layers, &config, Some(annotations));
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(client.push(
            &reference.parse().unwrap(),
            &layers,
            config,
            &RegistryAuth::Anonymous,
            Some(manifest),
        ))
        .unwrap_or_else(|e| panic!("pushing {reference}: {e}"));
        reference
    }
}

impl Drop for Registry {
    fn drop(&mut self) {
        let _ = Command::new("smolvm")
            .args(["machine", "delete", "-f", "-n", &self.machine])
            .output();
    }
}

/// Layers (data, media type) and image config of a kit image to push.
struct Image {
    layers: Vec<(Vec<u8>, String)>,
    config: serde_json::Value,
}

fn arch() -> &'static str {
    if cfg!(target_arch = "aarch64") {
        "arm64"
    } else {
        "amd64"
    }
}

impl Image {
    /// No layers: a declaration-only mixin.
    fn empty() -> Image {
        Image {
            layers: Vec::new(),
            config: serde_json::json!({
                "architecture": arch(),
                "os": "linux",
                "rootfs": {"type": "layers", "diff_ids": []},
                "config": {},
            }),
        }
    }

    /// Alpine's layers and config, pulled from Docker Hub with smolbento's own client.
    fn alpine() -> Image {
        Image::pull("alpine")
    }

    /// `reference`'s layers and config, pulled from Docker Hub with smolbento's own client.
    fn pull(reference: &str) -> Image {
        let cache = tempfile::tempdir().unwrap();
        let dir = smolbento::kits::registry::pull_image(
            reference,
            cache.path(),
            smolbento::kits::registry_auth::Logins::none(),
        )
        .unwrap();
        let blob = |d: &serde_json::Value| {
            let hex = d.as_str().unwrap().trim_start_matches("sha256:");
            std::fs::read(dir.join("blobs/sha256").join(hex)).unwrap()
        };
        let index: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.join("index.json")).unwrap()).unwrap();
        let manifest: serde_json::Value =
            serde_json::from_slice(&blob(&index["manifests"][0]["digest"])).unwrap();
        let layers = manifest["layers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|l| {
                let media = match l["mediaType"].as_str().unwrap() {
                    "application/vnd.docker.image.rootfs.diff.tar.gzip" => {
                        "application/vnd.oci.image.layer.v1.tar+gzip"
                    }
                    m => m,
                };
                (blob(&l["digest"]), media.to_string())
            })
            .collect();
        Image {
            layers,
            config: serde_json::from_slice(&blob(&manifest["config"]["digest"])).unwrap(),
        }
    }

    /// Appends an uncompressed layer holding `path` (relative, e.g. `opt/x/f`) with `body`.
    fn with_file(self, path: &str, body: &str) -> Image {
        self.with_files(&[(path, body)])
    }

    /// Appends one uncompressed layer holding each `(path, body)`.
    fn with_files(mut self, files: &[(&str, &str)]) -> Image {
        let mut b = tar::Builder::new(Vec::new());
        let mut dirs = std::collections::BTreeSet::new();
        for (path, body) in files {
            let parts: Vec<&str> = path.split('/').collect();
            for i in 1..parts.len() {
                let dir = format!("{}/", parts[..i].join("/"));
                if !dirs.insert(dir.clone()) {
                    continue;
                }
                let mut h = tar::Header::new_gnu();
                h.set_entry_type(tar::EntryType::Directory);
                h.set_mode(0o755);
                h.set_size(0);
                h.set_cksum();
                b.append_data(&mut h, dir, std::io::empty()).unwrap();
            }
            let mut h = tar::Header::new_gnu();
            h.set_mode(0o644);
            h.set_size(body.len() as u64);
            h.set_cksum();
            b.append_data(&mut h, path, body.as_bytes()).unwrap();
        }
        let data = b.into_inner().unwrap();
        let diff_id = sha256(&data);
        self.config["rootfs"]["diff_ids"]
            .as_array_mut()
            .unwrap()
            .push(diff_id.into());
        self.layers
            .push((data, "application/vnd.oci.image.layer.v1.tar".to_string()));
        self
    }
}

impl Image {
    /// The image's `path` (e.g. `etc/passwd`) from its topmost layer that has it, read with the
    /// host's `tar` (which detects gzip itself).
    fn file(&self, path: &str) -> String {
        let dir = tempfile::tempdir().unwrap();
        let layer = dir.path().join("layer");
        for (data, _) in self.layers.iter().rev() {
            std::fs::write(&layer, data).unwrap();
            for member in [path.to_string(), format!("./{path}")] {
                let out = Command::new("tar")
                    .arg("-xOf")
                    .arg(&layer)
                    .arg(&member)
                    .output()
                    .unwrap();
                if out.status.success() && !out.stdout.is_empty() {
                    return String::from_utf8(out.stdout).unwrap();
                }
            }
        }
        panic!("no {path} in the image");
    }
}

fn sha256(data: &[u8]) -> String {
    use sha2::Digest;
    let hex: String = sha2::Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    format!("sha256:{hex}")
}

/// A kit descriptor as published: `schemaVersion` 3 plus `kind` and capabilities.
fn descriptor(kind: &str, provides: &[&str], caps: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "schemaVersion": "3",
        "kind": kind,
        "provides": provides,
        "capabilities": caps,
    })
}

/// Install hook (as root) giving an Alpine guest the `agent` user, as the identity step would.
fn add_agent_hook() -> String {
    format!(
        "id agent >/dev/null 2>&1 || adduser -D -u {} agent",
        smolbento::sandbox::host_uid()
    )
}

impl E2e {
    /// `sbt create` of an Alpine-based shell sandbox with `kits` (`-t alpine --kit ...`).
    fn create_with_kits(&self, kits: &[&str]) {
        let ws = self.workspace();
        let mut args = vec!["create", "-t", "alpine"];
        for k in kits {
            args.extend(["--kit", k]);
        }
        args.extend([
            "shell",
            ws.to_str().unwrap(),
            "--name",
            &self.name,
            "--cpus",
            "1",
            "-m",
            "1g",
        ]);
        self.ok(&args);
    }
}

/// Root's view of `script` in sandbox `sb`: its stdout, whatever the exit status.
fn root_out(sb: &str, script: &str) -> String {
    String::from_utf8_lossy(&root_sh(sb, script).stdout).into_owned()
}

#[test]
#[ignore = "boots real VMs and pulls alpine; run with `just e2e`"]
fn published_workload_kit_runs_its_command() {
    let e = E2e::new("wl");
    let reg = Registry::start(&e);
    let mut image = Image::alpine();
    image.config["config"]["Entrypoint"] = serde_json::Value::Null;
    image.config["config"]["Cmd"] = serde_json::json!([
        "sh",
        "-c",
        "echo workload-command-ran-as-$(id -un) in $(pwd)"
    ]);
    let kit = reg.push(
        "workload",
        image,
        descriptor(
            "workload",
            &[],
            serde_json::json!([
                {"type": "com.docker.sandbox/sbx@1"},
                {"type": "com.docker.sandbox/lifecycle@1",
                 "config": {"install": [
                     {"command": add_agent_hook(), "user": "0"},
                     {"command": "apk add -q bash", "user": "0"},
                 ]}},
            ]),
        ),
    );
    let ws = e.workspace();
    e.ok(&[
        "create",
        &kit,
        ws.to_str().unwrap(),
        "--name",
        &e.name,
        "--cpus",
        "1",
        "-m",
        "1g",
    ]);
    assert_eq!(e.state(), "running");
    // The image has no USER, so the agent runs as root, as in sbx, in the workspace.
    let out = e.ok(&["run", "--name", &e.name]);
    let want = format!("workload-command-ran-as-root in {}", ws.display());
    assert!(out.contains(&want), "{out}");
}

#[test]
#[ignore = "boots real VMs and pulls alpine; run with `just e2e`"]
fn mixin_layer_is_visible_in_the_guest() {
    let e = E2e::new("layer");
    let reg = Registry::start(&e);
    let kit = reg.push(
        "layer",
        Image::empty().with_file("opt/e2e-mixin/hello", "hello from a mixin layer\n"),
        descriptor("mixin", &["e2e-layer@1.0.0"], serde_json::json!([])),
    );
    e.create_with_kits(&[&kit]);
    assert_eq!(
        root_out(&e.name, "cat /opt/e2e-mixin/hello"),
        "hello from a mixin layer\n"
    );
    // Alpine's own files are still there under the mixin's layer.
    assert!(root_out(&e.name, "cat /etc/alpine-release").starts_with('3'));
}

/// Deletes the shared `_builder` sandbox after the test, unless it existed before.
struct BuilderGuard(bool);

impl BuilderGuard {
    fn new() -> BuilderGuard {
        let existed = Command::new("smolvm")
            .args(["machine", "status", "-n", "sbx-_builder"])
            .output()
            .unwrap()
            .status
            .success();
        BuilderGuard(existed)
    }
}

impl Drop for BuilderGuard {
    fn drop(&mut self) {
        if !self.0 {
            let _ = Command::new("smolvm")
                .args(["machine", "delete", "-f", "-n", "sbx-_builder"])
                .output();
        }
    }
}

#[test]
#[ignore = "boots real VMs, builds in the builder sandbox and pulls from Docker Hub; run with `just e2e`"]
fn local_v3_kit_builds_in_the_builder_sandbox() {
    let e = E2e::new("build");
    let _builder = BuilderGuard::new();
    let kit = e.dir.path().join("built");
    std::fs::create_dir_all(&kit).unwrap();
    std::fs::write(
        kit.join("built.yaml"),
        r#"# syntax=docker/sandbox-kit:3
schemaVersion: "3"
kind: mixin
version: "1.0.0"
provides: [e2e-built]
build: |
  FROM busybox:1.37 AS build
  RUN mkdir -p /out/opt/e2e-built && echo "built in the builder" > /out/opt/e2e-built/hello
  FROM scratch
  COPY --from=build /out/ /
"#,
    )
    .unwrap();
    e.create_with_kits(&[kit.to_str().unwrap()]);
    assert_eq!(
        root_out(&e.name, "cat /opt/e2e-built/hello"),
        "built in the builder\n"
    );
    let ls = e.ok(&["ls", "--json"]);
    assert!(!ls.contains("_builder"), "the builder is hidden: {ls}");
}

#[test]
#[ignore = "boots real VMs and pulls from dhi.io with a login; run with `just e2e`"]
fn local_kit_builds_from_a_registry_that_needs_a_login() {
    // Local only: needs a Docker account with dhi.io access and its access token in a file.
    let (Ok(user), Ok(token_file)) = (
        std::env::var("SMOLBENTO_E2E_DHI_USER"),
        std::env::var("SMOLBENTO_E2E_DHI_TOKEN_FILE"),
    ) else {
        eprintln!(
            "skipped: set SMOLBENTO_E2E_DHI_USER and SMOLBENTO_E2E_DHI_TOKEN_FILE to build from dhi.io"
        );
        return;
    };
    let token = std::fs::read(&token_file).unwrap();
    let e = E2e::new("dhi");
    let _builder = BuilderGuard::new();

    // The token lives in the real keychain on macOS: remove it on every exit path. This also
    // removes a dhi.io credential you stored yourself.
    struct RegistryCleanup<'a>(&'a E2e);
    impl Drop for RegistryCleanup<'_> {
        fn drop(&mut self) {
            let _ = self.0.sbt(&["secret", "rm", "--registry", "dhi.io"]);
        }
    }
    let _cleanup = RegistryCleanup(&e);
    let mut set = e
        .env(Command::new(env!("CARGO_BIN_EXE_smolbento")).args([
            "secret",
            "set",
            "--registry",
            "dhi.io",
            "--username",
            &user,
            "--password-stdin",
        ]))
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    {
        use std::io::Write;
        set.stdin.take().unwrap().write_all(&token).unwrap();
    }
    let out = set.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "secret set --registry: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let kit = e.dir.path().join("dhi");
    std::fs::create_dir_all(&kit).unwrap();
    std::fs::write(
        kit.join("dhi.yaml"),
        r#"# syntax=docker/sandbox-kit:3
schemaVersion: "3"
kind: mixin
version: "1.0.0"
provides: [e2e-dhi]
build: |
  FROM dhi.io/debian-base:trixie AS base
  FROM scratch
  COPY --from=base /etc/os-release /opt/e2e-dhi/os-release
"#,
    )
    .unwrap();
    e.create_with_kits(&[kit.to_str().unwrap()]);
    let release = root_out(&e.name, "cat /opt/e2e-dhi/os-release");
    assert!(
        release.contains(r#"VERSION_CODENAME="trixie""#),
        "{release}"
    );
}

#[test]
#[ignore = "boots real VMs and needs example.com; run with `just e2e`"]
fn install_phase_network_closes_after_install() {
    let e = E2e::new("instnet");
    e.ok(&["policy", "init", "deny-all"]);
    let reg = Registry::start(&e);
    // During install: example.com by name, then by the IP it resolved to (any HTTP answer).
    let probe = r#"set -e
wget -q -T 15 -O /dev/null https://example.com
ip=$(nslookup example.com 2>/dev/null | awk '/^Address/ && $NF !~ /:/ {print $NF}' | head -n 1)
[ -n "$ip" ]
wget -S -T 15 -O /dev/null "http://$ip/" 2>&1 | grep -q 'HTTP/'
echo "$ip" > /etc/e2e-install-ip"#;
    let kit = reg.push(
        "install-net",
        Image::empty(),
        descriptor(
            "mixin",
            &["e2e-install-net"],
            serde_json::json!([
                {"type": "com.docker.sandbox/network-policy@1",
                 "config": {"install": {"allow": ["example.com"]}}},
                {"type": "com.docker.sandbox/lifecycle@1",
                 "config": {"install": [
                     {"command": add_agent_hook(), "user": "0"},
                     {"command": probe, "user": "0"},
                 ]}},
            ]),
        ),
    );
    e.create_with_kits(&[&kit]);
    let ip = root_out(&e.name, "cat /etc/e2e-install-ip")
        .trim()
        .to_string();
    assert!(!ip.is_empty(), "the install hook reached example.com");

    assert!(
        !reachable(&e, "https://example.com"),
        "example.com is closed after install"
    );
    let by_ip = e.sbt(&[
        "exec",
        &e.name,
        "sh",
        "-c",
        &format!("wget -S -T 8 -O /dev/null http://{ip}/ 2>&1 | grep -q 'HTTP/'"),
    ]);
    assert!(
        !by_ip.status.success(),
        "{ip} (example.com's address) is closed after install"
    );
    // `policy ls` never lists install-phase rules (as sbx), so check the stored policy too.
    let rules = e.ok(&["policy", "ls"]);
    assert!(
        !rules.contains("example.com"),
        "install rules not listed:\n{rules}"
    );
    let stored = std::fs::read_to_string(e.dir.path().join("config/policy.toml")).unwrap();
    assert!(
        !stored.contains("example.com"),
        "install rules removed:\n{stored}"
    );
}

#[test]
#[ignore = "boots real VMs and needs httpbin.org; run with `just e2e`"]
fn install_only_credential_is_gone_after_install() {
    let e = E2e::new("instcred");
    e.ok(&[
        "secret",
        "set-custom",
        "--host",
        "httpbin.org",
        "--env",
        "E2E_TOK",
        "--command",
        "printf real-secret-xyz",
    ]);
    let reg = Registry::start(&e);
    let kit = reg.push(
        "install-cred",
        Image::empty(),
        descriptor(
            "mixin",
            &["e2e-install-cred"],
            serde_json::json!([
                {"type": "com.docker.sandbox/credential@1",
                 "config": {"service": "e2e-tok", "phase": "install",
                            "apiKey": {"name": "KIT_TOK", "inject": [
                                {"domain": "httpbin.org", "header": "authorization",
                                 "format": "Bearer %s"}]}}},
                {"type": "com.docker.sandbox/lifecycle@1",
                 "config": {"install": [
                     {"command": add_agent_hook(), "user": "0"},
                     {"command": "wget -q -T 20 -O /etc/e2e-install-echo https://httpbin.org/headers",
                      "user": "0"},
                 ]}},
            ]),
        ),
    );
    e.create_with_kits(&[&kit]);
    let during = root_out(&e.name, "cat /etc/e2e-install-echo");
    assert!(
        during.contains("Bearer real-secret-xyz"),
        "substituted during install: {during}"
    );
    let after = e.sbt(&[
        "exec",
        &e.name,
        "sh",
        "-c",
        "wget -S -T 20 -O - https://httpbin.org/headers 2>&1",
    ]);
    let after = String::from_utf8_lossy(&after.stdout);
    assert!(after.contains("502"), "502 after install: {after}");
    assert!(!after.contains("real-secret-xyz"), "{after}");
}

#[test]
#[ignore = "boots real VMs and needs example.com; run with `just e2e`"]
fn kit_add_applies_network_and_hooks_live() {
    let e = E2e::new("kitadd");
    e.create_alpine();
    e.ok(&["policy", "init", "deny-all"]);
    e.ok(&["stop", &e.name]); // allow-all -> restricted applies on the next start
    e.ok(&["start", &e.name]);
    assert!(!reachable(&e, "https://example.com"), "deny-all blocks");
    let boot = root_out(&e.name, "cat /proc/sys/kernel/random/boot_id");

    let kit = e.dir.path().join("e2e-add");
    std::fs::create_dir_all(&kit).unwrap();
    std::fs::write(
        kit.join("spec.yaml"),
        r#"schemaVersion: "2"
kind: mixin
name: e2e-add
permissions:
  network:
    allow: [example.com]
setup:
  install:
    - command: touch /etc/e2e-kit-installed
  startup:
    - command: [touch, /tmp/e2e-kit-started]
      user: "0"
"#,
    )
    .unwrap();
    e.ok(&["kit", "add", &e.name, kit.to_str().unwrap(), "--yes"]);

    assert_eq!(
        root_out(&e.name, "cat /proc/sys/kernel/random/boot_id"),
        boot,
        "applied without a restart"
    );
    assert!(reachable(&e, "https://example.com"), "the kit's allow rule");
    assert!(
        root_sh(&e.name, "test -f /etc/e2e-kit-installed")
            .status
            .success()
    );
    assert!(
        wait_until(30, || root_sh(&e.name, "test -f /tmp/e2e-kit-started")
            .status
            .success()),
        "the startup hook ran"
    );
    assert!(root_out(&e.name, "cat /etc/smolbento/kits").contains("e2e-add"));
    // As in sbx: one `kit:<sandbox>` row, its hosts counted (listed with --wide).
    let rules = e.ok(&["policy", "ls", "--source", "kit"]);
    assert!(rules.contains("network: 1 allow"), "{rules}");
    let wide = e.ok(&["policy", "ls", "--source", "kit", "--wide"]);
    assert!(wide.contains(&format!("kit:{}", e.name)), "{wide}");
    assert!(wide.contains("example.com"), "{wide}");
}

/// Debian (it has bash and `usermod`) plus accounts `somebody` (uid 1234) and `numbered`
/// (uid 4321), a `BASH_ENV` file, `WORKDIR /x`, and env vars `E2E_DECLARED` and `E2E_UNDECLARED`,
/// published as a workload kit whose image `USER` is `user`. Its command reports who and where it
/// runs, whether bash sourced `BASH_ENV`, and writes a file in the workspace.
fn image_user_kit(reg: &Registry, repo: &str, user: &str, lifecycle: serde_json::Value) -> String {
    let base = Image::pull("debian:bookworm-slim");
    let passwd = base.file("etc/passwd")
        + "somebody:x:1234:1234::/home/somebody:/bin/bash\n\
           numbered:x:4321:4321::/home/numbered:/bin/sh\n";
    let group = base.file("etc/group") + "somebody:x:1234:\nnumbered:x:4321:\n";
    let mut image = base.with_files(&[
        ("etc/passwd", &passwd),
        ("etc/group", &group),
        ("etc/e2e-bash-env", "export E2E_FROM_BASH_ENV=yes\n"),
        ("x/.keep", ""),
    ]);
    let c = &mut image.config["config"];
    c["User"] = user.into();
    c["WorkingDir"] = "/x".into();
    c["Entrypoint"] = serde_json::Value::Null;
    c["Cmd"] = serde_json::json!([
        "sh",
        "-c",
        "echo \"ran user=$(id -un) bash_env=$E2E_FROM_BASH_ENV pwd=$(pwd)\"; \
         touch \"wrote-as-$(id -un)\""
    ]);
    let mut env: Vec<serde_json::Value> = c["Env"].as_array().cloned().unwrap_or_default();
    env.extend([
        "BASH_ENV=/etc/e2e-bash-env".into(),
        "E2E_DECLARED=declared".into(),
        "E2E_UNDECLARED=undeclared".into(),
    ]);
    c["Env"] = env.into();
    let mut caps = vec![serde_json::json!({"type": "com.docker.sandbox/sbx@1"})];
    if !lifecycle.is_null() {
        caps.push(
            serde_json::json!({"type": "com.docker.sandbox/lifecycle@1", "config": lifecycle}),
        );
    }
    reg.push(repo, image, descriptor("workload", &[], caps.into()))
}

impl E2e {
    /// `sbt create` of workload kit `kit` on the workspace.
    fn create_workload(&self, kit: &str) {
        let ws = self.workspace();
        self.ok(&[
            "create",
            kit,
            ws.to_str().unwrap(),
            "--name",
            &self.name,
            "--cpus",
            "1",
            "-m",
            "1g",
        ]);
    }

    /// Runs the workload's agent; asserts it ran as `user` (its uid mapped to the host's) with
    /// `BASH_ENV` sourced, in the workspace, and could write there.
    fn assert_agent_runs_as(&self, user: &str) {
        let ws = self.workspace();
        let run = self.sbt(&["run", "--name", &self.name]);
        if !run.status.success() {
            // What the guest saw, so a failure on another host (e.g. Linux CI) explains itself.
            let probe = "id; id agent; ls -lnd . ..; grep -E ' virtiofs | 9p ' /proc/mounts; \
                         cat /proc/self/uid_map /proc/self/gid_map 2>&1; \
                         cat /etc/smolbento/image-user 2>&1; touch probe-$(id -u) 2>&1; ls -ln";
            let as_root = self.sbt(&["exec", "--privileged", &self.name, "sh", "-c", probe]);
            let as_user = self.sbt(&["exec", "-u", user, &self.name, "sh", "-c", probe]);
            panic!(
                "sbt run failed:\n{}\n--- as root:\n{}{}\n--- as {user}:\n{}{}",
                String::from_utf8_lossy(&run.stderr),
                String::from_utf8_lossy(&as_root.stdout),
                String::from_utf8_lossy(&as_root.stderr),
                String::from_utf8_lossy(&as_user.stdout),
                String::from_utf8_lossy(&as_user.stderr),
            );
        }
        let out = String::from_utf8_lossy(&run.stdout).into_owned();
        let want = format!("ran user={user} bash_env=yes pwd={}", ws.display());
        assert!(out.contains(&want), "want {want:?} in:\n{out}");
        let written = ws.join(format!("wrote-as-{user}"));
        let meta = std::fs::metadata(&written)
            .unwrap_or_else(|e| panic!("{} on the host: {e}", written.display()));
        use std::os::unix::fs::MetadataExt;
        assert_eq!(meta.uid(), smolbento::sandbox::host_uid(), "owned by you");
    }
}

/// sbx #3 and #12: a v3 workload's agent runs as the image `USER` under bash (so `BASH_ENV` is
/// sourced) in the workspace. Install hooks run in `WORKDIR` with a clean environment (the
/// baseline plus declared vars); startup hooks get the whole container environment.
#[test]
#[ignore = "boots real VMs and pulls debian; run with `just e2e`"]
fn v3_workload_runs_as_its_image_user_with_bash_env() {
    let e = E2e::new("imguser");
    let reg = Registry::start(&e);
    let kit = image_user_kit(
        &reg,
        "image-user",
        "somebody",
        serde_json::json!({
            "install": [{"command": "env > /etc/e2e-install-env; pwd > /etc/e2e-install-pwd",
                         "user": "0", "env": ["E2E_DECLARED"]}],
            "startup": [{"command": "env > /etc/e2e-startup-env", "user": "0"}],
        }),
    );
    e.create_workload(&kit);

    let install = root_out(&e.name, "cat /etc/e2e-install-env");
    assert!(install.contains("E2E_DECLARED=declared"), "{install}");
    assert!(install.contains("PATH="), "{install}");
    assert!(!install.contains("E2E_UNDECLARED"), "{install}");
    assert!(!install.contains("BASH_ENV"), "{install}");
    assert_eq!(root_out(&e.name, "cat /etc/e2e-install-pwd"), "/x\n");
    let startup = root_out(&e.name, "cat /etc/e2e-startup-env");
    assert!(startup.contains("E2E_UNDECLARED=undeclared"), "{startup}");

    assert_eq!(e.ok(&["exec", &e.name, "id", "-un"]).trim(), "somebody");
    e.assert_agent_runs_as("somebody");
}

/// A numeric image `USER` runs as the account that has that uid, moved to the host's uid.
#[test]
#[ignore = "boots real VMs and pulls debian; run with `just e2e`"]
fn numeric_image_user_runs_as_its_account() {
    let e = E2e::new("numuser");
    let reg = Registry::start(&e);
    let kit = image_user_kit(&reg, "numeric-user", "4321", serde_json::Value::Null);
    e.create_workload(&kit);
    e.assert_agent_runs_as("numbered");
}

/// sbx #11: a blocking startup hook that fails keeps a new sandbox stopped (create only warns),
/// and every later start fails.
#[test]
#[ignore = "boots real VMs and pulls alpine; run with `just e2e`"]
fn failing_startup_hook_fails_the_start() {
    let e = E2e::new("startfail");
    let kit = e.dir.path().join("e2e-fail-start");
    std::fs::create_dir_all(&kit).unwrap();
    std::fs::write(
        kit.join("spec.yaml"),
        r#"schemaVersion: "2"
kind: mixin
name: e2e-fail-start
setup:
  startup:
    - command: [sh, -c, "sleep 2; exit 7"]
      user: "0"
"#,
    )
    .unwrap();
    let ws = e.workspace();
    let out = e.sbt(&[
        "create",
        "-t",
        "alpine",
        "--kit",
        kit.to_str().unwrap(),
        "shell",
        ws.to_str().unwrap(),
        "--name",
        &e.name,
        "--cpus",
        "1",
        "-m",
        "1g",
    ]);
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "create still succeeds:\n{err}");
    assert!(
        err.contains("StartRuntime after create failed")
            && err.contains("kit startup exited with code 7"),
        "{err}"
    );
    assert_eq!(e.state(), "stopped");

    let out = e.sbt(&["start", &e.name]);
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "start fails");
    assert!(err.contains("kit startup exited with code 7"), "{err}");
    assert_eq!(e.state(), "stopped");
}

/// sbx #13: a v2 startup hook without `user:` runs as the agent account (sbx's uid 1000; here
/// `agent` has the host's uid), and it doesn't keep the sandbox from starting.
#[test]
#[ignore = "boots real VMs and pulls alpine; run with `just e2e`"]
fn v2_startup_hook_runs_as_agent_by_default() {
    let e = E2e::new("v2user");
    let kit = e.dir.path().join("e2e-v2-user");
    std::fs::create_dir_all(&kit).unwrap();
    std::fs::write(
        kit.join("spec.yaml"),
        format!(
            r#"schemaVersion: "2"
kind: mixin
name: e2e-v2-user
setup:
  install:
    - command: "{}"
  startup:
    - command: [sh, -c, "id -un > /tmp/e2e-started-as"]
"#,
            add_agent_hook()
        ),
    )
    .unwrap();
    e.create_with_kits(&[kit.to_str().unwrap()]);
    e.ok(&["start", &e.name]);
    assert_eq!(e.state(), "running");
    let uid = smolbento::sandbox::host_uid();
    assert_eq!(
        root_out(
            &e.name,
            "cat /tmp/e2e-started-as; stat -c '%U %u' /tmp/e2e-started-as"
        ),
        format!("agent\nagent {uid}\n")
    );
}

/// sbx #15: a mixin's agent context goes beside the workspace, in the sandbox only: the shell
/// agent's `AGENTS.md` gets an index block and the kit's text goes to `kits-agent-context/`.
#[test]
#[ignore = "boots real VMs and pulls alpine; run with `just e2e`"]
fn mixin_agent_context_sits_beside_the_workspace() {
    let e = E2e::new("ctx");
    let kit = e.dir.path().join("e2e-ctx");
    std::fs::create_dir_all(&kit).unwrap();
    std::fs::write(
        kit.join("spec.yaml"),
        format!(
            r#"schemaVersion: "2"
kind: mixin
name: e2e-ctx
agentInstructions:
  content: "Use the e2e tools."
setup:
  install:
    - command: "{}"
"#,
            add_agent_hook()
        ),
    )
    .unwrap();
    e.create_with_kits(&[kit.to_str().unwrap()]);
    let parent = e.workspace().parent().unwrap().to_path_buf();
    let p = parent.display();
    let index = root_out(&e.name, &format!("cat {p}/AGENTS.md"));
    let line = format!("- **e2e-ctx** — See {p}/kits-agent-context/e2e-ctx.md.");
    assert!(
        index.contains("<!-- sbx:kits-section start -->")
            && index.contains(&line)
            && index.contains("<!-- sbx:kits-section end -->"),
        "{index}"
    );
    let body = root_out(&e.name, &format!("cat {p}/kits-agent-context/e2e-ctx.md"));
    assert!(body.contains("Use the e2e tools."), "{body}");
    assert_eq!(
        root_out(
            &e.name,
            &format!("stat -c %U {p}/AGENTS.md {p}/kits-agent-context/e2e-ctx.md")
        ),
        "agent\nagent\n"
    );
    assert!(!parent.join("AGENTS.md").exists(), "nothing on the host");
    assert!(
        !parent.join("kits-agent-context").exists(),
        "nothing on the host"
    );
}

/// sbx #6, #8, #9: kit argument errors stop `create` before any machine is made.
#[test]
#[ignore = "runs sbt against smolvm; run with `just e2e`"]
fn kit_arg_errors_stop_create() {
    let e = E2e::new("args");
    let ws = e.workspace();
    let ws = ws.to_str().unwrap();
    let fails = |args: &[&str], want: &str| {
        let out = e.sbt(args);
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success(), "{args:?} fails");
        assert!(err.contains(want), "{args:?}: want {want:?} in:\n{err}");
        assert_eq!(e.state(), "absent", "{args:?} made no sandbox");
    };
    fails(
        &["create", "shell", ws, "--name", &e.name, "--kit-arg", "a=1"],
        "kit arguments were supplied but no kits were referenced",
    );

    let kit = e.dir.path().join("e2e-args");
    std::fs::create_dir_all(&kit).unwrap();
    std::fs::write(
        kit.join("spec.yaml"),
        r#"schemaVersion: "2"
kind: mixin
name: e2e-args
args:
  opt:
    description: optional, no default
  num:
    default: 5
    enum: [5, 6]
setup:
  install:
    - command: "echo ${{ kit.args.opt }} ${{ kit.args.num }}"
"#,
    )
    .unwrap();
    let kit = kit.to_str().unwrap();
    fails(
        &[
            "create", "-t", "alpine", "--kit", kit, "shell", ws, "--name", &e.name,
        ],
        "create-phase kit arg \"opt\" has no resolved value",
    );
    // An empty value is a value, and unquoted numbers are strings.
    e.ok(&["kit", "validate", kit, "--kit-arg", "opt="]);

    // As in sbx: a local kit is a path (`../e2e-args` from the workspace), a bare word never is.
    let out = e.ok(&["kit", "validate", "../e2e-args", "--kit-arg", "opt="]);
    assert_eq!(out, "✓ ../e2e-args — valid\n");
    let out = e.ok(&[
        "kit",
        "validate",
        "../e2e-args",
        "--json",
        "--kit-arg",
        "opt=",
    ]);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["valid"], true, "{out}");
    let out = e.ok(&["kit", "inspect", "../e2e-args"]);
    assert!(
        out.starts_with("Name: e2e-args\nKind: mixin\nSchema: v2\n"),
        "{out}"
    );
    std::fs::create_dir_all(e.workspace().join("e2e-args")).unwrap();
    fails(
        &["create", "e2e-args", ws, "--name", &e.name],
        "unknown agent \"e2e-args\"",
    );
    fails(
        &[
            "create", "shell", ws, "--name", &e.name, "--kit", "e2e-args",
        ],
        "not a local path and does not look like a registry reference",
    );
}

/// A shell loop printing `NAME=value` for each sbx sandbox variable, run in the guest by `exec`
/// and `run`.
const SBX_VARS: &str = "for v in SANDBOX_NAME SANDBOX_VM_ID SANDBOX_ID WORKSPACE_DIR SBX_AGENT \
                        SBX_CRED_ANTHROPIC_MODE; do eval \"echo $v=\\$$v\"; done";

fn sbx_vars(out: &str) -> std::collections::BTreeMap<String, String> {
    out.lines()
        .filter_map(|l| l.trim_end_matches('\r').split_once('='))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

/// `8-4-4-4-12` lowercase hex.
fn is_uuid(s: &str) -> bool {
    let parts: Vec<&str> = s.split('-').collect();
    parts.iter().map(|p| p.len()).eq([8, 4, 4, 4, 12])
        && parts.iter().all(|p| {
            p.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        })
}

/// sbx's sandbox variables reach the agent and `exec`; a fork gets its own name and id
/// (`machine branch -e` wins over what the fork inherits from its parent).
#[test]
#[ignore = "boots real VMs; run with `just e2e`"]
fn sbx_sandbox_variables_reach_the_agent_exec_and_forks() {
    let e = E2e::new("env");
    e.create_alpine();
    let ws = e.workspace();
    let exec = sbx_vars(&e.ok(&["exec", &e.name, "sh", "-c", SBX_VARS]));
    assert_eq!(exec["SANDBOX_NAME"], e.name, "{exec:?}");
    assert_eq!(exec["SANDBOX_VM_ID"], e.name, "{exec:?}");
    assert!(is_uuid(&exec["SANDBOX_ID"]), "{exec:?}");
    assert_eq!(exec["WORKSPACE_DIR"], ws.to_str().unwrap(), "{exec:?}");
    assert_eq!(exec["SBX_AGENT"], "shell", "{exec:?}");
    assert_eq!(exec["SBX_CRED_ANTHROPIC_MODE"], "none", "{exec:?}");

    // The agent (the shell preset's shell) sees the same values.
    let agent = sbx_vars(&e.ok(&["run", "--name", &e.name, "--", "-c", SBX_VARS]));
    assert_eq!(agent, exec, "the agent's variables match exec's");

    // A mountless sandbox can be forked. Set up as `create_alpine` does, plus the guest workdir
    // (sbx images have it; Alpine doesn't).
    let m = E2e::new("envm");
    m.ok(&[
        "create", "shell", "--name", &m.name, "-t", "alpine", "--cpus", "1", "-m", "1g",
    ]);
    guest_root(
        &m.name,
        &format!(
            "adduser -D -u {} agent && apk add -q bash \
             && install -d -o agent /home/agent/workspace",
            smolbento::sandbox::host_uid()
        ),
    );
    let fork = format!("{}-fork-1", m.name);
    let forks = Forks(vec![fork.clone()]);
    assert_eq!(m.ok(&["fork", &m.name]).trim(), fork);
    let parent = sbx_vars(&m.ok(&["exec", &m.name, "sh", "-c", SBX_VARS]));
    let child = sbx_vars(&m.ok(&["exec", &fork, "sh", "-c", SBX_VARS]));
    assert_eq!(parent["SANDBOX_NAME"], m.name, "{parent:?}");
    assert_eq!(
        child["SANDBOX_NAME"], fork,
        "the fork's own name: {child:?}"
    );
    assert_eq!(child["SANDBOX_VM_ID"], fork, "{child:?}");
    assert!(is_uuid(&child["SANDBOX_ID"]), "{child:?}");
    assert_ne!(
        child["SANDBOX_ID"], parent["SANDBOX_ID"],
        "the fork's own id"
    );
    assert_ne!(
        exec["SANDBOX_ID"], parent["SANDBOX_ID"],
        "an id per sandbox"
    );
    assert_eq!(child["WORKSPACE_DIR"], parent["WORKSPACE_DIR"], "{child:?}");
    assert!(!parent["WORKSPACE_DIR"].is_empty(), "{parent:?}");
    m.ok(&["rm", "-f", &fork]);
    drop(forks);
}

#[test]
#[ignore = "boots real VMs; run with `just e2e`"]
fn env_files_create_exec_and_remove() {
    let e = E2e::new("envf");
    let dir = e.dir.path().join("envs");
    std::fs::create_dir_all(dir.join("ws")).unwrap();
    let base = dir.join("base.yaml");
    let local = dir.join("local.yaml");
    std::fs::write(
        &base,
        format!(
            "schemaVersion: \"1\"\nagent: shell\nname: {}\nworkspace: ./ws\n\
             args:\n  greeting:\n    required: true\n\
             env:\n  GREETING: ${{{{ env.args.greeting }}}}\n\
             secrets:\n  github:\n    value: dummy-token\n\
             sandboxOptions:\n  template: alpine\n  cpus: 1\n  memory: 1g\n",
            e.name
        ),
    )
    .unwrap();
    std::fs::write(&local, "env:\n  EXTRA: \"1\"\n").unwrap();
    let (base, local) = (base.to_str().unwrap(), local.to_str().unwrap());

    // The secret lives in the real keychain on macOS: remove it on every exit path.
    struct EnvCleanup<'a>(&'a E2e, [&'a str; 2]);
    impl Drop for EnvCleanup<'_> {
        fn drop(&mut self) {
            let [base, local] = self.1;
            let _ = self.0.sbt(&[
                "env",
                "rm",
                "--force",
                "--env-arg",
                "greeting=hi",
                base,
                local,
            ]);
        }
    }
    let _cleanup = EnvCleanup(&e, [base, local]);

    e.ok(&[
        "env",
        "create",
        "--force",
        base,
        local,
        "--env-arg",
        "greeting=hi",
    ]);
    assert_ne!(e.state(), "absent");
    // Alpine has no `agent` user or bash; add them as `create_alpine` does.
    guest_root(
        &e.name,
        &format!(
            "adduser -D -u {} agent && apk add -q bash",
            smolbento::sandbox::host_uid()
        ),
    );

    let out = e.ok(&[
        "env",
        "exec",
        "--env-arg",
        "greeting=hi",
        base,
        local,
        "--",
        "sh",
        "-c",
        "echo $GREETING $EXTRA; pwd",
    ]);
    let ws = dir.join("ws").canonicalize().unwrap();
    assert_eq!(out, format!("hi 1\n{}\n", ws.display()));

    let secrets = e.ok(&["secret", "ls"]);
    assert!(
        secrets.contains("github") && secrets.contains(&e.name),
        "{secrets}"
    );

    e.ok(&[
        "env",
        "rm",
        "--force",
        "--env-arg",
        "greeting=hi",
        base,
        local,
    ]);
    assert_eq!(e.state(), "absent");
    let secrets = e.ok(&["secret", "ls"]);
    assert!(!secrets.contains(&e.name), "{secrets}");
}
