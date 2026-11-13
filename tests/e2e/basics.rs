use super::*;

#[test]
#[ignore = "boots real VMs; run with `just e2e`"]
pub(crate) fn lifecycle_exec_and_same_path_mount() {
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
    // A plain exec is streamed: output past smolvm's 11 MiB buffered cap arrives whole, and the
    // command's exit status is sbt's.
    let big = e.ok(&["exec", &e.name, "head", "-c", "12000000", "/dev/zero"]);
    assert_eq!(big.len(), 12_000_000);
    let out = e.sbt(&["exec", &e.name, "sh", "-c", "echo to-err >&2; exit 7"]);
    assert_eq!(out.status.code(), Some(7));
    assert_eq!(String::from_utf8_lossy(&out.stderr), "to-err\n");

    e.ok(&["stop", &e.name]);
    assert_eq!(e.state(), "stopped");
    e.ok(&["rm", "-f", &e.name]);
    assert_eq!(e.state(), "absent");
}

#[test]
#[ignore = "boots real VMs; run with `just e2e`"]
pub(crate) fn run_attaches_then_stops_when_the_last_session_ends() {
    let e = E2e::new("run");
    e.create_alpine();
    let out = e.ok(&["run", "--name", &e.name, "--", "-c", "echo hello-from-run"]);
    assert!(out.contains("hello-from-run"), "{out}");
    assert_eq!(e.state(), "stopped");
}

#[test]
#[ignore = "boots real VMs; run with `just e2e`"]
pub(crate) fn cp_round_trip() {
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

    // A directory copies in like `cp -r`.
    let tree = e.dir.path().join("tree");
    std::fs::create_dir_all(tree.join("sub")).unwrap();
    std::fs::write(tree.join("sub/f"), "nested").unwrap();
    e.ok(&[
        "cp",
        tree.to_str().unwrap(),
        &format!("{}:/tmp/tree", e.name),
    ]);
    assert_eq!(e.ok(&["exec", &e.name, "cat", "/tmp/tree/sub/f"]), "nested");
}

#[test]
#[ignore = "boots real VMs; run with `just e2e`"]
pub(crate) fn diagnose_passes() {
    let e = E2e::new("diag");
    let out = e.ok(&["diagnose"]);
    assert!(!out.contains("FAIL"), "{out}");
}

pub(crate) fn reachable(e: &E2e, url: &str) -> bool {
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
pub(crate) fn policy_changes_apply_on_start_and_live() {
    let e = E2e::new("pol");
    e.create_alpine();
    e.ok(&["policy", "init", "deny-all"]);
    e.ok(&["stop", &e.name]); // allow-all -> restricted applies on the next start
    assert!(!reachable(&e, "https://httpbin.org"), "deny-all blocks");
    e.ok(&["policy", "allow", "network", "httpbin.org"]);
    assert!(reachable(&e, "https://httpbin.org"), "live allow");
    let ip = e.ok(&[
        "exec",
        &e.name,
        "sh",
        "-c",
        "nslookup httpbin.org 2>/dev/null | awk '/^Address/ && $NF !~ /:/ {print $NF}' | head -n 1",
    ]);
    let ip = ip.trim();
    assert!(!ip.is_empty(), "httpbin.org resolved");
    let by_ip = |e: &E2e| {
        let probe = format!("wget -S -T 8 -O /dev/null http://{ip}/ 2>&1 | grep -q 'HTTP/'");
        e.sbt(&["exec", &e.name, "sh", "-c", &probe])
            .status
            .success()
    };
    assert!(by_ip(&e), "live allow reaches {ip}");
    // The last host leaves a host-less list: closed live, by name and by its IP (no restart).
    e.ok(&["policy", "rm", "network", "--resource", "httpbin.org"]);
    assert!(!reachable(&e, "https://httpbin.org"), "live rm");
    assert!(!by_ip(&e), "live rm closes {ip} (httpbin.org's address)");
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
        !reachable(&e, "https://httpbin.org"),
        "balanced blocks httpbin.org"
    );
    let log = e.ok(&["policy", "log", &e.name]);
    assert!(log.contains("httpbin.org"), "{log}");
}

#[test]
#[ignore = "boots real VMs; run with `just e2e`"]
pub(crate) fn ports_publish_live() {
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
pub(crate) fn secrets_are_placeholders_in_the_guest() {
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
pub(crate) fn root_sh(sb: &str, script: &str) -> std::process::Output {
    let machine = format!("sbx-{sb}");
    let args = [
        "machine", "exec", "--name", &machine, "-u", "root", "--", "sh", "-c", script,
    ];
    Command::new("smolvm").args(args).output().unwrap()
}

/// `root_sh` that must succeed.
pub(crate) fn guest_root(sb: &str, script: &str) {
    let out = root_sh(sb, script);
    assert!(
        out.status.success(),
        "{script} in {sb}:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// A create whose first start fails removes the sandbox, and the remote `--clone` added with it:
/// Alpine has no `agent` user or git, so the clone inside the VM fails.
#[test]
#[ignore = "boots real VMs; run with `just e2e`"]
pub(crate) fn a_failed_clone_create_removes_the_sandbox() {
    let e = E2e::new("clonefail");
    let ws = e.workspace();
    let ws = ws.to_str().unwrap();
    let remote = format!("sandbox-{}", e.name);
    std::fs::write(e.workspace().join("README"), "host\n").unwrap();
    e.git_ok(&["init", "-q", "-b", "main"]);
    e.git_ok(&["add", "README"]);
    e.git_ok(&["commit", "-q", "-m", "host commit"]);

    let archive = Image::alpine_agent_archive();
    let out = e.sbt(&[
        "create",
        "--clone",
        "shell",
        ws,
        "--name",
        &e.name,
        "-t",
        archive.to_str().unwrap(),
        "--cpus",
        "1",
        "-m",
        "1g",
    ]);
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{err}");
    assert!(err.contains("cloning the repo in the sandbox"), "{err}");
    assert!(err.contains("the sandbox was removed"), "{err}");
    assert!(!e.ok(&["ls", "-q"]).lines().any(|n| n == e.name), "removed");
    assert!(
        !e.git_ok(&["remote"]).lines().any(|r| r == remote),
        "remote dropped with the sandbox"
    );
}

#[test]
#[ignore = "boots real VMs; run with `just e2e`"]
pub(crate) fn clone_round_trip() {
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

    e.create_clone();
    assert!(
        e.git_ok(&["remote"]).lines().any(|r| r == remote),
        "remote added"
    );

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
