//! End-to-end tests that boot real smolvm VMs. Ignored by default; run with `just e2e`.
//! Machines are small (1 CPU, 1 GiB) so they fit GitHub's private-repo runners.
//! The network policy test needs internet (example.com), and the secrets test needs httpbin.org.

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
        Command::new(env!("CARGO_BIN_EXE_smolbento"))
            .args(args)
            .current_dir(self.workspace())
            .env("SMOLBENTO_CONFIG_DIR", self.dir.path().join("config"))
            .env("SMOLBENTO_CACHE_DIR", self.dir.path().join("cache"))
            .env("SMOLBENTO_DOCKER", "false")
            .output()
            .unwrap()
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
