use super::*;
use crate::bridge_agent::unit_files;

#[test]
#[ignore = "boots real VMs; run with `just e2e`"]
pub(crate) fn lifecycle_exec_and_same_path_mount() {
    let e = E2e::new("life");
    e.create_alpine_offline();
    assert_eq!(e.state(), "running");

    std::fs::write(e.workspace().join("from-host"), "hello").unwrap();
    assert_eq!(e.ok(&["exec", &e.name, "cat", "from-host"]), "hello");
    e.sh_ok(&e.name, "echo back > from-guest");
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
    // command's exit status is bento's.
    let big = e.ok(&["exec", &e.name, "head", "-c", "12000000", "/dev/zero"]);
    assert_eq!(big.len(), 12_000_000);
    let out = e.sh(&e.name, "echo to-err >&2; exit 7");
    assert_eq!(out.status.code(), Some(7));
    assert_eq!(err_text(&out), "to-err\n");

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
    e.create_alpine_offline();
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

    // And copies back out, through an archive (smolvm's cp downloads single files only).
    let out = e.dir.path().join("out");
    e.ok(&[
        "cp",
        &format!("{}:/tmp/tree", e.name),
        out.to_str().unwrap(),
    ]);
    assert_eq!(
        std::fs::read_to_string(out.join("sub/f")).unwrap(),
        "nested"
    );
}

#[test]
#[ignore = "runs bento diagnose against smolvm; run with `just e2e`"]
pub(crate) fn diagnose_passes() {
    let e = E2e::new("diag");
    let out = e.ok(&["diagnose"]);
    assert!(!out.contains("FAIL"), "{out}");
}

#[test]
#[ignore = "downloads and runs the pinned smolvm; run with `just e2e`"]
pub(crate) fn the_pinned_smolvm_runs_from_smolbentos_home() {
    // Even when the run picks its own smolvm (`SMOLBENTO_SMOLVM`), this checks the pinned one.
    let out = smolvm_command()
        .arg("--version")
        .env_remove("SMOLBENTO_SMOLVM")
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", err_text(&out));
    let version = smolbento::smolvm::pin::pin().version.as_str();
    assert!(out_text(&out).contains(version), "{out:?}");
    let bin = Path::new(&smolvm_home())
        .join("engine")
        .join(version)
        .join("smolvm");
    assert!(bin.is_file(), "{} missing", bin.display());
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

/// Whether `url` gives any HTTP answer, an error status included, from `e`'s sandbox: the connection
/// was let through. `reachable` needs a 2xx, which a rate-limited API doesn't always give.
pub(crate) fn http_answers(e: &E2e, url: &str) -> bool {
    let probe = format!("wget -S -T 8 -O /dev/null {url} 2>&1 | grep -q 'HTTP/'");
    e.sh(&e.name, &probe).status.success()
}

#[test]
#[ignore = "boots real VMs and reaches httpbin.org; run with `just e2e`"]
pub(crate) fn policy_changes_apply_on_start_and_live() {
    let e = E2e::new("pol");
    e.create_alpine_offline();
    e.ok(&["policy", "init", "deny-all"]);
    e.ok(&["stop", &e.name]); // allow-all -> restricted applies on the next start
    assert!(!reachable(&e, "https://httpbin.org"), "deny-all blocks");
    e.ok(&["policy", "allow", "network", "httpbin.org"]);
    assert!(reachable(&e, "https://httpbin.org"), "live allow");
    // The last host leaves a host-less list: closed live (no restart).
    e.ok(&["policy", "rm", "network", "--resource", "httpbin.org"]);
    assert!(!reachable(&e, "https://httpbin.org"), "live rm");
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

/// smolvm's allow list admits a host's address live, and closes it with the last host. smolvm-only:
/// the probe sends `Host: <ip>`, which a hosted sandbox's egress process judges by the rules, and
/// they allow httpbin.org by name only (sbx denies it too).
#[test]
#[ignore = "boots real VMs and reaches httpbin.org; run with `just e2e`"]
pub(crate) fn smolvm_allow_list_opens_and_closes_an_address_live() {
    let mut e = E2e::new("polip");
    e.vars.push(("SMOLBENTO_NETWORK_EGRESS", "smolvm".into()));
    e.ok(&["policy", "init", "deny-all"]);
    e.create_alpine_offline();
    e.ok(&["policy", "allow", "network", "httpbin.org"]);
    let ip = e.sh_ok(&e.name, HTTPBIN_IP);
    let ip = ip.trim();
    assert!(!ip.is_empty(), "httpbin.org resolved");
    let url = format!("http://{ip}/");
    assert!(http_answers(&e, &url), "live allow reaches {ip}");
    // The last host leaves a host-less list: closed live.
    e.ok(&["policy", "rm", "network", "--resource", "httpbin.org"]);
    assert!(
        !http_answers(&e, &url),
        "live rm closes {ip} (httpbin.org's address)"
    );
}

#[test]
#[ignore = "boots real VMs; run with `just e2e`"]
pub(crate) fn ports_publish_live() {
    let e = E2e::new("port");
    e.create_alpine_offline();
    smolvm_ok(&[
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
    let mut body = Ok(String::new());
    wait_until(30, || {
        body = host_get(port, "/");
        body.as_ref().is_ok_and(|b| b.contains("hi-from-guest"))
    });
    let body = body.expect("published port answers");
    assert!(body.contains("hi-from-guest"), "{body}");
    e.ok(&["ports", &e.name, "--unpublish", &format!("{port}:8000")]);
}

/// A port published without a host port gets a new one at each start, as in sbx: here the old one
/// is taken while the sandbox is stopped, and the start still succeeds on a new one.
#[test]
#[ignore = "boots real VMs; run with `just e2e`"]
pub(crate) fn a_picked_port_is_picked_again_at_each_start() {
    let e = E2e::new("portre");
    e.create_alpine_offline();
    e.ok(&["ports", &e.name, "--publish", "8000"]);
    let host_port = || -> u16 {
        let rows: serde_json::Value =
            serde_json::from_str(&e.ok(&["ports", &e.name, "--json"])).unwrap();
        let row = rows
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["sandbox_port"] == 8000)
            .expect("8000 published");
        row["host_port"].as_u64().unwrap() as u16
    };
    let old = host_port();
    e.ok(&["stop", &e.name]);
    // Something else takes it while the sandbox is stopped.
    let _taken = std::net::TcpListener::bind(("127.0.0.1", old)).expect("old port free");
    e.ok(&["start", &e.name]);
    let new = host_port();
    assert_ne!(new, old);
    smolvm_ok(&[
        "machine",
        "exec",
        "--name",
        &e.machine(),
        "-d",
        "--",
        "sh",
        "-c",
        "while true; do printf 'HTTP/1.0 200 OK\\r\\n\\r\\nhi-again\\n' | nc -l -p 8000; done",
    ]);
    let mut body = Ok(String::new());
    wait_until(30, || {
        body = host_get(new, "/");
        body.as_ref().is_ok_and(|b| b.contains("hi-again"))
    });
    assert!(body.expect("new port answers").contains("hi-again"));
}

/// The pid of this sandbox's egress process, from the service manager; `None` while it isn't running.
pub(crate) fn egress_pid(unit: &std::path::Path) -> Option<u32> {
    let stem = unit.file_stem()?.to_str()?;
    let out = if cfg!(target_os = "macos") {
        let uid = smolbento::util::host_uid();
        let o = std::process::Command::new("launchctl")
            .args(["print", &format!("gui/{uid}/{stem}")])
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&o.stdout).into_owned();
        let line = text
            .lines()
            .find(|l| l.trim_start().starts_with("pid = "))?;
        line.rsplit('=').next()?.trim().to_string()
    } else {
        let o = std::process::Command::new("systemctl")
            .args([
                "--user",
                "show",
                "-p",
                "MainPID",
                "--value",
                &format!("{stem}.service"),
            ])
            .output()
            .ok()?;
        String::from_utf8_lossy(&o.stdout).trim().to_string()
    };
    out.parse().ok().filter(|p| *p > 0)
}

#[test]
#[ignore = "boots real VMs and needs httpbin.org; run with `just e2e`"]
pub(crate) fn hosted_egress_swaps_a_credential() {
    let mut e = E2e::new("hegr");
    e.vars.push(("SMOLBENTO_NETWORK_EGRESS", "hosted".into()));
    e.own_httpbin_secret("TOK", BASIC_SECRET);
    e.create_alpine_offline();
    assert!(basic_auth_ok(&e, &e.name, "TOK", "real-secret-xyz"));
    let seen = e.sh_ok(&e.name, "printf %s \"$TOK\"");
    assert!(seen.starts_with("SMOL_PLACEHOLDER_"), "{seen}");
    assert!(!seen.contains("real-secret"), "{seen}");

    let unit = unit_files(&e, &e.name)
        .into_iter()
        .find(|u| u.to_string_lossy().contains("egress"))
        .expect("a hosted sandbox has an egress unit");
    // Socket activation restarts a killed egress process on the next connection.
    let pid = egress_pid(&unit).expect("the egress process runs after a request");
    let _ = std::process::Command::new("kill")
        .args(["-9", &pid.to_string()])
        .status();
    assert!(
        basic_auth_ok(&e, &e.name, "TOK", "real-secret-xyz"),
        "egress is restarted by its socket"
    );

    // A new value applies at once: `secret set` restarts the egress process.
    let out = e.own_httpbin_secret("TOK", "dXNlcjpyb3RhdGVkLXh5eg==");
    let now = format!("Applied to {} now", e.name);
    assert!(out.contains(&now), "{out}");
    assert!(basic_auth_ok(&e, &e.name, "TOK", "rotated-xyz"));
    assert!(!basic_auth_ok(&e, &e.name, "TOK", "real-secret-xyz"));
    // A removed one is gone at once.
    let out = e.ok(&["secret", "rm", "tok", "--sandbox", &e.name]);
    let gone = format!("Running sandboxes {} no longer send it", e.name);
    assert!(out.contains(&gone), "{out}");
    assert!(!basic_auth_ok(&e, &e.name, "TOK", "rotated-xyz"));

    e.ok(&["rm", "-f", &e.name]);
    assert!(unit_files(&e, &e.name).is_empty(), "units go with rm");
    assert!(!e.dir.path().join("data/egress").join(&e.name).exists());
}

/// Sandbox `sb`'s egress log: a line per connection its egress process denied.
pub(crate) fn egress_log(e: &E2e, sb: &str) -> String {
    let log = e.dir.path().join("data/egress").join(sb).join("egress.log");
    std::fs::read_to_string(log).unwrap()
}

/// A hosted sandbox's egress process enforces a rule's port, which smolvm can't.
#[test]
#[ignore = "boots real VMs and reaches github.com; run with `just e2e`"]
pub(crate) fn hosted_port_rule() {
    let e = E2e::new("hport");
    e.ok(&["policy", "init", "deny-all"]);
    e.ok(&["policy", "allow", "network", "github.com:443"]);
    e.create_alpine_offline();
    assert!(reachable(&e, "https://github.com"), "port 443 is allowed");
    assert!(!reachable(&e, "http://github.com"), "port 80 isn't");
    let log = egress_log(&e, &e.name);
    assert!(log.contains("deny github.com:80: "), "{log}");
}

/// A name deny inside an allowed wildcard closes the connection once the guest sends its SNI.
#[test]
#[ignore = "boots real VMs and reaches github.com; run with `just e2e`"]
pub(crate) fn hosted_host_deny_inside_wildcard() {
    let e = E2e::new("hwild");
    e.ok(&["policy", "init", "deny-all"]);
    e.ok(&["policy", "allow", "network", "**.github.com"]);
    e.ok(&["policy", "deny", "network", "gist.github.com"]);
    e.create_alpine_offline();
    // Any answer counts: shared CI addresses often get api.github.com's 403 rate limit.
    let api = http_answers(&e, "https://api.github.com");
    assert!(api, "the wildcard allows api.github.com");
    assert!(
        !http_answers(&e, "https://gist.github.com"),
        "gist is denied"
    );
    let log = egress_log(&e, &e.name);
    assert!(log.contains("deny gist.github.com:443: "), "{log}");
}

/// An address deny with a port is decided before the guest sends anything: the egress process
/// answers smolvm's preamble with `ECONNREFUSED`, and the log line shows the deny came from it.
#[test]
#[ignore = "boots real VMs and reaches 1.1.1.1; run with `just e2e`"]
pub(crate) fn hosted_cidr_deny_is_a_refused_connect() {
    let e = E2e::new("hcidr");
    e.ok(&["policy", "deny", "network", "1.1.1.0/24:443"]);
    e.create_alpine_offline();
    // http_answers, not reachable: 1.1.1.1 redirects port 80 to 443.
    assert!(http_answers(&e, "http://1.1.1.1/"), "port 80 is allowed");
    assert!(!reachable(&e, "https://1.1.1.1"), "port 443 isn't");
    let log = egress_log(&e, &e.name);
    assert!(log.contains("deny 1.1.1.1:443: "), "{log}");
}

/// A `localhost:PORT` rule opens that host port alone to a hosted sandbox, where smolvm would open
/// every port.
#[test]
#[ignore = "boots real VMs; run with `just e2e`"]
pub(crate) fn hosted_localhost_port() {
    let (a, b) = (
        super::network::host_service(),
        super::network::host_service(),
    );
    let e = E2e::new("hlo");
    e.ok(&["policy", "init", "deny-all"]);
    e.ok(&["policy", "allow", "network", &format!("localhost:{a}")]);
    e.create_alpine_offline();
    let url = |p: u16| format!("http://host.docker.internal:{p}/");
    assert!(reachable(&e, &url(a)), "the rule's port");
    assert!(!reachable(&e, &url(b)), "another host port");
}

/// A deny applies to a running hosted sandbox from its next connection.
#[test]
#[ignore = "boots real VMs and reaches httpbin.org; run with `just e2e`"]
pub(crate) fn hosted_policy_change_is_live() {
    let e = E2e::new("hlive");
    e.create_alpine_offline();
    let boot = root_out(&e.name, "cat /proc/sys/kernel/random/boot_id");
    assert!(reachable(&e, "https://httpbin.org"), "allow-all");
    // Scoped: a global deny is refused while another test's sandbox binds an httpbin secret.
    e.ok(&[
        "policy",
        "deny",
        "network",
        "--sandbox",
        &e.name,
        "httpbin.org",
    ]);
    assert!(!reachable(&e, "https://httpbin.org"), "denied live");
    assert_eq!(
        root_out(&e.name, "cat /proc/sys/kernel/random/boot_id"),
        boot,
        "no restart"
    );
}

/// A fork of a hosted sandbox gets its own egress process: it swaps the parent's credential and
/// keeps the parent's deny.
#[test]
#[ignore = "boots real VMs and needs httpbin.org; run with `just e2e`"]
pub(crate) fn hosted_fork_swaps_and_enforces() {
    let e = E2e::new("hfork");
    e.git_repo();
    e.own_httpbin_secret("TOK", BASIC_SECRET);
    e.create_clone();
    let wiki = "https://www.wikipedia.org";
    assert!(reachable(&e, wiki), "allow-all");
    e.ok(&[
        "policy",
        "deny",
        "network",
        "--sandbox",
        &e.name,
        "www.wikipedia.org",
    ]);
    assert!(!reachable(&e, wiki), "the parent's deny");

    let forks = Machines(vec![format!("{}-fork-1", e.name)]);
    let f = &forks.0[0];
    assert_eq!(e.ok(&["fork", &e.name]).trim(), f.as_str());
    assert!(
        unit_files(&e, f)
            .iter()
            .any(|u| u.to_string_lossy().contains("egress")),
        "the fork has its own egress unit"
    );
    assert!(
        basic_auth_ok(&e, f, "TOK", "real-secret-xyz"),
        "the fork swaps"
    );
    let wget = format!("wget -q -T 8 -O /dev/null {wiki}");
    assert!(
        !e.sh(f, &wget).status.success(),
        "the deny holds in the fork"
    );
    e.ok(&["rm", "-f", f]);
    assert!(unit_files(&e, f).is_empty(), "the fork's units go with rm");
}

#[test]
#[ignore = "boots real VMs and needs httpbin.org; run with `just e2e`"]
pub(crate) fn secrets_are_placeholders_in_the_guest() {
    // smolvm's live credential binding: a hosted sandbox needs a recreate for a new service.
    let mut e = E2e::new("sec");
    e.vars.push(("SMOLBENTO_NETWORK_EGRESS", "smolvm".into()));
    e.ok(&["policy", "init", "balanced"]);
    e.own_httpbin_secret("TOK", BASIC_SECRET);
    e.create_alpine_offline();
    let seen = e.sh_ok(&e.name, "printf %s \"$TOK\"");
    assert!(seen.starts_with("SMOL_PLACEHOLDER_"), "{seen}");
    assert!(
        basic_auth_ok(&e, &e.name, "TOK", "real-secret-xyz"),
        "the host substitutes the secret"
    );
    assert!(
        !basic_auth_ok(&e, &e.name, "TOK", "other"),
        "httpbin checks the password"
    );
    // A new value reaches the running sandbox at once (smolvm's `machine credentials refresh`).
    let out = e.own_httpbin_secret("TOK", "dXNlcjpyb3RhdGVkLXh5eg==");
    let now = format!("Applied to {} now", e.name);
    assert!(out.contains(&now), "{out}");
    assert!(
        basic_auth_ok(&e, &e.name, "TOK", "rotated-xyz"),
        "the running sandbox uses the new value"
    );
    assert!(!basic_auth_ok(&e, &e.name, "TOK", "real-secret-xyz"));
    // A service it was created without is bound at once (`machine credentials add`).
    let out = e.own_httpbin_secret("TOK2", "dXNlcjpzZWNvbmQteHl6");
    assert!(out.contains(&now), "{out}");
    assert!(basic_auth_ok(&e, &e.name, "TOK2", "second-xyz"));
    // A removed one stops being sent at once.
    let out = e.ok(&["secret", "rm", "tok", "--sandbox", &e.name]);
    let gone = format!("Running sandboxes {} no longer send it", e.name);
    assert!(out.contains(&gone), "{out}");
    assert!(
        !basic_auth_ok(&e, &e.name, "TOK", "rotated-xyz"),
        "the removed value isn't sent"
    );
}

/// A sandbox that booted with no secrets records one set later, and uses it from its next start.
#[test]
#[ignore = "boots real VMs and needs httpbin.org; run with `just e2e`"]
pub(crate) fn a_secret_set_after_create_is_bound_without_recreating() {
    // smolvm binds it at the next start (a hosted sandbox binds it live: see below).
    let mut e = E2e::new("secadd");
    e.vars.push(("SMOLBENTO_NETWORK_EGRESS", "smolvm".into()));
    e.ok(&["policy", "init", "balanced"]);
    e.create_alpine_offline();
    // Running, but booted with no bindings: smolvm takes the new one from its next start.
    let out = e.own_httpbin_secret("TOK", BASIC_SECRET);
    let next = format!("Applies to {} on their next start", e.name);
    assert!(out.contains(&next), "{out}");
    e.ok(&["stop", &e.name]);
    assert!(
        basic_auth_ok(&e, &e.name, "TOK", "real-secret-xyz"),
        "bound from its next start"
    );
}

/// A running hosted sandbox binds a secret set after create at once: its egress process restarts
/// with the binding, and a new command sees the placeholder.
#[test]
#[ignore = "boots real VMs and needs httpbin.org; run with `just e2e`"]
pub(crate) fn a_secret_set_after_create_binds_a_hosted_sandbox_live() {
    let mut e = E2e::new("secaddh");
    e.vars.push(("SMOLBENTO_NETWORK_EGRESS", "hosted".into()));
    e.ok(&["policy", "init", "balanced"]);
    e.create_alpine_offline();
    let out = e.own_httpbin_secret("TOK", BASIC_SECRET);
    let now = format!("Applied to {} now", e.name);
    assert!(out.contains(&now), "{out}");
    assert!(
        basic_auth_ok(&e, &e.name, "TOK", "real-secret-xyz"),
        "bound live, without a restart"
    );
}

/// A create whose first start fails removes the sandbox, and the remote `--clone` added with it:
/// this Alpine has no git, so the clone inside the VM fails.
#[test]
#[ignore = "boots real VMs; run with `just e2e`"]
pub(crate) fn a_failed_clone_create_removes_the_sandbox() {
    let e = E2e::new("clonefail");
    let remote = format!("sandbox-{}", e.name);
    e.git_repo();

    let archive = Image::alpine_agent_archive();
    let head = ["--clone", "-t", archive.to_str().unwrap(), "shell"];
    let out = e.try_create(&e.name, &head);
    let err = err_text(&out);
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
    e.git_repo();
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
    let tok = e.sh_ok(&e.name, "printf %s \"$TOK\"");
    assert!(tok.starts_with("SMOL_PLACEHOLDER_"), "{tok}");
    e.guest_commit(&e.name, "guest-one");
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
    e.guest_commit(&e.name, "guest-two");
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
