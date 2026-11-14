use super::*;

/// The guest's startup log (empty until the startup runner first writes it).
pub(crate) fn startup_log(e: &E2e) -> String {
    let out = root_sh(&e.name, "cat /var/log/sbx-kit-startup.log 2>/dev/null");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Number of dockerd processes in the guest.
pub(crate) fn dockerds(e: &E2e) -> usize {
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
pub(crate) fn docker_kit_runs_dockerd_across_restarts() {
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
pub(crate) fn assert_one_dockerd(e: &E2e, what: &str) {
    let until = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        assert_eq!(dockerds(e), 1, "{what}");
        if std::time::Instant::now() >= until {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
}

#[test]
#[ignore = "boots real VMs and pulls alpine; run with `just e2e`"]
pub(crate) fn published_workload_kit_runs_its_command() {
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
pub(crate) fn mixin_layer_is_visible_in_the_guest() {
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
pub(crate) struct BuilderGuard(pub(crate) bool);

impl BuilderGuard {
    pub(crate) fn new() -> BuilderGuard {
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
pub(crate) fn local_v3_kit_builds_in_the_builder_sandbox() {
    let e = E2e::new("build");
    let _builder = BuilderGuard::new();
    // Layers are composed onto the base image, which must then be a registry reference.
    let _reg = Registry::start(&e);
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

/// A kit's `host-mount@1` directory is shared by its sandboxes and outlives them; `--mount`
/// replaces it with your own directory.
#[test]
#[ignore = "boots real VMs and pulls debian; run with `just e2e`"]
pub(crate) fn kit_host_mount_shared_and_kept() {
    const SHARED: &str = "/home/agent/.e2e-shared";
    let e = E2e::new("hostmount");
    // A pushed kit rather than a `build:` one, so this test stays out of the serial builder group
    // (building is covered by `local_v3_kit_builds_in_the_builder_sandbox`).
    let reg = Registry::start(&e);
    let base = Image::pull("debian:bookworm-slim");
    let passwd = base.file("etc/passwd") + "agent:x:1000:1000::/home/agent:/bin/bash\n";
    let group = base.file("etc/group") + "agent:x:1000:\n";
    let mut image = base.with_files(&[
        ("etc/passwd", &passwd),
        ("etc/group", &group),
        ("home/agent/.keep", ""),
    ]);
    let c = &mut image.config["config"];
    c["User"] = "agent".into();
    c["Entrypoint"] = serde_json::Value::Null;
    c["Cmd"] = serde_json::json!(["bash"]);
    let kit = reg.push(
        "hostmount",
        image,
        descriptor(
            "workload",
            &[],
            serde_json::json!([
                {"type": "com.docker.sandbox/sbx@1"},
                {"type": "com.docker.sandbox/host-mount@1", "config": {"path": SHARED}},
            ]),
        ),
    );
    let (a, b) = (format!("{}-a", e.name), format!("{}-b", e.name));
    struct Cleanup<'a>([&'a str; 2]);
    impl Drop for Cleanup<'_> {
        fn drop(&mut self) {
            for n in self.0 {
                let _ = Command::new("smolvm")
                    .args(["machine", "delete", "-f", "-n", &format!("sbx-{n}")])
                    .output();
            }
        }
    }
    let _cleanup = Cleanup([&a, &b]);
    let ws = e.workspace();
    let create = |name: &str, extra: &[&str]| {
        let mut args = vec![
            "create",
            &kit,
            ws.to_str().unwrap(),
            "--name",
            name,
            "--cpus",
            "1",
            "-m",
            "1g",
        ];
        args.extend(extra);
        e.ok(&args);
    };
    let mounts = |name: &str| -> serde_json::Value {
        let out = e.ok(&["inspect", "--json", name]);
        serde_json::from_str::<serde_json::Value>(&out).unwrap()["mounts"].clone()
    };

    // The agent in one sandbox writes; another sandbox of the same kit reads it.
    create(&a, &[]);
    create(&b, &[]);
    // A published kit's directories are keyed by `<registry>/<repository>`, as in sbx.
    let r: oci_client::Reference = kit.parse().unwrap();
    let managed = smolbento::kits::host_mount::managed_dir(
        &e.dir.path().join("data/kit-host-mounts"),
        &format!("{}/{}", r.registry(), r.repository()),
        SHARED,
    );
    assert_eq!(mounts(&a)[SHARED], managed.to_str().unwrap());
    let note = format!("{SHARED}/note");
    e.ok(&["exec", &a, "sh", "-c", &format!("echo from-a > {note}")]);
    assert_eq!(e.ok(&["exec", &b, "cat", &note]), "from-a\n");

    // Removing both sandboxes keeps the directory and its file.
    e.ok(&["rm", "-f", &a, &b]);
    assert_eq!(
        std::fs::read_to_string(managed.join("note")).unwrap(),
        "from-a\n"
    );

    // `--mount` binds a directory of yours instead.
    let mine = e.dir.path().join("mine");
    std::fs::create_dir_all(&mine).unwrap();
    let mine = mine.canonicalize().unwrap();
    std::fs::write(mine.join("note"), "from-host\n").unwrap();
    let bind = format!("{}:{SHARED}", mine.display());
    create(&e.name, &["--mount", &bind]);
    assert_eq!(e.ok(&["exec", &e.name, "cat", &note]), "from-host\n");
    assert_eq!(mounts(&e.name)[SHARED], mine.to_str().unwrap());
}

/// The keychain smolbento's secret store uses here (src/secrets/store.rs `platform`): macOS
/// `security`, or Linux `secret-tool` with a session bus. `None` means the 0600 file store, which
/// lives in the per-test config dir.
pub(crate) fn os_keychain(op: &str, account: &str) -> Option<Command> {
    if cfg!(target_os = "macos") {
        let mut c = Command::new("/usr/bin/security");
        c.args([op, "-s", "smolbento", "-a", account]);
        return Some(c);
    }
    let on_path = Command::new("sh")
        .args(["-c", "command -v secret-tool"])
        .output()
        .is_ok_and(|o| o.status.success());
    if std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_none() || !on_path {
        return None;
    }
    let op = if op == "find-generic-password" {
        "lookup"
    } else {
        "clear"
    };
    let mut c = Command::new("secret-tool");
    c.args([op, "service", "smolbento", "account", account]);
    Some(c)
}

/// Whether the keychain has smolbento's item ACCOUNT. Its value is never read or printed.
pub(crate) fn os_keychain_has(account: &str) -> bool {
    os_keychain("find-generic-password", account).is_some_and(|mut c| {
        c.output().is_ok_and(|o| {
            o.status.success() && (cfg!(target_os = "macos") || !o.stdout.is_empty())
        })
    })
}

pub(crate) fn os_keychain_delete(account: &str) {
    if let Some(mut c) = os_keychain("delete-generic-password", account) {
        let _ = c.output();
    }
}

#[test]
#[ignore = "boots real VMs and pulls from dhi.io with a login; run with `just e2e`"]
pub(crate) fn local_kit_builds_from_a_registry_that_needs_a_login() {
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
    // The value goes to the OS keychain, which is shared with your own smolbento whatever the
    // config dir: never touch a dhi.io login you stored yourself.
    const ACCOUNT: &str = "registry:dhi.io";
    if os_keychain_has(ACCOUNT) {
        eprintln!("skipped: your keychain already has a smolbento dhi.io login; not touching it");
        return;
    }
    let token = std::fs::read(&token_file).unwrap();
    // This recreates your real `_builder` (a global smolvm machine); your next real build
    // recreates it again.
    let e = E2e::new("dhi");
    let _builder = BuilderGuard::new();
    e.one_off_images();

    // Removed on every exit path; directly from the keychain too, in case `secret rm` refuses
    // after a partial `secret set`.
    struct RegistryCleanup<'a>(&'a E2e);
    impl Drop for RegistryCleanup<'_> {
        fn drop(&mut self) {
            let _ = self.0.sbt(&["secret", "rm", "--registry", "dhi.io"]);
            os_keychain_delete(ACCOUNT);
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
#[ignore = "boots real VMs and needs httpbin.org; run with `just e2e`"]
pub(crate) fn install_phase_network_closes_after_install() {
    let e = E2e::new("instnet");
    e.ok(&["policy", "init", "deny-all"]);
    let reg = Registry::start(&e);
    // During install: httpbin.org by name, then by the IP it resolved to (any HTTP answer).
    let probe = r#"set -e
wget -q -T 15 -O /dev/null https://httpbin.org
ip=$(nslookup httpbin.org 2>/dev/null | awk '/^Address/ && $NF !~ /:/ {print $NF}' | head -n 1)
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
                 "config": {"install": {"allow": ["httpbin.org"]}}},
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
    assert!(!ip.is_empty(), "the install hook reached httpbin.org");

    assert!(
        !reachable(&e, "https://httpbin.org"),
        "httpbin.org is closed after install"
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
        "{ip} (httpbin.org's address) is closed after install"
    );
    // `policy ls` never lists install-phase rules (as sbx), so check the stored policy too.
    let rules = e.ok(&["policy", "ls"]);
    assert!(
        !rules.contains("httpbin.org"),
        "install rules not listed:\n{rules}"
    );
    let stored = std::fs::read_to_string(e.dir.path().join("config/policy.toml")).unwrap();
    assert!(
        !stored.contains("httpbin.org"),
        "install rules removed:\n{stored}"
    );
}

#[test]
#[ignore = "boots real VMs and needs httpbin.org; run with `just e2e`"]
pub(crate) fn install_only_credential_is_gone_after_install() {
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
#[ignore = "boots real VMs and needs httpbin.org; run with `just e2e`"]
pub(crate) fn kit_add_applies_network_and_hooks_live() {
    let e = E2e::new("kitadd");
    e.create_alpine();
    e.ok(&["policy", "init", "deny-all"]);
    e.ok(&["stop", &e.name]); // allow-all -> restricted applies on the next start
    e.ok(&["start", &e.name]);
    assert!(!reachable(&e, "https://httpbin.org"), "deny-all blocks");
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
    allow: [httpbin.org]
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
    assert!(reachable(&e, "https://httpbin.org"), "the kit's allow rule");
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
    assert!(wide.contains("httpbin.org"), "{wide}");
}

/// Debian (it has bash and `usermod`) plus accounts `somebody` (uid 1234) and `numbered`
/// (uid 4321), a `BASH_ENV` file, `WORKDIR /x`, and env vars `E2E_DECLARED` and `E2E_UNDECLARED`,
/// published as a workload kit whose image `USER` is `user`. Its command reports who and where it
/// runs, whether bash sourced `BASH_ENV`, and writes a file in the workspace.
pub(crate) fn image_user_kit(
    reg: &Registry,
    repo: &str,
    user: &str,
    lifecycle: serde_json::Value,
) -> String {
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
    pub(crate) fn create_workload(&self, kit: &str) {
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

    /// Runs the workload's agent; asserts it ran as `user` with
    /// `BASH_ENV` sourced, in the workspace, and could write there.
    pub(crate) fn assert_agent_runs_as(&self, user: &str) {
        let ws = self.workspace();
        let run = self.sbt(&["run", "--name", &self.name]);
        if !run.status.success() {
            // What the guest saw, so a failure on another host (e.g. Linux CI) explains itself.
            let probe = "id; id agent; ls -lnd . ..; grep -E ' virtiofs | 9p ' /proc/mounts; \
                         cat /proc/self/uid_map /proc/self/gid_map 2>&1; \
                         touch probe-$(id -u) 2>&1; ls -ln";
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
        assert_eq!(meta.uid(), smolbento::util::host_uid(), "owned by you");
    }
}

/// sbx #3 and #12: a v3 workload's agent runs as the image `USER` under bash (so `BASH_ENV` is
/// sourced) in the workspace. Install hooks run in `WORKDIR` with a clean environment (the
/// baseline plus declared vars); startup hooks get the whole container environment.
#[test]
#[ignore = "boots real VMs and pulls debian; run with `just e2e`"]
pub(crate) fn v3_workload_runs_as_its_image_user_with_bash_env() {
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
pub(crate) fn numeric_image_user_runs_as_its_account() {
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
pub(crate) fn failing_startup_hook_fails_the_start() {
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
        Image::alpine_agent_archive().to_str().unwrap(),
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

/// sbx #13: a v2 startup hook without `user:` runs as the agent account, and it doesn't keep the sandbox from starting.
#[test]
#[ignore = "boots real VMs and pulls alpine; run with `just e2e`"]
pub(crate) fn v2_startup_hook_runs_as_agent_by_default() {
    let e = E2e::new("v2user");
    let kit = e.dir.path().join("e2e-v2-user");
    std::fs::create_dir_all(&kit).unwrap();
    std::fs::write(
        kit.join("spec.yaml"),
        r#"schemaVersion: "2"
kind: mixin
name: e2e-v2-user
setup:
  startup:
    - command: [sh, -c, "id -un > /tmp/e2e-started-as"]
"#,
    )
    .unwrap();
    e.create_with_kits(&[kit.to_str().unwrap()]);
    e.ok(&["start", &e.name]);
    assert_eq!(e.state(), "running");
    let uid = smolbento::util::host_uid();
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
pub(crate) fn mixin_agent_context_sits_beside_the_workspace() {
    let e = E2e::new("ctx");
    let kit = e.dir.path().join("e2e-ctx");
    std::fs::create_dir_all(&kit).unwrap();
    std::fs::write(
        kit.join("spec.yaml"),
        r#"schemaVersion: "2"
kind: mixin
name: e2e-ctx
agentInstructions:
  content: "Use the e2e tools."
"#,
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
pub(crate) fn kit_arg_errors_stop_create() {
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

    // As in sbx: a local kit is a path (`../e2e-args` from the workspace).
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
    // Where the agent goes, a bare word is an agent even with that directory present; where
    // only a kit goes, the directory is read (here an empty one, so it isn't a kit).
    std::fs::create_dir_all(e.workspace().join("e2e-args")).unwrap();
    fails(
        &["create", "e2e-args", ws, "--name", &e.name],
        "unknown agent \"e2e-args\"",
    );
    fails(
        &[
            "create", "shell", ws, "--name", &e.name, "--kit", "e2e-args",
        ],
        "isn't a kit: no spec.yaml or kit descriptor",
    );
    fails(
        &[
            "create",
            "shell",
            ws,
            "--name",
            &e.name,
            "--kit",
            "e2e-missing",
        ],
        "not a local path and does not look like a registry reference",
    );
}

/// A kit `kit push`es loads with `--kit`, its files included, and comes back with `kit pull`.
#[test]
#[ignore = "boots real VMs and pulls alpine; run with `just e2e`"]
pub(crate) fn a_pushed_kit_pulls_and_runs() {
    let e = E2e::new("push");
    let reg = Registry::start(&e);
    let kit = e.dir.path().join("pushed");
    std::fs::create_dir_all(kit.join("files/home")).unwrap();
    std::fs::write(
        kit.join("spec.yaml"),
        "schemaVersion: \"2\"\nkind: mixin\nname: pushed\n",
    )
    .unwrap();
    std::fs::write(kit.join("files/home/hello"), "from-the-registry\n").unwrap();
    let r = reg.reference("pushed");
    let out = e.ok(&["kit", "push", kit.to_str().unwrap(), &r]);
    assert!(out.starts_with(&format!("Pushed {r} (sha256:")), "{out}");
    e.create_with_kits(&[&r]);
    assert_eq!(
        root_out(&e.name, "cat /home/agent/hello"),
        "from-the-registry\n"
    );
    let out = e.ok(&["kit", "pull", &r, "-o", "out.tar.gz"]);
    assert_eq!(out, format!("Pulled {r} to out.tar.gz\n"));
    let pulled = std::fs::read(e.workspace().join("out.tar.gz")).unwrap();
    let pushed = smolbento::kits::artifact::read_dir(&kit)
        .unwrap()
        .files
        .unwrap();
    assert_eq!(pulled, pushed);
}

/// `kit sign --key` and `kit verify --key` on a pushed kit, through the referrers tag schema
/// (`registry:2` has no referrers API), and `kit push --sign`.
#[test]
#[ignore = "runs a registry VM and cosign; run with `just e2e`"]
pub(crate) fn a_signed_kit_verifies_with_its_key() {
    let has = |tool: &str| {
        std::process::Command::new(tool)
            .arg("version")
            .output()
            .is_ok()
    };
    // The dev shell has both; a missing one fails rather than skips, so CI can't pass unchecked.
    assert!(
        has("cosign") && has("openssl"),
        "needs cosign and openssl on PATH"
    );
    let e = E2e::new("sign");
    let reg = Registry::start(&e);
    let dir = e.dir.path();
    let keypair = |name: &str| {
        let key = dir.join(format!("{name}.pem"));
        let public = dir.join(format!("{name}.pub"));
        let run = |args: &[&str]| {
            let ok = std::process::Command::new("openssl")
                .args(args)
                .status()
                .unwrap();
            assert!(ok.success(), "openssl {args:?}");
        };
        run(&[
            "genpkey",
            "-algorithm",
            "EC",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-out",
            key.to_str().unwrap(),
        ]);
        run(&[
            "pkey",
            "-in",
            key.to_str().unwrap(),
            "-pubout",
            "-out",
            public.to_str().unwrap(),
        ]);
        (key.display().to_string(), public.display().to_string())
    };
    let (key, public) = keypair("signer");
    let (_, other) = keypair("other");
    let kit = dir.join("signed");
    std::fs::create_dir_all(&kit).unwrap();
    std::fs::write(
        kit.join("spec.yaml"),
        "schemaVersion: \"2\"\nkind: mixin\nname: signed\n",
    )
    .unwrap();
    let r = reg.reference("signed");
    e.ok(&["kit", "push", kit.to_str().unwrap(), &r]);

    let out = e.sbt(&["kit", "verify", &r, "--key", &public]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("kit is not signed"));

    assert_eq!(
        e.ok(&["kit", "sign", &r, "--key", &key]),
        format!("Signed {r}\n")
    );
    assert_eq!(
        e.ok(&["kit", "verify", &r, "--key", &public]),
        format!("  ✓ {r} — verified (oci)\n")
    );
    let json: serde_json::Value =
        serde_json::from_str(&e.ok(&["kit", "verify", &r, "--key", &public, "--json"])).unwrap();
    assert_eq!(json["verified"], true, "{json}");

    let out = e.sbt(&["kit", "verify", &r, "--key", &other, "--json"]);
    assert_eq!(out.status.code(), Some(1));
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(json["verified"], false, "{json}");
    assert!(
        json["error"]
            .as_str()
            .unwrap()
            .starts_with("kit signature verification failed"),
        "{json}"
    );

    // A second signature keeps the first in the referrers index.
    let (key2, public2) = keypair("second");
    e.ok(&["kit", "sign", &r, "--key", &key2]);
    e.ok(&["kit", "verify", &r, "--key", &public]);
    e.ok(&["kit", "verify", &r, "--key", &public2]);

    let r2 = reg.reference("signed-at-push");
    let out = e.ok(&[
        "kit",
        "push",
        kit.to_str().unwrap(),
        &r2,
        "--sign",
        "--key",
        &key,
    ]);
    assert!(out.ends_with(&format!("Signed {r2}\n")), "{out}");
    e.ok(&["kit", "verify", &r2, "--key", &public]);

    // kit.requireSignature with this key trusted: the signed kit loads, an unsigned one doesn't.
    let unsigned = reg.reference("unsigned");
    e.ok(&["kit", "push", kit.to_str().unwrap(), &unsigned]);
    e.ok(&["settings", "set", "kit.requireSignature", "true"]);
    let trust = |key: &str| format!(r#"[{{"key":"{key}"}}]"#);
    e.ok(&["settings", "set", "kit.trustedSigners", &trust(&public)]);
    let out = e.sbt(&["kit", "inspect", &r]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    assert!(
        stderr.contains(&format!("✓ {r} — signature verified (key {public})")),
        "{stderr}"
    );
    let out = e.sbt(&["kit", "inspect", &unsigned]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains(&format!("{unsigned} is not signed")),
        "{stderr}"
    );
    e.ok(&["settings", "set", "kit.trustedSigners", &trust(&other)]);
    let out = e.sbt(&["kit", "inspect", &r]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("kit signature verification failed"),
        "{stderr}"
    );
}
