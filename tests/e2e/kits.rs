use super::*;

/// The guest's startup log (empty until the startup runner first writes it).
pub(crate) fn startup_log(e: &E2e) -> String {
    root_out(&e.name, "cat /var/log/sbx-kit-startup.log 2>/dev/null")
}

/// Number of dockerd processes in the guest.
pub(crate) fn dockerds(e: &E2e) -> usize {
    let out = e.sh(&e.name, "pgrep -x dockerd || true");
    out_text(&out).lines().count()
}

/// The real `shell` agent kit (sbx's `docker.io/sbx/shell:latest`, pulled from Docker Hub) runs
/// Docker through the shipped `docker` kit, as its `start-docker` annotation asks: the kit's
/// `dockerd@1` has smolbento start dockerd on every start, once, and it outlives that exec.
#[test]
#[ignore = "boots real VMs and pulls sbx's shell kit; run with `just e2e`"]
pub(crate) fn real_shell_kit_runs_dockerd_across_restarts() {
    let mut e = E2e::new("dock");
    e.real_agent_kits();
    e.vars.push(("SMOLBENTO_DOCKER", "true".into()));
    e.create_real_kit("shell");
    assert_eq!(e.state(), "running");
    let inspect = e.ok(&["inspect", &e.name, "--json"]);
    assert!(
        inspect.contains("docker.io/sbx/shell:latest@sha256:"),
        "{inspect}"
    );
    assert!(inspect.contains("builtin:docker"), "{inspect}");
    let docker_info = || {
        e.sbt(&["exec", "--privileged", &e.name, "docker", "info"])
            .status
            .success()
    };
    // dockerd starts in the background: wait for it, as an agent would.
    let wait = || wait_until(90, docker_info);
    assert!(
        wait(),
        "docker info after create:\n{}\n{}",
        startup_log(&e),
        root_out(&e.name, "cat /var/log/dockerd.log; ps -ef")
    );
    assert_one_dockerd(&e, "dockerd survives the startup runner's exec");

    e.ok(&["stop", &e.name]);
    e.ok(&["start", &e.name]);
    assert!(wait(), "docker info after a restart");
    assert_one_dockerd(&e, "exactly one dockerd after a restart");
}

/// A kit declaring `dockerd@1` finds the engine running when its startup hooks run: its blocking
/// hook calls `docker info` without waiting. The image (sbx's shell image, which has Docker) is
/// given with `-t`, so no shipped kit is added: the local kit's request alone starts the engine.
/// tck: dockerd@1/engine-before-startup
#[test]
#[ignore = "boots real VMs and pulls sbx's shell image from Docker Hub; run with `just e2e`"]
pub(crate) fn a_kit_declaring_dockerd_finds_the_engine_at_startup() {
    let mut e = E2e::new("dockerd");
    e.vars.push(("SMOLBENTO_DOCKER", "true".into()));
    let kit = e.v3_kit_dir(
        "engine",
        r#"# syntax=docker/sandbox-kit:3
schemaVersion: "3"
kind: mixin
version: "1.0.0"
capabilities:
  - type: com.docker.sandbox/dockerd@1
  - type: com.docker.sandbox/lifecycle@1
    config:
      startup:
        - command: "docker info >/tmp/dinfo 2>&1"
"#,
    );
    e.create(
        &e.name,
        &["-t", "docker.io/sbx/shell:latest", "--kit", &kit, "shell"],
    );
    let inspect = e.ok(&["inspect", &e.name, "--json"]);
    assert!(!inspect.contains("builtin:docker"), "{inspect}");
    let info = root_out(&e.name, "cat /tmp/dinfo");
    assert!(
        info.contains("Server Version"),
        "{info}\n{}",
        startup_log(&e)
    );
}

/// The real `claude` agent kit: pulled from Docker Hub, its API key bound from your secret (the
/// value stays on the host), its install steps writing Claude's settings, its agent file in
/// place, the agent idle until `run` starts it, and the mounted workspace writable by the agent
/// (smolvm maps it to the kit's image user).
#[test]
#[ignore = "boots real VMs and pulls sbx's claude kit; run with `just e2e`"]
pub(crate) fn real_claude_kit_binds_its_api_key_and_seeds_its_settings() {
    let e = E2e::new("claude");
    e.real_agent_kits();
    let ws = e.workspace();
    // A host command, so no keychain is needed.
    e.ok(&[
        "secret",
        "set",
        "anthropic",
        "--command",
        "printf sk-ant-e2e-not-a-real-key",
    ]);
    e.create_real_kit("claude");
    let sh = |script: &str| out_text(&e.sh(&e.name, script));
    let settings = sh("cat ~/.claude/settings.json");
    assert!(
        settings.contains("apiKeyHelper"),
        "API-key mode seeds the helper:\n{settings}"
    );
    assert!(sh("env").contains("SBX_CRED_ANTHROPIC_MODE=apikey"));
    assert!(
        !sh("env").contains("sk-ant-e2e-not-a-real-key"),
        "the key never enters the guest"
    );
    // As in sbx: no ANTHROPIC_API_KEY, which Claude would ask about before using it.
    assert!(
        !sh("env").contains("ANTHROPIC_API_KEY="),
        "the key reaches Claude only through its helper"
    );
    // The kit gives its guide as agent-context@1 and @2: written once.
    assert_eq!(
        sh("grep -c '^## Claude Code' ~/.claude/CLAUDE.md"),
        "1\n",
        "the kit's agent file, with its guide once"
    );
    // The agent idles at boot: nothing runs claude until `run`.
    assert_eq!(sh("pgrep -x claude || true"), "", "{}", sh("ps -ef"));
    // The workspace is the agent's to write, and the file is yours on the host.
    assert_eq!(
        sh("touch e2e-written && echo ok"),
        "ok\n",
        "the agent writes its workspace"
    );
    assert!(ws.join("e2e-written").exists());
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
    e.create_workload(&kit);
    assert_eq!(e.state(), "running");
    // The image has no USER, so the agent runs as root, as in sbx, in the workspace.
    let out = e.ok(&["run", "--name", &e.name]);
    let want = format!(
        "workload-command-ran-as-root in {}",
        e.workspace().display()
    );
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

// A test that builds a local kit uses the shared `_builder` sandbox (in the tests' own smolvm home,
// `smolvm_home`), which it leaves in place for the next one, so BuildKit keeps its cache. It must
// be in the `builder` test group in `.config/nextest.toml`, which runs them one at a time.

#[test]
#[ignore = "boots real VMs, builds in the builder sandbox and pulls from Docker Hub; run with `just e2e`"]
pub(crate) fn local_v3_kit_builds_in_the_builder_sandbox() {
    let e = E2e::new("build");
    // Layers are composed onto the base image, which must then be a registry reference.
    let _reg = Registry::start(&e);
    let kit = e.v3_kit_dir(
        "built",
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
    );
    e.create_with_kits(&[&kit]);
    assert_eq!(
        root_out(&e.name, "cat /opt/e2e-built/hello"),
        "built in the builder\n"
    );
}

/// A kit's `host-mount@1` directory is shared by its sandboxes and outlives them. (`--mount`
/// binding your own directory instead is `mount_binds_a_host_directory_instead_of_the_managed_one`
/// in `src/cli/request_tests.rs`.)
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
    // The agent in one sandbox writes; another sandbox of the same kit reads it.
    let (a, b) = (&e.name, format!("{}-b", e.name));
    let _b = Machines(vec![b.clone()]);
    e.create(a, &[&kit]);
    e.create(&b, &[&kit]);
    // A published kit's directories are keyed by `<registry>/<repository>`, as in sbx.
    let r: oci_client::Reference = kit.parse().unwrap();
    let managed = smolbento::kits::host_mount::managed_dir(
        &e.dir.path().join("data/kit-host-mounts"),
        &format!("{}/{}", r.registry(), r.repository()),
        SHARED,
    );
    let inspect: serde_json::Value =
        serde_json::from_str(&e.ok(&["inspect", "--json", a])).unwrap();
    assert_eq!(inspect["mounts"][SHARED], managed.to_str().unwrap());
    let note = format!("{SHARED}/note");
    e.sh_ok(a, &format!("echo from-a > {note}"));
    assert_eq!(e.ok(&["exec", &b, "cat", &note]), "from-a\n");

    // Removing both sandboxes keeps the directory and its file.
    e.ok(&["rm", "-f", a, &b]);
    assert_eq!(
        std::fs::read_to_string(managed.join("note")).unwrap(),
        "from-a\n"
    );
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
#[ignore = "boots real VMs and pulls from dhi.io with a login; run with `just e2e-dhi`"]
pub(crate) fn local_kit_builds_from_a_registry_that_needs_a_login() {
    // Run with `just e2e-dhi` (`just e2e` leaves it out): needs a Docker account with dhi.io
    // access and its access token in a file.
    let (Ok(user), Ok(token_file)) = (
        std::env::var("SMOLBENTO_E2E_DHI_USER"),
        std::env::var("SMOLBENTO_E2E_DHI_TOKEN_FILE"),
    ) else {
        panic!("set SMOLBENTO_E2E_DHI_USER and SMOLBENTO_E2E_DHI_TOKEN_FILE to build from dhi.io");
    };
    // The value goes to the OS keychain, which is shared with your own smolbento whatever the
    // config dir: never touch a dhi.io login you stored yourself.
    const ACCOUNT: &str = "registry:dhi.io";
    assert!(
        !os_keychain_has(ACCOUNT),
        "your keychain already has a smolbento dhi.io login; not touching it"
    );
    let token = std::fs::read(&token_file).unwrap();
    // This recreates the tests' `_builder` (under their own smolvm home, not yours) with the dhi.io
    // login bound, and leaves it so: the next build, with other logins, recreates it again.
    let e = E2e::new("dhi");
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
        err_text(&out)
    );

    let kit = e.v3_kit_dir(
        "dhi",
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
    );
    e.create_with_kits(&[&kit]);
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
    let probe = format!(
        r#"set -e
wget -q -T 15 -O /dev/null https://httpbin.org
ip=$({HTTPBIN_IP})
[ -n "$ip" ]
wget -S -T 15 -O /dev/null "http://$ip/" 2>&1 | grep -q 'HTTP/'
echo "$ip" > /etc/e2e-install-ip"#
    );
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
    assert!(
        !http_answers(&e, &ip),
        "{ip} (httpbin.org's address) is closed after install"
    );
    // `policy ls` never lists install-phase rules (as sbx), so check the stored policy too.
    let rules = e.ok(&["policy", "ls", "--wide"]);
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
    e.httpbin_secret("E2E_TOK");
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
                                 "format": "Basic %s"}]}}},
                {"type": "com.docker.sandbox/lifecycle@1",
                 "config": {"install": [
                     {"command": add_agent_hook(), "user": "0"},
                     {"command": "wget -q -T 20 -O /dev/null \
                                  https://httpbin.org/basic-auth/user/real-secret-xyz \
                                  && touch /etc/e2e-install-authorized",
                      "user": "0"},
                 ]}},
            ]),
        ),
    );
    e.create_with_kits(&[&kit]);
    // smolvm scrubs the value out of responses, so httpbin's answer is the proof.
    assert!(
        root_sh(&e.name, "test -f /etc/e2e-install-authorized")
            .status
            .success(),
        "substituted during install"
    );
    let after = e.sh(
        &e.name,
        "wget -S -T 20 -O - https://httpbin.org/basic-auth/user/real-secret-xyz 2>&1",
    );
    let after = out_text(&after);
    assert!(after.contains("502"), "502 after install: {after}");
    assert!(!after.contains(BASIC_SECRET), "{after}");
}

#[test]
#[ignore = "boots real VMs and needs httpbin.org; run with `just e2e`"]
pub(crate) fn kit_add_applies_network_and_hooks_live() {
    let e = E2e::new("kitadd");
    // A v2 mixin is added below: a v2 workload.
    e.create_alpine_as(&e.v2_shell(), "apk add -q bash");
    e.ok(&["policy", "init", "deny-all"]);
    e.ok(&["stop", &e.name]); // allow-all -> restricted applies on the next start
    e.ok(&["start", &e.name]);
    assert!(!reachable(&e, "https://httpbin.org"), "deny-all blocks");
    let boot = root_out(&e.name, "cat /proc/sys/kernel/random/boot_id");

    let kit = e.v2_kit_dir(
        "e2e-add",
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
    );
    e.ok(&["kit", "add", &e.name, &kit, "--yes"]);

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
    // As in sbx: one `kit:<sandbox>` policy, its hosts counted (listed with --wide).
    let rules = e.ok(&["policy", "ls", "--source", "kit"]);
    assert!(rules.contains(&format!("kit:{}", e.name)), "{rules}");
    assert!(rules.contains("network: 1 allow"), "{rules}");
    let wide = e.ok(&["policy", "ls", "--source", "kit", "--wide"]);
    assert!(wide.contains(&format!("kit:{}", e.name)), "{wide}");
    assert!(wide.contains("httpbin.org"), "{wide}");
    // Recorded in the sandbox's labels, so a stopped sandbox lists it too.
    e.ok(&["stop", &e.name]);
    let out = e.ok(&["inspect", "--json", &e.name]);
    let kits = serde_json::from_str::<serde_json::Value>(&out).unwrap()["kits"].to_string();
    assert!(kits.contains("e2e-add"), "{kits}");
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
    /// `bento create` of workload kit `kit` on the workspace.
    pub(crate) fn create_workload(&self, kit: &str) {
        self.create(&self.name, &[kit]);
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
                "bento run failed:\n{}\n--- as root:\n{}{}\n--- as {user}:\n{}{}",
                err_text(&run),
                out_text(&as_root),
                err_text(&as_root),
                out_text(&as_user),
                err_text(&as_user),
            );
        }
        let out = out_text(&run);
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

/// sbx 0.51: a blocking startup hook that fails is a warning with the log's tail, at create and
/// at every start, and the sandbox runs.
#[test]
#[ignore = "boots real VMs and pulls alpine; run with `just e2e`"]
pub(crate) fn failing_startup_hook_warns_and_the_sandbox_runs() {
    let e = E2e::new("startfail");
    let kit = e.v2_kit_dir(
        "e2e-fail-start",
        r#"schemaVersion: "2"
kind: mixin
name: e2e-fail-start
setup:
  startup:
    - command: [sh, -c, "sleep 2; exit 7"]
      user: "0"
"#,
    );
    let archive = Image::alpine_agent_archive();
    // A v2 mixin needs a v2 workload.
    let head = [
        "-t",
        archive.to_str().unwrap(),
        "--kit",
        &kit,
        &e.v2_shell(),
    ];
    let out = e.try_create(&e.name, &head);
    let err = err_text(&out);
    assert!(out.status.success(), "create succeeds:\n{err}");
    assert!(
        err.contains("a kit startup step failed (kit startup exited with code 7); starting anyway")
            && err.contains("/var/log/sbx-kit-startup.log:"),
        "{err}"
    );
    assert_eq!(e.state(), "running");

    e.ok(&["stop", &e.name]);
    let out = e.sbt(&["start", &e.name]);
    let err = err_text(&out);
    assert!(out.status.success(), "start succeeds:\n{err}");
    assert!(err.contains("kit startup exited with code 7"), "{err}");
    assert_eq!(e.state(), "running");
}

/// sbx #13: a v2 startup hook without `user:` runs as the agent account, and it doesn't keep the sandbox from starting.
#[test]
#[ignore = "boots real VMs and pulls alpine; run with `just e2e`"]
pub(crate) fn v2_startup_hook_runs_as_agent_by_default() {
    let e = E2e::new("v2user");
    let kit = e.v2_kit_dir(
        "e2e-v2-user",
        r#"schemaVersion: "2"
kind: mixin
name: e2e-v2-user
setup:
  startup:
    - command: [sh, -c, "id -un > /tmp/e2e-started-as"]
"#,
    );
    e.create_with_kits(&[&kit]);
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

/// tck: lifecycle@1/default-users: a v3 startup hook without `user:` runs as the session user
/// (`agent` here, Alpine having no image user of its own), not root.
#[test]
#[ignore = "boots real VMs and pulls alpine; run with `just e2e`"]
pub(crate) fn v3_startup_hook_runs_as_the_session_user_by_default() {
    let e = E2e::new("v3user");
    let reg = Registry::start(&e);
    let kit = reg.push(
        "v3user",
        Image::empty(),
        descriptor(
            "mixin",
            &["e2e-v3-user@1.0.0"],
            serde_json::json!([{
                "type": "com.docker.sandbox/lifecycle@1",
                "config": {"startup": [{"command": "id -un > /tmp/e2e-started-as"}]}
            }]),
        ),
    );
    e.create_with_kits(&[&kit]);
    assert_eq!(e.state(), "running");
    assert_eq!(root_out(&e.name, "cat /tmp/e2e-started-as"), "agent\n");
}

/// sbx #15: a mixin's agent context goes beside the workspace, in the sandbox only. It is
/// `agent-context@2` (a v2 kit's instructions are), so the kit's text is in the shell agent's
/// `AGENTS.md` itself, where the agent reads it at startup.
#[test]
#[ignore = "boots real VMs and pulls alpine; run with `just e2e`"]
pub(crate) fn mixin_agent_context_sits_beside_the_workspace() {
    let e = E2e::new("ctx");
    let kit = e.v2_kit_dir(
        "e2e-ctx",
        r#"schemaVersion: "2"
kind: mixin
name: e2e-ctx
agentInstructions:
  content: "Use the e2e tools."
"#,
    );
    e.create_with_kits(&[&kit]);
    let parent = e.workspace().parent().unwrap().to_path_buf();
    let p = parent.display();
    let file = root_out(&e.name, &format!("cat {p}/AGENTS.md"));
    let section = "Use the e2e tools.\n<!-- sbx:kits-section end -->";
    assert!(
        file.contains("<!-- sbx:kits-section start -->") && file.contains(section),
        "{file}"
    );
    assert!(
        !root_sh(&e.name, &format!("test -e {p}/kits-agent-context"))
            .status
            .success(),
        "no per-kit files: the text is inline"
    );
    assert_eq!(
        root_out(&e.name, &format!("stat -c %U {p}/AGENTS.md")),
        "agent\n"
    );
    assert!(!parent.join("AGENTS.md").exists(), "nothing on the host");
}

/// tck: SPEC-v3 §7.1.1/atomic-selection. A group with a member smolbento can't apply leaves
/// nothing behind, even its supported members; a group it can apply is applied whole.
///
/// A published kit: a local v3 kit is built in the builder (even without a `build:` step) and read
/// from the build's descriptor annotation, as a pushed one is, so pushing keeps this test out of
/// the serial builder group.
#[test]
#[ignore = "boots real VMs and pulls alpine; run with `just e2e`"]
pub(crate) fn capability_groups_apply_whole_or_not_at_all() {
    let e = E2e::new("groups");
    let reg = Registry::start(&e);
    let kit = reg.push(
        "groups",
        Image::empty(),
        serde_json::json!({
            "schemaVersion": "3",
            "kind": "mixin",
            "capabilities": [
                {"group": {"optional": true, "capabilities": [
                    {"type": "com.docker.sandbox/lifecycle@1",
                     "config": {"files": [{"path": "/var/tmp/skipped-feature",
                                           "content": "skipped"}]}},
                    {"type": "com.docker.sandbox/usb-device@1",
                     "config": {"class": "smart-card"}},
                ]}},
                {"group": {"name": "Feature", "capabilities": [
                    {"type": "com.docker.sandbox/volume@1",
                     "config": {"path": "/var/tmp/group-volume"}},
                    {"type": "com.docker.sandbox/lifecycle@1",
                     "config": {"files": [{"path": "/var/tmp/group-feature",
                                           "content": "selected"}]}},
                ]}},
            ],
        }),
    );
    e.create_with_kits(&[&kit]);
    assert_eq!(root_out(&e.name, "cat /var/tmp/group-feature"), "selected");
    assert!(
        !root_sh(&e.name, "test -e /var/tmp/skipped-feature")
            .status
            .success(),
        "the skipped group's file was written"
    );
}

/// SPEC-v3 §6: kit arguments reach typed config fields (a port number) and paths, expanded
/// inside the config before smolbento reads it. A published kit, as in
/// `capability_groups_apply_whole_or_not_at_all`: its descriptor keeps the references, which
/// smolbento expands when it applies the kit.
#[test]
#[ignore = "boots real VMs and pulls alpine; run with `just e2e`"]
pub(crate) fn kit_args_reach_typed_config_fields() {
    let e = E2e::new("cfgargs");
    let reg = Registry::start(&e);
    let kit = reg.push(
        "cfgargs",
        Image::empty(),
        serde_json::json!({
            "schemaVersion": "3",
            "kind": "mixin",
            "args": {
                "port": {"default": "8123"},
                "name": {"default": "cfg-args"},
            },
            "capabilities": [
                {"type": "com.docker.sandbox/port@1",
                 "config": {"container": "${{ kit.args.port }}"}},
                {"type": "com.docker.sandbox/lifecycle@1",
                 "config": {"files": [{"path": "/var/tmp/${{ kit.args.name }}",
                                       "content": "port ${{ kit.args.port }}"}]}},
            ],
        }),
    );
    e.create_with_kits(&[&kit]);
    let ports = e.ok(&["ports", &e.name]);
    assert!(ports.contains("8123"), "{ports}");
    assert_eq!(root_out(&e.name, "cat /var/tmp/cfg-args"), "port 8123");
}

/// As in sbx: a local kit is a path, here `../e2e-path` from the workspace. (Kit argument and kit
/// reference errors are unit tests: `src/kits/resolve_tests.rs`, `src/kits/load.rs`,
/// `src/cli/kit_tests.rs`, `src/cli/run_tests.rs`, `src/cli/lifecycle_tests.rs`.)
#[test]
#[ignore = "runs bento against smolvm; run with `just e2e`"]
pub(crate) fn kit_validate_and_inspect_take_a_relative_path() {
    let e = E2e::new("relkit");
    e.v2_kit_dir(
        "e2e-path",
        "schemaVersion: \"2\"\nkind: mixin\nname: e2e-path\n",
    );
    let out = e.ok(&["kit", "validate", "../e2e-path"]);
    assert_eq!(out, "✓ ../e2e-path — valid\n");
    let out = e.ok(&["kit", "inspect", "../e2e-path"]);
    assert!(
        out.starts_with("Name: e2e-path\nKind: mixin\nSchema: v2\n"),
        "{out}"
    );
}

/// A kit `kit push`es loads with `--kit`, its files included, and comes back with `kit pull`.
#[test]
#[ignore = "boots real VMs and pulls alpine; run with `just e2e`"]
pub(crate) fn a_pushed_kit_pulls_and_runs() {
    let e = E2e::new("push");
    let reg = Registry::start(&e);
    let kit = e.v2_kit_dir(
        "pushed",
        "schemaVersion: \"2\"\nkind: mixin\nname: pushed\n",
    );
    let kit = Path::new(&kit);
    std::fs::create_dir_all(kit.join("files/home")).unwrap();
    std::fs::write(kit.join("files/home/hello"), "from-the-registry\n").unwrap();
    let r = reg.reference("pushed");
    let out = e.ok(&["kit", "push", kit.to_str().unwrap(), &r]);
    assert!(out.starts_with(&format!("Pushed {r} (sha256:")), "{out}");
    // A pulled v2 kit is still v2, so it needs a v2 workload (`create_with_kits` can only tell
    // from a local `spec.yaml`).
    let template = e.alpine_template();
    let shell = e.v2_shell();
    e.create(&e.name, &["-t", &template, "--kit", &r, &shell]);
    assert_eq!(
        root_out(&e.name, "cat /home/agent/hello"),
        "from-the-registry\n"
    );
    let out = e.ok(&["kit", "pull", &r, "-o", "out.tar.gz"]);
    assert_eq!(out, format!("Pulled {r} to out.tar.gz\n"));
    let pulled = std::fs::read(e.workspace().join("out.tar.gz")).unwrap();
    let pushed = smolbento::kits::artifact::read_dir(kit)
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
    let kit = e.v2_kit_dir(
        "signed",
        "schemaVersion: \"2\"\nkind: mixin\nname: signed\n",
    );
    let r = reg.reference("signed");
    e.ok(&["kit", "push", &kit, &r]);

    let out = e.sbt(&["kit", "verify", &r, "--key", &public]);
    assert!(!out.status.success());
    assert!(err_text(&out).contains("kit is not signed"));

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
    let out = e.ok(&["kit", "push", &kit, &r2, "--sign", "--key", &key]);
    assert!(out.ends_with(&format!("Signed {r2}\n")), "{out}");
    e.ok(&["kit", "verify", &r2, "--key", &public]);

    // kit.requireSignature with this key trusted: the signed kit loads, an unsigned one doesn't.
    let unsigned = reg.reference("unsigned");
    e.ok(&["kit", "push", &kit, &unsigned]);
    e.ok(&["settings", "set", "kit.requireSignature", "true"]);
    let trust = |key: &str| format!(r#"[{{"key":"{key}"}}]"#);
    e.ok(&["settings", "set", "kit.trustedSigners", &trust(&public)]);
    let out = e.sbt(&["kit", "inspect", &r]);
    let stderr = err_text(&out);
    assert!(out.status.success(), "{stderr}");
    assert!(
        stderr.contains(&format!("✓ {r} — signature verified (key {public})")),
        "{stderr}"
    );
    let out = e.sbt(&["kit", "inspect", &unsigned]);
    assert!(!out.status.success());
    let stderr = err_text(&out);
    assert!(
        stderr.contains(&format!("{unsigned} is not signed")),
        "{stderr}"
    );
    e.ok(&["settings", "set", "kit.trustedSigners", &trust(&other)]);
    let out = e.sbt(&["kit", "inspect", &r]);
    assert!(!out.status.success());
    let stderr = err_text(&out);
    assert!(
        stderr.contains("kit signature verification failed"),
        "{stderr}"
    );
}

/// The shipped `kits/nix` source, built in the builder sandbox.
fn nix_kit_dir() -> String {
    format!("{}/kits/nix", env!("CARGO_MANIFEST_DIR"))
}

/// A trivial build: exercises nix-daemon (the store is root's) without nixpkgs.
const NIX_BUILD: &str = r#"nix build --impure --no-link --expr 'builtins.derivation { name = "x"; system = builtins.currentSystem; builder = "/bin/sh"; args = [ "-c" "echo ok > $out" ]; }'"#;

/// `kits/nix`, built once, in two sandboxes in turn. On the `claude` agent: Nix and its daemon,
/// direnv on the workspace's `.envrc`, the kit's agent instructions, and the image's accounts left
/// alone. Then on a workload whose image user isn't `agent`: Nix works for that user. The second
/// create builds again, but in the builder the first build left, from BuildKit's cache.
#[test]
#[ignore = "boots real VMs, builds in the builder sandbox and downloads Nix; run with `just e2e`"]
pub(crate) fn nix_kit_works_for_an_agent_and_a_workload_image_user() {
    let e = E2e::new("nixkit");
    let reg = Registry::start(&e);
    let nix = nix_kit_dir();

    // The `claude` agent. Its agent file is in `~/.claude`, so the kit's instructions are too.
    let agent = "the claude agent sandbox";
    std::fs::write(e.workspace().join(".envrc"), "export E2E_DIRENV=yes\n").unwrap();
    e.create_with_kits_as("claude", &[&nix]);
    let as_agent = |script: &str| e.sh_ok(&e.name, script);
    let version = as_agent("nix --version");
    assert!(version.contains("nix"), "{agent}: nix --version: {version}");
    as_agent(NIX_BUILD);
    assert_eq!(
        as_agent("direnv exec . sh -c 'echo $E2E_DIRENV'").trim(),
        "yes",
        "{agent}: direnv loads the workspace's .envrc"
    );
    assert!(
        root_sh(&e.name, "getent passwd agent").status.success(),
        "{agent}: the image's agent account is left alone"
    );
    // Claude's kit and this one both offer agent-context@2: the text is in the agent file.
    let text = root_out(&e.name, "cat /home/agent/.claude/CLAUDE.md");
    let section = text
        .split_once("<!-- sbx:kits-section start -->")
        .and_then(|(_, rest)| rest.split_once("<!-- sbx:kits-section end -->"))
        .map(|(section, _)| section);
    assert!(
        section.is_some_and(|s| s.contains("Nix and direnv are installed.")),
        "{agent}: the kit's instructions in CLAUDE.md:\n{text}"
    );
    // Only one sandbox at a time, as when these were two tests.
    e.ok(&["rm", "-f", &e.name]);
    std::fs::remove_file(e.workspace().join(".envrc")).unwrap();

    // A workload whose image user is `somebody`, in its own sandbox.
    let workload = "the somebody workload sandbox";
    let wl = format!("{}-wl", e.name);
    let _wl = Machines(vec![wl.clone()]);
    let kit = image_user_kit(&reg, "nix-image-user", "somebody", serde_json::Value::Null);
    e.create(&wl, &["--kit", &nix, &kit]);
    assert_eq!(
        e.ok(&["exec", &wl, "id", "-un"]).trim(),
        "somebody",
        "{workload}: the session user"
    );
    let version = e.ok(&["exec", &wl, "nix", "--version"]);
    assert!(
        version.contains("nix"),
        "{workload}: nix --version: {version}"
    );
    e.sh_ok(&wl, NIX_BUILD);
}
