use std::collections::BTreeMap;

use anyhow::Result;
use clap::Parser;

use super::{Cli, Ctx, dispatch};
use crate::config::{Paths, Settings};
use crate::smolvm::Smolvm;
use crate::smolvm::fake::FakeRunner;
pub use crate::testgit::*;

pub struct TestEnv {
    pub ctx: Ctx<FakeRunner>,
    /// Keeps the temp dirs alive for the test's duration.
    _dir: tempfile::TempDir,
}

/// A context with temp config/cache/data dirs, cwd `<tmp>/proj`, `now` = 1_000_000, uid 501 and smolvm
/// 1.32.4.
pub fn test_env(extra_env: &[(&str, &str)]) -> TestEnv {
    let dir = tempfile::tempdir().unwrap();
    let mut env = BTreeMap::from([
        (
            "SMOLBENTO_CONFIG_DIR".to_string(),
            dir.path().join("config").display().to_string(),
        ),
        (
            "SMOLBENTO_CACHE_DIR".to_string(),
            dir.path().join("cache").display().to_string(),
        ),
        (
            "SMOLBENTO_DATA_DIR".to_string(),
            dir.path().join("data").display().to_string(),
        ),
    ]);
    for (k, v) in extra_env {
        env.insert(k.to_string(), v.to_string());
    }
    let paths = Paths::from_env(&env).unwrap();
    std::fs::create_dir_all(&paths.config).unwrap();
    std::fs::write(paths.policy_file(), "mode = \"allow-all\"\n").unwrap();
    let (settings, config_error) = Settings::load(&paths, env.clone());
    let fake = FakeRunner::new();
    fake.ok(&["--version"], "smolvm 1.32.4\n");
    let cwd = dir.path().join("proj");
    std::fs::create_dir_all(&cwd).unwrap();
    let cwd = cwd.canonicalize().unwrap();
    TestEnv {
        ctx: Ctx {
            vm: Smolvm::new(fake),
            settings,
            paths,
            cwd,
            env,
            now: 1_000_000,
            stdin_tty: false,
            stdout_tty: false,
            uid: 501,
            gid: 20,
            store: Box::new(crate::secrets::store::MemoryStore::default()),
            config_error,
            out: super::Out::Buffer(Default::default()),
            args: vec![],
        },
        _dir: dir,
    }
}

impl TestEnv {
    /// What commands have written to stdout since the last call.
    pub fn stdout(&self) -> String {
        match &self.ctx.out {
            super::Out::Buffer(b) => String::from_utf8(b.take()).unwrap(),
            super::Out::Stdout => unreachable!("tests capture stdout"),
        }
    }
}

/// Replaces config.toml with invalid TOML and reloads the settings as `main` would.
pub fn break_config(t: &mut TestEnv) {
    let file = t.ctx.paths.config_file();
    std::fs::create_dir_all(file.parent().unwrap()).unwrap();
    std::fs::write(&file, "docker = [broken").unwrap();
    let (settings, config_error) = Settings::load(&t.ctx.paths, t.ctx.env.clone());
    t.ctx.settings = settings;
    t.ctx.config_error = config_error;
}

/// Replaces policy.toml.
pub fn set_policy(t: &TestEnv, toml: &str) {
    std::fs::write(t.ctx.paths.policy_file(), toml).unwrap();
}

pub fn sbt(ctx: &mut Ctx<FakeRunner>, args: &[&str]) -> Result<i32> {
    let cli = Cli::try_parse_from(std::iter::once("sbt").chain(args.iter().copied()))?;
    ctx.args = args.iter().map(|a| a.to_string()).collect();
    dispatch(ctx, cli)
}

/// `machine status --json` output for a smolbento sandbox.
pub fn machine_json(machine: &str, state: &str, labels: &[(&str, &str)]) -> String {
    let labels: BTreeMap<&str, &str> = labels.iter().copied().collect();
    serde_json::json!({
        "name": machine,
        "state": state,
        "image": "img",
        "labels": labels,
        "created_at": 999_000,
        "published_ports": [],
    })
    .to_string()
}

/// A local v3 kit directory `dir` (under the cwd) whose `_builder` build hands back `descriptor`
/// (JSON) with `layers`.
pub fn v3_kit(t: &TestEnv, dir: &str, descriptor: &str, layers: &[&[u8]]) {
    let kit = t.ctx.cwd.join(dir);
    std::fs::create_dir(&kit).unwrap();
    std::fs::write(
        kit.join("kit.yaml"),
        "# syntax=docker/sandbox-kit:3\nschemaVersion: \"3\"\nkind: mixin\n",
    )
    .unwrap();
    let out = tempfile::tempdir().unwrap();
    crate::kits::registry::fixtures::oci_layout(out.path(), Some(descriptor), layers, "{}");
    let mut b = tar::Builder::new(Vec::new());
    b.append_dir_all(".", out.path()).unwrap();
    t.ctx
        .vm
        .runner()
        .ok(
            &["machine", "status", "-n", "sbx-_builder"],
            &machine_json(
                "sbx-_builder",
                "running",
                &[("sbx.name", "_builder"), ("sbx.docker", "true")],
            ),
        )
        .download(&b.into_inner().unwrap());
}

/// A running sandbox whose `sbx.ssh-agent` label is `grant` (none when `None`), and a record of
/// whether its agent socket was served during each interactive exec.
pub fn agent_probe(
    t: &TestEnv,
    tag: &str,
    grant: Option<&str>,
) -> (String, std::rc::Rc<std::cell::RefCell<Vec<bool>>>) {
    let name = format!("agent-{}-{tag}", std::process::id());
    let mut labels = vec![
        ("sbx.name", name.as_str()),
        ("sbx.agent", "shell"),
        ("sbx.workspace", "/w/proj"),
    ];
    if let Some(grant) = grant {
        labels.push(("sbx.ssh-agent", grant));
    }
    let runner = t.ctx.vm.runner();
    runner.ok(&["machine"], "");
    runner.ok(
        &["machine", "status"],
        &machine_json(&format!("sbx-{name}"), "running", &labels),
    );
    let (seen, probe) = socket_probe(crate::bridge::agent_socket(&name));
    runner.during_interactive(probe);
    (name, seen)
}

/// A running sandbox (`sbx.bridge=true` when `bridge`) with a name of its own: its bridge socket is
/// under the real `/tmp/sbt-<uid>`, shared with other test processes. Returns the name and, for each
/// interactive call, whether the bridge socket answered while the user was attached.
pub fn bridge_probe(
    t: &TestEnv,
    tag: &str,
    bridge: bool,
) -> (String, std::rc::Rc<std::cell::RefCell<Vec<bool>>>) {
    let name = format!("bridge-{}-{tag}", std::process::id());
    let mut labels = vec![
        ("sbx.name", name.as_str()),
        ("sbx.agent", "shell"),
        ("sbx.workspace", "/w/proj"),
    ];
    if bridge {
        labels.push(("sbx.bridge", "true"));
    }
    let runner = t.ctx.vm.runner();
    // Later registrations win: the catch-all goes first.
    runner.ok(&["machine"], "");
    runner.ok(
        &["machine", "status"],
        &machine_json(&format!("sbx-{name}"), "running", &labels),
    );
    let (seen, probe) = socket_probe(crate::bridge::host_socket(&name));
    runner.during_interactive(probe);
    (name, seen)
}

/// A record of whether `socket` answered, one entry per call of the returned probe.
pub fn socket_probe(
    socket: std::path::PathBuf,
) -> (
    std::rc::Rc<std::cell::RefCell<Vec<bool>>>,
    impl Fn() + 'static,
) {
    let seen = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let s = seen.clone();
    let probe = move || {
        let served = std::os::unix::net::UnixStream::connect(&socket).is_ok();
        s.borrow_mut().push(served);
    };
    (seen, probe)
}
