use std::collections::BTreeMap;

use anyhow::Result;
use clap::Parser;

use crate::cli::{Cli, Ctx, dispatch};
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
/// 1.34.4.
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
    fake.ok(&["--version"], "smolvm 1.34.4\n");
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
            store: Box::new(crate::secrets::store::MemoryStore::default()),
            config_error,
            out: crate::ctx::Out::Buffer(Default::default()),
            input: crate::ctx::In::Buffer(Default::default()),
            args: vec![],
            program: "sbt".into(),
        },
        _dir: dir,
    }
}

impl TestEnv {
    /// Makes stdin a terminal that answers prompts with `answers`, one line each.
    pub fn answer(&mut self, answers: &str) {
        self.ctx.stdin_tty = true;
        self.ctx.input = crate::ctx::In::Buffer(std::io::Cursor::new(answers.into()).into());
    }

    /// What commands have written to stdout since the last call.
    pub fn stdout(&self) -> String {
        match &self.ctx.out {
            crate::ctx::Out::Buffer(b) => String::from_utf8(b.take()).unwrap(),
            crate::ctx::Out::Stdout => unreachable!("tests capture stdout"),
        }
    }

    /// The fake smolvm.
    pub fn runner(&self) -> &FakeRunner {
        self.ctx.vm.runner()
    }

    /// The smolvm calls so far, each as one space-joined line.
    pub fn calls(&self) -> Vec<String> {
        self.runner().call_lines()
    }

    /// Runs `sbt ARGS`.
    pub fn sbt(&mut self, args: &[&str]) -> Result<i32> {
        sbt(&mut self.ctx, args)
    }

    /// Runs `sbt ARGS`, which must fail, and returns the error's message.
    pub fn sbt_err(&mut self, args: &[&str]) -> String {
        self.sbt(args).unwrap_err().to_string()
    }

    /// Makes `machine status` answer with `machine` in `state` with `labels`.
    pub fn machine(&self, machine: &str, state: &str, labels: &[(&str, &str)]) -> &FakeRunner {
        self.runner().ok(
            &["machine", "status"],
            &machine_json(machine, state, labels),
        )
    }

    /// Makes `machine status` answer with sandbox `name` (machine `sbx-<name>`) in `state`.
    pub fn sandbox(&self, name: &str, state: &str, labels: &[(&str, &str)]) -> &FakeRunner {
        let mut all = vec![("sbx.name", name)];
        all.extend_from_slice(labels);
        self.machine(&crate::sandbox::name::machine_name(name), state, &all)
    }

    /// Sandbox `name` is missing for `lookups` status calls, then exists as `created`.
    pub fn creatable(&self, name: &str, labels: &[(&str, &str)], lookups: usize) -> &FakeRunner {
        let fake = self.sandbox(name, "created", labels);
        for _ in 0..lookups {
            fake.once_fail(&["machine", "status"], "NOT_FOUND", "vm not found");
        }
        fake
    }

    /// Sandbox `claude-proj`, whose workspace is the cwd.
    pub fn project(&self, state: &str) -> &FakeRunner {
        let ws = self.ctx.cwd.display().to_string();
        self.sandbox("claude-proj", state, &Self::project_labels(&ws))
    }

    /// `claude-proj` is missing for `lookups` status calls, then exists as `created`.
    pub fn project_creatable(&self, lookups: usize) -> &FakeRunner {
        let ws = self.ctx.cwd.display().to_string();
        self.creatable("claude-proj", &Self::project_labels(&ws), lookups)
    }

    fn project_labels(ws: &str) -> [(&str, &str); 2] {
        [("sbx.agent", "claude"), ("sbx.workspace", ws)]
    }

    /// The smolvm calls that start with `prefix`.
    pub fn calls_of(&self, prefix: &str) -> Vec<String> {
        let mut calls = self.calls();
        calls.retain(|l| l.starts_with(prefix));
        calls
    }

    /// Whether smolvm got a call starting with `prefix`.
    pub fn made(&self, prefix: &str) -> bool {
        !self.calls_of(prefix).is_empty()
    }

    /// Makes `machine status` answer that no machine of that name exists.
    pub fn no_machine(&self) -> &FakeRunner {
        self.runner()
            .fail(&["machine", "status"], "NOT_FOUND", "vm not found")
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

/// The argv of `sh -c script` run as root in `machine`.
pub fn root_sh<'a>(machine: &'a str, script: &'a str) -> [&'a str; 10] {
    [
        "machine", "exec", "--name", machine, "-u", "root", "--", "sh", "-c", script,
    ]
}

/// `machine status --json` output for a smolbento sandbox; `sbx.mapped` is `true` unless given.
pub fn machine_json(machine: &str, state: &str, labels: &[(&str, &str)]) -> String {
    let mut labels: BTreeMap<&str, &str> = labels.iter().copied().collect();
    labels.entry("sbx.mapped").or_insert("true");
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
    t.runner()
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

type Seen = std::rc::Rc<std::cell::RefCell<Vec<bool>>>;

/// A running sandbox whose `sbx.ssh-agent` label is `grant` (none when `None`), and a record of
/// whether its agent socket was served during each interactive exec.
pub fn agent_probe(t: &TestEnv, tag: &str, grant: Option<&str>) -> (String, Seen) {
    let label = grant.map(|g| ("sbx.ssh-agent", g));
    probe(t, "agent", tag, label, crate::bridge::agent_socket)
}

/// A running sandbox (`sbx.bridge=true` when `bridge`) with a name of its own: its bridge socket is
/// under the real `/tmp/sbt-<uid>`, shared with other test processes. Returns the name and, for each
/// interactive call, whether the bridge socket answered while the user was attached.
pub fn bridge_probe(t: &TestEnv, tag: &str, bridge: bool) -> (String, Seen) {
    let label = bridge.then_some(("sbx.bridge", "true"));
    probe(t, "bridge", tag, label, crate::bridge::host_socket)
}

fn probe(
    t: &TestEnv,
    kind: &str,
    tag: &str,
    label: Option<(&str, &str)>,
    socket: fn(&str) -> std::path::PathBuf,
) -> (String, Seen) {
    let name = format!("{kind}-{}-{tag}", std::process::id());
    let mut labels = vec![("sbx.agent", "shell"), ("sbx.workspace", "/w/proj")];
    labels.extend(label);
    // Later registrations win: the catch-all goes first.
    t.runner().ok(&["machine"], "");
    let (seen, probe) = socket_probe(socket(&name));
    t.sandbox(&name, "running", &labels)
        .during_interactive(probe);
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

pub fn labels(name: &str) -> Vec<(&'static str, String)> {
    vec![
        ("sbx.name", name.to_string()),
        ("sbx.agent", "claude".into()),
        ("sbx.created", "999000".into()),
    ]
}

pub fn json(machine: &str, state: &str, name: &str) -> String {
    let l = labels(name);
    let pairs: Vec<(&str, &str)> = l.iter().map(|(k, v)| (*k, v.as_str())).collect();
    machine_json(machine, state, &pairs)
}

/// Fake smolvm for one create of `name` that succeeds.
pub fn creatable_as(t: &TestEnv, name: &str) {
    t.creatable(
        name,
        &[("sbx.agent", "claude"), ("sbx.created", "999000")],
        1,
    );
}

pub fn global_github_secret(t: &TestEnv) {
    use crate::secrets::{SecretEntry, SecretsFile, Source, scope_for};
    let entry = SecretEntry {
        service: "github".into(),
        scope: scope_for(None),
        source: Source::Keychain,
    };
    t.ctx.store.set(&entry.account(), "gh-123").unwrap();
    let mut f = SecretsFile::default();
    f.set(entry);
    f.save(&t.ctx.paths).unwrap();
}

/// The sandbox's rules as (decision, resources).
pub fn sandbox_rules(t: &TestEnv, name: &str) -> Vec<(String, Vec<String>)> {
    crate::policy::Policy::load(&t.ctx.paths)
        .unwrap()
        .sandboxes
        .get(name)
        .map(|s| {
            s.rules
                .iter()
                .map(|r| (r.decision.name().to_string(), r.resources.clone()))
                .collect()
        })
        .unwrap_or_default()
}

pub fn deny(resources: &[&str]) -> (String, Vec<String>) {
    (
        "deny".into(),
        resources.iter().map(|r| r.to_string()).collect(),
    )
}

pub fn saved_template(t: &TestEnv, name: &str, agent: &str) -> crate::templates::Entry {
    let src = t.ctx.cwd.join("p.smolmachine");
    std::fs::write(&src, "packed").unwrap();
    let r = crate::templates::TemplateRef::parse(name).unwrap();
    crate::templates::Store::new(&t.ctx.paths)
        .add(
            crate::templates::Entry {
                repository: r.repository,
                tag: r.tag,
                agent: agent.into(),
                image: "docker/sandbox-templates:shell-docker-0.10.0".into(),
                docker: false,
                created_at: "1970-01-12T13:46:30Z".into(),
                ..Default::default()
            },
            &src,
        )
        .unwrap()
}
