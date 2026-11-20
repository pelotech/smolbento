use std::collections::BTreeMap;

use anyhow::Result;
use clap::Parser;

use crate::cli::{Cli, Ctx, dispatch};
use crate::config::{Paths, Settings};
use crate::smolvm::Smolvm;
use crate::smolvm::fake::FakeRunner;
pub use crate::testgit::*;

/// A sandbox for [`TestEnv::sandboxes`]: (name, state, labels besides `sbx.name`).
pub type Listed<'a> = (&'a str, &'a str, &'a [(&'a str, &'a str)]);

pub struct TestEnv {
    pub ctx: Ctx<FakeRunner>,
    /// Keeps the temp dirs alive for the test's duration.
    _dir: tempfile::TempDir,
}

/// A context with temp config/cache/data dirs, cwd `<tmp>/proj`, `now` = 1_000_000 and smolvm
/// 1.35.1.
pub fn test_env(extra_env: &[(&str, &str)]) -> TestEnv {
    // Under /tmp, so `~/.smolbento`'s sockets fit macOS's limit.
    let dir = tempfile::tempdir_in("/tmp").unwrap();
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
    // A home of its own (smolbento's `~/.smolbento` lives under it); a test may set another.
    env.insert(
        "HOME".to_string(),
        dir.path().join("home").display().to_string(),
    );
    // An explicit smolvm, so no command downloads one (FakeRunner answers instead).
    env.insert(
        "SMOLBENTO_SMOLVM".to_string(),
        "/nonexistent/smolvm".to_string(),
    );
    // Built-in agents load these stand-ins, never Docker Hub.
    let agent_kits_dir = dir.path().join("agent-kits");
    crate::agents::write_stand_ins(&agent_kits_dir).unwrap();
    env.insert(
        "SMOLBENTO_AGENT_KITS_DIR".to_string(),
        agent_kits_dir.display().to_string(),
    );
    for (k, v) in extra_env {
        env.insert(k.to_string(), v.to_string());
    }
    let paths = Paths::from_env(&env).unwrap();
    std::fs::create_dir_all(&paths.config).unwrap();
    std::fs::write(paths.policy_file(), "mode = \"allow-all\"\n").unwrap();
    let (settings, config_error) = Settings::load(&paths, env.clone());
    let smolvm = crate::smolvm::locate::locate(&settings, &env).unwrap();
    let fake = FakeRunner::new();
    fake.ok(&["--version"], "smolvm 1.35.1\n");
    let cwd = dir.path().join("proj");
    std::fs::create_dir_all(&cwd).unwrap();
    let cwd = cwd.canonicalize().unwrap();
    TestEnv {
        ctx: Ctx {
            vm: Smolvm::new(fake),
            settings,
            smolvm,
            services: crate::host_service::HostServices::disabled(),
            paths,
            cwd,
            env,
            now: 1_000_000,
            stdin_tty: false,
            no_input: false,
            stdout_tty: false,
            store: Box::new(crate::secrets::store::MemoryStore::default()),
            config_error,
            out: crate::ctx::Out::Buffer(Default::default()),
            input: crate::ctx::In::Buffer(Default::default()),
            args: vec![],
            program: "bento".into(),
        },
        _dir: dir,
    }
}

/// A context that may load kits from local directories.
pub fn kit_env() -> TestEnv {
    test_env(&[("SMOLBENTO_KIT_ALLOW_LOCAL_KITS", "true")])
}

/// The path of the v2 kit fixture `name`.
pub fn v2_fixture(name: &str) -> String {
    format!(
        "{}/tests/fixtures/kits/v2/{name}",
        env!("CARGO_MANIFEST_DIR")
    )
}

impl TestEnv {
    /// Makes stdin a terminal that answers prompts with `answers`, one line each.
    pub fn answer(&mut self, answers: &str) {
        self.ctx.stdin_tty = true;
        self.stdin(answers);
    }

    /// Makes `text` what commands read from stdin.
    pub fn stdin(&mut self, text: &str) {
        self.ctx.input = crate::ctx::In::Buffer(std::io::Cursor::new(text.into()).into());
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

    /// Runs `bento ARGS`.
    pub fn sbt(&mut self, args: &[&str]) -> Result<i32> {
        sbt(&mut self.ctx, args)
    }

    /// Runs `bento ARGS`, which must fail, and returns the error's message.
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

    /// Makes `machine status` answer with sandbox `name` (machine `sbx-<name>`) in `state`. It
    /// launches `bash` unless `labels` give an `sbx.command`, as every kit sandbox records one.
    pub fn sandbox(&self, name: &str, state: &str, labels: &[(&str, &str)]) -> &FakeRunner {
        self.runner()
            .ok(&["machine", "status"], &sandbox_json(name, state, labels))
    }

    /// Makes `machine ls` list these (name, state, labels) sandboxes and `machine status -n` answer
    /// for each, labelled as [`Self::sandbox`] labels them.
    pub fn sandboxes(&self, list: &[Listed]) -> &FakeRunner {
        let jsons: Vec<String> = list
            .iter()
            .map(|(name, state, labels)| sandbox_json(name, state, labels))
            .collect();
        let fake = self.runner();
        fake.ok(
            &["machine", "ls", "--json"],
            &format!("[{}]", jsons.join(",")),
        );
        for ((name, ..), json) in list.iter().zip(&jsons) {
            let machine = crate::sandbox::name::machine_name(name);
            fake.ok(&["machine", "status", "-n", &machine], json);
        }
        fake
    }

    /// Sandbox `claude-proj`, running, with workspace `/w/proj`.
    pub fn running_proj(&self) -> &FakeRunner {
        self.sandbox("claude-proj", "running", &[("sbx.workspace", "/w/proj")])
    }

    /// A sandbox from before agents were kits: no `sbx.command`.
    pub fn old_sandbox(&self, name: &str, state: &str, labels: &[(&str, &str)]) -> &FakeRunner {
        let mut all = vec![("sbx.name", name)];
        all.extend_from_slice(labels);
        self.machine(&crate::sandbox::name::machine_name(name), state, &all)
    }

    /// Sandbox `name` is missing until the command creates it, then exists as `created`.
    pub fn creatable(&self, name: &str, labels: &[(&str, &str)]) -> &FakeRunner {
        self.sandbox(name, "created", labels)
            .missing_until_created(&crate::sandbox::name::machine_name(name))
    }

    /// Sandbox `claude-proj`, whose workspace is the cwd.
    pub fn project(&self, state: &str) -> &FakeRunner {
        let ws = self.ctx.cwd.display().to_string();
        self.sandbox("claude-proj", state, &Self::project_labels(&ws))
    }

    /// `claude-proj` is missing until the command creates it, then exists as `created`.
    pub fn project_creatable(&self) -> &FakeRunner {
        let ws = self.ctx.cwd.display().to_string();
        self.creatable("claude-proj", &Self::project_labels(&ws))
    }

    fn project_labels(ws: &str) -> [(&str, &str); 3] {
        [
            ("sbx.agent", "claude"),
            ("sbx.workspace", ws),
            (
                "sbx.command",
                r#"["claude","--dangerously-skip-permissions"]"#,
            ),
        ]
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

    /// The `machine create` call.
    pub fn create_line(&self) -> String {
        let calls = self.calls();
        let create = calls.iter().find(|l| l.starts_with("machine create"));
        create.unwrap_or_else(|| panic!("{calls:#?}")).clone()
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

impl TestEnv {
    /// Reloads settings from `ctx.env` (as `main` would) and the smolvm they pick.
    pub fn reload_settings(&mut self) {
        self.ctx.settings = Settings::load(&self.ctx.paths, self.ctx.env.clone()).0;
        self.ctx.smolvm = crate::smolvm::locate::locate(&self.ctx.settings, &self.ctx.env).unwrap();
    }

    /// Runs the downloaded smolvm rather than test_env's explicit stand-in.
    pub fn use_managed_smolvm(&mut self) {
        self.ctx.env.remove("SMOLBENTO_SMOLVM");
        self.reload_settings();
    }
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

/// `machine status --json` output for sandbox `name`: `sbx.name`, `labels`, and `sbx.command` =
/// `["bash"]` unless `labels` give one.
pub fn sandbox_json(name: &str, state: &str, labels: &[(&str, &str)]) -> String {
    let mut all = vec![("sbx.name", name)];
    if !labels.iter().any(|(k, _)| *k == "sbx.command") {
        all.push(("sbx.command", r#"["bash"]"#));
    }
    all.extend_from_slice(labels);
    machine_json(&crate::sandbox::name::machine_name(name), state, &all)
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

/// The labels [`labels`] gives besides `sbx.name`: a claude sandbox created at 999000.
pub const CLAUDE_LABELS: &[(&str, &str)] = &[("sbx.agent", "claude"), ("sbx.created", "999000")];

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
    t.creatable(name, &[("sbx.agent", "claude"), ("sbx.created", "999000")]);
}

pub fn global_github_secret(t: &TestEnv) {
    global_secret(t, "github", "gh-123");
}

/// A global secret for `service` in the keychain store.
pub fn global_secret(t: &TestEnv, service: &str, value: &str) {
    save_secret(t, service, None, value);
}

/// A secret for `service` in the keychain store, scoped to `sandbox` (global when `None`).
pub fn save_secret(t: &TestEnv, service: &str, sandbox: Option<&str>, value: &str) {
    use crate::secrets::{SecretEntry, SecretsFile, Source, scope_for};
    let entry = SecretEntry {
        service: service.into(),
        scope: scope_for(sandbox),
        source: Source::Keychain,
    };
    t.ctx.store.set(&entry.account(), value).unwrap();
    let mut f = SecretsFile::load(&t.ctx.paths).unwrap_or_default();
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

/// A saved template of agent `agent`'s stand-in kit (unpinned: it's a local layout).
pub fn saved_template(t: &TestEnv, name: &str, agent: &str) -> crate::templates::Entry {
    add_template(t, name, agent, saved_template_kits(t, agent))
}

/// The kit records of a template of agent `agent`: its stand-in kit.
pub fn saved_template_kits(t: &TestEnv, agent: &str) -> Vec<crate::sandbox::labels::KitRecord> {
    vec![crate::sandbox::labels::KitRecord {
        name: agent.into(),
        reference: crate::agents::kit_ref(&t.ctx.env, agent).unwrap(),
        provides: vec![],
        format: Some(crate::kits::model::Format::V3),
        args: Default::default(),
    }]
}

/// A template saved before agents were kits: no kit records.
pub fn legacy_template(t: &TestEnv, name: &str, agent: &str) -> crate::templates::Entry {
    add_template(t, name, agent, vec![])
}

fn add_template(
    t: &TestEnv,
    name: &str,
    agent: &str,
    kits: Vec<crate::sandbox::labels::KitRecord>,
) -> crate::templates::Entry {
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
                kits,
                ..Default::default()
            },
            &src,
        )
        .unwrap()
}

/// The `claude` stand-in's descriptor: the published kit's shape, trimmed (an API key with a
/// non-passthrough OAuth part, its agent file and skills, an install step that shows the mode).
pub const CLAUDE_STAND_IN: &str = r#"{
  "schemaVersion": "3",
  "kind": "workload",
  "args": {"model": {"default": "", "description": "Claude model to use"}},
  "capabilities": [
    {"type": "com.docker.sandbox/sbx@1"},
    {"type": "com.docker.sandbox/network-policy@1",
     "config": {"runtime": {"allow": ["api.anthropic.com:443", "platform.claude.com:443"]}}},
    {"type": "com.docker.sandbox/credential@1", "optional": true, "config": {
      "service": "anthropic", "phase": "runtime",
      "apiKey": {"inject": [{"domain": "api.anthropic.com", "header": "x-api-key", "format": "%s"}]},
      "oauth": {"tokenEndpoint": {"host": "platform.claude.com", "path": "/v1/oauth/token"},
                "sentinels": {"accessToken": "sk-ant-oat01-proxy-managed"}}}},
    {"type": "com.docker.sandbox/lifecycle@1", "config": {"install": [
      {"command": "echo mode=$SBX_CRED_ANTHROPIC_MODE", "env": ["SBX_CRED_ANTHROPIC_MODE"],
       "user": "agent"}]}},
    {"type": "com.docker.sandbox/agent-skills@1", "optional": true,
     "config": {"path": "/home/agent/.claude/skills"}},
    {"type": "com.docker.sandbox/agent-context@1", "optional": true,
     "config": {"content": "Claude Code notes\n", "directory": "/home/agent/.claude",
                "filename": "CLAUDE.md"}},
    {"type": "com.docker.sandbox/agent-context@2", "optional": true,
     "config": {"content": "Claude Code notes\n", "directory": "/home/agent/.claude",
                "filename": "CLAUDE.md"}}
  ]
}"#;

/// Replaces agent `name`'s stand-in in `t` with one whose descriptor is `descriptor`.
pub fn agent_stand_in(t: &TestEnv, name: &str, descriptor: &str) {
    let dir = std::path::Path::new(&t.ctx.env[crate::agents::KITS_DIR_ENV]);
    crate::agents::write_stand_in(dir, name, descriptor).unwrap();
}

/// A tiny HTTP server answering every GET with `body` (200), until the test ends. Returns its base
/// URL (`http://127.0.0.1:PORT`) and the request lines it has seen.
pub fn http_server(body: Vec<u8>) -> (String, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
    use std::io::{BufRead, BufReader, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let log = seen.clone();
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut conn) = conn else { break };
            let mut reader = BufReader::new(conn.try_clone().unwrap());
            let mut line = String::new();
            let _ = reader.read_line(&mut line);
            log.lock().unwrap().push(line.trim().to_string());
            // Skip the headers.
            loop {
                let mut h = String::new();
                if reader.read_line(&mut h).unwrap_or(0) == 0 || h == "\r\n" {
                    break;
                }
            }
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = conn.write_all(head.as_bytes());
            let _ = conn.write_all(&body);
        }
    });
    (base, seen)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kits::model::{CapBody, Kind, Source};
    use crate::kits::registry::read_layout;

    #[test]
    fn agent_stand_ins_read_as_kits() {
        let dir = tempfile::tempdir().unwrap();
        crate::agents::write_stand_ins(dir.path()).unwrap();
        for name in crate::agents::NAMES {
            let k = read_layout(&dir.path().join(name), Source::Registry(name.into())).unwrap();
            assert_eq!(k.kind, Kind::Workload, "{name}");
            assert!(k.starts_docker, "{name}");
            let want: Vec<String> = match name {
                "shell" => vec!["bash".into(), "-l".into()],
                _ => vec![name.into()],
            };
            assert_eq!(k.command, Some(want), "{name}");
        }
        let claude = tempfile::tempdir().unwrap();
        crate::kits::registry::fixtures::oci_layout(
            claude.path(),
            Some(CLAUDE_STAND_IN),
            &[],
            "{}",
        );
        let claude = read_layout(claude.path(), Source::Registry("claude".into())).unwrap();
        let cred = claude
            .caps
            .iter()
            .find_map(|c| match &c.body {
                CapBody::Credential(r) => Some(r),
                _ => None,
            })
            .expect("a credential");
        assert_eq!(cred.service, "anthropic");
        assert!(!cred.oauth.as_ref().unwrap().passthrough);
    }
}
