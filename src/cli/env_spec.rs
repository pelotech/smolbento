//! A loaded `sbxenv.yaml` as `create`'s options, the sandbox's secrets, and a summary.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use super::SandboxOpts;
use crate::agents;
use crate::env::file::{
    Binding, EnvFile, KitEntry, Lifecycle, PinnedKit, Port, RegistryDecl, SecretDecl, Workspace,
};
use crate::env::lifecycle::{Phase, Vars};
use crate::env::load::Loaded;
use crate::env::plan::{HOST_COMMANDS, Line, Marker, Resource, When, render};
use crate::sandbox::{name as sandbox_name, options};
use crate::secrets::SecretsFile;
use crate::util::sha256_digest;

#[derive(Debug)]
pub struct EnvSpec {
    pub name: String,
    /// The agent or workload kit source, the workspace, then extra workspaces (`path[:ro]`).
    pub targets: Vec<String>,
    pub opts: SandboxOpts,
    /// The file's env, for run/exec sessions.
    pub env: Vec<(String, String)>,
    /// Sorted by service.
    pub secrets: Vec<(String, SecretDecl)>,
    /// Registry host to its login, sorted by host.
    pub registries: Vec<(String, RegistryDecl)>,
    /// Service to the domains bound to it, sorted by service.
    pub bindings: Vec<(String, Binding)>,
    /// MCP server name and URL, in the file's order.
    pub mcp: Vec<(String, String)>,
    /// Host commands, each with an absolute working directory.
    pub lifecycle: Lifecycle,
    /// What `env run` launches in place of the agent's program, and with which arguments.
    pub entrypoint: Option<Vec<String>>,
    pub cmd: Option<Vec<String>>,
}

/// Command-line flags that override the file.
#[derive(Debug, Default)]
pub struct Overrides {
    pub name: Option<String>,
    pub clone: Option<bool>,
    pub kit_arg: Vec<String>,
    pub kit_args_file: Vec<PathBuf>,
}

/// The sandbox name: `overrides_name`, the file's `name`, or `<agent>-<basename>` of the
/// workspace (mountless: of the project directory). Checks nothing else.
pub fn name(loaded: &Loaded, overrides_name: Option<&str>) -> Result<String> {
    let f = &loaded.file;
    let name = match overrides_name.or(f.name.as_deref()) {
        Some(n) => n.to_string(),
        None => {
            let dir = match workspace(f) {
                Some((p, _)) => Path::new(p),
                None => loaded.project_dir.as_path(),
            };
            let base = dir.file_name().unwrap_or_default().to_string_lossy();
            format!("{}-{base}", f.agent.as_deref().unwrap_or_default())
        }
    };
    sandbox_name::validate(&name)?;
    Ok(name)
}

/// What `create` takes for this file, checked as far as it can be without side effects.
/// `secrets` is the secret store, for the services it knows.
pub fn spec(loaded: &Loaded, overrides: &Overrides, secrets: &SecretsFile) -> Result<EnvSpec> {
    let f = &loaded.file;
    let name = name(loaded, overrides.name.as_deref())?;
    let agent = f.agent.as_deref().unwrap_or_default();

    // A preset takes every kit as a mixin; otherwise the kit named like `agent` is the workload.
    let mut kits: Vec<String> = f
        .kits
        .iter()
        .flatten()
        .map(|k| source(k).to_string())
        .collect();
    // Registry references aren't checked: that needs the network.
    for k in &kits {
        crate::kits::load::check_kind(k)?;
        if k.starts_with('/') && !Path::new(k).exists() {
            bail!("{k}: no such file or directory");
        }
    }
    let target = if agents::find(agent).is_some() {
        agent.to_string()
    } else if let Some(r) = agents::retired(agent) {
        // As in sbx: a retired agent runs from the kit that keeps it, listed in `kits:`.
        let i = kits
            .iter()
            .position(|k| kit_name(k) == kit_name(r.kit))
            .with_context(|| r.env_file_refusal())?;
        kits.remove(i)
    } else {
        let i = kits
            .iter()
            .position(|k| kit_name(k) == agent)
            .with_context(|| agents::unknown(agent))?;
        kits.remove(i)
    };
    let kit_pins = f
        .kits
        .iter()
        .flatten()
        .filter_map(|k| match k {
            KitEntry::Pinned(PinnedKit {
                source,
                args: Some(args),
            }) => Some((
                source.clone(),
                args.iter().map(|(k, v)| format!("{k}={v}")).collect(),
            )),
            _ => None,
        })
        .collect();

    let mut targets = vec![target];
    let extra = f.additional_workspaces.iter().flatten();
    let paths = workspace(f)
        .map(|(p, _)| (p, false))
        .into_iter()
        .chain(extra.map(|w| (w.path.as_str(), w.read_only == Some(true))));
    for (path, read_only) in paths {
        if !Path::new(path).is_dir() {
            bail!("{path}: no such directory");
        }
        targets.push(if read_only {
            format!("{path}:ro")
        } else {
            path.to_string()
        });
    }

    let mut publish = Vec::new();
    for p in f.ports.iter().flatten() {
        publish.push(publish_spec(p)?);
    }

    let secret_decls: Vec<(String, SecretDecl)> =
        f.secrets.clone().unwrap_or_default().into_iter().collect();
    let bound = f.bindings.iter().flatten().map(|(s, _)| s);
    if let Some(service) = secret_decls
        .iter()
        .map(|(s, _)| s)
        .chain(bound)
        .find(|s| secrets.service(s).is_none())
    {
        bail!(crate::secrets::services::unknown(service));
    }
    let mcp: Vec<(String, String)> = f
        .mcp
        .iter()
        .flat_map(|m| &m.servers)
        .filter_map(|s| Some((s.name.clone(), s.url.clone()?)))
        .collect();

    let env: Vec<(String, String)> = f.env.clone().unwrap_or_default().into_iter().collect();
    let o = f.sandbox_options.as_ref();
    let clone = overrides
        .clone
        .or(workspace(f).and_then(|(_, c)| c))
        .unwrap_or(false);
    let opts = SandboxOpts {
        name: Some(name.clone()),
        cpus: o.and_then(|o| o.cpus),
        memory: o.and_then(|o| o.memory.clone()),
        env: env.iter().map(|(k, v)| format!("{k}={v}")).collect(),
        publish,
        mount: f
            .mounts
            .iter()
            .flatten()
            .map(|(guest, host)| format!("{host}:{guest}"))
            .collect(),
        template: o.and_then(|o| o.template.clone()),
        skills: o.and_then(|o| o.skills.clone()),
        // `load` refuses every policy but `missing` and `never`.
        pull: o.and_then(|o| o.pull_policy.clone()),
        // The file's servers, given to the agent as `--static-mcp` gives them.
        static_mcp: (!mcp.is_empty()).then(|| {
            mcp.iter()
                .map(|(n, _)| n.as_str())
                .collect::<Vec<_>>()
                .join(",")
        }),
        clone,
        no_fuse: o.and_then(|o| o.fuse) == Some(false),
        read_only_files: if o.and_then(|o| o.writable_env_files) == Some(true) {
            Vec::new()
        } else {
            files_in_mounted_workspaces(loaded, clone)
        },
        kit: kits,
        kit_arg: overrides.kit_arg.clone(),
        kit_args_file: overrides.kit_args_file.clone(),
        kit_pins,
        ..Default::default()
    };
    Ok(EnvSpec {
        name,
        targets,
        opts,
        env,
        secrets: secret_decls,
        registries: f
            .registries
            .clone()
            .unwrap_or_default()
            .into_iter()
            .collect(),
        bindings: f.bindings.clone().unwrap_or_default().into_iter().collect(),
        mcp,
        lifecycle: lifecycle(loaded),
        entrypoint: f.entrypoint.clone(),
        cmd: f.cmd.clone(),
    })
}

/// The plan section of the host commands.
pub const LIFECYCLE: &str = "LIFECYCLE";

/// The `rm` plan: the sandbox and what is scoped to it (`secrets`, `registries`), all to
/// destroy, and the `pre_remove` commands to run.
pub fn remove_summary(
    sandbox: Option<&str>,
    secrets: &[String],
    bindings: &[Resource],
    registries: &[String],
    pre_remove: &[Resource],
) -> String {
    let gone = |section: &str, name: &str| {
        Line::new(Marker::Destroy, &Resource::new(section, name, Vec::new()))
    };
    let mut lines: Vec<Line> = sandbox.iter().map(|n| gone("SANDBOX", n)).collect();
    lines.extend(secrets.iter().map(|s| gone("SECRETS", s)));
    lines.extend(bindings.iter().map(|r| Line::new(Marker::Destroy, r)));
    lines.extend(registries.iter().map(|h| gone("REGISTRIES", h)));
    lines.extend(pre_remove.iter().map(|r| Line::new(Marker::Run, r)));
    render(&lines, HOST_COMMANDS)
}

/// The `ENVIRONMENT` block: name and file(s).
pub fn header(loaded: &Loaded, name: &str) -> String {
    let files: Vec<String> = loaded
        .files
        .iter()
        .map(|p| p.display().to_string())
        .collect();
    match files.as_slice() {
        [file] => format!("ENVIRONMENT\n  Name:  {name}\n  File:  {file}\n"),
        _ => format!(
            "ENVIRONMENT\n  Name:   {name}\n  Files:  {}\n",
            files.join("\n          ")
        ),
    }
}

/// What applying the file sets up, in the plan's order.
pub fn resources(loaded: &Loaded, spec: &EnvSpec) -> Vec<Resource> {
    let f = &loaded.file;
    let field = |label: &str, value: &str| (label.to_string(), value.to_string());
    let mut out = Vec::new();

    let mut sandbox = vec![field("agent", f.agent.as_deref().unwrap_or_default())];
    if let Some(o) = &f.sandbox_options {
        // sbx's order; `writableEnvFiles` only when set.
        let opts = [
            ("template", o.template.clone()),
            ("memory", o.memory.clone()),
            ("cpus", o.cpus.map(|c| c.to_string())),
            ("pullPolicy", o.pull_policy.clone()),
            ("skills", o.skills.clone()),
            ("fuse", o.fuse.map(|f| f.to_string())),
            (
                "writableEnvFiles",
                o.writable_env_files.filter(|w| *w).map(|w| w.to_string()),
            ),
        ];
        for (k, v) in opts {
            if let Some(v) = v {
                sandbox.push(field(&format!("sandboxOptions.{k}"), &v));
            }
        }
    }
    out.push(Resource::new("SANDBOX", &spec.name, sandbox));

    for k in f.kits.iter().flatten() {
        let args = match k {
            KitEntry::Pinned(PinnedKit {
                args: Some(args), ..
            }) => args
                .iter()
                .map(|(name, value)| field(&format!("args.{name}"), value))
                .collect(),
            _ => Vec::new(),
        };
        out.push(Resource::new("KITS", source(k), args));
    }

    let host_path = |name: &str, fields| Resource {
        host_path: true,
        ..Resource::new("WORKSPACES", name, fields)
    };
    if let Some((path, _)) = workspace(f) {
        let clone = spec.opts.clone.then(|| field("clone", "true"));
        out.push(host_path(path, clone.into_iter().collect()));
    }
    for w in f.additional_workspaces.iter().flatten() {
        let ro = (w.read_only == Some(true)).then(|| field("readOnly", "true"));
        out.push(host_path(&w.path, ro.into_iter().collect()));
    }
    for (guest, host) in f.mounts.iter().flatten() {
        out.push(Resource {
            host_path: true,
            ..Resource::new("MOUNTS", &format!("{host} -> {guest}"), Vec::new())
        });
    }

    // Applied by every `env run`, so listed every time. sbx prints the list as quoted JSON.
    for (name, argv) in [("entrypoint", &spec.entrypoint), ("cmd", &spec.cmd)] {
        if let Some(argv) = argv {
            let json = serde_json::to_string(argv).unwrap_or_default();
            out.push(Resource {
                when: When::EveryRun,
                ..Resource::new(
                    "AGENT LAUNCH",
                    name,
                    vec![field("argv", &format!("{json:?}"))],
                )
            });
        }
    }

    for (k, v) in &spec.env {
        out.push(Resource {
            when: When::Live,
            ..Resource::new("ENV", k, vec![field("value", v)])
        });
    }

    for (service, s) in &spec.secrets {
        // Never the value: the plan is printed, and recorded when approved.
        let mut fields = source_fields("", s);
        // Whether a command or reference is resolved once or at every start.
        if s.snapshot == Some(true) {
            fields.push(field("snapshot", "true"));
        }
        if s.no_verify == Some(true) {
            fields.push(field("noVerify", "true"));
        }
        out.push(Resource {
            host_command: s.command.is_some(),
            ..Resource::new("SECRETS", service, fields)
        });
    }

    out.extend(binding_resources(&spec.bindings));

    for (host, r) in &spec.registries {
        let mut fields = source_fields("secret.", &r.secret);
        if let Some(u) = &r.username {
            fields.extend(source_fields("username.", u));
        }
        out.push(Resource {
            host_command: r.secret.command.is_some()
                || r.username.as_ref().is_some_and(|u| u.command.is_some()),
            ..Resource::new("REGISTRIES", host, fields)
        });
    }

    for (name, url) in &spec.mcp {
        out.push(Resource::new("MCP SERVERS", name, vec![field("url", url)]));
    }

    for p in f.ports.iter().flatten() {
        let host = p.host.map_or("ephemeral".to_string(), |h| h.to_string());
        let mut fields = vec![field("host", &host)];
        if let Some(ip) = &p.host_ip {
            fields.push(field("hostIP", ip));
        }
        out.push(Resource::new(
            "PORTS",
            &format!("{}/{}", p.sandbox, p.protocol_name()),
            fields,
        ));
    }
    out.extend(lifecycle_resources(loaded, &spec.lifecycle));
    out
}

/// The file's host commands, each with its working directory: the project directory unless it
/// names one.
pub fn lifecycle(loaded: &Loaded) -> Lifecycle {
    let mut lifecycle = loaded.file.lifecycle.clone().unwrap_or_default();
    let project = loaded.project_dir.display().to_string();
    for c in lifecycle.commands_mut() {
        c.workdir.get_or_insert_with(|| project.clone());
    }
    lifecycle
}

/// What host commands learn about the environment (`SBX_*`).
pub fn vars(loaded: &Loaded, name: &str) -> Vars {
    let f = &loaded.file;
    Vars {
        files: loaded.files.clone(),
        project_dir: loaded.project_dir.clone(),
        sandbox: name.to_string(),
        agent: f.agent.clone().unwrap_or_default(),
        workspace: workspace(f).map(|(path, _)| path.to_string()),
    }
}

/// The `LIFECYCLE` section: one resource per command, identified by its phase and position.
pub fn lifecycle_resources(loaded: &Loaded, lifecycle: &Lifecycle) -> Vec<Resource> {
    let field = |label: &str, value: &str| (label.to_string(), value.to_string());
    let mut out = Vec::new();
    for (phase, commands) in lifecycle.phases() {
        let when = match phase {
            Phase::Initialize => When::EveryRun,
            Phase::PostCreate => When::Create,
            Phase::PreRemove => When::Removal,
        };
        let phase = phase.name();
        for (i, c) in commands.iter().enumerate() {
            let mut fields = vec![field("workdir", c.workdir.as_deref().unwrap_or_default())];
            if let Some(name) = &c.name {
                fields.push(field("name", name));
            }
            if let Some(timeout) = &c.timeout {
                fields.push(field("timeout", timeout));
            }
            for (n, file) in loaded.files.iter().enumerate() {
                fields.push(field(
                    &format!("envFiles[{n}]"),
                    &file.display().to_string(),
                ));
            }
            out.push(Resource {
                id: format!("{phase}[{i}]"),
                when,
                host_command: true,
                ..Resource::new(LIFECYCLE, &format!("{phase}: {}", c.command), fields)
            });
        }
    }
    out
}

/// The `BINDINGS` section: one resource per service.
pub fn binding_resources(bindings: &[(String, Binding)]) -> Vec<Resource> {
    bindings
        .iter()
        .map(|(service, b)| {
            let (api_key, oauth) = b.domains();
            let kinds = [("apiKey", &b.api_key, api_key), ("oauth", &b.oauth, oauth)];
            let fields = kinds
                .into_iter()
                .filter(|(_, given, _)| given.is_some())
                .map(|(kind, _, d)| (format!("{kind}.domains"), d.join(", ")))
                .collect();
            Resource::new("BINDINGS", service, fields)
        })
        .collect()
}

/// A secret source as the plan shows it, under `prefix`: never a literal value.
fn source_fields(prefix: &str, s: &SecretDecl) -> Vec<(String, String)> {
    let field = |label: &str, value: &str| (format!("{prefix}{label}"), value.to_string());
    match (&s.value, &s.r#ref, &s.command) {
        (Some(v), _, _) => vec![field("value", &sha256_digest(v.as_bytes()))],
        (_, Some(r), _) => vec![field("ref", r)],
        (_, _, Some(c)) => vec![
            field("command", c),
            field("workdir", "fresh host temporary directory"),
        ],
        _ => vec![],
    }
}

/// The environment's files that a writable mounted workspace holds: sbx mounts them read-only
/// unless `writableEnvFiles`, and smolvm can't mount a single file, so starts make them read-only
/// in the guest instead. A cloned workspace is a copy, and a read-only one is read-only already.
fn files_in_mounted_workspaces(loaded: &Loaded, clone: bool) -> Vec<String> {
    let f = &loaded.file;
    let primary = workspace(f).filter(|_| !clone).map(|(p, _)| p.to_string());
    let extra = f.additional_workspaces.iter().flatten();
    let writable: Vec<String> = primary
        .into_iter()
        .chain(
            extra
                .filter(|w| w.read_only != Some(true))
                .map(|w| w.path.clone()),
        )
        .collect();
    loaded
        .files
        .iter()
        .filter(|file| writable.iter().any(|w| file.starts_with(w)))
        .map(|file| file.display().to_string())
        .collect()
}

/// The primary workspace's path and `clone`.
fn workspace(f: &EnvFile) -> Option<(&str, Option<bool>)> {
    match f.workspace.as_ref()? {
        Workspace::Path(p) => Some((p, None)),
        Workspace::Object(o) => Some((&o.path, o.clone)),
    }
}

fn source(k: &KitEntry) -> &str {
    match k {
        KitEntry::Source(s) | KitEntry::Pinned(PinnedKit { source: s, .. }) => s,
    }
}

/// A local kit's directory name, or a registry reference's last repository component without tag
/// or digest. Local sources are absolute by now.
fn kit_name(source: &str) -> &str {
    if source.starts_with('/') {
        return Path::new(source)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(source);
    }
    let repo = source.split('@').next().unwrap_or(source);
    let last = repo.rsplit('/').next().unwrap_or(repo);
    last.split(':').next().unwrap_or(last)
}

/// `tcp4`/`udp4` are `tcp`/`udp`; anything else is left for `-p`'s parser to refuse.
/// `-p`'s form of an environment's port. smolvm publishes every port on both 127.0.0.1 and ::1,
/// so a loopback host IP of either family needs no address, and `tcp4`/`tcp6` are `tcp`.
fn publish_spec(p: &Port) -> Result<String> {
    let proto = match p.protocol_name() {
        "tcp" | "tcp4" | "tcp6" => "tcp",
        "udp" | "udp4" | "udp6" => "udp",
        other => bail!(
            "unknown protocol '{other}' in port {} (use tcp or udp)",
            p.sandbox
        ),
    };
    let loopback = [
        std::net::IpAddr::from(std::net::Ipv4Addr::LOCALHOST),
        std::net::IpAddr::from(std::net::Ipv6Addr::LOCALHOST),
    ];
    if let Some(ip) = &p.host_ip
        && !ip.parse().is_ok_and(|a| loopback.contains(&a))
    {
        bail!("can't bind {ip}: smolvm publishes on 127.0.0.1 and ::1 only");
    }
    let spec = match p.host {
        Some(h) => format!("{h}:{}/{proto}", p.sandbox),
        None => format!("{}/{proto}", p.sandbox),
    };
    // `-p`'s parser checks the rest; the free port isn't needed here.
    options::parse_publish(&spec, &|| Ok(0))?;
    Ok(spec)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env::load::{ArgInputs, load};

    struct T {
        dir: tempfile::TempDir,
    }

    impl T {
        fn new() -> T {
            let t = T {
                dir: tempfile::tempdir().unwrap(),
            };
            for d in ["proj", "proj/web", "proj/docs", "proj/k", "proj/mine"] {
                std::fs::create_dir(t.dir.path().join(d)).unwrap();
            }
            t
        }
        fn root(&self) -> String {
            self.dir.path().display().to_string()
        }
        fn p(&self, rel: &str) -> String {
            format!("{}/{rel}", self.root())
        }
        fn write(&self, rel: &str, text: &str) {
            std::fs::write(self.dir.path().join(rel), text).unwrap();
        }
        fn loaded(&self, files: &[&str]) -> Loaded {
            let paths: Vec<String> = files.iter().map(|s| s.to_string()).collect();
            let cwd = self.dir.path().join("proj");
            load(&paths, &ArgInputs::default(), &cwd, self.dir.path()).unwrap()
        }
        fn spec_with(&self, text: &str, o: &Overrides) -> Result<EnvSpec> {
            self.write("proj/sbxenv.yaml", text);
            spec(&self.loaded(&["sbxenv.yaml"]), o, &SecretsFile::default())
        }
        fn spec(&self, text: &str) -> Result<EnvSpec> {
            self.spec_with(text, &Overrides::default())
        }
        fn err(&self, text: &str) -> String {
            self.spec(text).err().unwrap().to_string()
        }
    }

    const HEAD: &str = "schemaVersion: \"1\"\n";

    #[test]
    fn mounts_become_host_colon_path_binds() {
        let t = T::new();
        let s = t
            .spec(&format!(
                "{HEAD}agent: claude\nmounts:\n  /home/agent/b: ./two\n  /home/agent/a: /abs/one\n"
            ))
            .unwrap();
        assert_eq!(
            s.opts.mount,
            vec![
                "/abs/one:/home/agent/a".to_string(),
                format!("{}:/home/agent/b", t.p("proj/two")),
            ]
        );
        assert!(
            t.spec(&format!("{HEAD}agent: claude\n"))
                .unwrap()
                .opts
                .mount
                .is_empty()
        );
    }

    #[test]
    fn preset_agent_takes_every_kit() {
        let t = T::new();
        let s = t
            .spec(&format!(
                "{HEAD}agent: claude\nworkspace: ./web\nkits:\n  - org/a\n  - source: ./k\n    args:\n      x: \"1\"\n"
            ))
            .unwrap();
        assert_eq!(s.name, "claude-web");
        assert_eq!(s.targets, vec!["claude".to_string(), t.p("proj/web")]);
        assert_eq!(s.opts.name.as_deref(), Some("claude-web"));
        assert_eq!(s.opts.kit, vec!["org/a".to_string(), t.p("proj/k")]);
        assert_eq!(
            s.opts.kit_pins,
            vec![(t.p("proj/k"), vec!["x=1".to_string()])]
        );
    }

    #[test]
    fn workload_kit_named_by_agent_becomes_the_target() {
        let t = T::new();
        let s = t
            .spec(&format!(
                "{HEAD}agent: sbx-kit-claude\nkits:\n  - org/m\n  - docker.io/docker/sbx-kit-claude:2.1.267\n"
            ))
            .unwrap();
        assert_eq!(s.targets, vec!["docker.io/docker/sbx-kit-claude:2.1.267"]);
        assert_eq!(s.opts.kit, vec!["org/m"]);
        assert_eq!(s.name, "sbx-kit-claude-proj");
        let s = t
            .spec(&format!("{HEAD}agent: mine\nkits:\n  - ./mine\n"))
            .unwrap();
        assert_eq!(s.targets, vec![t.p("proj/mine")]);
        assert!(s.opts.kit.is_empty());
        let s = t
            .spec(&format!(
                "{HEAD}agent: k\nkits:\n  - reg.example:5000/org/k@sha256:abc\n"
            ))
            .unwrap();
        assert_eq!(s.targets[0], "reg.example:5000/org/k@sha256:abc");
    }

    #[test]
    fn kit_sources_are_checked_before_anything_happens() {
        let t = T::new();
        let e = t.err(&format!("{HEAD}agent: claude\nkits:\n  - ./nope\n"));
        assert_eq!(
            e,
            format!("{}: no such file or directory", t.p("proj/nope"))
        );
        let e = t.err(&format!(
            "{HEAD}agent: claude\nkits:\n  - source: ./k.zip\n"
        ));
        assert_eq!(
            e,
            crate::kits::load::check_kind("x.zip")
                .unwrap_err()
                .to_string()
                .replace("x.zip", &t.p("proj/k.zip"))
        );
        assert!(e.contains("not supported"), "{e}");
        let git = "git+https://github.com/o/r.git#ref=main";
        let e = t.err(&format!("{HEAD}agent: claude\nkits:\n  - {git}\n"));
        assert!(e.contains(git) && e.contains("not supported"), "{e}");
    }

    #[test]
    fn unknown_agent() {
        let t = T::new();
        let e = t.err(&format!("{HEAD}agent: nosuch\nkits:\n  - org/other\n"));
        assert_eq!(e, "unknown agent \"nosuch\"");
    }

    #[test]
    fn names() {
        let t = T::new();
        let file = format!("{HEAD}agent: claude\nworkspace: ./web\n");
        assert_eq!(t.spec(&file).unwrap().name, "claude-web");
        assert_eq!(
            t.spec(&format!("{HEAD}agent: claude\n")).unwrap().name,
            "claude-proj"
        );
        assert_eq!(
            t.spec(&format!("{file}name: from-file\n")).unwrap().name,
            "from-file"
        );
        let o = Overrides {
            name: Some("flag".into()),
            ..Default::default()
        };
        assert_eq!(t.spec_with(&file, &o).unwrap().name, "flag");
        assert!(
            t.spec_with(
                &file,
                &Overrides {
                    name: Some("x".into()),
                    ..Default::default()
                }
            )
            .is_err()
        );
        // `name` alone checks nothing else: the agent and the workspace may not exist.
        t.write(
            "proj/sbxenv.yaml",
            &format!("{HEAD}agent: nosuch\nworkspace: ./gone\n"),
        );
        let l = t.loaded(&["sbxenv.yaml"]);
        assert_eq!(name(&l, None).unwrap(), "nosuch-gone");
        assert_eq!(name(&l, Some("over")).unwrap(), "over");
        let l = t.loaded(&["."]);
        assert_eq!(name(&l, None).unwrap(), "nosuch-gone");
    }

    #[test]
    fn clone_and_workspaces() {
        let t = T::new();
        let cloned = format!("{HEAD}agent: claude\nworkspace:\n  path: ./web\n  clone: true\n");
        assert!(t.spec(&cloned).unwrap().opts.clone);
        let off = Overrides {
            clone: Some(false),
            ..Default::default()
        };
        assert!(!t.spec_with(&cloned, &off).unwrap().opts.clone);
        let plain = format!("{HEAD}agent: claude\nworkspace: ./web\n");
        assert!(!t.spec(&plain).unwrap().opts.clone);
        let on = Overrides {
            clone: Some(true),
            ..Default::default()
        };
        assert!(t.spec_with(&plain, &on).unwrap().opts.clone);

        let s = t
            .spec(&format!(
                "{plain}additionalWorkspaces:\n  - path: ./docs\n    readOnly: true\n  - path: ./web\n"
            ))
            .unwrap();
        assert_eq!(
            s.targets[1..],
            [
                t.p("proj/web"),
                format!("{}:ro", t.p("proj/docs")),
                t.p("proj/web")
            ]
        );
        let e = t.err(&format!("{HEAD}agent: claude\nworkspace: ./gone\n"));
        assert_eq!(e, format!("{}: no such directory", t.p("proj/gone")));
    }

    #[test]
    fn ports_env_and_options() {
        let t = T::new();
        let s = t
            .spec(&format!(
                "{HEAD}agent: claude\nports:\n  - sandbox: 3000\n    host: 3000\n  - sandbox: 53\n    protocol: udp4\n  - sandbox: 80\n    host: 8080\n    hostIP: 127.0.0.1\n    protocol: tcp4\n  - sandbox: 81\n    hostIP: \"::1\"\n  - sandbox: 3000\n    host: 3001\nenv:\n  B: two\n  A: one\nsandboxOptions:\n  cpus: 4\n  memory: 8g\n  template: img:1\n  pullPolicy: missing\n"
            ))
            .unwrap();
        assert_eq!(
            s.opts.publish,
            // The later 3000 replaces the earlier one, in its place.
            vec!["3001:3000/tcp", "53/udp", "8080:80/tcp", "81/tcp"]
        );
        assert_eq!(s.opts.env, vec!["A=one", "B=two"]);
        assert_eq!(
            s.env,
            vec![("A".into(), "one".into()), ("B".into(), "two".into())]
        );
        assert_eq!(s.opts.cpus, Some(4));
        assert_eq!(s.opts.memory.as_deref(), Some("8g"));
        assert_eq!(s.opts.template.as_deref(), Some("img:1"));
        assert_eq!(s.opts.pull.as_deref(), Some("missing"));

        let s = t
            .spec(&format!(
                "{HEAD}agent: claude\nsandboxOptions:\n  skills: off\n"
            ))
            .unwrap();
        assert_eq!(s.opts.skills.as_deref(), Some("off"));

        let e = t.err(&format!(
            "{HEAD}agent: claude\nports:\n  - sandbox: 80\n    protocol: sctp\n"
        ));
        assert!(e.starts_with("unknown protocol 'sctp'"), "{e}");
        let e = t.err(&format!(
            "{HEAD}agent: claude\nports:\n  - sandbox: 80\n    hostIP: 0.0.0.0\n"
        ));
        assert_eq!(
            e,
            "can't bind 0.0.0.0: smolvm publishes on 127.0.0.1 and ::1 only"
        );
    }

    #[test]
    fn ports_are_named_and_checked_as_sbx_does() {
        let t = T::new();
        t.write(
            "proj/sbxenv.yaml",
            &format!(
                "{HEAD}agent: claude\nports:\n  - sandbox: 1\n  - sandbox: 2\n    protocol: tcp\n  \
                 - sandbox: 4\n    protocol: tcp6\n  - sandbox: 5\n    protocol: udp\n  \
                 - sandbox: 7\n    protocol: udp6\n  - sandbox: 9\n    hostIP: \"::1\"\n"
            ),
        );
        let l = t.loaded(&["sbxenv.yaml"]);
        let s = spec(&l, &Overrides::default(), &SecretsFile::default()).unwrap();
        let names: Vec<String> = resources(&l, &s)
            .into_iter()
            .filter(|r| r.section == "PORTS")
            .map(|r| r.name)
            .collect();
        assert_eq!(
            names,
            ["1/tcp4", "2/tcp", "4/tcp6", "5/udp", "7/udp6", "9/tcp6"]
        );
        t.write(
            "proj/sbxenv.yaml",
            &format!("{HEAD}agent: claude\nports:\n  - sandbox: 80\n    hostIP: localhost\n"),
        );
        let cwd = t.dir.path().join("proj");
        let e = load(
            &["sbxenv.yaml".into()],
            &ArgInputs::default(),
            &cwd,
            t.dir.path(),
        );
        let e = e.err().unwrap().to_string();
        assert!(
            e.ends_with(": ports[0]: invalid host IP \"localhost\""),
            "{e}"
        );
    }

    #[test]
    fn a_later_additional_workspace_with_the_same_path_wins() {
        let t = T::new();
        let s = t
            .spec(&format!(
                "{HEAD}agent: claude\nadditionalWorkspaces:\n  - path: ./docs\n  - path: ./docs\n    readOnly: true\n"
            ))
            .unwrap();
        let docs = t.dir.path().join("proj/docs").display().to_string();
        assert_eq!(s.targets[1..], [format!("{docs}:ro")]);
    }

    #[test]
    fn a_retired_agent_needs_the_kit_that_keeps_it() {
        let t = T::new();
        let e = t.err(&format!("{HEAD}agent: gemini\n"));
        assert_eq!(
            e,
            "\"gemini\" is retired and is no longer a built-in agent; its replacement is \
             antigravity (docker.io/sbx/antigravity:latest). To keep running gemini, add \
             docker.io/sbx/gemini-kit:latest to the environment file's `kits:` (beside `agent: \
             gemini`)"
        );
        let s = t
            .spec(&format!(
                "{HEAD}agent: gemini\nkits:\n  - docker.io/sbx/gemini-kit:latest\n"
            ))
            .unwrap();
        assert_eq!(s.targets[0], "docker.io/sbx/gemini-kit:latest");
        assert!(s.name.starts_with("gemini-"), "{}", s.name);
    }

    #[test]
    fn a_kits_entry_naming_an_existing_directory_is_a_path() {
        // sbx 0.53 reads `kits: [mykit]` as the directory beside the file.
        let t = T::new();
        let dir = t.dir.path().join("proj/mykit");
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(dir.join("spec.yaml"), "schemaVersion: \"2\"\nkind: mixin\n").unwrap();
        let s = t
            .spec(&format!(
                "{HEAD}agent: claude\nkits:\n  - mykit\n  - acme/tool:1\n"
            ))
            .unwrap();
        assert_eq!(
            s.opts.kit,
            [dir.display().to_string(), "acme/tool:1".into()]
        );
    }

    #[test]
    fn env_files_in_a_writable_workspace_are_kept_read_only() {
        let t = T::new();
        let file = t.dir.path().join("proj/sbxenv.yaml").display().to_string();
        let spec = |extra: &str| {
            t.spec(&format!("{HEAD}agent: claude\nworkspace: .\n{extra}"))
                .unwrap()
                .opts
        };
        let o = spec("");
        assert_eq!(o.read_only_files, [file]);
        assert!(!o.no_fuse);
        assert!(
            spec("sandboxOptions:\n  writableEnvFiles: true\n")
                .read_only_files
                .is_empty()
        );
        // A clone is a copy in the sandbox: the file on the host isn't reachable.
        let s = t
            .spec_with(
                &format!("{HEAD}agent: claude\nworkspace: .\n"),
                &Overrides {
                    clone: Some(true),
                    ..Default::default()
                },
            )
            .unwrap();
        assert!(s.opts.read_only_files.is_empty());
        assert!(spec("sandboxOptions:\n  fuse: false\n").no_fuse);
    }

    #[test]
    fn secrets_are_sorted_and_checked() {
        let t = T::new();
        let s = t
            .spec(&format!(
                "{HEAD}agent: claude\nsecrets:\n  openai: {{ref: \"op://v/i/f\"}}\n  github: {{value: x}}\n"
            ))
            .unwrap();
        let names: Vec<&str> = s.secrets.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, ["github", "openai"]);
        let e = t.err(&format!(
            "{HEAD}agent: claude\nsecrets:\n  notaservice: {{value: x}}\n"
        ));
        assert!(e.starts_with("unknown service 'notaservice'"), "{e}");
    }

    /// The plan of a fresh environment: every resource to add.
    fn summarise(t: &T, files: &[&str]) -> String {
        let l = t.loaded(files);
        let s = spec(&l, &Overrides::default(), &SecretsFile::default()).unwrap();
        let lines: Vec<Line> = resources(&l, &s)
            .iter()
            .map(|r| Line::new(Marker::Add, r))
            .collect();
        (header(&l, &s.name) + &render(&lines, HOST_COMMANDS)).replace(&t.root(), "<root>")
    }

    #[test]
    fn summary_create() {
        let t = T::new();
        t.write(
            "proj/sbxenv.yaml",
            &format!(
                "{HEAD}name: web-app\nagent: claude\nworkspace:\n  path: ./web\n  clone: true\nadditionalWorkspaces:\n  - path: ./docs\n    readOnly: true\nkits:\n  - org/tool\n  - source: org/pinned\n    args:\n      region: us\nmounts:\n  /home/agent/.cache: ./cache\nenv:\n  NODE_ENV: development\nports:\n  - sandbox: 3000\n    host: 3000\n  - sandbox: 53\n    protocol: udp\nsecrets:\n  github:\n    command: gh auth token\n  openai:\n    value: sk-dummy\n  google:\n    ref: op://vault/item/field\nsandboxOptions:\n  cpus: 4\n  memory: 8g\n"
            ),
        );
        t.write("proj/local.yaml", "env:\n  LOG_LEVEL: debug\n");
        insta::assert_snapshot!(summarise(&t, &["sbxenv.yaml", "local.yaml"]));
    }

    #[test]
    fn summary_minimal_and_remove() {
        let t = T::new();
        t.write("proj/sbxenv.yaml", &format!("{HEAD}agent: claude\n"));
        insta::assert_snapshot!(summarise(&t, &["sbxenv.yaml"]));
        let l = t.loaded(&["sbxenv.yaml"]);
        let secrets = ["github".to_string(), "openai".to_string()];
        let removed = header(&l, "claude-proj")
            + &remove_summary(Some("claude-proj"), &secrets, &[], &[], &[]);
        insta::assert_snapshot!(removed.replace(&t.root(), "<root>"));
    }

    #[test]
    fn summary_of_lifecycle_registries_and_launch() {
        // The measured sbx plan for this file is in the notes.
        let t = T::new();
        t.write(
            "proj/sbxenv.yaml",
            &format!(
                "{HEAD}name: envm-life\nagent: shell\nworkspace: .\n\
                 entrypoint: [\"/bin/sh\", \"-c\"]\ncmd: [\"echo started; sleep 600\"]\n\
                 registries:\n  registry.example.invalid:\n    username:\n      value: someone\n    \
                 secret:\n      command: echo not-a-real-token\n\
                 lifecycle:\n  initialize:\n    - name: vars\n      command: pwd\n    \
                 - command: echo second\n      workdir: ./sub\n      timeout: 5s\n  \
                 postCreate:\n    - command: echo post-create\n  \
                 preRemove:\n    - command: echo pre-remove; exit 3\n"
            ),
        );
        let l = t.loaded(&["sbxenv.yaml"]);
        let s = spec(&l, &Overrides::default(), &SecretsFile::default()).unwrap();
        let lines = crate::env::approval::lines(None, &resources(&l, &s), false);
        let plan = header(&l, &s.name) + &render(&lines, HOST_COMMANDS);
        insta::assert_snapshot!(plan.replace(&t.root(), "<root>"));
    }
}
