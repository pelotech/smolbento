//! A loaded `sbxenv.yaml` as `create`'s options, the sandbox's secrets, and a summary.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use super::SandboxOpts;
use crate::agents;
use crate::env::file::{EnvFile, KitEntry, PinnedKit, Port, SecretDecl, Workspace};
use crate::env::load::Loaded;
use crate::env::plan::{Line, Marker, Resource, render};
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
        let proto = protocol(p);
        // `-p`'s parser refuses what smolvm can't publish; the free port isn't needed here.
        let host = p.host.map(|h| h.to_string()).unwrap_or_default();
        let ip = p.host_ip.as_deref().unwrap_or("127.0.0.1");
        options::parse_publish(&format!("{ip}:{host}:{}/{proto}", p.sandbox), &|| Ok(0))?;
        publish.push(match (&p.host_ip, p.host) {
            (Some(_), Some(h)) => format!("127.0.0.1:{h}:{}/{proto}", p.sandbox),
            (None, Some(h)) => format!("{h}:{}/{proto}", p.sandbox),
            (_, None) => format!("{}/{proto}", p.sandbox),
        });
    }

    let secret_decls: Vec<(String, SecretDecl)> =
        f.secrets.clone().unwrap_or_default().into_iter().collect();
    if let Some((service, _)) = secret_decls
        .iter()
        .find(|(s, _)| secrets.service(s).is_none())
    {
        bail!(crate::secrets::services::unknown(service));
    }

    let env: Vec<(String, String)> = f.env.clone().unwrap_or_default().into_iter().collect();
    let o = f.sandbox_options.as_ref();
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
        // `load` refuses every policy but `missing`.
        pull: o.and_then(|o| o.pull_policy.clone()),
        clone: overrides
            .clone
            .or(workspace(f).and_then(|(_, c)| c))
            .unwrap_or(false),
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
    })
}

/// The `rm` plan: the sandbox and the services scoped to it, all to destroy. Needs only the name,
/// so it works when the rest of the file (workspace, kits) no longer checks out.
pub fn remove_summary(loaded: &Loaded, name: &str, scoped: &[String]) -> String {
    let resource = |section: &str, name: &str| {
        Line::new(Marker::Destroy, &Resource::new(section, name, Vec::new()))
    };
    let mut lines = vec![resource("SANDBOX", name)];
    lines.extend(scoped.iter().map(|s| resource("SECRETS", s)));
    header(loaded, name) + &render(&lines)
}

/// The `ENVIRONMENT` block: name and file(s).
pub fn header(loaded: &Loaded, name: &str) -> String {
    let files: Vec<String> = loaded
        .files
        .iter()
        .map(|p| p.display().to_string())
        .collect();
    let label = if files.len() == 1 { "File: " } else { "Files:" };
    format!(
        "ENVIRONMENT\n  Name:  {name}\n  {label} {}\n",
        files.join("\n         ")
    )
}

/// What applying the file sets up, in the plan's order.
pub fn resources(loaded: &Loaded, spec: &EnvSpec) -> Vec<Resource> {
    let f = &loaded.file;
    let field = |label: &str, value: &str| (label.to_string(), value.to_string());
    let mut out = Vec::new();

    let mut sandbox = vec![field("agent", f.agent.as_deref().unwrap_or_default())];
    if let Some(o) = &f.sandbox_options {
        let opts = [
            ("cpus", o.cpus.map(|c| c.to_string())),
            ("memory", o.memory.clone()),
            ("template", o.template.clone()),
            ("skills", o.skills.clone()),
            ("pullPolicy", o.pull_policy.clone()),
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

    for (k, v) in &spec.env {
        out.push(Resource::new("ENV", k, vec![field("value", v)]));
    }

    for (service, s) in &spec.secrets {
        let mut fields = match (&s.value, &s.r#ref, &s.command) {
            // Never the value: the plan is printed, and recorded when approved.
            (Some(v), _, _) => vec![field("value", &sha256_digest(v.as_bytes()))],
            (_, Some(r), _) => vec![field("ref", r)],
            (_, _, Some(c)) => vec![
                field("command", c),
                field("workdir", "fresh host temporary directory"),
            ],
            _ => vec![],
        };
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

    for p in f.ports.iter().flatten() {
        let host = p.host.map_or("ephemeral".to_string(), |h| h.to_string());
        let mut fields = vec![field("host", &host)];
        if let Some(ip) = &p.host_ip {
            fields.push(field("hostIP", ip));
        }
        out.push(Resource::new(
            "PORTS",
            &format!("{}/{}", p.sandbox, protocol(p)),
            fields,
        ));
    }
    out
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
fn protocol(p: &Port) -> &str {
    match p.protocol.as_deref().unwrap_or("tcp") {
        "tcp4" => "tcp",
        "udp4" => "udp",
        other => other,
    }
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
                "{HEAD}agent: claude\nports:\n  - sandbox: 3000\n    host: 3000\n  - sandbox: 53\n    protocol: udp4\n  - sandbox: 80\n    host: 8080\n    hostIP: localhost\n    protocol: tcp4\nenv:\n  B: two\n  A: one\nsandboxOptions:\n  cpus: 4\n  memory: 8g\n  template: img:1\n  pullPolicy: missing\n"
            ))
            .unwrap();
        assert_eq!(
            s.opts.publish,
            vec!["3000:3000/tcp", "53/udp", "127.0.0.1:8080:80/tcp"]
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
            "{HEAD}agent: claude\nports:\n  - sandbox: 80\n    protocol: tcp6\n"
        ));
        assert!(e.starts_with("unknown protocol 'tcp6'"), "{e}");
        let e = t.err(&format!(
            "{HEAD}agent: claude\nports:\n  - sandbox: 80\n    hostIP: 0.0.0.0\n"
        ));
        assert!(e.starts_with("can't bind 0.0.0.0"), "{e}");
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
        (header(&l, &s.name) + &render(&lines)).replace(&t.root(), "<root>")
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
        let removed = remove_summary(&l, "claude-proj", &["github".into(), "openai".into()]);
        insta::assert_snapshot!(removed.replace(&t.root(), "<root>"));
    }
}
