//! A loaded `sbxenv.yaml` as `create`'s options, the sandbox's secrets, and a summary.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use super::file::{EnvFile, KitEntry, Port, SecretDecl, Workspace};
use super::load::Loaded;
use crate::agents;
use crate::cli::SandboxOpts;
use crate::cli::lifecycle::unknown_agent;
use crate::cli::secret::unknown_service;
use crate::kits::registry::sha256_digest;
use crate::sandbox::{name as sandbox_name, options};
use crate::secrets::SecretsFile;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Create,
    Run,
    Remove,
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
    let target = if agents::find(agent).is_some() {
        agent.to_string()
    } else {
        let i = kits
            .iter()
            .position(|k| kit_name(k) == agent)
            .with_context(|| unknown_agent(agent))?;
        kits.remove(i)
    };
    let kit_pins = f
        .kits
        .iter()
        .flatten()
        .filter_map(|k| match k {
            KitEntry::Pinned {
                source,
                args: Some(args),
            } => Some((
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
        bail!(unknown_service(service));
    }

    let env: Vec<(String, String)> = f.env.clone().unwrap_or_default().into_iter().collect();
    let o = f.sandbox_options.as_ref();
    let opts = SandboxOpts {
        name: Some(name.clone()),
        cpus: o.and_then(|o| o.cpus),
        memory: o.and_then(|o| o.memory.clone()),
        env: env.iter().map(|(k, v)| format!("{k}={v}")).collect(),
        publish,
        template: o.and_then(|o| o.template.clone()),
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

/// sbx's plan layout, without diffs. `scoped` is the services stored for the sandbox (rm only).
pub fn summary(loaded: &Loaded, spec: &EnvSpec, op: Op, scoped: &[String]) -> String {
    let f = &loaded.file;
    let files: Vec<String> = loaded
        .files
        .iter()
        .map(|p| p.display().to_string())
        .collect();
    let mut out = String::from("ENVIRONMENT\n");
    if let [file] = files.as_slice() {
        out += &format!("  Name: {}\n  File: {}\n", spec.name, file);
    } else {
        out += &format!(
            "  Name:  {}\n  Files: {}\n",
            spec.name,
            files.join("\n         ")
        );
    }

    if op == Op::Remove {
        let mut n = section(&mut out, "SANDBOX", '-', vec![(spec.name.clone(), vec![])]);
        let secrets = scoped.iter().map(|s| (s.clone(), vec![])).collect();
        n += section(&mut out, "SECRETS", '-', secrets);
        out += &format!("\n  0 to add · 0 to change · {n} to destroy\n");
        return out;
    }

    let mut sandbox = vec![format!("agent: {}", f.agent.as_deref().unwrap_or_default())];
    if let Some(o) = &f.sandbox_options {
        let opts = [
            ("cpus", o.cpus.map(|c| c.to_string())),
            ("memory", o.memory.clone()),
            ("template", o.template.clone()),
            ("pullPolicy", o.pull_policy.clone()),
        ];
        for (k, v) in opts {
            if let Some(v) = v {
                sandbox.push(format!("sandboxOptions.{k}: {v}"));
            }
        }
    }
    let mut n = section(&mut out, "SANDBOX", '+', vec![(spec.name.clone(), sandbox)]);

    let mut workspaces = Vec::new();
    if let Some((path, _)) = workspace(f) {
        let clone = spec.opts.clone.then(|| "clone: true".to_string());
        workspaces.push((path.to_string(), clone.into_iter().collect()));
    }
    for w in f.additional_workspaces.iter().flatten() {
        let ro = (w.read_only == Some(true)).then(|| "readOnly: true".to_string());
        workspaces.push((w.path.clone(), ro.into_iter().collect()));
    }
    n += section(&mut out, "WORKSPACES", '+', workspaces);

    let kits = f
        .kits
        .iter()
        .flatten()
        .map(|k| (source(k).to_string(), vec![]))
        .collect();
    n += section(&mut out, "KITS", '+', kits);

    let env = spec
        .env
        .iter()
        .map(|(k, v)| (k.clone(), vec![format!("value: {v}")]))
        .collect();
    n += section(&mut out, "ENV", '+', env);

    let mut commands = false;
    let secrets = spec
        .secrets
        .iter()
        .map(|(service, s)| {
            let detail = match (&s.value, &s.r#ref, &s.command) {
                (Some(v), _, _) => vec![format!("value: {}", sha256_digest(v.as_bytes()))],
                (_, Some(r), _) => vec![format!("ref: {r}")],
                (_, _, Some(c)) => {
                    commands = true;
                    vec![
                        format!("command: {c}"),
                        "workdir: fresh host temporary directory".to_string(),
                    ]
                }
                _ => vec![],
            };
            (service.clone(), detail)
        })
        .collect();
    n += section(&mut out, "SECRETS", '+', secrets);

    let ports = f
        .ports
        .iter()
        .flatten()
        .map(|p| {
            let host = p.host.map_or("ephemeral".to_string(), |h| h.to_string());
            (
                format!("{}/{}", p.sandbox, protocol(p)),
                vec![format!("host: {host}")],
            )
        })
        .collect();
    n += section(&mut out, "PORTS", '+', ports);

    out += &format!("\n  {n} to add · 0 to change · 0 to destroy\n");
    if commands {
        out += "  ! this plan runs commands on this machine, outside the sandbox, with your own privileges\n";
    }
    out
}

/// A titled section of `sign` entries, each with indented details; nothing when empty.
/// Returns the number of entries.
fn section(
    out: &mut String,
    title: &str,
    sign: char,
    entries: Vec<(String, Vec<String>)>,
) -> usize {
    if entries.is_empty() {
        return 0;
    }
    *out += &format!("\n{title}\n");
    for (head, details) in &entries {
        *out += &format!("  {sign} {head}\n");
        for d in details {
            *out += &format!("      {d}\n");
        }
    }
    entries.len()
}

/// The primary workspace's path and `clone`.
fn workspace(f: &EnvFile) -> Option<(&str, Option<bool>)> {
    match f.workspace.as_ref()? {
        Workspace::Path(p) => Some((p, None)),
        Workspace::Object { path, clone } => Some((path, *clone)),
    }
}

fn source(k: &KitEntry) -> &str {
    match k {
        KitEntry::Source(s) | KitEntry::Pinned { source: s, .. } => s,
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
            for d in ["proj", "proj/web", "proj/docs"] {
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

    fn summarise(t: &T, files: &[&str], op: Op, scoped: &[String]) -> String {
        let l = t.loaded(files);
        let s = spec(&l, &Overrides::default(), &SecretsFile::default()).unwrap();
        summary(&l, &s, op, scoped).replace(&t.root(), "<root>")
    }

    #[test]
    fn summary_create() {
        let t = T::new();
        t.write(
            "proj/sbxenv.yaml",
            &format!(
                "{HEAD}name: web-app\nagent: claude\nworkspace:\n  path: ./web\n  clone: true\nadditionalWorkspaces:\n  - path: ./docs\n    readOnly: true\nkits:\n  - org/tool\nenv:\n  NODE_ENV: development\nports:\n  - sandbox: 3000\n    host: 3000\n  - sandbox: 53\n    protocol: udp\nsecrets:\n  github:\n    command: gh auth token\n  openai:\n    value: sk-dummy\n  google:\n    ref: op://vault/item/field\nsandboxOptions:\n  cpus: 4\n  memory: 8g\n"
            ),
        );
        t.write("proj/local.yaml", "env:\n  LOG_LEVEL: debug\n");
        insta::assert_snapshot!(summarise(
            &t,
            &["sbxenv.yaml", "local.yaml"],
            Op::Create,
            &[]
        ));
    }

    #[test]
    fn summary_minimal_and_remove() {
        let t = T::new();
        t.write("proj/sbxenv.yaml", &format!("{HEAD}agent: claude\n"));
        insta::assert_snapshot!(summarise(&t, &["sbxenv.yaml"], Op::Run, &[]));
        insta::assert_snapshot!(summarise(
            &t,
            &["sbxenv.yaml"],
            Op::Remove,
            &["github".into(), "openai".into()]
        ));
    }
}
