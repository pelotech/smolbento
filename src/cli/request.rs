//! From `create`/`run` options to a sandbox request: the agent or workload, workspaces, `--clone`,
//! and the kit plan (load, pin args, order, resolve), with the `KITS` progress section.

use anyhow::{Context, Result, bail};

use super::progress::Progress;
use super::{Ctx, SandboxOpts};
use crate::agents;
use crate::kits::args::ArgValues;
use crate::kits::capability;
use crate::kits::load;
use crate::kits::model::{Content, Kind, Kit, Source};
use crate::kits::resolve::{Plan, resolve_for};
use crate::sandbox::{CreateRequest, name, options};
use crate::smolvm::Runner;
use crate::workspace::{self, Workspace, clone};

/// Turns sbx's create options into a [`CreateRequest`]. `default_to_cwd`: `run` mounts the current
/// directory when no path is given; `create` makes a mountless sandbox.
pub(crate) fn build_request<R: Runner>(
    ctx: &Ctx<R>,
    agent_name: &str,
    paths: &[String],
    opts: &SandboxOpts,
    default_to_cwd: bool,
) -> Result<CreateRequest> {
    let agent = agents::find(agent_name).with_context(|| agents::unknown(agent_name))?;
    let mut req = base_request(ctx, agent.name, paths, opts, default_to_cwd)?;
    let docker_enabled = ctx.settings.bool("docker.enabled")?;
    let store = crate::templates::Store::new(&ctx.paths);
    let saved = match &opts.template {
        Some(t) => store.find_ref(t)?,
        None => None,
    };
    if opts.pull.as_deref() == Some("never") && saved.is_none() {
        return Err(super::Unsupported(
            "--pull never works only with a saved template (see `sbt template ls`); smolvm \
             pulls missing images"
                .into(),
        )
        .into());
    }
    if let Some(e) = saved {
        if e.agent != agent.name {
            bail!(
                "template {} was saved from a {a} sandbox; run it with {a}",
                e.full(),
                a = e.agent
            );
        }
        req.template_pack = Some(store.pack(&e));
        req.template = Some(e.full());
        // Asks for the docker kit as the source sandbox had it.
        req.docker = e.docker && docker_enabled;
        req.image = e.image;
        return Ok(req);
    }
    // docker.enabled=false swaps the preset for its plain variant; an explicit -t is used as given.
    req.image = match &opts.template {
        Some(t) => t.clone(),
        None if docker_enabled => agent.image.to_string(),
        None => agents::plain_image(agent.image),
    };
    // Asks for the docker kit; `apply` sets it again from the kits actually applied.
    req.docker = docker_enabled && agents::is_docker_image(&req.image);
    Ok(req)
}

/// Everything but the image: `agent` is the preset or workload kit name (the `sbx.agent` label
/// and the default name's prefix).
fn base_request<R: Runner>(
    ctx: &Ctx<R>,
    agent: &str,
    paths: &[String],
    opts: &SandboxOpts,
    default_to_cwd: bool,
) -> Result<CreateRequest> {
    // Before anything else, like sbx; whether a kit declares each path is checked once kits resolve.
    let host_mounts = workspace::parse_mounts(&opts.mount, &ctx.cwd)?;
    let mut workspaces = paths
        .iter()
        .map(|p| Workspace::parse(p, &ctx.cwd))
        .collect::<Result<Vec<_>>>()?;
    if workspaces.is_empty() && default_to_cwd {
        workspaces.push(Workspace::parse(".", &ctx.cwd)?);
    }
    let name = match &opts.name {
        Some(n) => n.clone(),
        None => name::default_name(
            agent,
            workspaces
                .first()
                .map_or(ctx.cwd.as_path(), |w| w.path.as_path()),
        ),
    };
    name::validate(&name)?;

    let cpus = match opts.cpus {
        Some(c) if c > 0 => c,
        _ => options::host_cpus(),
    };
    let memory_mib = match &opts.memory {
        Some(m) => options::parse_memory(m)?,
        None => options::default_memory_mib(options::host_memory_mib()?),
    };
    let env = options::parse_env(&opts.env, &opts.env_file, &ctx.env)?;
    let ports = opts
        .publish
        .iter()
        .map(|p| options::parse_publish(p, &options::free_port))
        .collect::<Result<Vec<_>>>()?;
    // Before any smolvm call, so a bad value fails early.
    let skills_mode = crate::skills::resolve_mode(opts.skills.as_deref(), &ctx.settings)?;

    Ok(CreateRequest {
        name,
        agent: agent.into(),
        workspaces,
        cpus,
        memory_mib,
        env,
        ports,
        created: ctx.now,
        cpus_set: opts.cpus.is_some(),
        memory_set: opts.memory.is_some(),
        host_mounts,
        skills_mode,
        ..Default::default()
    })
}

/// Kit args need a kit: a `--kit` or a workload kit as the target. Like sbx this fails on every
/// command, including `run` of an existing sandbox.
pub(crate) fn check_kit_args(targets: &[String], opts: &SandboxOpts) -> Result<()> {
    let workload_kit = targets.first().is_some_and(|t| agents::find(t).is_none());
    if !workload_kit && opts.kit.is_empty() && has_kit_args(opts) {
        bail!("kit arguments were supplied but no kits were referenced");
    }
    Ok(())
}

/// The workload `kit_target` found: the preset as a kit, or a workload kit not loaded yet.
pub(crate) enum Workload {
    Preset(Box<Kit>),
    Ref(String),
}

/// `build_request` for `targets` (an agent preset or a workload kit REF, then workspace paths),
/// and the workload: the request (so its name) without loading any kit; a workload kit's name
/// comes from `load::kit_name`. `kit_plan` loads the kits. `None` when there are no kits: a
/// preset without `--kit`, unless its image gets the `docker` kit.
pub(crate) fn kit_target<R: Runner>(
    ctx: &Ctx<R>,
    targets: &[String],
    opts: &SandboxOpts,
    default_to_cwd: bool,
) -> Result<(CreateRequest, Option<Workload>)> {
    let (target, paths) = targets.split_first().context("specify an agent")?;
    Ok(match agents::find(target) {
        Some(agent) => {
            let req = build_request(ctx, target, paths, opts, default_to_cwd)?;
            if opts.kit.is_empty() && !req.docker {
                return Ok((req, None));
            }
            let workload = load::preset_kit(agent, &req.image);
            (req, Some(Workload::Preset(Box::new(workload))))
        }
        None => {
            if !looks_like_kit(target) {
                bail!(agents::unknown(target));
            }
            if opts.template.is_some() {
                bail!("-t can't be combined with a workload kit");
            }
            let name = load::kit_name(ctx, target)?;
            let req = base_request(ctx, &name, paths, opts, default_to_cwd)?;
            (req, Some(Workload::Ref(target.clone())))
        }
    })
}

/// Whether any kit flag was given (`run` warns that they don't apply to an existing sandbox).
pub(crate) fn has_kit_flags(opts: &SandboxOpts) -> bool {
    !opts.kit.is_empty() || has_kit_args(opts)
}

fn has_kit_args(opts: &SandboxOpts) -> bool {
    !opts.kit_arg.is_empty() || !opts.kit_args_file.is_empty()
}

/// The second half of `kit_target`, for a sandbox about to be created: loads the workload kit
/// (filling `req`'s image) and the `--kit` mixins, each a step under `KITS`, and resolves them
/// with the kit args and `req`'s working directory. Touches neither smolvm's machines nor the
/// policy: `plan::create` applies the plan.
pub(crate) fn kit_plan<R: Runner>(
    ctx: &Ctx<R>,
    req: &mut CreateRequest,
    workload: Workload,
    opts: &SandboxOpts,
    p: &Progress,
) -> Result<Plan> {
    let mut kits = KitsSection::new(p);
    let workload_source = match &workload {
        Workload::Ref(target) => Some(target.clone()),
        Workload::Preset(_) => None,
    };
    let workload = match workload {
        Workload::Preset(kit) => *kit,
        Workload::Ref(target) => {
            let mut kit = kits.load(ctx, &target)?;
            if kit.kind == Kind::Mixin {
                // sbx's report, then how to use the mixin.
                bail!(
                    "{}\n{target} is a mixin; add it with --kit to an agent, e.g. sbt run shell \
                     --kit {target}",
                    capability::incoherent(&[capability::NO_WORKLOAD.to_string()])
                );
            }
            load::check_launchable(ctx, &mut kit)?;
            // A Smolfile kit gets the shell preset's command, recorded in `sbx.command` so every
            // attach launches the same thing.
            if kit.command.is_none() {
                let shell = agents::find("shell").expect("the shell preset");
                kit.command = Some(shell.command.iter().map(|s| s.to_string()).collect());
            }
            if let Content::Image(image) = &kit.content {
                req.image = image.clone();
                req.docker = ctx.settings.bool("docker.enabled")? && agents::is_docker_image(image);
            }
            kit
        }
    };
    let mut args = ArgValues::parse(&opts.kit_args_file, &opts.kit_arg)?;
    let mixins = opts
        .kit
        .iter()
        .map(|r| kits.load(ctx, r))
        .collect::<Result<Vec<_>>>()?;
    for (source, pins) in &opts.kit_pins {
        let kit = match opts.kit.iter().position(|k| k == source) {
            Some(i) => &mixins[i],
            None if workload_source.as_ref() == Some(source) => &workload,
            None => continue,
        };
        args.pin(&kit.name, pins)?;
    }
    let mixins = order_mixins(req.docker, &workload, mixins)?;
    let plan = resolve_for(workload, mixins, &args, &req.workdir())?;
    if let Some(t) = &req.template {
        let layered = crate::kits::compose::layered_names(&plan)?;
        if !layered.is_empty() {
            bail!(
                "-t {t} can't be combined with kits that add image layers ({}): a template's \
                 filesystem is saved whole",
                layered.join(", ")
            );
        }
    }
    plan.warn_skipped();
    Ok(plan)
}

/// The `KITS` section, shown only once a kit is pulled or built: kits with nothing to fetch
/// (shipped, v2 or Smolfile) wait for it and are listed `✓ REF — cached` when it opens.
struct KitsSection<'a> {
    p: &'a Progress,
    open: bool,
    /// Kits loaded without a fetch before the section opened.
    waiting: Vec<String>,
}

impl<'a> KitsSection<'a> {
    fn new(p: &'a Progress) -> Self {
        Self {
            p,
            open: false,
            waiting: Vec::new(),
        }
    }

    /// Loads kit `reference`: a pull or build is a step, `○ REF — pulling…` or `building…`,
    /// then `✓ REF — ready`, or `cached` when the kit cache already had it all.
    fn load<R: Runner>(&mut self, ctx: &Ctx<R>, reference: &str) -> Result<Kit> {
        let mut step = None;
        let loaded = load::load_noting(ctx, reference, &mut |fetch| {
            self.open_section();
            let doing = match fetch {
                load::Fetch::Pull => "pulling",
                load::Fetch::Build => "building",
            };
            step = Some(self.p.step(reference, doing));
        });
        match (loaded, step) {
            (Ok((kit, cached)), Some(s)) => {
                s.done(if cached { "cached" } else { "ready" });
                Ok(kit)
            }
            (Ok((kit, _)), None) => {
                if self.open {
                    self.p.done(reference, "cached");
                } else {
                    self.waiting.push(reference.to_string());
                }
                Ok(kit)
            }
            (Err(e), Some(s)) => {
                s.fail();
                Err(e)
            }
            (Err(e), None) => Err(e),
        }
    }

    fn open_section(&mut self) {
        if !self.open {
            self.open = true;
            self.p.section("KITS");
            for reference in self.waiting.drain(..) {
                self.p.done(&reference, "cached");
            }
        }
    }
}

/// The mixins with the shipped docker kit first, whether given with `--kit docker` or added
/// because the image is Docker-enabled (`needs_docker_kit`): other kits' startup steps may use the
/// dockerd it starts (in sbx it's in the image).
fn order_mixins(docker_image: bool, workload: &Kit, mut mixins: Vec<Kit>) -> Result<Vec<Kit>> {
    if let Some(i) = mixins
        .iter()
        .position(|k| k.source == Source::Builtin("docker"))
    {
        let docker = mixins.remove(i);
        mixins.insert(0, docker);
    } else if needs_docker_kit(docker_image, workload, &mixins) {
        mixins.insert(
            0,
            load::builtin("docker").expect("the docker kit is shipped")?,
        );
    }
    Ok(mixins)
}

/// A Docker-enabled image gets dockerd through the shipped kit, unless `--kit docker` added it or
/// another kit in the plan provides `docker` (two would clash on `provides`).
fn needs_docker_kit(docker_image: bool, workload: &Kit, mixins: &[Kit]) -> bool {
    docker_image
        && !std::iter::once(workload).chain(mixins).any(|k| {
            k.source == Source::Builtin("docker")
                || k.provides
                    .iter()
                    .any(|p| capability::provides_name(p, "docker"))
        })
}

/// A path or a registry reference rather than a misspelt agent, which mustn't reach a registry.
/// As in sbx a bare word is only an agent name, tag or not (`alpine:3`), dotted or not (`.hidden`);
/// a reference is `.`, `..` or needs a `/` (`./kit`, `../kit`, `org/kit`).
fn looks_like_kit(target: &str) -> bool {
    target.contains('/') || target == "." || target == ".."
}

/// Resolves `--clone` into `req.clone`. Only for a sandbox that is about to be created: `--clone`
/// is a no-op when `run` re-attaches to an existing one.
pub(crate) fn resolve_clone(req: &mut CreateRequest, opts: &SandboxOpts) -> Result<()> {
    if opts.clone {
        let primary = req
            .workspaces
            .first()
            .context("--clone needs a workspace path, e.g. `sbt create --clone claude .`")?;
        req.clone = Some(clone::source(&primary.path)?);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::super::{Cli, Cmd, SandboxOpts};
    use super::*;
    use crate::testutil::*;

    fn fixture(name: &str) -> String {
        format!(
            "{}/tests/fixtures/kits/v2/{name}",
            env!("CARGO_MANIFEST_DIR")
        )
    }

    fn kit_env() -> TestEnv {
        test_env(&[("SMOLBENTO_KIT_ALLOW_LOCAL_KITS", "true")])
    }

    fn create_line(t: &TestEnv) -> String {
        t.calls()
            .into_iter()
            .find(|l| l.starts_with("machine create"))
            .expect("a machine create")
    }

    /// No machine touched: only the lookup that checks the name is free.
    fn no_machine_calls(t: &TestEnv) -> bool {
        !t.calls()
            .iter()
            .any(|l| l.starts_with("machine ") && !l.starts_with("machine status"))
    }

    /// A kit env whose sandbox names are all free.
    fn kit_env_free() -> TestEnv {
        let t = kit_env();
        t.no_machine();
        t
    }

    #[test]
    fn kit_pins_apply_beneath_kit_args() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("spec.yaml"),
            "schemaVersion: \"2\"\nkind: mixin\nname: pinme\nargs:\n  mode:\n    default: plain\nsetup:\n  install:\n    - command: echo mode=${{ kit.args.mode }}\n",
        )
        .unwrap();
        let kit = dir.path().display().to_string();
        for (flags, want) in [(vec![], "mode=pinned"), (vec!["mode=flag"], "mode=flag")] {
            let mut t = kit_env();
            creatable_as(&t, "shell-proj");
            let a = super::super::CreateArgs {
                targets: vec!["shell".into(), ".".into()],
                opts: SandboxOpts {
                    kit: vec![kit.clone()],
                    kit_arg: flags.iter().map(|s| s.to_string()).collect(),
                    kit_pins: vec![(kit.clone(), vec!["mode=pinned".into()])],
                    ..Default::default()
                },
                no_progress: false,
            };
            super::super::lifecycle::create(&mut t.ctx, &a).unwrap();
            let lines = t.calls();
            assert!(
                lines
                    .iter()
                    .any(|l| l.contains("machine exec") && l.contains(want)),
                "{want}: {lines:?}"
            );
        }
    }

    #[test]
    fn kit_pins_apply_to_a_workload_kit() {
        let dir = tempfile::tempdir().unwrap();
        let kit = dir.path().join("wl");
        std::fs::create_dir(&kit).unwrap();
        std::fs::write(
            kit.join("spec.yaml"),
            "schemaVersion: \"2\"\nkind: sandbox\nname: wl\nargs:\n  mode:\n    default: plain\nsandbox:\n  image: img:1\n  entrypoint: [/bin/agent]\nsetup:\n  install:\n    - command: echo mode=${{ kit.args.mode }}\n",
        )
        .unwrap();
        let kit = kit.display().to_string();
        let mut t = kit_env();
        creatable_as(&t, "wl-proj");
        let a = super::super::CreateArgs {
            targets: vec![kit.clone(), ".".into()],
            opts: SandboxOpts {
                kit_pins: vec![(kit.clone(), vec!["mode=pinned".into()])],
                ..Default::default()
            },
            no_progress: false,
        };
        super::super::lifecycle::create(&mut t.ctx, &a).unwrap();
        let lines = t.calls();
        assert!(
            lines
                .iter()
                .any(|l| l.contains("machine exec") && l.contains("mode=pinned")),
            "{lines:?}"
        );
        // The image comes from the kit, which loads after SANDBOX is printed.
        let out = t.stdout();
        assert!(
            out.contains(&format!("  Image:      from {kit}\n")),
            "{out}"
        );
        assert!(!out.contains("KITS"), "nothing pulled or built: {out}");
        assert!(
            out.contains("  ○ wl — installing…\n  ✓ wl — installed\n"),
            "{out}"
        );
    }

    #[test]
    fn create_with_a_mixin_kit_applies_it() {
        let mut t = kit_env();
        // allow-all would leave the kit's allow rule out of the argv.
        set_policy(&t, "mode = \"deny-all\"");
        creatable_as(&t, "shell-proj");
        let kit = fixture("tool-mixin");
        t.sbt(&[
            "create",
            "shell",
            ".",
            "--kit",
            &kit,
            "--kit-arg",
            "mode=slow",
            "--cpus",
            "1",
            "-m",
            "1g",
        ])
        .unwrap();
        let create = create_line(&t);
        assert!(create.contains("-e TOOL_MODE=fast"), "{create}");
        assert!(create.contains(":8080 "), "{create}");
        // The shell preset's image is Docker-enabled, so the docker kit comes too, first.
        assert!(
            create.contains(&format!("--label sbx.kits=[\"builtin:docker\",\"{kit}\"]")),
            "{create}"
        );
        assert!(create.contains("api.tool.example"), "{create}");
        let lines = t.calls();
        let start = lines
            .iter()
            .position(|l| l == "machine start -n sbx-shell-proj")
            .unwrap();
        let install = lines
            .iter()
            .position(|l| l.contains("machine exec") && l.contains("echo installed"))
            .expect("the install hook runs");
        assert!(start < install, "{lines:?}");
        // The progress, as sbx prints it without a terminal: no KITS (a v2 directory needs no
        // pull or build), and the install hooks' kit before the docker kit, which has none.
        let ws = t.ctx.cwd.display().to_string();
        assert_eq!(
            t.stdout().replace(&ws, "WS").replace(&kit, "KIT"),
            "
SANDBOX
  Name:       shell-proj
  Agent:      shell
  Workspace:  WS (rw)
  Image:      docker/sandbox-templates:shell-docker-0.10.0
  CPU:        1
  Memory:     1 GiB

IMAGE
  ○ image — preparing…
  ✓ image — ready

SETUP
  ○ sandbox — starting…
  ✓ sandbox — started
  ○ tool — installing…
  ✓ tool — installed
  ○ docker — installing…
  ✓ docker — installed

  ✓ Created sandbox shell-proj
        try: sbt run --name shell-proj
"
        );
    }

    #[test]
    fn create_writes_v2_workspace_files_into_the_workspace() {
        let mut t = kit_env();
        creatable_as(&t, "shell-proj");
        let kit = fixture("workspace-files");
        t.sbt(&["create", "shell", ".", "--kit", &kit]).unwrap();
        let ws = t.ctx.cwd.canonicalize().unwrap().display().to_string();
        let lines = t.calls();
        let wrote = |needle: &str| {
            lines
                .iter()
                .any(|l| l.starts_with("machine exec") && l.contains(needle))
        };
        assert!(wrote(&format!("{ws}/docs/NOTES.md")), "{lines:#?}");
        assert!(wrote(&format!("workdir={ws}")), "{lines:#?}");
    }

    #[test]
    fn create_with_a_workload_kit_names_the_sandbox_after_it() {
        let mut t = kit_env();
        creatable_as(&t, "toolbox-proj");
        t.sbt(&["create", &fixture("tool-workload"), "."]).unwrap();
        let create = create_line(&t);
        assert!(create.contains("-n sbx-toolbox-proj"), "{create}");
        assert!(
            create.contains("--image ghcr.io/example/toolbox:1"),
            "{create}"
        );
        assert!(
            create.contains(r#"--label sbx.command=["/bin/agent","--x"]"#),
            "{create}"
        );
        assert!(create.contains("--label sbx.agent=toolbox"), "{create}");
    }

    #[test]
    fn a_workload_kit_named_claude_gets_no_preset_variables() {
        let mut t = kit_env();
        let dir = tempfile::tempdir().unwrap();
        let kit = dir.path().join("claude");
        std::fs::create_dir(&kit).unwrap();
        std::fs::write(
            kit.join("spec.yaml"),
            "schemaVersion: \"2\"\nkind: sandbox\nname: claude\nsandbox:\n  image: img:1\n  \
             entrypoint: [/bin/agent]\n",
        )
        .unwrap();
        creatable_as(&t, "claude-proj");
        t.sbt(&["create", &kit.display().to_string(), "."]).unwrap();
        let create = create_line(&t);
        assert!(create.contains("-e SBX_AGENT=claude"), "{create}");
        assert!(!create.contains("SBX_CRED_"), "{create}");
        assert!(!create.contains("IS_SANDBOX"), "{create}");
    }

    #[test]
    fn a_workload_kit_without_a_command_is_refused() {
        let mut t = kit_env();
        let dir = tempfile::tempdir().unwrap();
        let kit = dir.path().join("bare");
        std::fs::create_dir(&kit).unwrap();
        std::fs::write(
            kit.join("spec.yaml"),
            "schemaVersion: \"2\"\nkind: sandbox\nname: bare\nsandbox:\n  image: img:1\n",
        )
        .unwrap();
        // The image declares no command either.
        crate::kits::registry::fixtures::cached_image(
            &t.ctx.paths.kit_cache(),
            "img:1",
            r#"{"config":{"Env":["A=1"]}}"#,
        );
        let fake = t.runner();
        fake.fail(&["machine", "status"], "NOT_FOUND", "vm not found");
        let err = t
            .sbt(&["create", &kit.display().to_string(), "."])
            .unwrap_err();
        assert_eq!(
            format!("{err:#}"),
            "workload kit image declares no ENTRYPOINT or CMD; the image config is the runtime \
             contract"
        );
        assert!(!t.calls().iter().any(|l| l.starts_with("machine create")),);
    }

    #[test]
    fn a_v2_workload_without_a_command_launches_its_images() {
        let mut t = kit_env();
        let dir = tempfile::tempdir().unwrap();
        let kit = dir.path().join("bare");
        std::fs::create_dir(&kit).unwrap();
        std::fs::write(
            kit.join("spec.yaml"),
            "schemaVersion: \"2\"\nkind: sandbox\nname: bare\nsandbox:\n  image: img:1\n",
        )
        .unwrap();
        crate::kits::registry::fixtures::cached_image(
            &t.ctx.paths.kit_cache(),
            "img:1",
            r#"{"config":{"Entrypoint":["/bin/agent"],"Cmd":["--x"]}}"#,
        );
        creatable_as(&t, "bare-proj");
        t.sbt(&["create", &kit.display().to_string(), "."]).unwrap();
        let create = create_line(&t);
        assert!(
            create.contains(r#"--label sbx.command=["/bin/agent","--x"]"#),
            "{create}"
        );
        // v2 still launches as `agent`.
        assert!(!create.contains("sbx.user"), "{create}");
    }

    #[test]
    fn a_local_kit_named_like_a_preset_is_still_a_kit() {
        let mut t = kit_env();
        let dir = tempfile::tempdir().unwrap();
        let kit = dir.path().join("mine");
        std::fs::create_dir(&kit).unwrap();
        std::fs::write(
            kit.join("spec.yaml"),
            "schemaVersion: \"2\"\nkind: sandbox\nname: shell\nsandbox:\n  image: img:1\n  \
             entrypoint: [/bin/agent]\n",
        )
        .unwrap();
        creatable_as(&t, "shell-proj");
        t.sbt(&["create", &kit.display().to_string(), "."]).unwrap();
        let create = create_line(&t);
        let path = kit.canonicalize().unwrap().display().to_string();
        assert!(
            create.contains(&format!("--label sbx.kits=[\"{path}\"]")),
            "{create}"
        );
        assert!(
            create.contains(r#"--label sbx.command=["/bin/agent"]"#),
            "{create}"
        );
    }

    #[test]
    fn a_mixin_as_the_target_fails_before_smolvm() {
        let mut t = kit_env_free();
        let kit = fixture("tool-mixin");
        let err = t.sbt_err(&["create", &kit]);
        assert_eq!(
            err,
            format!(
                "resolve: the kit set is not coherent:\n  - no workload kit in the set; every \
                 composition needs exactly one kind: workload base\n{kit} is a mixin; add it with \
                 --kit to an agent, e.g. sbt run shell --kit {kit}"
            )
        );
        assert!(no_machine_calls(&t));
    }

    #[test]
    fn bad_kit_flags_fail_before_smolvm() {
        let kit = fixture("tool-mixin");
        let workload = fixture("tool-workload");
        for (args, want) in [
            (
                vec!["create", "shell", "--kit", &kit, "--kit-arg", "nope=1"],
                "unknown kit argument nope",
            ),
            (
                vec!["create", "shell", "--kit-arg", "mode=1"],
                "kit arguments were supplied but no kits were referenced",
            ),
            (
                vec!["create", &workload, "-t", "img:1"],
                "-t can't be combined with a workload kit",
            ),
            (
                vec!["create", "shell", "--kit", "git+https://github.com/o/r.git"],
                "git kit sources are not supported",
            ),
            (
                vec!["create", "shell", "--kit", "./k.zip"],
                "ZIP kits are not supported",
            ),
        ] {
            let mut t = kit_env_free();
            let err = format!("{:#}", t.sbt(&args).unwrap_err());
            assert!(err.contains(want), "{args:?}: {err}");
            assert!(no_machine_calls(&t), "{args:?}");
            assert!(
                crate::policy::Policy::load(&t.ctx.paths)
                    .unwrap()
                    .sandboxes
                    .is_empty()
            );
        }
    }

    #[test]
    fn a_kit_create_on_an_existing_name_adds_no_rules() {
        let mut t = kit_env();
        t.runner().ok(
            &["machine", "status"],
            &json("sbx-shell-proj", "stopped", "shell-proj"),
        );
        let err = t.sbt_err(&["create", "shell", ".", "--kit", &fixture("tool-mixin")]);
        assert!(err.contains("already exists"), "{err}");
        assert!(sandbox_rules(&t, "shell-proj").is_empty());
    }

    #[test]
    fn a_kit_binding_merges_with_a_global_secret_of_the_same_variable() {
        let t = kit_env();
        global_github_secret(&t);
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("spec.yaml"),
            "schemaVersion: \"2\"\nkind: mixin\nname: gh\ncredentials:\n  - service: github\n    \
             apiKey:\n      name: GH_TOKEN\n      inject:\n        - domain: gist.github.com\n",
        )
        .unwrap();
        let (mut req, plan) = kit_request(&t, &["create", "shell", "--kit"], dir.path());
        crate::provision::prepare_create(&t.ctx, &mut req, &[], plan.as_ref()).unwrap();
        let gh: Vec<_> = req
            .credentials
            .iter()
            .filter(|c| c.env_var == "GH_TOKEN")
            .collect();
        assert_eq!(gh.len(), 1, "{:?}", req.credentials);
        assert!(gh[0].hosts.contains(&"gist.github.com".to_string()));
        assert!(gh[0].hosts.contains(&"api.github.com".to_string()));
        assert_eq!(req.secrets, vec!["github"]);
    }

    /// A mixin `gh` binding `service`'s secret to GH_TOKEN for `domain`.
    fn inject_kit(service: &str, domain: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("spec.yaml"),
            format!(
                "schemaVersion: \"2\"\nkind: mixin\nname: gh\ncredentials:\n  - service: {service}\n    \
                 apiKey:\n      name: GH_TOKEN\n      inject:\n        - domain: {domain}\n"
            ),
        )
        .unwrap();
        dir
    }

    #[test]
    fn a_kit_cant_send_a_builtin_secret_outside_its_hosts() {
        let t = kit_env();
        global_github_secret(&t);
        let dir = inject_kit("github", "evil.example.com");
        let (mut req, plan) = kit_request(&t, &["create", "shell", "--kit"], dir.path());
        let err = crate::provision::prepare_create(&t.ctx, &mut req, &[], plan.as_ref())
            .unwrap_err()
            .to_string();
        assert_eq!(
            err,
            "kit gh wants to send your github secret to evil.example.com, which github doesn't \
             use; refusing"
        );
        assert!(sandbox_rules(&t, "shell-proj").is_empty());
    }

    #[test]
    fn a_kit_may_send_a_custom_secret_anywhere() {
        let mut t = kit_env();
        t.sbt(&[
            "secret",
            "set-custom",
            "--env",
            "CORP",
            "--host",
            "api.corp.example",
            "-t",
            "c-1",
        ])
        .unwrap();
        let dir = inject_kit("corp", "ghe.corp.example");
        let (mut req, plan) = kit_request(&t, &["create", "shell", "--kit"], dir.path());
        crate::provision::prepare_create(&t.ctx, &mut req, &[], plan.as_ref()).unwrap();
        let c = req
            .credentials
            .iter()
            .find(|c| c.env_var == "GH_TOKEN")
            .unwrap_or_else(|| panic!("{:?}", req.credentials));
        assert_eq!(c.hosts, vec!["ghe.corp.example"]);
    }

    #[test]
    fn a_kit_injecting_a_global_secrets_variable_differently_fails() {
        let t = kit_env();
        global_github_secret(&t);
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("spec.yaml"),
            "schemaVersion: \"2\"\nkind: mixin\nname: gh\ncredentials:\n  - service: github\n    \
             apiKey:\n      name: GH_TOKEN\n      inject:\n        - domain: api.github.com\n          \
             header: x-token\n",
        )
        .unwrap();
        let (mut req, plan) = kit_request(&t, &["create", "shell", "--kit"], dir.path());
        let err = crate::provision::prepare_create(&t.ctx, &mut req, &[], plan.as_ref())
            .unwrap_err()
            .to_string();
        assert!(err.contains("GH_TOKEN"), "{err}");
        assert!(sandbox_rules(&t, "shell-proj").is_empty());
    }

    /// A mixin binding the github secret to `env` for api.github.com with `inject`.
    fn gh_kit(env: &str, inject: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("spec.yaml"),
            format!(
                "schemaVersion: \"2\"\nkind: mixin\nname: gh\ncredentials:\n  - service: github\n    \
                 apiKey:\n      name: {env}\n      inject:\n        - domain: api.github.com\n{inject}"
            ),
        )
        .unwrap();
        dir
    }

    #[test]
    fn a_kit_format_must_match_the_user_secret_of_its_variable() {
        // The user's github secret records no format and no header for GH_TOKEN.
        for (inject, ok) in [
            ("", true),
            ("          scheme: bearer\n", false),
            (
                "          scheme: basic\n          username: x-access-token\n",
                false,
            ),
        ] {
            let t = kit_env();
            global_github_secret(&t);
            let dir = gh_kit("GH_TOKEN", inject);
            let (mut req, plan) = kit_request(&t, &["create", "shell", "--kit"], dir.path());
            let r = crate::provision::prepare_create(&t.ctx, &mut req, &[], plan.as_ref());
            match ok {
                true => {
                    r.unwrap();
                    assert!(req.credential_formats.is_empty());
                }
                false => {
                    let err = r.unwrap_err().to_string();
                    assert_eq!(
                        err,
                        "kit gh: the github credential (GH_TOKEN) is injected differently by your \
                         github secret"
                    );
                }
            }
        }
    }

    #[test]
    fn two_kits_with_the_same_format_merge_and_differing_ones_fail() {
        // KIT_TOKEN isn't one of the github secret's own variables, so only the kits bind it.
        let bearer = "          scheme: bearer\n";
        let basic = "          scheme: basic\n          username: u\n";
        for (second, ok) in [(bearer, true), (basic, false)] {
            let t = kit_env();
            global_github_secret(&t);
            let dir = gh_kit("KIT_TOKEN", bearer);
            let other = gh_kit("KIT_TOKEN", second);
            let spec = other.path().join("spec.yaml");
            let text = std::fs::read_to_string(&spec)
                .unwrap()
                .replace("name: gh", "name: gh2");
            std::fs::write(&spec, text).unwrap();
            let other = other.path().display().to_string();
            let (mut req, plan) = kit_request(
                &t,
                &["create", "shell", "--kit", other.as_str(), "--kit"],
                dir.path(),
            );
            let r = crate::provision::prepare_create(&t.ctx, &mut req, &[], plan.as_ref());
            assert_eq!(r.is_ok(), ok, "{second}: {r:?}");
            if ok {
                let kit: Vec<_> = req
                    .credentials
                    .iter()
                    .filter(|c| c.env_var == "KIT_TOKEN")
                    .collect();
                assert_eq!(kit.len(), 1, "{:?}", req.credentials);
                assert_eq!(kit[0].set_header.as_deref(), Some("authorization"));
            }
        }
    }

    #[test]
    fn the_shipped_docker_kit_comes_before_user_kits() {
        let t = kit_env();
        let kit = |name: &str| {
            let dir = tempfile::tempdir().unwrap();
            std::fs::write(
                dir.path().join("spec.yaml"),
                format!("schemaVersion: \"2\"\nkind: mixin\nname: {name}\n"),
            )
            .unwrap();
            dir
        };
        let (b, a) = (kit("bkit"), kit("akit"));
        let b_path = b.path().display().to_string();
        let (_, plan) = kit_request(
            &t,
            &["create", "shell", "--kit", &b_path, "--kit"],
            a.path(),
        );
        let names: Vec<String> = plan
            .unwrap()
            .mixins
            .iter()
            .map(|k| k.name.clone())
            .collect();
        assert_eq!(names, ["docker", "bkit", "akit"]);
    }

    #[test]
    fn an_explicit_docker_kit_comes_before_user_kits_too() {
        let t = kit_env();
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("spec.yaml"),
            "schemaVersion: \"2\"\nkind: mixin\nname: akit\n",
        )
        .unwrap();
        let a = dir.path().display().to_string();
        // `--kit docker` after the user kit.
        let (_, plan) = kit_request(
            &t,
            &["create", "-t", "alpine", "shell", "--kit", &a, "--kit"],
            std::path::Path::new("docker"),
        );
        let names: Vec<String> = plan
            .unwrap()
            .mixins
            .iter()
            .map(|k| k.name.clone())
            .collect();
        assert_eq!(names, ["docker", "akit"]);
    }

    #[test]
    fn order_mixins_puts_the_docker_kit_first() {
        use crate::kits::load;
        use crate::kits::model::{Kind, Kit, Source};
        let wl = Kit::new("wl", Kind::Workload, Source::Registry("acme/wl:1".into()));
        let mixin = |n: &str| Kit::new(n, Kind::Mixin, Source::Registry(format!("acme/{n}:1")));
        let names = |ks: Vec<Kit>| ks.into_iter().map(|k| k.name).collect::<Vec<_>>();
        let docker = load::builtin("docker").unwrap().unwrap();
        // No Docker image: as given.
        assert_eq!(
            names(order_mixins(false, &wl, vec![mixin("a")]).unwrap()),
            ["a"]
        );
        // A Docker image gets the shipped kit, first.
        assert_eq!(
            names(order_mixins(true, &wl, vec![mixin("a")]).unwrap()),
            [docker.name.as_str(), "a"]
        );
        // `--kit docker` after another kit moves first, and isn't added twice.
        let given = vec![mixin("a"), docker.clone()];
        assert_eq!(
            names(order_mixins(true, &wl, given).unwrap()),
            [docker.name.as_str(), "a"]
        );
    }

    /// `kit_target` and a quiet `kit_plan` for `args` followed by `kit`.
    #[test]
    fn a_kit_providing_docker_replaces_the_shipped_one() {
        use crate::agents;
        use crate::kits::{load, model::Source};
        let preset = load::preset_kit(agents::find("shell").unwrap(), "img:1");
        let mut own = load::builtin("docker").unwrap().unwrap();
        own.source = Source::Registry("acme/dind:1".into());
        own.name = "dind".into();
        assert!(needs_docker_kit(true, &preset, &[]));
        assert!(!needs_docker_kit(false, &preset, &[]));
        assert!(!needs_docker_kit(true, &preset, &[own.clone()]));
        let shipped = load::builtin("docker").unwrap().unwrap();
        assert!(!needs_docker_kit(true, &preset, &[shipped]));
        own.provides.clear();
        assert!(needs_docker_kit(true, &preset, &[own]));
    }

    fn kit_request(
        t: &TestEnv,
        args: &[&str],
        kit: &std::path::Path,
    ) -> (
        crate::sandbox::CreateRequest,
        Option<crate::kits::resolve::Plan>,
    ) {
        let kit = kit.display().to_string();
        let argv: Vec<&str> = std::iter::once("sbt")
            .chain(args.iter().copied())
            .chain([kit.as_str(), "--cpus", "1", "-m", "1g"])
            .collect();
        let Some(Cmd::Create(a)) = Cli::try_parse_from(argv).unwrap().command else {
            panic!("expected create");
        };
        let (mut req, workload) = super::kit_target(&t.ctx, &a.targets, &a.opts, true).unwrap();
        let quiet = super::Progress::new(t.ctx.out.clone(), false, false, true);
        let plan = workload.map(|w| super::kit_plan(&t.ctx, &mut req, w, &a.opts, &quiet).unwrap());
        (req, plan)
    }

    const SHARED: &str = "/home/agent/.chk-shared";

    /// A `shell-proj` create with a v3 mixin `./hm` declaring host-mount@1 at `path`, mode 0750.
    fn host_mount_env(path: &str) -> TestEnv {
        let t = kit_env();
        creatable_as(&t, "shell-proj");
        let descriptor = format!(
            r#"{{"schemaVersion":"3","kind":"mixin","name":"hm","capabilities":[
                {{"type":"com.docker.sandbox/host-mount@1","config":{{"path":"{path}",
                "mode":"0750"}}}}]}}"#
        );
        v3_kit(&t, "hm", &descriptor, &[]);
        std::fs::create_dir(t.ctx.cwd.join("data")).unwrap();
        t
    }

    /// `./hm`'s managed directory for `path`.
    fn managed(t: &TestEnv, path: &str) -> std::path::PathBuf {
        let kit = t.ctx.cwd.join("hm").display().to_string();
        crate::kits::host_mount::managed_dir(&t.ctx.paths.kit_host_mounts(), &kit, path)
    }

    /// The `-v` values and the `sbx.host-mounts` label of the machine create.
    fn create_mounts(t: &TestEnv) -> (Vec<String>, Option<String>) {
        let call = t
            .ctx
            .vm
            .runner()
            .calls()
            .into_iter()
            .find(|c| c.starts_with(&["machine".to_string(), "create".to_string()]))
            .expect("a machine create");
        let value = |flag: &str| -> Vec<String> {
            call.windows(2)
                .filter(|w| w[0] == flag)
                .map(|w| w[1].clone())
                .collect()
        };
        let label = value("--label")
            .into_iter()
            .find_map(|l| l.strip_prefix("sbx.host-mounts=").map(String::from));
        (value("-v"), label)
    }

    fn mode(path: &std::path::Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).unwrap().permissions().mode() & 0o7777
    }

    /// Creates `args` (a `claude-proj` or `shell-proj` sandbox) with `env`; returns the env, the
    /// skills `-v` values and the `sbx.skills` label.
    fn skills_create(
        env: &[(&str, &str)],
        args: &[&str],
    ) -> (TestEnv, anyhow::Result<i32>, Vec<String>, Option<String>) {
        let mut all = vec![("SMOLBENTO_DOCKER", "false")];
        all.extend_from_slice(env);
        let mut t = test_env(&all);
        let agent = args[1];
        let fake = t.runner();
        fake.ok(
            &["machine", "status"],
            &json(
                &format!("sbx-{agent}-proj"),
                "created",
                &format!("{agent}-proj"),
            ),
        );
        fake.once_fail(&["machine", "status"], "NOT_FOUND", "vm not found");
        let r = t.sbt(args);
        if r.is_err() {
            return (t, r, vec![], None);
        }
        let store = t.ctx.paths.skills_store().display().to_string();
        let call = t
            .ctx
            .vm
            .runner()
            .calls()
            .into_iter()
            .find(|c| c.starts_with(&["machine".to_string(), "create".to_string()]))
            .expect("a machine create");
        let value = |flag: &str| -> Vec<String> {
            call.windows(2)
                .filter(|w| w[0] == flag)
                .map(|w| w[1].clone())
                .collect()
        };
        let mounts = value("-v")
            .into_iter()
            .filter(|v| v.starts_with(&format!("{store}:")))
            .collect();
        let label = value("--label")
            .into_iter()
            .find_map(|l| l.strip_prefix("sbx.skills=").map(String::from));
        (t, r, mounts, label)
    }

    #[test]
    fn create_shares_skills_by_mode() {
        use crate::skills::{Access, Label, Mode, Shared};
        let claude = "/home/agent/.claude/skills";
        // (env, args, the store's mount point, the label's mode and access)
        type Case<'a> = (
            &'a [(&'a str, &'a str)],
            &'a [&'a str],
            Option<&'a str>,
            Mode,
            Shared,
            Access,
        );
        let cases: [Case; 5] = [
            (
                &[],
                &["create", "claude", "."],
                Some("/run/sbx/skills-shared:ro"),
                Mode::Readonly,
                Shared::Ro,
                Access::Link,
            ),
            (
                &[],
                &["create", "claude", ".", "--skills", "readwrite"],
                Some(claude),
                Mode::Readwrite,
                Shared::None,
                Access::Rw,
            ),
            (
                &[],
                &["create", "claude", ".", "--skills", "off"],
                None,
                Mode::Off,
                Shared::None,
                Access::None,
            ),
            (
                &[("SMOLBENTO_SKILLS_DEFAULT_MODE", "off")],
                &["create", "claude", "."],
                None,
                Mode::Off,
                Shared::None,
                Access::None,
            ),
            (
                &[("SMOLBENTO_SKILLS_DEFAULT_MODE", "off")],
                &["create", "claude", ".", "--skills", "readonly"],
                Some("/run/sbx/skills-shared:ro"),
                Mode::Readonly,
                Shared::Ro,
                Access::Link,
            ),
        ];
        for (env, args, mount, want_mode, shared, access) in cases {
            let (t, r, mounts, label) = skills_create(env, args);
            r.unwrap();
            let store = t.ctx.paths.skills_store();
            let want: Vec<String> = mount
                .map(|m| format!("{}:{m}", store.display()))
                .into_iter()
                .collect();
            assert_eq!(mounts, want, "{args:?}");
            let label = Label::from_label(&label.expect("an sbx.skills label")).unwrap();
            assert_eq!(label.mode, want_mode, "{args:?}");
            assert_eq!(label.shared, shared, "{args:?}");
            assert_eq!(label.dirs.len(), 1, "{args:?}");
            assert_eq!(label.dirs[0].path, claude);
            assert_eq!(label.dirs[0].access, access, "{args:?}");
            if access == Access::None {
                assert!(!store.exists(), "{args:?}");
            } else {
                assert_eq!(mode(&store), 0o700, "{args:?}");
            }
        }

        let (t, r, mounts, label) = skills_create(&[], &["create", "shell", "."]);
        r.unwrap();
        assert!(mounts.is_empty() && label.is_none(), "{mounts:?} {label:?}");
        assert!(!t.ctx.paths.skills_store().exists());

        let (_, r, _, _) = skills_create(&[], &["create", "claude", ".", "--skills", "bogus"]);
        assert_eq!(
            r.unwrap_err().to_string(),
            "invalid skills mode \"bogus\": use off, readonly or readwrite"
        );
    }

    const AS: &str = "com.docker.sandbox/agent-skills@1";
    const AK: &str = "com.docker.sandbox/agent-skill@1";

    /// An `<agent>-proj` create env with a v3 mixin `./k` (named `k`) whose capabilities are
    /// `caps` (a JSON list body).
    fn skills_kit_env(agent: &str, caps: &str) -> TestEnv {
        let t = kit_env();
        let fake = t.runner();
        fake.ok(
            &["machine", "status"],
            &json(
                &format!("sbx-{agent}-proj"),
                "created",
                &format!("{agent}-proj"),
            ),
        );
        fake.once_fail(&["machine", "status"], "NOT_FOUND", "vm not found");
        let descriptor =
            format!(r#"{{"schemaVersion":"3","kind":"mixin","name":"k","capabilities":[{caps}]}}"#);
        v3_kit(&t, "k", &descriptor, &[]);
        t
    }

    /// The `sbx.skills` label of the machine create.
    fn skills_label(t: &TestEnv) -> crate::skills::Label {
        let call = t
            .ctx
            .vm
            .runner()
            .calls()
            .into_iter()
            .find(|c| c.starts_with(&["machine".to_string(), "create".to_string()]))
            .unwrap();
        let label = call
            .windows(2)
            .filter(|w| w[0] == "--label")
            .find_map(|w| w[1].strip_prefix("sbx.skills=").map(String::from))
            .expect("an sbx.skills label");
        crate::skills::Label::from_label(&label).unwrap()
    }

    #[test]
    fn a_kit_s_bundled_skill_caps_its_directory_and_links_before_install_hooks() {
        use crate::skills::Access;
        let caps = format!(
            r#"{{"type":"{AS}","config":{{"path":"/home/agent/.k/skills"}}}},
               {{"type":"{AK}","config":{{"path":"/opt/k/review"}}}},
               {{"type":"com.docker.sandbox/lifecycle@1",
                 "config":{{"install":[{{"command":"echo hook-ran"}}]}}}}"#
        );
        let mut t = skills_kit_env("shell", &caps);
        t.sbt(&[
            "create",
            "shell",
            ".",
            "--kit",
            "./k",
            "--skills",
            "readwrite",
        ])
        .unwrap();
        let label = skills_label(&t);
        assert_eq!(label.dirs.len(), 1, "{label:?}");
        assert_eq!(label.dirs[0].path, "/home/agent/.k/skills");
        assert_eq!(label.dirs[0].access, Access::Link);
        // The kit asks for readonly: the shared mount stays read-only under `readwrite`.
        assert_eq!(label.shared, crate::skills::Shared::Ro);
        let (mounts, _) = create_mounts(&t);
        let store = t.ctx.paths.skills_store().display().to_string();
        assert!(
            mounts.contains(&format!("{store}:/run/sbx/skills-shared:ro")),
            "{mounts:?}"
        );
        let lines = t.calls();
        let bundled = lines
            .iter()
            .position(|l| l.starts_with("machine exec") && l.contains("ln -sn '/opt/k/review'"))
            .expect("the bundled skills step");
        assert!(
            lines[bundled].contains(" -u root ") && lines[bundled].contains(" -- sh -c "),
            "{}",
            lines[bundled]
        );
        let hook = lines
            .iter()
            .position(|l| l.starts_with("machine exec") && l.contains("echo hook-ran"))
            .expect("the install hook");
        assert!(bundled < hook, "{lines:#?}");
    }

    /// The store's `-v` targets (`guest[:ro]`) of a `shell-proj` create with kit `k` and `caps`.
    fn kit_skills_mounts(caps: &str, mode: &str) -> (Vec<String>, crate::skills::Label) {
        let mut t = skills_kit_env("shell", caps);
        t.sbt(&["create", "shell", ".", "--kit", "./k", "--skills", mode])
            .unwrap();
        let store = format!("{}:", t.ctx.paths.skills_store().display());
        let (mounts, _) = create_mounts(&t);
        let mounts = mounts
            .iter()
            .filter_map(|m| m.strip_prefix(&store).map(String::from))
            .collect();
        (mounts, skills_label(&t))
    }

    /// sbx's kit table: without a bundled skill the store is mounted over each kit directory
    /// (no links); with one, every directory links and the shared mount takes the widest access.
    #[test]
    fn kit_skills_directories_follow_sbx_s_table() {
        use crate::skills::{Access, Shared};
        let dirs = format!(
            r#"{{"type":"{AS}","config":{{"path":"/r"}}}},
               {{"type":"{AS}","config":{{"path":"/w","mode":"readwrite"}}}}"#
        );
        let bundled = format!(r#"{dirs},{{"type":"{AK}","config":{{"path":"/opt/k/review"}}}}"#);
        let access =
            |l: &crate::skills::Label| -> Vec<Access> { l.dirs.iter().map(|d| d.access).collect() };
        let (m, l) = kit_skills_mounts(&dirs, "readwrite");
        assert_eq!(m, ["/r:ro", "/w"]);
        assert_eq!(
            (l.shared, access(&l)),
            (Shared::None, vec![Access::Ro, Access::Rw])
        );
        let (m, l) = kit_skills_mounts(&dirs, "readonly");
        assert_eq!(m, ["/r:ro", "/w:ro"]);
        assert_eq!(access(&l), [Access::Ro, Access::Ro]);
        let (m, l) = kit_skills_mounts(&dirs, "off");
        assert!(m.is_empty(), "{m:?}");
        assert_eq!(access(&l), [Access::None, Access::None]);
        let (m, l) = kit_skills_mounts(&bundled, "readwrite");
        assert_eq!(m, ["/run/sbx/skills-shared"]);
        assert_eq!(
            (l.shared, access(&l)),
            (Shared::Rw, vec![Access::Link, Access::Link])
        );
        let (m, l) = kit_skills_mounts(&bundled, "readonly");
        assert_eq!(m, ["/run/sbx/skills-shared:ro"]);
        assert_eq!(
            (l.shared, access(&l)),
            (Shared::Ro, vec![Access::Link, Access::Link])
        );
        let (m, l) = kit_skills_mounts(&bundled, "off");
        assert!(m.is_empty(), "{m:?}");
        assert_eq!(
            (l.shared, access(&l)),
            (Shared::None, vec![Access::None, Access::None])
        );
    }

    #[test]
    fn a_bundled_skill_without_a_skills_directory_fails_or_is_skipped() {
        let required = format!(r#"{{"type":"{AK}","config":{{"path":"/opt/k/review"}}}}"#);
        let mut t = skills_kit_env("shell", &required);
        let e = t
            .sbt(&["create", "shell", ".", "--kit", "./k"])
            .unwrap_err();
        assert_eq!(
            format!("{e:#}"),
            "kit k: skill review needs a skills directory: no agent-skills@1 in this sandbox"
        );
        let lines = t.calls();
        assert!(
            !lines.iter().any(|l| l.starts_with("machine create")),
            "{lines:#?}"
        );

        let optional =
            format!(r#"{{"type":"{AK}","optional":true,"config":{{"path":"/opt/k/review"}}}}"#);
        let mut t = skills_kit_env("shell", &optional);
        // Prints `note: kit k: skipping skill review: no skills directory in this sandbox`.
        t.sbt(&["create", "shell", ".", "--kit", "./k"]).unwrap();
        let lines = t.calls();
        assert!(lines.iter().any(|l| l.starts_with("machine create")));
        assert!(!lines.iter().any(|l| l.contains("ln -sn ")), "{lines:#?}");
    }

    #[test]
    fn a_kit_s_readonly_request_does_not_cap_the_built_in_readwrite_one() {
        use crate::skills::Access;
        let caps = format!(
            r#"{{"type":"{AS}","config":{{"path":"/home/agent/.claude/skills","mode":"readonly"}}}}"#
        );
        let mut t = skills_kit_env("claude", &caps);
        t.sbt(&[
            "create",
            "claude",
            ".",
            "--kit",
            "./k",
            "--skills",
            "readwrite",
        ])
        .unwrap();
        let label = skills_label(&t);
        assert_eq!(label.dirs.len(), 1, "{label:?}");
        assert_eq!(label.dirs[0].path, "/home/agent/.claude/skills");
        assert_eq!(label.dirs[0].access, Access::Rw);
    }

    #[test]
    fn create_mounts_a_kit_s_managed_host_directory() {
        let mut t = host_mount_env(SHARED);
        t.sbt(&["create", "shell", ".", "--kit", "./hm"]).unwrap();
        let out = t.stdout();
        assert!(
            out.contains("\nKITS\n  ○ ./hm — building…\n  ✓ ./hm — ready\n\nIMAGE\n"),
            "{out}"
        );
        let dir = managed(&t, SHARED);
        let (mounts, label) = create_mounts(&t);
        assert!(
            mounts.contains(&format!("{}:{SHARED}", dir.display())),
            "{mounts:?}"
        );
        let want = serde_json::json!({ SHARED: dir }).to_string();
        assert_eq!(label.as_deref(), Some(want.as_str()));
        assert_eq!(mode(&dir), 0o750);
        assert_eq!(mode(dir.parent().unwrap()), 0o700);
        assert_eq!(mode(&t.ctx.paths.kit_host_mounts()), 0o700);
    }

    #[test]
    fn an_existing_managed_directory_is_reused_unchanged() {
        use std::os::unix::fs::PermissionsExt;
        let mut t = host_mount_env(SHARED);
        let dir = managed(&t, SHARED);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o711)).unwrap();
        std::fs::write(dir.join("keep"), "x").unwrap();
        t.sbt(&["create", "shell", ".", "--kit", "./hm"]).unwrap();
        assert_eq!(mode(&dir), 0o711);
        assert_eq!(std::fs::read_to_string(dir.join("keep")).unwrap(), "x");
    }

    #[test]
    fn mount_binds_a_host_directory_instead_of_the_managed_one() {
        let mut t = host_mount_env(SHARED);
        let bind = format!("data:{SHARED}");
        t.sbt(&["create", "shell", ".", "--kit", "./hm", "--mount", &bind])
            .unwrap();
        let data = t.ctx.cwd.join("data");
        let (mounts, label) = create_mounts(&t);
        assert!(
            mounts.contains(&format!("{}:{SHARED}", data.display())),
            "{mounts:?}"
        );
        let want = serde_json::json!({ SHARED: data }).to_string();
        assert_eq!(label.as_deref(), Some(want.as_str()));
        assert!(!t.ctx.paths.kit_host_mounts().exists());
    }

    #[test]
    fn refused_mounts_create_nothing() {
        let shared = format!("data:{SHARED}");
        let other = "data:/home/agent/other";
        let undeclared = "no kit declares host-mount@1 at \"/home/agent/other\"";
        let cases: Vec<(Vec<&str>, String)> = vec![
            (
                vec!["--kit", "./hm", "--mount", "data"],
                "--mount \"data\" requires HOST:SANDBOX_PATH\n  try: sbt create --help".into(),
            ),
            (
                vec!["--kit", "./hm", "--mount", "missing:/x"],
                "HOST \"{cwd}/missing\" does not exist on the host".into(),
            ),
            (
                vec!["--kit", "./hm", "--mount", &shared, "--mount", &shared],
                format!("--mount {SHARED} given twice"),
            ),
            (vec!["--kit", "./hm", "--mount", other], undeclared.into()),
            // No kits at all.
            (vec!["-t", "alpine", "--mount", other], undeclared.into()),
        ];
        for (flags, want) in cases {
            let mut t = host_mount_env(SHARED);
            let cwd = t.ctx.cwd.display().to_string();
            let mut args = vec!["create", "shell", "."];
            args.extend(&flags);
            let e = t.sbt(&args).unwrap_err();
            assert_eq!(format!("{e:#}"), want.replace("{cwd}", &cwd), "{flags:?}");
            assert!(!t.made("machine create"), "{flags:?}");
            assert!(!t.ctx.paths.kit_host_mounts().exists(), "{flags:?}");
        }
    }

    #[test]
    fn a_host_mount_at_a_workspace_path_is_refused() {
        let ws = tempfile::tempdir().unwrap();
        let ws = ws.path().canonicalize().unwrap().display().to_string();
        let mut t = host_mount_env(&ws);
        let e = t
            .sbt(&["create", "shell", &ws, "--kit", "./hm", "--name", "ws"])
            .unwrap_err();
        assert_eq!(
            format!("{e:#}"),
            format!("host-mount@1 path {ws} is already a workspace mount")
        );
        assert!(!t.made("machine create"));
        assert!(!t.ctx.paths.kit_host_mounts().exists());
    }

    #[test]
    fn kit_docker_adds_dockerd_to_any_template() {
        let mut t = test_env(&[]);
        creatable_as(&t, "shell-proj");
        t.sbt(&["create", "-t", "alpine", "--kit", "docker", "shell", "."])
            .unwrap();
        let line = create_line(&t);
        assert!(line.contains("--image alpine "), "{line}");
        assert!(
            line.contains("-v /var/lib/docker -v /var/lib/containerd"),
            "{line}"
        );
        assert!(line.contains("--label sbx.docker=true"), "{line}");
        assert!(
            line.contains(r#"--label sbx.kits=["builtin:docker"]"#),
            "{line}"
        );
    }

    #[test]
    fn a_template_refuses_kits_that_add_image_layers() {
        let mut t = kit_env_free();
        saved_template(&t, "chk-tpl:v1", "shell");
        v3_kit(
            &t,
            "layered",
            r#"{"schemaVersion":"3","kind":"mixin","name":"layered"}"#,
            &[b"layer"],
        );
        let err = t
            .sbt(&[
                "create",
                "shell",
                "-t",
                "chk-tpl:v1",
                "--name",
                "bb",
                "--kit",
                "./layered",
            ])
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "-t docker.io/library/chk-tpl:v1 can't be combined with kits that add image layers \
             (layered): a template's filesystem is saved whole"
        );
        let lines = t.calls();
        assert!(
            !lines.iter().any(|l| l.contains("machine create")),
            "{lines:?}"
        );
    }

    #[test]
    fn create_of_a_taken_name_fails_before_printing_or_fetching_kits() {
        let mut t = kit_env();
        t.runner().ok(
            &["machine", "status"],
            &json("sbx-shell-proj", "stopped", "shell-proj"),
        );
        v3_kit(
            &t,
            "kit",
            r#"{"schemaVersion":"3","kind":"mixin","name":"m"}"#,
            &[],
        );
        let err = t
            .sbt(&["create", "shell", ".", "--kit", "./kit"])
            .unwrap_err();
        assert_eq!(err.to_string(), "sandbox 'shell-proj' already exists");
        assert_eq!(t.stdout(), "");
        assert_eq!(
            t.calls(),
            ["--version", "machine status -n sbx-shell-proj --json"]
        );
    }

    #[test]
    fn kits_without_a_fetch_wait_for_the_kits_section() {
        let mut t = host_mount_env(SHARED);
        let v2 = fixture("tool-mixin");
        t.sbt(&["create", "shell", ".", "--kit", &v2, "--kit", "./hm"])
            .unwrap();
        let out = t.stdout();
        assert!(
            out.contains(&format!(
                "\nKITS\n  ✓ {v2} — cached\n  ○ ./hm — building…\n  ✓ ./hm — ready\n\nIMAGE\n"
            )),
            "{out}"
        );
    }
}
