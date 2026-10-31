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
    let agent = agents::find(agent_name).with_context(|| unknown_agent(agent_name))?;
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

pub(crate) fn unknown_agent(name: &str) -> String {
    format!("unknown agent \"{name}\"")
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
                bail!(unknown_agent(target));
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
pub(super) fn order_mixins(
    docker_image: bool,
    workload: &Kit,
    mut mixins: Vec<Kit>,
) -> Result<Vec<Kit>> {
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
pub(super) fn needs_docker_kit(docker_image: bool, workload: &Kit, mixins: &[Kit]) -> bool {
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
