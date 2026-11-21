//! From `create`/`run` options to a sandbox request: the agent or workload, workspaces, `--clone`,
//! and the kit plan (load, pin args, order, resolve), with the `KITS` progress section.

use anyhow::{Context, Result, bail};

use super::progress::Progress;
use super::{Ctx, DiskSizes, SandboxOpts};
use crate::agents;
use crate::kits::capability;
use crate::kits::load;
use crate::kits::model::{Content, Kind, Kit, Source};
use crate::kits::resolve::{Plan, resolve_for};
use crate::sandbox::{self, CreateRequest, Recorded, Sandbox, name, options};
use crate::smolvm::Runner;
use crate::util;
use crate::workspace::{self, Workspace, clone};

/// Turns sbx's create options into a [`CreateRequest`], all but the image: `agent` is the agent
/// or workload kit name (the `sbx.agent` label and the default name's prefix). `default_to_cwd`:
/// `run` mounts the current directory when no path is given; `create` makes a mountless sandbox.
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
    let (storage_gib, overlay_gib) = disk_sizes(ctx, &opts.disk)?;
    let env = options::parse_env(&opts.env, &opts.env_file, &ctx.env)?;
    let ports = opts
        .publish
        .iter()
        .map(|p| options::parse_publish(p, &options::free_port))
        .collect::<Result<Vec<_>>>()?;
    // Before any smolvm call, so a bad value fails early.
    let skills_mode = crate::skills::resolve_mode(opts.skills.as_deref(), &ctx.settings)?;

    Ok(CreateRequest {
        rec: Recorded {
            no_fuse: opts.no_fuse,
            read_only_files: opts.read_only_files.clone(),
            ..Default::default()
        },
        name,
        agent: agent.into(),
        workspaces,
        cpus,
        memory_mib,
        storage_gib,
        overlay_gib,
        env,
        ports,
        created: ctx.now,
        cpus_set: opts.cpus.is_some(),
        memory_set: opts.memory.is_some(),
        host_mounts,
        skills_mode,
        mcp: opts.static_mcp.clone(),
        ..Default::default()
    })
}

/// Kit args need a kit: a `--kit` or a workload kit as the target. Like sbx this fails on every
/// command, including `run` of an existing sandbox.
pub(crate) fn check_kit_args(targets: &[String], opts: &SandboxOpts) -> Result<()> {
    // Every target is a workload kit, built-in agents included.
    if targets.is_empty() && opts.kit.is_empty() && opts.kit_args.given() {
        bail!("kit arguments were supplied but no kits were referenced");
    }
    Ok(())
}

/// The workload `kit_target` found, not loaded yet: a saved template's kits, a built-in agent's
/// kit or a workload kit.
pub(crate) enum Workload {
    /// A saved template: its recorded kits, loaded by their pinned refs.
    Template(Box<crate::templates::Entry>),
    /// A built-in agent's published kit, by `agents::kit_ref`.
    Agent {
        name: String,
        reference: String,
    },
    Ref(String),
}

/// smolvm's disk sizes in GiB, `(storage, overlay)`; `None` keeps smolvm's default. The root
/// filesystem's changes are the overlay. Docker's data and a clone's workspace share the storage
/// disk, so the larger of their sizes wins; without an environment file's `dockerSize`, the
/// `sandbox.disk.dockerVolume` setting applies.
fn disk_sizes<R: Runner>(ctx: &Ctx<R>, d: &DiskSizes) -> Result<(Option<u32>, Option<u32>)> {
    let gib = |v: Option<&str>, what| v.map(|v| util::size_gib(v, what)).transpose();
    let setting = ctx.settings.value("sandbox.disk.dockerVolume")?;
    let docker = match &d.docker {
        Some(v) => gib(Some(v), "sandboxOptions.dockerSize")?,
        None => gib(
            Some(setting.as_str()).filter(|v| !v.is_empty()),
            "sandbox.disk.dockerVolume",
        )?,
    };
    let cloned = gib(
        d.cloned_workspace.as_deref(),
        "sandboxOptions.clonedWorkspaceSize",
    )?;
    let overlay = gib(d.root.as_deref(), "sandboxOptions.rootSize")?;
    Ok((docker.max(cloned), overlay))
}

/// What `run` and `create` do about a default name (no `--name`), as sbx 0.53 does for two folders
/// with the same name. With `reuse` (`run`), the sandbox for this folder and agent is returned
/// whatever it's called. Otherwise a default name that another folder's sandbox holds is refused
/// with a suggested name, or, with `sandbox.autoName`, replaced by it.
pub(crate) fn settle_default_name<R: Runner>(
    ctx: &Ctx<R>,
    req: &mut CreateRequest,
    opts: &SandboxOpts,
    reuse: bool,
) -> Result<Option<Sandbox>> {
    if opts.name.is_some() {
        return Ok(None);
    }
    let Some(ws) = req.workspaces.first().map(|w| w.path.clone()) else {
        return Ok(None);
    };
    let here = ws.display().to_string();
    let all = sandbox::list(&ctx.vm)?;
    let mine =
        |s: &&Sandbox| s.meta.agent == req.agent && s.meta.workspace.as_deref() == Some(&here);
    if reuse && let Some(sb) = all.iter().find(mine) {
        return Ok(Some(sb.clone()));
    }
    let Some(owner) = all.iter().find(|s| s.name() == req.name && !mine(s)) else {
        return Ok(None);
    };
    let used_by = owner.meta.workspace.as_deref().unwrap_or("(none)");
    let suggested = name::suggest_name(&req.agent, &ws, |n| all.iter().any(|s| s.name() == n));
    if ctx.settings.bool("sandbox.autoName")? {
        eprintln!(
            "note: {} is used by workspace {used_by}; naming this sandbox {suggested}",
            req.name
        );
        req.name = suggested;
        return Ok(None);
    }
    bail!(
        "sandbox name \"{}\" is already used by workspace \"{used_by}\"; pass --name to choose a \
         different name, such as --name {suggested}",
        req.name
    )
}

/// The request for `targets` (a built-in agent or a workload kit REF, then workspace paths), and
/// its workload: a saved template given with `-t`, the agent's kit or the workload kit. Loads no
/// kit (a workload kit's name comes from `load::kit_name`); `kit_plan` loads them.
pub(crate) fn kit_target<R: Runner>(
    ctx: &Ctx<R>,
    targets: &[String],
    opts: &SandboxOpts,
    default_to_cwd: bool,
) -> Result<(CreateRequest, Workload)> {
    let (target, paths) = targets.split_first().context("specify an agent")?;
    if let Some(r) = agents::retired(target) {
        bail!(r.refusal());
    }
    let store = crate::templates::Store::new(&ctx.paths);
    let saved = match &opts.template {
        Some(t) => store.find_ref(t)?,
        None => None,
    };
    if let Some(e) = saved {
        e.check_current()?;
        let same = *target == e.agent
            || (looks_like_kit(target) && load::kit_name(ctx, target)? == e.agent);
        if !same {
            bail!(
                "template {} was saved from a {a} sandbox; run it with {a}",
                e.full(),
                a = e.agent
            );
        }
        let mut req = base_request(ctx, &e.agent, paths, opts, default_to_cwd)?;
        req.template_pack = Some(store.pack(&e));
        req.rec.template = Some(e.full());
        req.image = e.image.clone();
        return Ok((req, Workload::Template(Box::new(e))));
    }
    if opts.pull.as_deref() == Some("never") {
        return Err(super::Unsupported(
            "--pull never works only with a saved template (see `bento template ls`); smolvm \
             pulls missing images"
                .into(),
        )
        .into());
    }
    if let Some(reference) = agents::kit_ref(&ctx.env, target) {
        let req = base_request(ctx, target, paths, opts, default_to_cwd)?;
        let name = target.clone();
        return Ok((req, Workload::Agent { name, reference }));
    }
    if !looks_like_kit(target) {
        bail!(agents::unknown(target));
    }
    let name = load::kit_name(ctx, target)?;
    let req = base_request(ctx, &name, paths, opts, default_to_cwd)?;
    Ok((req, Workload::Ref(target.clone())))
}

/// Whether any kit flag was given (`run` warns that they don't apply to an existing sandbox).
pub(crate) fn has_kit_flags(opts: &SandboxOpts) -> bool {
    !opts.kit.is_empty() || opts.kit_args.given()
}

/// The second half of `kit_target`, for a sandbox about to be created: loads the workload kit
/// (filling `req`'s image) and the `--kit` mixins, each a step under `KITS`, and resolves them
/// with the kit args and `req`'s working directory. Touches neither smolvm's machines nor the
/// policy: `provision::create` applies the plan.
pub(crate) fn kit_plan<R: Runner>(
    ctx: &Ctx<R>,
    req: &mut CreateRequest,
    workload: Workload,
    opts: &SandboxOpts,
    p: &Progress,
) -> Result<Plan> {
    let mut kits = KitsSection::new(p, &req.name);
    let docker_enabled = ctx.settings.bool("docker.enabled")?;
    // A template's own mixins, and every recorded kit's args.
    let mut recorded: Vec<Kit> = Vec::new();
    let mut recorded_args: Vec<(String, Vec<String>)> = Vec::new();
    let (workload_source, mut workload) = match workload {
        Workload::Template(e) => {
            let offline = opts.pull.as_deref() == Some("never");
            // docker.enabled=false leaves out the docker kit the source sandbox had.
            let records = e
                .kits
                .iter()
                .filter(|r| docker_enabled || r.reference != "builtin:docker");
            for (i, rec) in records.enumerate() {
                // The workload record is the agent's own kit for an agent's template.
                let agent = (i == 0 && e.is_agent_template(&ctx.env)).then_some(e.agent.as_str());
                let mut kit = kits.load_pinned(ctx, &rec.reference, offline, agent)?;
                kit.content = match (i, kit.content) {
                    // The template's pack boots; its source image is recorded.
                    (0, _) => Content::Image(e.image.clone()),
                    // A mixin's layers are in the pack already.
                    (_, Content::Oci(_)) => Content::None,
                    (_, content) => content,
                };
                let args = rec.args.iter().map(|(k, v)| format!("{k}={v}")).collect();
                recorded_args.push((kit.name.clone(), args));
                recorded.push(kit);
            }
            (None, recorded.remove(0))
        }
        Workload::Agent { name, reference } => {
            let kit = kits.load_agent(ctx, &name, &reference)?;
            (Some(name), kit)
        }
        Workload::Ref(target) => {
            let kit = kits.load(ctx, &target, load::Position::Agent)?;
            if kit.kind == Kind::Mixin {
                // sbx's report, then how to use the mixin.
                bail!(
                    "{}\n{target} is a mixin; add it with --kit to an agent, e.g. bento run shell \
                     --kit {target}",
                    capability::incoherent(&[capability::NO_WORKLOAD.to_string()])
                );
            }
            (Some(target), kit)
        }
    };
    // A template already set the image; its docker kit comes only from its recorded kits.
    if req.template_pack.is_none() {
        load::check_launchable(ctx, &mut workload, Some(&req.name))?;
        // A Smolfile kit gets a login shell, recorded in `sbx.command` so every attach launches
        // the same thing.
        if workload.command.is_none() {
            workload.command = Some(vec!["bash".into(), "-l".into()]);
        }
        // `-t IMAGE` replaces the kit's image and keeps its capabilities.
        if let Some(image) = &opts.template {
            workload.content = Content::Image(image.clone());
        }
        if let Content::Image(image) = &workload.content {
            req.image = image.clone();
        }
        req.docker = wants_docker(&workload, docker_enabled);
    }
    let mut args = opts.kit_args.values()?;
    for (kit, pins) in &recorded_args {
        args.pin(kit, pins)?;
    }
    let mixins = recorded
        .into_iter()
        .map(Ok)
        .chain(
            opts.kit
                .iter()
                .map(|r| kits.load(ctx, r, load::Position::Kit)),
        )
        .collect::<Result<Vec<_>>>()?;
    for (source, pins) in &opts.kit_pins {
        let given = mixins.len() - opts.kit.len();
        let kit = match opts.kit.iter().position(|k| k == source) {
            Some(i) => &mixins[given + i],
            None if workload_source.as_ref() == Some(source) => &workload,
            None => continue,
        };
        args.pin(&kit.name, pins)?;
    }
    let mut mixins = order_mixins(req.docker, mixins)?;
    crate::kits::resolve::check_formats(&workload, &mixins)?;
    let mut skipped = Vec::new();
    if !docker_enabled {
        for k in std::iter::once(&mut workload).chain(&mut mixins) {
            skipped.extend(crate::kits::resolve::without_dockerd(k)?);
        }
    }
    let mut plan = resolve_for(workload, mixins, &args, &req.workdir())?;
    plan.skipped.extend(skipped);
    if let Some(t) = &req.rec.template {
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
    /// The sandbox being created: its registry logins may be used for the pulls.
    sandbox: String,
    open: bool,
    /// Kits loaded without a fetch before the section opened.
    waiting: Vec<String>,
}

impl<'a> KitsSection<'a> {
    fn new(p: &'a Progress, sandbox: &str) -> Self {
        Self {
            p,
            sandbox: sandbox.to_string(),
            open: false,
            waiting: Vec::new(),
        }
    }

    /// Loads kit `reference`: a pull or build is a step, `○ REF — pulling…` or `building…`,
    /// then `✓ REF — ready`, or `cached` when the kit cache already had it all.
    fn load<R: Runner>(
        &mut self,
        ctx: &Ctx<R>,
        reference: &str,
        position: load::Position,
    ) -> Result<Kit> {
        let sandbox = self.sandbox.clone();
        self.fetch(reference, |before| {
            load::load_noting(ctx, reference, Some(&sandbox), position, before)
        })
    }

    /// `load` for a template's kit `reference` (pinned): `load::pinned`.
    fn load_pinned<R: Runner>(
        &mut self,
        ctx: &Ctx<R>,
        reference: &str,
        offline: bool,
        agent: Option<&str>,
    ) -> Result<Kit> {
        let sandbox = self.sandbox.clone();
        self.fetch(load::unpinned(reference), |before| {
            load::pinned(ctx, reference, offline, agent, Some(&sandbox), before)
        })
    }

    /// `load` for built-in agent `name`'s kit, shown by its `reference`.
    fn load_agent<R: Runner>(&mut self, ctx: &Ctx<R>, name: &str, reference: &str) -> Result<Kit> {
        let sandbox = self.sandbox.clone();
        self.fetch(reference, |before| {
            load::agent(ctx, name, None, false, Some(&sandbox), before)
        })
    }

    /// Runs `load` (given the hook it calls before a fetch) with `reference`'s step.
    fn fetch(
        &mut self,
        reference: &str,
        load: impl FnOnce(&mut dyn FnMut(load::Fetch)) -> Result<(Kit, bool)>,
    ) -> Result<Kit> {
        let mut step = None;
        let loaded = load(&mut |fetch| {
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
fn order_mixins(docker_image: bool, mut mixins: Vec<Kit>) -> Result<Vec<Kit>> {
    if let Some(i) = mixins
        .iter()
        .position(|k| k.source == Source::Builtin("docker"))
    {
        let docker = mixins.remove(i);
        mixins.insert(0, docker);
    } else if needs_docker_kit(docker_image, &mixins) {
        mixins.insert(
            0,
            load::builtin("docker").expect("the docker kit is shipped")?,
        );
    }
    Ok(mixins)
}

/// A Docker-enabled image gets dockerd through the shipped kit (one `dockerd@1` request), unless
/// `--kit docker` added it. Other kits' `provides` don't decide: a kit that starts its own dockerd
/// declares `dockerd@1` (`autoStart: false`), and the merge collapses duplicate requests.
fn needs_docker_kit(docker_image: bool, mixins: &[Kit]) -> bool {
    docker_image && !mixins.iter().any(|k| k.source == Source::Builtin("docker"))
}

/// Whether a workload kit gets the `docker` kit: a prebuilt kit when its manifest asks for an
/// engine, a plain image when its name says it's Docker-enabled; never with `docker.enabled=false`.
fn wants_docker(kit: &Kit, enabled: bool) -> bool {
    enabled
        && match &kit.content {
            Content::Oci(_) => kit.starts_docker,
            Content::Image(image) => is_docker_image(image),
            _ => false,
        }
}

/// True for Docker's `-docker` template variants, which bundle a Docker engine: how an image given
/// with `-t` (not a kit) is judged.
fn is_docker_image(image: &str) -> bool {
    image.rsplit_once(':').is_some_and(|(_, tag)| {
        !tag.contains('/') && (tag.ends_with("-docker") || tag.contains("-docker-"))
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
            .context("--clone needs a workspace path, e.g. `bento create --clone claude .`")?;
        req.clone = Some(clone::source(&primary.path)?);
    }
    Ok(())
}

#[cfg(test)]
#[path = "request_tests.rs"]
mod tests;
