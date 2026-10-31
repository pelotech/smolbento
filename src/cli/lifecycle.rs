//! create, start, stop, rm, prune and reset.

use std::io::Write;
use std::path::Path;
use std::time::UNIX_EPOCH;

use anyhow::{Context, Result, bail};

use super::plan;
use super::progress::Progress;
use super::{CreateArgs, Ctx, PruneArgs, ResetArgs, RmArgs, SandboxOpts, confirm};
use crate::agents;
use crate::kits::args::ArgValues;
use crate::kits::capability;
use crate::kits::load;
use crate::kits::model::{Content, Kind, Kit, Source};
use crate::kits::resolve::{Plan, resolve_for};
use crate::sandbox::{self, CreateRequest, Event, Sandbox, name, options, session};
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
    let mut mixins = opts
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
    // First, added or given with `--kit docker`: other kits' startup steps may use the dockerd it
    // starts (in sbx it's in the image).
    if let Some(i) = mixins
        .iter()
        .position(|k| k.source == Source::Builtin("docker"))
    {
        let docker = mixins.remove(i);
        mixins.insert(0, docker);
    } else if needs_docker_kit(req.docker, &workload, &mixins) {
        mixins.insert(
            0,
            load::builtin("docker").expect("the docker kit is shipped")?,
        );
    }
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

pub fn create<R: Runner>(ctx: &mut Ctx<R>, a: &CreateArgs) -> Result<i32> {
    if a.targets.is_empty() {
        bail!("specify an agent, e.g. `sbt create claude .`");
    }
    check_kit_args(&a.targets, &a.opts)?;
    let (mut req, workload) = kit_target(ctx, &a.targets, &a.opts, false)?;
    let p = Progress::for_ctx(ctx, a.no_progress);
    let sb = create_reported(ctx, &p, &mut req, workload, &a.opts)?;
    p.finish(&format!("Created sandbox {}", sb.name()));
    p.hint(&format!("sbt run --name {}", sb.name()));
    Ok(0)
}

/// Creates the sandbox `kit_target` described, reporting it to `p`: the `SANDBOX` section, then
/// the `KITS`, `IMAGE` and `SETUP` steps. The caller prints the finish line. A taken name fails
/// before anything is printed or any kit is fetched.
pub(crate) fn create_reported<R: Runner>(
    ctx: &Ctx<R>,
    p: &Progress,
    req: &mut CreateRequest,
    workload: Option<Workload>,
    opts: &SandboxOpts,
) -> Result<Sandbox> {
    resolve_clone(req, opts)?;
    plan::check_free(ctx, &req.name)?;
    report_sandbox(p, req, workload.as_ref(), opts.clone);
    let kits = workload
        .map(|w| kit_plan(ctx, req, w, opts, p))
        .transpose()?;
    plan::create_reported(ctx, req, &opts.deny_network, kits.as_ref(), p)
}

/// The `SANDBOX` section, before any kit loads: a workload kit's image is known only once it
/// has, and CPU and memory are what smolbento passes unless a kit's resources change them.
fn report_sandbox(p: &Progress, req: &CreateRequest, workload: Option<&Workload>, clone: bool) {
    p.section("SANDBOX");
    p.field("Name", &req.name);
    p.field("Agent", &req.agent);
    let workspaces: Vec<String> = req
        .workspaces
        .iter()
        .enumerate()
        .map(|(i, w)| {
            let mode = match (i, clone, w.read_only) {
                (0, true, _) => "clone",
                (_, _, true) => "ro",
                _ => "rw",
            };
            format!("{} ({mode})", w.path.display())
        })
        .collect();
    let workspaces = if workspaces.is_empty() {
        "-".to_string()
    } else {
        workspaces.join(", ")
    };
    p.field("Workspace", &workspaces);
    let image = match workload {
        Some(Workload::Ref(r)) => format!("from {r}"),
        _ => req.image.clone(),
    };
    p.field("Image", &image);
    p.field("CPU", &req.cpus.to_string());
    p.field("Memory", &memory(req.memory_mib));
}

/// `32 GiB`, or `768 MiB` when it isn't whole GiB.
fn memory(mib: u64) -> String {
    if mib.is_multiple_of(1024) {
        format!("{} GiB", mib / 1024)
    } else {
        format!("{mib} MiB")
    }
}

/// `start NAME` reports one step per sandbox: `○ NAME — starting…`, then `✓ Started NAME`.
pub fn start<R: Runner>(ctx: &mut Ctx<R>, names: &[String]) -> Result<i32> {
    let p = Progress::for_ctx(ctx, false);
    for n in names {
        let sb = sandbox::get(&ctx.vm, n)?;
        if sb.is_running() {
            writeln!(&ctx.out, "{n} is already running")?;
            continue;
        }
        let start_plan = plan::start_plan(ctx, &sb.meta)?;
        let mut step = p.step(n, "starting");
        let started = sandbox::start_with(&ctx.vm, &sb, &start_plan, &mut |e| {
            if let Event::Pull(pull) = e {
                step.detail(&pull.to_string());
            }
        });
        match started {
            Ok(()) => step.done_as(&format!("Started {n}")),
            Err(e) => {
                step.fail();
                return Err(e);
            }
        }
    }
    Ok(0)
}

pub fn stop<R: Runner>(ctx: &mut Ctx<R>, names: &[String]) -> Result<i32> {
    for n in names {
        stop_sandbox(ctx, &sandbox::get(&ctx.vm, n)?)?;
    }
    Ok(0)
}

/// Stops `sb` if it's running and forgets its sessions.
pub(crate) fn stop_sandbox<R: Runner>(ctx: &Ctx<R>, sb: &Sandbox) -> Result<()> {
    if sb.is_running() {
        ctx.vm.stop(&sb.machine)?;
    }
    session::clear(&ctx.paths.sessions(), sb.name());
    writeln!(&ctx.out, "Stopped {}", sb.name())?;
    Ok(())
}

/// Deletes a sandbox and its per-sandbox policy; `forget_secrets` also drops its own secrets.
pub(crate) fn delete_sandbox<R: Runner>(
    ctx: &Ctx<R>,
    sb: &Sandbox,
    forget_secrets: bool,
) -> Result<()> {
    delete_keeping_remote(ctx, sb, forget_secrets)?;
    if let Some(repo) = &sb.meta.clone_repo {
        // Best effort: the host repo may be gone.
        let _ = clone::remove_remote(Path::new(repo), sb.name());
    }
    Ok(())
}

/// `delete_sandbox` without removing the `--clone` remote: `run --rm` keeps it, so the commits
/// fetched when the agent exits survive.
pub(crate) fn delete_keeping_remote<R: Runner>(
    ctx: &Ctx<R>,
    sb: &Sandbox,
    forget_secrets: bool,
) -> Result<()> {
    ctx.vm.delete(&sb.machine)?;
    session::clear(&ctx.paths.sessions(), sb.name());
    super::secret::forget_sandbox(ctx, sb.name(), forget_secrets)
}

fn remove<R: Runner>(ctx: &Ctx<R>, sb: &Sandbox, forget_secrets: bool) -> Result<()> {
    delete_sandbox(ctx, sb, forget_secrets)?;
    writeln!(&ctx.out, "Removed {}", sb.name())?;
    Ok(())
}

/// `targets` with forks before parents, so smolvm never refuses a parent for its live forks.
fn forks_first(mut targets: Vec<&Sandbox>) -> Vec<&Sandbox> {
    targets.sort_by_key(|sb| sb.meta.fork_of.is_none());
    targets
}

/// Forks of `sb` that aren't being removed with it.
pub(crate) fn remaining_forks<'a>(
    sb: &Sandbox,
    all: &'a [Sandbox],
    removing: &[&str],
) -> Vec<&'a str> {
    all.iter()
        .filter(|f| f.meta.fork_of.as_deref() == Some(sb.name()) && !removing.contains(&f.name()))
        .map(Sandbox::name)
        .collect()
}

pub fn rm<R: Runner>(ctx: &mut Ctx<R>, a: &RmArgs) -> Result<i32> {
    let all = sandbox::list(&ctx.vm)?;
    let targets: Vec<&Sandbox> = if a.all {
        all.iter().collect()
    } else {
        if a.sandboxes.is_empty() {
            bail!("specify sandboxes to remove, or --all");
        }
        a.sandboxes
            .iter()
            .map(|n| sandbox::pick(&all, n))
            .collect::<Result<_>>()?
    };
    if targets.is_empty() {
        writeln!(&ctx.out, "No sandboxes found")?;
        return Ok(0);
    }
    let names: Vec<&str> = targets.iter().map(|sb| sb.name()).collect();
    for sb in &targets {
        let forks = remaining_forks(sb, &all, &names);
        if !forks.is_empty() {
            bail!(
                "{} has forks; remove its forks first: {}",
                sb.name(),
                forks.join(", ")
            );
        }
    }
    confirm(ctx, &format!("Remove {}?", names.join(", ")), a.force)?;
    for sb in forks_first(targets) {
        remove(ctx, sb, true)?;
    }
    Ok(0)
}

/// Unix seconds before which `until=` matches. Accepts RFC 3339 or a duration ago (`24h`).
fn cutoff(filters: &[String], now: i64) -> Result<Option<i64>> {
    let mut cutoff = None;
    for f in filters {
        let Some(v) = f.strip_prefix("until=") else {
            bail!("unsupported filter '{f}'; only until=<timestamp|duration> is supported");
        };
        let t = match humantime::parse_rfc3339_weak(v) {
            Ok(t) => t.duration_since(UNIX_EPOCH)?.as_secs() as i64,
            Err(_) => {
                now - humantime::parse_duration(v)
                    .with_context(|| format!("invalid until value '{v}'"))?
                    .as_secs() as i64
            }
        };
        cutoff = Some(t);
    }
    Ok(cutoff)
}

pub fn prune<R: Runner>(ctx: &mut Ctx<R>, a: &PruneArgs) -> Result<i32> {
    let cutoff = cutoff(&a.filter, ctx.now)?;
    let all = sandbox::list(&ctx.vm)?;
    let targets: Vec<&Sandbox> = all
        .iter()
        .filter(|sb| !sb.is_running())
        .filter(|sb| cutoff.is_none_or(|c| sb.meta.created < c))
        .collect();
    // A parent whose forks stay can't be deleted. One pass is enough while forks can't be forked
    // (`check_forkable`): a skipped parent is never itself a fork that keeps another target.
    let names: Vec<&str> = targets.iter().map(|sb| sb.name()).collect();
    let (skipped, targets): (Vec<&Sandbox>, Vec<&Sandbox>) = targets
        .into_iter()
        .partition(|sb| !remaining_forks(sb, &all, &names).is_empty());
    for sb in &skipped {
        writeln!(&ctx.out, "{} has forks; skipped", sb.name())?;
    }
    let targets = forks_first(targets);
    if targets.is_empty() {
        writeln!(&ctx.out, "Nothing to prune")?;
        return Ok(0);
    }
    if a.dry_run {
        for sb in &targets {
            writeln!(&ctx.out, "Would remove {}", sb.name())?;
        }
        return Ok(0);
    }
    confirm(
        ctx,
        &format!("Remove {} stopped sandbox(es)?", targets.len()),
        a.force,
    )?;
    for sb in &targets {
        remove(ctx, sb, true)?;
    }
    Ok(0)
}

pub fn reset<R: Runner>(ctx: &mut Ctx<R>, a: &ResetArgs) -> Result<i32> {
    confirm(
        ctx,
        "Remove every sandbox, smolbento's session state and the shared skills store?",
        a.force,
    )?;
    let all = sandbox::list(&ctx.vm)?;
    for sb in forks_first(all.iter().collect()) {
        remove(ctx, sb, !a.preserve_secrets)?;
    }
    let _ = std::fs::remove_dir_all(ctx.paths.sessions());
    // A store that won't go must not keep the secrets from being forgotten.
    let wiped = crate::skills::store::Store::new(&ctx.paths).wipe();
    if !a.preserve_secrets {
        super::secret::forget_all(ctx)?;
    }
    wiped?;
    Ok(0)
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::super::testutil::*;
    use super::super::{Cli, Cmd, SandboxOpts};
    use super::build_request;

    fn labels(name: &str) -> Vec<(&'static str, String)> {
        vec![
            ("sbx.name", name.to_string()),
            ("sbx.agent", "claude".into()),
            ("sbx.created", "999000".into()),
        ]
    }

    fn json(machine: &str, state: &str, name: &str) -> String {
        let l = labels(name);
        let pairs: Vec<(&str, &str)> = l.iter().map(|(k, v)| (*k, v.as_str())).collect();
        machine_json(machine, state, &pairs)
    }

    #[test]
    fn create_clone_mounts_the_repo_and_adds_the_remote() {
        let mut t = test_env(&[]);
        let (_d, root) = temp_repo();
        t.ctx.cwd = root.clone();
        let fake = t.runner();
        fake.ok(
            &["machine", "status"],
            &json("sbx-claude-repo", "created", "claude-repo"),
        );
        fake.once_fail(&["machine", "status"], "NOT_FOUND", "vm not found");
        t.sbt(&["create", "--clone", "claude", "."]).unwrap();
        let create = t
            .ctx
            .vm
            .runner()
            .call_lines()
            .into_iter()
            .find(|l| l.contains("machine create"))
            .unwrap();
        assert!(
            create.contains(&format!(
                "-v {}/.git:/run/sandbox/source:ro",
                root.display()
            )),
            "{create}"
        );
        assert!(create.contains("--label sbx.clone=true"), "{create}");
        assert_eq!(
            git_config(&root, "remote.sandbox-claude-repo.uploadpack"),
            "smolbento _upload-pack claude-repo"
        );
        assert_eq!(
            git_config(&root, "remote.sandbox-claude-repo.tagOpt"),
            "--no-tags"
        );
    }

    fn no_machine_created(t: &TestEnv) -> bool {
        !t.calls().iter().any(|l| l.contains("machine create"))
    }

    #[test]
    fn clone_needs_a_repo_before_smolvm_is_called() {
        let mut t = test_env(&[]);
        let err = t.sbt_err(&["create", "--clone", "claude", "."]);
        assert!(err.contains("--clone needs a git repository"), "{err}");
        assert!(no_machine_created(&t));
    }

    #[test]
    fn clone_needs_a_workspace_path_before_smolvm_is_called() {
        let mut t = test_env(&[]);
        let err = t.sbt_err(&["create", "--clone", "claude"]);
        assert!(err.contains("--clone needs a workspace path"), "{err}");
        assert!(no_machine_created(&t));
    }

    #[test]
    fn clone_needs_a_free_remote_before_smolvm_is_called() {
        let mut t = test_env(&[]);
        let (_d, root) = temp_repo();
        git(
            &root,
            &[
                "remote",
                "add",
                "sandbox-claude-repo",
                "https://example.com/x",
            ],
        );
        t.ctx.cwd = root;
        t.no_machine();
        let err = t.sbt_err(&["create", "--clone", "claude", "."]);
        assert!(
            err.contains("already has a remote 'sandbox-claude-repo'"),
            "{err}"
        );
        assert!(no_machine_created(&t));
    }

    #[test]
    fn clone_create_still_works_when_a_remote_url_has_a_token() {
        // The credential warning goes to stderr (see clone::userinfo_remotes' own test); it must
        // not stop the create.
        let mut t = test_env(&[]);
        let (_d, root) = temp_repo();
        git(
            &root,
            &[
                "remote",
                "add",
                "origin",
                "https://u:tok@github.com/o/r.git",
            ],
        );
        t.ctx.cwd = root;
        let fake = t.runner();
        fake.ok(
            &["machine", "status"],
            &json("sbx-claude-repo", "created", "claude-repo"),
        );
        fake.once_fail(&["machine", "status"], "NOT_FOUND", "vm not found");
        t.sbt(&["create", "--clone", "claude", "."]).unwrap();
        assert!(!no_machine_created(&t));
    }

    #[test]
    fn a_failed_clone_create_removes_the_remote_only_when_no_machine_exists() {
        // machine create fails: no machine, so the remote is removed again.
        let mut t = test_env(&[]);
        let (_d, root) = temp_repo();
        t.ctx.cwd = root.clone();
        let fake = t.runner();
        fake.fail(&["machine", "status"], "NOT_FOUND", "vm not found");
        fake.fail(&["machine", "create"], "CREATE_FAILED", "no space left");
        assert!(t.sbt(&["create", "--clone", "claude", "."]).is_err());
        assert_eq!(git_config(&root, "remote.sandbox-claude-repo.url"), "");

        // Created but the start failed (e.g. the clone step): the machine exists, so the remote
        // stays for the next start's retry.
        let mut t = test_env(&[]);
        t.ctx.cwd = root.clone();
        let fake = t.runner();
        fake.ok(
            &["machine", "status"],
            &json("sbx-claude-repo", "created", "claude-repo"),
        );
        fake.once_fail(&["machine", "status"], "NOT_FOUND", "vm not found");
        fake.fail(&["machine", "start"], "START_FAILED", "boot failed");
        assert!(t.sbt(&["create", "--clone", "claude", "."]).is_err());
        assert_eq!(
            git_config(&root, "remote.sandbox-claude-repo.url"),
            "file:///sbt/claude-repo"
        );
    }

    #[test]
    fn a_failed_clone_create_keeps_a_remote_it_didnt_add() {
        // Left by an earlier `run --rm` of the same name, with the agent's fetched commits.
        let mut t = test_env(&[]);
        let (_d, root) = temp_repo();
        crate::workspace::clone::add_remote(&root, "claude-repo").unwrap();
        t.ctx.cwd = root.clone();
        let fake = t.runner();
        fake.fail(&["machine", "status"], "NOT_FOUND", "vm not found");
        fake.fail(&["machine", "create"], "CREATE_FAILED", "no space left");
        assert!(t.sbt(&["create", "--clone", "claude", "."]).is_err());
        assert_eq!(
            git_config(&root, "remote.sandbox-claude-repo.url"),
            "file:///sbt/claude-repo"
        );
    }

    #[test]
    fn create_builds_the_machine_from_the_preset() {
        let mut t = test_env(&[]);
        let fake = t.runner();
        fake.ok(
            &["machine", "status"],
            &json("sbx-claude-proj", "created", "claude-proj"),
        );
        fake.once_fail(&["machine", "status"], "NOT_FOUND", "vm not found");
        t.sbt(&[
            "create", "claude", ".", "--cpus", "2", "-m", "4g", "-e", "A=1", "-p", "8080:80",
        ])
        .unwrap();

        let ws = t.ctx.cwd.display().to_string();
        let create = t
            .ctx
            .vm
            .runner()
            .calls()
            .into_iter()
            .find(|c| c.get(1).is_some_and(|a| a == "create"))
            .unwrap();
        let pair = |flag: &str| -> Vec<String> {
            create
                .windows(2)
                .filter(|w| w[0] == flag)
                .map(|w| w[1].clone())
                .collect()
        };
        assert_eq!(pair("-n"), vec!["sbx-claude-proj"]);
        assert_eq!(
            pair("--image"),
            vec!["docker/sandbox-templates:claude-code-docker-0.10.0"]
        );
        assert_eq!(
            pair("-v"),
            vec![
                format!("{ws}:{ws}"),
                // Skills default to readonly: the store, shared read-only.
                format!(
                    "{}:/run/sbx/skills-shared:ro",
                    t.ctx.paths.skills_store().display()
                ),
                "/var/lib/docker".into(),
                "/var/lib/containerd".into()
            ]
        );
        assert_eq!(pair("--cpus"), vec!["2"]);
        assert_eq!(pair("--mem"), vec!["4096"]);
        // The user's -e first, then sbx's sandbox variables (SANDBOX_ID is a fresh UUID).
        let mut env = pair("-e");
        let id = env.remove(3);
        assert!(
            id.starts_with("SANDBOX_ID=") && id.len() == "SANDBOX_ID=".len() + 36,
            "{id}"
        );
        assert_eq!(
            env,
            vec![
                "A=1".to_string(),
                "SANDBOX_NAME=claude-proj".into(),
                "SANDBOX_VM_ID=claude-proj".into(),
                format!("WORKSPACE_DIR={ws}"),
                "SBX_AGENT=claude".into(),
                "SBX_CRED_ANTHROPIC_MODE=none".into(),
                "IS_SANDBOX=1".into(),
            ]
        );
        assert_eq!(pair("-p"), vec!["8080:80"]);
        assert!(pair("--label").contains(&"sbx.created=1000000".to_string()));
        assert!(pair("--label").contains(&"sbx.docker=true".to_string()));
        // Docker-in-sandbox is the shipped `docker` kit: its volumes above, its startup hook here.
        assert!(pair("--label").contains(&r#"sbx.kits=["builtin:docker"]"#.to_string()));
        let uploads = t.runner().uploads();
        let (_, script) = uploads
            .iter()
            .find(|(to, _)| to == "sbx-claude-proj:/etc/smolbento/startup.d/01-docker.sh")
            .expect("the docker kit's startup script");
        assert!(script.contains("exec dockerd"), "{script}");
        assert!(
            script.contains("$d sh -c ") && script.contains("fi' &\n"),
            "dockerd runs in the background: {script}"
        );
        // A host-mounted sandbox can't be forked, so it isn't started branchable.
        assert!(
            t.calls()
                .contains(&"machine start -n sbx-claude-proj".to_string())
        );
    }

    #[test]
    fn create_on_an_existing_name_fails_before_touching_the_policy() {
        let mut t = test_env(&[]);
        t.runner().ok(
            &["machine", "status"],
            &json("sbx-claude-proj", "stopped", "claude-proj"),
        );
        let before = std::fs::read_to_string(t.ctx.paths.policy_file()).unwrap();
        let err = t.sbt_err(&["create", "claude", ".", "--deny-network", "evil.com"]);
        assert!(
            err.contains("sandbox 'claude-proj' already exists"),
            "{err}"
        );
        assert_eq!(
            std::fs::read_to_string(t.ctx.paths.policy_file()).unwrap(),
            before
        );
        assert!(
            !t.calls()
                .iter()
                .any(|l| l.contains("create") || l.contains("start"))
        );
    }

    /// Fake smolvm for one create of claude-proj that succeeds.
    fn creatable(t: &TestEnv) {
        let fake = t.runner();
        fake.ok(
            &["machine", "status"],
            &json("sbx-claude-proj", "created", "claude-proj"),
        );
        fake.once_fail(&["machine", "status"], "NOT_FOUND", "vm not found");
    }

    fn global_github_secret(t: &TestEnv) {
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
    fn sandbox_rules(t: &TestEnv, name: &str) -> Vec<(String, Vec<String>)> {
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

    fn deny(resources: &[&str]) -> (String, Vec<String>) {
        (
            "deny".into(),
            resources.iter().map(|r| r.to_string()).collect(),
        )
    }

    #[test]
    fn create_deny_network_adds_sandbox_deny_rules() {
        let mut t = test_env(&[]);
        set_policy(&t, "mode = \"balanced\"\n");
        global_github_secret(&t);
        creatable(&t);
        t.sbt(&[
            "create",
            "claude",
            ".",
            "--deny-network",
            "evil.com,10.0.0.0/8",
            "--deny-network",
            "tracker.example",
        ])
        .unwrap();

        // One sandbox-scoped rule per value, as `policy deny network --sandbox` adds them.
        assert_eq!(
            sandbox_rules(&t, "claude-proj"),
            vec![
                deny(&["evil.com"]),
                deny(&["10.0.0.0/8"]),
                deny(&["tracker.example"])
            ]
        );
        let p = crate::policy::Policy::load(&t.ctx.paths).unwrap();
        assert!(p.rules.is_empty(), "nothing global: {p:?}");
        assert!(!p.sandboxes["claude-proj"].deny_network);

        let lines = t.calls();
        let create = lines
            .iter()
            .find(|l| l.starts_with("machine create"))
            .unwrap();
        assert!(create.contains(" --deny-cidr 10.0.0.0/8 "), "{create}");
        // The sandbox keeps its mode and secrets.
        assert!(
            create.contains(" --credential gh_token=GH_TOKEN@api.github.com,github.com,"),
            "{create}"
        );
        assert!(create.contains("registry.npmjs.org"), "{create}");
        assert!(!create.contains("gh-123"));
    }

    #[test]
    fn create_denies_host_loopback_unless_a_localhost_rule_applies() {
        let rule =
            "[[rules]]\nid = \"r-1\"\ndecision = \"allow\"\nresources = [\"LOCALHOST:11434\"]\n";
        for mode in ["allow-all", "balanced", "deny-all"] {
            for localhost in [false, true] {
                let mut t = test_env(&[]);
                let extra = if localhost { rule } else { "" };
                set_policy(&t, &format!("mode = \"{mode}\"\n{extra}"));
                creatable(&t);
                t.sbt(&["create", "claude", "."]).unwrap();
                let lines = t.calls();
                let create = lines
                    .iter()
                    .find(|l| l.starts_with("machine create"))
                    .unwrap();
                for cidr in ["127.0.0.0/8", "::1/128"] {
                    assert_eq!(
                        create.contains(&format!(" --deny-cidr {cidr} ")),
                        !localhost,
                        "{mode}: {create}"
                    );
                }
                assert_eq!(
                    create.contains("--label sbx.host-access=true"),
                    localhost,
                    "{mode}: {create}"
                );
                // A restricted sandbox with host access gets the gateway from the start.
                if mode != "allow-all" {
                    assert_eq!(
                        create.contains("--allow-cidr 100.96.0.1/32"),
                        localhost,
                        "{mode}: {create}"
                    );
                }
                if !localhost {
                    // Not a rule: `policy ls` doesn't show it.
                    let p = crate::policy::Policy::load(&t.ctx.paths).unwrap();
                    assert!(p.rules.is_empty(), "{mode}: {p:?}");
                    assert!(sandbox_rules(&t, "claude-proj").is_empty(), "{mode}");
                }
            }
        }
    }

    #[test]
    fn deny_network_is_checked_before_the_machine_is_created() {
        // A bad host: nothing is created and the policy is untouched.
        let mut t = test_env(&[]);
        let fake = t.runner();
        fake.fail(&["machine", "status"], "NOT_FOUND", "vm not found");
        let before = std::fs::read_to_string(t.ctx.paths.policy_file()).unwrap();
        let err = t
            .sbt(&[
                "create",
                "claude",
                ".",
                "--deny-network",
                "ok.com,10.0.0.0/33",
            ])
            .unwrap_err();
        assert!(format!("{err:#}").contains("--deny-network"), "{err:#}");
        assert_eq!(
            std::fs::read_to_string(t.ctx.paths.policy_file()).unwrap(),
            before
        );
        let lines = t.calls();
        assert!(!lines.iter().any(|l| l.contains("create")), "{lines:?}");

        // A host a secret bound at create uses: smolvm would keep it reachable.
        let mut t = test_env(&[]);
        global_github_secret(&t);
        let fake = t.runner();
        fake.fail(&["machine", "status"], "NOT_FOUND", "vm not found");
        let err = t.sbt_err(&["create", "claude", ".", "--deny-network", "github.com"]);
        assert!(
            err.contains(
                "can't deny github.com: sandbox claude-proj would be created with a github secret"
            ),
            "{err}"
        );
        assert!(sandbox_rules(&t, "claude-proj").is_empty());
        let lines = t.calls();
        assert!(!lines.iter().any(|l| l.contains("create")), "{lines:?}");
    }

    #[test]
    fn a_failed_create_removes_only_its_own_deny_rules() {
        let earlier = "mode = \"allow-all\"\n[[sandboxes.claude-proj.rules]]\nid = \"r-old\"\n\
                       decision = \"deny\"\nresources = [\"old.example\"]\n";
        let mut t = test_env(&[]);
        set_policy(&t, earlier);
        let fake = t.runner();
        fake.fail(&["machine", "status"], "NOT_FOUND", "vm not found");
        fake.fail(&["machine", "create"], "CREATE_FAILED", "no space left");
        let err = t
            .sbt(&["create", "claude", ".", "--deny-network", "evil.com"])
            .unwrap_err();
        assert!(err.to_string().contains("no space left"), "{err:#}");
        assert_eq!(
            sandbox_rules(&t, "claude-proj"),
            vec![deny(&["old.example"])]
        );

        // Nothing earlier: the sandbox's entry goes away.
        let mut t = test_env(&[]);
        let fake = t.runner();
        fake.fail(&["machine", "status"], "NOT_FOUND", "vm not found");
        fake.fail(&["machine", "create"], "CREATE_FAILED", "no space left");
        assert!(
            t.sbt(&["create", "claude", ".", "--deny-network", "evil.com"])
                .is_err()
        );
        assert!(
            crate::policy::Policy::load(&t.ctx.paths)
                .unwrap()
                .sandboxes
                .is_empty()
        );

        // Created but failed to start: the machine exists, so its rules stay.
        let mut t = test_env(&[]);
        creatable(&t);
        t.runner()
            .fail(&["machine", "start"], "START_FAILED", "boot failed");
        assert!(
            t.sbt(&["create", "claude", ".", "--deny-network", "evil.com"])
                .is_err()
        );
        assert_eq!(sandbox_rules(&t, "claude-proj"), vec![deny(&["evil.com"])]);

        // No policy chosen and no terminal: create stops before adding rules, and the rollback
        // doesn't write a policy.toml either.
        let mut t = test_env(&[]);
        std::fs::remove_file(t.ctx.paths.policy_file()).unwrap();
        let fake = t.runner();
        fake.fail(&["machine", "status"], "NOT_FOUND", "vm not found");
        assert!(
            t.sbt(&["create", "claude", ".", "--deny-network", "evil.com"])
                .is_err()
        );
        assert!(!t.ctx.paths.policy_file().exists());
    }

    #[test]
    fn create_without_path_is_mountless_and_docker_can_be_disabled() {
        let mut t = test_env(&[("SMOLBENTO_DOCKER", "false")]);
        let fake = t.runner();
        fake.ok(
            &["machine", "status"],
            &json("sbx-shell-proj", "created", "shell-proj"),
        );
        fake.once_fail(&["machine", "status"], "NOT_FOUND", "vm not found");
        t.sbt(&["create", "shell", "--cpus", "1", "-m", "1g"])
            .unwrap();
        let line = t
            .ctx
            .vm
            .runner()
            .call_lines()
            .into_iter()
            .find(|l| l.starts_with("machine create"))
            .unwrap();
        assert!(
            line.contains("--image docker/sandbox-templates:shell-0.10.0"),
            "{line}"
        );
        assert!(!line.contains(" -v "), "{line}");
        assert!(line.contains("--label sbx.docker=false"), "{line}");
        assert!(!line.contains("sbx.kits"), "no docker kit: {line}");
        assert!(
            t.calls()
                .contains(&"machine start -n sbx-shell-proj --branchable".to_string())
        );
    }

    #[test]
    fn kit_docker_adds_dockerd_to_any_template() {
        let mut t = test_env(&[]);
        let fake = t.runner();
        fake.ok(
            &["machine", "status"],
            &json("sbx-shell-proj", "created", "shell-proj"),
        );
        fake.once_fail(&["machine", "status"], "NOT_FOUND", "vm not found");
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
    fn explicit_template_is_kept_when_docker_is_disabled() {
        let t = test_env(&[("SMOLBENTO_DOCKER", "false")]);
        let Some(Cmd::Create(a)) = Cli::try_parse_from([
            "sbt",
            "create",
            "shell",
            "-t",
            "docker/sandbox-templates:shell-docker-0.10.0",
            "--cpus",
            "1",
            "-m",
            "1g",
        ])
        .unwrap()
        .command
        else {
            panic!("expected create");
        };
        let req = build_request(&t.ctx, "shell", &[], &a.opts, false).unwrap();
        assert_eq!(req.image, "docker/sandbox-templates:shell-docker-0.10.0");
        assert!(!req.docker, "docker.enabled=false still skips dockerd");
    }

    fn saved_template(t: &TestEnv, name: &str, agent: &str) -> crate::templates::Entry {
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

    #[test]
    fn a_saved_template_is_created_from_its_pack() {
        let t = test_env(&[]);
        let e = saved_template(&t, "chk-tpl:v1", "shell");
        let opts = SandboxOpts {
            template: Some("chk-tpl:v1".into()),
            pull: Some("never".into()),
            ..Default::default()
        };
        let req = build_request(&t.ctx, "shell", &[], &opts, false).unwrap();
        let pack = crate::templates::Store::new(&t.ctx.paths).pack(&e);
        assert_eq!(req.template_pack, Some(pack));
        assert_eq!(
            req.template.as_deref(),
            Some("docker.io/library/chk-tpl:v1")
        );
        assert_eq!(req.image, e.image);
        assert!(!req.docker, "the template's docker flag, not the image's");
    }

    #[test]
    fn a_template_saved_from_another_agent_is_refused() {
        let t = test_env(&[]);
        saved_template(&t, "t:v1", "shell");
        let opts = SandboxOpts {
            template: Some("t:v1".into()),
            ..Default::default()
        };
        let err = build_request(&t.ctx, "claude", &[], &opts, false)
            .unwrap_err()
            .to_string();
        assert_eq!(
            err,
            "template docker.io/library/t:v1 was saved from a shell sandbox; run it with shell"
        );
    }

    #[test]
    fn pull_never_needs_a_saved_template() {
        let t = test_env(&[]);
        let opts = SandboxOpts {
            template: Some("alpine".into()),
            pull: Some("never".into()),
            ..Default::default()
        };
        let err = build_request(&t.ctx, "shell", &[], &opts, false).unwrap_err();
        assert_eq!(
            err.to_string(),
            "--pull never works only with a saved template (see `sbt template ls`); smolvm pulls missing images"
        );
        assert_eq!(crate::cli::exit_code(&err), 2);
    }

    #[test]
    fn an_unsaved_template_is_still_an_image() {
        let t = test_env(&[]);
        let opts = SandboxOpts {
            template: Some("alpine".into()),
            ..Default::default()
        };
        let req = build_request(&t.ctx, "shell", &[], &opts, false).unwrap();
        assert_eq!(
            (req.image.as_str(), req.template_pack.is_none()),
            ("alpine", true)
        );
    }

    #[test]
    fn create_from_a_saved_template_passes_from_and_the_label() {
        let mut t = test_env(&[]);
        let e = saved_template(&t, "chk-tpl:v1", "shell");
        let fake = t.runner();
        fake.ok(&["machine", "status"], &json("sbx-bb", "created", "bb"));
        fake.once_fail(&["machine", "status"], "NOT_FOUND", "vm not found");
        t.sbt(&["create", "shell", "-t", "chk-tpl:v1", "--name", "bb"])
            .unwrap();
        let create = t
            .ctx
            .vm
            .runner()
            .call_lines()
            .into_iter()
            .find(|l| l.contains("machine create"))
            .unwrap();
        let pack = crate::templates::Store::new(&t.ctx.paths).pack(&e);
        assert!(
            create.contains(&format!("--from {}", pack.display())),
            "{create}"
        );
        assert!(
            create.contains("--label sbx.template=docker.io/library/chk-tpl:v1"),
            "{create}"
        );
        assert!(!create.contains("--image"), "{create}");
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
    fn a_templates_docker_flag_follows_docker_enabled() {
        for (enabled, want) in [("false", false), ("true", true)] {
            let t = test_env(&[("SMOLBENTO_DOCKER", enabled)]);
            let src = t.ctx.cwd.join("p.smolmachine");
            std::fs::write(&src, "packed").unwrap();
            let r = crate::templates::TemplateRef::parse("d:v1").unwrap();
            crate::templates::Store::new(&t.ctx.paths)
                .add(
                    crate::templates::Entry {
                        repository: r.repository,
                        tag: r.tag,
                        agent: "shell".into(),
                        image: "img:1".into(),
                        docker: true,
                        created_at: "1970-01-12T13:46:30Z".into(),
                        ..Default::default()
                    },
                    &src,
                )
                .unwrap();
            let opts = SandboxOpts {
                template: Some("d:v1".into()),
                ..Default::default()
            };
            let req = build_request(&t.ctx, "shell", &[], &opts, false).unwrap();
            assert_eq!(req.docker, want, "docker.enabled={enabled}");
        }
    }

    #[test]
    fn create_rejects_unknown_agents_and_bad_names() {
        let mut t = test_env(&[]);
        assert!(
            t.sbt_err(&["create", "nope"])
                .contains("unknown agent \"nope\"")
        );
        // Exact sbx text; a bare word with a tag is still an agent name.
        // A dotted bare word is a name too; only `.`, `..` and paths are kit refs.
        for w in ["alpine", "alpine:3", ".hidden", "...", ".kit.yaml"] {
            assert_eq!(t.sbt_err(&["create", w]), format!("unknown agent \"{w}\""));
        }
        assert!(
            t.sbt_err(&["create", "claude", "--name", "a_b"])
                .contains("'_'")
        );
    }

    #[test]
    fn create_without_kits_prints_no_kits_or_kit_steps() {
        let mut t = test_env(&[("SMOLBENTO_DOCKER", "false")]);
        let fake = t.runner();
        fake.ok(
            &["machine", "status"],
            &json("sbx-shell-proj", "created", "shell-proj"),
        );
        fake.once_fail(&["machine", "status"], "NOT_FOUND", "vm not found");
        t.sbt(&[
            "create",
            "--name",
            "shell-proj",
            "shell",
            "--cpus",
            "3",
            "-m",
            "1536m",
        ])
        .unwrap();
        assert_eq!(
            t.stdout(),
            "
SANDBOX
  Name:       shell-proj
  Agent:      shell
  Workspace:  -
  Image:      docker/sandbox-templates:shell-0.10.0
  CPU:        3
  Memory:     1536 MiB

IMAGE
  ○ image — preparing…
  ✓ image — ready

SETUP
  ○ sandbox — starting…
  ✓ sandbox — started

  ✓ Created sandbox shell-proj
        try: sbt run --name shell-proj
"
        );
    }

    #[test]
    fn create_shows_clone_and_read_only_workspaces() {
        let mut t = test_env(&[]);
        let fake = t.runner();
        fake.ok(
            &["machine", "status"],
            &json("sbx-claude-proj", "created", "claude-proj"),
        );
        fake.once_fail(&["machine", "status"], "NOT_FOUND", "vm not found");
        let docs = t.ctx.cwd.join("docs");
        std::fs::create_dir(&docs).unwrap();
        t.sbt(&["create", "claude", ".", "docs:ro"]).unwrap();
        let ws = t.ctx.cwd.display().to_string();
        let out = t.stdout();
        assert!(
            out.contains(&format!("  Workspace:  {ws} (rw), {ws}/docs (ro)\n")),
            "{out}"
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

    #[test]
    fn create_no_progress_prints_nothing() {
        let mut t = test_env(&[]);
        creatable(&t);
        t.sbt(&["create", "claude", ".", "--no-progress"]).unwrap();
        assert_eq!(t.stdout(), "");
    }

    #[test]
    fn a_failed_image_pull_fails_its_step() {
        let mut t = test_env(&[]);
        creatable(&t);
        t.runner()
            .fail(&["machine", "start"], "PULL_FAILED", "no such image");
        t.sbt(&["create", "claude", "."]).unwrap_err();
        let out = t.stdout();
        assert!(
            out.ends_with("\nIMAGE\n  ○ image — preparing…\n  ✗ image — failed\n"),
            "{out}"
        );
    }

    #[test]
    fn stop_and_start() {
        let mut t = test_env(&[]);
        t.runner().ok(
            &["machine", "status"],
            &json("sbx-claude-proj", "running", "claude-proj"),
        );
        t.sbt(&["stop", "claude-proj"]).unwrap();
        assert!(
            t.calls()
                .contains(&"machine stop -n sbx-claude-proj".to_string())
        );

        let mut t = test_env(&[]);
        t.runner().ok(
            &["machine", "status"],
            &json("sbx-claude-proj", "stopped", "claude-proj"),
        );
        t.stdout();
        t.sbt(&["start", "claude-proj"]).unwrap();
        assert!(
            t.calls()
                .contains(&"machine start -n sbx-claude-proj --branchable".to_string())
        );
        assert_eq!(
            t.stdout(),
            "  ○ claude-proj — starting…\n  ✓ Started claude-proj\n"
        );
    }

    #[test]
    fn a_failed_start_fails_its_step() {
        let mut t = test_env(&[]);
        let fake = t.runner();
        fake.ok(
            &["machine", "status"],
            &json("sbx-claude-proj", "stopped", "claude-proj"),
        );
        fake.fail(&["machine", "start"], "BOOT_FAILED", "no hypervisor");
        let err = t.sbt(&["start", "claude-proj"]).unwrap_err();
        assert!(format!("{err:#}").contains("no hypervisor"), "{err:#}");
        assert_eq!(
            t.stdout(),
            "  ○ claude-proj — starting…\n  ✗ claude-proj — failed\n"
        );
    }

    #[test]
    fn start_needs_a_policy() {
        let mut t = test_env(&[]);
        set_policy(&t, "");
        t.runner().ok(
            &["machine", "status"],
            &json("sbx-claude-proj", "stopped", "claude-proj"),
        );
        let err = t.sbt_err(&["start", "claude-proj"]);
        assert!(
            err.contains("no network policy chosen yet; run `sbt policy init"),
            "{err}"
        );
        let started = |t: &TestEnv| {
            t.calls()
                .into_iter()
                .any(|l| l.starts_with("machine update") || l.starts_with("machine start"))
        };
        assert!(!started(&t));
        t.sbt(&["policy", "init", "balanced"]).unwrap();
        t.sbt(&["start", "claude-proj"]).unwrap();
        assert!(started(&t));
    }

    fn clone_json(name: &str, state: &str, repo: &std::path::Path) -> String {
        machine_json(
            &format!("sbx-{name}"),
            state,
            &[
                ("sbx.name", name),
                ("sbx.created", "999000"),
                ("sbx.clone", "true"),
                ("sbx.workspace", &repo.display().to_string()),
            ],
        )
    }

    /// Fakes `machine ls --json` for the one sandbox a test `rm`s by name.
    fn ls_one(t: &TestEnv, json: &str) {
        t.runner()
            .ok(&["machine", "ls", "--json"], &format!("[{json}]"));
    }

    fn remote(repo: &std::path::Path, name: &str) -> String {
        git_config(repo, &format!("remote.sandbox-{name}.url"))
    }

    #[test]
    fn rm_prune_and_reset_remove_our_remote_but_keep_foreign_ones() {
        for cmd in [
            vec!["rm", "-f", "box"],
            vec!["prune", "-f"],
            vec!["reset", "-f"],
        ] {
            let mut t = test_env(&[]);
            let (_d, repo) = temp_repo();
            crate::workspace::clone::add_remote(&repo, "box").unwrap();
            git(
                &repo,
                &[
                    "remote",
                    "add",
                    "sandbox-other",
                    "https://example.com/x.git",
                ],
            );
            let fake = t.runner();
            fake.ok(&["machine", "status"], &clone_json("box", "stopped", &repo));
            fake.ok(
                &["machine", "ls", "--json"],
                &format!("[{}]", clone_json("box", "stopped", &repo)),
            );
            assert!(!remote(&repo, "box").is_empty());
            t.sbt(&cmd).unwrap();
            assert_eq!(remote(&repo, "box"), "", "{cmd:?}");
            assert!(!remote(&repo, "other").is_empty(), "{cmd:?}");
        }
    }

    #[test]
    fn rm_keeps_a_foreign_remote_of_the_same_name() {
        let mut t = test_env(&[]);
        let (_d, repo) = temp_repo();
        git(
            &repo,
            &["remote", "add", "sandbox-box", "https://example.com/x.git"],
        );
        t.runner()
            .ok(&["machine", "status"], &clone_json("box", "stopped", &repo));
        ls_one(&t, &clone_json("box", "stopped", &repo));
        t.sbt(&["rm", "-f", "box"]).unwrap();
        assert!(!remote(&repo, "box").is_empty());
    }

    #[test]
    fn rm_succeeds_when_the_clone_workspace_is_gone() {
        let mut t = test_env(&[]);
        let gone = t.ctx.cwd.join("deleted");
        t.runner()
            .ok(&["machine", "status"], &clone_json("box", "stopped", &gone));
        ls_one(&t, &clone_json("box", "stopped", &gone));
        t.sbt(&["rm", "-f", "box"]).unwrap();
    }

    #[test]
    fn rm_removes_the_remote_from_the_repo_top_when_the_subdirectory_is_gone() {
        let mut t = test_env(&[]);
        let (_d, repo) = temp_repo();
        crate::workspace::clone::add_remote(&repo, "box").unwrap();
        let sub = repo.join("deleted").display().to_string();
        let box_json = machine_json(
            "sbx-box",
            "stopped",
            &[
                ("sbx.name", "box"),
                ("sbx.clone", "true"),
                ("sbx.workspace", &sub),
                ("sbx.clone-top", &repo.display().to_string()),
            ],
        );
        t.runner().ok(&["machine", "status"], &box_json);
        ls_one(&t, &box_json);
        t.sbt(&["rm", "-f", "box"]).unwrap();
        assert_eq!(remote(&repo, "box"), "");
    }

    #[test]
    fn rm_needs_force_without_a_terminal() {
        let mut t = test_env(&[]);
        t.runner().ok(
            &["machine", "status"],
            &json("sbx-claude-proj", "running", "claude-proj"),
        );
        ls_one(&t, &json("sbx-claude-proj", "running", "claude-proj"));
        assert!(t.sbt_err(&["rm", "claude-proj"]).contains("pass -f"));
        t.sbt(&["rm", "-f", "claude-proj"]).unwrap();
        assert!(
            t.calls()
                .contains(&"machine delete -n sbx-claude-proj -f".to_string())
        );
    }

    #[test]
    fn rm_asks_on_a_terminal_and_removes_only_on_yes() {
        let mut t = test_env(&[]);
        t.ctx.vm.runner().ok(
            &["machine", "status"],
            &json("sbx-claude-proj", "running", "claude-proj"),
        );
        ls_one(&t, &json("sbx-claude-proj", "running", "claude-proj"));
        let deleted = |t: &TestEnv| {
            t.ctx
                .vm
                .runner()
                .call_lines()
                .iter()
                .any(|l| l.starts_with("machine delete"))
        };
        t.answer("n\n");
        let e = sbt(&mut t.ctx, &["rm", "claude-proj"]).unwrap_err();
        assert_eq!(e.to_string(), "aborted");
        assert_eq!(t.stdout(), "Remove claude-proj? [y/N] ");
        assert!(!deleted(&t));
        t.answer("y\n");
        sbt(&mut t.ctx, &["rm", "claude-proj"]).unwrap();
        assert!(deleted(&t));
    }

    #[test]
    fn prune_removes_only_old_stopped_sandboxes() {
        let mut t = test_env(&[]);
        let ls = format!(
            "[{},{},{}]",
            json("sbx-old", "stopped", "old"),
            json("sbx-live", "running", "live"),
            machine_json(
                "sbx-new",
                "stopped",
                &[("sbx.name", "new"), ("sbx.created", "999990")]
            )
        );
        t.runner().ok(&["machine", "ls", "--json"], &ls);
        t.runner().ok(
            &["machine", "status", "-n", "sbx-live"],
            &json("sbx-live", "running", "live"),
        );
        t.sbt(&["prune", "-f", "--filter", "until=1m"]).unwrap();
        let deletes: Vec<String> = t
            .ctx
            .vm
            .runner()
            .call_lines()
            .into_iter()
            .filter(|l| l.contains("delete"))
            .collect();
        assert_eq!(deletes, vec!["machine delete -n sbx-old -f"]);
    }

    #[test]
    fn reset_deletes_everything() {
        let mut t = test_env(&[]);
        let ls = format!(
            "[{},{}]",
            json("sbx-a1", "stopped", "a1"),
            json("sbx-b1", "stopped", "b1")
        );
        t.runner().ok(&["machine", "ls", "--json"], &ls);
        t.sbt(&["reset", "-f"]).unwrap();
        let deletes = t
            .ctx
            .vm
            .runner()
            .call_lines()
            .into_iter()
            .filter(|l| l.contains("delete"))
            .count();
        assert_eq!(deletes, 2);
    }

    #[test]
    fn reset_preserve_secrets_keeps_sandbox_scoped_secrets() {
        use crate::policy::Policy;
        use crate::secrets::{SecretEntry, SecretsFile, Source, scope_for};

        let mut t = test_env(&[]);
        let entry = SecretEntry {
            service: "github".into(),
            scope: scope_for(Some("a1")),
            source: Source::Keychain,
        };
        t.ctx.store.set(&entry.account(), "gh-123").unwrap();
        let mut f = SecretsFile::default();
        f.set(entry.clone());
        f.save(&t.ctx.paths).unwrap();
        set_policy(
            &t,
            "mode = \"balanced\"\n[[sandboxes.a1.rules]]\nid = \"r-1\"\ndecision = \"allow\"\n\
             resources = [\"a.com\"]\n",
        );
        t.runner().ok(
            &["machine", "ls", "--json"],
            &format!("[{}]", json("sbx-a1", "stopped", "a1")),
        );
        t.sbt(&["reset", "-f", "--preserve-secrets"]).unwrap();
        let f = SecretsFile::load(&t.ctx.paths).unwrap();
        assert_eq!(f.secrets, vec![entry.clone()]);
        assert_eq!(
            t.ctx.store.get(&entry.account()).unwrap().as_deref(),
            Some("gh-123")
        );
        assert!(Policy::load(&t.ctx.paths).unwrap().sandboxes.is_empty());
    }

    fn fork_json(name: &str, state: &str, parent: Option<&str>) -> String {
        let mut l = labels(name);
        if let Some(p) = parent {
            l.push(("sbx.fork-of", p.to_string()));
        }
        let pairs: Vec<(&str, &str)> = l.iter().map(|(k, v)| (*k, v.as_str())).collect();
        machine_json(&format!("sbx-{name}"), state, &pairs)
    }

    /// `a` with forks `a-fork-1` and `a-fork-2`, in the given states.
    fn with_forks(t: &TestEnv, a: &str, f1: &str, f2: &str) {
        let (ja, j1, j2) = (
            fork_json("a", a, None),
            fork_json("a-fork-1", f1, Some("a")),
            fork_json("a-fork-2", f2, Some("a")),
        );
        let fake = t.runner();
        fake.ok(&["machine", "ls", "--json"], &format!("[{ja},{j1},{j2}]"));
        fake.ok(&["machine", "status", "-n", "sbx-a"], &ja);
        fake.ok(&["machine", "status", "-n", "sbx-a-fork-1"], &j1);
        fake.ok(&["machine", "status", "-n", "sbx-a-fork-2"], &j2);
    }

    fn deletes(t: &TestEnv) -> Vec<String> {
        t.calls()
            .into_iter()
            .filter(|l| l.contains("machine delete"))
            .map(|l| l.replace("machine delete -n sbx-", "").replace(" -f", ""))
            .collect()
    }

    #[test]
    fn rm_refuses_a_parent_that_still_has_forks() {
        let mut t = test_env(&[]);
        with_forks(&t, "stopped", "stopped", "stopped");
        let err = t.sbt_err(&["rm", "-f", "a"]);
        assert!(
            err.contains("remove its forks first: a-fork-1, a-fork-2"),
            "{err}"
        );
        assert!(deletes(&t).is_empty());
    }

    #[test]
    fn rm_deletes_forks_named_in_the_same_call_before_the_parent() {
        let mut t = test_env(&[]);
        with_forks(&t, "stopped", "stopped", "stopped");
        t.sbt(&["rm", "-f", "a", "a-fork-1", "a-fork-2"]).unwrap();
        assert_eq!(deletes(&t), vec!["a-fork-1", "a-fork-2", "a"]);
        // Named targets come from the one list, not a status call each.
        let calls = t.calls();
        assert!(
            calls.iter().all(|c| !c.starts_with("machine status")),
            "{calls:?}"
        );
    }

    #[test]
    fn rm_of_a_missing_sandbox_deletes_nothing() {
        let mut t = test_env(&[]);
        with_forks(&t, "stopped", "stopped", "stopped");
        let err = t.sbt(&["rm", "-f", "a-fork-1", "nope"]).unwrap_err();
        assert_eq!(err.to_string(), "sandbox 'nope' not found (see `sbt ls`)");
        assert!(deletes(&t).is_empty());
    }

    #[test]
    fn rm_all_deletes_forks_before_parents_and_lists_once() {
        let mut t = test_env(&[]);
        with_forks(&t, "stopped", "stopped", "stopped");
        t.sbt(&["rm", "-f", "--all"]).unwrap();
        assert_eq!(deletes(&t), vec!["a-fork-1", "a-fork-2", "a"]);
        let lists = t
            .ctx
            .vm
            .runner()
            .call_lines()
            .iter()
            .filter(|c| c.starts_with("machine ls"))
            .count();
        assert_eq!(lists, 1);
    }

    #[test]
    fn prune_skips_a_parent_whose_fork_is_running() {
        let mut t = test_env(&[]);
        with_forks(&t, "stopped", "running", "stopped");
        t.sbt(&["prune", "-f"]).unwrap();
        assert_eq!(deletes(&t), vec!["a-fork-2"]);

        let mut t = test_env(&[]);
        with_forks(&t, "stopped", "stopped", "stopped");
        t.sbt(&["prune", "-f"]).unwrap();
        assert_eq!(deletes(&t), vec!["a-fork-1", "a-fork-2", "a"]);
    }

    #[test]
    fn prune_says_which_parents_it_skipped() {
        let mut t = test_env(&[]);
        with_forks(&t, "stopped", "running", "stopped");
        t.sbt(&["prune", "-f"]).unwrap();
        // remove() reports through the same sink, after the skips.
        assert_eq!(t.stdout(), "a has forks; skipped\nRemoved a-fork-2\n");
    }

    #[test]
    fn prune_until_keeps_a_new_fork_of_an_old_parent() {
        let mut t = test_env(&[]);
        let parent = fork_json("a", "stopped", None);
        // `fork` labels the copy with its own creation time (now), not the parent's.
        let fork = machine_json(
            "sbx-a-fork-1",
            "stopped",
            &[
                ("sbx.name", "a-fork-1"),
                ("sbx.created", "1000000"),
                ("sbx.fork-of", "a"),
            ],
        );
        let fake = t.runner();
        fake.ok(&["machine", "ls", "--json"], &format!("[{parent},{fork}]"));
        fake.ok(&["machine", "status", "-n", "sbx-a"], &parent);
        fake.ok(&["machine", "status", "-n", "sbx-a-fork-1"], &fork);
        t.sbt(&["prune", "-f", "--filter", "until=1m"]).unwrap();
        assert!(deletes(&t).is_empty(), "{:?}", deletes(&t));
    }

    #[test]
    fn reset_deletes_forks_before_parents() {
        let mut t = test_env(&[]);
        with_forks(&t, "stopped", "stopped", "stopped");
        t.sbt(&["reset", "-f"]).unwrap();
        assert_eq!(deletes(&t), vec!["a-fork-1", "a-fork-2", "a"]);
    }

    #[test]
    fn reset_removes_the_skills_store() {
        let mut t = test_env(&[]);
        t.runner().ok(&["machine", "ls", "--json"], "[]");
        let store = t.ctx.paths.skills_store();
        std::fs::create_dir_all(store.join("a")).unwrap();
        std::fs::create_dir_all(t.ctx.paths.skills_metadata()).unwrap();
        t.sbt(&["reset", "-f"]).unwrap();
        assert!(!store.exists() && !t.ctx.paths.skills_metadata().exists());
    }

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
            let fake = t.runner();
            fake.ok(
                &["machine", "status"],
                &json("sbx-shell-proj", "created", "shell-proj"),
            );
            fake.once_fail(&["machine", "status"], "NOT_FOUND", "vm not found");
            let a = super::CreateArgs {
                targets: vec!["shell".into(), ".".into()],
                opts: super::SandboxOpts {
                    kit: vec![kit.clone()],
                    kit_arg: flags.iter().map(|s| s.to_string()).collect(),
                    kit_pins: vec![(kit.clone(), vec!["mode=pinned".into()])],
                    ..Default::default()
                },
                no_progress: false,
            };
            super::create(&mut t.ctx, &a).unwrap();
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
        let fake = t.runner();
        fake.ok(
            &["machine", "status"],
            &json("sbx-wl-proj", "created", "wl-proj"),
        );
        fake.once_fail(&["machine", "status"], "NOT_FOUND", "vm not found");
        let a = super::CreateArgs {
            targets: vec![kit.clone(), ".".into()],
            opts: super::SandboxOpts {
                kit_pins: vec![(kit.clone(), vec!["mode=pinned".into()])],
                ..Default::default()
            },
            no_progress: false,
        };
        super::create(&mut t.ctx, &a).unwrap();
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
        let fake = t.runner();
        fake.ok(
            &["machine", "status"],
            &json("sbx-shell-proj", "created", "shell-proj"),
        );
        fake.once_fail(&["machine", "status"], "NOT_FOUND", "vm not found");
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
        let fake = t.runner();
        fake.ok(
            &["machine", "status"],
            &json("sbx-shell-proj", "created", "shell-proj"),
        );
        fake.once_fail(&["machine", "status"], "NOT_FOUND", "vm not found");
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
        let fake = t.runner();
        fake.ok(
            &["machine", "status"],
            &json("sbx-toolbox-proj", "created", "toolbox-proj"),
        );
        fake.once_fail(&["machine", "status"], "NOT_FOUND", "vm not found");
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
        let fake = t.runner();
        fake.ok(
            &["machine", "status"],
            &json("sbx-claude-proj", "created", "claude-proj"),
        );
        fake.once_fail(&["machine", "status"], "NOT_FOUND", "vm not found");
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
        let fake = t.runner();
        fake.ok(
            &["machine", "status"],
            &json("sbx-bare-proj", "created", "bare-proj"),
        );
        fake.once_fail(&["machine", "status"], "NOT_FOUND", "vm not found");
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
        let fake = t.runner();
        fake.ok(
            &["machine", "status"],
            &json("sbx-shell-proj", "created", "shell-proj"),
        );
        fake.once_fail(&["machine", "status"], "NOT_FOUND", "vm not found");
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
        crate::cli::plan::prepare_create(&t.ctx, &mut req, &[], plan.as_ref()).unwrap();
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
        let err = crate::cli::plan::prepare_create(&t.ctx, &mut req, &[], plan.as_ref())
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
        crate::cli::plan::prepare_create(&t.ctx, &mut req, &[], plan.as_ref()).unwrap();
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
        let err = crate::cli::plan::prepare_create(&t.ctx, &mut req, &[], plan.as_ref())
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
            let r = crate::cli::plan::prepare_create(&t.ctx, &mut req, &[], plan.as_ref());
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
            let r = crate::cli::plan::prepare_create(&t.ctx, &mut req, &[], plan.as_ref());
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

    /// `kit_target` and a quiet `kit_plan` for `args` followed by `kit`.
    #[test]
    fn a_kit_providing_docker_replaces_the_shipped_one() {
        use super::needs_docker_kit;
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
        let fake = t.runner();
        fake.ok(
            &["machine", "status"],
            &json("sbx-shell-proj", "created", "shell-proj"),
        );
        fake.once_fail(&["machine", "status"], "NOT_FOUND", "vm not found");
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
            assert!(no_machine_create(&t), "{flags:?}");
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
        assert!(no_machine_create(&t));
        assert!(!t.ctx.paths.kit_host_mounts().exists());
    }

    fn no_machine_create(t: &TestEnv) -> bool {
        !t.calls().iter().any(|l| l.starts_with("machine create"))
    }
}
