//! create, start, stop, rm, prune and reset.

use std::io::Write;
use std::path::Path;
use std::time::UNIX_EPOCH;

use anyhow::{Context, Result, bail};

use super::progress::{CreateSteps, Progress};
use super::request::{
    Workload, check_kit_args, kit_plan, kit_target, resolve_clone, settle_default_name,
};
use super::{CreateArgs, Ctx, OutputArgs, PruneArgs, ResetArgs, RmArgs, SandboxOpts, confirm};
use crate::provision;
use crate::sandbox::{self, CreateRequest, Event, Sandbox, session};
use crate::smolvm::Runner;
use crate::workspace::clone;

pub fn create<R: Runner>(ctx: &mut Ctx<R>, a: &CreateArgs) -> Result<i32> {
    check_kit_args(&a.targets, &a.opts)?;
    let (mut req, workload) = kit_target(ctx, &a.targets, &a.opts, false)?;
    settle_default_name(ctx, &mut req, &a.opts, false)?;
    let p = Progress::for_ctx(ctx, a.no_progress);
    let sb = create_reported(ctx, &p, &mut req, workload, &a.opts)?;
    p.finish(&format!("Created sandbox {}", sb.name()));
    p.hint(&format!("bento run --name {}", sb.name()));
    Ok(0)
}

/// Creates the sandbox `kit_target` described, reporting it to `p`: the `SANDBOX` section, then
/// the `KITS`, `IMAGE` and `SETUP` steps. The caller prints the finish line. A taken name fails
/// before anything is printed or any kit is fetched.
pub(crate) fn create_reported<R: Runner>(
    ctx: &Ctx<R>,
    p: &Progress,
    req: &mut CreateRequest,
    workload: Workload,
    opts: &SandboxOpts,
) -> Result<Sandbox> {
    resolve_clone(req, opts)?;
    provision::check_free(ctx, &req.name)?;
    // A bad `--static-mcp` fails here, not after the kits were fetched and built.
    // A built-in agent, not a kit named like one, gets its MCP config written.
    let agent = match &workload {
        Workload::Agent { .. } => true,
        Workload::Template(e) => e.is_agent_template(&ctx.env),
        Workload::Ref(_) => false,
    };
    provision::mcp_attachment(ctx, req, agent)?;
    report_sandbox(p, req, &workload, opts.clone);
    let kits = Some(kit_plan(ctx, req, workload, opts, p)?);
    let mut steps = CreateSteps::new(p);
    let created = provision::create_with(
        ctx,
        req,
        &opts.deny_network,
        kits.as_ref(),
        None,
        &mut |e| steps.on(e),
    );
    steps.end(created.is_ok());
    created
}

/// The `SANDBOX` section, before any kit loads: a workload kit's image is known only once it
/// has, and CPU and memory are what smolbento passes unless a kit's resources change them.
fn report_sandbox(p: &Progress, req: &CreateRequest, workload: &Workload, clone: bool) {
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
        Workload::Ref(r) | Workload::Agent { reference: r, .. } => format!("from {r}"),
        Workload::Template(_) => req.image.clone(),
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
    provision::sweep_orphans(ctx);
    for n in names {
        let sb = sandbox::get(&ctx.vm, n)?;
        provision::refresh_services(ctx, &sb);
        if sb.is_running() {
            writeln!(&ctx.out, "{n} is already running")?;
            continue;
        }
        let start_plan = provision::start_plan(ctx, &sb.meta)?;
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

pub fn stop<R: Runner>(ctx: &mut Ctx<R>, names: &[String], output: &OutputArgs) -> Result<i32> {
    let mut report = Report::new(output);
    let result = names.iter().try_for_each(|n| {
        let sb = sandbox::get(&ctx.vm, n)?;
        stop_quietly(ctx, &sb)?;
        report.did(ctx, "Stopped", sb.name())
    });
    report.finish(ctx, result)?;
    Ok(0)
}

/// What a command did to sandboxes: a line each as it goes (`Stopped a`), or with `--json` or
/// `--format`, sbx's list of `{action, resource, name}` at the end.
struct Report<'a> {
    output: &'a OutputArgs,
    done: Vec<Done>,
}

/// In sbx's key order.
#[derive(serde::Serialize)]
struct Done {
    action: String,
    resource: &'static str,
    name: String,
}

/// `prune --dry-run --json`, in sbx's shape: its `would_remove` and `skipped_unknown_stop`
/// (always empty: smolvm always knows a machine's state), then smolbento's leftover units.
#[derive(serde::Serialize)]
struct DryRun<'a> {
    would_remove: Vec<WouldRemove>,
    skipped_unknown_stop: [(); 0],
    host_services: &'a [String],
}

/// sbx's keys, less `stopped_at`, which smolvm doesn't record.
#[derive(serde::Serialize)]
struct WouldRemove {
    name: String,
    agent: String,
    /// `HOST:GUEST[:ro]`; smolbento mounts a workspace at its host path.
    mounts: Vec<String>,
    workspaces: Vec<String>,
}

impl WouldRemove {
    fn of(sb: &Sandbox) -> Self {
        let path = |w: &String| w.strip_suffix(":ro").unwrap_or(w).to_string();
        Self {
            name: sb.name().to_string(),
            agent: sb.meta.agent.clone(),
            mounts: sb
                .meta
                .workspaces
                .iter()
                .map(|w| format!("{}:{w}", path(w)))
                .collect(),
            workspaces: sb.meta.workspaces.iter().map(path).collect(),
        }
    }
}

impl<'a> Report<'a> {
    fn new(output: &'a OutputArgs) -> Self {
        Self {
            output,
            done: Vec::new(),
        }
    }

    /// `verb` is `Stopped` or `Removed`.
    fn did<R: Runner>(&mut self, ctx: &Ctx<R>, verb: &str, name: &str) -> Result<()> {
        if !self.output.is_table() {
            self.done.push(Done {
                action: verb.to_lowercase(),
                resource: "sandbox",
                name: name.to_string(),
            });
        } else {
            writeln!(&ctx.out, "{verb} sandbox {name}")?;
        }
        Ok(())
    }

    /// Prints the list (structured output only), also when the command failed partway: what it
    /// did before failing is done. Then passes `result` on.
    fn finish<R: Runner>(self, ctx: &Ctx<R>, result: Result<()>) -> Result<()> {
        if let Some(text) = self.output.structured(&self.done)? {
            write!(&ctx.out, "{text}")?;
        }
        result
    }
}

/// Stops `sb` if it's running and forgets its sessions.
pub(crate) fn stop_sandbox<R: Runner>(ctx: &Ctx<R>, sb: &Sandbox) -> Result<()> {
    stop_quietly(ctx, sb)?;
    writeln!(&ctx.out, "Stopped sandbox {}", sb.name())?;
    Ok(())
}

fn stop_quietly<R: Runner>(ctx: &Ctx<R>, sb: &Sandbox) -> Result<()> {
    if sb.is_running() {
        ctx.vm.stop(&sb.machine)?;
    }
    session::clear(&ctx.paths.sessions(), sb.name());
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
    // The units serving its sockets go with it.
    if let Err(e) = ctx.services.remove(sb.name()) {
        crate::warning!("removing the host services of {}: {e:#}", sb.name());
    }
    session::clear(&ctx.paths.sessions(), sb.name());
    super::secret::forget_sandbox(ctx, sb.name(), forget_secrets)
}

fn remove<R: Runner>(ctx: &Ctx<R>, sb: &Sandbox, forget_secrets: bool) -> Result<()> {
    delete_sandbox(ctx, sb, forget_secrets)?;
    writeln!(&ctx.out, "Removed sandbox {}", sb.name())?;
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
    // First, so it happens even when a name isn't found: that is how leftovers of a sandbox
    // deleted with `smolvm machine delete` get cleaned by naming it.
    provision::sweep_orphans(ctx);
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
    let mut report = Report::new(&a.output);
    if targets.is_empty() {
        if a.output.is_table() {
            writeln!(&ctx.out, "No sandboxes found")?;
        }
        report.finish(ctx, Ok(()))?;
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
    let result = forks_first(targets).into_iter().try_for_each(|sb| {
        delete_sandbox(ctx, sb, true)?;
        report.did(ctx, "Removed", sb.name())
    });
    report.finish(ctx, result)?;
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
    let targets = forks_first(targets);
    // Units of sandboxes deleted with `smolvm machine delete`: leftovers, not sandboxes.
    let orphans = provision::orphan_services(ctx);
    // --json and --format describe the dry-run listing only, and print nothing else.
    if !a.output.is_table() {
        if !a.dry_run {
            bail!(
                "--format describes the --dry-run listing; pass --dry-run to preview removals, \
                 or run the prune without --format\n  try: bento prune --dry-run --format json"
            );
        }
        let doc = DryRun {
            would_remove: targets.iter().map(|sb| WouldRemove::of(sb)).collect(),
            skipped_unknown_stop: [],
            host_services: &orphans,
        };
        write!(
            &ctx.out,
            "{}",
            a.output.structured(&doc)?.unwrap_or_default()
        )?;
        return Ok(0);
    }
    for sb in &skipped {
        writeln!(&ctx.out, "{} has forks; skipped", sb.name())?;
    }
    if targets.is_empty() && orphans.is_empty() {
        writeln!(&ctx.out, "Nothing to prune")?;
        return Ok(0);
    }
    if a.dry_run {
        for sb in &targets {
            writeln!(&ctx.out, "Would remove {}", sb.name())?;
        }
        for name in &orphans {
            writeln!(&ctx.out, "Would remove {name} (leftover host services)")?;
        }
        return Ok(0);
    }
    if !targets.is_empty() {
        confirm(
            ctx,
            &format!("Remove {} stopped sandbox(es)?", targets.len()),
            a.force,
        )?;
        for sb in &targets {
            remove(ctx, sb, true)?;
        }
    }
    for name in provision::sweep_orphans(ctx) {
        writeln!(&ctx.out, "Removed {name} (leftover host services)")?;
    }
    Ok(0)
}

/// Resets smolbento to a freshly installed state, as `sbx reset` does: every sandbox (smolbento's
/// own, and its leftovers in smolvm's default state), the SSH config block, background services,
/// settings, policy, templates, kits, skills and caches, stored secrets unless
/// `--preserve-secrets`, and last `~/.smolbento` (smolvm's state and the downloaded smolvm, which
/// does the deleting before that).
pub fn reset<R: Runner>(ctx: &mut Ctx<R>, a: &ResetArgs) -> Result<i32> {
    // A home the user chose may hold their own files: only the smolvm in it goes.
    let chosen = ctx.smolvm.home != crate::smolvm::locate::default_home(&ctx.env)?;
    let home = if chosen {
        ctx.smolvm.home.join("engine")
    } else {
        ctx.smolvm.home.clone()
    };
    confirm(
        ctx,
        &format!(
            "Reset smolbento to a freshly installed state? This removes every sandbox (also \
             smolbento's in smolvm's default location), {} (smolvm's state and the downloaded \
             smolvm), settings and network policy, templates, kits and skills, the SSH config \
             block, background services, and stored secrets (unless --preserve-secrets)",
            home.display()
        ),
        a.force,
    )?;
    let all = sandbox::list(&ctx.vm)?;
    for sb in forks_first(all.iter().collect()) {
        remove(ctx, sb, !a.preserve_secrets)?;
    }
    // Sandboxes from before smolbento kept its own state; never a machine without its labels.
    // Problems there only warn: what follows still resets this installation.
    match ctx.vm.list_default_state() {
        Ok(mut machines) => {
            machines.retain(|m| m.labels.contains_key("sbx.name"));
            machines.sort_by_key(|m| !m.labels.contains_key("sbx.fork-of"));
            for m in machines {
                if let Err(e) = ctx.vm.delete_default_state(&m.name) {
                    crate::warning!(
                        "couldn't remove {} from smolvm's default location: {e:#}",
                        m.name
                    );
                }
            }
        }
        Err(e) => crate::warning!("couldn't list smolvm's default location: {e:#}"),
    }
    provision::sweep_orphans(ctx);
    if let Some(home) = ctx.env.get("HOME") {
        super::setup::remove_block(&std::path::Path::new(home).join(".ssh"))?;
    }
    let _ = std::fs::remove_dir_all(ctx.paths.sessions());
    // A store that won't go must not keep the secrets from being forgotten.
    let wiped = crate::skills::store::Store::new(&ctx.paths).wipe();
    if !a.preserve_secrets {
        super::secret::forget_all(ctx)?;
    }
    wiped?;
    let keep = if a.preserve_secrets {
        vec![ctx.paths.secrets_file(), ctx.paths.secret_values_file()]
    } else {
        Vec::new()
    };
    for dir in [&ctx.paths.cache, &ctx.paths.data, &ctx.paths.config] {
        remove_tree(dir, &keep)?;
    }
    remove_tree(&home, &[])?;
    if chosen {
        writeln!(
            &ctx.out,
            "Kept {}: it's your smolvm.home. Delete it if it holds nothing else.",
            ctx.smolvm.home.display()
        )?;
    }
    Ok(0)
}

/// Removes `dir` and everything in it but the files in `keep` (and the directories holding them).
fn remove_tree(dir: &std::path::Path, keep: &[std::path::PathBuf]) -> Result<()> {
    if !keep.iter().any(|k| k.starts_with(dir)) {
        return match std::fs::remove_dir_all(dir) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                Err(e).with_context(|| format!("removing {}", dir.display()))
            }
            _ => Ok(()),
        };
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Ok(());
    };
    for e in entries.flatten() {
        let p = e.path();
        if keep.contains(&p) {
            continue;
        }
        if p.is_dir() {
            remove_tree(&p, keep)?;
        } else {
            std::fs::remove_file(&p).with_context(|| format!("removing {}", p.display()))?;
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "lifecycle_tests.rs"]
mod tests;
