//! create, start, stop, rm, prune and reset.

use std::io::Write;
use std::path::Path;
use std::time::UNIX_EPOCH;

use anyhow::{Context, Result, bail};

use super::plan;
use super::{CreateArgs, Ctx, PruneArgs, ResetArgs, RmArgs, SandboxOpts, confirm};
use crate::agents;
use crate::kits::args::ArgValues;
use crate::kits::capability;
use crate::kits::load;
use crate::kits::model::{Content, Kind, Kit, Source};
use crate::kits::resolve::{Plan, resolve_for};
use crate::sandbox::{self, CreateRequest, Sandbox, name, options, session};
use crate::smolvm::Runner;
use crate::workspace::{Workspace, clone};

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

fn unknown_agent(name: &str) -> String {
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
        ..Default::default()
    })
}

/// `build_request` for `targets` (an agent preset or a workload kit REF, then workspace paths)
/// plus `--kit` mixins: loads and resolves the kits, without touching smolvm's machines or the
/// policy. `plan::create` applies the plan. A preset without `--kit` gives no plan, unless its
/// image gets the `docker` kit.
pub(crate) fn build_kit_request<R: Runner>(
    ctx: &Ctx<R>,
    targets: &[String],
    opts: &SandboxOpts,
    default_to_cwd: bool,
) -> Result<(CreateRequest, Option<Plan>)> {
    check_kit_args(targets, opts)?;
    let (mut req, workload) = kit_target(ctx, targets, opts, default_to_cwd)?;
    let plan = workload
        .map(|w| kit_plan(ctx, &mut req, w, opts))
        .transpose()?;
    Ok((req, plan))
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

/// The first half of `build_kit_request`: the request (so its name) and the workload. Loads
/// nothing: a workload kit's name comes from `load::kit_name`. `None` when there are no kits.
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

/// The second half of `build_kit_request`, for a sandbox about to be created: loads the workload
/// kit (filling `req`'s image) and the `--kit` mixins, and resolves them with the kit args and
/// `req`'s working directory.
pub(crate) fn kit_plan<R: Runner>(
    ctx: &Ctx<R>,
    req: &mut CreateRequest,
    workload: Workload,
    opts: &SandboxOpts,
) -> Result<Plan> {
    let workload = match workload {
        Workload::Preset(kit) => *kit,
        Workload::Ref(target) => {
            let mut kit = load::load(ctx, &target)?;
            if kit.kind == Kind::Mixin {
                bail!(
                    "{target} is a mixin; add it with --kit to an agent, e.g. sbt run shell --kit {target}"
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
    let args = ArgValues::parse(&opts.kit_args_file, &opts.kit_arg)?;
    let mut mixins = opts
        .kit
        .iter()
        .map(|r| load::load(ctx, r))
        .collect::<Result<Vec<_>>>()?;
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
    plan.warn_skipped();
    Ok(plan)
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
/// As in sbx a bare word is only an agent name, tag or not (`alpine:3`); a reference needs a `/`.
fn looks_like_kit(target: &str) -> bool {
    target.contains('/') || target.starts_with('.')
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
    let (mut req, kits) = build_kit_request(ctx, &a.targets, &a.opts, false)?;
    resolve_clone(&mut req, &a.opts)?;
    let sb = plan::create(ctx, &mut req, &a.opts.deny_network, kits.as_ref())?;
    writeln!(&ctx.out, "Created sandbox {}", sb.name())?;
    Ok(0)
}

pub fn start<R: Runner>(ctx: &mut Ctx<R>, names: &[String]) -> Result<i32> {
    for n in names {
        let sb = sandbox::get(&ctx.vm, n)?;
        if sb.is_running() {
            writeln!(&ctx.out, "{n} is already running")?;
            continue;
        }
        let start_plan = plan::start_plan(ctx, &sb.meta)?;
        sandbox::start(&ctx.vm, &sb, &start_plan)?;
        writeln!(&ctx.out, "Started {n}")?;
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
fn remove<R: Runner>(ctx: &Ctx<R>, sb: &Sandbox, forget_secrets: bool) -> Result<()> {
    ctx.vm.delete(&sb.machine)?;
    if let Some(repo) = &sb.meta.clone_repo {
        // Best effort: the host repo may be gone.
        let _ = clone::remove_remote(Path::new(repo), sb.name());
    }
    session::clear(&ctx.paths.sessions(), sb.name());
    super::secret::forget_sandbox(ctx, sb.name(), forget_secrets)?;
    writeln!(&ctx.out, "Removed {}", sb.name())?;
    Ok(())
}

/// `targets` with forks before parents, so smolvm never refuses a parent for its live forks.
fn forks_first(mut targets: Vec<&Sandbox>) -> Vec<&Sandbox> {
    targets.sort_by_key(|sb| sb.meta.fork_of.is_none());
    targets
}

/// Forks of `sb` that aren't being removed with it.
fn remaining_forks<'a>(sb: &Sandbox, all: &'a [Sandbox], removing: &[&str]) -> Vec<&'a str> {
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
        "Remove every sandbox and smolbento's session state?",
        a.force,
    )?;
    let all = sandbox::list(&ctx.vm)?;
    for sb in forks_first(all.iter().collect()) {
        remove(ctx, sb, !a.preserve_secrets)?;
    }
    let _ = std::fs::remove_dir_all(ctx.paths.sessions());
    if !a.preserve_secrets {
        super::secret::forget_all(ctx)?;
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::super::testutil::*;
    use super::super::{Cli, Cmd};
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
        let fake = t.ctx.vm.runner();
        fake.ok(
            &["machine", "status"],
            &json("sbx-claude-repo", "created", "claude-repo"),
        );
        fake.once_fail(&["machine", "status"], "NOT_FOUND", "vm not found");
        sbt(&mut t.ctx, &["create", "--clone", "claude", "."]).unwrap();
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
        !t.ctx
            .vm
            .runner()
            .call_lines()
            .iter()
            .any(|l| l.contains("machine create"))
    }

    #[test]
    fn clone_needs_a_repo_before_smolvm_is_called() {
        let mut t = test_env(&[]);
        let err = sbt(&mut t.ctx, &["create", "--clone", "claude", "."])
            .unwrap_err()
            .to_string();
        assert!(err.contains("--clone needs a git repository"), "{err}");
        assert!(no_machine_created(&t));
    }

    #[test]
    fn clone_needs_a_workspace_path_before_smolvm_is_called() {
        let mut t = test_env(&[]);
        let err = sbt(&mut t.ctx, &["create", "--clone", "claude"])
            .unwrap_err()
            .to_string();
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
        t.ctx
            .vm
            .runner()
            .fail(&["machine", "status"], "NOT_FOUND", "vm not found");
        let err = sbt(&mut t.ctx, &["create", "--clone", "claude", "."])
            .unwrap_err()
            .to_string();
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
        let fake = t.ctx.vm.runner();
        fake.ok(
            &["machine", "status"],
            &json("sbx-claude-repo", "created", "claude-repo"),
        );
        fake.once_fail(&["machine", "status"], "NOT_FOUND", "vm not found");
        sbt(&mut t.ctx, &["create", "--clone", "claude", "."]).unwrap();
        assert!(!no_machine_created(&t));
    }

    #[test]
    fn a_failed_clone_create_removes_the_remote_only_when_no_machine_exists() {
        // machine create fails: no machine, so the remote is removed again.
        let mut t = test_env(&[]);
        let (_d, root) = temp_repo();
        t.ctx.cwd = root.clone();
        let fake = t.ctx.vm.runner();
        fake.fail(&["machine", "status"], "NOT_FOUND", "vm not found");
        fake.fail(&["machine", "create"], "CREATE_FAILED", "no space left");
        assert!(sbt(&mut t.ctx, &["create", "--clone", "claude", "."]).is_err());
        assert_eq!(git_config(&root, "remote.sandbox-claude-repo.url"), "");

        // Created but the start failed (e.g. the clone step): the machine exists, so the remote
        // stays for the next start's retry.
        let mut t = test_env(&[]);
        t.ctx.cwd = root.clone();
        let fake = t.ctx.vm.runner();
        fake.ok(
            &["machine", "status"],
            &json("sbx-claude-repo", "created", "claude-repo"),
        );
        fake.once_fail(&["machine", "status"], "NOT_FOUND", "vm not found");
        fake.fail(&["machine", "start"], "START_FAILED", "boot failed");
        assert!(sbt(&mut t.ctx, &["create", "--clone", "claude", "."]).is_err());
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
        let fake = t.ctx.vm.runner();
        fake.fail(&["machine", "status"], "NOT_FOUND", "vm not found");
        fake.fail(&["machine", "create"], "CREATE_FAILED", "no space left");
        assert!(sbt(&mut t.ctx, &["create", "--clone", "claude", "."]).is_err());
        assert_eq!(
            git_config(&root, "remote.sandbox-claude-repo.url"),
            "file:///sbt/claude-repo"
        );
    }

    #[test]
    fn create_builds_the_machine_from_the_preset() {
        let mut t = test_env(&[]);
        let fake = t.ctx.vm.runner();
        fake.ok(
            &["machine", "status"],
            &json("sbx-claude-proj", "created", "claude-proj"),
        );
        fake.once_fail(&["machine", "status"], "NOT_FOUND", "vm not found");
        sbt(
            &mut t.ctx,
            &[
                "create", "claude", ".", "--cpus", "2", "-m", "4g", "-e", "A=1", "-p", "8080:80",
            ],
        )
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
        let uploads = t.ctx.vm.runner().uploads();
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
            t.ctx
                .vm
                .runner()
                .call_lines()
                .contains(&"machine start -n sbx-claude-proj".to_string())
        );
    }

    #[test]
    fn create_on_an_existing_name_fails_before_touching_the_policy() {
        let mut t = test_env(&[]);
        t.ctx.vm.runner().ok(
            &["machine", "status"],
            &json("sbx-claude-proj", "stopped", "claude-proj"),
        );
        let before = std::fs::read_to_string(t.ctx.paths.policy_file()).unwrap();
        let err = sbt(
            &mut t.ctx,
            &["create", "claude", ".", "--deny-network", "evil.com"],
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("sandbox 'claude-proj' already exists"),
            "{err}"
        );
        assert_eq!(
            std::fs::read_to_string(t.ctx.paths.policy_file()).unwrap(),
            before
        );
        assert!(
            !t.ctx
                .vm
                .runner()
                .call_lines()
                .iter()
                .any(|l| l.contains("create") || l.contains("start"))
        );
    }

    /// Fake smolvm for one create of claude-proj that succeeds.
    fn creatable(t: &TestEnv) {
        let fake = t.ctx.vm.runner();
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
        sbt(
            &mut t.ctx,
            &[
                "create",
                "claude",
                ".",
                "--deny-network",
                "evil.com,10.0.0.0/8",
                "--deny-network",
                "tracker.example",
            ],
        )
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

        let lines = t.ctx.vm.runner().call_lines();
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
    fn create_denies_host_loopback_in_every_mode() {
        for mode in ["allow-all", "balanced"] {
            let mut t = test_env(&[]);
            set_policy(&t, &format!("mode = \"{mode}\"\n"));
            creatable(&t);
            sbt(&mut t.ctx, &["create", "claude", "."]).unwrap();
            let lines = t.ctx.vm.runner().call_lines();
            let create = lines
                .iter()
                .find(|l| l.starts_with("machine create"))
                .unwrap();
            for cidr in ["127.0.0.0/8", "::1/128"] {
                assert!(
                    create.contains(&format!(" --deny-cidr {cidr} ")),
                    "{mode}: {create}"
                );
            }
            // Not a rule: `policy ls` doesn't show it.
            let p = crate::policy::Policy::load(&t.ctx.paths).unwrap();
            assert!(p.rules.is_empty(), "{mode}: {p:?}");
            assert!(sandbox_rules(&t, "claude-proj").is_empty(), "{mode}");
        }
    }

    #[test]
    fn deny_network_is_checked_before_the_machine_is_created() {
        // A bad host: nothing is created and the policy is untouched.
        let mut t = test_env(&[]);
        let fake = t.ctx.vm.runner();
        fake.fail(&["machine", "status"], "NOT_FOUND", "vm not found");
        let before = std::fs::read_to_string(t.ctx.paths.policy_file()).unwrap();
        let err = sbt(
            &mut t.ctx,
            &[
                "create",
                "claude",
                ".",
                "--deny-network",
                "ok.com,10.0.0.0/33",
            ],
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("--deny-network"), "{err:#}");
        assert_eq!(
            std::fs::read_to_string(t.ctx.paths.policy_file()).unwrap(),
            before
        );
        let lines = t.ctx.vm.runner().call_lines();
        assert!(!lines.iter().any(|l| l.contains("create")), "{lines:?}");

        // A host a secret bound at create uses: smolvm would keep it reachable.
        let mut t = test_env(&[]);
        global_github_secret(&t);
        let fake = t.ctx.vm.runner();
        fake.fail(&["machine", "status"], "NOT_FOUND", "vm not found");
        let err = sbt(
            &mut t.ctx,
            &["create", "claude", ".", "--deny-network", "github.com"],
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains(
                "can't deny github.com: sandbox claude-proj would be created with a github secret"
            ),
            "{err}"
        );
        assert!(sandbox_rules(&t, "claude-proj").is_empty());
        let lines = t.ctx.vm.runner().call_lines();
        assert!(!lines.iter().any(|l| l.contains("create")), "{lines:?}");
    }

    #[test]
    fn a_failed_create_removes_only_its_own_deny_rules() {
        let earlier = "mode = \"allow-all\"\n[[sandboxes.claude-proj.rules]]\nid = \"r-old\"\n\
                       decision = \"deny\"\nresources = [\"old.example\"]\n";
        let mut t = test_env(&[]);
        set_policy(&t, earlier);
        let fake = t.ctx.vm.runner();
        fake.fail(&["machine", "status"], "NOT_FOUND", "vm not found");
        fake.fail(&["machine", "create"], "CREATE_FAILED", "no space left");
        let err = sbt(
            &mut t.ctx,
            &["create", "claude", ".", "--deny-network", "evil.com"],
        )
        .unwrap_err();
        assert!(err.to_string().contains("no space left"), "{err:#}");
        assert_eq!(
            sandbox_rules(&t, "claude-proj"),
            vec![deny(&["old.example"])]
        );

        // Nothing earlier: the sandbox's entry goes away.
        let mut t = test_env(&[]);
        let fake = t.ctx.vm.runner();
        fake.fail(&["machine", "status"], "NOT_FOUND", "vm not found");
        fake.fail(&["machine", "create"], "CREATE_FAILED", "no space left");
        assert!(
            sbt(
                &mut t.ctx,
                &["create", "claude", ".", "--deny-network", "evil.com"]
            )
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
        t.ctx
            .vm
            .runner()
            .fail(&["machine", "start"], "START_FAILED", "boot failed");
        assert!(
            sbt(
                &mut t.ctx,
                &["create", "claude", ".", "--deny-network", "evil.com"]
            )
            .is_err()
        );
        assert_eq!(sandbox_rules(&t, "claude-proj"), vec![deny(&["evil.com"])]);

        // No policy chosen and no terminal: create stops before adding rules, and the rollback
        // doesn't write a policy.toml either.
        let mut t = test_env(&[]);
        std::fs::remove_file(t.ctx.paths.policy_file()).unwrap();
        let fake = t.ctx.vm.runner();
        fake.fail(&["machine", "status"], "NOT_FOUND", "vm not found");
        assert!(
            sbt(
                &mut t.ctx,
                &["create", "claude", ".", "--deny-network", "evil.com"]
            )
            .is_err()
        );
        assert!(!t.ctx.paths.policy_file().exists());
    }

    #[test]
    fn create_without_path_is_mountless_and_docker_can_be_disabled() {
        let mut t = test_env(&[("SMOLBENTO_DOCKER", "false")]);
        let fake = t.ctx.vm.runner();
        fake.ok(
            &["machine", "status"],
            &json("sbx-shell-proj", "created", "shell-proj"),
        );
        fake.once_fail(&["machine", "status"], "NOT_FOUND", "vm not found");
        sbt(&mut t.ctx, &["create", "shell", "--cpus", "1", "-m", "1g"]).unwrap();
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
            t.ctx
                .vm
                .runner()
                .call_lines()
                .contains(&"machine start -n sbx-shell-proj --branchable".to_string())
        );
    }

    #[test]
    fn kit_docker_adds_dockerd_to_any_template() {
        let mut t = test_env(&[]);
        let fake = t.ctx.vm.runner();
        fake.ok(
            &["machine", "status"],
            &json("sbx-shell-proj", "created", "shell-proj"),
        );
        fake.once_fail(&["machine", "status"], "NOT_FOUND", "vm not found");
        sbt(
            &mut t.ctx,
            &["create", "-t", "alpine", "--kit", "docker", "shell", "."],
        )
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

    #[test]
    fn create_rejects_unknown_agents_and_bad_names() {
        let mut t = test_env(&[]);
        assert!(
            sbt(&mut t.ctx, &["create", "nope"])
                .unwrap_err()
                .to_string()
                .contains("unknown agent \"nope\"")
        );
        // Exact sbx text; a bare word with a tag is still an agent name.
        for w in ["alpine", "alpine:3"] {
            assert_eq!(
                sbt(&mut t.ctx, &["create", w]).unwrap_err().to_string(),
                format!("unknown agent \"{w}\"")
            );
        }
        assert!(
            sbt(&mut t.ctx, &["create", "claude", "--name", "a_b"])
                .unwrap_err()
                .to_string()
                .contains("'_'")
        );
    }

    #[test]
    fn stop_and_start() {
        let mut t = test_env(&[]);
        t.ctx.vm.runner().ok(
            &["machine", "status"],
            &json("sbx-claude-proj", "running", "claude-proj"),
        );
        sbt(&mut t.ctx, &["stop", "claude-proj"]).unwrap();
        assert!(
            t.ctx
                .vm
                .runner()
                .call_lines()
                .contains(&"machine stop -n sbx-claude-proj".to_string())
        );

        let mut t = test_env(&[]);
        t.ctx.vm.runner().ok(
            &["machine", "status"],
            &json("sbx-claude-proj", "stopped", "claude-proj"),
        );
        sbt(&mut t.ctx, &["start", "claude-proj"]).unwrap();
        assert!(
            t.ctx
                .vm
                .runner()
                .call_lines()
                .contains(&"machine start -n sbx-claude-proj --branchable".to_string())
        );
    }

    #[test]
    fn start_needs_a_policy() {
        let mut t = test_env(&[]);
        set_policy(&t, "");
        t.ctx.vm.runner().ok(
            &["machine", "status"],
            &json("sbx-claude-proj", "stopped", "claude-proj"),
        );
        let err = sbt(&mut t.ctx, &["start", "claude-proj"])
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("no network policy chosen yet; run `sbt policy init"),
            "{err}"
        );
        let started = |t: &TestEnv| {
            t.ctx
                .vm
                .runner()
                .call_lines()
                .into_iter()
                .any(|l| l.starts_with("machine update") || l.starts_with("machine start"))
        };
        assert!(!started(&t));
        sbt(&mut t.ctx, &["policy", "init", "balanced"]).unwrap();
        sbt(&mut t.ctx, &["start", "claude-proj"]).unwrap();
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
        t.ctx
            .vm
            .runner()
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
            let fake = t.ctx.vm.runner();
            fake.ok(&["machine", "status"], &clone_json("box", "stopped", &repo));
            fake.ok(
                &["machine", "ls", "--json"],
                &format!("[{}]", clone_json("box", "stopped", &repo)),
            );
            assert!(!remote(&repo, "box").is_empty());
            sbt(&mut t.ctx, &cmd).unwrap();
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
        t.ctx
            .vm
            .runner()
            .ok(&["machine", "status"], &clone_json("box", "stopped", &repo));
        ls_one(&t, &clone_json("box", "stopped", &repo));
        sbt(&mut t.ctx, &["rm", "-f", "box"]).unwrap();
        assert!(!remote(&repo, "box").is_empty());
    }

    #[test]
    fn rm_succeeds_when_the_clone_workspace_is_gone() {
        let mut t = test_env(&[]);
        let gone = t.ctx.cwd.join("deleted");
        t.ctx
            .vm
            .runner()
            .ok(&["machine", "status"], &clone_json("box", "stopped", &gone));
        ls_one(&t, &clone_json("box", "stopped", &gone));
        sbt(&mut t.ctx, &["rm", "-f", "box"]).unwrap();
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
        t.ctx.vm.runner().ok(&["machine", "status"], &box_json);
        ls_one(&t, &box_json);
        sbt(&mut t.ctx, &["rm", "-f", "box"]).unwrap();
        assert_eq!(remote(&repo, "box"), "");
    }

    #[test]
    fn rm_needs_force_without_a_terminal() {
        let mut t = test_env(&[]);
        t.ctx.vm.runner().ok(
            &["machine", "status"],
            &json("sbx-claude-proj", "running", "claude-proj"),
        );
        ls_one(&t, &json("sbx-claude-proj", "running", "claude-proj"));
        assert!(
            sbt(&mut t.ctx, &["rm", "claude-proj"])
                .unwrap_err()
                .to_string()
                .contains("pass -f")
        );
        sbt(&mut t.ctx, &["rm", "-f", "claude-proj"]).unwrap();
        assert!(
            t.ctx
                .vm
                .runner()
                .call_lines()
                .contains(&"machine delete -n sbx-claude-proj -f".to_string())
        );
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
        t.ctx.vm.runner().ok(&["machine", "ls", "--json"], &ls);
        t.ctx.vm.runner().ok(
            &["machine", "status", "-n", "sbx-live"],
            &json("sbx-live", "running", "live"),
        );
        sbt(&mut t.ctx, &["prune", "-f", "--filter", "until=1m"]).unwrap();
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
        t.ctx.vm.runner().ok(&["machine", "ls", "--json"], &ls);
        sbt(&mut t.ctx, &["reset", "-f"]).unwrap();
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
        t.ctx.vm.runner().ok(
            &["machine", "ls", "--json"],
            &format!("[{}]", json("sbx-a1", "stopped", "a1")),
        );
        sbt(&mut t.ctx, &["reset", "-f", "--preserve-secrets"]).unwrap();
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
        let fake = t.ctx.vm.runner();
        fake.ok(&["machine", "ls", "--json"], &format!("[{ja},{j1},{j2}]"));
        fake.ok(&["machine", "status", "-n", "sbx-a"], &ja);
        fake.ok(&["machine", "status", "-n", "sbx-a-fork-1"], &j1);
        fake.ok(&["machine", "status", "-n", "sbx-a-fork-2"], &j2);
    }

    fn deletes(t: &TestEnv) -> Vec<String> {
        t.ctx
            .vm
            .runner()
            .call_lines()
            .into_iter()
            .filter(|l| l.contains("machine delete"))
            .map(|l| l.replace("machine delete -n sbx-", "").replace(" -f", ""))
            .collect()
    }

    #[test]
    fn rm_refuses_a_parent_that_still_has_forks() {
        let mut t = test_env(&[]);
        with_forks(&t, "stopped", "stopped", "stopped");
        let err = sbt(&mut t.ctx, &["rm", "-f", "a"]).unwrap_err().to_string();
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
        sbt(&mut t.ctx, &["rm", "-f", "a", "a-fork-1", "a-fork-2"]).unwrap();
        assert_eq!(deletes(&t), vec!["a-fork-1", "a-fork-2", "a"]);
        // Named targets come from the one list, not a status call each.
        let calls = t.ctx.vm.runner().call_lines();
        assert!(
            calls.iter().all(|c| !c.starts_with("machine status")),
            "{calls:?}"
        );
    }

    #[test]
    fn rm_of_a_missing_sandbox_deletes_nothing() {
        let mut t = test_env(&[]);
        with_forks(&t, "stopped", "stopped", "stopped");
        let err = sbt(&mut t.ctx, &["rm", "-f", "a-fork-1", "nope"]).unwrap_err();
        assert_eq!(err.to_string(), "sandbox 'nope' not found (see `sbt ls`)");
        assert!(deletes(&t).is_empty());
    }

    #[test]
    fn rm_all_deletes_forks_before_parents_and_lists_once() {
        let mut t = test_env(&[]);
        with_forks(&t, "stopped", "stopped", "stopped");
        sbt(&mut t.ctx, &["rm", "-f", "--all"]).unwrap();
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
        sbt(&mut t.ctx, &["prune", "-f"]).unwrap();
        assert_eq!(deletes(&t), vec!["a-fork-2"]);

        let mut t = test_env(&[]);
        with_forks(&t, "stopped", "stopped", "stopped");
        sbt(&mut t.ctx, &["prune", "-f"]).unwrap();
        assert_eq!(deletes(&t), vec!["a-fork-1", "a-fork-2", "a"]);
    }

    #[test]
    fn prune_says_which_parents_it_skipped() {
        let mut t = test_env(&[]);
        with_forks(&t, "stopped", "running", "stopped");
        sbt(&mut t.ctx, &["prune", "-f"]).unwrap();
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
        let fake = t.ctx.vm.runner();
        fake.ok(&["machine", "ls", "--json"], &format!("[{parent},{fork}]"));
        fake.ok(&["machine", "status", "-n", "sbx-a"], &parent);
        fake.ok(&["machine", "status", "-n", "sbx-a-fork-1"], &fork);
        sbt(&mut t.ctx, &["prune", "-f", "--filter", "until=1m"]).unwrap();
        assert!(deletes(&t).is_empty(), "{:?}", deletes(&t));
    }

    #[test]
    fn reset_deletes_forks_before_parents() {
        let mut t = test_env(&[]);
        with_forks(&t, "stopped", "stopped", "stopped");
        sbt(&mut t.ctx, &["reset", "-f"]).unwrap();
        assert_eq!(deletes(&t), vec!["a-fork-1", "a-fork-2", "a"]);
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
        t.ctx
            .vm
            .runner()
            .call_lines()
            .into_iter()
            .find(|l| l.starts_with("machine create"))
            .expect("a machine create")
    }

    fn no_machine_calls(t: &TestEnv) -> bool {
        !t.ctx
            .vm
            .runner()
            .call_lines()
            .iter()
            .any(|l| l.starts_with("machine "))
    }

    #[test]
    fn create_with_a_mixin_kit_applies_it() {
        let mut t = kit_env();
        // allow-all would leave the kit's allow rule out of the argv.
        set_policy(&t, "mode = \"deny-all\"");
        let fake = t.ctx.vm.runner();
        fake.ok(
            &["machine", "status"],
            &json("sbx-shell-proj", "created", "shell-proj"),
        );
        fake.once_fail(&["machine", "status"], "NOT_FOUND", "vm not found");
        let kit = fixture("tool-mixin");
        sbt(
            &mut t.ctx,
            &[
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
            ],
        )
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
        let lines = t.ctx.vm.runner().call_lines();
        let start = lines
            .iter()
            .position(|l| l == "machine start -n sbx-shell-proj")
            .unwrap();
        let install = lines
            .iter()
            .position(|l| l.contains("machine exec") && l.contains("echo installed"))
            .expect("the install hook runs");
        assert!(start < install, "{lines:?}");
        assert_eq!(t.stdout(), "Created sandbox shell-proj\n");
    }

    #[test]
    fn create_writes_v2_workspace_files_into_the_workspace() {
        let mut t = kit_env();
        let fake = t.ctx.vm.runner();
        fake.ok(
            &["machine", "status"],
            &json("sbx-shell-proj", "created", "shell-proj"),
        );
        fake.once_fail(&["machine", "status"], "NOT_FOUND", "vm not found");
        let kit = fixture("workspace-files");
        sbt(&mut t.ctx, &["create", "shell", ".", "--kit", &kit]).unwrap();
        let ws = t.ctx.cwd.canonicalize().unwrap().display().to_string();
        let lines = t.ctx.vm.runner().call_lines();
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
        let fake = t.ctx.vm.runner();
        fake.ok(
            &["machine", "status"],
            &json("sbx-toolbox-proj", "created", "toolbox-proj"),
        );
        fake.once_fail(&["machine", "status"], "NOT_FOUND", "vm not found");
        sbt(&mut t.ctx, &["create", &fixture("tool-workload"), "."]).unwrap();
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
        let fake = t.ctx.vm.runner();
        fake.fail(&["machine", "status"], "NOT_FOUND", "vm not found");
        let err = sbt(&mut t.ctx, &["create", &kit.display().to_string(), "."]).unwrap_err();
        assert_eq!(
            format!("{err:#}"),
            "workload kit image declares no ENTRYPOINT or CMD; the image config is the runtime \
             contract"
        );
        assert!(
            !t.ctx
                .vm
                .runner()
                .call_lines()
                .iter()
                .any(|l| l.starts_with("machine create")),
        );
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
        let fake = t.ctx.vm.runner();
        fake.ok(
            &["machine", "status"],
            &json("sbx-bare-proj", "created", "bare-proj"),
        );
        fake.once_fail(&["machine", "status"], "NOT_FOUND", "vm not found");
        sbt(&mut t.ctx, &["create", &kit.display().to_string(), "."]).unwrap();
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
        let fake = t.ctx.vm.runner();
        fake.ok(
            &["machine", "status"],
            &json("sbx-shell-proj", "created", "shell-proj"),
        );
        fake.once_fail(&["machine", "status"], "NOT_FOUND", "vm not found");
        sbt(&mut t.ctx, &["create", &kit.display().to_string(), "."]).unwrap();
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
        let mut t = kit_env();
        let kit = fixture("tool-mixin");
        let err = sbt(&mut t.ctx, &["create", &kit]).unwrap_err().to_string();
        assert_eq!(
            err,
            format!(
                "{kit} is a mixin; add it with --kit to an agent, e.g. sbt run shell --kit {kit}"
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
        ] {
            let mut t = kit_env();
            let err = format!("{:#}", sbt(&mut t.ctx, &args).unwrap_err());
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
        t.ctx.vm.runner().ok(
            &["machine", "status"],
            &json("sbx-shell-proj", "stopped", "shell-proj"),
        );
        let err = sbt(
            &mut t.ctx,
            &["create", "shell", ".", "--kit", &fixture("tool-mixin")],
        )
        .unwrap_err()
        .to_string();
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
        sbt(
            &mut t.ctx,
            &[
                "secret",
                "set-custom",
                "--env",
                "CORP",
                "--host",
                "api.corp.example",
                "-t",
                "c-1",
            ],
        )
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

    /// `build_kit_request` for `args` followed by `kit`.
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
        super::build_kit_request(&t.ctx, &a.targets, &a.opts, true).unwrap()
    }
}
