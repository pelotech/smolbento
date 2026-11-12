//! create, start, stop, rm, prune and reset.

use std::io::Write;
use std::path::Path;
use std::time::UNIX_EPOCH;

use anyhow::{Context, Result, bail};

use super::progress::{CreateSteps, Progress};
use super::request::{Workload, check_kit_args, kit_plan, kit_target, resolve_clone};
use super::{CreateArgs, Ctx, PruneArgs, ResetArgs, RmArgs, SandboxOpts, confirm};
use crate::provision;
use crate::sandbox::{self, CreateRequest, Event, Sandbox, session};
use crate::smolvm::Runner;
use crate::workspace::clone;

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
    provision::check_free(ctx, &req.name)?;
    // A bad `--static-mcp` fails here, not after the kits were fetched and built.
    let preset = workload
        .as_ref()
        .is_none_or(|w| matches!(w, Workload::Preset(_)));
    provision::mcp_attachment(ctx, req, preset)?;
    report_sandbox(p, req, workload.as_ref(), opts.clone);
    let kits = workload
        .map(|w| kit_plan(ctx, req, w, opts, p))
        .transpose()?;
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

    use super::super::request::*;
    use super::super::{Cli, Cmd, SandboxOpts};
    use crate::testutil::*;

    #[test]
    fn create_clone_mounts_the_repo_and_adds_the_remote() {
        let mut t = test_env(&[]);
        let (_d, root) = temp_repo();
        t.ctx.cwd = root.clone();
        creatable_as(&t, "claude-repo");
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

    #[test]
    fn clone_needs_a_repo_before_smolvm_is_called() {
        let mut t = test_env(&[]);
        let err = t.sbt_err(&["create", "--clone", "claude", "."]);
        assert!(err.contains("--clone needs a git repository"), "{err}");
        assert!(!t.made("machine create"));
    }

    #[test]
    fn clone_needs_a_workspace_path_before_smolvm_is_called() {
        let mut t = test_env(&[]);
        let err = t.sbt_err(&["create", "--clone", "claude"]);
        assert!(err.contains("--clone needs a workspace path"), "{err}");
        assert!(!t.made("machine create"));
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
        assert!(!t.made("machine create"));
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
        creatable_as(&t, "claude-repo");
        t.sbt(&["create", "--clone", "claude", "."]).unwrap();
        assert!(t.made("machine create"));
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
        creatable_as(&t, "claude-repo");
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
        creatable_as(&t, "claude-proj");
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

    fn creatable(t: &TestEnv) {
        creatable_as(t, "claude-proj");
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
        creatable_as(&t, "shell-proj");
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
        creatable_as(&t, "shell-proj");
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
        creatable_as(&t, "claude-proj");
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
}
