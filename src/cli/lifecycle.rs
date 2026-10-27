//! create, start, stop, rm, prune and reset.

use std::path::Path;
use std::time::UNIX_EPOCH;

use anyhow::{Context, Result, bail};

use super::plan;
use super::{CreateArgs, Ctx, PruneArgs, ResetArgs, RmArgs, SandboxOpts, confirm};
use crate::agents;
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
    let agent = agents::find(agent_name).with_context(|| {
        format!(
            "unknown agent '{agent_name}' (agents: {}); kits are not implemented yet",
            agents::names().join(", ")
        )
    })?;
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
            agent.name,
            workspaces
                .first()
                .map_or(ctx.cwd.as_path(), |w| w.path.as_path()),
        ),
    };
    name::validate(&name)?;

    let docker_enabled = ctx.settings.bool("docker.enabled")?;
    // docker.enabled=false swaps the preset for its plain variant; an explicit -t is used as given.
    let image = match &opts.template {
        Some(t) => t.clone(),
        None if docker_enabled => agent.image.to_string(),
        None => agents::plain_image(agent.image),
    };
    let docker = docker_enabled && agents::is_docker_image(&image);

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
        agent: agent.name.into(),
        image,
        workspaces,
        cpus,
        memory_mib,
        env,
        ports,
        docker,
        created: ctx.now,
        ..Default::default()
    })
}

/// Resolves `--clone` into `req.clone`. Only for a sandbox that is about to be created: `--clone`
/// is a no-op when `run` re-attaches to an existing one.
pub(crate) fn resolve_clone(req: &mut CreateRequest, opts: &SandboxOpts) -> Result<()> {
    if opts.clone {
        let primary = req
            .workspaces
            .first()
            .context("--clone needs a workspace path, e.g. `sbt create --clone claude .`")?;
        req.clone = Some(crate::workspace::clone::source(&primary.path)?);
    }
    Ok(())
}

pub fn create<R: Runner>(ctx: &mut Ctx<R>, a: &CreateArgs) -> Result<i32> {
    let (agent, paths) = a
        .targets
        .split_first()
        .context("specify an agent, e.g. `sbt create claude .`")?;
    let mut req = build_request(ctx, agent, paths, &a.opts, false)?;
    resolve_clone(&mut req, &a.opts)?;
    let sb = plan::create(ctx, &mut req, &a.opts.deny_network)?;
    println!("Created sandbox {}", sb.name());
    Ok(0)
}

pub fn start<R: Runner>(ctx: &mut Ctx<R>, names: &[String]) -> Result<i32> {
    for n in names {
        let sb = sandbox::get(&ctx.vm, n)?;
        if sb.is_running() {
            println!("{n} is already running");
            continue;
        }
        let start_plan = plan::start_plan(ctx, &sb.meta)?;
        sandbox::start(&ctx.vm, &sb, &start_plan)?;
        println!("Started {n}");
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
    println!("Stopped {}", sb.name());
    Ok(())
}

/// Deletes a sandbox and its per-sandbox policy; `forget_secrets` also drops its own secrets.
fn remove<R: Runner>(ctx: &Ctx<R>, sb: &Sandbox, forget_secrets: bool) -> Result<()> {
    ctx.vm.delete(&sb.machine)?;
    if let Some(repo) = &sb.meta.clone {
        clone::remove_remote(Path::new(repo), sb.name());
    }
    session::clear(&ctx.paths.sessions(), sb.name());
    super::secret::forget_sandbox(ctx, sb.name(), forget_secrets)?;
    println!("Removed {}", sb.name());
    Ok(())
}

pub fn rm<R: Runner>(ctx: &mut Ctx<R>, a: &RmArgs) -> Result<i32> {
    let targets: Vec<Sandbox> = if a.all {
        sandbox::list(&ctx.vm)?
    } else {
        if a.sandboxes.is_empty() {
            bail!("specify sandboxes to remove, or --all");
        }
        a.sandboxes
            .iter()
            .map(|n| sandbox::get(&ctx.vm, n))
            .collect::<Result<_>>()?
    };
    if targets.is_empty() {
        println!("No sandboxes found");
        return Ok(0);
    }
    let names: Vec<&str> = targets.iter().map(Sandbox::name).collect();
    confirm(ctx, &format!("Remove {}?", names.join(", ")), a.force)?;
    for sb in &targets {
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
    let targets: Vec<Sandbox> = sandbox::list(&ctx.vm)?
        .into_iter()
        .filter(|sb| !sb.is_running())
        .filter(|sb| cutoff.is_none_or(|c| sb.meta.created < c))
        .collect();
    if targets.is_empty() {
        println!("Nothing to prune");
        return Ok(0);
    }
    if a.dry_run {
        for sb in &targets {
            println!("Would remove {}", sb.name());
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
    for sb in sandbox::list(&ctx.vm)? {
        remove(ctx, &sb, !a.preserve_secrets)?;
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
        assert_eq!(pair("-e"), vec!["A=1"]);
        assert_eq!(pair("-p"), vec!["8080:80"]);
        assert!(pair("--label").contains(&"sbx.created=1000000".to_string()));
        assert!(pair("--label").contains(&"sbx.docker=true".to_string()));
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
        assert!(
            t.ctx
                .vm
                .runner()
                .call_lines()
                .contains(&"machine start -n sbx-shell-proj".to_string())
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
                .contains("unknown agent 'nope'")
        );
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
                .contains(&"machine start -n sbx-claude-proj".to_string())
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
        sbt(&mut t.ctx, &["rm", "-f", "box"]).unwrap();
    }

    #[test]
    fn rm_removes_the_remote_from_the_repo_top_when_the_subdirectory_is_gone() {
        let mut t = test_env(&[]);
        let (_d, repo) = temp_repo();
        crate::workspace::clone::add_remote(&repo, "box").unwrap();
        let sub = repo.join("deleted").display().to_string();
        t.ctx.vm.runner().ok(
            &["machine", "status"],
            &machine_json(
                "sbx-box",
                "stopped",
                &[
                    ("sbx.name", "box"),
                    ("sbx.clone", "true"),
                    ("sbx.workspace", &sub),
                    ("sbx.clone-top", &repo.display().to_string()),
                ],
            ),
        );
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
}
