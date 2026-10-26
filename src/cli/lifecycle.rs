//! create, start, stop, rm, prune and reset.

use std::time::UNIX_EPOCH;

use anyhow::{Context, Result, bail};

use super::plan;
use super::{CreateArgs, Ctx, PruneArgs, ResetArgs, RmArgs, SandboxOpts, confirm};
use crate::agents;
use crate::sandbox::{self, CreateRequest, Sandbox, name, options, session};
use crate::smolvm::{NetworkSpec, Runner};
use crate::workspace::Workspace;

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
        network: NetworkSpec::default(),
        deny_cidrs: vec![],
        credentials: vec![],
        secrets: vec![],
        credential_hosts: vec![],
    })
}

pub fn create<R: Runner>(ctx: &mut Ctx<R>, a: &CreateArgs) -> Result<i32> {
    let (agent, paths) = a
        .targets
        .split_first()
        .context("specify an agent, e.g. `sbt create claude .`")?;
    let mut req = build_request(ctx, agent, paths, &a.opts, false)?;
    // Before prepare_create, which may prompt and records --deny-network.
    if sandbox::find(&ctx.vm, &req.name)?.is_some() {
        bail!("sandbox '{}' already exists", req.name);
    }
    plan::prepare_create(ctx, &mut req, a.opts.deny_network)?;
    let start_plan = plan::start_plan(ctx, &req.name, &req.secrets, &req.credential_hosts)?;
    let sb = sandbox::create(&ctx.vm, &req, &start_plan)?;
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
        let start_plan =
            plan::start_plan(ctx, sb.name(), &sb.meta.secrets, &sb.meta.credential_hosts)?;
        sandbox::start(&ctx.vm, &sb, &start_plan)?;
        println!("Started {n}");
    }
    Ok(0)
}

pub fn stop<R: Runner>(ctx: &mut Ctx<R>, names: &[String]) -> Result<i32> {
    for n in names {
        let sb = sandbox::get(&ctx.vm, n)?;
        if sb.is_running() {
            ctx.vm.stop(&sb.machine)?;
        }
        session::clear(&ctx.paths.sessions(), n);
        println!("Stopped {n}");
    }
    Ok(0)
}

fn remove<R: Runner>(ctx: &Ctx<R>, sb: &Sandbox) -> Result<()> {
    ctx.vm.delete(&sb.machine)?;
    session::clear(&ctx.paths.sessions(), sb.name());
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
        remove(ctx, sb)?;
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
        remove(ctx, sb)?;
    }
    Ok(0)
}

pub fn reset<R: Runner>(ctx: &mut Ctx<R>, a: &ResetArgs) -> Result<i32> {
    // smolbento stores no secrets yet, so --preserve-secrets has nothing to preserve.
    confirm(
        ctx,
        "Remove every sandbox and smolbento's session state?",
        a.force,
    )?;
    for sb in sandbox::list(&ctx.vm)? {
        remove(ctx, &sb)?;
    }
    let _ = std::fs::remove_dir_all(ctx.paths.sessions());
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
    fn create_builds_the_machine_from_the_preset() {
        let mut t = test_env(&[]);
        let fake = t.ctx.vm.runner();
        fake.ok(
            &["machine", "status"],
            &json("sbx-claude-proj", "created", "claude-proj"),
        );
        fake.once_fail(&["machine", "status"], "NOT_FOUND", "vm not found");
        // create checks the name, then sandbox::create checks again.
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
        let err = sbt(&mut t.ctx, &["create", "claude", ".", "--deny-network"])
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

    #[test]
    fn create_deny_network_binds_global_secrets() {
        use crate::policy::Policy;
        use crate::secrets::{SecretEntry, SecretsFile, Source, scope_for};

        let mut t = test_env(&[]);
        let entry = SecretEntry {
            service: "github".into(),
            scope: scope_for(None),
            source: Source::Keychain,
        };
        t.ctx.store.set(&entry.account(), "gh-123").unwrap();
        let mut f = SecretsFile::default();
        f.set(entry);
        f.save(&t.ctx.paths).unwrap();
        let fake = t.ctx.vm.runner();
        fake.ok(
            &["machine", "status"],
            &json("sbx-claude-proj", "created", "claude-proj"),
        );
        fake.once_fail(&["machine", "status"], "NOT_FOUND", "vm not found");
        // create checks the name, then sandbox::create checks again.
        fake.once_fail(&["machine", "status"], "NOT_FOUND", "vm not found");
        sbt(&mut t.ctx, &["create", "claude", ".", "--deny-network"]).unwrap();

        let lines = t.ctx.vm.runner().call_lines();
        let create = lines
            .iter()
            .find(|l| l.starts_with("machine create"))
            .unwrap();
        assert!(
            create.contains(" --credential gh_token=GH_TOKEN@api.github.com,github.com,"),
            "{create}"
        );
        assert!(create.contains(" --label sbx.secrets=github "), "{create}");
        assert!(
            create.contains(
                " --label sbx.credential-hosts=api.github.com,api.githubcopilot.com,\
                 copilot.github.com,gist.github.com,github.com,raw.githubusercontent.com "
            ),
            "{create}"
        );
        assert!(
            !create.contains("--net "),
            "deny-network is restricted: {create}"
        );
        assert!(Policy::load(&t.ctx.paths).unwrap().sandboxes["claude-proj"].deny_network);
        let start = lines
            .iter()
            .position(|l| l == "machine start -n sbx-claude-proj");
        let envs = t.ctx.vm.runner().envs();
        assert!(start.is_some());
        assert_eq!(
            envs,
            vec![vec![
                ("GH_TOKEN".to_string(), "gh-123".to_string()),
                ("GITHUB_TOKEN".to_string(), "gh-123".to_string())
            ]]
        );
        assert!(!create.contains("gh-123"));
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
        // create checks the name, then sandbox::create checks again.
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
}
