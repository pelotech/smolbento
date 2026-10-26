//! run: create the sandbox if needed, start it, attach to the agent, and stop it when the last
//! session ends (unless it was started with -d).

use anyhow::{Context, Result, bail};

use super::lifecycle::build_request;
use super::plan;
use super::{Ctx, RunArgs, Unsupported};
use crate::agents;
use crate::sandbox::{self, session};
use crate::smolvm::{ExecSpec, Runner};

/// Flag checks that need no smolvm; `dispatch` runs them before its smolvm gate.
pub fn check_args(a: &RunArgs) -> Result<()> {
    a.opts.check_supported()?;
    if a.new {
        return Err(Unsupported("--new is a Docker Cloud option".into()).into());
    }
    if a.detach_keys.is_some() {
        return Err(Unsupported("--detach-keys is not supported".into()).into());
    }
    if a.rm && a.detach {
        bail!("--rm can't be combined with -d");
    }
    Ok(())
}

pub fn run<R: Runner>(ctx: &mut Ctx<R>, a: &RunArgs) -> Result<i32> {
    let existing = match &a.opts.name {
        Some(n) => sandbox::find(&ctx.vm, n)?,
        None => None,
    };
    let (mut sb, created) = match existing {
        Some(sb) => (sb, false),
        None => {
            let Some((agent, paths)) = a.targets.split_first() else {
                bail!(
                    "specify an agent (e.g. `sbt run claude`) or the --name of an existing sandbox"
                );
            };
            let mut req = build_request(ctx, agent, paths, &a.opts, true)?;
            match sandbox::find(&ctx.vm, &req.name)? {
                Some(sb) => (sb, false),
                None => {
                    plan::prepare_create(ctx, &mut req, a.opts.deny_network)?;
                    let start_plan = plan::start_plan(ctx, &req.name, &req.secrets)?;
                    (sandbox::create(&ctx.vm, &req, &start_plan)?, true)
                }
            }
        }
    };
    if a.opts.deny_network && !created {
        eprintln!(
            "warning: --deny-network only applies when a sandbox is created; {} already exists",
            sb.name()
        );
    }
    plan::ensure_running(ctx, &mut sb)?;

    let sessions = ctx.paths.sessions();
    if a.detach {
        session::mark_detached(&sessions, sb.name())?;
        println!("{}", sb.name());
        return Ok(0);
    }

    let agent = agents::find(&sb.meta.agent).with_context(|| {
        format!(
            "sandbox '{}' has no known agent ('{}')",
            sb.name(),
            sb.meta.agent
        )
    })?;
    let spec = ExecSpec {
        name: sb.machine.clone(),
        user: Some("agent".into()),
        workdir: Some(sb.workdir()),
        interactive: true,
        tty: ctx.stdin_tty,
        cmd: agents::command_with_args(agent.command, &a.agent_args),
        ..Default::default()
    };
    let code = {
        let _session = session::Session::register(&sessions, sb.name())?;
        ctx.vm.exec(&spec)?
    };

    // The agent's exit code is the result; failing to clean up after it only warrants a warning.
    if a.rm {
        match ctx.vm.delete(&sb.machine) {
            Ok(()) => session::clear(&sessions, sb.name()),
            Err(e) => eprintln!("warning: removing sandbox {}: {e:#}", sb.name()),
        }
    } else if !session::is_detached(&sessions, sb.name())
        && session::live_sessions(&sessions, sb.name()) == 0
        && let Err(e) = ctx.vm.stop(&sb.machine)
    {
        eprintln!("warning: stopping sandbox {}: {e:#}", sb.name());
    }
    Ok(code)
}

#[cfg(test)]
mod tests {
    use super::super::testutil::*;
    use crate::sandbox::session;

    fn created(t: &TestEnv, state: &str) {
        let ws = t.ctx.cwd.display().to_string();
        t.ctx.vm.runner().ok(
            &["machine", "status"],
            &machine_json(
                "sbx-claude-proj",
                state,
                &[
                    ("sbx.name", "claude-proj"),
                    ("sbx.agent", "claude"),
                    ("sbx.workspace", ws.as_str()),
                ],
            ),
        );
    }

    #[test]
    fn creates_attaches_and_stops_after_the_last_session() {
        let mut t = test_env(&[]);
        created(&t, "created");
        // run looks the name up, then sandbox::create checks again before creating.
        t.ctx
            .vm
            .runner()
            .once_fail(&["machine", "status"], "NOT_FOUND", "vm not found");
        t.ctx
            .vm
            .runner()
            .once_fail(&["machine", "status"], "NOT_FOUND", "vm not found");
        t.ctx.vm.runner().interactive_exit(0);
        assert_eq!(
            sbt(
                &mut t.ctx,
                &["run", "claude", "--cpus", "1", "-m", "1g", "--", "-c"]
            )
            .unwrap(),
            0
        );

        let ws = t.ctx.cwd.display().to_string();
        assert_eq!(
            t.ctx.vm.runner().interactive_calls()[0].join(" "),
            format!(
                "machine exec --name sbx-claude-proj -u agent -w {ws} -i -- claude --dangerously-skip-permissions -c"
            )
        );
        let lines = t.ctx.vm.runner().call_lines();
        assert!(
            lines
                .iter()
                .any(|l| l.starts_with("machine create -n sbx-claude-proj"))
        );
        assert!(
            lines.iter().any(|l| l.ends_with("usermod -o -u 501 agent")),
            "the agent takes ctx.uid: {lines:?}"
        );
        assert_eq!(lines.last().unwrap(), "machine stop -n sbx-claude-proj");
        assert_eq!(
            session::live_sessions(&t.ctx.paths.sessions(), "claude-proj"),
            0
        );
    }

    #[test]
    fn running_an_existing_sandbox_needs_no_policy_and_records_nothing() {
        let mut t = test_env(&[]);
        std::fs::remove_file(t.ctx.paths.policy_file()).unwrap();
        created(&t, "stopped");
        t.ctx.vm.runner().interactive_exit(0);
        assert_eq!(
            sbt(&mut t.ctx, &["run", "claude", "--deny-network"]).unwrap(),
            0
        );
        assert!(!t.ctx.paths.policy_file().exists());
        let lines = t.ctx.vm.runner().call_lines();
        assert!(!lines.iter().any(|l| l.contains("create")), "{lines:?}");
        assert!(
            lines
                .iter()
                .any(|l| l == "machine start -n sbx-claude-proj"),
            "{lines:?}"
        );
    }

    #[test]
    fn reattaches_by_name_and_returns_the_agent_status() {
        let mut t = test_env(&[]);
        created(&t, "running");
        t.ctx.vm.runner().interactive_exit(42);
        assert_eq!(
            sbt(&mut t.ctx, &["run", "--name", "claude-proj"]).unwrap(),
            42
        );
        assert!(
            !t.ctx
                .vm
                .runner()
                .call_lines()
                .iter()
                .any(|l| l.contains("create"))
        );
    }

    #[test]
    fn detach_leaves_it_running_and_later_runs_keep_it() {
        let mut t = test_env(&[]);
        created(&t, "running");
        sbt(&mut t.ctx, &["run", "-d", "--name", "claude-proj"]).unwrap();
        assert!(t.ctx.vm.runner().interactive_calls().is_empty());
        sbt(&mut t.ctx, &["run", "--name", "claude-proj"]).unwrap();
        assert!(
            !t.ctx
                .vm
                .runner()
                .call_lines()
                .iter()
                .any(|l| l.contains("stop"))
        );
    }

    #[test]
    fn rm_deletes_after_exit() {
        let mut t = test_env(&[]);
        created(&t, "running");
        sbt(&mut t.ctx, &["run", "--rm", "--name", "claude-proj"]).unwrap();
        assert_eq!(
            t.ctx.vm.runner().call_lines().last().unwrap(),
            "machine delete -n sbx-claude-proj -f"
        );
    }

    #[test]
    fn cleanup_failures_warn_and_keep_the_agent_status() {
        let mut t = test_env(&[]);
        created(&t, "running");
        t.ctx.vm.runner().interactive_exit(7);
        t.ctx
            .vm
            .runner()
            .fail(&["machine", "stop"], "SMOLVM_ERROR", "boom");
        assert_eq!(
            sbt(&mut t.ctx, &["run", "--name", "claude-proj"]).unwrap(),
            7
        );
        t.ctx
            .vm
            .runner()
            .fail(&["machine", "delete"], "SMOLVM_ERROR", "boom");
        assert_eq!(
            sbt(&mut t.ctx, &["run", "--rm", "--name", "claude-proj"]).unwrap(),
            7
        );
    }

    #[test]
    fn unsupported_flags_exit_2_even_without_a_usable_smolvm() {
        let mut t = test_env(&[]);
        t.ctx.vm.runner().ok(&["--version"], "smolvm 1.0.0\n");
        for args in [
            &["run", "claude", "--clone"][..],
            &["create", "claude", "--clone"][..],
            &["run", "claude", "--new"][..],
        ] {
            let err = sbt(&mut t.ctx, args).unwrap_err();
            assert_eq!(super::super::exit_code(&err), 2, "{args:?}: {err}");
        }
        assert!(t.ctx.vm.runner().calls().is_empty());
    }

    #[test]
    fn argument_errors() {
        let mut t = test_env(&[]);
        assert!(
            sbt(&mut t.ctx, &["run"])
                .unwrap_err()
                .to_string()
                .contains("specify an agent")
        );
        assert!(
            sbt(&mut t.ctx, &["run", "-d", "--rm", "claude"])
                .unwrap_err()
                .to_string()
                .contains("--rm")
        );
    }
}
