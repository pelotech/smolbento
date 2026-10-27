//! run: create the sandbox if needed, start it, attach to the agent, and stop it when the last
//! session ends (unless it was started with -d).

use std::path::Path;

use anyhow::{Context, Result, bail};

use super::lifecycle::{build_request, resolve_clone};
use super::plan;
use super::{Ctx, RunArgs, Unsupported};
use crate::agents;
use crate::sandbox::{self, Sandbox, session};
use crate::smolvm::{ExecSpec, Runner};
use crate::workspace::clone;

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
                    resolve_clone(&mut req, &a.opts)?;
                    (plan::create(ctx, &mut req, &a.opts.deny_network)?, true)
                }
            }
        }
    };
    if !a.opts.deny_network.is_empty() && !created {
        eprintln!(
            "warning: --deny-network only adds rules when a sandbox is created; {} already exists \
             (use `sbt policy deny network --sandbox {}`)",
            sb.name(),
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

    // Fetch before `--rm` deletes the sandbox, and while it still runs for `_upload-pack`.
    if fetch_on_exit(ctx, &sb)
        && let Some(repo) = &sb.meta.clone
        && let Err(e) = clone::fetch(Path::new(repo), sb.name())
    {
        eprintln!("warning: fetching the agent's commits: {e:#}");
    }

    // The agent's exit code is the result; failing to clean up after it only warrants a warning.
    if a.rm {
        match ctx.vm.delete(&sb.machine) {
            Ok(()) => session::clear(&sessions, sb.name()),
            Err(e) => eprintln!("warning: removing sandbox {}: {e:#}", sb.name()),
        }
    } else if session::idle(&sessions, sb.name())
        && let Err(e) = ctx.vm.stop(&sb.machine)
    {
        eprintln!("warning: stopping sandbox {}: {e:#}", sb.name());
    }
    Ok(code)
}

/// A bad setting value only skips the fetch: the stop or `--rm` and the agent's status still apply.
fn fetch_on_exit<R: Runner>(ctx: &Ctx<R>, sb: &Sandbox) -> bool {
    sb.meta.clone.is_some()
        && ctx
            .settings
            .bool("clone.fetch-on-exit")
            .unwrap_or_else(|e| {
                eprintln!("warning: not fetching the agent's commits: {e:#}");
                false
            })
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
    fn clone_is_ignored_when_run_attaches_to_an_existing_sandbox() {
        let mut t = test_env(&[]);
        created(&t, "running");
        t.ctx.vm.runner().interactive_exit(0);
        // cwd is not a git repo, yet --clone must not matter for an existing sandbox.
        sbt(&mut t.ctx, &["run", "claude", "--clone"]).unwrap();
        assert!(
            !t.ctx
                .vm
                .runner()
                .call_lines()
                .iter()
                .any(|l| l.contains("machine create"))
        );
    }

    #[test]
    fn creates_attaches_and_stops_after_the_last_session() {
        let mut t = test_env(&[]);
        created(&t, "created");
        // run looks the name up, then plan::create checks again before creating.
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
    fn a_failed_create_does_not_leave_deny_rules_behind() {
        let mut t = test_env(&[]);
        let fake = t.ctx.vm.runner();
        fake.fail(&["machine", "status"], "NOT_FOUND", "vm not found");
        fake.fail(&["machine", "create"], "CREATE_FAILED", "no space left");
        assert!(sbt(&mut t.ctx, &["run", "claude", "--deny-network", "evil.com"]).is_err());
        let p = crate::policy::Policy::load(&t.ctx.paths).unwrap();
        assert!(p.sandboxes.is_empty(), "{p:?}");
    }

    #[test]
    fn deny_network_adds_sandbox_deny_rules_at_create() {
        let mut t = test_env(&[]);
        created(&t, "created");
        // run looks the name up, then plan::create checks again before creating.
        for _ in 0..2 {
            t.ctx
                .vm
                .runner()
                .once_fail(&["machine", "status"], "NOT_FOUND", "vm not found");
        }
        t.ctx.vm.runner().interactive_exit(0);
        sbt(
            &mut t.ctx,
            &[
                "run",
                "claude",
                "--deny-network",
                "a.example,b.example",
                "--deny-network",
                "c.example",
            ],
        )
        .unwrap();
        let p = crate::policy::Policy::load(&t.ctx.paths).unwrap();
        let rules: Vec<Vec<String>> = p.sandboxes["claude-proj"]
            .rules
            .iter()
            .map(|r| {
                assert_eq!(r.decision, crate::policy::Decision::Deny);
                r.resources.clone()
            })
            .collect();
        assert_eq!(
            rules,
            vec![
                vec!["a.example".to_string()],
                vec!["b.example".to_string()],
                vec!["c.example".to_string()]
            ]
        );
        assert!(p.rules.is_empty());
    }

    #[test]
    fn running_an_existing_sandbox_records_nothing_and_starting_it_needs_a_policy() {
        let mut t = test_env(&[]);
        std::fs::remove_file(t.ctx.paths.policy_file()).unwrap();
        created(&t, "running");
        t.ctx.vm.runner().interactive_exit(0);
        assert_eq!(
            sbt(&mut t.ctx, &["run", "claude", "--deny-network", "evil.com"]).unwrap(),
            0
        );
        assert!(!t.ctx.paths.policy_file().exists());
        let lines = t.ctx.vm.runner().call_lines();
        assert!(!lines.iter().any(|l| l.contains("create")), "{lines:?}");

        // A stopped one has to start, and every start needs a policy.
        let mut t = test_env(&[]);
        std::fs::remove_file(t.ctx.paths.policy_file()).unwrap();
        created(&t, "stopped");
        let err = sbt(&mut t.ctx, &["run", "claude", "--deny-network", "evil.com"])
            .unwrap_err()
            .to_string();
        assert!(err.contains("sbt policy init"), "{err}");
        assert!(!t.ctx.paths.policy_file().exists());
        let lines = t.ctx.vm.runner().call_lines();
        assert!(
            !lines
                .iter()
                .any(|l| l.contains("create") || l.contains("start")),
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
            &["run", "claude", "--kit", "x"][..],
            &["create", "claude", "--kit", "x"][..],
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

    fn clone_sandbox(t: &TestEnv, ws: &std::path::Path) {
        t.ctx.vm.runner().ok(
            &["machine", "status"],
            &machine_json(
                "sbx-claude-proj",
                "running",
                &[
                    ("sbx.name", "claude-proj"),
                    ("sbx.agent", "claude"),
                    ("sbx.workspace", &ws.display().to_string()),
                    ("sbx.clone", "true"),
                ],
            ),
        );
    }

    #[test]
    fn a_failed_fetch_warns_and_keeps_the_agent_status_and_the_stop() {
        let mut t = test_env(&[]);
        // The remote's upload-pack records that the fetch ran, then fails it.
        let (_keep, repo) = temp_repo();
        let marker = repo.parent().unwrap().join("fetch-ran");
        git(
            &repo,
            &[
                "remote",
                "add",
                "sandbox-claude-proj",
                "file:///sbt/claude-proj",
            ],
        );
        git(
            &repo,
            &[
                "config",
                "remote.sandbox-claude-proj.uploadpack",
                &format!("touch '{}'; exit 1 #", marker.display()),
            ],
        );
        clone_sandbox(&t, &repo);
        t.ctx.vm.runner().interactive_exit(5);
        assert_eq!(
            sbt(&mut t.ctx, &["run", "--name", "claude-proj"]).unwrap(),
            5
        );
        assert!(marker.exists(), "the fetch was never attempted");
        assert_eq!(
            t.ctx.vm.runner().call_lines().last().unwrap(),
            "machine stop -n sbx-claude-proj"
        );
    }

    #[test]
    fn fetch_on_exit_needs_a_clone_and_the_setting() {
        let (_keep, repo) = temp_repo();
        for (env, clone, want) in [
            (&[][..], true, true),
            (
                &[("SMOLBENTO_CLONE_FETCH_ON_EXIT", "false")][..],
                true,
                false,
            ),
            (&[][..], false, false),
        ] {
            let t = test_env(env);
            if clone {
                clone_sandbox(&t, &repo);
            } else {
                created(&t, "running");
            }
            let sb = crate::sandbox::find(&t.ctx.vm, "claude-proj")
                .unwrap()
                .unwrap();
            assert_eq!(super::fetch_on_exit(&t.ctx, &sb), want);
        }
    }

    #[test]
    fn a_bad_fetch_setting_skips_the_fetch_but_not_the_rm() {
        let mut t = test_env(&[("SMOLBENTO_CLONE_FETCH_ON_EXIT", "yes")]);
        let (_keep, repo) = temp_repo();
        clone_sandbox(&t, &repo);
        t.ctx.vm.runner().interactive_exit(3);
        assert_eq!(
            sbt(&mut t.ctx, &["run", "--rm", "--name", "claude-proj"]).unwrap(),
            3
        );
        assert_eq!(
            t.ctx.vm.runner().call_lines().last().unwrap(),
            "machine delete -n sbx-claude-proj -f"
        );
    }
}
