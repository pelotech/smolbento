//! `_upload-pack`: the fetch side of a clone sandbox's `sandbox-<name>` remote. git runs it with
//! the pack protocol on stdin/stdout, so nothing else may reach stdout and nothing may prompt.

use anyhow::{Result, bail};

use super::{Ctx, plan};
use crate::sandbox::{self, session};
use crate::smolvm::{ExecSpec, Runner};

pub fn run<R: Runner>(ctx: &mut Ctx<R>, sandbox: &str) -> Result<i32> {
    // stdin is git's pipe, but never ask (ensure_policy prompts on stdout).
    ctx.stdin_tty = false;
    let mut sb = sandbox::get(&ctx.vm, sandbox)?;
    let Some(dir) = sb.meta.clone_dir() else {
        bail!("sandbox '{sandbox}' isn't a clone sandbox");
    };
    let started = !sb.is_running();
    plan::ensure_running(ctx, &mut sb)?;
    let env = ctx
        .env
        .get("GIT_PROTOCOL")
        .map(|p| ("GIT_PROTOCOL".to_string(), p.clone()));
    let code = ctx.vm.exec(&ExecSpec {
        name: sb.machine.clone(),
        user: Some("agent".into()),
        env: env.into_iter().collect(),
        interactive: true,
        cmd: vec!["git-upload-pack".into(), dir],
        ..Default::default()
    })?;
    let sessions = ctx.paths.sessions();
    if started
        && !session::is_detached(&sessions, sb.name())
        && session::live_sessions(&sessions, sb.name()) == 0
        && let Err(e) = ctx.vm.stop(&sb.machine)
    {
        eprintln!("warning: stopping sandbox {}: {e:#}", sb.name());
    }
    Ok(code)
}

#[cfg(test)]
mod tests {
    use crate::cli::testutil::{TestEnv, machine_json, sbt, test_env};
    use crate::sandbox::session;

    fn clone_sandbox(t: &TestEnv, state: &str) {
        t.ctx.vm.runner().ok(
            &["machine", "status"],
            &machine_json(
                "sbx-box",
                state,
                &[
                    ("sbx.name", "box"),
                    ("sbx.agent", "shell"),
                    ("sbx.workspace", "/w/r"),
                    ("sbx.clone", "true"),
                ],
            ),
        );
    }

    #[test]
    fn pipes_git_upload_pack_with_the_protocol() {
        let mut t = test_env(&[("GIT_PROTOCOL", "version=2")]);
        clone_sandbox(&t, "running");
        t.ctx.vm.runner().interactive_exit(0);
        assert_eq!(
            sbt(&mut t.ctx, &["_upload-pack", "box", "/sbt/box"]).unwrap(),
            0
        );
        let calls = t.ctx.vm.runner().interactive_calls();
        assert_eq!(
            calls,
            vec![vec![
                "machine",
                "exec",
                "--name",
                "sbx-box",
                "-u",
                "agent",
                "-e",
                "GIT_PROTOCOL=version=2",
                "-i",
                "--",
                "git-upload-pack",
                "/w/r",
            ]]
        );
        assert!(
            !t.ctx
                .vm
                .runner()
                .call_lines()
                .iter()
                .any(|l| l.contains("machine stop"))
        );
    }

    #[test]
    fn starts_a_stopped_sandbox_and_stops_it_again() {
        let mut t = test_env(&[]);
        // Later registrations win: the catch-all goes first.
        t.ctx.vm.runner().ok(&["machine"], "");
        clone_sandbox(&t, "stopped");
        t.ctx.vm.runner().interactive_exit(0);
        sbt(&mut t.ctx, &["_upload-pack", "box", "/sbt/box"]).unwrap();
        let lines = t.ctx.vm.runner().call_lines();
        let start = lines
            .iter()
            .position(|l| l.contains("machine start"))
            .expect("started");
        let stop = lines
            .iter()
            .position(|l| l.contains("machine stop"))
            .expect("stopped");
        assert!(start < stop, "{lines:?}");
    }

    #[test]
    fn leaves_it_running_when_a_session_is_live() {
        let mut t = test_env(&[]);
        t.ctx.vm.runner().ok(&["machine"], "");
        clone_sandbox(&t, "stopped");
        t.ctx.vm.runner().interactive_exit(0);
        let _s = session::Session::register(&t.ctx.paths.sessions(), "box").unwrap();
        sbt(&mut t.ctx, &["_upload-pack", "box"]).unwrap();
        assert!(
            !t.ctx
                .vm
                .runner()
                .call_lines()
                .iter()
                .any(|l| l.contains("machine stop"))
        );
    }

    #[test]
    fn refuses_a_sandbox_that_isnt_a_clone() {
        let mut t = test_env(&[]);
        t.ctx.vm.runner().ok(
            &["machine", "status"],
            &machine_json(
                "sbx-box",
                "running",
                &[("sbx.name", "box"), ("sbx.workspace", "/w/r")],
            ),
        );
        let err = sbt(&mut t.ctx, &["_upload-pack", "box"])
            .unwrap_err()
            .to_string();
        assert!(err.contains("isn't a clone sandbox"), "{err}");
    }
}
