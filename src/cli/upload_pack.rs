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
    let Some(dir) = sb.meta.clone.clone() else {
        bail!("sandbox '{sandbox}' isn't a clone sandbox");
    };
    let was_stopped = !sb.is_running();
    let sessions = ctx.paths.sessions();
    // Registered while git runs, so a concurrent `_upload-pack` won't stop the sandbox under it.
    let live = session::Session::register(&sessions, sb.name())?;
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
    });
    // Our own session must not keep the sandbox running.
    drop(live);
    // Re-stop a sandbox this command started even when the exec failed.
    if was_stopped
        && session::idle(&sessions, sb.name())
        && let Err(e) = ctx.vm.stop(&sb.machine)
    {
        eprintln!("warning: stopping sandbox {}: {e:#}", sb.name());
    }
    code
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

    /// A live session of another process (this test's parent), as a concurrent `_upload-pack`.
    fn other_session(t: &TestEnv) {
        let dir = t.ctx.paths.sessions().join("box");
        std::fs::create_dir_all(&dir).unwrap();
        let pid = std::os::unix::process::parent_id();
        std::fs::write(dir.join(pid.to_string()), b"").unwrap();
    }

    /// Whether smolvm got a `machine <cmd>` call.
    fn called(t: &TestEnv, cmd: &str) -> bool {
        t.ctx
            .vm
            .runner()
            .call_lines()
            .iter()
            .any(|l| l.contains(cmd))
    }

    fn stopped(t: &TestEnv) -> bool {
        called(t, "machine stop")
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
        assert!(!stopped(&t));
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
    fn stops_it_again_when_the_exec_fails() {
        let mut t = test_env(&[]);
        t.ctx.vm.runner().ok(&["machine"], "");
        clone_sandbox(&t, "stopped");
        t.ctx.vm.runner().interactive_fail("spawning smolvm: busy");
        let err = sbt(&mut t.ctx, &["_upload-pack", "box"])
            .unwrap_err()
            .to_string();
        assert!(err.contains("spawning smolvm"), "{err}");
        assert_eq!(
            t.ctx.vm.runner().call_lines().last().unwrap(),
            "machine stop -n sbx-box"
        );
    }

    #[test]
    fn overlapping_calls_leave_the_stop_to_the_last_one() {
        let mut t = test_env(&[]);
        t.ctx.vm.runner().ok(&["machine"], "");
        clone_sandbox(&t, "stopped");
        t.ctx.vm.runner().interactive_exit(0);
        // Another `_upload-pack` is mid-fetch: it registered its session before this one started.
        other_session(&t);
        sbt(&mut t.ctx, &["_upload-pack", "box"]).unwrap();
        assert!(!stopped(&t));
        // Only the other session is left; ours is gone.
        assert_eq!(session::live_sessions(&t.ctx.paths.sessions(), "box"), 1);
        // Once it's done, the next call stops the sandbox it started.
        session::clear(&t.ctx.paths.sessions(), "box");
        sbt(&mut t.ctx, &["_upload-pack", "box"]).unwrap();
        assert!(stopped(&t));
    }

    #[test]
    fn a_detached_session_suppresses_the_stop() {
        let mut t = test_env(&[]);
        t.ctx.vm.runner().ok(&["machine"], "");
        clone_sandbox(&t, "stopped");
        t.ctx.vm.runner().interactive_exit(0);
        session::mark_detached(&t.ctx.paths.sessions(), "box").unwrap();
        sbt(&mut t.ctx, &["_upload-pack", "box"]).unwrap();
        assert!(!stopped(&t));
    }

    #[test]
    fn returns_a_non_zero_upload_pack_exit() {
        let mut t = test_env(&[]);
        clone_sandbox(&t, "running");
        t.ctx.vm.runner().interactive_exit(3);
        assert_eq!(sbt(&mut t.ctx, &["_upload-pack", "box"]).unwrap(), 3);
    }

    #[test]
    fn passes_no_env_without_a_git_protocol() {
        let mut t = test_env(&[]);
        clone_sandbox(&t, "running");
        t.ctx.vm.runner().interactive_exit(0);
        sbt(&mut t.ctx, &["_upload-pack", "box"]).unwrap();
        let calls = t.ctx.vm.runner().interactive_calls();
        assert!(!calls[0].contains(&"-e".to_string()), "{calls:?}");
    }

    #[test]
    fn never_prompts_for_a_policy_even_on_a_terminal() {
        let mut t = test_env(&[]);
        std::fs::remove_file(t.ctx.paths.policy_file()).unwrap();
        t.ctx.stdin_tty = true;
        clone_sandbox(&t, "stopped");
        let err = sbt(&mut t.ctx, &["_upload-pack", "box"])
            .unwrap_err()
            .to_string();
        assert!(err.contains("sbt policy init"), "{err}");
        assert!(t.ctx.vm.runner().interactive_calls().is_empty());
        assert!(!called(&t, "machine start"));
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
