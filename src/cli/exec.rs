//! exec and cp.

use std::path::Path;

use anyhow::{Context, Result, bail};

use super::plan;
use super::{CpArgs, Ctx, ExecArgs, Unsupported};
use crate::bridge;
use crate::sandbox::{self, name, options};
use crate::smolvm::{ExecSpec, Runner};

pub fn exec<R: Runner>(ctx: &mut Ctx<R>, a: &ExecArgs) -> Result<i32> {
    if a.detach {
        return Err(Unsupported("exec -d is not supported (as in sbx)".into()).into());
    }
    if a.detach_keys.is_some() {
        return Err(Unsupported("--detach-keys is not supported".into()).into());
    }
    let mut sb = sandbox::get(&ctx.vm, &a.sandbox)?;
    plan::ensure_running(ctx, &mut sb)?;
    let user = if a.privileged {
        "root".to_string()
    } else {
        // A v3 workload's image user, as sbx; else `agent`.
        match &a.user {
            Some(u) => u.clone(),
            None => sandbox::launch_user(&ctx.vm, &sb).unwrap_or_else(|| "agent".into()),
        }
    };
    let mut env = options::parse_env(&a.env, &a.env_file, &ctx.env)?;
    sandbox::env::session_tz(&ctx.env, a.tty, &mut env);
    let spec = ExecSpec {
        name: sb.machine.clone(),
        user: Some(user),
        workdir: Some(a.workdir.clone().unwrap_or_else(|| sb.workdir())),
        env,
        interactive: a.interactive,
        tty: a.tty,
        detach: false,
        cmd: a.command.clone(),
    };
    // `exec -it` is an attached session: serve the browser and clipboard bridge during it.
    let _bridge = if a.interactive && a.tty {
        bridge::attach(&ctx.env, &ctx.settings, &sb)
    } else {
        None
    };
    // A runtime `ssh-agent@1` grant is served for every exec (`git commit -S` runs this way too).
    let _agent = bridge::filter::attach(&ctx.env, &ctx.paths, &sb);
    ctx.vm.exec(&spec)
}

/// `SANDBOX:/abs/path` -> (sandbox, path). Anything else is a host path.
fn sandbox_path(arg: &str) -> Option<(&str, &str)> {
    let (sandbox, path) = arg.split_once(':')?;
    (!sandbox.is_empty() && !sandbox.contains('/')).then_some((sandbox, path))
}

pub fn cp<R: Runner>(ctx: &mut Ctx<R>, a: &CpArgs) -> Result<i32> {
    let (sandbox_name, guest_path, sandbox_is_src) = match (
        sandbox_path(&a.src),
        sandbox_path(&a.dst),
    ) {
        (Some((s, p)), None) => (s, p, true),
        (None, Some((s, p))) => (s, p, false),
        _ => bail!(
            "one of SRC and DST must be SANDBOX:/path (copying between sandboxes is not supported)"
        ),
    };
    if !guest_path.starts_with('/') {
        bail!("sandbox paths must be absolute: {sandbox_name}:{guest_path}");
    }
    let mut sb = sandbox::get(&ctx.vm, sandbox_name)?;
    plan::ensure_running(ctx, &mut sb)?;
    let guest = format!("{}:{guest_path}", name::machine_name(sandbox_name));
    if sandbox_is_src {
        ctx.vm.cp(&guest, &a.dst)?;
    } else {
        let src = if a.follow_link {
            Path::new(&a.src)
                .canonicalize()
                .with_context(|| format!("{} does not exist", a.src))?
                .display()
                .to_string()
        } else {
            a.src.clone()
        };
        ctx.vm.cp(&src, &guest)?;
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::super::testutil::*;

    fn running(t: &TestEnv) {
        t.ctx.vm.runner().ok(
            &["machine", "status"],
            &machine_json(
                "sbx-claude-proj",
                "running",
                &[("sbx.name", "claude-proj"), ("sbx.workspace", "/w/proj")],
            ),
        );
    }

    #[test]
    fn exec_defaults_to_agent_in_the_workspace() {
        let mut t = test_env(&[]);
        running(&t);
        t.ctx.vm.runner().interactive_exit(7);
        assert_eq!(
            sbt(&mut t.ctx, &["exec", "-it", "claude-proj", "ls", "-la"]).unwrap(),
            7
        );
        assert_eq!(
            t.ctx.vm.runner().interactive_calls()[0].join(" "),
            "machine exec --name sbx-claude-proj -u agent -w /w/proj -i -t -- ls -la"
        );
    }

    #[test]
    fn exec_defaults_to_a_v3_workloads_image_user() {
        let mut t = test_env(&[]);
        t.ctx.vm.runner().ok(
            &["machine", "status"],
            &machine_json(
                "sbx-tool-proj",
                "running",
                &[
                    ("sbx.name", "tool-proj"),
                    ("sbx.workspace", "/w/proj"),
                    ("sbx.user", "somebody"),
                ],
            ),
        );
        sbt(&mut t.ctx, &["exec", "tool-proj", "id"]).unwrap();
        // A numeric image user runs as the account the start recorded for it.
        t.ctx.vm.runner().ok(
            &["machine", "status"],
            &machine_json(
                "sbx-tool-proj",
                "running",
                &[
                    ("sbx.name", "tool-proj"),
                    ("sbx.workspace", "/w/proj"),
                    ("sbx.user", "1001:1001"),
                ],
            ),
        );
        t.ctx.vm.runner().download(b"somebody\n");
        sbt(&mut t.ctx, &["exec", "tool-proj", "id"]).unwrap();
        sbt(&mut t.ctx, &["exec", "-u", "root", "tool-proj", "id"]).unwrap();
        let calls: Vec<String> = t
            .ctx
            .vm
            .runner()
            .interactive_calls()
            .iter()
            .map(|c| c.join(" "))
            .collect();
        assert_eq!(
            calls,
            [
                "machine exec --name sbx-tool-proj -u somebody -w /w/proj -- id",
                "machine exec --name sbx-tool-proj -u somebody:1001 -w /w/proj -- id",
                "machine exec --name sbx-tool-proj -u root -w /w/proj -- id",
            ]
        );
    }

    #[test]
    fn exec_privileged_env_and_starts_stopped() {
        let mut t = test_env(&[("HOSTVAR", "h")]);
        t.ctx.vm.runner().ok(
            &["machine", "status"],
            &machine_json("sbx-claude-proj", "stopped", &[("sbx.name", "claude-proj")]),
        );
        sbt(
            &mut t.ctx,
            &[
                "exec",
                "--privileged",
                "-e",
                "HOSTVAR",
                "-w",
                "/tmp",
                "claude-proj",
                "id",
            ],
        )
        .unwrap();
        assert!(
            t.ctx
                .vm
                .runner()
                .call_lines()
                .contains(&"machine start -n sbx-claude-proj --branchable".to_string())
        );
        assert_eq!(
            t.ctx.vm.runner().interactive_calls()[0].join(" "),
            "machine exec --name sbx-claude-proj -u root -w /tmp -e HOSTVAR=h -- id"
        );
    }

    #[test]
    fn exec_passes_the_host_tz_only_with_a_tty() {
        for (flags, want) in [(&["-it"][..], true), (&["-i"][..], false)] {
            let mut t = test_env(&[("TZ", "Asia/Kolkata")]);
            t.ctx.vm.runner().ok(
                &["machine", "status"],
                &machine_json("sbx-claude-proj", "running", &[("sbx.name", "claude-proj")]),
            );
            let mut args = vec!["exec"];
            args.extend(flags);
            args.extend(["claude-proj", "id"]);
            sbt(&mut t.ctx, &args).unwrap();
            let line = t.ctx.vm.runner().interactive_calls()[0].join(" ");
            assert_eq!(line.contains(" -e TZ=Asia/Kolkata"), want, "{line}");
        }
    }

    #[test]
    fn exec_detach_is_unsupported() {
        let mut t = test_env(&[]);
        running(&t);
        let err = sbt(&mut t.ctx, &["exec", "-d", "claude-proj", "true"]).unwrap_err();
        assert_eq!(super::super::exit_code(&err), 2);
    }

    #[test]
    fn cp_rewrites_sandbox_paths() {
        let mut t = test_env(&[]);
        running(&t);
        sbt(&mut t.ctx, &["cp", "./file", "claude-proj:/tmp/file"]).unwrap();
        sbt(&mut t.ctx, &["cp", "claude-proj:/etc/hosts", "./hosts"]).unwrap();
        let cps: Vec<String> = t
            .ctx
            .vm
            .runner()
            .call_lines()
            .into_iter()
            .filter(|l| l.contains(" cp "))
            .collect();
        assert_eq!(
            cps,
            vec![
                "machine cp ./file sbx-claude-proj:/tmp/file",
                "machine cp sbx-claude-proj:/etc/hosts ./hosts"
            ]
        );
    }

    #[test]
    fn cp_rules() {
        let mut t = test_env(&[]);
        running(&t);
        assert!(
            sbt(&mut t.ctx, &["cp", "a", "b"])
                .unwrap_err()
                .to_string()
                .contains("one of")
        );
        assert!(
            sbt(&mut t.ctx, &["cp", "claude-proj:/a", "claude-proj:/b"])
                .unwrap_err()
                .to_string()
                .contains("one of")
        );
        assert!(
            sbt(&mut t.ctx, &["cp", "a", "claude-proj:rel"])
                .unwrap_err()
                .to_string()
                .contains("absolute")
        );
    }

    #[test]
    fn exec_it_serves_the_bridge_while_attached() {
        let mut t = test_env(&[]);
        let (name, seen) = bridge_probe(&t, "exec", true);
        sbt(&mut t.ctx, &["exec", "-it", &name, "sh"]).unwrap();
        // Without a terminal it isn't an attached session.
        sbt(&mut t.ctx, &["exec", "-i", &name, "sh"]).unwrap();
        sbt(&mut t.ctx, &["exec", &name, "true"]).unwrap();
        assert_eq!(*seen.borrow(), vec![true, false, false]);
        assert!(!crate::bridge::host_socket(&name).exists());
    }

    #[test]
    fn every_exec_serves_a_runtime_ssh_agent_grant() {
        let mut t = test_env(&[]);
        let (name, seen) = agent_probe(&t, "exec", Some(r#"{"runtime":{"sign":null}}"#));
        sbt(&mut t.ctx, &["exec", "-it", &name, "sh"]).unwrap();
        sbt(&mut t.ctx, &["exec", "-i", &name, "sh"]).unwrap();
        sbt(&mut t.ctx, &["exec", &name, "git", "commit"]).unwrap();
        assert_eq!(*seen.borrow(), vec![true, true, true]);
        // Stopped with the exec.
        assert!(!crate::bridge::agent_socket(&name).exists());
    }

    #[test]
    fn exec_serves_no_ssh_agent_without_a_runtime_grant() {
        for (tag, grant) in [
            ("none", None),
            ("install", Some(r#"{"install":{"sign":null}}"#)),
        ] {
            let mut t = test_env(&[]);
            let (name, seen) = agent_probe(&t, tag, grant);
            sbt(&mut t.ctx, &["exec", "-it", &name, "sh"]).unwrap();
            sbt(&mut t.ctx, &["exec", &name, "true"]).unwrap();
            assert_eq!(*seen.borrow(), vec![false, false], "{tag}");
        }
    }

    #[test]
    fn exec_it_serves_no_bridge_for_an_unlabelled_sandbox() {
        let mut t = test_env(&[]);
        let (name, seen) = bridge_probe(&t, "exec", false);
        sbt(&mut t.ctx, &["exec", "-it", &name, "sh"]).unwrap();
        assert_eq!(*seen.borrow(), vec![false]);
    }

    #[test]
    fn exec_it_serves_no_bridge_over_ssh_without_a_display() {
        let mut t = test_env(&[("SSH_CONNECTION", "10.0.0.1 50000 10.0.0.2 22")]);
        let (name, seen) = bridge_probe(&t, "exec", true);
        sbt(&mut t.ctx, &["exec", "-it", &name, "sh"]).unwrap();
        assert_eq!(*seen.borrow(), vec![false]);
    }
}
