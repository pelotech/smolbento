//! exec and cp.

use std::path::Path;

use anyhow::{Context, Result, bail};

use super::{CpArgs, Ctx, ExecArgs, Unsupported};
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
    sandbox::ensure_running(&ctx.vm, &mut sb, ctx.uid)?;
    let user = if a.privileged {
        "root".to_string()
    } else {
        a.user.clone().unwrap_or_else(|| "agent".into())
    };
    let spec = ExecSpec {
        name: sb.machine.clone(),
        user: Some(user),
        workdir: Some(a.workdir.clone().unwrap_or_else(|| sb.workdir())),
        env: options::parse_env(&a.env, &a.env_file, &ctx.env)?,
        interactive: a.interactive,
        tty: a.tty,
        detach: false,
        cmd: a.command.clone(),
    };
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
    sandbox::ensure_running(&ctx.vm, &mut sb, ctx.uid)?;
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
                .contains(&"machine start -n sbx-claude-proj".to_string())
        );
        assert_eq!(
            t.ctx.vm.runner().interactive_calls()[0].join(" "),
            "machine exec --name sbx-claude-proj -u root -w /tmp -e HOSTVAR=h -- id"
        );
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
}
