//! exec and cp.

use std::path::Path;

use anyhow::{Context, Result, bail};

use super::{CpArgs, Ctx, ExecArgs};
use crate::bridge;
use crate::provision;
use crate::sandbox::{self, name, options};
use crate::smolvm::{ExecSpec, Runner};

pub fn exec<R: Runner>(ctx: &mut Ctx<R>, a: &ExecArgs) -> Result<i32> {
    let f = &a.flags;
    super::refuse_as(&[(f.detach, "exec -d")], "is not supported (as in sbx)")?;
    super::refuse_as(
        &[(f.detach_keys.is_some(), "--detach-keys")],
        "is not supported",
    )?;
    let mut sb = sandbox::get(&ctx.vm, &a.sandbox)?;
    provision::ensure_running(ctx, &mut sb)?;
    let user = if f.privileged {
        "root".to_string()
    } else {
        // A v3 workload's image user, as sbx; else `agent`.
        f.user
            .clone()
            .unwrap_or_else(|| sb.meta.rec.session_user().to_string())
    };
    let mut env = options::parse_env(&f.env, &f.env_file, &ctx.env)?;
    sandbox::env::session_env(&ctx.env, f.tty, sb.meta.bridge, &mut env);
    let spec = ExecSpec {
        name: sb.machine.clone(),
        user: Some(user),
        workdir: Some(f.workdir.clone().unwrap_or_else(|| sb.workdir())),
        env,
        interactive: f.interactive,
        tty: f.tty,
        // Without stdin or a TTY smolvm buffers the output until the command ends and fails it
        // past 11 MiB; streamed, it arrives as it's written and has no cap.
        stream: !f.interactive && !f.tty,
        timeout: None,
        cmd: a.command.clone(),
    };
    // `exec -it` is an attached session: serve the browser and clipboard bridge during it.
    let _bridge = if f.interactive && f.tty {
        bridge::attach(&ctx.env, &ctx.settings, &ctx.smolvm, &sb)
    } else {
        None
    };
    // A runtime `ssh-agent@1` grant is served for every exec (`git commit -S` runs this way too).
    let _agent = crate::ssh_agent::filter::attach(&ctx.env, &ctx.paths, &sb);
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
    provision::ensure_running(ctx, &mut sb)?;
    let guest = format!("{}:{guest_path}", name::machine_name(sandbox_name));
    if sandbox_is_src {
        // smolvm's cp downloads single files only: a directory comes out as an archive.
        if ctx.vm.is_dir(&sb.machine, guest_path) {
            copy_dir_out(ctx, &sb.machine, guest_path, &ctx.cwd.join(&a.dst))?;
        } else {
            ctx.vm.cp(&guest, &a.dst)?;
        }
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

/// Copies the sandbox's directory `src` to the host as `docker cp` does: as `dst` when that
/// doesn't exist, else into it as `dst/<name>`. It never merges into an existing directory. The
/// archive comes from the guest, so it's unpacked into a fresh directory by the `tar` crate,
/// which keeps every entry inside it, and moved into place only whole.
fn copy_dir_out<R: Runner>(ctx: &Ctx<R>, machine: &str, src: &str, dst: &Path) -> Result<()> {
    let target = if dst.is_dir() {
        let name = Path::new(src)
            .file_name()
            .with_context(|| format!("can't copy {src} into a directory: it has no name"))?;
        dst.join(name)
    } else if dst.exists() {
        bail!(
            "can't copy the directory {src} to the file {}",
            dst.display()
        );
    } else {
        dst.to_path_buf()
    };
    if target.exists() {
        bail!(
            "{} already exists; bento cp doesn't copy a directory into an existing one",
            target.display()
        );
    }
    let parent = target
        .parent()
        .with_context(|| format!("{} has no parent directory", target.display()))?;
    let staging = tempfile::Builder::new()
        .prefix(".bento-cp-")
        .tempdir_in(parent)
        .with_context(|| format!("creating a temp dir in {}", parent.display()))?;
    let archive = staging.path().join("archive.tar");
    ctx.vm
        .archive(machine, src, &archive)
        .with_context(|| format!("copying {src} out of the sandbox"))?;
    let tree = staging.path().join("tree");
    std::fs::create_dir(&tree).with_context(|| format!("creating {}", tree.display()))?;
    let file =
        std::fs::File::open(&archive).with_context(|| format!("opening {}", archive.display()))?;
    tar::Archive::new(file)
        .unpack(&tree)
        .with_context(|| format!("unpacking {src}"))?;
    std::fs::rename(&tree, &target).with_context(|| format!("moving {src} to {}", target.display()))
}

#[cfg(test)]
mod tests {
    use crate::testutil::*;

    #[test]
    fn exec_defaults_to_agent_in_the_workspace() {
        let mut t = test_env(&[]);
        t.running_proj();
        t.runner().interactive_exit(7);
        assert_eq!(
            t.sbt(&["exec", "-it", "claude-proj", "ls", "-la"]).unwrap(),
            7
        );
        assert_eq!(
            t.runner().interactive_calls()[0].join(" "),
            "machine exec --name sbx-claude-proj -u agent -w /w/proj -i -t -- ls -la"
        );
    }

    #[test]
    fn exec_defaults_to_a_v3_workloads_image_user() {
        let mut t = test_env(&[]);
        t.machine(
            "sbx-tool-proj",
            "running",
            &[
                ("sbx.name", "tool-proj"),
                ("sbx.workspace", "/w/proj"),
                ("sbx.user", "somebody"),
            ],
        );
        t.sbt(&["exec", "tool-proj", "id"]).unwrap();
        // A numeric image user stays as given (its uid is no longer moved). Mountless, it works
        // in the image's WORKDIR (tck: sbx@1/workspace-at-workdir).
        t.machine(
            "sbx-tool-proj",
            "running",
            &[
                ("sbx.name", "tool-proj"),
                ("sbx.workdir", "/img/wd"),
                ("sbx.user", "1001:1001"),
            ],
        );
        t.sbt(&["exec", "tool-proj", "id"]).unwrap();
        t.sbt(&["exec", "-u", "root", "tool-proj", "id"]).unwrap();
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
                "machine exec --name sbx-tool-proj -u somebody -w /w/proj --stream -- id",
                "machine exec --name sbx-tool-proj -u 1001:1001 -w /img/wd --stream -- id",
                "machine exec --name sbx-tool-proj -u root -w /img/wd --stream -- id",
            ]
        );
    }

    #[test]
    fn exec_privileged_env_and_starts_stopped() {
        let mut t = test_env(&[("HOSTVAR", "h")]);
        t.machine("sbx-claude-proj", "stopped", &[("sbx.name", "claude-proj")]);
        t.sbt(&[
            "exec",
            "--privileged",
            "-e",
            "HOSTVAR",
            "-w",
            "/tmp",
            "claude-proj",
            "id",
        ])
        .unwrap();
        assert!(
            t.calls()
                .contains(&"machine start -n sbx-claude-proj --branchable".to_string())
        );
        assert_eq!(
            t.runner().interactive_calls()[0].join(" "),
            "machine exec --name sbx-claude-proj -u root -w /tmp -e HOSTVAR=h --stream -- id"
        );
    }

    #[test]
    fn exec_passes_the_host_tz_only_with_a_tty() {
        for (flags, want) in [(&["-it"][..], true), (&["-i"][..], false)] {
            let mut t = test_env(&[("TZ", "Asia/Kolkata")]);
            t.machine("sbx-claude-proj", "running", &[("sbx.name", "claude-proj")]);
            let mut args = vec!["exec"];
            args.extend(flags);
            args.extend(["claude-proj", "id"]);
            t.sbt(&args).unwrap();
            let line = t.runner().interactive_calls()[0].join(" ");
            assert_eq!(line.contains(" -e TZ=Asia/Kolkata"), want, "{line}");
        }
    }

    #[test]
    fn exec_passes_the_host_terminal_and_points_browser_at_the_bridge() {
        // Without these an agent prints a login URL as plain, hard-wrapped text and never
        // opens the browser.
        let mut t = test_env(&[("TERM_PROGRAM", "iTerm.app"), ("COLORTERM", "truecolor")]);
        t.machine(
            "sbx-claude-proj",
            "running",
            &[("sbx.name", "claude-proj"), ("sbx.bridge", "true")],
        );
        t.sbt(&["exec", "-i", "claude-proj", "id"]).unwrap();
        let line = t.runner().interactive_calls()[0].join(" ");
        assert!(line.contains(" -e BROWSER=xdg-open"), "{line}");
        assert!(
            !line.contains("TERM_PROGRAM"),
            "no TTY, no terminal: {line}"
        );
    }

    #[test]
    fn exec_tty_passes_the_host_terminal() {
        let mut t = test_env(&[("TERM_PROGRAM", "iTerm.app"), ("COLORTERM", "truecolor")]);
        t.running_proj();
        t.sbt(&["exec", "-it", "claude-proj", "id"]).unwrap();
        let line = t.runner().interactive_calls()[0].join(" ");
        assert!(line.contains(" -e TERM_PROGRAM=iTerm.app"), "{line}");
        assert!(line.contains(" -e COLORTERM=truecolor"), "{line}");
        assert!(!line.contains("BROWSER"), "no bridge, no BROWSER: {line}");
    }

    #[test]
    fn exec_detach_is_unsupported() {
        let mut t = test_env(&[]);
        t.running_proj();
        let err = t.sbt(&["exec", "-d", "claude-proj", "true"]).unwrap_err();
        assert_eq!(super::super::exit_code(&err), 2);
    }

    /// `machine files list` lists directories only: anything else is a file.
    fn not_a_dir(t: &TestEnv) {
        t.runner().fail(
            &["machine", "files", "--name", "sbx-claude-proj", "list"],
            "SMOLVM_ERROR",
            "not a directory",
        );
    }

    /// A tar of `entries` (path, content), as `machine files archive` sends a directory.
    fn tar_of(entries: &[(&str, &str)]) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        for (path, content) in entries {
            let mut h = tar::Header::new_gnu();
            h.set_size(content.len() as u64);
            h.set_mode(0o644);
            b.append_data(&mut h, path, content.as_bytes()).unwrap();
        }
        b.into_inner().unwrap()
    }

    #[test]
    fn cp_rewrites_sandbox_paths() {
        let mut t = test_env(&[]);
        t.running_proj();
        not_a_dir(&t);
        t.sbt(&["cp", "./file", "claude-proj:/tmp/file"]).unwrap();
        t.sbt(&["cp", "claude-proj:/etc/hosts", "./hosts"]).unwrap();
        let cps: Vec<String> = t
            .calls()
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

    /// A directory comes out as an archive, unpacked as `docker cp` places it: as DST when DST
    /// doesn't exist, else into DST under its own name.
    #[test]
    fn cp_copies_a_directory_out() {
        let mut t = test_env(&[]);
        t.running_proj();
        t.runner()
            .download(&tar_of(&[("./a.txt", "one"), ("./sub/b.txt", "two")]));
        let out = t.ctx.cwd.join("out");
        t.sbt(&["cp", "claude-proj:/w/proj/src", "out"]).unwrap();
        assert_eq!(std::fs::read_to_string(out.join("a.txt")).unwrap(), "one");
        assert_eq!(
            std::fs::read_to_string(out.join("sub/b.txt")).unwrap(),
            "two"
        );
        assert!(
            t.calls().iter().any(
                |l| l.starts_with("machine files --name sbx-claude-proj archive /w/proj/src /")
            ),
            "{:?}",
            t.calls()
        );

        // Into an existing directory: under the source's name.
        t.sbt(&["cp", "claude-proj:/w/proj/src", "out"]).unwrap();
        assert_eq!(
            std::fs::read_to_string(out.join("src/a.txt")).unwrap(),
            "one"
        );

        // Never merged into an existing copy, and no temp dir is left behind.
        let err = t.sbt_err(&["cp", "claude-proj:/w/proj/src", "out"]);
        assert!(err.contains("already exists"), "{err}");
        let leftovers: Vec<_> = std::fs::read_dir(&out)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .filter(|n| n.to_string_lossy().starts_with(".bento-cp-"))
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
    }

    #[test]
    fn cp_refuses_a_directory_onto_a_file() {
        let mut t = test_env(&[]);
        t.running_proj();
        t.runner().download(&tar_of(&[("./a.txt", "one")]));
        std::fs::write(t.ctx.cwd.join("file"), "x").unwrap();
        let err = t.sbt_err(&["cp", "claude-proj:/w/proj/src", "file"]);
        assert!(err.contains("to the file"), "{err}");
        assert_eq!(
            std::fs::read_to_string(t.ctx.cwd.join("file")).unwrap(),
            "x"
        );
    }

    /// The guest makes the archive: an entry that climbs out of the copy, or writes through a
    /// link the archive itself planted, lands nowhere outside it.
    #[test]
    fn cp_keeps_a_hostile_archive_inside_the_copy() {
        let mut t = test_env(&[]);
        t.running_proj();
        let outside = t.ctx.cwd.join("outside");
        std::fs::create_dir(&outside).unwrap();

        let mut b = tar::Builder::new(Vec::new());
        // `../escaped`: written raw, as the tar crate won't build such a path itself.
        let mut h = tar::Header::new_old();
        h.as_old_mut().name[..10].copy_from_slice(b"../escaped");
        h.set_size(1);
        h.set_mode(0o644);
        h.set_cksum();
        b.append(&h, &b"x"[..]).unwrap();
        // A link to `outside`, then a file written through it.
        let mut l = tar::Header::new_gnu();
        l.set_entry_type(tar::EntryType::Symlink);
        l.set_size(0);
        b.append_link(&mut l, "./link", &outside).unwrap();
        let mut f = tar::Header::new_gnu();
        f.set_size(1);
        f.set_mode(0o644);
        b.append_data(&mut f, "./link/planted", &b"x"[..]).unwrap();
        t.runner().download(&b.into_inner().unwrap());

        let err = t.sbt_err(&["cp", "claude-proj:/w/proj/src", "out"]);
        assert!(err.contains("unpacking /w/proj/src"), "{err}");
        assert!(!t.ctx.cwd.join("escaped").exists());
        assert!(!outside.join("planted").exists());
        // Refused whole: no partial copy, no temp dir.
        let left: Vec<_> = std::fs::read_dir(&t.ctx.cwd)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n == "out" || n.starts_with(".bento-cp-"))
            .collect();
        assert!(left.is_empty(), "{left:?}");
    }

    #[test]
    fn cp_rules() {
        let mut t = test_env(&[]);
        t.running_proj();
        assert!(t.sbt_err(&["cp", "a", "b"]).contains("one of"));
        assert!(
            t.sbt_err(&["cp", "claude-proj:/a", "claude-proj:/b"])
                .contains("one of")
        );
        assert!(
            t.sbt_err(&["cp", "a", "claude-proj:rel"])
                .contains("absolute")
        );
    }

    #[test]
    fn exec_it_serves_the_bridge_while_attached() {
        let mut t = test_env(&[]);
        let (name, seen) = bridge_probe(&t, "exec", true);
        t.sbt(&["exec", "-it", &name, "sh"]).unwrap();
        // Without a terminal it isn't an attached session.
        t.sbt(&["exec", "-i", &name, "sh"]).unwrap();
        t.sbt(&["exec", &name, "true"]).unwrap();
        assert_eq!(*seen.borrow(), vec![true, false, false]);
        assert!(!crate::bridge::host_socket(&name).exists());
    }

    #[test]
    fn every_exec_serves_a_runtime_ssh_agent_grant() {
        let mut t = test_env(&[]);
        let (name, seen) = agent_probe(&t, "exec", Some(r#"{"runtime":{"sign":null}}"#));
        t.sbt(&["exec", "-it", &name, "sh"]).unwrap();
        t.sbt(&["exec", "-i", &name, "sh"]).unwrap();
        t.sbt(&["exec", &name, "git", "commit"]).unwrap();
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
            t.sbt(&["exec", "-it", &name, "sh"]).unwrap();
            t.sbt(&["exec", &name, "true"]).unwrap();
            assert_eq!(*seen.borrow(), vec![false, false], "{tag}");
        }
    }

    #[test]
    fn exec_it_serves_no_bridge_for_an_unlabelled_sandbox() {
        let mut t = test_env(&[]);
        let (name, seen) = bridge_probe(&t, "exec", false);
        t.sbt(&["exec", "-it", &name, "sh"]).unwrap();
        assert_eq!(*seen.borrow(), vec![false]);
    }

    #[test]
    fn exec_it_serves_no_bridge_over_ssh_without_a_display() {
        let mut t = test_env(&[("SSH_CONNECTION", "10.0.0.1 50000 10.0.0.2 22")]);
        let (name, seen) = bridge_probe(&t, "exec", true);
        t.sbt(&["exec", "-it", &name, "sh"]).unwrap();
        assert_eq!(*seen.borrow(), vec![false]);
    }
}
