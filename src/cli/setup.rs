//! `setup ssh`: the managed block in `~/.ssh/config`.

use std::fs;
use std::io::Write;
use std::os::unix::fs::DirBuilderExt;
use std::path::Path;

use anyhow::{Context, Result};

use super::{Ctx, SetupCmd, SetupSshCmd};
use crate::config::{Symlink, write_atomic};
use crate::smolvm::Runner;
use crate::ssh::block;

pub fn run<R: Runner>(ctx: &Ctx<R>, cmd: SetupCmd) -> Result<i32> {
    let SetupCmd::Ssh(a) = cmd;
    let auto_create = (a.auto_create, "--auto-create (desktop app connections)");
    super::refuse_as(&[auto_create], "is not supported")?;
    let ssh_dir = Path::new(ctx.env.get("HOME").context("HOME is not set")?).join(".ssh");
    match a.cmd {
        None => install(ctx, &ssh_dir),
        Some(SetupSshCmd::Remove) => remove(ctx, &ssh_dir),
    }
}

fn read(path: &Path) -> Result<String> {
    match fs::read_to_string(path) {
        Ok(s) => Ok(s),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

fn install<R: Runner>(ctx: &Ctx<R>, ssh_dir: &Path) -> Result<i32> {
    let config = ssh_dir.join("config");
    if !ssh_dir.exists() {
        fs::DirBuilder::new()
            .mode(0o700)
            .recursive(true)
            .create(ssh_dir)
            .with_context(|| format!("creating {}", ssh_dir.display()))?;
    }
    let old = read(&config)?;
    let new = block::upsert(&old, &block::render(&binary(ctx), &proxy_env(ctx)))?;
    if new != old {
        // A new file is private; an existing one keeps its mode.
        write_atomic(
            &config,
            new.as_bytes(),
            (!config.exists()).then_some(0o600),
            Symlink::Follow,
        )?;
    }
    if block::has_sbx_block(&new) {
        crate::warning!(
            "{} also has a docker sandboxes (sbx) block; both claim `Host *.sbx` and \
the first one in the file wins (smolbento's is first unless you moved it)",
            config.display()
        );
    }
    writeln!(
        &ctx.out,
        "ssh NAME.sbx now reaches sandbox NAME ({})",
        config.display()
    )?;
    Ok(0)
}

fn remove<R: Runner>(ctx: &Ctx<R>, ssh_dir: &Path) -> Result<i32> {
    let config = ssh_dir.join("config");
    if remove_block(ssh_dir)? {
        writeln!(
            &ctx.out,
            "removed the smolbento block from {}",
            config.display()
        )?;
    } else {
        writeln!(&ctx.out, "no smolbento block in {}", config.display())?;
    }
    Ok(0)
}

/// Removes smolbento's block from `<ssh_dir>/config`; whether there was one.
pub fn remove_block(ssh_dir: &Path) -> Result<bool> {
    let config = ssh_dir.join("config");
    let old = read(&config)?;
    match block::remove(&old)? {
        Some(new) => {
            write_atomic(&config, new.as_bytes(), None, Symlink::Follow)?;
            Ok(true)
        }
        None => Ok(false),
    }
}

/// How `ssh` should call us, as an absolute path (IDEs run the ProxyCommand with a minimal PATH):
/// where the name this binary was run as is found on PATH, when that is this very binary (a stable
/// link such as `/opt/homebrew/bin/bento`, not a versioned Cellar path); else this binary's path.
fn binary<R: Runner>(ctx: &Ctx<R>) -> String {
    let exe = std::env::current_exe()
        .ok()
        .and_then(|e| e.canonicalize().ok());
    let path = ctx.env.get("PATH").cloned().unwrap_or_default();
    let on_path = |name: &str| crate::util::find_on_path(Some(&path), name);
    for name in [ctx.program.as_str(), "bento", "smolbento"] {
        if let (Some(found), Some(exe)) = (on_path(name), &exe)
            && found.canonicalize().ok().as_ref() == Some(exe)
        {
            return found.display().to_string();
        }
    }
    exe.map_or_else(|| "bento".into(), |e| e.display().to_string())
}

/// What the ProxyCommand sets: only the smolvm settings the user set, since `bento ssh proxy` finds
/// the pinned smolvm and `~/.smolbento` by itself. An explicit smolvm goes in by its absolute path,
/// so it doesn't depend on the IDE's PATH.
fn proxy_env<R: Runner>(ctx: &Ctx<R>) -> Vec<(String, String)> {
    let mut env = Vec::new();
    if !ctx
        .settings
        .value("smolvm.path")
        .unwrap_or_default()
        .is_empty()
    {
        match smolvm_path(ctx) {
            Some(p) => env.push(("SMOLBENTO_SMOLVM".to_string(), p)),
            None => crate::warning!(
                "smolvm.path isn't an absolute path or on your PATH; IDEs started from \
the Dock or a launcher may not find it (set it to an absolute path, then run `bento setup ssh` again)"
            ),
        }
    }
    let home = ctx.settings.value("smolvm.home").unwrap_or_default();
    if !home.is_empty() {
        env.push(("SMOLBENTO_SMOLVM_HOME".to_string(), home));
    }
    env
}

/// The explicit smolvm's absolute path (`smolvm.path`, looked up on PATH when it's a bare name).
/// `None` if not found.
fn smolvm_path<R: Runner>(ctx: &Ctx<R>) -> Option<String> {
    let configured = ctx.settings.value("smolvm.path").ok()?;
    let p = Path::new(&configured);
    if p.is_absolute() {
        return p.is_file().then(|| configured.clone());
    }
    let path = ctx.env.get("PATH")?;
    std::env::split_paths(path)
        .map(|d| d.join(&configured))
        .find(|c| c.is_file() && c.is_absolute())
        .map(|c| c.display().to_string())
}

#[cfg(test)]
mod tests {
    use crate::ssh::block::{BEGIN, END};
    use crate::testutil::*;

    fn home(t: &mut TestEnv) -> std::path::PathBuf {
        let h = t.ctx.paths.config.parent().unwrap().join("home");
        std::fs::create_dir_all(&h).unwrap();
        t.ctx.env.insert("HOME".into(), h.display().to_string());
        h
    }

    #[test]
    fn creates_the_private_dir_and_config_then_removes_the_block() {
        use std::os::unix::fs::PermissionsExt;
        let mut t = test_env(&[]);
        let h = home(&mut t);
        assert_eq!(t.sbt(&["setup", "ssh"]).unwrap(), 0);
        let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&h.join(".ssh")), 0o700);
        assert_eq!(mode(&h.join(".ssh/config")), 0o600);
        let cfg = std::fs::read_to_string(h.join(".ssh/config")).unwrap();
        assert!(cfg.starts_with(BEGIN) && cfg.contains(" ssh proxy %n") && cfg.contains(END));
        t.sbt(&["setup", "ssh", "remove"]).unwrap();
        assert_eq!(std::fs::read_to_string(h.join(".ssh/config")).unwrap(), "");
    }

    #[test]
    fn keeps_the_users_config_and_mode_and_is_rerunnable() {
        use std::os::unix::fs::PermissionsExt;
        let mut t = test_env(&[]);
        let h = home(&mut t);
        std::fs::create_dir_all(h.join(".ssh")).unwrap();
        let user = "Host gh\n  User git\n";
        std::fs::write(h.join(".ssh/config"), user).unwrap();
        std::fs::set_permissions(
            h.join(".ssh/config"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        t.sbt(&["setup", "ssh"]).unwrap();
        let first = std::fs::read_to_string(h.join(".ssh/config")).unwrap();
        t.sbt(&["setup", "ssh"]).unwrap();
        assert_eq!(
            std::fs::read_to_string(h.join(".ssh/config")).unwrap(),
            first
        );
        assert!(first.ends_with(user));
        let mode = std::fs::metadata(h.join(".ssh/config"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o644);
        t.sbt(&["setup", "ssh", "remove"]).unwrap();
        assert_eq!(
            std::fs::read_to_string(h.join(".ssh/config")).unwrap(),
            user
        );
    }

    #[test]
    fn leaves_an_sbx_block_alone() {
        let mut t = test_env(&[]);
        let h = home(&mut t);
        std::fs::create_dir_all(h.join(".ssh")).unwrap();
        let sbx = "# >>> docker sandboxes (managed) >>>\nHost *.sbx\n# <<< docker sandboxes (managed) <<<\n";
        std::fs::write(h.join(".ssh/config"), sbx).unwrap();
        t.sbt(&["setup", "ssh"]).unwrap();
        t.sbt(&["setup", "ssh", "remove"]).unwrap();
        assert_eq!(std::fs::read_to_string(h.join(".ssh/config")).unwrap(), sbx);
    }

    #[test]
    fn the_proxy_command_names_smolvm_only_when_explicit() {
        // test_env sets an explicit smolvm; without one, the ProxyCommand runs bento alone.
        let mut t = test_env(&[]);
        let h = home(&mut t);
        t.use_managed_smolvm();
        t.sbt(&["setup", "ssh"]).unwrap();
        let cfg = std::fs::read_to_string(h.join(".ssh/config")).unwrap();
        assert!(!cfg.contains("SMOLBENTO_SMOLVM"), "{cfg}");
        // An explicit one that exists is named, by its absolute path.
        let s = h.join("my-smolvm");
        std::fs::write(&s, "").unwrap();
        t.ctx
            .env
            .insert("SMOLBENTO_SMOLVM".into(), s.display().to_string());
        t.reload_settings();
        t.sbt(&["setup", "ssh"]).unwrap();
        let cfg = std::fs::read_to_string(h.join(".ssh/config")).unwrap();
        assert!(
            cfg.contains(&format!("SMOLBENTO_SMOLVM='{}'", s.display())),
            "{cfg}"
        );
    }

    #[test]
    fn auto_create_is_unsupported() {
        let mut t = test_env(&[]);
        home(&mut t);
        assert!(
            t.sbt_err(&["setup", "ssh", "--auto-create"])
                .contains("not supported")
        );
    }
}
