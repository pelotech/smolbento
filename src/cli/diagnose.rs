//! diagnose: checks smolvm, its home and host tools, the hypervisor and the config file.

use anyhow::Result;
use std::io::Write;
use std::path::PathBuf;

use super::Ctx;
use crate::smolvm::Runner;

pub fn run<R: Runner>(ctx: &mut Ctx<R>) -> Result<i32> {
    let mut checks = vec![smolvm_check(ctx), home_check(ctx)?];
    #[cfg(target_os = "macos")]
    checks.push(mkfs_check(&mkfs_dirs(&ctx.env)));
    #[cfg(target_os = "linux")]
    checks.push(libbz2_check(&lib_dirs()));
    #[cfg(target_os = "linux")]
    checks.push(kvm_check());
    #[cfg(target_os = "macos")]
    checks.push(entitlement_check(
        &crate::smolvm::locate::locate(&ctx.settings, &ctx.env)?
            .bin
            .display()
            .to_string(),
        &ctx.env,
    ));
    checks.push(config_check(ctx));
    checks.extend(services_check(ctx));
    let (text, code) = report(&checks);
    write!(&ctx.out, "{text}")?;
    Ok(code)
}

pub fn report(checks: &[(bool, String)]) -> (String, i32) {
    let text = checks
        .iter()
        .map(|(ok, msg)| format!("{} {msg}\n", if *ok { "ok  " } else { "FAIL" }))
        .collect();
    let code = if checks.iter().all(|(ok, _)| *ok) {
        0
    } else {
        1
    };
    (text, code)
}

/// The smolvm `sbt` runs: the pinned release (or not downloaded yet), or the explicit
/// `smolvm.path`, whose version is only noted when it differs from the pin.
pub fn smolvm_check<R: Runner>(ctx: &Ctx<R>) -> (bool, String) {
    let pinned = &crate::smolvm::pin::pin().version;
    let cmd = match crate::smolvm::locate::locate(&ctx.settings, &ctx.env) {
        Ok(c) => c,
        Err(e) => return (false, format!("smolvm: {e:#}")),
    };
    if cmd.managed && !cmd.bin.is_file() {
        return (
            true,
            format!(
                "smolvm {pinned} (pinned) isn't downloaded yet: the first command that needs it \
                 downloads it, or run `sbt smolvm --version`"
            ),
        );
    }
    let v = match ctx.vm.version() {
        Ok(v) => v,
        Err(e) => return (false, format!("smolvm: {e:#}")),
    };
    let msg = if cmd.managed {
        format!("smolvm {v} (pinned, {})", cmd.bin.display())
    } else if &v == pinned {
        format!("smolvm {v} ({}, from smolvm.path)", cmd.bin.display())
    } else {
        format!(
            "smolvm {v} ({}, from smolvm.path; smolbento is tested with {pinned})",
            cmd.bin.display()
        )
    };
    (true, msg)
}

/// `smolvm.home`, and on macOS how long its longest socket path is against the limit.
fn home_check<R: Runner>(ctx: &Ctx<R>) -> Result<(bool, String)> {
    let cmd = crate::smolvm::locate::locate(&ctx.settings, &ctx.env)?;
    let home = cmd.home.display();
    if !cfg!(target_os = "macos") {
        return Ok((true, format!("smolvm.home {home}")));
    }
    let n = crate::smolvm::locate::longest_socket_path(&cmd.home);
    Ok((
        n <= 103,
        format!("smolvm.home {home} (longest socket path {n} of 103 bytes)"),
    ))
}

/// `name` in the first of `dirs` that has it.
fn find_in(name: &str, dirs: &[PathBuf]) -> Option<PathBuf> {
    dirs.iter().map(|d| d.join(name)).find(|p| p.exists())
}

/// macOS: where smolvm looks for `mkfs.ext4` (PATH, then Homebrew's e2fsprogs).
#[cfg(target_os = "macos")]
fn mkfs_dirs(env: &std::collections::BTreeMap<String, String>) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = env
        .get("PATH")
        .map(|p| std::env::split_paths(p).collect())
        .unwrap_or_default();
    dirs.extend(
        [
            "/opt/homebrew/opt/e2fsprogs/sbin",
            "/usr/local/opt/e2fsprogs/sbin",
            "/opt/homebrew/sbin",
        ]
        .map(PathBuf::from),
    );
    dirs
}

/// `mkfs.ext4`: smolvm needs it only for disks larger than its templates, so it's a note.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn mkfs_check(dirs: &[PathBuf]) -> (bool, String) {
    match find_in("mkfs.ext4", dirs) {
        Some(p) => (true, format!("mkfs.ext4 {}", p.display())),
        None => (
            true,
            "mkfs.ext4 not found: disks larger than smolvm's templates need it (brew install \
             e2fsprogs)"
                .into(),
        ),
    }
}

/// Linux: where the system's libraries are.
#[cfg(target_os = "linux")]
fn lib_dirs() -> Vec<PathBuf> {
    [
        "/lib",
        "/usr/lib",
        "/lib64",
        "/usr/lib64",
        "/lib/x86_64-linux-gnu",
        "/usr/lib/x86_64-linux-gnu",
        "/lib/aarch64-linux-gnu",
        "/usr/lib/aarch64-linux-gnu",
    ]
    .map(PathBuf::from)
    .to_vec()
}

/// `libbz2.so.1`: the downloaded smolvm needs the system's.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn libbz2_check(dirs: &[PathBuf]) -> (bool, String) {
    match find_in("libbz2.so.1", dirs) {
        Some(p) => (true, format!("libbz2 {}", p.display())),
        None => (
            false,
            "libbz2.so.1 not found: smolvm needs it (install your distribution's bzip2 library)"
                .into(),
        ),
    }
}

fn config_check<R: Runner>(ctx: &Ctx<R>) -> (bool, String) {
    let path = ctx.paths.config_file();
    match &ctx.config_error {
        Some(err) => (false, format!("config {}: {err}", path.display())),
        None => (true, format!("config {}", path.display())),
    }
}

/// Units whose sandbox smolvm no longer has (deleted with `smolvm machine delete`).
fn services_check<R: Runner>(ctx: &Ctx<R>) -> Option<(bool, String)> {
    let orphans = crate::provision::orphan_services(ctx);
    (!orphans.is_empty()).then(|| {
        (
            false,
            format!(
                "host services left by removed sandboxes: {}; `{} prune` removes them",
                orphans.join(", "),
                ctx.program
            ),
        )
    })
}

#[cfg(target_os = "linux")]
fn kvm_check() -> (bool, String) {
    match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/kvm")
    {
        Ok(_) => (true, "/dev/kvm is accessible".into()),
        Err(e) => (
            false,
            format!("/dev/kvm: {e}; enable KVM and add your user to the kvm group"),
        ),
    }
}

/// smolvm needs `com.apple.security.hypervisor`; Homebrew installs a wrapper script next to the
/// signed `smolvm-bin`.
#[cfg(target_os = "macos")]
fn entitlement_check(
    smolvm: &str,
    env: &std::collections::BTreeMap<String, String>,
) -> (bool, String) {
    use std::path::{Path, PathBuf};

    let found: Option<PathBuf> = if smolvm.contains('/') {
        Some(PathBuf::from(smolvm))
    } else {
        env.get("PATH")
            .into_iter()
            .flat_map(|p| std::env::split_paths(p).collect::<Vec<_>>())
            .map(|dir| dir.join(smolvm))
            .find(|p| p.is_file())
    };
    let Some(path) = found.and_then(|p| p.canonicalize().ok()) else {
        return (false, format!("{smolvm} not found on PATH"));
    };
    let bin = path.with_file_name("smolvm-bin");
    let bin = if bin.is_file() { bin } else { path };
    let out = std::process::Command::new("codesign")
        .args(["-d", "--entitlements", "-", "--xml"])
        .arg(Path::new(&bin))
        .output();
    match out {
        Ok(o) if String::from_utf8_lossy(&o.stdout).contains("com.apple.security.hypervisor") => (
            true,
            format!("{} has the hypervisor entitlement", bin.display()),
        ),
        Ok(_) => (
            false,
            format!(
                "{} lacks com.apple.security.hypervisor; reinstall smolvm",
                bin.display()
            ),
        ),
        Err(e) => (false, format!("codesign: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;

    #[test]
    fn report_formats_and_fails_on_any_failure() {
        let (text, code) = report(&[(true, "a".into()), (false, "b".into())]);
        assert_eq!(text, "ok   a\nFAIL b\n");
        assert_eq!(code, 1);
        assert_eq!(report(&[(true, "a".into())]).1, 0);
    }

    #[test]
    fn invalid_config_fails_the_config_check() {
        let mut t = test_env(&[]);
        let file = t.ctx.paths.config_file().display().to_string();
        assert_eq!(config_check(&t.ctx), (true, format!("config {file}")));
        break_config(&mut t);
        let (ok, msg) = config_check(&t.ctx);
        assert!(!ok);
        assert!(
            msg.starts_with(&format!("config {file}: TOML parse error")),
            "{msg}"
        );
        assert_eq!(t.sbt(&["diagnose"]).unwrap(), 1);
    }

    fn pinned() -> &'static str {
        &crate::smolvm::pin::pin().version
    }

    #[test]
    fn an_explicit_smolvm_is_named_and_a_differing_version_noted() {
        let t = test_env(&[]);
        // test_env's smolvm is explicit, at the pinned version.
        t.runner()
            .ok(&["--version"], &format!("smolvm {}\n", pinned()));
        assert_eq!(
            smolvm_check(&t.ctx),
            (
                true,
                format!(
                    "smolvm {} (/nonexistent/smolvm, from smolvm.path)",
                    pinned()
                )
            )
        );
        // No floor: an explicit smolvm is the user's; a different version is only noted.
        t.runner().ok(&["--version"], "smolvm 1.0.0\n");
        assert_eq!(
            smolvm_check(&t.ctx),
            (
                true,
                format!(
                    "smolvm 1.0.0 (/nonexistent/smolvm, from smolvm.path; smolbento is tested \
                     with {})",
                    pinned()
                )
            )
        );
    }

    #[test]
    fn a_managed_smolvm_not_yet_downloaded_says_when_it_will_be() {
        let mut t = test_env(&[]);
        t.ctx.env.remove("SMOLBENTO_SMOLVM");
        t.ctx.settings = crate::config::Settings::load(&t.ctx.paths, t.ctx.env.clone()).0;
        let (ok, msg) = smolvm_check(&t.ctx);
        assert!(ok);
        assert_eq!(
            msg,
            format!(
                "smolvm {} (pinned) isn't downloaded yet: the first command that needs it \
                 downloads it, or run `sbt smolvm --version`",
                pinned()
            )
        );
    }

    #[test]
    fn home_is_reported_with_its_socket_room_on_macos() {
        let t = test_env(&[("HOME", "/Users/jhill")]);
        let (ok, msg) = home_check(&t.ctx).unwrap();
        assert!(ok);
        if cfg!(target_os = "macos") {
            assert_eq!(
                msg,
                "smolvm.home /Users/jhill/.smolbento (longest socket path 84 of 103 bytes)"
            );
        } else {
            assert_eq!(msg, "smolvm.home /Users/jhill/.smolbento");
        }
    }

    #[test]
    fn host_tools_are_found_or_explained() {
        let dir = tempfile::tempdir().unwrap();
        let dirs = [dir.path().to_path_buf()];
        assert_eq!(
            mkfs_check(&dirs),
            (
                true,
                "mkfs.ext4 not found: disks larger than smolvm's templates need it (brew install \
                 e2fsprogs)"
                    .to_string()
            )
        );
        std::fs::write(dir.path().join("mkfs.ext4"), "").unwrap();
        assert_eq!(
            mkfs_check(&dirs),
            (
                true,
                format!("mkfs.ext4 {}", dir.path().join("mkfs.ext4").display())
            )
        );
        assert_eq!(
            libbz2_check(&dirs),
            (
                false,
                "libbz2.so.1 not found: smolvm needs it (install your distribution's bzip2 \
                 library)"
                    .to_string()
            )
        );
        std::fs::write(dir.path().join("libbz2.so.1"), "").unwrap();
        assert!(libbz2_check(&dirs).0);
    }
}
