//! diagnose: checks smolvm, the hypervisor and the config file.

use anyhow::Result;
use std::io::Write;

use super::{Ctx, MIN_SMOLVM, version_at_least};
use crate::smolvm::Runner;

pub fn run<R: Runner>(ctx: &mut Ctx<R>) -> Result<i32> {
    let mut checks = vec![smolvm_check(ctx)];
    #[cfg(target_os = "linux")]
    checks.push(kvm_check());
    #[cfg(target_os = "macos")]
    checks.push(entitlement_check(
        &ctx.settings.value("smolvm.path")?,
        &ctx.env,
    ));
    checks.push(config_check(ctx));
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

pub fn smolvm_check<R: Runner>(ctx: &Ctx<R>) -> (bool, String) {
    match ctx.vm.version() {
        Ok(v) => (
            version_at_least(&v, MIN_SMOLVM),
            format!("smolvm {v} (minimum {MIN_SMOLVM})"),
        ),
        Err(e) => (false, format!("smolvm: {e:#}")),
    }
}

fn config_check<R: Runner>(ctx: &Ctx<R>) -> (bool, String) {
    let path = ctx.paths.config_file();
    match &ctx.config_error {
        Some(err) => (false, format!("config {}: {err}", path.display())),
        None => (true, format!("config {}", path.display())),
    }
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
    use super::super::testutil::*;
    use super::*;

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
        assert_eq!(sbt(&mut t.ctx, &["diagnose"]).unwrap(), 1);
    }

    #[test]
    fn smolvm_version_check() {
        let t = test_env(&[]);
        assert!(smolvm_check(&t.ctx).0);
        t.ctx.vm.runner().ok(&["--version"], "smolvm 1.0.0\n");
        let (ok, msg) = smolvm_check(&t.ctx);
        assert!(!ok);
        assert!(msg.contains("minimum 1.32.4"), "{msg}");
    }
}
