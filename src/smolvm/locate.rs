//! The smolvm `bento` runs and how: the managed copy of the pinned release (or `smolvm.path`), with
//! smolbento's own state (`SMOLVM_DATA_DIR=<smolvm.home>`).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use super::{install, pin};
use crate::config::Settings;

/// Points the download at another server (tests only).
pub const URL_ENV: &str = "SMOLBENTO_SMOLVM_URL";

/// macOS's limit on a Unix socket path, in bytes (`sun_path` less its terminator).
const MACOS_SOCKET_LIMIT: usize = 103;

/// How to run smolvm.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmolvmCmd {
    /// The wrapper to run.
    pub bin: PathBuf,
    /// Set on every smolvm process: `SMOLVM_DATA_DIR`, unless `smolvm.home` is `-`.
    pub env: Vec<(String, String)>,
    /// `bin` is the managed copy of the pinned release (downloaded on first need).
    pub managed: bool,
    /// smolbento's home: smolvm's state and the downloaded smolvm (`engine/`).
    pub home: PathBuf,
    /// `smolvm.home` was set by the user (its socket paths are checked).
    pub home_explicit: bool,
}

/// The smolvm to run, from `smolvm.path` and `smolvm.home`. Downloads nothing.
pub fn locate(settings: &Settings, env: &BTreeMap<String, String>) -> Result<SmolvmCmd> {
    let user_home = env.get("HOME").context("HOME is not set")?;
    let default_home = Path::new(user_home).join(".smolbento");
    let set_home = settings.value("smolvm.home")?;
    let (home, home_explicit, state) = match set_home.as_str() {
        "" => (default_home.clone(), false, true),
        // smolvm's own default state; the download stays in smolbento's default home.
        "-" => (default_home.clone(), false, false),
        h => (PathBuf::from(h), true, true),
    };
    let env = if state {
        vec![("SMOLVM_DATA_DIR".to_string(), home.display().to_string())]
    } else {
        Vec::new()
    };
    let path = settings.value("smolvm.path")?;
    let (bin, managed) = if path.is_empty() {
        let engine_home = if state { &home } else { &default_home };
        let v = &pin::pin().version;
        (install::engine_dir(engine_home, v).join("smolvm"), true)
    } else {
        (PathBuf::from(path), false)
    };
    Ok(SmolvmCmd {
        bin,
        env,
        managed,
        home,
        home_explicit,
    })
}

/// Downloads the pinned smolvm when `cmd` is the managed copy and it's missing; progress goes to
/// stderr. An explicit smolvm is the user's: nothing to do.
pub fn ensure_installed(cmd: &SmolvmCmd, env: &BTreeMap<String, String>) -> Result<()> {
    if !cmd.managed || cmd.bin.is_file() {
        return Ok(());
    }
    let base = env.get(URL_ENV).map_or(pin::RELEASES, String::as_str);
    let engine_home = cmd
        .bin
        .ancestors()
        .nth(3)
        .context("the managed smolvm has no home")?;
    install::ensure(
        engine_home,
        pin::pin(),
        pin::host_platform()?,
        base,
        &mut |line| eprintln!("{line}"),
    )?;
    Ok(())
}

/// The longest socket path smolvm makes under `home` on macOS, in bytes: a machine's
/// `port-forward.sock` in `Library/Caches/smolvm/vms/<16 hex>/`.
pub fn longest_socket_path(home: &Path) -> usize {
    home.join("Library/Caches/smolvm/vms")
        .join("0".repeat(16))
        .join("port-forward.sock")
        .as_os_str()
        .len()
}

/// Refuses an explicitly set `smolvm.home` whose sockets wouldn't fit macOS's limit. The default
/// always fits; Linux has no `Library/Caches` in its paths.
pub fn check_home(cmd: &SmolvmCmd) -> Result<()> {
    if !cfg!(target_os = "macos") || !cmd.home_explicit {
        return Ok(());
    }
    let n = longest_socket_path(&cmd.home);
    if n > MACOS_SOCKET_LIMIT {
        bail!(
            "smolvm.home {} is too long for macOS sockets ({n} bytes, limit \
             {MACOS_SOCKET_LIMIT}); set smolvm.home to a shorter path",
            cmd.home.display()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;

    fn located(extra: &[(&str, &str)]) -> Result<SmolvmCmd> {
        let mut all = vec![("HOME", "/h")];
        all.extend_from_slice(extra);
        let t = test_env(&all);
        let mut env = t.ctx.env.clone();
        // test_env points smolvm.path at a dummy; these tests choose for themselves.
        if !extra.iter().any(|(k, _)| *k == "SMOLBENTO_SMOLVM") {
            env.remove("SMOLBENTO_SMOLVM");
        }
        let settings = crate::config::Settings::load(&t.ctx.paths, env.clone()).0;
        locate(&settings, &env)
    }

    #[test]
    fn defaults_to_the_managed_copy_and_home() {
        let c = located(&[]).unwrap();
        let v = &crate::smolvm::pin::pin().version;
        assert_eq!(
            c.bin,
            PathBuf::from(format!("/h/.smolbento/engine/{v}/smolvm"))
        );
        assert!(c.managed);
        assert_eq!(c.home, PathBuf::from("/h/.smolbento"));
        assert_eq!(
            c.env,
            [("SMOLVM_DATA_DIR".to_string(), "/h/.smolbento".to_string())]
        );
        assert!(!c.home_explicit);
    }

    #[test]
    fn an_explicit_smolvm_is_used_as_is() {
        let c = located(&[("SMOLBENTO_SMOLVM", "/opt/s")]).unwrap();
        assert_eq!(c.bin, PathBuf::from("/opt/s"));
        assert!(!c.managed);
    }

    #[test]
    fn home_can_be_set_and_dash_means_smolvms_default() {
        let c = located(&[("SMOLBENTO_SMOLVM_HOME", "/x y/é")]).unwrap();
        assert_eq!(c.home, PathBuf::from("/x y/é"));
        assert_eq!(c.env[0].1, "/x y/é");
        assert!(c.home_explicit);
        let c = located(&[("SMOLBENTO_SMOLVM_HOME", "-")]).unwrap();
        assert!(c.env.is_empty(), "smolvm's own default state");
        // The download still lives in smolbento's default home.
        assert!(c.bin.starts_with("/h/.smolbento/engine"));
    }

    #[test]
    fn the_socket_check_counts_bytes() {
        assert_eq!(
            longest_socket_path(Path::new("/Users/jhill/.smolbento")),
            84
        );
        assert_eq!(
            longest_socket_path(Path::new("/Users/jhill/.smolbentoé")),
            86,
            "é is two bytes"
        );
        let long = format!("/Users/jhill/{}", "x".repeat(40));
        let cmd = SmolvmCmd {
            home: PathBuf::from(&long),
            home_explicit: true,
            ..located(&[]).unwrap()
        };
        if cfg!(target_os = "macos") {
            let e = check_home(&cmd).unwrap_err().to_string();
            assert!(e.contains("limit 103"), "{e}");
        } else {
            check_home(&cmd).unwrap();
        }
        // Only an explicit home is checked.
        check_home(&SmolvmCmd {
            home_explicit: false,
            ..cmd
        })
        .unwrap();
    }
}
