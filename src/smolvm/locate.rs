//! The smolvm `bento` runs and how: the managed copy of the pinned release (or `smolvm.path`), with
//! smolbento's own state (`SMOLVM_DATA_DIR=<smolvm.home>`).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use super::client::DATA_DIR;
use super::{install, pin};
use crate::config::Settings;

/// Points the download at another server (tests only).
pub const URL_ENV: &str = "SMOLBENTO_SMOLVM_URL";

/// macOS's limit on a Unix socket path, in bytes (`sun_path` less its terminator).
pub const MACOS_SOCKET_LIMIT: usize = 103;

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
}

impl SmolvmCmd {
    /// smolvm keeps its state in `home` (not its own default location).
    pub fn has_state(&self) -> bool {
        !self.env.is_empty()
    }
}

/// `~/.smolbento`.
pub fn default_home(env: &BTreeMap<String, String>) -> Result<PathBuf> {
    let user_home = env.get("HOME").context("HOME is not set")?;
    Ok(Path::new(user_home).join(".smolbento"))
}

/// The smolvm to run, from `smolvm.path` and `smolvm.home`. Downloads nothing.
pub fn locate(settings: &Settings, env: &BTreeMap<String, String>) -> Result<SmolvmCmd> {
    let set_home = settings.value("smolvm.home")?;
    // `-`: smolvm's own default state; the download stays in smolbento's default home.
    let home = match set_home.as_str() {
        "" | "-" => default_home(env)?,
        h => absolute_home(h, env)?,
    };
    let env = if set_home == "-" {
        Vec::new()
    } else {
        vec![(DATA_DIR.to_string(), home.display().to_string())]
    };
    let path = settings.value("smolvm.path")?;
    let (bin, managed) = if path.is_empty() {
        let v = &pin::pin().version;
        (install::engine_dir(&home, v).join("smolvm"), true)
    } else {
        (PathBuf::from(path), false)
    };
    Ok(SmolvmCmd {
        bin,
        env,
        managed,
        home,
    })
}

/// A set `smolvm.home`, with `~/` expanded. A relative path would follow the current directory,
/// so sandboxes would come and go with `cd` (and `reset` would delete the wrong folder).
fn absolute_home(h: &str, env: &BTreeMap<String, String>) -> Result<PathBuf> {
    let p = crate::util::expand_home(h, env)?.unwrap_or_else(|| h.into());
    if !p.is_absolute() {
        bail!("smolvm.home must be an absolute path (or start with ~/), not {h}");
    }
    Ok(p)
}

/// Downloads the pinned smolvm when `cmd` is the managed copy and it's missing; progress goes to
/// stderr. An explicit smolvm is the user's: nothing to do.
pub fn ensure_installed(cmd: &SmolvmCmd, env: &BTreeMap<String, String>) -> Result<()> {
    if !cmd.managed || cmd.bin.is_file() {
        return Ok(());
    }
    let base = env.get(URL_ENV).map_or(pin::RELEASES, String::as_str);
    install::ensure(
        &cmd.home,
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

/// The longest socket path under `home`, or an error when it's past macOS's limit.
pub fn socket_room(home: &Path) -> Result<usize> {
    let n = longest_socket_path(home);
    if n > MACOS_SOCKET_LIMIT {
        bail!(
            "smolvm.home {} is too long for macOS sockets ({n} bytes, limit \
             {MACOS_SOCKET_LIMIT}); set smolvm.home to a shorter path",
            home.display()
        );
    }
    Ok(n)
}

/// Refuses a home whose sockets wouldn't fit macOS's limit (a long user name can push even
/// `~/.smolbento` past it). Linux has no `Library/Caches` in its paths.
pub fn check_home(cmd: &SmolvmCmd) -> Result<()> {
    if !cfg!(target_os = "macos") || !cmd.has_state() {
        return Ok(());
    }
    socket_room(&cmd.home).map(drop)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;

    fn located(extra: &[(&str, &str)]) -> Result<SmolvmCmd> {
        let t = test_env(&[("HOME", "/h")]);
        let mut env = t.ctx.env.clone();
        // test_env points smolvm.path at a dummy; these tests choose for themselves.
        env.remove("SMOLBENTO_SMOLVM");
        for (k, v) in extra {
            env.insert(k.to_string(), v.to_string());
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
        let c = located(&[("SMOLBENTO_SMOLVM_HOME", "-")]).unwrap();
        assert!(c.env.is_empty(), "smolvm's own default state");
        // The download still lives in smolbento's default home.
        assert!(c.bin.starts_with("/h/.smolbento/engine"));
    }

    #[test]
    fn home_expands_a_tilde_and_must_be_absolute() {
        let c = located(&[("SMOLBENTO_SMOLVM_HOME", "~/vms")]).unwrap();
        assert_eq!(c.home, PathBuf::from("/h/vms"));
        let e = located(&[("SMOLBENTO_SMOLVM_HOME", "vms")]).unwrap_err();
        assert_eq!(
            e.to_string(),
            "smolvm.home must be an absolute path (or start with ~/), not vms"
        );
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
            ..located(&[]).unwrap()
        };
        if cfg!(target_os = "macos") {
            let e = check_home(&cmd).unwrap_err().to_string();
            assert!(e.contains("limit 103"), "{e}");
        } else {
            check_home(&cmd).unwrap();
        }
        // smolvm's own default state isn't in the home.
        check_home(&SmolvmCmd {
            env: Vec::new(),
            ..cmd
        })
        .unwrap();
    }
}
