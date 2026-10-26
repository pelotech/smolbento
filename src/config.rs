//! Where smolbento keeps its files, and its settings (`sbt settings`).

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct Paths {
    pub config: PathBuf,
    pub cache: PathBuf,
}

impl Paths {
    pub fn policy_file(&self) -> PathBuf {
        self.config.join("policy.toml")
    }

    pub fn secrets_file(&self) -> PathBuf {
        self.config.join("secrets.toml")
    }

    /// Fallback secret values where no keychain is usable (mode 0600).
    pub fn secret_values_file(&self) -> PathBuf {
        self.config.join("secret-values.toml")
    }

    /// `SMOLBENTO_*_DIR`, then XDG, then `~/.config` / `~/.cache` (also on macOS).
    pub fn from_env(env: &BTreeMap<String, String>) -> Result<Paths> {
        let pick = |own: &str, xdg: &str, fallback: &str| -> Result<PathBuf> {
            if let Some(dir) = env.get(own) {
                return Ok(PathBuf::from(dir));
            }
            if let Some(dir) = env.get(xdg) {
                return Ok(Path::new(dir).join("smolbento"));
            }
            let home = env.get("HOME").context("HOME is not set")?;
            Ok(Path::new(home).join(fallback).join("smolbento"))
        };
        Ok(Paths {
            config: pick("SMOLBENTO_CONFIG_DIR", "XDG_CONFIG_HOME", ".config")?,
            cache: pick("SMOLBENTO_CACHE_DIR", "XDG_CACHE_HOME", ".cache")?,
        })
    }

    pub fn config_file(&self) -> PathBuf {
        self.config.join("config.toml")
    }

    pub fn sessions(&self) -> PathBuf {
        self.cache.join("sessions")
    }
}

pub struct SettingDef {
    pub key: &'static str,
    pub env: &'static str,
    pub default: &'static str,
    pub help: &'static str,
}

pub const SETTINGS: &[SettingDef] = &[
    SettingDef {
        key: "docker.enabled",
        env: "SMOLBENTO_DOCKER",
        default: "true",
        help: "Use Docker-enabled agent images and run a private dockerd in each sandbox",
    },
    SettingDef {
        key: "smolvm.path",
        env: "SMOLBENTO_SMOLVM",
        default: "smolvm",
        help: "smolvm binary to run",
    },
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Env,
    File,
    Default,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct File {
    #[serde(default)]
    settings: BTreeMap<String, String>,
}

pub struct Settings {
    path: PathBuf,
    file: File,
    env: BTreeMap<String, String>,
}

impl Settings {
    /// A config file that can't be read or parsed doesn't stop loading: the settings fall back to
    /// env and defaults, and the error comes back so callers can report it (`sbt diagnose`) or
    /// refuse to go on.
    pub fn load(paths: &Paths, env: BTreeMap<String, String>) -> (Settings, Option<String>) {
        let path = paths.config_file();
        let (file, error) = match fs::read_to_string(&path) {
            Ok(text) => match toml::from_str(&text) {
                Ok(file) => (file, None),
                Err(e) => (File::default(), Some(e.to_string().trim_end().to_string())),
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (File::default(), None),
            Err(e) => (File::default(), Some(e.to_string())),
        };
        (Settings { path, file, env }, error)
    }

    fn def(key: &str) -> Result<&'static SettingDef> {
        SETTINGS
            .iter()
            .find(|d| d.key == key)
            .with_context(|| format!("unknown setting '{key}' (see `sbt settings ls`)"))
    }

    /// Env var, then config file, then default.
    pub fn get(&self, key: &str) -> Result<(String, Source)> {
        let def = Self::def(key)?;
        if let Some(v) = self.env.get(def.env) {
            return Ok((v.clone(), Source::Env));
        }
        if let Some(v) = self.file.settings.get(key) {
            return Ok((v.clone(), Source::File));
        }
        Ok((def.default.to_string(), Source::Default))
    }

    pub fn value(&self, key: &str) -> Result<String> {
        Ok(self.get(key)?.0)
    }

    pub fn bool(&self, key: &str) -> Result<bool> {
        parse_bool(&self.value(key)?).with_context(|| format!("setting {key}"))
    }

    pub fn set(&mut self, key: &str, value: &str) -> Result<()> {
        let def = Self::def(key)?;
        if matches!(def.default, "true" | "false") {
            parse_bool(value)?;
        }
        self.file
            .settings
            .insert(key.to_string(), value.to_string());
        self.save()
    }

    pub fn unset(&mut self, key: &str) -> Result<()> {
        Self::def(key)?;
        self.file.settings.remove(key);
        self.save()
    }

    fn save(&self) -> Result<()> {
        write_atomic(
            &self.path,
            toml::to_string(&self.file)?.as_bytes(),
            None,
            Symlink::Follow,
        )
    }
}

/// What `write_atomic` does when `path` is a symlink.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Symlink {
    /// Write the file the link points to (dotfiles managed with stow and the like).
    Follow,
    /// Replace the link with a regular file.
    Replace,
}

static TEMP_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Replaces `path` with `bytes` atomically: readers see the old file or the new one, never a
/// partial write. The bytes go to a new temp file in the same directory, created exclusively
/// under a unique name (so a file or symlink planted there is never followed), with `mode` (or
/// else the mode of the file it replaces) set before anything is written; it's synced, then
/// renamed over the target. The temp file is removed on any error, and stale ones left by killed
/// writers are cleaned up. `links` says whether a symlink at `path` is written through (config
/// files a user may keep in a dotfiles repo) or replaced (secret values: never written through
/// a link).
pub fn write_atomic(path: &Path, bytes: &[u8], mode: Option<u32>, links: Symlink) -> Result<()> {
    write_in(path, bytes, mode, links, &TEMP_COUNTER)
}

/// The temp file name `write_atomic` uses for `base`: `.<base>.<pid>.<n>.tmp`.
fn temp_name(dir: &Path, base: &str, pid: u32, n: u64) -> PathBuf {
    dir.join(format!(".{base}.{pid}.{n}.tmp"))
}

/// Where to write for `path`: the file a symlink points to when following links. A dangling
/// link resolves to where it points, so the file is created there.
fn write_target(path: &Path, links: Symlink) -> Result<PathBuf> {
    let is_link = fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink());
    if links == Symlink::Replace || !is_link {
        return Ok(path.to_path_buf());
    }
    if let Ok(real) = fs::canonicalize(path) {
        return Ok(real);
    }
    let mut target = path.to_path_buf();
    for _ in 0..40 {
        if !fs::symlink_metadata(&target).is_ok_and(|m| m.file_type().is_symlink()) {
            return Ok(target);
        }
        let next = fs::read_link(&target)
            .with_context(|| format!("reading the link {}", target.display()))?;
        target = match target.parent() {
            Some(dir) => dir.join(next),
            None => next,
        };
    }
    bail!("too many levels of symbolic links at {}", path.display())
}

/// Temp files of other processes that were killed mid-write (older than 10 minutes, so not one
/// still being written). Best effort: errors are ignored.
fn remove_stale_temp_files(dir: &Path, base: &str) {
    const STALE: std::time::Duration = std::time::Duration::from_secs(600);
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    let prefix = format!(".{base}.");
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(rest) = name
            .to_str()
            .and_then(|n| n.strip_prefix(&prefix))
            .and_then(|n| n.strip_suffix(".tmp"))
        else {
            continue;
        };
        let Some((pid, n)) = rest.split_once('.') else {
            continue;
        };
        let (Ok(pid), Ok(_)) = (pid.parse::<u32>(), n.parse::<u64>()) else {
            continue;
        };
        let old = entry
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.elapsed().ok())
            .is_some_and(|age| age > STALE);
        if pid != std::process::id() && old {
            let _ = fs::remove_file(entry.path());
        }
    }
}

#[cfg(unix)]
fn existing_mode(path: &Path) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    fs::symlink_metadata(path)
        .ok()
        .filter(|m| m.is_file())
        .map(|m| m.permissions().mode() & 0o7777)
}

#[cfg(not(unix))]
fn existing_mode(_path: &Path) -> Option<u32> {
    None
}

/// Creates the temp file exclusively, with `mode` where the platform has modes.
fn create_temp(tmp: &Path, mode: Option<u32>) -> std::io::Result<fs::File> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        opts.mode(mode.unwrap_or(0o666));
        let file = opts.open(tmp)?;
        // create_new's mode is filtered by the umask; set it exactly.
        if let Some(m) = mode {
            file.set_permissions(fs::Permissions::from_mode(m))?;
        }
        Ok(file)
    }
    #[cfg(not(unix))]
    {
        let _ = mode;
        opts.open(tmp)
    }
}

fn write_in(
    path: &Path,
    bytes: &[u8],
    mode: Option<u32>,
    links: Symlink,
    counter: &std::sync::atomic::AtomicU64,
) -> Result<()> {
    use std::io::Write;
    use std::sync::atomic::Ordering;

    let target = write_target(path, links)?;
    let dir = match target.parent() {
        Some(d) if !d.as_os_str().is_empty() => d.to_path_buf(),
        _ => PathBuf::from("."),
    };
    fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let mode = mode.or_else(|| existing_mode(&target));
    let base = target
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned();
    remove_stale_temp_files(&dir, &base);
    let (tmp, mut file) = loop {
        let n = counter.fetch_add(1, Ordering::Relaxed);
        let tmp = temp_name(&dir, &base, std::process::id(), n);
        match create_temp(&tmp, mode) {
            Ok(f) => break (tmp, f),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => {
                // create_temp may fail after creating the file (setting its mode).
                let _ = fs::remove_file(&tmp);
                return Err(e).with_context(|| format!("writing {}", path.display()));
            }
        }
    };
    let result = (|| -> std::io::Result<()> {
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&tmp, &target)
    })();
    if let Err(e) = result {
        let _ = fs::remove_file(&tmp);
        return Err(e).with_context(|| format!("writing {}", path.display()));
    }
    // Make the rename itself durable; best effort (and not possible on every platform).
    if let Ok(d) = fs::File::open(&dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

pub fn parse_bool(v: &str) -> Result<bool> {
    match v.to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => Ok(true),
        "false" | "0" | "no" | "off" => Ok(false),
        _ => bail!("'{v}' is not a boolean (use true or false)"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    #[cfg(unix)]
    fn entries(dir: &Path) -> Vec<String> {
        let mut v: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        v.sort();
        v
    }

    #[cfg(unix)]
    #[test]
    fn write_atomic_can_write_through_a_symlink() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let real_dir = dir.path().join("dotfiles");
        fs::create_dir(&real_dir).unwrap();
        let real = real_dir.join("policy.toml");
        fs::write(&real, "old").unwrap();
        fs::set_permissions(&real, fs::Permissions::from_mode(0o640)).unwrap();
        let link_dir = dir.path().join("cfg");
        fs::create_dir(&link_dir).unwrap();
        let link = link_dir.join("policy.toml");
        std::os::unix::fs::symlink("../dotfiles/policy.toml", &link).unwrap();
        write_atomic(&link, b"new", None, Symlink::Follow).unwrap();
        assert!(
            fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read_to_string(&real).unwrap(), "new");
        let mode = fs::metadata(&real).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o640);
        assert_eq!(entries(&real_dir), ["policy.toml"]);
        assert_eq!(entries(&link_dir), ["policy.toml"]);
        // A dangling link: the file is created where it points.
        fs::remove_file(&real).unwrap();
        write_atomic(&link, b"again", None, Symlink::Follow).unwrap();
        assert_eq!(fs::read_to_string(&real).unwrap(), "again");
    }

    #[cfg(unix)]
    #[test]
    fn write_atomic_skips_a_temp_name_that_is_taken() {
        use std::sync::atomic::AtomicU64;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f.toml");
        let outside = dir.path().join("outside");
        fs::write(&outside, "keep").unwrap();
        // Plant a symlink at exactly the first name the helper will try.
        let planted = temp_name(dir.path(), "f.toml", std::process::id(), 0);
        std::os::unix::fs::symlink(&outside, &planted).unwrap();
        let counter = AtomicU64::new(0);
        write_in(&path, b"new", Some(0o600), Symlink::Replace, &counter).unwrap();
        assert_eq!(fs::read_to_string(&outside).unwrap(), "keep");
        assert_eq!(fs::read_to_string(&path).unwrap(), "new");
        assert!(
            fs::symlink_metadata(&planted)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(counter.load(std::sync::atomic::Ordering::Relaxed), 2);
    }

    #[test]
    fn write_atomic_removes_stale_temp_files_of_other_processes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f.toml");
        let old = std::time::SystemTime::now() - std::time::Duration::from_secs(3600);
        let stale = temp_name(dir.path(), "f.toml", 99_999_999, 3);
        let fresh = temp_name(dir.path(), "f.toml", 99_999_998, 0);
        let mine = temp_name(dir.path(), "f.toml", std::process::id(), 999_999);
        let other = temp_name(dir.path(), "g.toml", 99_999_999, 0);
        for p in [&stale, &fresh, &mine, &other] {
            fs::write(p, "x").unwrap();
        }
        for p in [&stale, &mine, &other] {
            fs::File::options()
                .write(true)
                .open(p)
                .unwrap()
                .set_modified(old)
                .unwrap();
        }
        write_atomic(&path, b"new", None, Symlink::Replace).unwrap();
        assert!(!stale.exists(), "stale temp file of a dead write");
        assert!(fresh.exists(), "may be another process mid-write");
        assert!(mine.exists(), "this process's own");
        assert!(other.exists(), "another file's");
    }

    #[cfg(unix)]
    #[test]
    fn write_atomic_writes_with_the_mode_and_leaves_no_temp_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f.toml");
        write_atomic(&path, b"a = 1\n", Some(0o600), Symlink::Follow).unwrap();
        write_atomic(&path, b"a = 2\n", Some(0o600), Symlink::Follow).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "a = 2\n");
        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        assert_eq!(entries(dir.path()), ["f.toml"]);
    }

    #[cfg(unix)]
    #[test]
    fn write_atomic_keeps_an_existing_files_mode_when_none_is_given() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f.toml");
        fs::write(&path, "old").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        write_atomic(&path, b"new", None, Symlink::Replace).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o640);
    }

    #[cfg(unix)]
    #[test]
    fn write_atomic_replaces_a_symlink_and_cleans_up_on_failure() {
        let dir = tempfile::tempdir().unwrap();
        let outside = dir.path().join("outside");
        fs::write(&outside, "keep").unwrap();
        let path = dir.path().join("f.toml");
        std::os::unix::fs::symlink(&outside, &path).unwrap();
        write_atomic(&path, b"new", None, Symlink::Replace).unwrap();
        assert_eq!(fs::read_to_string(&outside).unwrap(), "keep");
        assert!(
            !fs::symlink_metadata(&path)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        // Renaming a file over a non-empty directory fails: the temp file must not stay behind.
        let blocked = dir.path().join("blocked");
        fs::create_dir(&blocked).unwrap();
        fs::write(blocked.join("x"), "").unwrap();
        assert!(write_atomic(&blocked, b"new", None, Symlink::Replace).is_err());
        assert_eq!(entries(dir.path()), ["blocked", "f.toml", "outside"]);
    }

    fn env(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn paths_precedence() {
        let p = Paths::from_env(&env(&[("HOME", "/h")])).unwrap();
        assert_eq!(p.config, PathBuf::from("/h/.config/smolbento"));
        assert_eq!(p.cache, PathBuf::from("/h/.cache/smolbento"));
        let p = Paths::from_env(&env(&[("HOME", "/h"), ("XDG_CONFIG_HOME", "/x")])).unwrap();
        assert_eq!(p.config, PathBuf::from("/x/smolbento"));
        let p = Paths::from_env(&env(&[
            ("SMOLBENTO_CONFIG_DIR", "/c"),
            ("SMOLBENTO_CACHE_DIR", "/k"),
        ]))
        .unwrap();
        assert_eq!(
            (p.config.clone(), p.cache.clone()),
            (PathBuf::from("/c"), PathBuf::from("/k"))
        );
        assert_eq!(p.sessions(), PathBuf::from("/k/sessions"));
    }

    #[test]
    fn settings_default_file_env() {
        let dir = tempfile::tempdir().unwrap();
        let e = env(&[
            ("SMOLBENTO_CONFIG_DIR", dir.path().to_str().unwrap()),
            ("SMOLBENTO_CACHE_DIR", "/k"),
        ]);
        let paths = Paths::from_env(&e).unwrap();

        let mut s = Settings::load(&paths, e.clone()).0;
        assert_eq!(
            s.get("docker.enabled").unwrap(),
            ("true".to_string(), Source::Default)
        );
        s.set("docker.enabled", "false").unwrap();

        let s = Settings::load(&paths, e.clone()).0;
        assert_eq!(
            s.get("docker.enabled").unwrap(),
            ("false".to_string(), Source::File)
        );
        assert!(!s.bool("docker.enabled").unwrap());

        let mut with_env = e.clone();
        with_env.insert("SMOLBENTO_DOCKER".into(), "1".into());
        let mut s = Settings::load(&paths, with_env).0;
        assert_eq!(
            s.get("docker.enabled").unwrap(),
            ("1".to_string(), Source::Env)
        );
        assert!(s.bool("docker.enabled").unwrap());

        s.unset("docker.enabled").unwrap();
        let s = Settings::load(&paths, e).0;
        assert_eq!(s.get("docker.enabled").unwrap().1, Source::Default);
    }

    #[test]
    fn rejects_unknown_keys_and_bad_bools() {
        let dir = tempfile::tempdir().unwrap();
        let e = env(&[
            ("SMOLBENTO_CONFIG_DIR", dir.path().to_str().unwrap()),
            ("SMOLBENTO_CACHE_DIR", "/k"),
        ]);
        let mut s = Settings::load(&Paths::from_env(&e).unwrap(), e).0;
        assert!(
            s.get("nope")
                .unwrap_err()
                .to_string()
                .contains("unknown setting")
        );
        assert!(s.set("docker.enabled", "maybe").is_err());
        s.set("smolvm.path", "/opt/smolvm").unwrap();
        assert_eq!(s.value("smolvm.path").unwrap(), "/opt/smolvm");
    }

    #[test]
    fn invalid_file_falls_back_to_env_and_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let e = env(&[
            ("SMOLBENTO_CONFIG_DIR", dir.path().to_str().unwrap()),
            ("SMOLBENTO_CACHE_DIR", "/k"),
            ("SMOLBENTO_SMOLVM", "/opt/smolvm"),
        ]);
        let paths = Paths::from_env(&e).unwrap();
        fs::write(paths.config_file(), "not = [valid").unwrap();
        let (s, err) = Settings::load(&paths, e);
        assert!(err.unwrap().contains("TOML parse error"));
        assert_eq!(s.get("docker.enabled").unwrap().1, Source::Default);
        assert_eq!(s.get("smolvm.path").unwrap().1, Source::Env);
    }
}
