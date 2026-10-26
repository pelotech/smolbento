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
        write_atomic(&self.path, toml::to_string(&self.file)?.as_bytes(), None)
    }
}

/// Replaces `path` with `bytes` atomically: readers see the old file or the new one, never a
/// partial write. The bytes go to a new temp file in the same directory, created exclusively
/// under a unique name (so a file or symlink planted there is never followed), with `mode` (or
/// else the mode of the file it replaces) set before anything is written; it's synced, then
/// renamed over `path`. A symlink at `path` is replaced by the file rather than written
/// through. The temp file is removed on any error.
pub fn write_atomic(path: &Path, bytes: &[u8], mode: Option<u32>) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    };
    fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let mode = mode.or_else(|| {
        fs::symlink_metadata(path)
            .ok()
            .filter(|m| m.is_file())
            .map(|m| m.permissions().mode() & 0o7777)
    });
    let base = path.file_name().unwrap_or_default().to_string_lossy();
    let (tmp, mut file) = loop {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let tmp = dir.join(format!(".{base}.{}.{n}.tmp", std::process::id()));
        let mut opts = fs::OpenOptions::new();
        opts.write(true)
            .create_new(true)
            .mode(mode.unwrap_or(0o666));
        match opts.open(&tmp) {
            Ok(f) => break (tmp, f),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e).with_context(|| format!("writing {}", path.display())),
        }
    };
    let result = (|| -> std::io::Result<()> {
        // create_new's mode is filtered by the umask; set it exactly.
        if let Some(m) = mode {
            file.set_permissions(fs::Permissions::from_mode(m))?;
        }
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&tmp, path)
    })();
    if let Err(e) = result {
        let _ = fs::remove_file(&tmp);
        return Err(e).with_context(|| format!("writing {}", path.display()));
    }
    // Make the rename itself durable; best effort.
    if let Ok(d) = fs::File::open(dir) {
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

    fn entries(dir: &Path) -> Vec<String> {
        let mut v: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        v.sort();
        v
    }

    #[test]
    fn write_atomic_writes_with_the_mode_and_leaves_no_temp_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f.toml");
        write_atomic(&path, b"a = 1\n", Some(0o600)).unwrap();
        write_atomic(&path, b"a = 2\n", Some(0o600)).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "a = 2\n");
        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        assert_eq!(entries(dir.path()), ["f.toml"]);
    }

    #[test]
    fn write_atomic_keeps_an_existing_files_mode_when_none_is_given() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f.toml");
        fs::write(&path, "old").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        write_atomic(&path, b"new", None).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o640);
    }

    #[test]
    fn write_atomic_replaces_a_symlink_and_cleans_up_on_failure() {
        let dir = tempfile::tempdir().unwrap();
        let outside = dir.path().join("outside");
        fs::write(&outside, "keep").unwrap();
        let path = dir.path().join("f.toml");
        std::os::unix::fs::symlink(&outside, &path).unwrap();
        write_atomic(&path, b"new", None).unwrap();
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
        assert!(write_atomic(&blocked, b"new", None).is_err());
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
