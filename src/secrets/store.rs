//! Where stored secret values live. The OS keychain is used through its CLI with the value on
//! stdin, so values never appear in argv. On macOS, `/usr/bin/security` creates and reads the
//! items, so smolbento upgrades (new ad-hoc signatures) never trigger keychain prompts. Writes go
//! through `security -i` with one command line on stdin and the value hex-encoded (`-X`): the
//! prompt mode of `-w` reads the terminal, not stdin.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};

use crate::config::Paths;

const SERVICE: &str = "smolbento";

pub trait SecretStore {
    fn get(&self, account: &str) -> Result<Option<String>>;
    fn set(&self, account: &str, value: &str) -> Result<()>;
    fn delete(&self, account: &str) -> Result<()>;
    /// Where values go, for messages.
    fn describe(&self) -> String;
}

/// Runs a store CLI with `input` on stdin; returns (exit code, stdout, stderr).
fn run(program: &str, args: &[&str], input: Option<&str>) -> Result<(i32, String, String)> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("running {program}"))?;
    if let Some(input) = input {
        // A child that exits early closes the pipe; its exit code and stderr tell the story.
        match child
            .stdin
            .take()
            .expect("piped stdin")
            .write_all(input.as_bytes())
        {
            Err(e) if e.kind() != std::io::ErrorKind::BrokenPipe => return Err(e.into()),
            _ => {}
        }
    }
    let out = child.wait_with_output()?;
    Ok((
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).trim().to_string(),
    ))
}

fn strip_newline(mut s: String) -> String {
    while s.ends_with('\n') || s.ends_with('\r') {
        s.pop();
    }
    s
}

/// macOS login keychain via `/usr/bin/security`.
pub struct MacKeychain;

const SECURITY: &str = "/usr/bin/security";
/// `security` exits with this when an item isn't found.
const NOT_FOUND: i32 = 44;

/// The one `security -i` command that stores a value, hex-encoded so no quoting applies.
fn keychain_add_line(account: &str, value: &str) -> Result<String> {
    if account.is_empty()
        || account
            .chars()
            .any(|c| c.is_whitespace() || c == '"' || c == '\'')
    {
        bail!("invalid secret account '{account}'");
    }
    let hex: String = value.bytes().map(|b| format!("{b:02x}")).collect();
    Ok(format!(
        "add-generic-password -U -s {SERVICE} -a {account} -X {hex}\n"
    ))
}

impl SecretStore for MacKeychain {
    fn get(&self, account: &str) -> Result<Option<String>> {
        let (code, out, err) = run(
            SECURITY,
            &["find-generic-password", "-s", SERVICE, "-a", account, "-w"],
            None,
        )?;
        match code {
            0 => Ok(Some(strip_newline(out))),
            NOT_FOUND => Ok(None),
            _ => bail!("reading the keychain: {err}"),
        }
    }

    fn set(&self, account: &str, value: &str) -> Result<()> {
        let line = keychain_add_line(account, value)?;
        let (code, _, err) = run(SECURITY, &["-i"], Some(&line))?;
        if code != 0 {
            bail!("writing the keychain: {err}");
        }
        Ok(())
    }

    fn delete(&self, account: &str) -> Result<()> {
        let (code, _, err) = run(
            SECURITY,
            &["delete-generic-password", "-s", SERVICE, "-a", account],
            None,
        )?;
        if code != 0 && code != NOT_FOUND {
            bail!("deleting from the keychain: {err}");
        }
        Ok(())
    }

    fn describe(&self) -> String {
        "macOS Keychain".into()
    }
}

/// Linux Secret Service via `secret-tool` (libsecret).
pub struct SecretTool;

impl SecretStore for SecretTool {
    fn get(&self, account: &str) -> Result<Option<String>> {
        let (code, out, err) = run(
            "secret-tool",
            &["lookup", "service", SERVICE, "account", account],
            None,
        )?;
        match code {
            0 => Ok(Some(strip_newline(out))),
            1 if err.is_empty() => Ok(None),
            _ => bail!("reading the Secret Service: {err}"),
        }
    }

    fn set(&self, account: &str, value: &str) -> Result<()> {
        let (code, _, err) = run(
            "secret-tool",
            &[
                "store", "--label", SERVICE, "service", SERVICE, "account", account,
            ],
            Some(value),
        )?;
        if code != 0 {
            bail!("writing the Secret Service: {err}");
        }
        Ok(())
    }

    fn delete(&self, account: &str) -> Result<()> {
        let (code, _, err) = run(
            "secret-tool",
            &["clear", "service", SERVICE, "account", account],
            None,
        )?;
        if code != 0 && !err.is_empty() {
            bail!("deleting from the Secret Service: {err}");
        }
        Ok(())
    }

    fn describe(&self) -> String {
        "Secret Service (secret-tool)".into()
    }
}

/// A 0600 TOML file, for machines without a usable keychain (headless Linux, CI).
pub struct FileStore {
    path: PathBuf,
}

impl FileStore {
    pub fn new(path: PathBuf) -> FileStore {
        FileStore { path }
    }

    fn read(&self) -> Result<BTreeMap<String, String>> {
        match fs::read_to_string(&self.path) {
            // The TOML error would quote the offending line, which may hold a secret.
            Ok(text) => toml::from_str(&text).map_err(|_| {
                anyhow::anyhow!(
                    "{} is not valid TOML (contents not shown because it holds secrets)",
                    self.path.display()
                )
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(BTreeMap::new()),
            Err(e) => Err(e).with_context(|| format!("reading {}", self.path.display())),
        }
    }

    fn write(&self, values: &BTreeMap<String, String>) -> Result<()> {
        if let Some(dir) = self.path.parent() {
            fs::create_dir_all(dir)?;
        }
        let mut name = self.path.file_name().unwrap_or_default().to_os_string();
        name.push(".tmp");
        let tmp = self.path.with_file_name(name);
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .with_context(|| format!("writing {}", tmp.display()))?;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))?;
        f.write_all(toml::to_string(values)?.as_bytes())?;
        fs::rename(&tmp, &self.path).with_context(|| format!("writing {}", self.path.display()))?;
        Ok(())
    }
}

impl SecretStore for FileStore {
    fn get(&self, account: &str) -> Result<Option<String>> {
        Ok(self.read()?.get(account).cloned())
    }

    fn set(&self, account: &str, value: &str) -> Result<()> {
        let mut values = self.read()?;
        values.insert(account.to_string(), value.to_string());
        self.write(&values)
    }

    fn delete(&self, account: &str) -> Result<()> {
        let mut values = self.read()?;
        if values.remove(account).is_some() {
            self.write(&values)?;
        }
        Ok(())
    }

    fn describe(&self) -> String {
        format!("{} (mode 0600)", self.path.display())
    }
}

/// For tests.
#[derive(Default)]
pub struct MemoryStore(RefCell<BTreeMap<String, String>>);

impl SecretStore for MemoryStore {
    fn get(&self, account: &str) -> Result<Option<String>> {
        Ok(self.0.borrow().get(account).cloned())
    }

    fn set(&self, account: &str, value: &str) -> Result<()> {
        self.0
            .borrow_mut()
            .insert(account.to_string(), value.to_string());
        Ok(())
    }

    fn delete(&self, account: &str) -> Result<()> {
        self.0.borrow_mut().remove(account);
        Ok(())
    }

    fn describe(&self) -> String {
        "memory".into()
    }
}

fn on_path(program: &str, env: &BTreeMap<String, String>) -> bool {
    env.get("PATH")
        .is_some_and(|p| std::env::split_paths(p).any(|d| Path::new(&d).join(program).is_file()))
}

/// The OS keychain where one is usable, else the 0600 file.
pub fn platform(paths: &Paths, env: &BTreeMap<String, String>) -> Box<dyn SecretStore> {
    if cfg!(target_os = "macos") {
        return Box::new(MacKeychain);
    }
    if env.contains_key("DBUS_SESSION_BUS_ADDRESS") && on_path("secret-tool", env) {
        return Box::new(SecretTool);
    }
    Box::new(FileStore::new(paths.secret_values_file()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keychain_add_line_hex_encodes_the_value() {
        let line = keychain_add_line("global/github", "a\"b$ c").unwrap();
        assert_eq!(
            line,
            "add-generic-password -U -s smolbento -a global/github -X 612262242063\n"
        );
        assert!(!line.contains("a\"b"));
        let long = "x".repeat(300);
        let line = keychain_add_line("global/x", &long).unwrap();
        assert!(line.contains(&"78".repeat(300)) && !line.contains(&long));
        assert_eq!(line.matches('\n').count(), 1);
        for bad in ["a b", "a\"b", "a\nb", "a'b", ""] {
            assert!(keychain_add_line(bad, "v").is_err(), "{bad:?}");
        }
    }

    #[test]
    fn file_store_tightens_a_loose_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.toml");
        std::fs::write(&path, "\"old\" = \"1\"\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let s = FileStore::new(path.clone());
        s.set("new", "2").unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(s.get("old").unwrap().as_deref(), Some("1"));
        assert_eq!(s.get("new").unwrap().as_deref(), Some("2"));
    }

    #[test]
    fn corrupt_file_error_hides_contents() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.toml");
        std::fs::write(&path, "\"a\" = \"s3cret").unwrap();
        let err = FileStore::new(path).get("a").unwrap_err();
        assert!(!format!("{err:#}").contains("s3cret"), "{err:#}");
    }

    #[test]
    fn memory_store() {
        let s = MemoryStore::default();
        assert_eq!(s.get("a").unwrap(), None);
        s.set("a", "v").unwrap();
        assert_eq!(s.get("a").unwrap().as_deref(), Some("v"));
        s.delete("a").unwrap();
        assert_eq!(s.get("a").unwrap(), None);
    }

    #[test]
    fn file_store_is_private() {
        let dir = tempfile::tempdir().unwrap();
        let s = FileStore::new(dir.path().join("cfg/secret-values.toml"));
        s.set("global/anthropic", "sk-1").unwrap();
        s.set("global/github", "gh-2").unwrap();
        assert_eq!(s.get("global/anthropic").unwrap().as_deref(), Some("sk-1"));
        let mode = std::fs::metadata(dir.path().join("cfg/secret-values.toml"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        s.delete("global/anthropic").unwrap();
        assert_eq!(s.get("global/anthropic").unwrap(), None);
        assert_eq!(s.get("global/github").unwrap().as_deref(), Some("gh-2"));
    }

    #[test]
    fn platform_falls_back_to_the_file_without_a_keyring() {
        let dir = tempfile::tempdir().unwrap();
        let env = std::collections::BTreeMap::from([
            (
                "SMOLBENTO_CONFIG_DIR".to_string(),
                dir.path().display().to_string(),
            ),
            (
                "SMOLBENTO_CACHE_DIR".to_string(),
                dir.path().display().to_string(),
            ),
            ("PATH".to_string(), "/nonexistent".to_string()),
        ]);
        let paths = crate::config::Paths::from_env(&env).unwrap();
        let store = platform(&paths, &env);
        if cfg!(target_os = "macos") {
            assert!(store.describe().contains("macOS Keychain"));
        } else {
            assert!(store.describe().contains("secret-values.toml"));
        }
    }
}
