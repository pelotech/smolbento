//! Where stored secret values live. The OS keychain is used through its CLI with the value on
//! stdin, so values never appear in argv. On macOS, `/usr/bin/security` creates and reads the
//! items, so smolbento upgrades (new ad-hoc signatures) never trigger keychain prompts. Writes go
//! through `security -i` with one command line on stdin (the prompt mode of `-w` reads the
//! terminal, not stdin). The stored password is `sbx1:` plus the value's bytes as hex: `security`
//! prints any password with non-printable or non-ASCII bytes as hex, and truncates `-i` lines at
//! about 4096 characters, so values over ~1900 bytes are refused and each write is read back.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
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

/// Longest `security -i` line written: `security` silently truncates input lines at about 4096
/// characters.
const KEYCHAIN_LINE_MAX: usize = 4000;
/// Marks a keychain password holding the value's bytes as hex. `find-generic-password -w` prints
/// hex itself for any password with non-printable or non-ASCII bytes, so the stored password is
/// always printable.
const KEYCHAIN_PREFIX: &str = "sbx1:";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The one `security -i` command that stores a value: `sbx1:` plus the value's bytes as hex, so
/// no quoting applies and the raw value never appears.
fn keychain_add_line(account: &str, value: &str) -> Result<String> {
    if account.is_empty()
        || account
            .chars()
            .any(|c| c.is_whitespace() || c == '"' || c == '\'')
    {
        bail!("invalid secret account '{account}'");
    }
    let line = format!(
        "add-generic-password -U -s {SERVICE} -a {account} -w {KEYCHAIN_PREFIX}{}\n",
        hex(value.as_bytes())
    );
    if line.len() > KEYCHAIN_LINE_MAX {
        bail!(
            "secret is too large for the macOS Keychain (max ~1900 bytes); use --ref or --command"
        );
    }
    Ok(line)
}

/// A keychain password back to the value. Errors never include the password.
fn decode_keychain_value(stored: &str) -> Result<String> {
    let Some(payload) = stored.strip_prefix(KEYCHAIN_PREFIX) else {
        return Ok(stored.to_string());
    };
    let bad = || anyhow::anyhow!("the keychain item isn't a valid smolbento value");
    if payload.len() % 2 != 0 {
        return Err(bad());
    }
    let bytes = (0..payload.len())
        .step_by(2)
        .map(|i| {
            payload
                .get(i..i + 2)
                .and_then(|h| u8::from_str_radix(h, 16).ok())
                .ok_or_else(bad)
        })
        .collect::<Result<Vec<u8>>>()?;
    String::from_utf8(bytes).map_err(|_| bad())
}

impl SecretStore for MacKeychain {
    fn get(&self, account: &str) -> Result<Option<String>> {
        let (code, out, err) = run(
            SECURITY,
            &["find-generic-password", "-s", SERVICE, "-a", account, "-w"],
            None,
        )?;
        match code {
            0 => decode_keychain_value(&strip_newline(out)).map(Some),
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
        if self.get(account).ok().flatten().as_deref() != Some(value) {
            let _ = self.delete(account);
            bail!("the macOS Keychain didn't store the value intact");
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
            // Stored as given (`set` doesn't encode), so returned as is.
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

    /// Atomic, and always 0600; a symlink at the path is replaced, not followed (see
    /// `write_atomic`).
    fn write(&self, values: &BTreeMap<String, String>) -> Result<()> {
        crate::config::write_atomic(&self.path, toml::to_string(values)?.as_bytes(), Some(0o600))
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
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn keychain_add_line_stores_a_printable_hex_payload() {
        let line = keychain_add_line("global/github", "a\"b$ c").unwrap();
        assert_eq!(
            line,
            "add-generic-password -U -s smolbento -a global/github -w sbx1:612262242063\n"
        );
        assert!(!line.contains("a\"b"));
        let long = "x".repeat(300);
        let line = keychain_add_line("global/x", &long).unwrap();
        assert!(line.contains(&format!("-w sbx1:{}", "78".repeat(300))) && !line.contains(&long));
        assert_eq!(line.matches('\n').count(), 1);
        for bad in ["a b", "a\"b", "a\nb", "a'b", ""] {
            assert!(keychain_add_line(bad, "v").is_err(), "{bad:?}");
        }
    }

    #[test]
    fn keychain_add_line_refuses_values_security_would_truncate() {
        let line = keychain_add_line("global/x", &"x".repeat(1900)).unwrap();
        assert!(line.len() <= KEYCHAIN_LINE_MAX, "{}", line.len());
        let err = keychain_add_line("global/x", &"x".repeat(2000))
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("too large for the macOS Keychain") && err.contains("--ref"),
            "{err}"
        );
        assert!(!err.contains("xxxx"), "{err}");
    }

    #[test]
    fn decode_keychain_value_reads_the_hex_payload() {
        let enc = |v: &str| format!("sbx1:{}", hex(v.as_bytes()));
        assert_eq!(decode_keychain_value(&enc("a\nb")).unwrap(), "a\nb");
        assert_eq!(
            decode_keychain_value(&enc("pässwörd-ключ")).unwrap(),
            "pässwörd-ключ"
        );
        assert_eq!(decode_keychain_value(&enc("")).unwrap(), "");
        assert_eq!(decode_keychain_value("plain-old").unwrap(), "plain-old");
        for bad in ["sbx1:zz-secret", "sbx1:abc", "sbx1:ff"] {
            let err = decode_keychain_value(bad).unwrap_err().to_string();
            assert!(!err.contains(bad) && !err.contains("secret"), "{err}");
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
    fn file_store_never_follows_a_planted_temp_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.toml");
        let outside = dir.path().join("outside");
        std::fs::write(&outside, "keep").unwrap();
        std::os::unix::fs::symlink(&outside, dir.path().join("v.toml.tmp")).unwrap();
        let s = FileStore::new(path.clone());
        s.set("a", "s3cret").unwrap();
        assert_eq!(std::fs::read_to_string(&outside).unwrap(), "keep");
        assert_eq!(s.get("a").unwrap().as_deref(), Some("s3cret"));
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        s.delete("a").unwrap();
        let mut names: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(names, ["outside", "v.toml", "v.toml.tmp"]);
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
