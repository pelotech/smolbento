//! Small helpers with no dependency on the rest of the crate.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};

/// Creates `dir` (and its parents) and makes it the owner's only (0700).
pub fn create_private_dir(dir: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
        .with_context(|| format!("setting the mode of {}", dir.display()))
}

/// Unix seconds as an RFC 3339 UTC time.
pub fn rfc3339(secs: i64) -> String {
    let at = std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs.max(0) as u64);
    humantime::format_rfc3339_seconds(at).to_string()
}

/// `s` as one shell word: as is when that's safe, else single-quoted.
pub fn shell_word(s: &str) -> String {
    let plain = |c: char| c.is_ascii_alphanumeric() || "-_./:=@%+,".contains(c);
    if !s.is_empty() && s.chars().all(plain) {
        s.to_string()
    } else {
        sh_quote(s)
    }
}

/// The distinct `values`, in the order first seen.
pub fn union<'a>(values: impl Iterator<Item = &'a String>) -> Vec<String> {
    let mut union: Vec<String> = Vec::new();
    for v in values {
        if !union.contains(v) {
            union.push(v.clone());
        }
    }
    union
}

/// Flushes `f` to disk. Unit tests skip it: on macOS `sync_all` is `F_FULLFSYNC`, which made
/// up over half of `just test`.
pub fn sync(f: &std::fs::File) -> std::io::Result<()> {
    if cfg!(test) {
        return Ok(());
    }
    f.sync_all()
}

/// Single-quotes `s` for `sh -c`.
pub fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// Waits for `child` to exit until `until`, polling; `None` when it is still running then.
pub fn wait_until(
    child: &mut std::process::Child,
    until: std::time::Instant,
) -> std::io::Result<Option<std::process::ExitStatus>> {
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        if std::time::Instant::now() >= until {
            return Ok(None);
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

/// Sets `key` in `env` to `value` unless it is already set.
pub fn env_default(env: &mut Vec<(String, String)>, key: &str, value: impl Into<String>) {
    if !env.iter().any(|(k, _)| k == key) {
        env.push((key.into(), value.into()));
    }
}

pub fn host_uid() -> u32 {
    // SAFETY: getuid has no preconditions and cannot fail.
    unsafe { libc::getuid() }
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// `sha256:<hex>`, the form OCI digests take.
pub fn sha256_digest(data: &[u8]) -> String {
    format!("sha256:{}", hex(&Sha256::digest(data)))
}

/// The hex SHA-256 of a file's contents, read in a stream.
pub fn sha256_file(path: &Path) -> std::io::Result<String> {
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex(&hasher.finalize()))
}

/// Parses `40g`, `512m`, `1TiB` or a byte count into bytes; `what` names the value in errors.
pub fn parse_size(value: &str, what: &str) -> Result<u64> {
    let v = value.trim().to_ascii_lowercase();
    let split = v.find(|c: char| !c.is_ascii_digit()).unwrap_or(v.len());
    let (num, unit) = v.split_at(split);
    let n: u64 = num
        .parse()
        .with_context(|| format!("invalid {what} '{value}'"))?;
    let shift = match unit.trim_end_matches(['b', 'i']) {
        "" => 0,
        "k" => 10,
        "m" => 20,
        "g" => 30,
        "t" => 40,
        _ => bail!("invalid {what} unit in '{value}' (use k, m, g or t)"),
    };
    n.checked_mul(1 << shift)
        .with_context(|| format!("{what} '{value}' is too large"))
}

/// `parse_size` in whole GiB, rounded up and at least 1, as smolvm's disk sizes take them.
pub fn size_gib(value: &str, what: &str) -> Result<u32> {
    let bytes = parse_size(value, what)?;
    let gib = bytes.div_ceil(1 << 30).max(1);
    u32::try_from(gib).with_context(|| format!("{what} '{value}' is too large"))
}

/// `path` with a leading `~/` replaced by `env`'s `HOME`; `None` for any other path.
pub fn expand_home(path: &str, env: &BTreeMap<String, String>) -> Result<Option<PathBuf>> {
    let Some(rest) = path.strip_prefix("~/") else {
        return Ok(None);
    };
    let home = env.get("HOME").context("HOME is not set")?;
    Ok(Some(Path::new(home).join(rest)))
}

/// The first `name` that is a file in a directory of `path` (a `PATH` value); `None` without one.
pub fn find_on_path(path: Option<impl AsRef<OsStr>>, name: impl AsRef<Path>) -> Option<PathBuf> {
    std::env::split_paths(path?.as_ref())
        .map(|d| d.join(&name))
        .find(|p| p.is_file())
}

/// Runs `fut` to its end on a new single-threaded runtime, with the TLS provider HTTPS clients
/// need; `what` names the client in the error. Sync: it must not be called from inside a runtime.
pub fn block_on<T>(what: &str, fut: impl Future<Output = Result<T>>) -> Result<T> {
    // reqwest's no-provider rustls build needs a default. Err means one is already installed.
    let _ = rustls::crypto::ring::default_provider().install_default();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .with_context(|| format!("starting the {what}"))?
        .block_on(fut)
}

/// Prints `warning: …` to stderr without panicking: `eprintln!` panics when stderr is gone (the
/// terminal hung up), and warnings are printed from cleanup paths that must finish.
#[macro_export]
macro_rules! warning {
    ($($arg:tt)*) => {{
        use std::io::Write as _;
        let _ = writeln!(std::io::stderr(), "warning: {}", format_args!($($arg)*));
    }};
}

/// `path` cleaned lexically: `.` dropped, `..` taking the component before it (none above the
/// root), repeated and trailing `/` collapsed. No file system access, so links aren't followed
/// (std's `absolute` keeps `..`).
pub fn clean_path(path: &Path) -> PathBuf {
    use std::path::Component;
    let mut clean = PathBuf::new();
    for c in path.components() {
        match c {
            Component::ParentDir => {
                clean.pop();
            }
            Component::CurDir => {}
            c => clean.push(c),
        }
    }
    clean
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn size_units() {
        assert_eq!(parse_size("40g", "size").unwrap(), 40 << 30);
        assert_eq!(parse_size("1TiB", "size").unwrap(), 1 << 40);
        assert_eq!(parse_size(" 7 ", "size").unwrap(), 7);
        let err = parse_size("20x", "cache size").unwrap_err().to_string();
        assert!(err.contains("invalid cache size unit"), "{err}");
        assert!(parse_size("", "size").is_err());
        assert!(parse_size("-1g", "size").is_err());
    }

    #[test]
    fn a_file_hashes_like_its_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f");
        std::fs::write(&path, b"abc").unwrap();
        assert_eq!(
            format!("sha256:{}", sha256_file(&path).unwrap()),
            sha256_digest(b"abc")
        );
    }
}
