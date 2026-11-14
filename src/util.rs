//! Small helpers with no dependency on the rest of the crate.

use std::path::Path;

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};

/// Single-quotes `s` for `sh -c`.
pub fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
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
