//! The smolvm release smolbento runs: `smolvm.lock`, compiled in. `just smolvm-pin VERSION`
//! rewrites the lock from that release's `checksums.sha256`.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use anyhow::{Result, bail};
use serde::Deserialize;

/// Where smolvm publishes its releases.
pub const RELEASES: &str = "https://github.com/smol-machines/smolvm/releases/download";

/// The pinned smolvm: its version and each platform's release tarball SHA-256.
#[derive(Debug, Deserialize)]
pub struct Pin {
    pub version: String,
    pub sha256: BTreeMap<String, String>,
}

/// The pin compiled into this build.
pub fn pin() -> &'static Pin {
    static PIN: OnceLock<Pin> = OnceLock::new();
    PIN.get_or_init(|| {
        toml::from_str(include_str!("../../smolvm.lock")).expect("smolvm.lock is valid TOML")
    })
}

/// smolvm's asset platform for a Rust target triple; `None` where smolvm publishes none.
pub fn platform(target: &str) -> Option<&'static str> {
    match target {
        "aarch64-apple-darwin" => Some("darwin-arm64"),
        "x86_64-unknown-linux-gnu" => Some("linux-x86_64"),
        "aarch64-unknown-linux-gnu" => Some("linux-arm64"),
        _ => None,
    }
}

/// `platform`, or the error telling the user how to run smolbento anyway.
pub fn platform_of(target: &str) -> Result<&'static str> {
    match platform(target) {
        Some(p) => Ok(p),
        None => bail!(
            "no smolvm release for this platform ({target}); set SMOLBENTO_SMOLVM to a smolvm \
             you built"
        ),
    }
}

/// The asset platform of the machine this build runs on.
pub fn host_platform() -> Result<&'static str> {
    platform_of(host_target())
}

/// The target triple this build was compiled for (the three smolbento releases, else a name
/// for the error).
fn host_target() -> &'static str {
    match (std::env::consts::ARCH, std::env::consts::OS) {
        ("aarch64", "macos") => "aarch64-apple-darwin",
        ("x86_64", "linux") => "x86_64-unknown-linux-gnu",
        ("aarch64", "linux") => "aarch64-unknown-linux-gnu",
        ("x86_64", "macos") => "x86_64-apple-darwin",
        _ => concat!("unsupported-", "target"),
    }
}

/// The release tarball's URL under `base` (`RELEASES`, or a test server).
pub fn asset_url(base: &str, version: &str, platform: &str) -> String {
    format!("{base}/v{version}/smolvm-{version}-{platform}.tar.gz")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_lock_parses_and_names_every_platform() {
        let p = pin();
        assert!(!p.version.is_empty());
        let keys: Vec<&str> = p.sha256.keys().map(String::as_str).collect();
        assert_eq!(keys, ["darwin-arm64", "linux-arm64", "linux-x86_64"]);
        for h in p.sha256.values() {
            assert_eq!(h.len(), 64, "{h}");
            assert!(h.chars().all(|c| c.is_ascii_hexdigit()), "{h}");
        }
    }

    #[test]
    fn targets_map_to_assets() {
        assert_eq!(platform("aarch64-apple-darwin"), Some("darwin-arm64"));
        assert_eq!(platform("x86_64-unknown-linux-gnu"), Some("linux-x86_64"));
        assert_eq!(platform("aarch64-unknown-linux-gnu"), Some("linux-arm64"));
        assert_eq!(platform("x86_64-apple-darwin"), None);
    }

    #[test]
    fn asset_url_is_smolvms_release_layout() {
        assert_eq!(
            asset_url(RELEASES, "1.35.1", "darwin-arm64"),
            "https://github.com/smol-machines/smolvm/releases/download/v1.35.1/\
             smolvm-1.35.1-darwin-arm64.tar.gz"
        );
    }

    #[test]
    fn an_unknown_platform_says_to_set_smolvm() {
        let e = platform_of("x86_64-apple-darwin").unwrap_err().to_string();
        assert_eq!(
            e,
            "no smolvm release for this platform (x86_64-apple-darwin); set SMOLBENTO_SMOLVM to \
             a smolvm you built"
        );
    }
}
