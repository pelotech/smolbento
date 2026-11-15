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

/// smolvm's release name for this machine.
pub fn host_platform() -> Result<&'static str> {
    platform(std::env::consts::ARCH, std::env::consts::OS)
}

/// smolvm's release name for `arch` and `os` (Rust's names), or how to run smolbento anyway.
fn platform(arch: &str, os: &str) -> Result<&'static str> {
    match (arch, os) {
        ("aarch64", "macos") => Ok("darwin-arm64"),
        ("x86_64", "linux") => Ok("linux-x86_64"),
        ("aarch64", "linux") => Ok("linux-arm64"),
        _ => bail!("no smolvm release for {arch}-{os}; set SMOLBENTO_SMOLVM to a smolvm you built"),
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
    fn platforms_map_to_assets() {
        assert_eq!(platform("aarch64", "macos").unwrap(), "darwin-arm64");
        assert_eq!(platform("x86_64", "linux").unwrap(), "linux-x86_64");
        assert_eq!(platform("aarch64", "linux").unwrap(), "linux-arm64");
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
        let e = platform("x86_64", "macos").unwrap_err().to_string();
        assert_eq!(
            e,
            "no smolvm release for x86_64-macos; set SMOLBENTO_SMOLVM to a smolvm you built"
        );
    }
}
