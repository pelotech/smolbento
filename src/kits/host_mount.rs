//! `host-mount@1`: the kit identity that keys a mount's managed host directory, and that directory.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use oci_client::Reference;
use sha2::{Digest, Sha256};

use super::model::{Kit, Source};
use super::registry::hex;

/// What keys a kit's host mounts (sbx): a local kit's canonical path; a published kit's
/// `<registry>/<repository>`, without tag or digest so updates keep its directories.
pub fn identity(kit: &Kit) -> Result<String> {
    match &kit.source {
        // Loading stores local kits by their canonical path.
        Source::LocalV3(p) | Source::LocalV2(p) | Source::Smolfile(p) => {
            Ok(p.to_string_lossy().into_owned())
        }
        Source::Registry(r) => {
            let r: Reference = r
                .parse()
                .with_context(|| format!("invalid kit reference '{r}'"))?;
            Ok(format!("{}/{}", r.registry(), r.repository()))
        }
        Source::Preset(_) | Source::Builtin(_) => {
            bail!("kit {} has no identity for host-mount@1", kit.name)
        }
    }
}

/// `<root>/<sha256hex(identity)>/<sha256hex(path)>`, sbx's layout.
pub fn managed_dir(root: &Path, identity: &str, path: &str) -> PathBuf {
    let sha = |s: &str| hex(&Sha256::digest(s.as_bytes()));
    root.join(sha(identity)).join(sha(path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kits::model::{Content, Kind};

    fn kit(source: Source) -> Kit {
        Kit {
            name: "k".into(),
            source,
            digest: None,
            kind: Kind::Mixin,
            provides: vec![],
            requires: vec![],
            integrates: vec![],
            conflicts: vec![],
            args: Default::default(),
            caps: vec![],
            env: vec![],
            content: Content::None,
            command: None,
            config: None,
            reference: None,
        }
    }

    #[test]
    fn a_local_kit_is_its_canonical_path() {
        for source in [
            Source::LocalV3("/private/tmp/k".into()),
            Source::LocalV2("/private/tmp/k".into()),
            Source::Smolfile("/private/tmp/k".into()),
        ] {
            assert_eq!(identity(&kit(source)).unwrap(), "/private/tmp/k");
        }
    }

    #[test]
    fn a_published_kit_is_its_repository_without_tag_or_digest() {
        let digest = format!("docker.io/x/y@sha256:{}", "a".repeat(64));
        for (r, want) in [
            ("docker.io/x/y:1", "docker.io/x/y"),
            (digest.as_str(), "docker.io/x/y"),
            ("ghcr.io/a/b:2", "ghcr.io/a/b"),
            ("x/y", "docker.io/x/y"),
            ("alpine:3", "docker.io/library/alpine"),
        ] {
            assert_eq!(identity(&kit(Source::Registry(r.into()))).unwrap(), want);
        }
    }

    #[test]
    fn presets_and_builtins_have_no_identity() {
        assert!(identity(&kit(Source::Preset("img:1".into()))).is_err());
        assert!(identity(&kit(Source::Builtin("docker"))).is_err());
    }

    #[test]
    fn the_managed_dir_is_sbx_s_hash_layout() {
        let d = managed_dir(
            Path::new("/data"),
            "/private/tmp/k",
            "/home/agent/.chk-shared",
        );
        assert_eq!(
            d.file_name().unwrap(),
            "54af5215c37c9f50db44fb188fc377d30009e718b59d6136e8a17deabe54de8c"
        );
        let id = hex(&Sha256::digest(b"/private/tmp/k"));
        assert_eq!(d.parent().unwrap(), Path::new("/data").join(id));
    }
}
