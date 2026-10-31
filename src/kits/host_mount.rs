//! `host-mount@1`: the kit identity that keys a mount's managed host directory, and that directory.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use oci_client::Reference;
use sha2::{Digest, Sha256};

use super::model::{Kit, Source};
use super::registry::hex;
use super::resolve::HostMount;

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

/// Where a kit host mount comes from on the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostDir {
    pub host: PathBuf,
    pub guest: String,
    /// The managed directory's mode; `None` for a `--mount` binding.
    pub managed_mode: Option<u32>,
}

/// Each `declared` host mount's directory, in kit order: its `--mount` binding (`(host, guest)`
/// from `bindings`), else its managed directory under `root`. Every binding must be declared, and
/// no declared path may be one of `workspaces` (guest paths).
pub fn host_dirs(
    declared: &[HostMount],
    bindings: &[(PathBuf, String)],
    workspaces: &[String],
    root: &Path,
) -> Result<Vec<HostDir>> {
    if let Some((_, guest)) = bindings
        .iter()
        .find(|(_, g)| !declared.iter().any(|d| d.path == *g))
    {
        bail!("no kit declares host-mount@1 at {guest:?}");
    }
    declared
        .iter()
        .map(|d| {
            if workspaces.contains(&d.path) {
                bail!("host-mount@1 path {} is already a workspace mount", d.path);
            }
            Ok(match bindings.iter().find(|(_, g)| *g == d.path) {
                Some((host, _)) => HostDir {
                    host: host.clone(),
                    guest: d.path.clone(),
                    managed_mode: None,
                },
                None => {
                    let mode = d.mode.as_deref().unwrap_or("0755");
                    HostDir {
                        host: managed_dir(root, &d.identity, &d.path),
                        guest: d.path.clone(),
                        managed_mode: Some(
                            u32::from_str_radix(mode, 8)
                                .with_context(|| format!("host-mount@1 mode {mode:?}"))?,
                        ),
                    }
                }
            })
        })
        .collect()
}

/// Creates the missing managed directories: parents `0700`, the directory itself with its mode.
/// An existing one is left as it is, contents and permissions.
pub fn create_managed(dirs: &[HostDir]) -> Result<()> {
    for d in dirs {
        let Some(mode) = d.managed_mode.filter(|_| !d.host.is_dir()) else {
            continue;
        };
        create_dir(&d.host, mode).with_context(|| format!("creating {}", d.host.display()))?;
    }
    Ok(())
}

/// One managed directory. A directory that appears meanwhile (a concurrent first create of the
/// same kit) is reused as it is.
fn create_dir(host: &Path, mode: u32) -> std::io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        if let Some(parent) = host.parent() {
            builder.mode(0o700).create(parent)?;
        }
        match builder.recursive(false).mode(mode).create(host) {
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
            // The create mode is filtered by the umask; set it exactly.
            Ok(()) => std::fs::set_permissions(host, std::fs::Permissions::from_mode(mode))?,
        }
    }
    #[cfg(not(unix))]
    {
        let _ = mode;
        builder.create(host)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kits::model::Kind;

    fn kit(source: Source) -> Kit {
        Kit::new("k", Kind::Mixin, source)
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

    #[cfg(unix)]
    #[test]
    fn a_dir_created_concurrently_is_reused_untouched() {
        use std::os::unix::fs::PermissionsExt;
        let root = std::env::temp_dir().join(format!("sbt-hm-{}", std::process::id()));
        let host = root.join("kit").join("dir");
        create_dir(&host, 0o755).unwrap();
        std::fs::write(host.join("keep"), "1").unwrap();
        std::fs::set_permissions(&host, std::fs::Permissions::from_mode(0o700)).unwrap();
        // The lost race: the directory exists when the create runs.
        create_dir(&host, 0o755).unwrap();
        assert!(host.join("keep").exists());
        let mode = std::fs::metadata(&host).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
        std::fs::remove_dir_all(&root).unwrap();
    }
}
