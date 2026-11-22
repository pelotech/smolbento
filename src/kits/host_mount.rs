//! `host-mount@1`: the kit identity that keys a mount's managed host directory, and that directory.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use oci_client::Reference;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::model::{Kit, Source};
use super::resolve::HostMount;
use crate::util::hex;

/// What keys a kit's host mounts (sbx): a local kit's canonical path; a published kit's
/// `<registry>/<repository>`, without tag or digest so updates keep its directories.
pub fn identity(kit: &Kit) -> Result<String> {
    match &kit.source {
        // Loading stores local kits by their canonical path.
        Source::Local(p) | Source::Smolfile(p) => Ok(p.to_string_lossy().into_owned()),
        Source::Registry(r) | Source::Agent(r) => {
            let r: Reference = r
                .parse()
                .with_context(|| format!("invalid kit reference '{r}'"))?;
            Ok(format!("{}/{}", r.registry(), r.repository()))
        }
        Source::Builtin(_) => {
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
    /// `None` for a `--mount` binding: the user's directory, not one smolbento keeps.
    pub managed: Option<Managed>,
}

/// A managed directory's mode, and the kit identity that keys it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Managed {
    pub mode: u32,
    pub kit: String,
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
                    managed: None,
                },
                None => {
                    let mode = d.mode.as_deref().unwrap_or("0755");
                    HostDir {
                        host: managed_dir(root, &d.identity, &d.path),
                        guest: d.path.clone(),
                        managed: Some(Managed {
                            mode: u32::from_str_radix(mode, 8)
                                .with_context(|| format!("host-mount@1 mode {mode:?}"))?,
                            kit: d.identity.clone(),
                        }),
                    }
                }
            })
        })
        .collect()
}

/// Creates the missing managed directories: parents `0700`, the directory itself with its mode.
/// An existing one is left as it is, contents and permissions. Each gets its record (beside it,
/// never inside: the sandbox sees the directory) when it has none, so older ones gain one too.
pub fn create_managed(dirs: &[HostDir]) -> Result<()> {
    for d in dirs {
        let Some(m) = &d.managed else { continue };
        if !d.host.is_dir() {
            create_dir(&d.host, m.mode)
                .with_context(|| format!("creating {}", d.host.display()))?;
        }
        let record = d.host.with_extension("json");
        if !record.exists() {
            let r = Record {
                kit: m.kit.clone(),
                path: d.guest.clone(),
            };
            crate::config::write_atomic(
                &record,
                &serde_json::to_vec(&r)?,
                Some(0o600),
                crate::config::Symlink::Replace,
            )?;
        }
    }
    Ok(())
}

/// A managed directory's record: `<dir>.json`. The directory's name is a hash, so this is the
/// only place its kit and path can be read back.
#[derive(Serialize, Deserialize)]
struct Record {
    kit: String,
    path: String,
}

/// A kept managed directory, as `kit mounts ls` lists it.
#[derive(Debug, Serialize)]
pub struct Kept {
    pub id: String,
    pub kit: String,
    pub path: String,
    pub host_path: PathBuf,
}

/// The managed directories under `root` that have a record, by kit then path.
pub fn kept(root: &Path) -> Result<Vec<Kept>> {
    let mut kept = Vec::new();
    let Ok(kits) = std::fs::read_dir(root) else {
        return Ok(kept);
    };
    for kit_dir in kits {
        let kit_dir = kit_dir?.path();
        let Ok(entries) = std::fs::read_dir(&kit_dir) else {
            continue;
        };
        for e in entries {
            let record = e?.path();
            let host = record.with_extension("");
            if record.extension().is_none_or(|x| x != "json") || !host.is_dir() {
                continue;
            }
            let text =
                std::fs::read(&record).with_context(|| format!("reading {}", record.display()))?;
            let r: Record = serde_json::from_slice(&text)
                .with_context(|| format!("reading {}", record.display()))?;
            let short = |p: &Path| {
                let n = p.file_name().unwrap_or_default().to_string_lossy();
                n.chars().take(12).collect::<String>()
            };
            kept.push(Kept {
                id: format!("{}-{}", short(&kit_dir), short(&host)),
                kit: r.kit,
                path: r.path,
                host_path: host,
            });
        }
    }
    kept.sort_by(|a, b| (&a.kit, &a.path).cmp(&(&b.kit, &b.path)));
    Ok(kept)
}

/// Removes the kept directory `id` names (from `kept`), its contents and record; the kit's
/// directory too once it holds nothing else.
pub fn remove(root: &Path, id: &str) -> Result<()> {
    let Some(k) = kept(root)?.into_iter().find(|k| k.id == id) else {
        bail!("no kept host mount {id:?}; see: bento kit mounts ls");
    };
    std::fs::remove_dir_all(&k.host_path)
        .with_context(|| format!("removing {}", k.host_path.display()))?;
    std::fs::remove_file(k.host_path.with_extension("json"))?;
    if let Some(parent) = k.host_path.parent() {
        // Fails while another of the kit's directories is there, as it should.
        let _ = std::fs::remove_dir(parent);
    }
    Ok(())
}

/// One managed directory. A directory that appears meanwhile (a concurrent first create of the
/// same kit) is reused as it is.
fn create_dir(host: &Path, mode: u32) -> std::io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
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
            Source::Local("/private/tmp/k".into()),
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

    fn managed(root: &Path, kit: &str, path: &str) -> HostDir {
        HostDir {
            host: managed_dir(root, kit, path),
            guest: path.into(),
            managed: Some(Managed {
                mode: 0o755,
                kit: kit.into(),
            }),
        }
    }

    #[test]
    fn a_managed_dir_is_kept_with_its_kit_and_path() {
        let root = tempfile::tempdir().unwrap();
        let d = managed(root.path(), "/k", "/home/agent/.cache");
        create_managed(std::slice::from_ref(&d)).unwrap();
        let kept = kept(root.path()).unwrap();
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].kit, "/k");
        assert_eq!(kept[0].path, "/home/agent/.cache");
        assert_eq!(kept[0].host_path, d.host);
        assert!(!kept[0].id.is_empty());
        // A `--mount` binding is the user's directory: nothing is kept for it.
        let bound = HostDir {
            managed: None,
            ..managed(root.path(), "/k", "/other")
        };
        create_managed(&[bound]).unwrap();
        assert_eq!(super::kept(root.path()).unwrap().len(), 1);
    }

    /// A directory made before records existed gains one when a sandbox next uses it.
    #[test]
    fn an_existing_dir_gains_its_record_untouched() {
        let root = tempfile::tempdir().unwrap();
        let d = managed(root.path(), "/k", "/data");
        create_dir(&d.host, 0o755).unwrap();
        std::fs::write(d.host.join("keep"), "1").unwrap();
        assert!(kept(root.path()).unwrap().is_empty());
        create_managed(std::slice::from_ref(&d)).unwrap();
        assert_eq!(kept(root.path()).unwrap()[0].path, "/data");
        assert!(d.host.join("keep").exists());
    }

    #[test]
    fn remove_takes_only_a_listed_id() {
        let root = tempfile::tempdir().unwrap();
        let d = managed(root.path(), "/k", "/data");
        create_managed(std::slice::from_ref(&d)).unwrap();
        std::fs::write(d.host.join("keep"), "1").unwrap();
        for id in ["", "..", "../x", "nope"] {
            let e = remove(root.path(), id).unwrap_err();
            assert_eq!(
                e.to_string(),
                format!("no kept host mount {id:?}; see: bento kit mounts ls")
            );
        }
        let id = kept(root.path()).unwrap()[0].id.clone();
        remove(root.path(), &id).unwrap();
        assert!(!d.host.exists());
        assert!(kept(root.path()).unwrap().is_empty());
        // The kit's directory goes with its last mount.
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
    }
}
