//! A v2 kit as sbx 0.53 publishes it: `kit pack`'s ZIP, and the OCI artifact `kit push` writes
//! (the spec as the config, `files/` as one tar.gz layer), plus reading that layer back.
//!
//! Archives are deterministic (sorted paths, fixed times and owners) but not byte-identical to
//! sbx's: Go's and Rust's deflate differ.

use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, bail};
use base64::Engine;
use serde_json::{Value, json};

use crate::util::sha256_digest;

pub const KIT_V2_ARTIFACT: &str = "application/vnd.docker.sandbox.kit.v2";
const SPEC_MEDIA_TYPE: &str = "application/vnd.docker.sandbox.kit.v2.spec+yaml";
const LAYER_MEDIA_TYPE: &str = "application/vnd.oci.image.layer.v1.tar+gzip";
const EMPTY_MEDIA_TYPE: &str = "application/vnd.oci.empty.v1+json";
/// Where a kit's `files/home` lands in the guest, and so its prefix in the layer.
const HOME_IN_LAYER: &str = "home/agent";

/// What `kit push` publishes from a kit directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Payload {
    /// spec.yaml as written: the artifact's config.
    pub spec: Vec<u8>,
    /// The files layer (tar.gz); `None` for the empty layer.
    pub files: Option<Vec<u8>>,
    /// The manifest annotations from the spec (`created` is added by [`manifest`]).
    pub annotations: BTreeMap<String, String>,
}

/// Reads a v2 kit directory into what `kit push` publishes.
pub fn read_dir(dir: &Path) -> Result<Payload> {
    let spec_path = dir.join("spec.yaml");
    let spec = fs::read(&spec_path).with_context(|| format!("reading {}", spec_path.display()))?;
    let yaml = String::from_utf8(spec.clone()).context("spec.yaml isn't UTF-8")?;
    let v: Value = serde_saphyr::from_str(&yaml).context("reading spec.yaml")?;
    let text = |k: &str| match &v[k] {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    };
    match text("schemaVersion").as_deref() {
        None => bail!("schemaVersion is required"),
        Some("2") => {}
        Some("1") => bail!("kit schemaVersion \"1\" isn't supported"),
        Some(other) => bail!("unsupported schemaVersion \"{other}\" (supported: [1 2])"),
    }
    if dir.join("files/workspace").exists() {
        let name = crate::kits::v2::name_in(&yaml, dir)?;
        bail!("kit {name}: files/workspace isn't supported in a published kit yet");
    }
    let mut annotations = BTreeMap::new();
    for (key, field) in [
        ("org.opencontainers.image.title", "displayName"),
        ("org.opencontainers.image.description", "description"),
        ("vnd.docker.sandbox.kit.kind", "kind"),
        ("vnd.docker.sandbox.kit.name", "name"),
        ("vnd.docker.sandbox.kit.version", "version"),
    ] {
        if let Some(t) = text(field) {
            annotations.insert(key.to_string(), t);
        }
    }
    Ok(Payload {
        spec,
        files: files_layer(&dir.join("files/home"))?,
        annotations,
    })
}

/// Regular files under `root`, sorted, as paths relative to it; symlinks are skipped (the loader
/// warns about them).
fn files_under(root: &Path) -> Result<Vec<PathBuf>> {
    fn walk(root: &Path, dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
        let mut entries: Vec<_> = fs::read_dir(dir)
            .with_context(|| format!("reading {}", dir.display()))?
            .collect::<std::io::Result<_>>()?;
        entries.sort_by_key(|e| e.file_name());
        for e in entries {
            let t = e.file_type()?;
            if t.is_dir() {
                walk(root, &e.path(), out)?;
            } else if t.is_file() {
                out.push(e.path().strip_prefix(root)?.to_path_buf());
            }
        }
        Ok(())
    }
    let mut out = Vec::new();
    if root.is_dir() {
        walk(root, root, &mut out)?;
    }
    Ok(out)
}

fn gzip(data: &[u8]) -> Result<Vec<u8>> {
    let mut gz = flate2::GzBuilder::new().write(Vec::new(), flate2::Compression::default());
    gz.write_all(data)?;
    Ok(gz.finish()?)
}

/// The payload `kit pull` saves for a kit without files: an empty tar, gzip'd.
pub fn empty_files_layer() -> Result<Vec<u8>> {
    gzip(&[0; 1024])
}

/// The files layer: `files/home/X` as `home/agent/X`, owned by 1000, mtime 0.
fn files_layer(home: &Path) -> Result<Option<Vec<u8>>> {
    let files = files_under(home)?;
    if files.is_empty() {
        return Ok(None);
    }
    let mut b = tar::Builder::new(Vec::new());
    for rel in files {
        let path = home.join(&rel);
        let data = fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
        let exec = fs::metadata(&path)?.permissions().mode() & 0o111 != 0;
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Regular);
        h.set_size(data.len() as u64);
        h.set_mode(if exec { 0o755 } else { 0o644 });
        h.set_uid(1000);
        h.set_gid(1000);
        h.set_mtime(0);
        b.append_data(&mut h, Path::new(HOME_IN_LAYER).join(&rel), &data[..])?;
    }
    Ok(Some(gzip(&b.into_inner()?)?))
}

/// `kit pack`'s ZIP of `spec.yaml` and `files/`: stored entries, directories included, sorted,
/// every time 1980-01-01 00:00.
pub fn zip(dir: &Path) -> Result<Vec<u8>> {
    // (name, contents (None for a directory), Unix mode)
    let mut entries: Vec<(String, Option<Vec<u8>>, u32)> = Vec::new();
    let files = dir.join("files");
    if files.is_dir() {
        let mut dirs = std::collections::BTreeSet::from(["files/".to_string()]);
        for rel in files_under(&files)? {
            let name = format!("files/{}", rel.display());
            let mut parent = rel.parent();
            while let Some(p) = parent.filter(|p| !p.as_os_str().is_empty()) {
                dirs.insert(format!("files/{}/", p.display()));
                parent = p.parent();
            }
            let path = files.join(&rel);
            let exec = fs::metadata(&path)?.permissions().mode() & 0o111 != 0;
            let mode = if exec { 0o100755 } else { 0o100644 };
            entries.push((name, Some(fs::read(&path)?), mode));
        }
        entries.extend(dirs.into_iter().map(|d| (d, None, 0o40755)));
    }
    entries.push((
        "spec.yaml".into(),
        Some(fs::read(dir.join("spec.yaml"))?),
        0o100644,
    ));
    entries.sort_by(|a, b| a.0.cmp(&b.0));

    let (mut out, mut central) = (Vec::new(), Vec::new());
    let le16 = |v: &mut Vec<u8>, n: u16| v.extend_from_slice(&n.to_le_bytes());
    let le32 = |v: &mut Vec<u8>, n: u32| v.extend_from_slice(&n.to_le_bytes());
    const DATE: u16 = (1 << 5) | 1; // 1980-01-01
    for (name, data, mode) in &entries {
        let body = data.as_deref().unwrap_or_default();
        let mut crc = flate2::Crc::new();
        crc.update(body);
        let (crc, size, offset) = (
            crc.sum(),
            u32::try_from(body.len())?,
            u32::try_from(out.len())?,
        );
        let name_len = u16::try_from(name.len())?;
        // Local header: version 2.0, no flags, stored, time 0.
        le32(&mut out, 0x0403_4b50);
        for n in [20, 0, 0, 0, DATE] {
            le16(&mut out, n);
        }
        for n in [crc, size, size] {
            le32(&mut out, n);
        }
        le16(&mut out, name_len);
        le16(&mut out, 0);
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(body);
        // Central directory entry, made on Unix with the file's mode.
        let dos_dir = if data.is_none() { 0x10 } else { 0 };
        let attrs = (mode << 16) | dos_dir;
        le32(&mut central, 0x0201_4b50);
        for n in [(3 << 8) | 20, 20, 0, 0, 0, DATE] {
            le16(&mut central, n);
        }
        for n in [crc, size, size] {
            le32(&mut central, n);
        }
        for n in [name_len, 0, 0, 0, 0] {
            le16(&mut central, n);
        }
        le32(&mut central, attrs);
        le32(&mut central, offset);
        central.extend_from_slice(name.as_bytes());
    }
    let (cd_offset, cd_size, count) = (
        u32::try_from(out.len())?,
        u32::try_from(central.len())?,
        u16::try_from(entries.len())?,
    );
    out.extend_from_slice(&central);
    le32(&mut out, 0x0605_4b50);
    for n in [0, 0, count, count] {
        le16(&mut out, n);
    }
    le32(&mut out, cd_size);
    le32(&mut out, cd_offset);
    le16(&mut out, 0);
    Ok(out)
}

/// The manifest bytes, and every blob it names as `(digest, bytes)`.
pub fn manifest(p: &Payload, created: &str) -> (Vec<u8>, Vec<(String, Vec<u8>)>) {
    let spec_digest = sha256_digest(&p.spec);
    let mut blobs = vec![(spec_digest.clone(), p.spec.clone())];
    let layer = match &p.files {
        Some(f) => {
            let digest = sha256_digest(f);
            blobs.push((digest.clone(), f.clone()));
            json!({"mediaType": LAYER_MEDIA_TYPE, "digest": digest, "size": f.len()})
        }
        None => {
            let digest = sha256_digest(b"{}");
            blobs.push((digest.clone(), b"{}".to_vec()));
            let data = base64::engine::general_purpose::STANDARD.encode(b"{}");
            json!({"mediaType": EMPTY_MEDIA_TYPE, "digest": digest, "size": 2, "data": data})
        }
    };
    let mut annotations = p.annotations.clone();
    annotations.insert("org.opencontainers.image.created".into(), created.into());
    let m = json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "artifactType": KIT_V2_ARTIFACT,
        "config": {"mediaType": SPEC_MEDIA_TYPE, "digest": spec_digest, "size": p.spec.len()},
        "layers": [layer],
        "annotations": annotations,
    });
    (
        serde_json::to_vec(&m).expect("a JSON value serializes"),
        blobs,
    )
}

/// Unpacks a published files layer into `into/files/home`; refuses anything outside `home/agent/`
/// before writing.
pub fn unpack_files(tar_gz: &[u8], into: &Path) -> Result<()> {
    let mut files = Vec::new();
    let mut a = tar::Archive::new(flate2::read::GzDecoder::new(tar_gz));
    for e in a.entries().context("reading the kit's files layer")? {
        let mut e = e.context("reading the kit's files layer")?;
        let shown = String::from_utf8_lossy(&e.path_bytes()).into_owned();
        let kind = e.header().entry_type();
        if kind.is_dir() {
            continue;
        }
        let rel = std::str::from_utf8(&e.path_bytes())
            .ok()
            .and_then(home_relative)
            .filter(|_| kind.is_file());
        let Some(rel) = rel else {
            bail!("the kit's files layer has {shown}, outside home/agent or not a regular file");
        };
        let mode = e.header().mode().unwrap_or(0o644) & 0o777;
        let mut data = Vec::new();
        e.read_to_end(&mut data)?;
        files.push((rel, mode, data));
    }
    let home = into.join("files/home");
    for (rel, mode, data) in files {
        let path = home.join(rel);
        fs::create_dir_all(path.parent().expect("a joined path has a parent"))?;
        fs::write(&path, data).with_context(|| format!("writing {}", path.display()))?;
        fs::set_permissions(&path, fs::Permissions::from_mode(mode))?;
    }
    Ok(())
}

/// `X` of a layer path `home/agent/X`; `None` for anything else (`..`, an absolute path,
/// `home/agent` itself).
fn home_relative(path: &str) -> Option<PathBuf> {
    let rel = Path::new(path).strip_prefix(HOME_IN_LAYER).ok()?;
    let plain = rel.components().all(|c| matches!(c, Component::Normal(_)));
    (plain && !rel.as_os_str().is_empty()).then(|| rel.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Read;
    use std::os::unix::fs::PermissionsExt;

    const SPEC: &str = "schemaVersion: \"2\"\nkind: mixin\nname: demo\ndisplayName: Demo Kit\n\
                        description: A demo.\nversion: 1.2.0\n";

    fn kit(spec: &str) -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        fs::write(d.path().join("spec.yaml"), spec).unwrap();
        d
    }

    fn put(dir: &Path, rel: &str, body: &str, mode: u32) {
        let p = dir.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, body).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(mode)).unwrap();
    }

    /// (path, mode, uid, gid, mtime) of each entry.
    fn entries(tar_gz: &[u8]) -> Vec<(String, u32, u64, u64, u64)> {
        let mut a = tar::Archive::new(flate2::read::GzDecoder::new(tar_gz));
        a.entries()
            .unwrap()
            .map(|e| {
                let h = e.unwrap().header().clone();
                (
                    h.path().unwrap().display().to_string(),
                    h.mode().unwrap(),
                    h.uid().unwrap(),
                    h.gid().unwrap(),
                    h.mtime().unwrap(),
                )
            })
            .collect()
    }

    #[test]
    fn the_files_layer_is_stable_and_maps_home() {
        let d = kit(SPEC);
        put(d.path(), "files/home/.config/a", "a", 0o644);
        put(d.path(), "files/home/bin/x", "x", 0o700);
        let p = read_dir(d.path()).unwrap();
        assert_eq!(p, read_dir(d.path()).unwrap());
        assert_eq!(p.spec, SPEC.as_bytes());
        assert_eq!(
            entries(p.files.as_deref().unwrap()),
            [
                ("home/agent/.config/a".into(), 0o644, 1000, 1000, 0),
                ("home/agent/bin/x".into(), 0o755, 1000, 1000, 0),
            ]
        );
    }

    #[test]
    fn a_kit_without_files_gets_the_empty_layer() {
        let d = kit(SPEC);
        assert_eq!(read_dir(d.path()).unwrap().files, None);
        fs::create_dir_all(d.path().join("files/home/sub")).unwrap();
        let p = read_dir(d.path()).unwrap();
        assert_eq!(p.files, None);
        let (m, blobs) = manifest(&p, "2026-11-12T00:00:00Z");
        let m: serde_json::Value = serde_json::from_slice(&m).unwrap();
        assert_eq!(
            m["layers"],
            serde_json::json!([{
                "mediaType": "application/vnd.oci.empty.v1+json",
                "digest": "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
                "size": 2,
                "data": "e30=",
            }])
        );
        assert!(blobs.iter().any(|(_, b)| b == b"{}"));
    }

    #[test]
    fn annotations_come_from_the_spec() {
        let d = kit(SPEC);
        put(d.path(), "files/home/a", "a", 0o644);
        let p = read_dir(d.path()).unwrap();
        let (bytes, blobs) = manifest(&p, "2026-11-12T00:00:00Z");
        let m: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(m["artifactType"], KIT_V2_ARTIFACT);
        assert_eq!(m["mediaType"], "application/vnd.oci.image.manifest.v1+json");
        assert_eq!(
            m["config"]["mediaType"],
            "application/vnd.docker.sandbox.kit.v2.spec+yaml"
        );
        assert_eq!(
            m["config"]["digest"],
            crate::util::sha256_digest(SPEC.as_bytes())
        );
        assert_eq!(
            m["layers"][0]["mediaType"],
            "application/vnd.oci.image.layer.v1.tar+gzip"
        );
        assert_eq!(
            m["annotations"],
            serde_json::json!({
                "org.opencontainers.image.created": "2026-11-12T00:00:00Z",
                "org.opencontainers.image.title": "Demo Kit",
                "org.opencontainers.image.description": "A demo.",
                "vnd.docker.sandbox.kit.kind": "mixin",
                "vnd.docker.sandbox.kit.name": "demo",
                "vnd.docker.sandbox.kit.version": "1.2.0",
            })
        );
        assert_eq!(blobs.len(), 2);
        for (digest, b) in &blobs {
            assert_eq!(&crate::util::sha256_digest(b), digest);
        }
        let bare = kit("schemaVersion: \"2\"\nkind: mixin\n");
        let p = read_dir(bare.path()).unwrap();
        assert_eq!(
            p.annotations.keys().collect::<Vec<_>>(),
            ["vnd.docker.sandbox.kit.kind"]
        );
    }

    #[test]
    fn v3_v1_and_workspace_files_are_refused() {
        let err = |d: &tempfile::TempDir| read_dir(d.path()).unwrap_err().to_string();
        assert_eq!(
            err(&kit("schemaVersion: \"3\"\nkind: mixin\n")),
            "unsupported schemaVersion \"3\" (supported: [1 2])"
        );
        assert_eq!(
            err(&kit("schemaVersion: \"1\"\nkind: mixin\n")),
            "kit schemaVersion \"1\" isn't supported"
        );
        assert_eq!(err(&kit("kind: mixin\n")), "schemaVersion is required");
        let d = kit(SPEC);
        put(d.path(), "files/workspace/a", "a", 0o644);
        assert_eq!(
            err(&d),
            "kit demo: files/workspace isn't supported in a published kit yet"
        );
    }

    /// Entry names from the ZIP's central directory.
    fn zip_names(z: &[u8]) -> Vec<String> {
        let end = z.len() - 22;
        assert_eq!(&z[end..end + 4], b"PK\x05\x06");
        let count = u16::from_le_bytes([z[end + 10], z[end + 11]]) as usize;
        let mut at = u32::from_le_bytes(z[end + 16..end + 20].try_into().unwrap()) as usize;
        let mut names = Vec::new();
        for _ in 0..count {
            assert_eq!(&z[at..at + 4], b"PK\x01\x02");
            let n = u16::from_le_bytes([z[at + 28], z[at + 29]]) as usize;
            let extra = u16::from_le_bytes([z[at + 30], z[at + 31]]) as usize;
            let comment = u16::from_le_bytes([z[at + 32], z[at + 33]]) as usize;
            names.push(String::from_utf8(z[at + 46..at + 46 + n].to_vec()).unwrap());
            at += 46 + n + extra + comment;
        }
        names
    }

    #[test]
    fn the_zip_is_stable_and_lists_spec_and_files() {
        let d = kit(SPEC);
        put(d.path(), "files/home/a", "a", 0o644);
        let z = zip(d.path()).unwrap();
        assert_eq!(z, zip(d.path()).unwrap());
        assert_eq!(
            zip_names(&z),
            ["files/", "files/home/", "files/home/a", "spec.yaml"]
        );
        // The system unzip reads it, contents intact.
        let out = d.path().join("k.zip");
        fs::write(&out, &z).unwrap();
        let listed = std::process::Command::new("unzip")
            .args(["-p", out.to_str().unwrap(), "spec.yaml"])
            .output();
        if let Ok(o) = listed {
            assert_eq!(o.stdout, SPEC.as_bytes());
        }
    }

    #[test]
    fn the_zip_keeps_the_execute_bit() {
        let d = kit(SPEC);
        put(d.path(), "files/home/bin/x", "x", 0o755);
        put(d.path(), "files/home/a", "a", 0o600);
        let z = zip(d.path()).unwrap();
        // Unix mode from each central directory entry's external attributes, by name.
        let end = z.len() - 22;
        let mut at = u32::from_le_bytes(z[end + 16..end + 20].try_into().unwrap()) as usize;
        let mut modes = std::collections::BTreeMap::new();
        while &z[at..at + 4] == b"PK\x01\x02" {
            let n = u16::from_le_bytes([z[at + 28], z[at + 29]]) as usize;
            let attrs = u32::from_le_bytes(z[at + 38..at + 42].try_into().unwrap());
            modes.insert(
                String::from_utf8(z[at + 46..at + 46 + n].to_vec()).unwrap(),
                (attrs >> 16) & 0o777,
            );
            at += 46 + n;
        }
        assert_eq!(modes["files/home/bin/x"], 0o755);
        assert_eq!(modes["files/home/a"], 0o644);
    }

    fn tar_gz(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut b = tar::Builder::new(gz);
        for (path, body) in entries {
            let mut h = tar::Header::new_gnu();
            h.set_size(body.len() as u64);
            h.set_mode(0o644);
            h.set_entry_type(tar::EntryType::Regular);
            // Bypass the builder's path checks, as a hostile layer would.
            let name = &mut h.as_old_mut().name;
            name[..path.len()].copy_from_slice(path.as_bytes());
            h.set_cksum();
            b.append(&h, *body).unwrap();
        }
        b.into_inner().unwrap().finish().unwrap()
    }

    #[test]
    fn unpack_writes_home_agent_into_files_home() {
        let into = tempfile::tempdir().unwrap();
        unpack_files(&tar_gz(&[("home/agent/.cfg/a", b"hi")]), into.path()).unwrap();
        let mut s = String::new();
        fs::File::open(into.path().join("files/home/.cfg/a"))
            .unwrap()
            .read_to_string(&mut s)
            .unwrap();
        assert_eq!(s, "hi");
    }

    #[test]
    fn unpack_refuses_paths_outside_home_agent() {
        for bad in [
            "etc/passwd",
            "home/agent/../../x",
            "/home/agent/x",
            "home/agent",
        ] {
            let into = tempfile::tempdir().unwrap();
            let layer = tar_gz(&[("home/agent/ok", b"ok"), (bad, b"x")]);
            let e = unpack_files(&layer, into.path()).unwrap_err().to_string();
            assert!(e.contains("outside home/agent"), "{bad}: {e}");
            assert_eq!(fs::read_dir(into.path()).unwrap().count(), 0, "{bad}");
        }
    }
}
