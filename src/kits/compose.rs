//! Builds the `--image` for a plan: the workload's image as is, or one archive that stacks every
//! mixin's layers on top of the workload's.

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use serde_json::{Value, json};

use crate::kits::model::{Content, Kit};
use crate::kits::registry::{self, hex_of, put_bytes, sha256_digest, store_dir};
use crate::kits::registry_auth::Logins;
use crate::kits::resolve::Plan;

/// The `--image` for a plan: the workload's ref or path when no mixin has layers; otherwise a
/// cached archive at `<cache>/composed/<sha256 of input manifest digests>.tar`.
pub fn image_for(plan: &Plan, cache: &Path, logins: Logins) -> Result<String> {
    let layered = layered_mixins(plan)?;
    let w = &plan.workload;
    if layered.is_empty() {
        return match &w.content {
            Content::Image(r) => Ok(r.clone()),
            Content::Oci(dir) => {
                let l = Layout::read(dir)?;
                let tar = cache
                    .join("images")
                    .join(format!("{}.tar", hex_of(&l.digest)?));
                ensure_tar(&tar, |out| l.archive(out))?;
                Ok(tar.display().to_string())
            }
            _ => bail!("kit '{}' has no image", w.name),
        };
    }
    let base = match &w.content {
        Content::Image(r) => Layout::read(&registry::pull_image(r, cache, logins)?)?,
        Content::Oci(dir) => Layout::read(dir)?,
        Content::Smolfile(_) => bail!("mixins with image layers can't be added to a Smolfile kit"),
        Content::None => bail!("kit '{}' has no image to add layers to", w.name),
    };
    let mut digests = vec![base.digest.clone()];
    digests.extend(layered.iter().map(|(_, l)| l.digest.clone()));
    let key = sha256_digest(digests.join(",").as_bytes());
    let tar = cache
        .join("composed")
        .join(format!("{}.tar", hex_of(&key)?));
    ensure_tar(&tar, |out| compose(&base, &layered, cache, out))?;
    Ok(tar.display().to_string())
}

/// Whether any mixin brings image layers (a Smolfile workload can't take them).
pub fn has_mixin_layers(plan: &Plan) -> Result<bool> {
    Ok(!layered_mixins(plan)?.is_empty())
}

/// Whether this kit brings image layers of its own (`kit add` can't apply them live).
pub fn has_layers(kit: &Kit) -> Result<bool> {
    Ok(match &kit.content {
        Content::Oci(dir) => !Layout::read(dir)?.layers().is_empty(),
        _ => false,
    })
}

fn layered_mixins(plan: &Plan) -> Result<Vec<(&Kit, Layout)>> {
    let mut layered = Vec::new();
    for m in &plan.mixins {
        if let Content::Oci(dir) = &m.content {
            let l = Layout::read(dir)?;
            if !l.layers().is_empty() {
                layered.push((m, l));
            }
        }
    }
    Ok(layered)
}

/// An OCI layout directory read just enough to stack layers.
struct Layout {
    dir: PathBuf,
    digest: String,
    manifest: Value,
    config: Value,
}

impl Layout {
    fn read(dir: &Path) -> Result<Self> {
        let read = |p: PathBuf| fs::read(&p).with_context(|| format!("reading {}", p.display()));
        let index: Value = serde_json::from_slice(&read(dir.join("index.json"))?)
            .with_context(|| format!("reading {}/index.json", dir.display()))?;
        let digest = index["manifests"][0]["digest"]
            .as_str()
            .ok_or_else(|| anyhow!("the layout in {} has no manifest", dir.display()))?
            .to_string();
        let blobs = dir.join("blobs").join("sha256");
        let bytes = read(blobs.join(hex_of(&digest)?))?;
        if sha256_digest(&bytes) != digest {
            bail!("manifest {digest} in {} is corrupt", dir.display());
        }
        let manifest: Value = serde_json::from_slice(&bytes).context("reading the manifest")?;
        let cfg = manifest["config"]["digest"]
            .as_str()
            .ok_or_else(|| anyhow!("the manifest {digest} has no config"))?;
        let config = serde_json::from_slice(&read(blobs.join(hex_of(cfg)?))?)
            .context("reading the image config")?;
        Ok(Self {
            dir: dir.to_path_buf(),
            digest,
            manifest,
            config,
        })
    }

    fn layers(&self) -> &[Value] {
        self.manifest["layers"].as_array().map_or(&[], |v| v)
    }

    fn blob(&self, digest: &str) -> Result<PathBuf> {
        Ok(self.dir.join("blobs").join("sha256").join(hex_of(digest)?))
    }

    /// The layout as a tar, unchanged.
    fn archive(&self, out: &mut impl Write) -> Result<()> {
        let mut blobs = vec![(self.digest.clone(), self.blob(&self.digest)?)];
        let cfg = self.manifest["config"]["digest"]
            .as_str()
            .unwrap_or_default();
        blobs.push((cfg.to_string(), self.blob(cfg)?));
        for l in self.layers() {
            let d = l["digest"].as_str().unwrap_or_default();
            blobs.push((d.to_string(), self.blob(d)?));
        }
        let media = self.manifest["mediaType"].as_str();
        let size = fs::metadata(self.blob(&self.digest)?)?.len();
        write_tar(out, &self.digest, media, size, blobs)
    }
}

fn compose(
    base: &Layout,
    layered: &[(&Kit, Layout)],
    cache: &Path,
    out: &mut impl Write,
) -> Result<()> {
    let mut manifest = base.manifest.clone();
    let mut config = base.config.clone();
    let mut blobs = Vec::new();
    for l in base.layers() {
        let d = l["digest"].as_str().unwrap_or_default();
        blobs.push((d.to_string(), base.blob(d)?));
    }
    let layers = manifest["layers"]
        .as_array_mut()
        .ok_or_else(|| anyhow!("the manifest {} has no layers", base.digest))?;
    let mut rootfs = config["rootfs"]["diff_ids"]
        .as_array()
        .cloned()
        .ok_or_else(|| anyhow!("the image config of {} has no rootfs.diff_ids", base.digest))?;
    let mut history = config["history"].as_array().cloned().unwrap_or_default();
    for (kit, l) in layered {
        let ids = l.config["rootfs"]["diff_ids"]
            .as_array()
            .filter(|ids| ids.len() == l.layers().len())
            .ok_or_else(|| {
                anyhow!(
                    "kit '{}' has layers that don't match its diff_ids",
                    kit.name
                )
            })?;
        for (layer, id) in l.layers().iter().zip(ids) {
            let d = layer["digest"].as_str().unwrap_or_default();
            blobs.push((d.to_string(), l.blob(d)?));
            layers.push(layer.clone());
            rootfs.push(id.clone());
            history.push(json!({
                "created_by": format!("smolbento kit {}", kit.name),
                "empty_layer": false,
            }));
        }
    }
    config["rootfs"]["diff_ids"] = Value::Array(rootfs);
    config["history"] = Value::Array(history);

    // New blobs go to the shared store first, so a later compose can reuse them.
    fs::create_dir_all(store_dir(cache))?;
    let cfg_bytes = serde_json::to_vec(&config)?;
    let cfg_digest = sha256_digest(&cfg_bytes);
    put_bytes(cache, &cfg_digest, &cfg_bytes)?;
    manifest["config"]["digest"] = json!(cfg_digest);
    manifest["config"]["size"] = json!(cfg_bytes.len());
    if let Some(o) = manifest.as_object_mut() {
        o.remove("annotations");
    }
    let m_bytes = serde_json::to_vec(&manifest)?;
    let m_digest = sha256_digest(&m_bytes);
    put_bytes(cache, &m_digest, &m_bytes)?;
    let store = |d: &str| -> Result<PathBuf> { Ok(store_dir(cache).join(hex_of(d)?)) };
    blobs.push((cfg_digest.clone(), store(&cfg_digest)?));
    blobs.push((m_digest.clone(), store(&m_digest)?));
    write_tar(
        out,
        &m_digest,
        manifest["mediaType"].as_str(),
        m_bytes.len() as u64,
        blobs,
    )
}

/// An OCI image-layout tar. Names carry no `./` (smolvm rejects them), and mtimes, modes and
/// order are fixed so equal inputs give equal bytes.
fn write_tar(
    out: &mut impl Write,
    manifest_digest: &str,
    media_type: Option<&str>,
    manifest_size: u64,
    mut blobs: Vec<(String, PathBuf)>,
) -> Result<()> {
    blobs.sort_by(|a, b| a.0.cmp(&b.0));
    blobs.dedup_by(|a, b| a.0 == b.0);
    let index = json!({
        "schemaVersion": 2,
        "manifests": [{
            "mediaType": media_type.unwrap_or("application/vnd.oci.image.manifest.v1+json"),
            "digest": manifest_digest,
            "size": manifest_size,
        }],
    });
    let mut b = tar::Builder::new(out);
    add(&mut b, "oci-layout", br#"{"imageLayoutVersion":"1.0.0"}"#)?;
    add(&mut b, "index.json", &serde_json::to_vec(&index)?)?;
    for (digest, path) in blobs {
        // Layers can be gigabytes: stream them from disk rather than reading them whole.
        let file = fs::File::open(&path).with_context(|| format!("reading {}", path.display()))?;
        let len = file.metadata()?.len();
        let name = format!("blobs/sha256/{}", hex_of(&digest)?);
        let mut h = header(len);
        // At most the header's size, and a blob that shrank since is an error, not a short entry.
        let mut data = Counted {
            inner: file.take(len),
            n: 0,
        };
        b.append_data(&mut h, &name, &mut data)
            .with_context(|| format!("adding {name} to the image archive"))?;
        if data.n != len {
            bail!(
                "{} changed while being archived ({} of {len} bytes)",
                path.display(),
                data.n
            );
        }
    }
    b.finish()?;
    Ok(())
}

/// A reader counting the bytes read through it.
struct Counted<R> {
    inner: R,
    n: u64,
}

impl<R: Read> Read for Counted<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.n += n as u64;
        Ok(n)
    }
}

fn header(len: u64) -> tar::Header {
    let mut h = tar::Header::new_gnu();
    h.set_size(len);
    h.set_mode(0o644);
    h.set_mtime(0);
    h.set_entry_type(tar::EntryType::Regular);
    h
}

fn add<W: Write>(b: &mut tar::Builder<W>, name: &str, data: &[u8]) -> Result<()> {
    let mut h = header(data.len() as u64);
    b.append_data(&mut h, name, data)
        .with_context(|| format!("adding {name} to the image archive"))
}

/// Writes the archive atomically unless it is already there.
fn ensure_tar(path: &Path, build: impl FnOnce(&mut fs::File) -> Result<()>) -> Result<()> {
    if path.exists() {
        return Ok(());
    }
    let dir = path.parent().ok_or_else(|| anyhow!("bad archive path"))?;
    fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let mut tmp = tempfile::NamedTempFile::new_in(dir)?;
    build(tmp.as_file_mut())?;
    tmp.as_file().sync_all()?;
    tmp.persist(path)
        .map_err(|e| e.error)
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use super::*;
    use crate::kits::model::{Kit, Source};
    use crate::kits::registry::fixtures::oci_layout;

    const DESC: &str = r#"{"schemaVersion":"3","kind":"mixin","provides":["x"]}"#;

    fn config(ids: &[&str]) -> String {
        json!({"rootfs": {"type": "layers", "diff_ids": ids},
               "history": ids.iter().map(|_| json!({"created_by": "base"})).collect::<Vec<_>>()})
        .to_string()
    }

    fn kit(name: &str, content: Content, digest: &str) -> Kit {
        let mut k = crate::kits::v3::parse_json(DESC, Source::Registry(name.into())).unwrap();
        k.name = name.into();
        k.digest = Some(digest.into());
        k.content = content;
        k
    }

    fn plan(workload: Kit, mixins: Vec<Kit>) -> Plan {
        Plan {
            workload,
            mixins,
            args: Default::default(),
            merged: Default::default(),
            skipped: vec![],
        }
    }

    struct Fx {
        _t: tempfile::TempDir,
        cache: PathBuf,
        base: Kit,
        mix: Kit,
        bare: Kit,
    }

    fn fx() -> Fx {
        let t = tempfile::tempdir().unwrap();
        let cache = t.path().join("cache");
        let mk = |n: &str, layers: &[&[u8]], ids: &[&str]| {
            let d = t.path().join(n);
            let dg = oci_layout(&d, Some(DESC), layers, &config(ids));
            kit(n, Content::Oci(d), &dg)
        };
        Fx {
            base: mk("base", &[b"base-layer"], &["sha256:aa"]),
            mix: mk("mix", &[b"mix-layer"], &["sha256:bb"]),
            bare: mk("bare", &[], &[]),
            cache,
            _t: t,
        }
    }

    fn read_tar(path: &str) -> Vec<(String, Vec<u8>)> {
        let mut a = tar::Archive::new(fs::File::open(path).unwrap());
        a.entries()
            .unwrap()
            .map(|e| {
                let mut e = e.unwrap();
                let name = e.path().unwrap().to_string_lossy().into_owned();
                let mut v = Vec::new();
                e.read_to_end(&mut v).unwrap();
                (name, v)
            })
            .collect()
    }

    #[test]
    fn composes_layers_in_plan_order() {
        let f = fx();
        let p = plan(f.base.clone(), vec![f.mix.clone(), f.bare.clone()]);
        let path = image_for(&p, &f.cache, Logins::none()).unwrap();
        assert!(path.starts_with(f.cache.join("composed").to_str().unwrap()));
        let entries = read_tar(&path);
        let names: Vec<&str> = entries.iter().map(|e| e.0.as_str()).collect();
        assert_eq!(&names[..2], ["oci-layout", "index.json"]);
        assert!(names.iter().all(|n| !n.starts_with("./")));
        assert!(names[2..].iter().all(|n| n.starts_with("blobs/sha256/")));
        let get = |hexd: &str| {
            let n = format!("blobs/sha256/{hexd}");
            entries.iter().find(|e| e.0 == n).unwrap().1.clone()
        };
        let index: Value = serde_json::from_slice(&entries[1].1).unwrap();
        let md = index["manifests"][0]["digest"].as_str().unwrap();
        let mbytes = get(hex_of(md).unwrap());
        assert_eq!(sha256_digest(&mbytes), md);
        let manifest: Value = serde_json::from_slice(&mbytes).unwrap();
        let want = [sha256_digest(b"base-layer"), sha256_digest(b"mix-layer")];
        let got: Vec<&str> = manifest["layers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|l| l["digest"].as_str().unwrap())
            .collect();
        assert_eq!(got, want);
        for d in want {
            assert!(!get(hex_of(&d).unwrap()).is_empty());
        }
        let cd = manifest["config"]["digest"].as_str().unwrap();
        let cbytes = get(hex_of(cd).unwrap());
        assert_eq!(sha256_digest(&cbytes), cd);
        let cfg: Value = serde_json::from_slice(&cbytes).unwrap();
        assert_eq!(cfg["rootfs"]["diff_ids"], json!(["sha256:aa", "sha256:bb"]));
        let hist = cfg["history"].as_array().unwrap();
        assert_eq!(hist.len(), 2);
        assert_eq!(hist[1]["created_by"], "smolbento kit mix");
    }

    #[test]
    fn multi_layer_mixin_appends_all_layers_in_order() {
        let f = fx();
        let d = f._t.path().join("two");
        let dg = oci_layout(
            &d,
            Some(DESC),
            &[b"one", b"two"],
            &config(&["sha256:c1", "sha256:c2"]),
        );
        let two = kit("two", Content::Oci(d), &dg);
        let path = image_for(&plan(f.base.clone(), vec![two]), &f.cache, Logins::none()).unwrap();
        let entries = read_tar(&path);
        let get = |d: &str| {
            let n = format!("blobs/sha256/{}", hex_of(d).unwrap());
            serde_json::from_slice::<Value>(&entries.iter().find(|e| e.0 == n).unwrap().1).unwrap()
        };
        let index: Value = serde_json::from_slice(&entries[1].1).unwrap();
        let manifest = get(index["manifests"][0]["digest"].as_str().unwrap());
        let got: Vec<&str> = manifest["layers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|l| l["digest"].as_str().unwrap())
            .collect();
        assert_eq!(
            got,
            [
                sha256_digest(b"base-layer"),
                sha256_digest(b"one"),
                sha256_digest(b"two")
            ]
        );
        let cfg = get(manifest["config"]["digest"].as_str().unwrap());
        assert_eq!(
            cfg["rootfs"]["diff_ids"],
            json!(["sha256:aa", "sha256:c1", "sha256:c2"])
        );
        assert_eq!(cfg["history"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn composed_config_and_manifest_land_in_the_shared_store() {
        let f = fx();
        let path = image_for(
            &plan(f.base.clone(), vec![f.mix.clone()]),
            &f.cache,
            Logins::none(),
        )
        .unwrap();
        let entries = read_tar(&path);
        let index: Value = serde_json::from_slice(&entries[1].1).unwrap();
        let md = index["manifests"][0]["digest"].as_str().unwrap();
        let mbytes = fs::read(store_dir(&f.cache).join(hex_of(md).unwrap())).unwrap();
        assert_eq!(sha256_digest(&mbytes), md);
        let manifest: Value = serde_json::from_slice(&mbytes).unwrap();
        let cd = manifest["config"]["digest"].as_str().unwrap();
        let cbytes = fs::read(store_dir(&f.cache).join(hex_of(cd).unwrap())).unwrap();
        assert_eq!(sha256_digest(&cbytes), cd);
    }

    #[test]
    fn second_run_reuses_the_archive() {
        let f = fx();
        let p = plan(f.base.clone(), vec![f.mix.clone()]);
        let a = image_for(&p, &f.cache, Logins::none()).unwrap();
        let bytes = fs::read(&a).unwrap();
        let m1 = fs::metadata(&a).unwrap().modified().unwrap();
        let b = image_for(&p, &f.cache, Logins::none()).unwrap();
        assert_eq!(a, b);
        assert_eq!(fs::metadata(&b).unwrap().modified().unwrap(), m1);
        // Same inputs rebuilt from scratch give the same bytes.
        fs::remove_file(&a).unwrap();
        image_for(&p, &f.cache, Logins::none()).unwrap();
        assert_eq!(fs::read(&a).unwrap(), bytes);
    }

    #[test]
    fn no_mixin_layers_keeps_the_workload_image() {
        let f = fx();
        let mut w = f.base.clone();
        w.content = Content::Image("alpine:3".into());
        let p = plan(w, vec![f.bare.clone()]);
        assert_eq!(image_for(&p, &f.cache, Logins::none()).unwrap(), "alpine:3");
    }

    #[test]
    fn layout_workload_without_mixin_layers_becomes_a_tar() {
        let f = fx();
        let p = plan(f.base.clone(), vec![f.bare.clone()]);
        let path = image_for(&p, &f.cache, Logins::none()).unwrap();
        let entries = read_tar(&path);
        assert_eq!(entries[0].0, "oci-layout");
        assert_eq!(entries[1].0, "index.json");
        assert_eq!(entries.len(), 5);
        assert!(entries.iter().all(|e| !e.0.starts_with("./")));
        assert_eq!(image_for(&p, &f.cache, Logins::none()).unwrap(), path);
    }

    #[test]
    fn smolfile_workload_rejects_layered_mixins() {
        let f = fx();
        let mut w = f.base.clone();
        w.content = Content::Smolfile("x.smolfile".into());
        let err = image_for(&plan(w, vec![f.mix.clone()]), &f.cache, Logins::none()).unwrap_err();
        assert_eq!(
            err.to_string(),
            "mixins with image layers can't be added to a Smolfile kit"
        );
    }

    #[test]
    fn mismatched_diff_ids_are_an_error() {
        let f = fx();
        let d = f._t.path().join("odd");
        let dg = oci_layout(&d, Some(DESC), &[b"l"], &config(&[]));
        let odd = kit("odd", Content::Oci(d), &dg);
        let err =
            image_for(&plan(f.base.clone(), vec![odd]), &f.cache, Logins::none()).unwrap_err();
        assert!(err.to_string().contains("don't match its diff_ids"));
    }
}
