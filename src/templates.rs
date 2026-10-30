//! Saved sandbox templates (Phase 5d): smolvm packs under `<data>/templates`, indexed by
//! `templates.json`.

use std::io::Read;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::Paths;

pub const INDEX: &str = "templates.json";
pub const ARCHIVE_META: &str = "smolbento-template.json";
pub const ARCHIVE_PACK: &str = "template.smolmachine";

/// A template name as Docker reads an image ref: `chk-tpl` is `docker.io/library/chk-tpl:latest`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TemplateRef {
    pub repository: String,
    pub tag: String,
}

impl TemplateRef {
    pub fn parse(s: &str) -> Result<TemplateRef> {
        // Docker refs are lowercase; the OCI parser is laxer about the rest.
        if !s
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._/:-@".contains(&b))
        {
            bail!("invalid template name '{s}'");
        }
        let r: oci_client::Reference = s
            .parse()
            .with_context(|| format!("invalid template name '{s}'"))?;
        if r.digest().is_some() {
            bail!("invalid template name '{s}': a template is named by a tag, not a digest");
        }
        Ok(TemplateRef {
            repository: format!("{}/{}", r.registry(), r.repository()),
            tag: r.tag().unwrap_or("latest").to_string(),
        })
    }

    pub fn full(&self) -> String {
        format!("{}:{}", self.repository, self.tag)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub id: String,
    pub repository: String,
    pub tag: String,
    /// The source sandbox's agent (`sbx.agent`); `ls` shows it as FLAVOR.
    pub agent: String,
    /// The source machine's image.
    pub image: String,
    /// The source sandbox ran a private dockerd (`sbx.docker`).
    pub docker: bool,
    /// RFC 3339, UTC.
    pub created_at: String,
    #[serde(default)]
    pub size: u64,
}

impl Entry {
    pub fn full(&self) -> String {
        format!("{}:{}", self.repository, self.tag)
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Index {
    version: u32,
    templates: Vec<Entry>,
}

/// An id prefix that matches more than one template.
#[derive(Debug)]
pub struct Ambiguous;

impl std::fmt::Display for Ambiguous {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "matches more than one template")
    }
}

impl std::error::Error for Ambiguous {}

/// Leftovers of an interrupted save or load younger than this may belong to a running one.
const STALE: std::time::Duration = std::time::Duration::from_secs(3600);

pub struct Store {
    pub dir: PathBuf,
}

impl Store {
    pub fn new(paths: &Paths) -> Store {
        Store {
            dir: paths.templates(),
        }
    }

    fn ensure(&self) -> Result<()> {
        std::fs::create_dir_all(&self.dir)
            .with_context(|| format!("creating {}", self.dir.display()))?;
        std::fs::set_permissions(&self.dir, std::fs::Permissions::from_mode(0o700))?;
        Ok(())
    }

    fn read(&self) -> Result<Index> {
        let path = self.dir.join(INDEX);
        match std::fs::read_to_string(&path) {
            Ok(s) => {
                serde_json::from_str(&s).with_context(|| format!("reading {}", path.display()))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Index {
                version: 1,
                templates: vec![],
            }),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }

    /// Written to a temp file and renamed over the index.
    fn write(&self, index: &Index) -> Result<()> {
        self.ensure()?;
        let tmp = self.dir.join(format!("{INDEX}.tmp"));
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        std::io::Write::write_all(&mut f, serde_json::to_string_pretty(index)?.as_bytes())?;
        std::fs::rename(&tmp, self.dir.join(INDEX))?;
        Ok(())
    }

    pub fn list(&self) -> Result<Vec<Entry>> {
        Ok(self.read()?.templates)
    }

    /// `name` as a ref, else as an id prefix of 4 or more hex digits (sbx accepts a prefix).
    /// A prefix that names more than one template is an [`Ambiguous`] error.
    pub fn find(&self, name: &str) -> Result<Option<Entry>> {
        let all = self.list()?;
        if let Ok(r) = TemplateRef::parse(name)
            && let Some(e) = all.iter().find(|e| e.full() == r.full())
        {
            return Ok(Some(e.clone()));
        }
        let hex = name.len() >= 4 && name.bytes().all(|b| b.is_ascii_hexdigit());
        if !hex {
            return Ok(None);
        }
        let prefix = name.to_ascii_lowercase();
        let mut hits = all.into_iter().filter(|e| e.id.starts_with(&prefix));
        let first = hits.next();
        if first.is_some() && hits.next().is_some() {
            return Err(Ambiguous.into());
        }
        Ok(first)
    }

    /// `name` as a ref only (`-t`).
    pub fn find_ref(&self, name: &str) -> Result<Option<Entry>> {
        let Ok(r) = TemplateRef::parse(name) else {
            return Ok(None);
        };
        Ok(self.list()?.into_iter().find(|e| e.full() == r.full()))
    }

    pub fn pack(&self, e: &Entry) -> PathBuf {
        self.dir.join(format!("{}.smolmachine", e.id))
    }

    /// A temp dir inside the store, so `add` renames within one filesystem.
    /// First sweeps what an interrupted save or load left behind.
    pub fn temp_dir(&self) -> Result<tempfile::TempDir> {
        self.ensure()?;
        let _ = self.sweep(STALE);
        Ok(tempfile::Builder::new()
            .prefix(".tmp-")
            .tempdir_in(&self.dir)?)
    }

    /// Deletes `.tmp-*` dirs and unindexed packs last modified more than `age` ago.
    fn sweep(&self, age: std::time::Duration) -> Result<()> {
        let indexed: Vec<String> = self.read()?.templates.into_iter().map(|e| e.id).collect();
        for entry in std::fs::read_dir(&self.dir)?.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let orphan = name
                .strip_suffix(".smolmachine")
                .is_some_and(|id| !indexed.iter().any(|i| i == id));
            if !(name.starts_with(".tmp-") || orphan) {
                continue;
            }
            let old = entry
                .metadata()
                .and_then(|m| m.modified())
                .ok()
                .and_then(|m| m.elapsed().ok())
                .is_some_and(|e| e > age);
            if old {
                let p = entry.path();
                let _ = if p.is_dir() {
                    std::fs::remove_dir_all(&p)
                } else {
                    std::fs::remove_file(&p)
                };
            }
        }
        Ok(())
    }

    /// Moves `pack` into the store as `meta`'s template, replacing any template with its ref.
    pub fn add(&self, meta: Entry, pack: &Path) -> Result<Entry> {
        self.ensure()?;
        let id = sha256_prefix(pack)?;
        let size = std::fs::metadata(pack)?.len();
        let entry = Entry { id, size, ..meta };
        let dest = self.pack(&entry);
        if std::fs::rename(pack, &dest).is_err() {
            // Another filesystem (tests, or a pack built elsewhere).
            std::fs::copy(pack, &dest)?;
            std::fs::remove_file(pack)?;
        }
        std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o600))?;
        let mut index = self.read()?;
        index.version = 1;
        let replaced: Vec<Entry> = index
            .templates
            .iter()
            .filter(|e| e.full() == entry.full())
            .cloned()
            .collect();
        index.templates.retain(|e| e.full() != entry.full());
        index.templates.push(entry.clone());
        self.write(&index)?;
        for old in replaced {
            self.drop_unused(&index, &old)?;
        }
        Ok(entry)
    }

    pub fn remove(&self, e: &Entry) -> Result<()> {
        let mut index = self.read()?;
        index.templates.retain(|t| t.full() != e.full());
        self.write(&index)?;
        self.drop_unused(&index, e)
    }

    /// `e` as a tar of its entry (without `id`) and its pack, for `template load` elsewhere.
    pub fn export(&self, e: &Entry, out: &Path) -> Result<()> {
        let meta = serde_json::to_vec_pretty(&Entry {
            id: String::new(),
            ..e.clone()
        })?;
        let f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(out)
            .with_context(|| format!("creating {}", out.display()))?;
        let mut tar = tar::Builder::new(f);
        let mut header = tar::Header::new_gnu();
        header.set_size(meta.len() as u64);
        header.set_mode(0o600);
        header.set_cksum();
        tar.append_data(&mut header, ARCHIVE_META, meta.as_slice())?;
        tar.append_path_with_name(self.pack(e), ARCHIVE_PACK)?;
        tar.into_inner()?;
        Ok(())
    }

    /// Adds the template in an `export` archive, replacing one with its ref.
    pub fn import(&self, file: &Path) -> Result<Entry> {
        let not_ours = || format!("{} isn't a smolbento template archive", file.display());
        let f = std::fs::File::open(file)
            .with_context(|| format!("failed to open {}", file.display()))?;
        let tmp = self.temp_dir()?;
        let mut meta: Option<Entry> = None;
        let mut pack = None;
        for entry in tar::Archive::new(f).entries().with_context(not_ours)? {
            let mut entry = entry.with_context(not_ours)?;
            let name = entry.path().with_context(not_ours)?.display().to_string();
            if matches!(name.as_str(), ARCHIVE_META | ARCHIVE_PACK)
                && !entry.header().entry_type().is_file()
            {
                bail!(not_ours());
            }
            match name.as_str() {
                ARCHIVE_META => {
                    // Truncation fails the JSON parse below.
                    let mut s = String::new();
                    (&mut entry).take(1 << 20).read_to_string(&mut s)?;
                    meta = Some(serde_json::from_str(&s).with_context(not_ours)?);
                }
                ARCHIVE_PACK => {
                    let p = tmp.path().join(ARCHIVE_PACK);
                    entry.unpack(&p)?;
                    pack = Some(p);
                }
                _ => {}
            }
        }
        let (Some(mut meta), Some(pack)) = (meta, pack) else {
            bail!(not_ours());
        };
        // The name is checked as `save` checks it, and stored normalized.
        let r = TemplateRef::parse(&meta.full()).with_context(not_ours)?;
        meta.repository = r.repository;
        meta.tag = r.tag;
        // `agent` and `image` end up in labels and argv.
        if crate::agents::find(&meta.agent).is_none()
            || meta.image.chars().any(char::is_control)
            || meta.agent.chars().any(char::is_control)
        {
            bail!(not_ours());
        }
        self.add(meta, &pack)
    }

    /// Deletes `e`'s pack unless another entry still names it.
    fn drop_unused(&self, index: &Index, e: &Entry) -> Result<()> {
        if index.templates.iter().all(|t| t.id != e.id) {
            match std::fs::remove_file(self.pack(e)) {
                Err(err) if err.kind() != std::io::ErrorKind::NotFound => return Err(err.into()),
                _ => {}
            }
        }
        Ok(())
    }
}

fn sha256_prefix(path: &Path) -> Result<String> {
    let mut f = std::fs::File::open(path).with_context(|| format!("reading {}", path.display()))?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    let hex: String = h.finalize().iter().map(|b| format!("{b:02x}")).collect();
    Ok(hex[..12].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let s = Store {
            dir: dir.path().join("templates"),
        };
        (dir, s)
    }

    fn meta(r: &str) -> Entry {
        let t = TemplateRef::parse(r).unwrap();
        Entry {
            repository: t.repository,
            tag: t.tag,
            agent: "shell".into(),
            image: "img:1".into(),
            docker: true,
            created_at: "2026-10-30T00:00:00Z".into(),
            ..Default::default()
        }
    }

    fn pack(dir: &Path, body: &str) -> PathBuf {
        let p = dir.join(format!("{body}.smolmachine"));
        std::fs::write(&p, body).unwrap();
        p
    }

    #[test]
    fn find_ref_ignores_id_prefixes() {
        let (dir, s) = store();
        let e = s.add(meta("t:v1"), &pack(dir.path(), "a")).unwrap();
        assert_eq!(s.find_ref("t:v1").unwrap(), Some(e.clone()));
        assert_eq!(s.find_ref(&e.id[..6]).unwrap(), None);
    }

    #[test]
    fn refs_normalize_like_docker() {
        let full = |r: &str| TemplateRef::parse(r).unwrap().full();
        assert_eq!(full("chk-tpl"), "docker.io/library/chk-tpl:latest");
        assert_eq!(full("chk-tpl:v1"), "docker.io/library/chk-tpl:v1");
        assert_eq!(full("me/tpl:v2"), "docker.io/me/tpl:v2");
        assert_eq!(full("ghcr.io/me/tpl:3"), "ghcr.io/me/tpl:3");
        assert!(TemplateRef::parse("Bad Name").is_err());
        assert!(TemplateRef::parse("x@sha256:abc").is_err());
    }

    #[test]
    fn add_list_find_remove() {
        let (dir, s) = store();
        let e = s.add(meta("chk-tpl:v1"), &pack(dir.path(), "a")).unwrap();
        assert_eq!(e.id.len(), 12);
        assert_eq!(e.size, 1);
        assert!(s.pack(&e).exists());
        assert_eq!(s.list().unwrap(), vec![e.clone()]);
        assert_eq!(s.find("chk-tpl:v1").unwrap(), Some(e.clone()));
        assert_eq!(
            s.find("docker.io/library/chk-tpl:v1").unwrap(),
            Some(e.clone())
        );
        assert_eq!(s.find(&e.id[..6]).unwrap(), Some(e.clone()));
        assert_eq!(s.find("chk-tpl").unwrap(), None, "latest isn't v1");
        s.remove(&e).unwrap();
        assert!(s.list().unwrap().is_empty());
        assert!(!s.pack(&e).exists());
    }

    #[test]
    fn saving_a_ref_again_replaces_it_and_drops_its_old_pack() {
        let (dir, s) = store();
        let old = s.add(meta("t:v1"), &pack(dir.path(), "a")).unwrap();
        let new = s.add(meta("t:v1"), &pack(dir.path(), "b")).unwrap();
        assert_ne!(old.id, new.id);
        assert_eq!(s.list().unwrap(), vec![new]);
        assert!(!s.pack(&old).exists());
    }

    #[test]
    fn two_refs_may_share_a_pack() {
        let (dir, s) = store();
        let a = s.add(meta("t:a"), &pack(dir.path(), "same")).unwrap();
        let b = s.add(meta("t:b"), &pack(dir.path(), "same")).unwrap();
        assert_eq!(a.id, b.id);
        s.remove(&a).unwrap();
        assert!(s.pack(&b).exists(), "still named by t:b");
    }

    #[test]
    fn store_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let (dir, s) = store();
        s.add(meta("t"), &pack(dir.path(), "a")).unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&s.dir), 0o700);
        assert_eq!(mode(&s.dir.join(INDEX)), 0o600);
    }

    #[test]
    fn export_then_import_round_trips() {
        let (dir, s) = store();
        let e = s.add(meta("t:v1"), &pack(dir.path(), "body")).unwrap();
        let out = dir.path().join("t.tar");
        s.export(&e, &out).unwrap();
        s.remove(&e).unwrap();
        let back = s.import(&out).unwrap();
        assert_eq!(back, e);
        assert_eq!(std::fs::read_to_string(s.pack(&back)).unwrap(), "body");
        let names: Vec<String> = tar::Archive::new(std::fs::File::open(&out).unwrap())
            .entries()
            .unwrap()
            .map(|e| e.unwrap().path().unwrap().display().to_string())
            .collect();
        assert_eq!(names, vec![ARCHIVE_META, ARCHIVE_PACK]);
    }

    #[test]
    fn import_refuses_other_files() {
        let (dir, s) = store();
        let f = dir.path().join("x.tar");
        std::fs::write(&f, "not a tar").unwrap();
        let err = s.import(&f).unwrap_err().to_string();
        assert!(err.contains("isn't a smolbento template archive"), "{err}");
        assert!(s.list().unwrap().is_empty());
    }

    #[test]
    fn import_refuses_links_in_the_archive() {
        let (dir, s) = store();
        let f = dir.path().join("x.tar");
        let mut b = tar::Builder::new(std::fs::File::create(&f).unwrap());
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Symlink);
        h.set_size(0);
        h.set_mode(0o600);
        b.append_link(&mut h, ARCHIVE_PACK, "/etc/passwd").unwrap();
        b.into_inner().unwrap();
        let err = s.import(&f).unwrap_err().to_string();
        assert!(err.contains("isn't a smolbento template archive"), "{err}");
        assert!(s.list().unwrap().is_empty());
    }

    fn backdate(p: &Path) {
        let old = std::time::SystemTime::now() - std::time::Duration::from_secs(2 * 3600);
        std::fs::File::open(p).unwrap().set_modified(old).unwrap();
    }

    #[test]
    fn temp_dir_sweeps_stale_temps_and_orphan_packs() {
        let (dir, s) = store();
        let kept = s.add(meta("t:v1"), &pack(dir.path(), "a")).unwrap();
        let stale_tmp = s.dir.join(".tmp-old");
        let fresh_tmp = s.dir.join(".tmp-new");
        std::fs::create_dir(&stale_tmp).unwrap();
        std::fs::create_dir(&fresh_tmp).unwrap();
        let stale_pack = s.dir.join("deadbeef0000.smolmachine");
        let fresh_pack = s.dir.join("cafe00000000.smolmachine");
        std::fs::write(&stale_pack, "x").unwrap();
        std::fs::write(&fresh_pack, "x").unwrap();
        backdate(&stale_tmp);
        backdate(&stale_pack);
        backdate(&s.pack(&kept)); // old but indexed
        let _t = s.temp_dir().unwrap();
        assert!(!stale_tmp.exists());
        assert!(!stale_pack.exists());
        assert!(fresh_tmp.exists());
        assert!(fresh_pack.exists());
        assert!(s.pack(&kept).exists());
    }

    #[test]
    fn find_refuses_an_ambiguous_id_prefix() {
        let (_dir, s) = store();
        let e = |id: &str, tag: &str| Entry {
            id: id.into(),
            tag: tag.into(),
            ..meta("t")
        };
        s.write(&Index {
            version: 1,
            templates: vec![e("abcd11111111", "a"), e("abcd22222222", "b")],
        })
        .unwrap();
        let err = s.find("abcd").unwrap_err();
        assert!(err.downcast_ref::<Ambiguous>().is_some(), "{err}");
        assert!(s.find("abcd1").unwrap().is_some());
        // A ref match wins over prefixes.
        assert!(s.find("t:a").unwrap().is_some());
    }

    fn archive(dir: &Path, m: &Entry) -> PathBuf {
        let f = dir.join("x.tar");
        let mut b = tar::Builder::new(std::fs::File::create(&f).unwrap());
        for (name, body) in [
            (ARCHIVE_META, serde_json::to_vec(m).unwrap()),
            (ARCHIVE_PACK, b"body".to_vec()),
        ] {
            let mut h = tar::Header::new_gnu();
            h.set_size(body.len() as u64);
            h.set_mode(0o600);
            h.set_cksum();
            b.append_data(&mut h, name, body.as_slice()).unwrap();
        }
        b.into_inner().unwrap();
        f
    }

    #[test]
    fn import_normalizes_the_ref() {
        let (dir, s) = store();
        let m = Entry {
            repository: "chk-tpl".into(),
            ..meta("t")
        };
        let e = s.import(&archive(dir.path(), &m)).unwrap();
        assert_eq!(e.full(), "docker.io/library/chk-tpl:latest");
        assert_eq!(e.repository, "docker.io/library/chk-tpl");
    }

    #[test]
    fn import_refuses_an_unknown_agent_or_control_characters() {
        let (dir, s) = store();
        for m in [
            Entry {
                agent: "nope".into(),
                ..meta("t")
            },
            Entry {
                image: "img\n:1".into(),
                ..meta("t")
            },
            Entry {
                agent: "shell\u{1b}".into(),
                ..meta("t")
            },
        ] {
            let err = s.import(&archive(dir.path(), &m)).unwrap_err().to_string();
            assert!(err.contains("isn't a smolbento template archive"), "{err}");
        }
        assert!(s.list().unwrap().is_empty());
    }
}
