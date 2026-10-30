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
    pub fn find(&self, name: &str) -> Result<Option<Entry>> {
        let all = self.list()?;
        if let Ok(r) = TemplateRef::parse(name)
            && let Some(e) = all.iter().find(|e| e.full() == r.full())
        {
            return Ok(Some(e.clone()));
        }
        let hex = name.len() >= 4 && name.bytes().all(|b| b.is_ascii_hexdigit());
        Ok(all
            .into_iter()
            .find(|e| hex && e.id.starts_with(&name.to_ascii_lowercase())))
    }

    pub fn pack(&self, e: &Entry) -> PathBuf {
        self.dir.join(format!("{}.smolmachine", e.id))
    }

    /// A temp dir inside the store, so `add` renames within one filesystem.
    pub fn temp_dir(&self) -> Result<tempfile::TempDir> {
        self.ensure()?;
        Ok(tempfile::Builder::new()
            .prefix(".tmp-")
            .tempdir_in(&self.dir)?)
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
}
