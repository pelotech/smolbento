//! The host store: plain skill directories, replaced whole, plus sbx's `sources.json`.

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use super::valid_name;
use crate::config::{Paths, Symlink, write_atomic};

pub struct Store {
    pub dir: PathBuf,
    pub meta: PathBuf,
}

/// sbx's `agent-skills-metadata/sources.json`: where each repository-added skill came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sources {
    pub version: u32,
    pub skills: BTreeMap<String, Source>,
}

impl Default for Sources {
    fn default() -> Self {
        Sources {
            version: 1,
            skills: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Source {
    pub repository: String,
    pub commit: String,
}

impl Store {
    pub fn new(paths: &Paths) -> Store {
        Store {
            dir: paths.skills_store(),
            meta: paths.skills_metadata(),
        }
    }

    /// Creates the store (0700) so it can be mounted while empty.
    pub fn ensure(&self) -> Result<()> {
        private_dir(&self.dir)
    }

    /// Valid skill names, sorted. Temp and old directories start with `.` and never list.
    pub fn list(&self) -> Result<Vec<String>> {
        let entries = match fs::read_dir(&self.dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e).with_context(|| format!("reading {}", self.dir.display())),
        };
        let mut names: Vec<String> = entries
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
            .filter_map(|e| e.file_name().into_string().ok())
            .filter(|n| valid_name(n))
            .collect();
        names.sort();
        Ok(names)
    }

    pub fn has(&self, name: &str) -> bool {
        valid_name(name) && self.dir.join(name).is_dir()
    }

    /// Copies `src` in as `name`, swapping it in whole: readers see the old tree or the new one.
    pub fn install(&self, name: &str, src: &Path) -> Result<()> {
        if !valid_name(name) {
            bail!("invalid skill name {name:?}");
        }
        self.ensure()?;
        let tmp = tempfile::Builder::new()
            .prefix(&format!(".tmp-{name}-"))
            .tempdir_in(&self.dir)?;
        copy_tree(src, tmp.path())?;
        fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o755))?;
        let target = self.dir.join(name);
        let old = self.dir.join(format!(".old-{name}-{}", std::process::id()));
        let had = target.exists();
        if had {
            fs::rename(&target, &old).with_context(|| format!("replacing {}", target.display()))?;
        }
        fs::rename(tmp.keep(), &target)
            .with_context(|| format!("installing {}", target.display()))?;
        if had {
            fs::remove_dir_all(&old).with_context(|| format!("removing {}", old.display()))?;
        }
        Ok(())
    }

    pub fn remove(&self, name: &str) -> Result<()> {
        if !self.has(name) {
            bail!("skill {name:?} is not installed");
        }
        fs::remove_dir_all(self.dir.join(name))
            .with_context(|| format!("removing {}", self.dir.join(name).display()))
    }

    /// `sbt reset`: the store and its metadata.
    pub fn wipe(&self) -> Result<()> {
        for d in [&self.dir, &self.meta] {
            match fs::remove_dir_all(d) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                    return Err(e).with_context(|| format!("removing {}", d.display()));
                }
                _ => {}
            }
        }
        Ok(())
    }

    pub fn sources(&self) -> Result<Sources> {
        let path = self.meta.join("sources.json");
        match fs::read_to_string(&path) {
            Ok(t) => {
                serde_json::from_str(&t).with_context(|| format!("parsing {}", path.display()))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Sources::default()),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }

    pub fn save_sources(&self, s: &Sources) -> Result<()> {
        private_dir(&self.meta)?;
        let text = serde_json::to_string_pretty(s)? + "\n";
        write_atomic(
            &self.meta.join("sources.json"),
            text.as_bytes(),
            Some(0o600),
            Symlink::Replace,
        )
    }
}

fn private_dir(dir: &Path) -> Result<()> {
    fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("setting the mode of {}", dir.display()))
}

/// Copies directories and regular files (mode bits kept) from `src` into the existing `dst`.
/// Symlinks and other file types are skipped, as sbx does.
pub fn copy_tree(src: &Path, dst: &Path) -> Result<()> {
    for e in fs::read_dir(src).with_context(|| format!("reading {}", src.display()))? {
        let e = e?;
        let (from, to) = (e.path(), dst.join(e.file_name()));
        let t = e.file_type()?;
        if t.is_dir() {
            fs::create_dir(&to)?;
            fs::set_permissions(&to, fs::metadata(&from)?.permissions())?;
            copy_tree(&from, &to)?;
        } else if t.is_file() {
            fs::copy(&from, &to).with_context(|| format!("copying {}", from.display()))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, Store) {
        let d = tempfile::tempdir().unwrap();
        let s = Store {
            dir: d.path().join("agent-skills"),
            meta: d.path().join("agent-skills-metadata"),
        };
        (d, s)
    }

    fn skill(root: &Path, name: &str, body: &str) -> PathBuf {
        let p = root.join(name);
        fs::create_dir_all(p.join("scripts")).unwrap();
        fs::write(p.join("SKILL.md"), body).unwrap();
        fs::write(p.join("scripts/run.sh"), "#!/bin/sh\n").unwrap();
        fs::set_permissions(p.join("scripts/run.sh"), fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    #[test]
    fn install_lists_and_replaces_whole_trees() {
        let (d, s) = store();
        assert!(s.list().unwrap().is_empty());
        let src = skill(d.path(), "src", "one");
        fs::write(src.join("old.md"), "x").unwrap();
        s.install("beta", &src).unwrap();
        s.install("alpha", &src).unwrap();
        assert_eq!(s.list().unwrap(), ["alpha", "beta"]);
        let mode = fs::metadata(s.dir.join("alpha/scripts/run.sh"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o755);
        assert_eq!(
            fs::metadata(&s.dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        // Replacing drops files the new tree doesn't have.
        let src2 = skill(d.path(), "src2", "two");
        s.install("alpha", &src2).unwrap();
        assert_eq!(
            fs::read_to_string(s.dir.join("alpha/SKILL.md")).unwrap(),
            "two"
        );
        assert!(!s.dir.join("alpha/old.md").exists());
        // No temp or old directories left behind, and dot-dirs never list.
        fs::create_dir(s.dir.join(".tmp-x")).unwrap();
        assert_eq!(s.list().unwrap(), ["alpha", "beta"]);
    }

    #[test]
    fn copy_skips_symlinks() {
        let (d, s) = store();
        let src = skill(d.path(), "src", "one");
        std::os::unix::fs::symlink("/etc/passwd", src.join("leak")).unwrap();
        s.install("a", &src).unwrap();
        assert!(fs::symlink_metadata(s.dir.join("a/leak")).is_err());
    }

    #[test]
    fn remove_and_wipe() {
        let (d, s) = store();
        let src = skill(d.path(), "src", "one");
        s.install("a", &src).unwrap();
        s.remove("a").unwrap();
        assert!(!s.has("a"));
        assert!(s.remove("a").is_err());
        s.install("a", &src).unwrap();
        s.save_sources(&Sources::default()).unwrap();
        s.wipe().unwrap();
        assert!(!s.dir.exists() && !s.meta.exists());
    }

    #[test]
    fn sources_round_trip_in_sbx_format() {
        let (_d, s) = store();
        assert_eq!(s.sources().unwrap(), Sources::default());
        let mut src = Sources::default();
        src.skills.insert(
            "pdf".into(),
            Source {
                repository: "https://github.com/anthropics/skills".into(),
                commit: "ca45".into(),
            },
        );
        s.save_sources(&src).unwrap();
        let text = fs::read_to_string(s.meta.join("sources.json")).unwrap();
        assert!(
            text.contains(r#""version": 1"#)
                && text.contains(r#""repository": "https://github.com/anthropics/skills""#),
            "{text}"
        );
        assert_eq!(
            fs::metadata(s.meta.join("sources.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(s.sources().unwrap(), src);
    }
}
