//! Workspace directories, mounted at the same absolute path inside the sandbox.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

pub mod clone;

use crate::smolvm::Mount;

/// Working directory of a sandbox created without a workspace (sbx's choice).
pub const MOUNTLESS_WORKDIR: &str = "/home/agent/workspace";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Workspace {
    pub path: PathBuf,
    pub read_only: bool,
}

impl Workspace {
    /// Parses `PATH` or `PATH:ro`, relative to `cwd`.
    pub fn parse(arg: &str, cwd: &Path) -> Result<Workspace> {
        let (raw, read_only) = match arg.strip_suffix(":ro") {
            Some(path) => (path, true),
            None => (arg, false),
        };
        let path = cwd
            .join(raw)
            .canonicalize()
            .with_context(|| format!("workspace {raw} does not exist"))?;
        if !path.is_dir() {
            bail!(
                "workspace {} is a file; smolvm can only mount directories",
                path.display()
            );
        }
        Ok(Workspace { path, read_only })
    }

    pub fn mount(&self) -> Mount {
        Mount {
            host: Some(self.path.clone()),
            guest: self.path.display().to_string(),
            read_only: self.read_only,
        }
    }

    /// Back from `label`.
    pub fn from_label(label: &str) -> Workspace {
        match label.strip_suffix(":ro") {
            Some(path) => Workspace {
                path: path.into(),
                read_only: true,
            },
            None => Workspace {
                path: label.into(),
                read_only: false,
            },
        }
    }

    /// As stored in the `sbx.workspaces` label.
    pub fn label(&self) -> String {
        if self.read_only {
            format!("{}:ro", self.path.display())
        } else {
            self.path.display().to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_relative_and_read_only() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        std::fs::create_dir(root.join("docs")).unwrap();

        let w = Workspace::parse(".", &root).unwrap();
        assert_eq!(
            w,
            Workspace {
                path: root.clone(),
                read_only: false
            }
        );

        let w = Workspace::parse("docs:ro", &root).unwrap();
        assert!(w.read_only);
        assert_eq!(w.label(), format!("{}:ro", root.join("docs").display()));
        assert_eq!(Workspace::from_label(&w.label()), w);
        let m = w.mount();
        assert_eq!(m.host.as_deref(), Some(root.join("docs").as_path()));
        assert_eq!(m.guest, root.join("docs").display().to_string());
        assert!(m.read_only);
    }

    #[test]
    fn rejects_missing_and_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("f"), "x").unwrap();
        assert!(
            Workspace::parse("missing", dir.path())
                .unwrap_err()
                .to_string()
                .contains("does not exist")
        );
        assert!(
            Workspace::parse("f", dir.path())
                .unwrap_err()
                .to_string()
                .contains("only mount directories")
        );
    }
}
