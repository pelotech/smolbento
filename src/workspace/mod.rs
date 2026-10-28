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
        check_dir(&path)?;
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

fn check_dir(path: &Path) -> Result<()> {
    if !path.is_dir() {
        bail!(
            "workspace {} is a file; smolvm can only mount directories",
            path.display()
        );
    }
    Ok(())
}

/// Parses `--mount HOST:SANDBOX_PATH` into the canonical host directory and the guest path. HOST
/// is relative to `cwd`; SANDBOX_PATH is after the last `:`.
pub fn parse_mount(arg: &str, cwd: &Path) -> Result<(PathBuf, String)> {
    let (host, guest) = match arg.rsplit_once(':') {
        Some((h, g)) if !h.is_empty() && !g.is_empty() => (h, g),
        _ => bail!("--mount \"{arg}\" requires HOST:SANDBOX_PATH\n  try: sbt create --help"),
    };
    let abs = cwd.join(host);
    let host = abs
        .canonicalize()
        .ok()
        .with_context(|| format!("HOST \"{}\" does not exist on the host", abs.display()))?;
    check_dir(&host)?;
    Ok((host, guest.to_string()))
}

/// `parse_mount` for each `--mount`; a SANDBOX_PATH is bound once.
pub fn parse_mounts(args: &[String], cwd: &Path) -> Result<Vec<(PathBuf, String)>> {
    let mut mounts: Vec<(PathBuf, String)> = Vec::new();
    for arg in args {
        let (host, guest) = parse_mount(arg, cwd)?;
        if mounts.iter().any(|(_, g)| *g == guest) {
            bail!("--mount {guest} given twice");
        }
        mounts.push((host, guest));
    }
    Ok(mounts)
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

    #[test]
    fn parses_a_mount_binding() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        std::fs::create_dir(root.join("data")).unwrap();
        std::fs::write(root.join("f"), "x").unwrap();
        assert_eq!(
            parse_mount("data:/home/agent/x", &root).unwrap(),
            (root.join("data"), "/home/agent/x".to_string())
        );
        // HOST may hold a `:`; SANDBOX_PATH is after the last one.
        std::fs::create_dir(root.join("a:b")).unwrap();
        assert_eq!(parse_mount("a:b:/x", &root).unwrap().0, root.join("a:b"));
        let err = |arg: &str| format!("{:#}", parse_mount(arg, &root).unwrap_err());
        for arg in ["data", ":/x", "data:"] {
            assert_eq!(
                err(arg),
                format!("--mount \"{arg}\" requires HOST:SANDBOX_PATH\n  try: sbt create --help")
            );
        }
        assert_eq!(
            err("missing:/x"),
            format!(
                "HOST \"{}\" does not exist on the host",
                root.join("missing").display()
            )
        );
        assert_eq!(
            err("f:/x"),
            format!(
                "workspace {} is a file; smolvm can only mount directories",
                root.join("f").display()
            )
        );
    }

    #[test]
    fn a_sandbox_path_can_be_bound_once() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let args = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(
            parse_mounts(&args(&[".:/a", ".:/b"]), &root).unwrap().len(),
            2
        );
        let e = parse_mounts(&args(&[".:/a", ".:/a"]), &root).unwrap_err();
        assert_eq!(e.to_string(), "--mount /a given twice");
    }
}
