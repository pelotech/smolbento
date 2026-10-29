//! `sbt skills add/update`: repository URLs, a shallow clone with host git, and the skills in it.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};

use super::valid_name;

/// `owner/repo` (GitHub) or a remote git URL, as sbx accepts them, except plaintext `http://`
/// and `git://` (see docs/sbx-compatibility.md).
pub fn parse_url(arg: &str) -> Result<String> {
    const BAD: &str = "repository must be a remote Git URL or GitHub owner/repository";
    if let Some((scheme, _)) = arg.split_once("://") {
        return match scheme {
            "https" | "ssh" => Ok(arg.to_string()),
            _ => bail!("{BAD}: {scheme}: invalid protocol"),
        };
    }
    // scp-like `user@host:path`
    if let Some((user_host, path)) = arg.split_once(':')
        && user_host.contains('@')
        && !path.is_empty()
    {
        return Ok(arg.to_string());
    }
    let parts: Vec<&str> = arg.split('/').collect();
    let ok = |s: &str| {
        !s.is_empty()
            && s != "."
            && s != ".."
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    };
    if parts.len() == 2 && parts.iter().all(|p| ok(p)) {
        return Ok(format!("https://github.com/{arg}"));
    }
    bail!("{BAD}: {arg}")
}

/// A shallow clone in a temp dir, removed on drop.
pub struct Checkout {
    pub url: String,
    pub commit: String,
    root: PathBuf,
    _dir: tempfile::TempDir,
}

impl Checkout {
    pub fn root(&self) -> &Path {
        &self.root
    }
}

/// `git clone --depth 1` with the user's git (credentials, helpers and SSH agent apply; hooks
/// don't run). Git's own messages go to the terminal.
pub fn clone(url: &str) -> Result<Checkout> {
    let dir = tempfile::tempdir()?;
    let root = dir.path().join("repo");
    let status = Command::new("git")
        .args([
            "-c",
            "core.hooksPath=/dev/null",
            "clone",
            "--depth",
            "1",
            "--quiet",
            "--no-tags",
            "--",
            url,
        ])
        .arg(&root)
        .status()
        .context("running git")?;
    if !status.success() {
        bail!("cloning {url}: git exited with {status}");
    }
    let out = Command::new("git")
        .arg("-C")
        .arg(&root)
        .args(["rev-parse", "HEAD"])
        .output()?;
    if !out.status.success() {
        bail!("cloning {url}: reading the commit failed");
    }
    Ok(Checkout {
        url: url.to_string(),
        commit: String::from_utf8_lossy(&out.stdout).trim().to_string(),
        root,
        _dir: dir,
    })
}

/// Every directory below `root` (not `.git`, never through a symlink) with a regular `SKILL.md`,
/// by its basename. Invalid names are skipped with a warning.
pub fn discover(root: &Path) -> Result<BTreeMap<String, PathBuf>> {
    let mut found: BTreeMap<String, PathBuf> = BTreeMap::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for e in fs::read_dir(&dir).with_context(|| format!("reading {}", dir.display()))? {
            let e = e?;
            if e.file_type()?.is_dir() && e.file_name() != ".git" {
                stack.push(e.path());
            }
        }
        if dir == root || !fs::symlink_metadata(dir.join("SKILL.md")).is_ok_and(|m| m.is_file()) {
            continue;
        }
        let name = dir
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        if !valid_name(&name) {
            eprintln!(
                "warning: skipping {}: {name:?} is not a valid skill name",
                dir.display()
            );
            continue;
        }
        if let Some(other) = found.insert(name.clone(), dir.clone()) {
            bail!(
                "two skills named {name:?}: {} and {}",
                other.display(),
                dir.display()
            );
        }
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testgit::git;

    #[test]
    fn urls() {
        assert_eq!(
            parse_url("anthropics/skills").unwrap(),
            "https://github.com/anthropics/skills"
        );
        for keep in [
            "https://github.com/a/b",
            "https://host/x/y.git",
            "ssh://git@host/x.git",
            "git@github.com:a/b.git",
        ] {
            assert_eq!(parse_url(keep).unwrap(), keep);
        }
        let e = parse_url("file:///tmp/x").unwrap_err().to_string();
        assert_eq!(
            e,
            "repository must be a remote Git URL or GitHub owner/repository: file: invalid protocol"
        );
        for bad in ["/tmp/x", "./x", "x", "a/b/c", "ftp://h/x"] {
            assert!(parse_url(bad).is_err(), "{bad}");
        }
        // Plaintext transports are refused like any other scheme.
        for (bad, scheme) in [("http://host/x.git", "http"), ("git://host/x.git", "git")] {
            assert_eq!(
                parse_url(bad).unwrap_err().to_string(),
                format!(
                    "repository must be a remote Git URL or GitHub owner/repository: {scheme}: invalid protocol"
                )
            );
        }
    }

    fn repo(dir: &Path) {
        for (p, body) in [
            ("skills/alpha/SKILL.md", "a"),
            ("beta/SKILL.md", "b"),
            ("docs/README.md", "x"),
            (".git-like/SKILL.md", "no"),
        ] {
            let f = dir.join(p);
            fs::create_dir_all(f.parent().unwrap()).unwrap();
            fs::write(f, body).unwrap();
        }
        git(dir, &["init", "-q"]);
        git(dir, &["add", "-A"]);
        git(
            dir,
            &[
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@t",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "-qm",
                "init",
            ],
        );
    }

    #[test]
    fn clones_and_discovers_skill_dirs() {
        let d = tempfile::tempdir().unwrap();
        repo(d.path());
        let c = clone(d.path().to_str().unwrap()).unwrap();
        assert_eq!(c.commit.len(), 40);
        let found = discover(c.root()).unwrap();
        assert_eq!(found.keys().collect::<Vec<_>>(), ["alpha", "beta"]);
        assert!(found["alpha"].ends_with("skills/alpha"));
    }

    #[test]
    fn two_skills_with_one_name_is_an_error() {
        let d = tempfile::tempdir().unwrap();
        for p in ["a/x/SKILL.md", "b/x/SKILL.md"] {
            fs::create_dir_all(d.path().join(p).parent().unwrap()).unwrap();
            fs::write(d.path().join(p), "s").unwrap();
        }
        let e = discover(d.path()).unwrap_err().to_string();
        assert!(e.contains("two skills named \"x\""), "{e}");
    }
}
