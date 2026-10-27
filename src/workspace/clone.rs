//! Clone mode, host side: the repo a `--clone` sandbox copies, and its `sandbox-<name>` remote.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};

/// Where the host repo's git dir is mounted, read-only, in a clone sandbox (as sbx).
pub const SOURCE_MOUNT: &str = "/run/sandbox/source";

/// The host repo a clone sandbox is made from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloneSource {
    /// Top of the working tree: the clone's path in the sandbox.
    pub top: PathBuf,
    /// The git common dir (a linked worktree's is the main repo's `.git`), mounted read-only.
    pub git_dir: PathBuf,
}

/// The git binary isn't installed (as opposed to git failing).
#[derive(Debug)]
struct GitMissing;

impl std::fmt::Display for GitMissing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("clone mode needs git on the host")
    }
}

impl std::error::Error for GitMissing {}

/// Runs host git in `repo`; the error is git's first stderr line.
fn git(repo: &Path, args: &[&str]) -> Result<String> {
    git_with("git", repo, args)
}

fn git_with(program: &str, repo: &Path, args: &[&str]) -> Result<String> {
    let out = Command::new(program)
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => anyhow::Error::new(GitMissing),
            _ => anyhow::Error::new(e).context("running git"),
        })?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        bail!(
            "git {}: {}",
            args.join(" "),
            err.lines().next().unwrap_or("failed")
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim_end().to_string())
}

pub fn source(path: &Path) -> Result<CloneSource> {
    source_with("git", path)
}

fn source_with(program: &str, path: &Path) -> Result<CloneSource> {
    let out = git_with(
        program,
        path,
        &[
            "rev-parse",
            "--path-format=absolute",
            "--show-toplevel",
            "--git-common-dir",
        ],
    )
    .map_err(|e| {
        if e.is::<GitMissing>() {
            e
        } else {
            anyhow::anyhow!(
                "--clone needs a git repository; {} isn't one",
                path.display()
            )
        }
    })?;
    let mut lines = out.lines();
    let (Some(top), Some(git_dir)) = (lines.next(), lines.next()) else {
        bail!(
            "--clone needs a git repository; {} isn't one",
            path.display()
        );
    };
    Ok(CloneSource {
        top: top.into(),
        git_dir: git_dir.into(),
    })
}

pub fn worktree_branch(path: &Path) -> Result<Option<String>> {
    let out = git(
        path,
        &[
            "rev-parse",
            "--path-format=absolute",
            "--git-dir",
            "--git-common-dir",
        ],
    )?;
    let mut lines = out.lines();
    if lines.next() == lines.next() {
        return Ok(None);
    }
    Ok(git(path, &["symbolic-ref", "-q", "--short", "HEAD"])
        .ok()
        .filter(|b| !b.is_empty()))
}

pub fn remote_name(sandbox: &str) -> String {
    format!("sandbox-{sandbox}")
}

pub fn upload_pack_cmd(sandbox: &str) -> String {
    format!("sbt _upload-pack {sandbox}")
}

/// Whether `sandbox-<name>` exists, and whether smolbento made it.
fn remote_owner(repo: &Path, sandbox: &str) -> Option<bool> {
    let remote = remote_name(sandbox);
    git(repo, &["config", &format!("remote.{remote}.url")]).ok()?;
    let pack = git(repo, &["config", &format!("remote.{remote}.uploadpack")]).unwrap_or_default();
    Some(pack == upload_pack_cmd(sandbox))
}

pub fn check_remote_free(repo: &Path, sandbox: &str) -> Result<()> {
    if remote_owner(repo, sandbox) == Some(false) {
        bail!(
            "the repo already has a remote '{}'; rename or remove it first",
            remote_name(sandbox)
        );
    }
    Ok(())
}

pub fn add_remote(repo: &Path, sandbox: &str) -> Result<()> {
    let remote = remote_name(sandbox);
    if remote_owner(repo, sandbox).is_none() {
        git(
            repo,
            &["remote", "add", &remote, &format!("file:///sbt/{sandbox}")],
        )?;
    }
    git(
        repo,
        &[
            "config",
            &format!("remote.{remote}.uploadpack"),
            &upload_pack_cmd(sandbox),
        ],
    )?;
    // Only commits come back: tags the agent makes must not land in the host's refs/tags.
    git(
        repo,
        &["config", &format!("remote.{remote}.tagOpt"), "--no-tags"],
    )?;
    Ok(())
}

pub fn remove_remote(repo: &Path, sandbox: &str) {
    if remote_owner(repo, sandbox) == Some(true) {
        let _ = git(repo, &["remote", "remove", &remote_name(sandbox)]);
    }
}

/// A path or `file://` URL: not reachable from the sandbox.
fn is_local(url: &str) -> bool {
    if url.starts_with("file://") {
        return true;
    }
    if url.contains("://") {
        return false;
    }
    // scp-style `[user@]host:path` has no `/` before its `:`.
    url.find(':').is_none_or(|i| url[..i].contains('/'))
}

/// An http(s) URL without `user[:token]@`, so no host credential reaches the sandbox.
fn strip_userinfo(url: &str) -> String {
    for scheme in ["https://", "http://"] {
        if let Some(rest) = url.strip_prefix(scheme) {
            let end = rest.find('/').unwrap_or(rest.len());
            if let Some(at) = rest[..end].rfind('@') {
                return format!("{scheme}{}", &rest[at + 1..]);
            }
        }
    }
    url.to_string()
}

pub fn copied_remotes(repo: &Path) -> Result<Vec<(String, String)>> {
    let mut out = Vec::new();
    for name in git(repo, &["remote"])?.lines() {
        if name.starts_with("sandbox-") {
            continue;
        }
        let url = git(repo, &["remote", "get-url", name])?;
        if !is_local(&url) {
            out.push((name.to_string(), strip_userinfo(&url)));
        }
    }
    Ok(out)
}

pub fn fetch(repo: &Path, sandbox: &str) -> Result<()> {
    let status = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args([
            "-c",
            "fetch.fsckObjects=true",
            "fetch",
            "--no-tags",
            "--no-recurse-submodules",
            &remote_name(sandbox),
        ])
        .status()
        .context("running git")?;
    if !status.success() {
        bail!("git fetch {} failed", remote_name(sandbox));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    fn git_in(dir: &Path, args: &[&str]) {
        let st = Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(args)
            .status()
            .unwrap();
        assert!(st.success(), "git {args:?}");
    }

    fn repo() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap().join("repo");
        std::fs::create_dir(&root).unwrap();
        git_in(&root, &["init", "-q", "-b", "main"]);
        git_in(
            &root,
            &[
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@t",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "-q",
                "--allow-empty",
                "-m",
                "base",
            ],
        );
        (dir, root)
    }

    #[test]
    fn source_finds_top_and_git_dir_from_a_subdirectory() {
        let (_d, root) = repo();
        std::fs::create_dir(root.join("sub")).unwrap();
        let s = source(&root.join("sub")).unwrap();
        assert_eq!(
            s,
            CloneSource {
                top: root.clone(),
                git_dir: root.join(".git")
            }
        );
    }

    #[test]
    fn source_rejects_a_plain_directory() {
        let d = tempfile::tempdir().unwrap();
        let err = source(d.path()).unwrap_err().to_string();
        assert!(err.contains("--clone needs a git repository"), "{err}");
    }

    #[test]
    fn source_reports_missing_git_not_a_missing_repo() {
        let d = tempfile::tempdir().unwrap();
        let err = source_with("sbt-no-such-git", d.path())
            .unwrap_err()
            .to_string();
        assert_eq!(err, "clone mode needs git on the host");
    }

    #[test]
    fn linked_worktree_uses_the_main_git_dir_and_its_own_branch() {
        let (d, root) = repo();
        let wt = d.path().canonicalize().unwrap().join("wt");
        git_in(
            &root,
            &["worktree", "add", "-q", "-b", "feat", wt.to_str().unwrap()],
        );
        let s = source(&wt).unwrap();
        assert_eq!(s.top, wt);
        assert_eq!(s.git_dir, root.join(".git"));
        assert_eq!(worktree_branch(&wt).unwrap().as_deref(), Some("feat"));
        assert_eq!(worktree_branch(&root).unwrap(), None);
    }

    #[test]
    fn remote_add_check_and_remove() {
        let (_d, root) = repo();
        check_remote_free(&root, "box").unwrap();
        add_remote(&root, "box").unwrap();
        let get = |k: &str| {
            let o = Command::new("git")
                .arg("-C")
                .arg(&root)
                .args(["config", k])
                .output()
                .unwrap();
            String::from_utf8(o.stdout).unwrap().trim().to_string()
        };
        assert_eq!(get("remote.sandbox-box.url"), "file:///sbt/box");
        assert_eq!(get("remote.sandbox-box.uploadpack"), "sbt _upload-pack box");
        assert_eq!(get("remote.sandbox-box.tagopt"), "--no-tags");
        assert_eq!(
            get("remote.sandbox-box.fetch"),
            "+refs/heads/*:refs/remotes/sandbox-box/*"
        );
        // Ours: a re-create may reuse it.
        check_remote_free(&root, "box").unwrap();
        remove_remote(&root, "box");
        assert_eq!(get("remote.sandbox-box.url"), "");
        // Foreign: refused, and never removed.
        git_in(
            &root,
            &["remote", "add", "sandbox-box", "https://example.com/x.git"],
        );
        let err = check_remote_free(&root, "box").unwrap_err().to_string();
        assert!(err.contains("sandbox-box"), "{err}");
        remove_remote(&root, "box");
        assert_eq!(get("remote.sandbox-box.url"), "https://example.com/x.git");
        // A missing repo is silent.
        remove_remote(Path::new("/nonexistent/repo"), "box");
    }

    #[test]
    fn copied_remotes_skip_local_and_strip_http_userinfo() {
        let (_d, root) = repo();
        git_in(
            &root,
            &[
                "remote",
                "add",
                "origin",
                "https://u:tok@github.com/o/r.git",
            ],
        );
        git_in(&root, &["remote", "add", "up", "git@github.com:o/r.git"]);
        git_in(&root, &["remote", "add", "ssh", "ssh://git@host/r.git"]);
        git_in(&root, &["remote", "add", "path", "/srv/r.git"]);
        git_in(&root, &["remote", "add", "file", "file:///srv/r.git"]);
        add_remote(&root, "box").unwrap();
        let mut got = copied_remotes(&root).unwrap();
        got.sort();
        assert_eq!(
            got,
            vec![
                ("origin".into(), "https://github.com/o/r.git".into()),
                ("ssh".into(), "ssh://git@host/r.git".into()),
                ("up".into(), "git@github.com:o/r.git".into()),
            ]
        );
    }

    #[test]
    fn is_local_classifies_urls() {
        assert!(is_local("/srv/r.git"));
        assert!(is_local("../r.git"));
        assert!(is_local("file:///srv/r.git"));
        assert!(!is_local("https://host/x"));
        assert!(!is_local("ssh://git@host/r.git"));
        assert!(!is_local("git@github.com:o/r.git"));
        assert!(!is_local("host:path"));
    }

    #[test]
    fn strip_userinfo_edge_cases() {
        assert_eq!(strip_userinfo("https://host/x"), "https://host/x");
        assert_eq!(strip_userinfo("http://u@h:8080/x"), "http://h:8080/x");
        assert_eq!(strip_userinfo("https://u:t@h"), "https://h");
        assert_eq!(strip_userinfo("https://h/a@b"), "https://h/a@b");
        assert_eq!(strip_userinfo("ssh://git@h/x"), "ssh://git@h/x");
    }
}
