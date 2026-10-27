//! Host git helpers for tests.

use std::path::{Path, PathBuf};
use std::process::Command;

/// A temp git repo (`<tmp>/repo`, branch main, one empty commit).
pub fn temp_repo() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap().join("repo");
    std::fs::create_dir(&root).unwrap();
    git(&root, &["init", "-q", "-b", "main"]);
    git(
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

/// Runs `git -C dir args`, asserting success.
pub fn git(dir: &Path, args: &[&str]) {
    let st = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .status()
        .unwrap();
    assert!(st.success(), "git {args:?}");
}

/// `git -C repo config key`, trimmed; empty when unset.
pub fn git_config(repo: &Path, key: &str) -> String {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["config", key])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}
