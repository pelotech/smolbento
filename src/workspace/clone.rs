//! Clone mode, host side: the repo a `--clone` sandbox copies, and its `sandbox-<name>` remote.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

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

/// Spawns `program -C repo args`; a missing binary is [`GitMissing`].
fn git_output(program: &str, repo: &Path, args: &[&str]) -> Result<Output> {
    Command::new(program)
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => anyhow::Error::new(GitMissing),
            _ => anyhow::Error::new(e).context("running git"),
        })
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).trim_end().to_string()
}

/// git's first stderr line.
fn first_line(out: &Output) -> String {
    let err = String::from_utf8_lossy(&out.stderr);
    err.lines().next().unwrap_or("failed").to_string()
}

/// Runs host git in `repo`; the error is git's first stderr line.
fn git(repo: &Path, args: &[&str]) -> Result<String> {
    let out = git_output("git", repo, args)?;
    if !out.status.success() {
        bail!("git {}: {}", args.join(" "), first_line(&out));
    }
    Ok(stdout(&out))
}

pub fn source(path: &Path) -> Result<CloneSource> {
    source_with("git", path)
}

/// `source` with another git binary. Only git failing means "not a repo"; a spawn error stays.
fn source_with(program: &str, path: &Path) -> Result<CloneSource> {
    let out = git_output(
        program,
        path,
        &[
            "rev-parse",
            "--path-format=absolute",
            "--show-toplevel",
            "--git-common-dir",
        ],
    )?;
    let text = stdout(&out);
    let mut lines = text.lines();
    match (out.status.success(), lines.next(), lines.next()) {
        (true, Some(top), Some(git_dir)) => Ok(CloneSource {
            top: top.into(),
            git_dir: git_dir.into(),
        }),
        _ => bail!(
            "--clone needs a git repository; {} isn't one",
            path.display()
        ),
    }
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
    let (git_dir, common) = (lines.next(), lines.next());
    if git_dir == common {
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
    format!("smolbento _upload-pack {sandbox}")
}

/// Whether `sandbox-<name>` exists, and whether smolbento made it.
#[derive(Debug, PartialEq, Eq)]
enum Remote {
    Absent,
    Ours,
    Foreign,
}

fn remote_owner(repo: &Path, sandbox: &str) -> Result<Remote> {
    let remote = remote_name(sandbox);
    if config_get(repo, &format!("remote.{remote}.url"))?.is_none() {
        return Ok(Remote::Absent);
    }
    let pack = config_get(repo, &format!("remote.{remote}.uploadpack"))?.unwrap_or_default();
    Ok(if pack == upload_pack_cmd(sandbox) {
        Remote::Ours
    } else {
        Remote::Foreign
    })
}

/// `git config <key>`: `None` when the key is unset (exit 1); any other failure is an error.
fn config_get(repo: &Path, key: &str) -> Result<Option<String>> {
    let out = git_output("git", repo, &["config", key])?;
    match out.status.code() {
        Some(0) => Ok(Some(stdout(&out))),
        Some(1) => Ok(None),
        _ => bail!("git config {key}: {}", first_line(&out)),
    }
}

pub fn check_remote_free(repo: &Path, sandbox: &str) -> Result<()> {
    if remote_owner(repo, sandbox)? == Remote::Foreign {
        bail!(
            "the repo already has a remote '{}'; rename or remove it first",
            remote_name(sandbox)
        );
    }
    Ok(())
}

/// Adds and configures the `sandbox-<name>` remote; `true` when it created it (rather than reusing
/// one an earlier sandbox of this name left).
pub fn add_remote(repo: &Path, sandbox: &str) -> Result<bool> {
    let remote = remote_name(sandbox);
    let added = remote_owner(repo, sandbox)? == Remote::Absent;
    if added {
        git(
            repo,
            &["remote", "add", &remote, &format!("file:///sbt/{sandbox}")],
        )?;
    }
    let configure = || -> Result<()> {
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
    };
    configure().inspect_err(|_| {
        // Half-configured, it would read as a foreign remote; don't leave it behind.
        if added {
            let _ = git(repo, &["remote", "remove", &remote]);
        }
    })?;
    Ok(added)
}

pub fn remove_remote(repo: &Path, sandbox: &str) {
    if matches!(remote_owner(repo, sandbox), Ok(Remote::Ours)) {
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

/// An http(s) URL without `user[:token]@`, so the clone's copied remotes hold no credential.
/// The sandbox can still read the host repo's own config at [`SOURCE_MOUNT`].
fn strip_userinfo(url: &str) -> String {
    if let Some((scheme, rest)) = url.split_once("://")
        && ["http", "https"]
            .iter()
            .any(|s| scheme.eq_ignore_ascii_case(s))
    {
        let end = rest.find('/').unwrap_or(rest.len());
        if let Some(at) = rest[..end].rfind('@') {
            return format!("{scheme}://{}", &rest[at + 1..]);
        }
    }
    url.to_string()
}

/// Every remote's name and URL (`get-url`, so `insteadOf` rewrites apply).
fn remotes(repo: &Path) -> Result<Vec<(String, String)>> {
    git(repo, &["remote"])?
        .lines()
        .map(|name| Ok((name.to_string(), git(repo, &["remote", "get-url", name])?)))
        .collect()
}

/// Remotes whose http(s) URL carries a user name or token, which the sandbox can read in the
/// mounted host config.
pub fn userinfo_remotes(repo: &Path) -> Result<Vec<String>> {
    Ok(remotes(repo)?
        .into_iter()
        .filter(|(_, url)| strip_userinfo(url) != *url)
        .map(|(name, _)| name)
        .collect())
}

pub fn copied_remotes(repo: &Path) -> Result<Vec<(String, String)>> {
    Ok(remotes(repo)?
        .into_iter()
        .filter(|(name, url)| !name.starts_with("sandbox-") && !is_local(url))
        .map(|(name, url)| (name, strip_userinfo(&url)))
        .collect())
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
    use crate::testgit::{git, git_config, temp_repo};

    #[test]
    fn source_finds_top_and_git_dir_from_a_subdirectory() {
        let (_d, root) = temp_repo();
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
        let (d, root) = temp_repo();
        let wt = d.path().canonicalize().unwrap().join("wt");
        git(
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
        let (_d, root) = temp_repo();
        check_remote_free(&root, "box").unwrap();
        assert!(add_remote(&root, "box").unwrap(), "created");
        let get = |k: &str| git_config(&root, k);
        assert_eq!(get("remote.sandbox-box.url"), "file:///sbt/box");
        assert_eq!(
            get("remote.sandbox-box.uploadpack"),
            "smolbento _upload-pack box"
        );
        assert_eq!(get("remote.sandbox-box.tagopt"), "--no-tags");
        assert_eq!(
            get("remote.sandbox-box.fetch"),
            "+refs/heads/*:refs/remotes/sandbox-box/*"
        );
        // Ours: a re-create may reuse it.
        assert_eq!(remote_owner(&root, "box").unwrap(), Remote::Ours);
        check_remote_free(&root, "box").unwrap();
        assert!(!add_remote(&root, "box").unwrap(), "reused");
        remove_remote(&root, "box");
        assert_eq!(get("remote.sandbox-box.url"), "");
        // Foreign: refused, and never removed.
        git(
            &root,
            &["remote", "add", "sandbox-box", "https://example.com/x.git"],
        );
        let err = check_remote_free(&root, "box").unwrap_err().to_string();
        assert!(err.contains("sandbox-box"), "{err}");
        remove_remote(&root, "box");
        assert_eq!(get("remote.sandbox-box.url"), "https://example.com/x.git");
        assert_eq!(remote_owner(&root, "box").unwrap(), Remote::Foreign);
        // A missing repo is silent.
        remove_remote(Path::new("/nonexistent/repo"), "box");
    }

    #[test]
    fn copied_remotes_skip_local_and_strip_http_userinfo() {
        let (_d, root) = temp_repo();
        git(
            &root,
            &[
                "remote",
                "add",
                "origin",
                "https://u:tok@github.com/o/r.git",
            ],
        );
        git(&root, &["remote", "add", "up", "git@github.com:o/r.git"]);
        git(&root, &["remote", "add", "ssh", "ssh://git@host/r.git"]);
        git(&root, &["remote", "add", "path", "/srv/r.git"]);
        git(&root, &["remote", "add", "file", "file:///srv/r.git"]);
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
        assert_eq!(strip_userinfo("HTTPS://u:t@h/x"), "HTTPS://h/x");
        assert_eq!(strip_userinfo("Http://u@h/x"), "Http://h/x");
    }

    #[test]
    fn userinfo_remotes_names_the_remotes_with_credentials() {
        let (_d, root) = temp_repo();
        git(
            &root,
            &["remote", "add", "origin", "https://u:tok@h/o/r.git"],
        );
        git(&root, &["remote", "add", "up", "https://h/o/r.git"]);
        git(&root, &["remote", "add", "ssh", "ssh://git@h/r.git"]);
        assert_eq!(userinfo_remotes(&root).unwrap(), vec!["origin"]);
    }

    #[test]
    fn source_passes_other_spawn_errors_through() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let prog = d.path().join("not-executable");
        std::fs::write(&prog, "").unwrap();
        std::fs::set_permissions(&prog, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = format!(
            "{:#}",
            source_with(prog.to_str().unwrap(), d.path()).unwrap_err()
        );
        assert!(err.contains("running git"), "{err}");
        assert!(!err.contains("isn't one"), "{err}");
    }

    #[test]
    fn remote_owner_errors_when_config_cannot_be_read() {
        let d = tempfile::tempdir().unwrap();
        let gone = d.path().join("gone");
        let err = check_remote_free(&gone, "box").unwrap_err().to_string();
        assert!(err.contains("git config"), "{err}");
        assert!(add_remote(&gone, "box").is_err());
        // An unset key is still just absent.
        let (_d, root) = temp_repo();
        assert_eq!(remote_owner(&root, "box").unwrap(), Remote::Absent);
    }

    #[test]
    fn add_remote_removes_the_remote_it_added_when_configuring_fails() {
        let (_d, root) = temp_repo();
        // Two uploadpack values make the later `git config` overwrite fail.
        git(
            &root,
            &["config", "--add", "remote.sandbox-box.uploadpack", "a"],
        );
        git(
            &root,
            &["config", "--add", "remote.sandbox-box.uploadpack", "b"],
        );
        assert!(add_remote(&root, "box").is_err());
        assert_eq!(
            git_config(&root, "remote.sandbox-box.url"),
            "",
            "the half-added remote was left"
        );
    }

    #[test]
    fn fetch_errors_on_a_missing_remote() {
        let (_d, root) = temp_repo();
        let err = fetch(&root, "box").unwrap_err().to_string();
        assert!(err.contains("sandbox-box"), "{err}");
    }
}
