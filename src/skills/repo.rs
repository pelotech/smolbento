//! `sbt skills add/update`: repository URLs, a shallow clone with host git, and the skills in it.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};

use super::valid_name;

/// `owner/repo` (GitHub) or a remote git URL, as sbx accepts them. Plaintext `http://` and
/// `git://` are allowed, as in sbx (see SECURITY.md).
pub fn parse_url(arg: &str) -> Result<String> {
    const BAD: &str = "repository must be a remote Git URL or GitHub owner/repository";
    if let Some((scheme, _)) = arg.split_once("://") {
        return match scheme {
            "https" | "ssh" | "http" | "git" => Ok(arg.to_string()),
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

/// The repository's basename without `.git`: the name of a repository that is one skill and
/// has no `name:` in its `SKILL.md`.
pub fn repo_name(url: &str) -> String {
    let u = url.trim_end_matches('/');
    let base = u.rsplit(['/', ':']).next().unwrap_or(u);
    base.strip_suffix(".git").unwrap_or(base).to_string()
}

/// A shallow clone in a temp dir, removed on drop. Its files only: `.git` is gone.
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
/// don't run). Git's output is captured for the error; with no terminal and
/// `GIT_TERMINAL_PROMPT=0`, a credential prompt fails instead of hanging.
pub fn clone(url: &str) -> Result<Checkout> {
    let dir = tempfile::tempdir()?;
    let root = dir.path().join("repo");
    let out = Command::new("git")
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
        .env("GIT_TERMINAL_PROMPT", "0")
        .stdin(Stdio::null())
        .output()
        .context("running git")?;
    if !out.status.success() {
        // sbx's format: the exit status, then git's output on one line.
        let status = match out.status.code() {
            Some(c) => format!("exit status {c}"),
            None => out.status.to_string(),
        };
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        bail!(
            "clone skills repository: {status}: {}",
            text.replace(['\r', '\n'], " ").trim()
        );
    }
    let out = Command::new("git")
        .arg("-C")
        .arg(&root)
        .args(["rev-parse", "HEAD"])
        .stdin(Stdio::null())
        .output()?;
    if !out.status.success() {
        bail!("cloning {url}: reading the commit failed");
    }
    // A repository that is one skill copies everything but `.git`.
    fs::remove_dir_all(root.join(".git")).context("removing the clone's .git")?;
    Ok(Checkout {
        url: url.to_string(),
        commit: String::from_utf8_lossy(&out.stdout).trim().to_string(),
        root,
        _dir: dir,
    })
}

/// The top-level `name:` in a leading `---` YAML block, trimmed and unquoted.
pub fn frontmatter_name(text: &str) -> Option<String> {
    let mut lines = text.lines().map(|l| l.trim_end_matches('\r'));
    if lines.next()?.trim_end() != "---" {
        return None;
    }
    for line in lines {
        if matches!(line.trim_end(), "---" | "...") {
            return None;
        }
        if let Some(v) = line.strip_prefix("name:") {
            let v = v.trim();
            let v = ['"', '\'']
                .iter()
                .find_map(|q| v.strip_prefix(*q).and_then(|v| v.strip_suffix(*q)))
                .unwrap_or(v);
            return (!v.is_empty()).then(|| v.to_string());
        }
    }
    None
}

fn has_skill_md(dir: &Path) -> bool {
    fs::symlink_metadata(dir.join("SKILL.md")).is_ok_and(|m| m.is_file())
}

/// A skill directory's name: its `SKILL.md` frontmatter `name:`, else `fallback`.
fn skill_name(dir: &Path, fallback: &str) -> String {
    fs::read_to_string(dir.join("SKILL.md"))
        .ok()
        .and_then(|t| frontmatter_name(&t))
        .unwrap_or_else(|| fallback.to_string())
}

/// The skills in a checkout, as sbx finds them. A regular `SKILL.md` at the root makes the whole
/// repository one skill (named `repo` without a frontmatter name). Otherwise every directory
/// below the root (not `.git`, never through a symlink) with a regular `SKILL.md` is a skill,
/// and its own subdirectories aren't searched. Invalid names are skipped with a warning.
pub fn discover(root: &Path, repo: &str) -> Result<BTreeMap<String, PathBuf>> {
    let mut found: BTreeMap<String, PathBuf> = BTreeMap::new();
    let mut add = |dir: &Path, fallback: &str| -> Result<()> {
        let name = skill_name(dir, fallback);
        if !valid_name(&name) {
            eprintln!(
                "warning: skipping {}: {name:?} is not a valid skill name",
                dir.display()
            );
            return Ok(());
        }
        if let Some(other) = found.insert(name.clone(), dir.to_path_buf()) {
            bail!(
                "two skills named {name:?}: {} and {}",
                other.display(),
                dir.display()
            );
        }
        Ok(())
    };
    if has_skill_md(root) {
        add(root, repo)?;
        return Ok(found);
    }
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        if dir != root && has_skill_md(&dir) {
            let base = dir.file_name().unwrap_or_default().to_string_lossy();
            add(&dir, &base)?;
            continue;
        }
        for e in fs::read_dir(&dir).with_context(|| format!("reading {}", dir.display()))? {
            let e = e?;
            if e.file_type()?.is_dir() && e.file_name() != ".git" {
                stack.push(e.path());
            }
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
            // Plaintext transports reach git, as in sbx.
            "http://host/x.git",
            "git://host/x.git",
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
    }

    #[test]
    fn repo_names() {
        for (url, name) in [
            ("https://github.com/a/skills", "skills"),
            ("https://github.com/a/skills.git", "skills"),
            ("https://github.com/a/skills/", "skills"),
            ("git@github.com:a/b.git", "b"),
            ("git@host:b.git", "b"),
            ("/tmp/x/repo", "repo"),
        ] {
            assert_eq!(repo_name(url), name, "{url}");
        }
    }

    #[test]
    fn frontmatter_names() {
        for (text, want) in [
            ("---\nname: pdf\ndescription: x\n---\nbody", Some("pdf")),
            ("---\r\nname:  \"q-1\" \r\n---\r\n", Some("q-1")),
            ("---\ndescription: x\nname: 'single'\n...\n", Some("single")),
            // Only the top level counts, and only inside the leading block.
            ("---\nmeta:\n  name: inner\n---\nname: after\n", None),
            ("name: nofront\n", None),
            ("---\nname:\n---\n", None),
            ("", None),
        ] {
            assert_eq!(frontmatter_name(text).as_deref(), want, "{text:?}");
        }
    }

    fn write(root: &Path, files: &[(&str, &str)]) {
        for (p, body) in files {
            let f = root.join(p);
            fs::create_dir_all(f.parent().unwrap()).unwrap();
            fs::write(f, body).unwrap();
        }
    }

    fn repo(dir: &Path) {
        write(
            dir,
            &[
                ("skills/alpha/SKILL.md", "a"),
                ("beta/SKILL.md", "b"),
                ("docs/README.md", "x"),
                (".git-like/SKILL.md", "no"),
            ],
        );
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
        // A checkout is the files only.
        assert!(!c.root().join(".git").exists());
        let found = discover(c.root(), "repo").unwrap();
        // `.git-like` isn't a valid name: skipped with a warning.
        assert_eq!(found.keys().collect::<Vec<_>>(), ["alpha", "beta"]);
        assert!(found["alpha"].ends_with("skills/alpha"));
    }

    #[test]
    fn a_clone_failure_carries_git_s_output_on_one_line() {
        let d = tempfile::tempdir().unwrap();
        let missing = d.path().join("nope");
        let e = clone(missing.to_str().unwrap())
            .err()
            .expect("a failed clone")
            .to_string();
        assert!(
            e.starts_with("clone skills repository: exit status 128: "),
            "{e}"
        );
        assert!(
            e.contains("nope") && !e.contains('\n') && e == e.trim(),
            "{e:?}"
        );
    }

    #[test]
    fn names_come_from_the_frontmatter_and_fall_back_to_the_directory() {
        let d = tempfile::tempdir().unwrap();
        write(
            d.path(),
            &[
                ("template/SKILL.md", "---\nname: template-skill\n---\n"),
                ("plain/SKILL.md", "no frontmatter"),
                ("unnamed/SKILL.md", "---\ndescription: x\n---\n"),
                ("bad/SKILL.md", "---\nname: ../evil\n---\n"),
            ],
        );
        let found = discover(d.path(), "repo").unwrap();
        assert_eq!(
            found.keys().collect::<Vec<_>>(),
            ["plain", "template-skill", "unnamed"]
        );
        assert!(found["template-skill"].ends_with("template"));
    }

    #[test]
    fn discovery_stops_at_a_skill_directory() {
        let d = tempfile::tempdir().unwrap();
        write(
            d.path(),
            &[
                ("outer/SKILL.md", "o"),
                ("outer/skills/inner/SKILL.md", "i"),
                ("other/deep/x/SKILL.md", "x"),
            ],
        );
        let found = discover(d.path(), "repo").unwrap();
        assert_eq!(found.keys().collect::<Vec<_>>(), ["outer", "x"]);
    }

    #[test]
    fn a_skill_md_at_the_root_makes_the_repository_one_skill() {
        let d = tempfile::tempdir().unwrap();
        write(
            d.path(),
            &[
                ("SKILL.md", "---\nname: affiliate-check\n---\n"),
                ("skills/a/SKILL.md", "a"),
            ],
        );
        let found = discover(d.path(), "affiliate-skills").unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found["affiliate-check"], d.path());
        fs::write(d.path().join("SKILL.md"), "no name").unwrap();
        let found = discover(d.path(), "affiliate-skills").unwrap();
        assert_eq!(found.keys().collect::<Vec<_>>(), ["affiliate-skills"]);
    }

    #[test]
    fn two_skills_with_one_name_is_an_error() {
        let d = tempfile::tempdir().unwrap();
        write(
            d.path(),
            &[
                ("a/x/SKILL.md", "s"),
                ("b/y/SKILL.md", "---\nname: x\n---\n"),
            ],
        );
        let e = discover(d.path(), "repo").unwrap_err().to_string();
        assert!(e.contains("two skills named \"x\""), "{e}");
    }
}
