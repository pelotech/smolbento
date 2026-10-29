//! Agent skills: the shared store (`sbt skills`) and how sandboxes see it (`--skills`, kit
//! `agent-skills@1`/`agent-skill@1`). Spec: Phase 5c.

pub mod import;
pub mod repo;
pub mod store;

use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use crate::config::Settings;
use crate::smolvm::Mount;

/// Where a sandbox sees the whole store read-only; its skills directories link into it.
pub const SHARED: &str = "/run/sbx/skills-shared";

/// sbx's skill name rule: a portable directory name that can't leave its parent.
pub fn valid_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    name.len() <= 255
        && bytes.next().is_some_and(|b| b.is_ascii_alphanumeric())
        && bytes.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// How a sandbox shares the store (`--skills`, `skills.defaultMode`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Off,
    #[default]
    Readonly,
    Readwrite,
}

impl Mode {
    pub fn parse(s: &str) -> Result<Mode> {
        Ok(match s {
            "off" => Mode::Off,
            "readonly" => Mode::Readonly,
            "readwrite" => Mode::Readwrite,
            _ => bail!("invalid skills mode {s:?}: use off, readonly or readwrite"),
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Off => "off",
            Mode::Readonly => "readonly",
            Mode::Readwrite => "readwrite",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Access {
    /// Bundled kit skills only (`off`).
    None,
    /// Links into the read-only `SHARED` mount, rebuilt at each start.
    Ro,
    /// The store mounted over the directory.
    Rw,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dir {
    pub path: String,
    pub access: Access,
}

/// The `sbx.skills` label: fixed at create.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Label {
    pub mode: Mode,
    pub dirs: Vec<Dir>,
}

impl Label {
    pub fn to_label(&self) -> String {
        serde_json::to_string(self).expect("a skills label serializes")
    }

    pub fn from_label(s: &str) -> Option<Label> {
        serde_json::from_str(s).ok()
    }
}

/// A skills directory someone asked for: the built-in agent's or a kit's `agent-skills@1`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Want {
    pub path: String,
    pub readwrite: bool,
}

/// What a create mounts and labels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Setup {
    pub store: PathBuf,
    pub label: Label,
}

/// One entry per path (widest request wins), with the narrower of `mode` and the request. A
/// sandbox with bundled skills never mounts over a directory (they'd land in the user's store).
pub fn plan_dirs(mode: Mode, wants: &[Want], has_bundled: bool) -> Vec<Dir> {
    let mut by_path: std::collections::BTreeMap<&str, bool> = Default::default();
    for w in wants {
        *by_path.entry(&w.path).or_default() |= w.readwrite;
    }
    by_path
        .into_iter()
        .map(|(path, rw)| Dir {
            path: path.to_string(),
            access: match mode {
                Mode::Off => Access::None,
                Mode::Readwrite if rw && !has_bundled => Access::Rw,
                _ => Access::Ro,
            },
        })
        .collect()
}

/// The store once read-only at `SHARED` when any directory links into it, and over each
/// read-write directory.
pub fn mounts(store: &Path, dirs: &[Dir]) -> Vec<Mount> {
    let mut m = Vec::new();
    if dirs.iter().any(|d| d.access == Access::Ro) {
        m.push(Mount {
            host: Some(store.to_path_buf()),
            guest: SHARED.into(),
            read_only: true,
        });
    }
    m.extend(
        dirs.iter()
            .filter(|d| d.access == Access::Rw)
            .map(|d| Mount {
                host: Some(store.to_path_buf()),
                guest: d.path.clone(),
                read_only: false,
            }),
    );
    m
}

/// Run at every start as the launch user: for each read-only directory, drop links into the
/// shared mount whose skill is gone, then link every store entry that has no name there yet
/// (anything already there wins: the agent's own skill, image content, a bundled kit skill).
pub fn link_script(dirs: &[Dir]) -> Option<String> {
    link_script_at(SHARED, dirs)
}

fn link_script_at(shared: &str, dirs: &[Dir]) -> Option<String> {
    let ro: Vec<String> = dirs
        .iter()
        .filter(|d| d.access == Access::Ro)
        .map(|d| crate::sandbox::sh_quote(&d.path))
        .collect();
    if ro.is_empty() {
        return None;
    }
    let s = crate::sandbox::sh_quote(shared);
    Some(format!(
        r#"S={s}
rc=0
for d in {dirs}; do
  mkdir -p "$d" || {{ rc=1; continue; }}
  for l in "$d"/* "$d"/.[!.]*; do
    [ -L "$l" ] || continue
    case "$(readlink "$l")" in "$S"/*) [ -e "$l" ] || rm -f "$l" ;; esac
  done
  for e in "$S"/*; do
    n=${{e##*/}}
    case "$n" in [A-Za-z0-9]*) ;; *) continue ;; esac
    case "$n" in *[!A-Za-z0-9._-]*) continue ;; esac
    [ -e "$d/$n" ] || [ -L "$d/$n" ] || ln -s "$S/$n" "$d/$n" || rc=1
  done
done
exit $rc"#,
        dirs = ro.join(" ")
    ))
}

/// The kit first start's step for bundled skills (before install hooks; the start's setup has
/// linked the store already, so a store entry of the same name counts as taken). Each skill
/// needs a regular `SKILL.md` and its name free in every directory; then it's linked into all.
/// A required skill that can't be exposed fails the step (and the create); an optional one warns.
pub fn bundled_script(dirs: &[Dir], skills: &[(String, String, bool)]) -> String {
    let dirs: Vec<String> = dirs
        .iter()
        .map(|d| crate::sandbox::sh_quote(&d.path))
        .collect();
    let dirs = dirs.join(" ");
    let mut s = String::from("rc=0\n");
    for (name, source, optional) in skills {
        let (n, src) = (
            crate::sandbox::sh_quote(name),
            crate::sandbox::sh_quote(source),
        );
        // `name` is a valid skill name and `source` has no `$ " \` \\` (Task 9), so both are
        // safe inside the double-quoted messages.
        let (fail, unlinked) = if *optional {
            (
                format!(r#"echo "warning: skipping skill {name}: $why" >&2"#),
                format!(r#"echo "warning: skipping skill {name}: couldn't link into $d" >&2"#),
            )
        } else {
            (
                r#"echo "$why" >&2; rc=1"#.to_string(),
                format!(r#"echo "skill {name}: couldn't link into $d" >&2; rc=1"#),
            )
        };
        s += &format!(
            r#"why=
if [ -L {src}/SKILL.md ] || [ ! -f {src}/SKILL.md ]; then why="{source}/SKILL.md is not a regular file"; fi
for d in {dirs}; do
  if [ -z "$why" ] && {{ [ -e "$d"/{n} ] || [ -L "$d"/{n} ]; }}; then why="$d/{name} already exists"; fi
done
if [ -n "$why" ]; then {fail}; else for d in {dirs}; do mkdir -p "$d" && ln -s {src} "$d"/{n} || {{ {unlinked}; }}; done; fi
"#
        );
    }
    s + "exit $rc\n"
}

/// `--skills` (or sbxenv's `sandboxOptions.skills`), else `skills.defaultMode`.
pub fn resolve_mode(flag: Option<&str>, settings: &Settings) -> Result<Mode> {
    match flag {
        Some(f) => Mode::parse(f),
        None => Mode::parse(&settings.value("skills.defaultMode")?)
            .map_err(|e| anyhow::anyhow!("setting skills.defaultMode: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skill_names() {
        for ok in ["pdf", "a", "Front-end_2.x", &"a".repeat(255)] {
            assert!(valid_name(ok), "{ok}");
        }
        for bad in [
            "",
            ".tmp-x",
            "-x",
            "_x",
            "a/b",
            "..",
            "a b",
            &"a".repeat(256),
        ] {
            assert!(!valid_name(bad), "{bad}");
        }
    }

    #[test]
    fn modes_parse() {
        assert_eq!(Mode::parse("readonly").unwrap(), Mode::Readonly);
        assert_eq!(Mode::parse("readwrite").unwrap(), Mode::Readwrite);
        assert_eq!(Mode::parse("off").unwrap(), Mode::Off);
        let e = Mode::parse("rw").unwrap_err().to_string();
        assert!(e.contains("off, readonly or readwrite"), "{e}");
    }

    fn want(p: &str, rw: bool) -> Want {
        Want {
            path: p.into(),
            readwrite: rw,
        }
    }
    fn dir(p: &str, a: Access) -> Dir {
        Dir {
            path: p.into(),
            access: a,
        }
    }

    #[test]
    fn bundled_script_links_checks_and_skips_optional_conflicts() {
        let t = tempfile::tempdir().unwrap();
        let src = t.path().join("img/review");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("SKILL.md"), "s").unwrap();
        let d1 = t.path().join("a/skills");
        let d2 = t.path().join("b/skills");
        let dirs = [
            dir(d1.to_str().unwrap(), Access::Ro),
            dir(d2.to_str().unwrap(), Access::None),
        ];
        let s = src.to_str().unwrap().to_string();
        let run = |skills: &[(String, String, bool)]| {
            std::process::Command::new("sh")
                .args(["-c", &bundled_script(&dirs, skills)])
                .output()
                .unwrap()
        };
        let ok = run(&[("review-pr".into(), s.clone(), false)]);
        assert!(
            ok.status.success(),
            "{}",
            String::from_utf8_lossy(&ok.stderr)
        );
        assert_eq!(std::fs::read_link(d1.join("review-pr")).unwrap(), src);
        assert_eq!(std::fs::read_link(d2.join("review-pr")).unwrap(), src);
        // Taken now: required fails, optional warns and goes on.
        let again = run(&[("review-pr".into(), s.clone(), false)]);
        assert!(!again.status.success());
        assert!(String::from_utf8_lossy(&again.stderr).contains("review-pr already exists"));
        let opt = run(&[("review-pr".into(), s.clone(), true)]);
        assert!(opt.status.success());
        assert!(String::from_utf8_lossy(&opt.stderr).contains("warning: skipping skill review-pr"));
        let missing = run(&[("x".into(), "/nonexistent/x".into(), false)]);
        assert!(
            String::from_utf8_lossy(&missing.stderr)
                .contains("/nonexistent/x/SKILL.md is not a regular file")
        );
    }

    /// Make `p` read-only for the closure (restored on drop). None when root, which ignores mode.
    #[cfg(unix)]
    fn read_only<T>(p: &Path, f: impl FnOnce() -> T) -> Option<T> {
        use std::os::unix::fs::PermissionsExt;
        struct Restore(std::path::PathBuf);
        impl Drop for Restore {
            fn drop(&mut self) {
                let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o755));
            }
        }
        // SAFETY: geteuid has no preconditions.
        if unsafe { libc::geteuid() } == 0 {
            return None;
        }
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o555)).unwrap();
        let _restore = Restore(p.to_path_buf());
        Some(f())
    }

    #[test]
    fn bundled_script_fails_a_required_skill_it_cannot_link() {
        let t = tempfile::tempdir().unwrap();
        let src = t.path().join("img/review");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("SKILL.md"), "s").unwrap();
        let locked = t.path().join("locked");
        std::fs::create_dir(&locked).unwrap();
        let d = locked.join("skills");
        let dirs = [dir(d.to_str().unwrap(), Access::Ro)];
        let s = src.to_str().unwrap().to_string();
        let run = |optional: bool| {
            std::process::Command::new("sh")
                .args([
                    "-c",
                    &bundled_script(&dirs, &[("review".into(), s.clone(), optional)]),
                ])
                .output()
                .unwrap()
        };
        let Some((req, opt)) = read_only(&locked, || (run(false), run(true))) else {
            return;
        };
        assert!(!req.status.success());
        assert!(
            String::from_utf8_lossy(&req.stderr)
                .contains(&format!("skill review: couldn't link into {}", d.display())),
            "{}",
            String::from_utf8_lossy(&req.stderr)
        );
        assert!(opt.status.success());
        assert!(
            String::from_utf8_lossy(&opt.stderr).contains(&format!(
                "warning: skipping skill review: couldn't link into {}",
                d.display()
            )),
            "{}",
            String::from_utf8_lossy(&opt.stderr)
        );
    }

    #[test]
    fn link_script_fails_for_a_dir_it_cannot_write_and_still_links_the_others() {
        let t = tempfile::tempdir().unwrap();
        let shared = t.path().join("shared");
        std::fs::create_dir_all(shared.join("alpha")).unwrap();
        let locked = t.path().join("locked");
        std::fs::create_dir(&locked).unwrap();
        let bad = locked.join("skills");
        let good = t.path().join("home/.codex/skills");
        let dirs = [
            dir(bad.to_str().unwrap(), Access::Ro),
            dir(good.to_str().unwrap(), Access::Ro),
        ];
        let script = link_script_at(shared.to_str().unwrap(), &dirs).unwrap();
        let run = || {
            std::process::Command::new("sh")
                .args(["-c", &script])
                .output()
                .unwrap()
        };
        let Some(out) = read_only(&locked, run) else {
            return;
        };
        assert!(!out.status.success());
        assert_eq!(
            std::fs::read_link(good.join("alpha")).unwrap(),
            shared.join("alpha")
        );
        // An existing but unwritable directory fails too.
        std::fs::create_dir(&bad).unwrap();
        let Some(out) = read_only(&bad, run) else {
            return;
        };
        assert!(!out.status.success());
    }

    #[test]
    fn link_script_links_new_entries_clears_dangling_and_keeps_the_agent_s_own() {
        let t = tempfile::tempdir().unwrap();
        let shared = t.path().join("shared");
        let d = t.path().join("home/.claude/skills");
        for n in ["alpha", "gone", "mine", ".tmp-x"] {
            std::fs::create_dir_all(shared.join(n)).unwrap();
        }
        let dirs = [
            dir(d.to_str().unwrap(), Access::Ro),
            dir("/x", Access::Rw),
            dir("/y", Access::None),
        ];
        let script = link_script_at(shared.to_str().unwrap(), &dirs).unwrap();
        assert!(!script.contains("/x") && !script.contains("/y"));
        let run = || {
            assert!(
                std::process::Command::new("sh")
                    .args(["-c", &script])
                    .status()
                    .unwrap()
                    .success()
            )
        };
        std::fs::create_dir_all(d.join("mine")).unwrap(); // the agent's own
        run();
        assert_eq!(
            std::fs::read_link(d.join("alpha")).unwrap(),
            shared.join("alpha")
        );
        assert!(std::fs::symlink_metadata(d.join("mine")).unwrap().is_dir());
        assert!(std::fs::symlink_metadata(d.join(".tmp-x")).is_err());
        std::fs::remove_dir(shared.join("gone")).unwrap();
        std::fs::create_dir(shared.join("gamma")).unwrap();
        run();
        assert!(std::fs::symlink_metadata(d.join("gone")).is_err());
        assert!(d.join("gamma").exists());
        assert_eq!(link_script_at("/s", &[dir("/x", Access::Rw)]), None);
    }

    #[test]
    fn dirs_take_the_narrower_access_and_bundled_caps_at_links() {
        let w = [want("/s", true), want("/k", false), want("/s", false)];
        assert_eq!(
            plan_dirs(Mode::Readwrite, &w, false),
            [dir("/k", Access::Ro), dir("/s", Access::Rw)]
        );
        assert_eq!(
            plan_dirs(Mode::Readonly, &w, false),
            [dir("/k", Access::Ro), dir("/s", Access::Ro)]
        );
        assert_eq!(
            plan_dirs(Mode::Off, &w, false),
            [dir("/k", Access::None), dir("/s", Access::None)]
        );
        assert_eq!(
            plan_dirs(Mode::Readwrite, &w, true),
            [dir("/k", Access::Ro), dir("/s", Access::Ro)]
        );
        assert!(plan_dirs(Mode::Readonly, &[], false).is_empty());
    }

    #[test]
    fn mounts_share_one_read_only_mount_and_mount_over_rw_dirs() {
        let store = Path::new("/h/store");
        let m = mounts(
            store,
            &[
                dir("/a", Access::Ro),
                dir("/b", Access::Ro),
                dir("/c", Access::Rw),
                dir("/d", Access::None),
            ],
        );
        let got: Vec<(String, bool)> = m.iter().map(|m| (m.guest.clone(), m.read_only)).collect();
        assert_eq!(got, [(SHARED.to_string(), true), ("/c".to_string(), false)]);
        assert!(m.iter().all(|m| m.host.as_deref() == Some(store)));
        assert!(mounts(store, &[dir("/d", Access::None)]).is_empty());
    }

    #[test]
    fn label_round_trip() {
        let l = Label {
            mode: Mode::Readonly,
            dirs: vec![dir("/home/agent/.claude/skills", Access::Ro)],
        };
        let s = l.to_label();
        assert_eq!(
            s,
            r#"{"mode":"readonly","dirs":[{"path":"/home/agent/.claude/skills","access":"ro"}]}"#
        );
        assert_eq!(Label::from_label(&s), Some(l));
    }
}
