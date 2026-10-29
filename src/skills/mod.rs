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

/// Where a sandbox sees the whole store when its skills directories link into it.
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

/// How a sandbox sees the store in one skills directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Access {
    /// Nothing from the store (`off`); bundled kit skills are still linked.
    None,
    /// Links into the `SHARED` mount, rebuilt at each start.
    Link,
    /// The store mounted read-only over the directory.
    Ro,
    /// The store mounted read-write over the directory.
    Rw,
}

/// The store mounted at `SHARED`, for `Link` directories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Shared {
    None,
    Ro,
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
    pub shared: Shared,
    pub dirs: Vec<Dir>,
}

impl Label {
    pub fn to_label(&self) -> String {
        serde_json::to_string(self).expect("a skills label serializes")
    }

    pub fn from_label(s: &str) -> Option<Label> {
        serde_json::from_str(s).ok()
    }

    /// Whether the store is mounted at all (so it must exist).
    pub fn mounts_store(&self) -> bool {
        self.shared != Shared::None
            || self
                .dirs
                .iter()
                .any(|d| matches!(d.access, Access::Ro | Access::Rw))
    }
}

/// A skills directory someone asked for: the built-in agent's or a kit's `agent-skills@1`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Want {
    pub path: String,
    pub readwrite: bool,
    /// The built-in agent's directory: links when read-only (a kit's is mounted over).
    pub builtin: bool,
}

/// What a create mounts and labels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Setup {
    pub store: PathBuf,
    pub label: Label,
}

/// sbx's model. Per path (requests merged: the widest mode, and built-in if any is), a directory's
/// effective access is the narrower of `mode` and its request.
/// - `off`: nothing from the store; bundled skills are linked anyway.
/// - With bundled skills, every directory links (bundled skills must never land in the user's
///   store), and `SHARED` is read-write if any directory's effective access is.
/// - Otherwise the built-in agent's directory links when read-only and has the store mounted over
///   it when read-write; a kit's has the store mounted over it either way.
pub fn plan(mode: Mode, wants: &[Want], has_bundled: bool) -> Label {
    let mut by_path: std::collections::BTreeMap<&str, (bool, bool)> = Default::default();
    for w in wants {
        let e = by_path.entry(&w.path).or_default();
        e.0 |= w.readwrite;
        e.1 |= w.builtin;
    }
    let mut shared_rw = false;
    let dirs: Vec<Dir> = by_path
        .into_iter()
        .map(|(path, (rw, builtin))| {
            let rw = rw && mode == Mode::Readwrite;
            shared_rw |= rw;
            let access = match (mode, has_bundled, builtin, rw) {
                (Mode::Off, ..) => Access::None,
                (_, true, ..) | (_, false, true, false) => Access::Link,
                (_, false, _, true) => Access::Rw,
                (_, false, false, false) => Access::Ro,
            };
            Dir {
                path: path.to_string(),
                access,
            }
        })
        .collect();
    let shared = if !dirs.iter().any(|d| d.access == Access::Link) {
        Shared::None
    } else if shared_rw && has_bundled {
        Shared::Rw
    } else {
        Shared::Ro
    };
    Label { mode, shared, dirs }
}

/// The store at `SHARED` for linking directories, and over each mounted-over directory.
pub fn mounts(store: &Path, label: &Label) -> Vec<Mount> {
    let mut m = Vec::new();
    if label.shared != Shared::None {
        m.push(Mount {
            host: Some(store.to_path_buf()),
            guest: SHARED.into(),
            read_only: label.shared == Shared::Ro,
        });
    }
    m.extend(label.dirs.iter().filter_map(|d| {
        let read_only = match d.access {
            Access::Ro => true,
            Access::Rw => false,
            Access::None | Access::Link => return None,
        };
        Some(Mount {
            host: Some(store.to_path_buf()),
            guest: d.path.clone(),
            read_only,
        })
    }));
    m
}

/// Sets `o` to the owner of skills directories and links: the `agent` account if the image has
/// one, else uid 1000, as sbx does (smolbento remaps `agent` to the host user).
const OWNER: &str = r#"if u=$(id -u agent 2>/dev/null) && g=$(id -g agent 2>/dev/null); then o=$u:$g; else o=1000:1000; fi"#;

/// `real DIR` succeeds when DIR's longest existing prefix resolves to itself: no symlink anywhere
/// in the path (skills paths are canonical), so root never creates or chowns through one. Run
/// before `mkdir -p` and again after it. A root-owned symlinked component (`/home -> /var/home`)
/// is refused too.
const REAL: &str = r#"real() { q=$1; while [ ! -e "$q" ] && [ ! -L "$q" ]; do q=${q%/*}; q=${q:-/}; done; [ "$(cd "$q" 2>/dev/null && pwd -P)" = "$q" ]; }"#;

/// Run as root at every start: for each linking directory, make it (owned by the agent, refusing
/// a symlink), drop links into the shared mount whose skill is gone, then link every store entry
/// that has no name there yet (anything already there wins: the agent's own skill, image
/// content, a bundled kit skill). Links belong to the agent too.
pub fn link_script(dirs: &[Dir]) -> Option<String> {
    link_script_at(SHARED, OWNER, dirs)
}

fn link_script_at(shared: &str, owner: &str, dirs: &[Dir]) -> Option<String> {
    let link: Vec<String> = dirs
        .iter()
        .filter(|d| d.access == Access::Link)
        .map(|d| crate::sandbox::sh_quote(&d.path))
        .collect();
    if link.is_empty() {
        return None;
    }
    let s = crate::sandbox::sh_quote(shared);
    Some(format!(
        r#"S={s}
{owner}
{REAL}
rc=0
for d in {dirs}; do
  if ! real "$d" || ! mkdir -p "$d" || ! real "$d"; then echo "$d is not a plain directory path (a symlink in it?); not linking skills there" >&2; rc=1; continue; fi
  chown "$o" "$d" || {{ rc=1; continue; }}
  for l in "$d"/* "$d"/.[!.]*; do
    [ -L "$l" ] || continue
    case "$(readlink "$l")" in "$S"/*) [ -e "$l" ] || rm -f "$l" ;; esac
  done
  for e in "$S"/*; do
    n=${{e##*/}}
    case "$n" in [A-Za-z0-9]*) ;; *) continue ;; esac
    case "$n" in *[!A-Za-z0-9._-]*) continue ;; esac
    [ -e "$d/$n" ] || [ -L "$d/$n" ] || {{ ln -sn "$S/$n" "$d/$n" && chown -h "$o" "$d/$n"; }} || rc=1
  done
done
exit $rc"#,
        dirs = link.join(" ")
    ))
}

/// The kit first start's step for bundled skills, as root (before install hooks; the start's
/// setup has linked the store already, so a store entry of the same name counts as taken). Each
/// skill needs a regular `SKILL.md` and its name free in every directory; then it's linked into
/// all, owned by the agent. A required skill that can't be exposed fails the step (and the
/// create) with sbx's message for a taken name; an optional one warns.
pub fn bundled_script(dirs: &[Dir], skills: &[(String, String, bool)]) -> String {
    bundled_script_as(OWNER, dirs, skills)
}

fn bundled_script_as(owner: &str, dirs: &[Dir], skills: &[(String, String, bool)]) -> String {
    let dirs: Vec<String> = dirs
        .iter()
        .map(|d| crate::sandbox::sh_quote(&d.path))
        .collect();
    let dirs = dirs.join(" ");
    let mut s = format!("{owner}\n{REAL}\nrc=0\n");
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
                format!(
                    r#"if [ -n "$taken" ]; then echo "failed to compose shared skills into the sandbox: bundled skills {name} cannot be exposed in $taken: another skill already uses the name" >&2; else echo "$why" >&2; fi; rc=1"#
                ),
                format!(r#"echo "skill {name}: couldn't link into $d" >&2; rc=1"#),
            )
        };
        s += &format!(
            r#"why=; taken=
if [ -L {src}/SKILL.md ] || [ ! -f {src}/SKILL.md ]; then why="{source}/SKILL.md is not a regular file"; fi
for d in {dirs}; do
  if [ -z "$why" ] && {{ [ -e "$d"/{n} ] || [ -L "$d"/{n} ]; }}; then why="$d/{name} already exists"; taken=$d; fi
done
if [ -n "$why" ]; then {fail}; else for d in {dirs}; do real "$d" && mkdir -p "$d" && real "$d" && chown "$o" "$d" && ln -sn {src} "$d"/{n} && chown -h "$o" "$d"/{n} || {{ {unlinked}; }}; done; fi
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
            builtin: false,
        }
    }
    fn builtin(p: &str) -> Want {
        Want {
            path: p.into(),
            readwrite: true,
            builtin: true,
        }
    }
    fn dir(p: &str, a: Access) -> Dir {
        Dir {
            path: p.into(),
            access: a,
        }
    }
    /// The test runner's own uid:gid as the owner (it can't chown to another).
    const ME: &str = "o=$(id -u):$(id -g)";

    #[test]
    fn bundled_script_links_checks_and_skips_optional_conflicts() {
        let t = tmp();
        let src = t.path().join("img/review");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("SKILL.md"), "s").unwrap();
        let d1 = t.path().join("a/skills");
        let d2 = t.path().join("b/skills");
        let dirs = [
            dir(d1.to_str().unwrap(), Access::Link),
            dir(d2.to_str().unwrap(), Access::None),
        ];
        let s = src.to_str().unwrap().to_string();
        let run = |skills: &[(String, String, bool)]| {
            std::process::Command::new("sh")
                .args(["-c", &bundled_script_as(ME, &dirs, skills)])
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
        // Taken now: required fails with sbx's message, optional warns and goes on.
        let again = run(&[("review-pr".into(), s.clone(), false)]);
        assert!(!again.status.success());
        assert_eq!(
            String::from_utf8_lossy(&again.stderr),
            format!(
                "failed to compose shared skills into the sandbox: bundled skills review-pr \
                 cannot be exposed in {}: another skill already uses the name\n",
                d1.display()
            )
        );
        let opt = run(&[("review-pr".into(), s.clone(), true)]);
        assert!(opt.status.success());
        assert!(String::from_utf8_lossy(&opt.stderr).contains(&format!(
            "warning: skipping skill review-pr: {}/review-pr already exists",
            d1.display()
        )));
        let missing = run(&[("x".into(), "/nonexistent/x".into(), false)]);
        assert!(
            String::from_utf8_lossy(&missing.stderr)
                .contains("/nonexistent/x/SKILL.md is not a regular file")
        );
    }

    #[test]
    fn the_scripts_run_as_root_and_hand_dirs_and_links_to_the_agent() {
        let d = [dir("/home/agent/.claude/skills", Access::Link)];
        let link = link_script(&d).unwrap();
        let bundled = bundled_script(&d, &[("r".into(), "/opt/r".into(), false)]);
        for s in [&link, &bundled] {
            assert!(s.contains(OWNER), "{s}");
            assert!(s.contains(r#"chown "$o" "$d""#), "{s}");
            assert!(s.contains(r#"chown -h "$o" "$d"#), "{s}");
        }
        // The owner: `agent` if the image has one, else 1000:1000.
        let out = std::process::Command::new("sh")
            .args(["-c", &format!("id() {{ return 1; }}; {OWNER}; echo \"$o\"")])
            .output()
            .unwrap();
        assert_eq!(String::from_utf8_lossy(&out.stdout), "1000:1000\n");
        let out = std::process::Command::new("sh")
            .args([
                "-c",
                &format!(
                    "id() {{ [ \"$2\" = agent ] && {{ [ \"$1\" = -u ] && echo 501 || echo 20; }}; }}; {OWNER}; echo \"$o\""
                ),
            ])
            .output()
            .unwrap();
        assert_eq!(String::from_utf8_lossy(&out.stdout), "501:20\n");
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
        let t = tmp();
        let src = t.path().join("img/review");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("SKILL.md"), "s").unwrap();
        let locked = t.path().join("locked");
        std::fs::create_dir(&locked).unwrap();
        let d = locked.join("skills");
        let dirs = [dir(d.to_str().unwrap(), Access::Link)];
        let s = src.to_str().unwrap().to_string();
        let run = |optional: bool| {
            std::process::Command::new("sh")
                .args([
                    "-c",
                    &bundled_script_as(ME, &dirs, &[("review".into(), s.clone(), optional)]),
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
        let t = tmp();
        let shared = t.path().join("shared");
        std::fs::create_dir_all(shared.join("alpha")).unwrap();
        let locked = t.path().join("locked");
        std::fs::create_dir(&locked).unwrap();
        let bad = locked.join("skills");
        let good = t.path().join("home/.codex/skills");
        let dirs = [
            dir(bad.to_str().unwrap(), Access::Link),
            dir(good.to_str().unwrap(), Access::Link),
        ];
        let script = link_script_at(shared.to_str().unwrap(), ME, &dirs).unwrap();
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

    /// A temp dir under the canonical temp path (macOS's `/var` is a symlink, which the scripts
    /// refuse).
    fn tmp() -> tempfile::TempDir {
        tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap()
    }

    /// Both scripts refuse a skills directory reached through a symlink, as its last component or
    /// a parent (`~/.claude -> /elsewhere`), and create and change nothing there.
    #[test]
    fn the_scripts_refuse_a_symlinked_directory_or_parent() {
        let t = tmp();
        let shared = t.path().join("shared");
        std::fs::create_dir_all(shared.join("alpha")).unwrap();
        let src = t.path().join("img/review");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("SKILL.md"), "s").unwrap();
        let elsewhere = t.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        let last = t.path().join("skills");
        std::os::unix::fs::symlink(&elsewhere, &last).unwrap();
        let parent = t.path().join("home/.claude");
        std::fs::create_dir(t.path().join("home")).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &parent).unwrap();
        let s = src.to_str().unwrap().to_string();
        let sh = |script: &str| {
            std::process::Command::new("sh")
                .args(["-c", script])
                .output()
                .unwrap()
        };
        for d in [last, parent.join("skills"), parent.join("a/b/skills")] {
            let dirs = [dir(d.to_str().unwrap(), Access::Link)];
            let out = sh(&link_script_at(shared.to_str().unwrap(), ME, &dirs).unwrap());
            assert!(!out.status.success(), "{}", d.display());
            assert!(
                String::from_utf8_lossy(&out.stderr).contains("not a plain directory path"),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
            let req = sh(&bundled_script_as(
                ME,
                &dirs,
                &[("review".into(), s.clone(), false)],
            ));
            assert!(!req.status.success(), "{}", d.display());
            let opt = sh(&bundled_script_as(
                ME,
                &dirs,
                &[("review".into(), s.clone(), true)],
            ));
            assert!(opt.status.success(), "{}", d.display());
            assert!(
                String::from_utf8_lossy(&opt.stderr).contains("warning: skipping skill review"),
                "{}",
                String::from_utf8_lossy(&opt.stderr)
            );
            assert!(
                std::fs::read_dir(&elsewhere).unwrap().next().is_none(),
                "nothing made through {}",
                d.display()
            );
        }
    }

    #[test]
    fn link_script_links_new_entries_clears_dangling_and_keeps_the_agent_s_own() {
        let t = tmp();
        let shared = t.path().join("shared");
        let d = t.path().join("home/.claude/skills");
        for n in ["alpha", "gone", "mine", ".tmp-x"] {
            std::fs::create_dir_all(shared.join(n)).unwrap();
        }
        let dirs = [
            dir(d.to_str().unwrap(), Access::Link),
            dir("/not-linked-rw", Access::Rw),
            dir("/not-linked-ro", Access::Ro),
            dir("/not-linked-none", Access::None),
        ];
        let script = link_script_at(shared.to_str().unwrap(), ME, &dirs).unwrap();
        assert!(!script.contains("/not-linked"));
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
        assert_eq!(
            link_script_at("/s", ME, &[dir("/x", Access::Rw), dir("/y", Access::Ro)]),
            None
        );
    }

    fn planned(mode: Mode, w: &[Want], bundled: bool) -> (Shared, Vec<(String, Access)>) {
        let l = plan(mode, w, bundled);
        assert_eq!(l.mode, mode);
        (
            l.shared,
            l.dirs.into_iter().map(|d| (d.path, d.access)).collect(),
        )
    }

    fn pa(v: &[(&str, Access)]) -> Vec<(String, Access)> {
        v.iter().map(|(p, a)| (p.to_string(), *a)).collect()
    }

    #[test]
    fn built_in_directories_link_read_only_and_are_mounted_over_read_write() {
        let w = [builtin("/c")];
        use Access::*;
        assert_eq!(
            planned(Mode::Readonly, &w, false),
            (Shared::Ro, pa(&[("/c", Link)]))
        );
        assert_eq!(
            planned(Mode::Readwrite, &w, false),
            (Shared::None, pa(&[("/c", Rw)]))
        );
        assert_eq!(
            planned(Mode::Off, &w, false),
            (Shared::None, pa(&[("/c", None)]))
        );
        assert!(plan(Mode::Readonly, &[], false).dirs.is_empty());
    }

    /// sbx's kit table (notes, "Kits in sbx"): `/r` readonly, `/w` readwrite.
    #[test]
    fn kit_directories_are_mounted_over_unless_a_skill_is_bundled() {
        let w = [want("/r", false), want("/w", true), want("/r", false)];
        use Access::*;
        assert_eq!(
            planned(Mode::Readwrite, &w, false),
            (Shared::None, pa(&[("/r", Ro), ("/w", Rw)]))
        );
        assert_eq!(
            planned(Mode::Readonly, &w, false),
            (Shared::None, pa(&[("/r", Ro), ("/w", Ro)]))
        );
        assert_eq!(
            planned(Mode::Off, &w, false),
            (Shared::None, pa(&[("/r", None), ("/w", None)]))
        );
        assert_eq!(
            planned(Mode::Readwrite, &w, true),
            (Shared::Rw, pa(&[("/r", Link), ("/w", Link)]))
        );
        assert_eq!(
            planned(Mode::Readonly, &w, true),
            (Shared::Ro, pa(&[("/r", Link), ("/w", Link)]))
        );
        assert_eq!(
            planned(Mode::Off, &w, true),
            (Shared::None, pa(&[("/r", None), ("/w", None)]))
        );
        // Readwrite but no directory asks for it: the shared mount stays read-only.
        assert_eq!(
            planned(Mode::Readwrite, &[want("/r", false)], true),
            (Shared::Ro, pa(&[("/r", Link)]))
        );
    }

    #[test]
    fn a_path_that_is_built_in_and_a_kit_s_behaves_as_built_in() {
        use Access::*;
        let w = [want("/c", false), builtin("/c"), want("/k", false)];
        assert_eq!(
            planned(Mode::Readonly, &w, false),
            (Shared::Ro, pa(&[("/c", Link), ("/k", Ro)]))
        );
        assert_eq!(
            planned(Mode::Readwrite, &w, false),
            (Shared::None, pa(&[("/c", Rw), ("/k", Ro)]))
        );
        // With a bundled skill the built-in request makes the shared mount read-write.
        assert_eq!(
            planned(Mode::Readwrite, &w, true),
            (Shared::Rw, pa(&[("/c", Link), ("/k", Link)]))
        );
    }

    #[test]
    fn mounts_follow_the_label() {
        let store = Path::new("/h/store");
        let label = |shared, dirs: Vec<Dir>| Label {
            mode: Mode::Readwrite,
            shared,
            dirs,
        };
        let got = |l: &Label| -> Vec<(String, bool)> {
            mounts(store, l)
                .iter()
                .map(|m| {
                    assert_eq!(m.host.as_deref(), Some(store));
                    (m.guest.clone(), m.read_only)
                })
                .collect()
        };
        let l = label(
            Shared::Rw,
            vec![
                dir("/a", Access::Link),
                dir("/b", Access::Ro),
                dir("/c", Access::Rw),
                dir("/d", Access::None),
            ],
        );
        assert!(l.mounts_store());
        assert_eq!(
            got(&l),
            [
                (SHARED.to_string(), false),
                ("/b".to_string(), true),
                ("/c".to_string(), false)
            ]
        );
        let l = label(Shared::Ro, vec![dir("/a", Access::Link)]);
        assert_eq!(got(&l), [(SHARED.to_string(), true)]);
        let l = label(Shared::None, vec![dir("/d", Access::None)]);
        assert!(got(&l).is_empty() && !l.mounts_store());
    }

    #[test]
    fn label_round_trip() {
        let l = Label {
            mode: Mode::Readonly,
            shared: Shared::Ro,
            dirs: vec![dir("/home/agent/.claude/skills", Access::Link)],
        };
        let s = l.to_label();
        assert_eq!(
            s,
            r#"{"mode":"readonly","shared":"ro","dirs":[{"path":"/home/agent/.claude/skills","access":"link"}]}"#
        );
        assert_eq!(Label::from_label(&s), Some(l));
    }
}
