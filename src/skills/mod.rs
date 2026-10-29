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
for d in {dirs}; do
  mkdir -p "$d"
  for l in "$d"/* "$d"/.[!.]*; do
    [ -L "$l" ] || continue
    case "$(readlink "$l")" in "$S"/*) [ -e "$l" ] || rm -f "$l" ;; esac
  done
  for e in "$S"/*; do
    n=${{e##*/}}
    case "$n" in [A-Za-z0-9]*) ;; *) continue ;; esac
    case "$n" in *[!A-Za-z0-9._-]*) continue ;; esac
    [ -e "$d/$n" ] || [ -L "$d/$n" ] || ln -s "$S/$n" "$d/$n"
  done
done"#,
        dirs = ro.join(" ")
    ))
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
