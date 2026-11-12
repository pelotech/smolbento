//! What the user approved for an environment, and the plan against it.
//!
//! One record per environment, named after its sandbox. It holds the approved resources and
//! nothing about the sandbox itself: whether that exists is smolvm's to say.

use std::path::{Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use super::plan::{Line, Marker, Resource};
use crate::config::{self, Paths};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    /// The environment files, in order: another set under the same name isn't approved.
    pub files: Vec<String>,
    pub approved_at: String,
    pub approved: Vec<Resource>,
}

/// Why applying has to ask.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Need {
    No,
    /// Nothing is approved, or the files or resources differ from what was.
    Changed,
    /// Everything is approved, but commands will run on the host, which asks every time unless
    /// `env.rememberHostCommands` is on.
    HostCommands,
}

fn path(paths: &Paths, name: &str) -> PathBuf {
    paths.env_records().join(format!("{name}.toml"))
}

fn file_names(files: &[PathBuf]) -> Vec<String> {
    files.iter().map(|f| f.display().to_string()).collect()
}

/// The record for sandbox `name`. A missing or unreadable one is no approval.
pub fn load(paths: &Paths, name: &str) -> Option<Record> {
    let text = std::fs::read_to_string(path(paths, name)).ok()?;
    toml::from_str(&text).ok()
}

/// Records `resources` as approved, at `now` (seconds since the epoch).
pub fn save(
    paths: &Paths,
    name: &str,
    files: &[PathBuf],
    resources: &[Resource],
    now: i64,
) -> Result<()> {
    let at = UNIX_EPOCH + Duration::from_secs(now.max(0) as u64);
    let record = Record {
        files: file_names(files),
        approved_at: humantime::format_rfc3339_seconds(at).to_string(),
        approved: resources.to_vec(),
    };
    let path = path(paths, name);
    create_parent(&path)?;
    config::save_toml(&path, &record)
}

fn create_parent(path: &Path) -> Result<()> {
    let dir = path.parent().context("a record path has a parent")?;
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))
}

/// Forgets the approval for sandbox `name`, if there is one.
pub fn forget(paths: &Paths, name: &str) -> Result<()> {
    let path = path(paths, name);
    match std::fs::remove_file(&path) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
            Err(e).with_context(|| format!("removing {}", path.display()))
        }
        _ => Ok(()),
    }
}

/// Whether applying `current` (from `files`) has to ask. `exists` says the sandbox does: a host
/// command only runs when it is created.
pub fn need(
    record: Option<&Record>,
    files: &[PathBuf],
    current: &[Resource],
    exists: bool,
    remember_host_commands: bool,
) -> Need {
    let approved = record.is_some_and(|r| r.files == file_names(files) && r.approved == current);
    if !approved {
        Need::Changed
    } else if !exists && !remember_host_commands && current.iter().any(|r| r.host_command) {
        Need::HostCommands
    } else {
        Need::No
    }
}

/// The plan's lines for `current`. Without a sandbox everything is to add; with one, only what
/// differs from the record is shown.
pub fn lines(record: Option<&Record>, current: &[Resource], exists: bool) -> Vec<Line> {
    let approved: &[Resource] = record.map_or(&[], |r| &r.approved);
    let recorded = |r: &Resource| {
        approved
            .iter()
            .find(|a| a.section == r.section && a.name == r.name)
    };
    if !exists {
        return current
            .iter()
            .map(|r| {
                let same = recorded(r) == Some(r);
                if r.host_path && !same {
                    Line {
                        note: Some("present, not recorded as applied, needs your approval"),
                        ..Line::new(Marker::Approve, r)
                    }
                } else if r.host_command && same {
                    Line::new(Marker::Run, r)
                } else {
                    Line::new(Marker::Add, r)
                }
            })
            .collect();
    }
    // Only `env` reaches a sandbox that exists.
    let note = |r: &Resource| (r.section != "ENV").then_some("waits for the next create");
    let mut out = Vec::new();
    for r in current {
        let line = match recorded(r) {
            Some(a) if a == r => continue,
            Some(a) => Line {
                fields: changed_fields(a, r),
                ..Line::new(Marker::Change, r)
            },
            None => Line::new(Marker::Add, r),
        };
        out.push(Line {
            note: note(r),
            ..line
        });
    }
    let gone = approved.iter().filter(|a| {
        !current
            .iter()
            .any(|r| r.section == a.section && r.name == a.name)
    });
    out.extend(gone.map(|a| Line {
        note: note(a),
        ..Line::new(Marker::Destroy, a)
    }));
    out
}

/// Each field whose value differs, as `label: old -> new`; a side without the field is empty.
fn changed_fields(old: &Resource, new: &Resource) -> Vec<String> {
    let value = |r: &Resource, label: &str| {
        r.fields
            .iter()
            .find(|(l, _)| l == label)
            .map(|(_, v)| v.clone())
            .unwrap_or_default()
    };
    let mut labels: Vec<&str> = new.fields.iter().map(|(l, _)| l.as_str()).collect();
    for (l, _) in &old.fields {
        if !labels.contains(&l.as_str()) {
            labels.push(l);
        }
    }
    labels
        .into_iter()
        .filter(|l| value(old, l) != value(new, l))
        .map(|l| format!("{l}: {} -> {}", value(old, l), value(new, l)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::test_paths;
    use crate::env::plan::resource;

    fn files() -> Vec<PathBuf> {
        vec![PathBuf::from("/p/sbxenv.yaml")]
    }

    fn command() -> Resource {
        Resource {
            host_command: true,
            ..resource("SECRETS", "github", &[("command", "gh auth token")])
        }
    }

    fn workspace() -> Resource {
        Resource {
            host_path: true,
            ..resource("WORKSPACES", "/p", &[])
        }
    }

    fn current() -> Vec<Resource> {
        vec![
            resource("SANDBOX", "web", &[("agent", "claude")]),
            workspace(),
            resource("ENV", "GOFLAGS", &[("value", "-mod=mod")]),
            resource("PORTS", "8080/tcp", &[("host", "18080")]),
        ]
    }

    fn record(approved: Vec<Resource>) -> Record {
        Record {
            files: vec!["/p/sbxenv.yaml".into()],
            approved_at: "2026-11-12T00:00:00Z".into(),
            approved,
        }
    }

    #[test]
    fn no_record_needs_approval() {
        assert_eq!(
            need(None, &files(), &current(), false, false),
            Need::Changed
        );
        assert_eq!(need(None, &files(), &current(), true, true), Need::Changed);
    }

    #[test]
    fn an_equal_record_needs_none() {
        let r = record(current());
        assert_eq!(need(Some(&r), &files(), &current(), false, false), Need::No);
    }

    #[test]
    fn a_changed_field_or_file_set_needs_approval() {
        let r = record(current());
        let mut changed = current();
        changed[2].fields[0].1 = "-mod=readonly".into();
        assert_eq!(
            need(Some(&r), &files(), &changed, true, false),
            Need::Changed
        );
        let other = vec![
            PathBuf::from("/p/sbxenv.yaml"),
            PathBuf::from("/p/local.yaml"),
        ];
        assert_eq!(
            need(Some(&r), &other, &current(), true, false),
            Need::Changed
        );
    }

    #[test]
    fn host_commands_ask_only_before_a_create_and_without_the_setting() {
        let mut with_command = current();
        with_command.push(command());
        let r = record(with_command.clone());
        let ask = |exists, remember| need(Some(&r), &files(), &with_command, exists, remember);
        assert_eq!(ask(false, false), Need::HostCommands);
        assert_eq!(ask(false, true), Need::No);
        assert_eq!(ask(true, false), Need::No);
        assert_eq!(ask(true, true), Need::No);
    }

    #[test]
    fn save_then_load_round_trips_and_forget_removes() {
        let (_d, paths) = test_paths();
        assert_eq!(load(&paths, "web"), None);
        let mut resources = current();
        resources.push(command());
        save(&paths, "web", &files(), &resources, 1_794_441_600).unwrap();
        let r = load(&paths, "web").unwrap();
        assert_eq!(r.approved, resources);
        assert_eq!(r.files, ["/p/sbxenv.yaml"]);
        assert_eq!(r.approved_at, "2026-11-12T00:00:00Z");
        forget(&paths, "web").unwrap();
        assert_eq!(load(&paths, "web"), None);
        forget(&paths, "web").unwrap();
    }

    #[test]
    fn a_corrupt_or_empty_record_counts_as_none() {
        let (_d, paths) = test_paths();
        std::fs::create_dir_all(paths.env_records()).unwrap();
        for text in ["not toml [", ""] {
            std::fs::write(paths.env_records().join("web.toml"), text).unwrap();
            assert_eq!(load(&paths, "web"), None, "{text:?}");
        }
    }

    #[test]
    fn a_fresh_plan_marks_host_paths_for_approval() {
        let lines = lines(None, &current(), false);
        let markers: Vec<Marker> = lines.iter().map(|l| l.marker).collect();
        assert_eq!(
            markers,
            [Marker::Add, Marker::Approve, Marker::Add, Marker::Add]
        );
        assert_eq!(
            lines[1].note,
            Some("present, not recorded as applied, needs your approval")
        );
        assert_eq!(lines[2].fields, ["value: -mod=mod"]);
    }

    #[test]
    fn an_approved_host_command_is_run_before_a_create() {
        let resources = vec![workspace(), command()];
        let r = record(resources.clone());
        let lines = lines(Some(&r), &resources, false);
        let markers: Vec<Marker> = lines.iter().map(|l| l.marker).collect();
        // An approved workspace is to add again: the sandbox is gone.
        assert_eq!(markers, [Marker::Add, Marker::Run]);
    }

    #[test]
    fn an_existing_sandbox_shows_only_differences() {
        let r = record(current());
        assert_eq!(lines(Some(&r), &current(), true), []);

        let mut changed = current();
        changed[2].fields[0].1 = "-mod=readonly".into();
        changed[3].fields[0].1 = "18081".into();
        changed.remove(1);
        changed.push(resource("ENV", "NEW", &[("value", "1")]));
        let lines = lines(Some(&r), &changed, true);
        let shown: Vec<(char, &str, Option<&str>, &[String])> = lines
            .iter()
            .map(|l| {
                (
                    l.marker.sign(),
                    l.resource.name.as_str(),
                    l.note,
                    l.fields.as_slice(),
                )
            })
            .collect();
        let waits = Some("waits for the next create");
        assert_eq!(
            shown,
            [
                (
                    '~',
                    "GOFLAGS",
                    None,
                    &["value: -mod=mod -> -mod=readonly".to_string()][..]
                ),
                (
                    '~',
                    "8080/tcp",
                    waits,
                    &["host: 18080 -> 18081".to_string()][..]
                ),
                ('+', "NEW", None, &["value: 1".to_string()][..]),
                ('-', "/p", waits, &[][..]),
            ]
        );
    }
}
