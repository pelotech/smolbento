//! What the user approved for an environment, and the plan against it.
//!
//! One record per environment, named after its sandbox. It holds the approved resources and
//! nothing about the sandbox itself: whether that exists is smolvm's to say.

use std::path::PathBuf;
use std::time::{Duration, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use super::plan::{Line, Marker, Resource, When};
use crate::config::{self, Paths};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    /// The environment files, in order: another set under the same name isn't approved.
    pub files: Vec<String>,
    pub approved_at: String,
    pub approved: Vec<Resource>,
}

impl Record {
    /// The record without the resources of `section`.
    pub fn without(mut self, section: &str) -> Record {
        self.approved.retain(|r| r.section != section);
        self
    }
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
    let mut record: Record = toml::from_str(&text).ok()?;
    // Records written before resources had an id and a time they apply: the id was the name,
    // and only `ENV` reached an existing sandbox.
    for r in record.approved.iter_mut().filter(|r| r.id.is_empty()) {
        r.id = r.name.clone();
        if r.section == "ENV" {
            r.when = When::Live;
        }
    }
    Some(record)
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
    // Private: it holds what the plan shows, env values and commands included.
    config::write_atomic(
        &path(paths, name),
        toml::to_string(&record)?.as_bytes(),
        Some(0o600),
        config::Symlink::Follow,
    )
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

/// Whether applying `current` (from `files`) has to ask. As in sbx, a file that declares host
/// commands asks on every invocation, whether or not they run in it.
pub fn need(
    record: Option<&Record>,
    files: &[PathBuf],
    current: &[Resource],
    remember_host_commands: bool,
) -> Need {
    let approved = record.is_some_and(|r| r.files == file_names(files) && r.approved == current);
    if !approved {
        Need::Changed
    } else if !remember_host_commands && current.iter().any(|r| r.host_command) {
        Need::HostCommands
    } else {
        Need::No
    }
}

/// The plan's lines for `current`: what a create would set up when the sandbox doesn't exist,
/// else what differs from the record. A record for another set of files is no record: as in sbx,
/// each set of files is an environment of its own.
pub fn lines(
    record: Option<&Record>,
    files: &[PathBuf],
    current: &[Resource],
    exists: bool,
) -> Vec<Line> {
    let record = record.filter(|r| r.files == file_names(files));
    match (record, exists) {
        (Some(r), true) => differences(&r.approved, current),
        (Some(r), false) => before_create(&r.approved, current),
        (None, true) => unrecorded(current),
        (None, false) => before_create(&[], current),
    }
}

/// A sandbox that exists with nothing recorded for these files: what it already has needs
/// approval, and what reaches it at once (`env`, the launch command) is to add.
fn unrecorded(current: &[Resource]) -> Vec<Line> {
    current
        .iter()
        .map(|r| match r.when {
            When::Live | When::EveryRun => Line::new(Marker::Add, r),
            When::Removal => noted(Marker::Approve, r, AT_REMOVAL),
            When::Create => noted(Marker::Approve, r, PRESENT),
        })
        .collect()
}

fn find<'a>(list: &'a [Resource], r: &Resource) -> Option<&'a Resource> {
    list.iter().find(|o| o.section == r.section && o.id == r.id)
}

const PRESENT: &str = "present, not recorded as applied, needs your approval";
const AT_REMOVAL: &str = "waiting for this environment's removal, needs your approval";

fn noted(marker: Marker, r: &Resource, note: &'static str) -> Line {
    Line {
        note: Some(note),
        ..Line::new(marker, r)
    }
}

/// Everything is to add, with two exceptions. A path on the host is there already and a removal
/// command runs later, so each is either approved (and not listed) or needs approval. An
/// approved command of every run is to run again.
fn before_create(approved: &[Resource], current: &[Resource]) -> Vec<Line> {
    current
        .iter()
        .filter_map(|r| {
            let same = find(approved, r) == Some(r);
            let later = r.host_path || r.when == When::Removal;
            if later && same {
                None
            } else if r.when == When::Removal {
                Some(noted(Marker::Approve, r, AT_REMOVAL))
            } else if r.host_path {
                Some(noted(Marker::Approve, r, PRESENT))
            } else if same && r.host_command && r.when == When::EveryRun {
                Some(Line::new(Marker::Run, r))
            } else {
                Some(Line::new(Marker::Add, r))
            }
        })
        .collect()
}

/// What was added, changed or removed since the approval, plus what every run applies again.
/// A change that only a create applies says it waits.
fn differences(approved: &[Resource], current: &[Resource]) -> Vec<Line> {
    let waits = |r: &Resource, line: Line| Line {
        note: line
            .note
            .or((r.when == When::Create).then_some("waits for the next create")),
        ..line
    };
    let mut out = Vec::new();
    for r in current {
        let old = find(approved, r);
        let same = old == Some(r);
        let changed = |marker| Line {
            fields: old.map_or_else(|| Line::new(marker, r).fields, |a| changed_fields(a, r)),
            ..Line::new(marker, r)
        };
        let line = match r.when {
            // The launch command: applied by every run, so listed every time (as sbx does).
            When::EveryRun if !r.host_command => Line::new(Marker::Add, r),
            When::EveryRun if same => Line::new(Marker::Run, r),
            When::Removal if !same => Line {
                note: Some(AT_REMOVAL),
                ..changed(Marker::Approve)
            },
            _ if same => continue,
            _ if old.is_some() => changed(Marker::Change),
            _ => Line::new(Marker::Add, r),
        };
        out.push(waits(r, line));
    }
    let gone = approved.iter().filter(|a| find(current, a).is_none());
    out.extend(gone.map(|a| waits(a, Line::new(Marker::Destroy, a))));
    out
}

/// Each field whose value differs, as `label: old -> new`; a side without the field is empty.
/// A resource whose name changed (a lifecycle command's text) says so first.
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
    let command = |r: &'_ Resource| {
        r.name
            .split_once(": ")
            .map_or(r.name.clone(), |(_, c)| c.to_string())
    };
    let renamed =
        (old.name != new.name).then(|| format!("command: {} -> {}", command(old), command(new)));
    renamed
        .into_iter()
        .chain(
            labels
                .into_iter()
                .filter(|l| value(old, l) != value(new, l))
                .map(|l| format!("{l}: {} -> {}", value(old, l), value(new, l))),
        )
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

    fn env(name: &str, value: &str) -> Resource {
        Resource {
            when: When::Live,
            ..resource("ENV", name, &[("value", value)])
        }
    }

    fn current() -> Vec<Resource> {
        vec![
            resource("SANDBOX", "web", &[("agent", "claude")]),
            workspace(),
            env("GOFLAGS", "-mod=mod"),
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
        assert_eq!(need(None, &files(), &current(), false), Need::Changed);
        assert_eq!(need(None, &files(), &current(), true), Need::Changed);
    }

    #[test]
    fn an_equal_record_needs_none() {
        let r = record(current());
        assert_eq!(need(Some(&r), &files(), &current(), false), Need::No);
    }

    #[test]
    fn a_changed_field_or_file_set_needs_approval() {
        let r = record(current());
        let mut changed = current();
        changed[2].fields[0].1 = "-mod=readonly".into();
        assert_eq!(need(Some(&r), &files(), &changed, false), Need::Changed);
        let other = vec![
            PathBuf::from("/p/sbxenv.yaml"),
            PathBuf::from("/p/local.yaml"),
        ];
        assert_eq!(need(Some(&r), &other, &current(), false), Need::Changed);
    }

    #[test]
    fn host_commands_ask_every_time_unless_remembered() {
        let mut with_command = current();
        with_command.push(command());
        let r = record(with_command.clone());
        assert_eq!(
            need(Some(&r), &files(), &with_command, false),
            Need::HostCommands
        );
        assert_eq!(need(Some(&r), &files(), &with_command, true), Need::No);
    }

    fn lifecycle(phase: &str, i: usize, command: &str, when: When) -> Resource {
        Resource {
            id: format!("{phase}[{i}]"),
            when,
            host_command: true,
            ..resource(
                "LIFECYCLE",
                &format!("{phase}: {command}"),
                &[("workdir", "/p")],
            )
        }
    }

    fn launch() -> Resource {
        Resource {
            when: When::EveryRun,
            ..resource("AGENT LAUNCH", "cmd", &[("argv", "x")])
        }
    }

    fn signs(lines: &[Line]) -> String {
        lines.iter().map(|l| l.marker.sign()).collect()
    }

    #[test]
    fn lifecycle_and_launch_before_a_create() {
        let all = vec![
            launch(),
            lifecycle("initialize", 0, "a", When::EveryRun),
            lifecycle("postCreate", 0, "b", When::Create),
            lifecycle("preRemove", 0, "c", When::Removal),
        ];
        let fresh = lines(None, &files(), &all, false);
        assert_eq!(signs(&fresh), "+++!");
        assert_eq!(
            fresh[3].note,
            Some("waiting for this environment's removal, needs your approval")
        );
        // Approved: the every-run command runs again, the removal command is not listed.
        assert_eq!(
            signs(&lines(Some(&record(all.clone())), &files(), &all, false)),
            "+>+"
        );
    }

    #[test]
    fn lifecycle_and_launch_for_an_existing_sandbox() {
        let all = vec![
            launch(),
            lifecycle("initialize", 0, "a", When::EveryRun),
            lifecycle("postCreate", 0, "b", When::Create),
            lifecycle("preRemove", 0, "c", When::Removal),
        ];
        let r = record(all.clone());
        // Unchanged: the launch is applied again, `initialize` runs again.
        let same = lines(Some(&r), &files(), &all, true);
        assert_eq!(signs(&same), "+>");
        assert_eq!(same[0].note, None);

        let changed = vec![
            launch(),
            lifecycle("initialize", 0, "a2", When::EveryRun),
            lifecycle("postCreate", 0, "b2", When::Create),
            lifecycle("preRemove", 0, "c2", When::Removal),
        ];
        let lines = lines(Some(&r), &files(), &changed, true);
        assert_eq!(signs(&lines), "+~~!");
        assert_eq!(lines[1].resource.name, "initialize: a2");
        assert_eq!(lines[1].fields, ["command: a -> a2"]);
        assert_eq!(lines[1].note, None, "it runs on this invocation");
        assert_eq!(lines[2].note, Some("waits for the next create"));
        assert_eq!(
            lines[3].note,
            Some("waiting for this environment's removal, needs your approval")
        );
        assert_eq!(lines[3].fields, ["command: c -> c2"]);
    }

    #[test]
    fn a_record_from_before_ids_still_matches() {
        // As 0.16.0 wrote it: no `id`, no `when`.
        let (_d, paths) = test_paths();
        std::fs::create_dir_all(paths.env_records()).unwrap();
        std::fs::write(
            paths.env_records().join("web.toml"),
            r#"files = ["/p/sbxenv.yaml"]
approved_at = "2026-11-12T00:00:00Z"

[[approved]]
section = "SANDBOX"
name = "web"
fields = [["agent", "claude"]]

[[approved]]
section = "WORKSPACES"
name = "/p"
fields = []
host_path = true

[[approved]]
section = "ENV"
name = "GOFLAGS"
fields = [["value", "-mod=mod"]]

[[approved]]
section = "PORTS"
name = "8080/tcp"
fields = [["host", "18080"]]
"#,
        )
        .unwrap();
        let r = load(&paths, "web").unwrap();
        assert_eq!(need(Some(&r), &files(), &current(), false), Need::No);
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
        let lines = lines(None, &files(), &current(), false);
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
    fn an_approved_host_path_is_not_listed_before_a_create() {
        let resources = vec![workspace(), command()];
        let r = record(resources.clone());
        let lines = lines(Some(&r), &files(), &resources, false);
        assert_eq!(lines, [Line::new(Marker::Add, &command())]);
    }

    #[test]
    fn an_existing_sandbox_shows_only_differences() {
        let r = record(current());
        assert_eq!(lines(Some(&r), &files(), &current(), true), []);

        let mut changed = current();
        changed[2].fields[0].1 = "-mod=readonly".into();
        changed[3].fields[0].1 = "18081".into();
        changed.remove(1);
        changed.push(env("NEW", "1"));
        let lines = lines(Some(&r), &files(), &changed, true);
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

    #[test]
    fn another_file_set_is_another_environment() {
        let r = record(current());
        let other = vec![
            PathBuf::from("/p/sbxenv.yaml"),
            PathBuf::from("/p/same.yaml"),
        ];
        // The sandbox exists: what it has needs approval, `env` is to add (measured on sbx).
        let lines = lines(Some(&r), &other, &current(), true);
        assert_eq!(signs(&lines), "!!+!");
        assert_eq!(
            lines[0].note,
            Some("present, not recorded as applied, needs your approval")
        );
        assert_eq!(need(Some(&r), &other, &current(), false), Need::Changed);
    }
}
