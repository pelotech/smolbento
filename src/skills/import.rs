//! `sbt skills import`: the agents' own skills directories, first copy of a name wins.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use super::valid_name;

/// sbx's sources, in its order (relative to HOME).
pub const SOURCES: [&str; 6] = [
    ".agents/skills",
    ".claude/skills",
    ".config/opencode/skills",
    ".copilot/skills",
    ".cursor/skills",
    ".factory/skills",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    Pick { name: String, from: PathBuf },
    Duplicate { name: String, dir: PathBuf },
    Loose(String),
    Missing(PathBuf),
}

pub fn scan(home: &Path) -> Vec<Event> {
    let mut seen = BTreeSet::new();
    let mut events = Vec::new();
    for rel in SOURCES {
        let dir = home.join(rel);
        let Ok(rd) = fs::read_dir(&dir) else {
            events.push(Event::Missing(dir));
            continue;
        };
        let mut entries: Vec<_> = rd.filter_map(|e| e.ok()).collect();
        entries.sort_by_key(|e| e.file_name());
        for e in entries {
            let name = e.file_name().to_string_lossy().into_owned();
            // Top-level links are followed (`is_dir` follows them).
            if !e.path().is_dir() {
                events.push(Event::Loose(name));
            } else if !valid_name(&name) {
                continue;
            } else if !seen.insert(name.clone()) {
                events.push(Event::Duplicate {
                    name,
                    dir: dir.clone(),
                });
            } else {
                events.push(Event::Pick {
                    name,
                    from: e.path(),
                });
            }
        }
    }
    events
}
