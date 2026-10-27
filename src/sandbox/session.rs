//! One file per attached `run` session (`<sessions>/<sandbox>/<pid>`), so the last session to
//! exit can stop the sandbox. `run -d` leaves a `detached` marker that keeps it running.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

const DETACHED: &str = "detached";

pub struct Session {
    path: PathBuf,
}

impl Session {
    pub fn register(sessions: &Path, sandbox: &str) -> Result<Session> {
        let dir = sessions.join(sandbox);
        fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        let path = dir.join(std::process::id().to_string());
        fs::write(&path, b"").with_context(|| format!("writing {}", path.display()))?;
        Ok(Session { path })
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

/// Counts live sessions, deleting files left behind by processes that died.
pub fn live_sessions(sessions: &Path, sandbox: &str) -> usize {
    let Ok(entries) = fs::read_dir(sessions.join(sandbox)) else {
        return 0;
    };
    let mut live = 0;
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<u32>().ok())
        else {
            continue;
        };
        if pid_alive(pid) {
            live += 1;
        } else {
            let _ = fs::remove_file(entry.path());
        }
    }
    live
}

pub fn mark_detached(sessions: &Path, sandbox: &str) -> Result<()> {
    let dir = sessions.join(sandbox);
    fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    fs::write(dir.join(DETACHED), b"").context("writing detached marker")
}

pub fn is_detached(sessions: &Path, sandbox: &str) -> bool {
    sessions.join(sandbox).join(DETACHED).exists()
}

/// Nobody needs the sandbox running: it wasn't started with `run -d` and has no live session.
pub fn idle(sessions: &Path, sandbox: &str) -> bool {
    !is_detached(sessions, sandbox) && live_sessions(sessions, sandbox) == 0
}

/// Forgets every session and the detached marker (on stop and rm).
pub fn clear(sessions: &Path, sandbox: &str) {
    let _ = fs::remove_dir_all(sessions.join(sandbox));
}

fn pid_alive(pid: u32) -> bool {
    let Ok(pid) = i32::try_from(pid) else {
        return false;
    };
    if pid <= 0 {
        return false;
    }
    // SAFETY: signal 0 only checks that the process exists.
    let rc = unsafe { libc::kill(pid, 0) };
    rc == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_counts_and_drops() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(live_sessions(dir.path(), "a"), 0);
        let s = Session::register(dir.path(), "a").unwrap();
        assert_eq!(live_sessions(dir.path(), "a"), 1);
        drop(s);
        assert_eq!(live_sessions(dir.path(), "a"), 0);
    }

    #[test]
    fn dead_pids_are_pruned() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("a")).unwrap();
        std::fs::write(dir.path().join("a/2000000000"), "").unwrap();
        assert_eq!(live_sessions(dir.path(), "a"), 0);
        assert!(!dir.path().join("a/2000000000").exists());
    }

    #[test]
    fn detached_marker() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!is_detached(dir.path(), "a"));
        assert!(idle(dir.path(), "a"));
        mark_detached(dir.path(), "a").unwrap();
        assert!(is_detached(dir.path(), "a"));
        assert!(!idle(dir.path(), "a"));
        assert_eq!(live_sessions(dir.path(), "a"), 0);
        clear(dir.path(), "a");
        assert!(!is_detached(dir.path(), "a"));
    }
}
