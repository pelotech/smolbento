//! `_serve KIND SANDBOX`: what a host service unit (`host_service`) runs for each connection to a
//! sandbox's agent or bridge socket. The service manager passes the connection as stdin; the
//! guest is untrusted, so nothing else may reach it: stdout and stderr go to /dev/null.

use std::fs::{File, OpenOptions};
use std::net::Shutdown;
use std::os::fd::AsRawFd;
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use super::Ctx;
use crate::bridge;
use crate::host_service::{Kind, MAX_CONNECTIONS};
use crate::sandbox::{self, Sandbox};
use crate::smolvm::Runner;
use crate::ssh_agent::filter::{self, Backing};

pub fn run<R: Runner>(ctx: &Ctx<R>, kind: &str, name: &str) -> Result<i32> {
    let conn = take_connection()?;
    let kind = Kind::parse(kind).with_context(|| format!("unknown service kind '{kind}'"))?;
    let slots = ctx.services.slot_files(name, kind);
    guarded(conn, &slots, MAX_CONNECTIONS, |conn, slot| {
        let sb = sandbox::get(&ctx.vm, name)?;
        // Units belong to `service` sandboxes only; a stale one for another is closed.
        if !sb.meta.service {
            bail!("sandbox '{name}' isn't served by units");
        }
        match kind {
            Kind::Agent => agent(ctx, &sb, &conn),
            Kind::Bridge => bridge(ctx, &sb, &conn, slot)?,
        }
        Ok(())
    })?;
    Ok(0)
}

/// Runs `serve` on `conn` holding one of the `max` slots, at most `max` at once per sandbox and
/// kind, whichever service manager started us (the guest is untrusted and could open connections
/// in a loop). A connection past the cap is closed at once, silently. The slot is released when
/// `serve` drops it or this process ends, a crash included.
fn guarded(
    conn: UnixStream,
    slots: &[PathBuf],
    max: usize,
    serve: impl FnOnce(UnixStream, File) -> Result<()>,
) -> Result<()> {
    match acquire_slot(slots, max) {
        Some(slot) => serve(conn, slot),
        None => Ok(()),
    }
}

/// Locks the first free file of `slots` (created 0600) until the returned file is dropped or the
/// process ends; `None` when every one is held, or the files can't be made.
fn acquire_slot(slots: &[PathBuf], max: usize) -> Option<File> {
    slots.iter().take(max).find_map(|p| lock(p))
}

fn lock(path: &Path) -> Option<File> {
    let f = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .open(path)
        .ok()?;
    // SAFETY: flock on a descriptor we own; it fails (EWOULDBLOCK) when another process holds it.
    (unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0).then_some(f)
}

/// stdin as the connection, then stdout and stderr to /dev/null (under launchd's inetd mode and
/// systemd's `StandardInput=socket` they would otherwise be the guest's end of the socket too).
fn take_connection() -> Result<UnixStream> {
    // SAFETY: dup of fd 0 either fails or returns a new descriptor nothing else owns.
    let fd = unsafe { libc::dup(0) };
    if fd < 0 {
        bail!(
            "no connection on stdin: {}",
            std::io::Error::last_os_error()
        );
    }
    // SAFETY: `fd` is open and owned only here.
    let conn = UnixStream::from(unsafe { OwnedFd::from_raw_fd(fd) });
    // SAFETY: open and dup2 on constant arguments; fds 1 and 2 are replaced, not closed.
    unsafe {
        let null = libc::open(c"/dev/null".as_ptr(), libc::O_WRONLY);
        if null >= 0 {
            libc::dup2(null, 1);
            libc::dup2(null, 2);
            libc::close(null);
        }
    }
    Ok(conn)
}

fn agent<R: Runner>(ctx: &Ctx<R>, sb: &Sandbox, conn: &UnixStream) {
    let Some(access) = sb.meta.ssh_agent.as_ref().and_then(|a| a.runtime.as_ref()) else {
        return;
    };
    filter::serve_connection(conn, access, &Backing::new(&ctx.paths, &ctx.env));
}

fn bridge<R: Runner>(ctx: &Ctx<R>, sb: &Sandbox, conn: &UnixStream, slot: File) -> Result<()> {
    if !sb.meta.bridge || !bridge::has_display(&ctx.env, cfg!(target_os = "linux")) {
        return Ok(());
    }
    let handlers = bridge::handlers(
        &ctx.env,
        ctx.settings.bool("browser.enabled")?,
        &ctx.settings.value("smolvm.path")?,
        sb,
        true,
    );
    bridge::serve_connection(conn, &handlers);
    // The client reads to the end of the answer: close the connection before a login relay, if
    // one started, keeps this process alive (dropping `handlers` waits for it).
    let _ = conn.shutdown(Shutdown::Both);
    // The slot is for the connection: a lingering relay no longer holds one.
    drop(slot);
    drop(handlers);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn the_cap_plus_first_concurrent_connection_is_closed_unserved() {
        use std::sync::{Arc, Barrier};
        let dir = tempfile::tempdir().unwrap();
        let slots: Vec<PathBuf> = (0..3)
            .map(|i| dir.path().join(format!("s.slot{i}")))
            .collect();
        let (all_in, release) = (Arc::new(Barrier::new(4)), Arc::new(Barrier::new(4)));
        let served = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut threads = Vec::new();
        for _ in 0..3 {
            let (slots, all_in, release, served) = (
                slots.clone(),
                all_in.clone(),
                release.clone(),
                served.clone(),
            );
            threads.push(std::thread::spawn(move || {
                let (_client, server) = UnixStream::pair().unwrap();
                guarded(server, &slots, 3, |_conn, _slot| {
                    served.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    all_in.wait();
                    release.wait();
                    Ok(())
                })
                .unwrap();
            }));
        }
        all_in.wait();
        // All three slots are held: the fourth connection is closed, its peer sees only EOF.
        let (mut client, server) = UnixStream::pair().unwrap();
        let ran = std::cell::Cell::new(false);
        guarded(server, &slots, 3, |_c, _s| {
            ran.set(true);
            Ok(())
        })
        .unwrap();
        assert!(!ran.get(), "the cap+1th is never served");
        let mut got = Vec::new();
        client.read_to_end(&mut got).unwrap();
        assert!(got.is_empty());
        release.wait();
        for t in threads {
            t.join().unwrap();
        }
        assert_eq!(served.load(std::sync::atomic::Ordering::SeqCst), 3);
        // Released: serves again.
        let (_c, server) = UnixStream::pair().unwrap();
        guarded(server, &slots, 3, |_c, _s| {
            ran.set(true);
            Ok(())
        })
        .unwrap();
        assert!(ran.get());
    }

    #[test]
    fn slots_are_per_process_locks_held_for_the_connections_life() {
        let dir = tempfile::tempdir().unwrap();
        let slots = vec![dir.path().join("a.slot0")];
        let first = acquire_slot(&slots, 1).unwrap();
        let out = std::thread::scope(|s| {
            s.spawn(|| acquire_slot(&slots, 1).is_none())
                .join()
                .unwrap()
        });
        assert!(out, "a second open file description can't take it");
        drop(first);
        assert!(acquire_slot(&slots, 1).is_some());
    }
}
