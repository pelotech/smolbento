//! `_serve KIND SANDBOX`: what a host service unit (`host_service`) runs for each connection to a
//! sandbox's agent or bridge socket. The service manager passes the connection as stdin; the
//! guest is untrusted, so nothing else may reach it: stdout and stderr go to /dev/null.

use std::fs::File;
use std::net::Shutdown;
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};

use super::Ctx;
use crate::bridge;
use crate::host_service::{Kind, acquire_slot};
use crate::sandbox::{self, Sandbox};
use crate::smolvm::Runner;
use crate::ssh_agent::filter::{self, Backing};

pub fn run<R: Runner>(
    ctx: &Ctx<R>,
    kind: &str,
    name: &str,
    conn: Option<UnixStream>,
) -> Result<i32> {
    let conn = conn.map_or_else(take_connection, Ok)?;
    let kind = Kind::parse(kind).with_context(|| format!("unknown service kind '{kind}'"))?;
    let slots = ctx.services.slot_files(name, kind);
    guarded(conn, &slots, |conn, slot| {
        let sb = sandbox::get(&ctx.vm, name)?;
        // Units belong to `service` sandboxes only; a stale one for another is closed.
        if !sb.meta.service {
            bail!("sandbox '{name}' isn't served by units");
        }
        match kind {
            Kind::Agent => agent(ctx, &sb, &conn),
            Kind::Bridge => bridge(ctx, &sb, &conn, slot)?,
            Kind::Egress => bail!("_serve egress isn't implemented yet"),
        }
        Ok(())
    })?;
    Ok(0)
}

/// Runs `serve` on `conn` holding one of `slots`, so at most that many at once per sandbox and
/// kind, whichever service manager started us (the guest is untrusted and could open connections
/// in a loop). A connection past the cap is closed at once, silently. The slot is released when
/// `serve` drops it or this process ends, a crash included.
fn guarded(
    conn: UnixStream,
    slots: &[PathBuf],
    serve: impl FnOnce(UnixStream, File) -> Result<()>,
) -> Result<()> {
    match acquire_slot(slots) {
        Some(slot) => serve(conn, slot),
        None => Ok(()),
    }
}

/// stdin as the connection, then stdout and stderr to /dev/null (under launchd's inetd mode and
/// systemd's `StandardInput=socket` they would otherwise be the guest's end of the socket too).
/// Redirects fds 1 and 2 first so even an error here cannot write onto the guest socket.
pub(super) fn take_connection() -> Result<UnixStream> {
    // SAFETY: open and dup2 on constant arguments; fds 1 and 2 are replaced, not closed.
    unsafe {
        let null = libc::open(c"/dev/null".as_ptr(), libc::O_WRONLY);
        if null >= 0 {
            libc::dup2(null, 1);
            libc::dup2(null, 2);
            libc::close(null);
        }
    }
    // SAFETY: dup of fd 0 either fails or returns a new descriptor nothing else owns.
    let fd = unsafe { libc::dup(0) };
    if fd < 0 {
        bail!(
            "no connection on stdin: {}",
            std::io::Error::last_os_error()
        );
    }
    // SAFETY: `fd` is open and owned only here.
    Ok(UnixStream::from(unsafe { OwnedFd::from_raw_fd(fd) }))
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
        bridge::Allowed::from_settings(&ctx.settings)?,
        &ctx.smolvm,
        sb,
        Some(ctx.services.relay_slot_files(sb.name())),
    );
    bridge::serve_connection(conn, &handlers);
    // The client reads to the end of the answer: close the connection before a login relay, if
    // one started, keeps this process alive (dropping `handlers` waits for it).
    let _ = conn.shutdown(Shutdown::Both);
    // The connection's slot goes with it; a lingering relay holds a relay slot instead.
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
                guarded(server, &slots, |_conn, _slot| {
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
        guarded(server, &slots, |_c, _s| {
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
        guarded(server, &slots, |_c, _s| {
            ran.set(true);
            Ok(())
        })
        .unwrap();
        assert!(ran.get());
    }

    #[test]
    fn slots_are_per_process_locks_held_for_the_connections_life() {
        let dir = tempfile::tempdir().unwrap();
        let slots = [dir.path().join("a.slot0")];
        let first = acquire_slot(&slots).unwrap();
        let out =
            std::thread::scope(|s| s.spawn(|| acquire_slot(&slots).is_none()).join().unwrap());
        assert!(out, "a second open file description can't take it");
        drop(first);
        assert!(acquire_slot(&slots).is_some());
    }
}
