//! `_serve KIND SANDBOX`: what a host service unit (`host_service`) runs for each connection to a
//! sandbox's agent or bridge socket. The service manager passes the connection as stdin; the
//! guest is untrusted, so nothing else may reach it: stdout and stderr go to /dev/null.

use std::net::Shutdown;
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;

use anyhow::{Context, Result, bail};

use super::Ctx;
use crate::bridge;
use crate::host_service::Kind;
use crate::sandbox::{self, Sandbox};
use crate::smolvm::Runner;
use crate::ssh_agent::filter::{self, Backing};

pub fn run<R: Runner>(ctx: &Ctx<R>, kind: &str, name: &str) -> Result<i32> {
    let conn = take_connection()?;
    let kind = Kind::parse(kind).with_context(|| format!("unknown service kind '{kind}'"))?;
    let sb = sandbox::get(&ctx.vm, name)?;
    // Units belong to `service` sandboxes only; a stale one for another is closed.
    if !sb.meta.service {
        bail!("sandbox '{name}' isn't served by units");
    }
    match kind {
        Kind::Agent => agent(ctx, &sb, &conn),
        Kind::Bridge => bridge(ctx, &sb, &conn)?,
    }
    Ok(0)
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

fn bridge<R: Runner>(ctx: &Ctx<R>, sb: &Sandbox, conn: &UnixStream) -> Result<()> {
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
    drop(handlers);
    Ok(())
}
