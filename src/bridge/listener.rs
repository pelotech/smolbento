//! The Unix socket listener the bridge and the SSH agent filter share: bind a private socket,
//! serve it on one thread until dropped, and read with a deadline.

use std::fs;
use std::io::Read;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};

/// How long a client has, from its connect, to send its whole request; also how long writing the
/// answer may take. Requests are handled one at a time, so this bounds what a slow client holds.
pub(super) const DEADLINE: Duration = Duration::from_secs(10);

/// How often the accept loop and a request being read check for a stop.
pub(super) const POLL: Duration = Duration::from_millis(50);

/// A running listener. Dropping it stops the thread (within `POLL`, or once a running opener or
/// copier returns; those have their own timeout), so no request is handled after it, and removes
/// the socket file, if it is still the one this process bound.
pub struct Server {
    path: PathBuf,
    ino: u64,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

/// Binds `path` (as `serve`) and runs `accept` on a thread with the non-blocking listener and the
/// stop flag that dropping the returned `Server` sets.
pub(super) fn spawn(
    path: &Path,
    accept: impl FnOnce(&UnixListener, Arc<AtomicBool>) + Send + 'static,
) -> Result<Option<Server>> {
    let Some(listener) = bind(path)? else {
        return Ok(None);
    };
    let ino = fs::symlink_metadata(path)?.ino();
    listener.set_nonblocking(true)?;
    let stop = Arc::new(AtomicBool::new(false));
    let thread = {
        let stop = stop.clone();
        thread::spawn(move || accept(&listener, stop))
    };
    Ok(Some(Server {
        path: path.to_path_buf(),
        ino,
        stop,
        thread: Some(thread),
    }))
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
        if fs::symlink_metadata(&self.path).is_ok_and(|m| m.ino() == self.ino) {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn bind(path: &Path) -> Result<Option<UnixListener>> {
    if let Some(dir) = path.parent() {
        make_private_dir(dir)?;
    }
    if fs::symlink_metadata(path).is_ok() {
        if UnixStream::connect(path).is_ok() {
            return Ok(None);
        }
        fs::remove_file(path).with_context(|| format!("removing stale {}", path.display()))?;
    }
    match UnixListener::bind(path) {
        Ok(l) => Ok(Some(l)),
        // Another session bound it since the check.
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => Ok(None),
        Err(e) => Err(e).with_context(|| format!("listening on {}", path.display())),
    }
}

/// Creates `dir` 0700, or checks that an existing one is a directory of ours (it is under the
/// shared `/tmp`) and tightens it to 0700.
fn make_private_dir(dir: &Path) -> Result<()> {
    match fs::DirBuilder::new().mode(0o700).create(dir) {
        Err(e) if e.kind() != std::io::ErrorKind::AlreadyExists => {
            return Err(e).with_context(|| format!("creating {}", dir.display()));
        }
        _ => {}
    }
    let m = fs::symlink_metadata(dir)?;
    if !m.is_dir() || m.uid() != crate::util::host_uid() {
        bail!("{} isn't a directory owned by you", dir.display());
    }
    if m.mode() & 0o777 != 0o700 {
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// A socket that can wait a while for data: Unix (the bridge) or TCP (the login relay).
pub(super) trait Stream {
    fn read_for(&self, buf: &mut [u8], timeout: Duration) -> std::io::Result<usize>;
}

impl Stream for UnixStream {
    fn read_for(&self, buf: &mut [u8], timeout: Duration) -> std::io::Result<usize> {
        self.set_read_timeout(Some(timeout))?;
        (&mut &*self).read(buf)
    }
}

impl Stream for std::net::TcpStream {
    fn read_for(&self, buf: &mut [u8], timeout: Duration) -> std::io::Result<usize> {
        self.set_read_timeout(Some(timeout))?;
        (&mut &*self).read(buf)
    }
}

/// Reads from `stream` until `until` (for all reads, not each), or until `stop` is set.
pub(super) struct Deadline<'a, S> {
    pub stream: &'a S,
    pub until: Instant,
    pub stop: &'a AtomicBool,
}

impl<S: Stream> Read for Deadline<'_, S> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        use std::io::ErrorKind::{Interrupted, TimedOut, WouldBlock};
        loop {
            let left = self.until.saturating_duration_since(Instant::now());
            if left.is_zero() || self.stop.load(Ordering::Relaxed) {
                return Err(TimedOut.into());
            }
            // Wake up every POLL to see a stop.
            match self.stream.read_for(buf, left.min(POLL)) {
                Err(e) if matches!(e.kind(), WouldBlock | TimedOut | Interrupted) => {}
                r => return r,
            }
        }
    }
}
