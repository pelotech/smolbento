//! Child processes with piped or pty stdio, which the SSH server relays to a channel. The
//! interactive `Runner::interactive` can't serve it: that one inherits this process's terminal.

use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Arc;

use anyhow::{Context, Result};

/// A pseudo-terminal's size in character cells.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pty {
    pub cols: u16,
    pub rows: u16,
}

/// What can be done to a running [`Proc`] from another thread.
pub struct ProcCtl {
    pid: libc::pid_t,
    master: Option<File>,
}

impl ProcCtl {
    /// Sets the terminal size (a pty process only).
    pub fn resize(&self, size: Pty) {
        if let Some(m) = &self.master {
            let ws = winsize(size);
            // SAFETY: TIOCSWINSZ reads a `winsize` from a valid pointer; the fd is a pty master
            // this struct keeps open.
            unsafe { libc::ioctl(m.as_raw_fd(), libc::TIOCSWINSZ as _, &ws) };
        }
    }

    /// Ends the process (a hang-up for a terminal session, else a termination).
    pub fn kill(&self) {
        let sig = if self.master.is_some() {
            libc::SIGHUP
        } else {
            libc::SIGTERM
        };
        // SAFETY: signalling a pid we spawned; at worst it has exited (ESRCH).
        unsafe { libc::kill(self.pid, sig) };
    }
}

/// A running process. With a pty, `stdout` and `stdin` are the master side and there is no
/// separate `stderr`.
pub struct Proc {
    pub stdin: Box<dyn Write + Send>,
    pub stdout: Box<dyn Read + Send>,
    pub stderr: Option<Box<dyn Read + Send>>,
    pub ctl: Arc<ProcCtl>,
    /// Waits for the process to end and returns its exit code (`128 + n` after signal `n`).
    pub wait: Box<dyn FnOnce() -> Result<i32> + Send>,
}

/// Starts smolvm processes with piped or pty stdio. Owned, so it can move to other threads.
#[derive(Clone)]
pub struct ProcessSpawner {
    pub(super) bin: PathBuf,
    pub(super) env: Vec<(String, String)>,
}

impl ProcessSpawner {
    fn command(&self, args: &[String]) -> Command {
        let mut cmd = Command::new(&self.bin);
        cmd.args(args).envs(self.env.iter().map(|(k, v)| (k, v)));
        cmd
    }
}

fn winsize(size: Pty) -> libc::winsize {
    libc::winsize {
        ws_row: size.rows,
        ws_col: size.cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    }
}

fn cloexec(fd: &OwnedFd) {
    // SAFETY: fcntl on an fd we own.
    unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) };
}

/// A new pty: (master, slave), both close-on-exec.
fn open_pty(size: Pty) -> Result<(OwnedFd, OwnedFd)> {
    let (mut master, mut slave) = (0, 0);
    let mut ws = winsize(size);
    // SAFETY: openpty writes two fds through valid pointers; the winsize is read. It is passed as a
    // raw pointer: macOS declares the parameter `*mut winsize`, glibc `*const winsize`.
    let rc = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &raw mut ws,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).context("opening a pty");
    }
    // SAFETY: openpty returned these as new descriptors nothing else owns.
    let (master, slave) = unsafe { (OwnedFd::from_raw_fd(master), OwnedFd::from_raw_fd(slave)) };
    cloexec(&master);
    cloexec(&slave);
    Ok((master, slave))
}

impl ProcessSpawner {
    /// Runs smolvm with `args`, on a new pty of the given size when there is one.
    pub fn spawn(&self, args: &[String], pty: Option<Pty>) -> Result<Proc> {
        let mut cmd = self.command(args);
        let spawn_error = || format!("could not run {}", self.bin.display());
        let Some(size) = pty else {
            let mut child = cmd
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .with_context(spawn_error)?;
            let pid = child.id() as libc::pid_t;
            return Ok(Proc {
                stdin: Box::new(child.stdin.take().context("smolvm stdin")?),
                stdout: Box::new(child.stdout.take().context("smolvm stdout")?),
                stderr: Some(Box::new(child.stderr.take().context("smolvm stderr")?)),
                ctl: Arc::new(ProcCtl { pid, master: None }),
                wait: Box::new(move || Ok(super::exit_code(child.wait()?))),
            });
        };
        let (master, slave) = open_pty(size)?;
        let slave = File::from(slave);
        cmd.stdin(Stdio::from(slave.try_clone()?))
            .stdout(Stdio::from(slave.try_clone()?))
            .stderr(Stdio::from(slave));
        // SAFETY: setsid and ioctl are async-signal-safe, and nothing else runs between fork and
        // exec. The child leads a new session with the pty as its terminal, so a resize reaches
        // it as SIGWINCH and a hang-up as SIGHUP.
        unsafe {
            cmd.pre_exec(|| {
                libc::setsid();
                libc::ioctl(0, libc::TIOCSCTTY as _, 0);
                Ok(())
            });
        }
        let mut child = cmd.spawn().with_context(spawn_error)?;
        // Our copies of the slave must close, or the master never sees the end of the session.
        drop(cmd);
        let master = File::from(master);
        let pid = child.id() as libc::pid_t;
        Ok(Proc {
            stdin: Box::new(master.try_clone()?),
            stdout: Box::new(PtyReader(master.try_clone()?)),
            stderr: None,
            ctl: Arc::new(ProcCtl {
                pid,
                master: Some(master),
            }),
            wait: Box::new(move || Ok(super::exit_code(child.wait()?))),
        })
    }
}

/// A pty master: once the session ends, reads fail with EIO (Linux) rather than return 0.
struct PtyReader(File);

impl Read for PtyReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self.0.read(buf) {
            Err(e) if e.raw_os_error() == Some(libc::EIO) => Ok(0),
            other => other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A spawner whose "smolvm" is `sh`, so `args` is `-c SCRIPT`.
    fn sh() -> ProcessSpawner {
        ProcessSpawner {
            bin: "/bin/sh".into(),
            env: vec![],
        }
    }

    fn read_all(mut r: impl Read) -> String {
        let mut s = String::new();
        let _ = r.read_to_string(&mut s);
        s
    }

    fn script(s: &str) -> Vec<String> {
        vec!["-c".into(), s.into()]
    }

    #[test]
    fn piped_processes_keep_stdout_and_stderr_apart_and_report_the_exit_code() {
        let mut p = sh()
            .spawn(&script("cat; echo oops >&2; exit 7"), None)
            .unwrap();
        p.stdin.write_all(b"in\n").unwrap();
        drop(p.stdin);
        assert_eq!(read_all(p.stdout), "in\n");
        assert_eq!(read_all(p.stderr.unwrap()), "oops\n");
        assert_eq!((p.wait)().unwrap(), 7);
    }

    #[test]
    fn a_pty_process_has_the_size_a_controlling_terminal_and_follows_resizes() {
        let script = script(
            "stty size; trap 'stty size; exit 0' WINCH; echo ready; while :; do sleep 0.05; done",
        );
        let p = sh()
            .spawn(&script, Some(Pty { cols: 80, rows: 24 }))
            .unwrap();
        pty_check(p.stdout, p.ctl, p.wait);
    }

    fn pty_check(
        mut out: Box<dyn Read + Send>,
        ctl: Arc<ProcCtl>,
        wait: Box<dyn FnOnce() -> Result<i32> + Send>,
    ) {
        let mut seen = String::new();
        let mut buf = [0u8; 256];
        while !seen.contains("ready") {
            let n = out.read(&mut buf).unwrap();
            assert!(n > 0, "ended early: {seen:?}");
            seen.push_str(&String::from_utf8_lossy(&buf[..n]));
        }
        assert!(seen.contains("24 80"), "{seen:?}");
        ctl.resize(Pty {
            cols: 120,
            rows: 40,
        });
        seen.clear();
        loop {
            let n = out.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            seen.push_str(&String::from_utf8_lossy(&buf[..n]));
        }
        assert!(seen.contains("40 120"), "{seen:?}");
        assert_eq!(wait().unwrap(), 0);
    }

    #[test]
    fn kill_ends_a_pty_process_with_a_hang_up() {
        let p = sh()
            .spawn(&script("sleep 30"), Some(Pty { cols: 80, rows: 24 }))
            .unwrap();
        p.ctl.kill();
        assert_eq!((p.wait)().unwrap(), 128 + libc::SIGHUP);
    }
}
