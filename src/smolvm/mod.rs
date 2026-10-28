//! Everything that runs the `smolvm` binary. No other module spawns smolvm.

mod client;
mod error;
pub mod fake;
mod network;
mod pull;
mod types;

pub use client::{CreateSpec, Credential, ExecSpec, Mount, PortMap, Smolvm};
pub use error::SmolvmError;
pub use network::{AllowList, LOOPBACK, NetworkSpec};
pub use pull::{PullProgress, pull_progress};
pub use types::{EgressEvent, Machine, MachineState, PublishedPort};

use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, ExitStatus, Stdio};

use anyhow::{Context, Result};

/// Captured result of one smolvm invocation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Output {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

/// Runs smolvm. The production implementation spawns the binary; tests use [`fake::FakeRunner`].
pub trait Runner {
    /// Runs smolvm with `--error-format json` and captures its output.
    fn run(&self, args: &[String]) -> Result<Output>;
    /// Like `run`, with extra environment variables for the smolvm process only (secret values
    /// for `machine start`), and inherited variables to remove first (credentials without a value
    /// must not fall back to the host shell's).
    fn run_with_env(
        &self,
        args: &[String],
        env: &[(String, String)],
        remove: &[String],
    ) -> Result<Output> {
        let _ = (env, remove);
        self.run(args)
    }
    /// Like `run_with_env`, calling `on_line` with each piece of stderr (split on `\r` and `\n`)
    /// as smolvm writes it, for progress. The returned `Output` still holds all of stderr.
    fn run_streaming(
        &self,
        args: &[String],
        env: &[(String, String)],
        remove: &[String],
        on_line: &mut dyn FnMut(&str),
    ) -> Result<Output> {
        let _ = on_line;
        self.run_with_env(args, env, remove)
    }
    /// Runs smolvm attached to this terminal (stdio inherited) and returns its exit code.
    /// Used for `exec`, so raw mode, resizes and colour pass straight through.
    fn interactive(&self, args: &[String]) -> Result<i32>;
}

/// Spawns the real smolvm binary.
pub struct ProcessRunner {
    bin: PathBuf,
    debug: bool,
}

impl ProcessRunner {
    pub fn new(bin: impl Into<PathBuf>) -> Self {
        Self {
            bin: bin.into(),
            debug: false,
        }
    }

    /// Print each smolvm command line to stderr.
    pub fn debug(mut self, on: bool) -> Self {
        self.debug = on;
        self
    }

    fn trace(&self, args: &[String]) {
        if self.debug {
            eprintln!("+ {} {}", self.bin.display(), args.join(" "));
        }
    }

    /// `smolvm --error-format json ARGS` with stdin closed, `remove` unset and then `env` set.
    fn command(&self, args: &[String], env: &[(String, String)], remove: &[String]) -> Command {
        let mut cmd = Command::new(&self.bin);
        for name in remove {
            cmd.env_remove(name);
        }
        cmd.arg("--error-format")
            .arg("json")
            .args(args)
            .envs(env.iter().map(|(k, v)| (k, v)))
            .stdin(Stdio::null());
        cmd
    }

    fn spawn_error(&self) -> String {
        format!(
            "could not run {}; install smolvm with `brew install smol-machines/tap/smolvm` or set smolvm.path",
            self.bin.display()
        )
    }
}

impl Runner for ProcessRunner {
    fn run(&self, args: &[String]) -> Result<Output> {
        self.run_with_env(args, &[], &[])
    }

    fn run_with_env(
        &self,
        args: &[String],
        env: &[(String, String)],
        remove: &[String],
    ) -> Result<Output> {
        self.trace(args);
        let out = self
            .command(args, env, remove)
            .output()
            .with_context(|| self.spawn_error())?;
        Ok(Output {
            code: exit_code(out.status),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        })
    }

    fn run_streaming(
        &self,
        args: &[String],
        env: &[(String, String)],
        remove: &[String],
        on_line: &mut dyn FnMut(&str),
    ) -> Result<Output> {
        self.trace(args);
        let mut child = self
            .command(args, env, remove)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| self.spawn_error())?;
        let mut stdout_pipe = child.stdout.take().context("smolvm stdout")?;
        let mut stderr_pipe = child.stderr.take().context("smolvm stderr")?;
        // A scoped thread drains stdout while this thread reads stderr as it arrives, so smolvm
        // never blocks on a full stdout pipe while we wait for stderr (or the other way round).
        let (stdout, stderr) = std::thread::scope(|s| {
            let stdout = s.spawn(move || {
                let mut buf = Vec::new();
                stdout_pipe.read_to_end(&mut buf).map(|_| buf)
            });
            let stderr = read_pieces(&mut stderr_pipe, on_line);
            let stdout = stdout
                .join()
                .unwrap_or_else(|_| Err(std::io::Error::other("stdout reader panicked")));
            (stdout, stderr)
        });
        let status = child.wait().context("waiting for smolvm")?;
        Ok(Output {
            code: exit_code(status),
            stdout: String::from_utf8_lossy(&stdout.context("reading smolvm stdout")?).into_owned(),
            stderr: String::from_utf8_lossy(&stderr.context("reading smolvm stderr")?).into_owned(),
        })
    }

    fn interactive(&self, args: &[String]) -> Result<i32> {
        self.trace(args);
        let mut child = Command::new(&self.bin)
            .args(args)
            .spawn()
            .with_context(|| self.spawn_error())?;
        // The child started with default signal handling; from here Ctrl-C belongs to it.
        let _guard = IgnoreInterrupt::new();
        let status = child.wait().context("waiting for smolvm")?;
        Ok(exit_code(status))
    }
}

/// Reads `r` to the end, calling `on_line` with each non-empty piece between `\r`s and `\n`s
/// as soon as it ends, and with the unterminated rest at the end. smolvm leaves its latest pull
/// progress unterminated until the next update, so a rest ending in `%` or `...` is passed on as
/// soon as it's read (once: not again when its terminator arrives). Returns everything read.
fn read_pieces(r: &mut impl Read, on_line: &mut dyn FnMut(&str)) -> std::io::Result<Vec<u8>> {
    let mut all = Vec::new();
    let mut start = 0;
    // Where the current piece ended when it was passed on early, if it was.
    let mut sent_to = None;
    let mut buf = [0u8; 4096];
    let mut emit = |piece: &[u8]| {
        if !piece.is_empty() {
            on_line(&String::from_utf8_lossy(piece));
        }
    };
    loop {
        let n = match r.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        all.extend_from_slice(&buf[..n]);
        while let Some(i) = all[start..].iter().position(|b| matches!(b, b'\r' | b'\n')) {
            if sent_to != Some(start + i) {
                emit(&all[start..start + i]);
            }
            start += i + 1;
            sent_to = None;
        }
        let rest = &all[start..];
        if (rest.ends_with(b"%") || rest.ends_with(b"...")) && sent_to != Some(all.len()) {
            emit(rest);
            sent_to = Some(all.len());
        }
    }
    if sent_to != Some(all.len()) {
        emit(&all[start..]);
    }
    Ok(all)
}

fn exit_code(status: ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(0))
}

/// Ignores SIGINT in this process until dropped.
pub(crate) struct IgnoreInterrupt(libc::sighandler_t);

impl IgnoreInterrupt {
    pub(crate) fn new() -> Self {
        // SAFETY: swaps the SIGINT disposition; Drop restores the previous one.
        Self(unsafe { libc::signal(libc::SIGINT, libc::SIG_IGN) })
    }
}

impl Drop for IgnoreInterrupt {
    fn drop(&mut self) {
        // SAFETY: restores the disposition saved in `new`.
        unsafe { libc::signal(libc::SIGINT, self.0) };
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// A stand-in for smolvm that prints `$HOME|$PROBE`, with `unset` for missing variables.
    fn probe(dir: &std::path::Path) -> ProcessRunner {
        let script = dir.join("fake-smolvm");
        std::fs::write(
            &script,
            "#!/bin/sh\nprintf '%s|%s' \"${HOME-unset}\" \"${PROBE-unset}\"\n",
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        ProcessRunner::new(script)
    }

    /// A stand-in for smolvm running `body` as a shell script.
    fn script(dir: &std::path::Path, body: &str) -> ProcessRunner {
        let script = dir.join("fake-smolvm");
        std::fs::write(&script, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        ProcessRunner::new(script)
    }

    fn pair(k: &str, v: &str) -> (String, String) {
        (k.to_string(), v.to_string())
    }

    #[test]
    fn remove_drops_inherited_variables_and_env_wins_over_remove() {
        let dir = tempfile::tempdir().unwrap();
        let runner = probe(dir.path());
        let inherited = std::env::var("HOME").unwrap();
        let run = |env: &[(String, String)], remove: &[&str]| {
            let remove: Vec<String> = remove.iter().map(|s| s.to_string()).collect();
            runner.run_with_env(&[], env, &remove).unwrap().stdout
        };
        assert_eq!(run(&[], &[]), format!("{inherited}|unset"));
        // HOME is set in this process; removing it leaves the child without one.
        assert_eq!(run(&[], &["HOME"]), "unset|unset");
        // A name in both lists gets the given value: removals happen before `env` is applied.
        assert_eq!(
            run(&[pair("HOME", "/x"), pair("PROBE", "p")], &["HOME"]),
            "/x|p"
        );
        // `env` is for the child only.
        assert_eq!(std::env::var("PROBE").ok(), None);
    }

    #[test]
    fn streaming_splits_stderr_on_cr_and_lf_and_keeps_everything() {
        let dir = tempfile::tempdir().unwrap();
        let runner = script(
            dir.path(),
            r"printf 'out'; printf 'a...\ra... 5%%\ra... 9%%\r\nnext\n\ntail' >&2; exit 3",
        );
        let mut lines = Vec::new();
        let out = runner
            .run_streaming(&[], &[], &[], &mut |l| lines.push(l.to_string()))
            .unwrap();
        assert_eq!(lines, ["a...", "a... 5%", "a... 9%", "next", "tail"]);
        assert_eq!(out.code, 3);
        assert_eq!(out.stdout, "out");
        assert_eq!(out.stderr, "a...\ra... 5%\ra... 9%\r\nnext\n\ntail");
    }

    #[test]
    fn streaming_drains_a_full_stdout_pipe_while_reading_stderr() {
        let dir = tempfile::tempdir().unwrap();
        // More than a pipe buffer on stdout before anything on stderr.
        let runner = script(
            dir.path(),
            "head -c 300000 /dev/zero | tr '\\0' x; echo done >&2",
        );
        let mut lines = Vec::new();
        let out = runner
            .run_streaming(&[], &[], &[], &mut |l| lines.push(l.to_string()))
            .unwrap();
        assert_eq!(out.stdout.len(), 300000);
        assert_eq!(lines, ["done"]);
    }

    #[test]
    fn streaming_passes_env_and_removals_like_run_with_env() {
        let dir = tempfile::tempdir().unwrap();
        let runner = probe(dir.path());
        let out = runner
            .run_streaming(&[], &[pair("PROBE", "p")], &["HOME".into()], &mut |_| {})
            .unwrap();
        assert_eq!(out.stdout, "unset|p");
    }

    /// Hands out `chunks` one read at a time, logging each read next to the lines it produced.
    struct Chunks<'a> {
        chunks: std::collections::VecDeque<&'static str>,
        log: &'a std::cell::RefCell<Vec<String>>,
    }

    impl Read for Chunks<'_> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.log.borrow_mut().push("<read>".into());
            let Some(chunk) = self.chunks.pop_front() else {
                return Ok(0);
            };
            buf[..chunk.len()].copy_from_slice(chunk.as_bytes());
            Ok(chunk.len())
        }
    }

    #[test]
    fn unterminated_progress_is_passed_on_when_read_and_only_once() {
        let log = std::cell::RefCell::new(Vec::new());
        let mut r = Chunks {
            chunks: [
                "Pulling a...",
                "\rPulling a... [=> ] 5%",
                "\rPulling a... [==] 100% — syncing...",
                "\rPulling a... done.\nwarn: x",
            ]
            .into(),
            log: &log,
        };
        let all = read_pieces(&mut r, &mut |l| log.borrow_mut().push(l.to_string())).unwrap();
        assert_eq!(
            log.take(),
            [
                "<read>",
                "Pulling a...",
                "<read>",
                "Pulling a... [=> ] 5%",
                "<read>",
                "Pulling a... [==] 100% — syncing...",
                "<read>",
                "Pulling a... done.",
                "<read>",
                "warn: x",
            ]
        );
        assert!(all.ends_with(b"done.\nwarn: x"));
    }
}
