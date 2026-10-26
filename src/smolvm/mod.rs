//! Everything that runs the `smolvm` binary. No other module spawns smolvm.

mod client;
mod error;
pub mod fake;
mod network;
mod types;

pub use client::{CreateSpec, Credential, ExecSpec, Mount, PortMap, Smolvm};
pub use error::SmolvmError;
pub use network::{AllowList, LOOPBACK, NetworkSpec};
pub use types::{EgressEvent, Machine, MachineState, PublishedPort};

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
        let mut cmd = Command::new(&self.bin);
        for name in remove {
            cmd.env_remove(name);
        }
        let out = cmd
            .arg("--error-format")
            .arg("json")
            .args(args)
            .envs(env.iter().map(|(k, v)| (k, v)))
            .stdin(Stdio::null())
            .output()
            .with_context(|| self.spawn_error())?;
        Ok(Output {
            code: exit_code(out.status),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
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

fn exit_code(status: ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(0))
}

/// Ignores SIGINT in this process until dropped.
struct IgnoreInterrupt(libc::sighandler_t);

impl IgnoreInterrupt {
    fn new() -> Self {
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
