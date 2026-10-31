//! What every command runs with: smolvm, settings, paths, the environment, and where output
//! goes and prompt answers come from. Commands live in `cli`; domain code that needs more than one
//! of these takes a `Ctx` too.

use std::collections::BTreeMap;
use std::io::{BufRead, Write};
use std::path::PathBuf;

use crate::config::{Paths, Settings};
use crate::smolvm::{Runner, Smolvm};

/// Everything a command needs; tests build one around a `FakeRunner`.
pub struct Ctx<R: Runner> {
    pub vm: Smolvm<R>,
    pub settings: Settings,
    pub paths: Paths,
    pub cwd: PathBuf,
    pub env: BTreeMap<String, String>,
    /// Unix seconds.
    pub now: i64,
    pub stdin_tty: bool,
    /// Whether stdout is a terminal: progress redraws in place and uses colour only then.
    pub stdout_tty: bool,
    /// The host user's uid and gid; the sandbox's `agent` user takes them.
    pub uid: u32,
    pub gid: u32,
    /// Where stored secret values live (OS keychain, or the 0600 file).
    pub store: Box<dyn crate::secrets::store::SecretStore>,
    /// Why config.toml couldn't be loaded; only `diagnose` and `settings` run despite it.
    pub config_error: Option<String>,
    /// Where command output goes; write with `writeln!(&ctx.out, ..)`. Errors and warnings go to
    /// stderr (`eprintln!`).
    pub out: Out,
    /// Where prompts read answers; read with `ctx.read_line()`.
    pub input: In,
    /// The command-line arguments after argv[0], for hints that repeat the command.
    pub args: Vec<String>,
}

impl<R: Runner> Ctx<R> {
    /// One line of input (a prompt's answer), with its line ending; empty at end of input.
    pub fn read_line(&self) -> std::io::Result<String> {
        let mut line = String::new();
        match &self.input {
            In::Stdin => std::io::stdin().lock().read_line(&mut line)?,
            In::Buffer(b) => b.borrow_mut().read_line(&mut line)?,
        };
        Ok(line)
    }
}

/// Prompt input: the process's stdin, or answers a test supplies.
pub enum In {
    Stdin,
    Buffer(std::cell::RefCell<std::io::Cursor<Vec<u8>>>),
}

/// Command output: the process's stdout, or a buffer tests read. Clones share the same output,
/// so a progress reporter can own one without borrowing `Ctx`.
#[derive(Clone)]
pub enum Out {
    Stdout,
    Buffer(std::rc::Rc<std::cell::RefCell<Vec<u8>>>),
}

impl Write for &Out {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Out::Stdout => std::io::stdout().write(buf),
            Out::Buffer(b) => b.borrow_mut().write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Out::Stdout => std::io::stdout().flush(),
            Out::Buffer(_) => Ok(()),
        }
    }
}
