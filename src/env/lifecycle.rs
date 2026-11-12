//! Running an environment's lifecycle commands on the host, as sbx does.
//!
//! They run with the user's privileges and sbt's own environment plus the `SBX_*` variables. They
//! get neither the file's `env` values nor any secret.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Instant;

use anyhow::{Context, Result, bail};

use super::file::HostCommand;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Initialize,
    PostCreate,
    PreRemove,
}

impl Phase {
    /// The name in the file, in errors and in `SBX_LIFECYCLE_PHASE`.
    pub fn name(self) -> &'static str {
        match self {
            Phase::Initialize => "initialize",
            Phase::PostCreate => "postCreate",
            Phase::PreRemove => "preRemove",
        }
    }

    fn heading(self) -> &'static str {
        match self {
            Phase::Initialize => "HOST INITIALIZE",
            Phase::PostCreate => "HOST POST-CREATE",
            Phase::PreRemove => "HOST PRE-REMOVE",
        }
    }
}

/// What the commands learn about the environment.
#[derive(Debug, Clone)]
pub struct Vars {
    pub files: Vec<PathBuf>,
    pub project_dir: PathBuf,
    pub sandbox: String,
    pub agent: String,
    /// The primary workspace; `None` for a mountless sandbox.
    pub workspace: Option<String>,
}

impl Vars {
    fn env(&self, phase: Phase) -> Vec<(&'static str, String)> {
        let files: Vec<String> = self.files.iter().map(|f| f.display().to_string()).collect();
        let mut env = vec![
            ("SBX_LIFECYCLE_PHASE", phase.name().to_string()),
            ("SBX_ENV_FILE", files.first().cloned().unwrap_or_default()),
            ("SBX_ENV_FILES", files.join(":")),
            ("SBX_ENV_DIR", self.project_dir.display().to_string()),
            ("SBX_SANDBOX_NAME", self.sandbox.clone()),
            ("SBX_AGENT", self.agent.clone()),
        ];
        if let Some(w) = &self.workspace {
            env.push(("SBX_WORKSPACE", w.clone()));
        }
        env
    }
}

/// Runs `commands` in order under the phase's heading, stopping at the first that fails or times
/// out. Prints nothing when there are none. `terminal` picks sbx's layout for a terminal.
pub fn run(
    mut out: impl Write,
    terminal: bool,
    phase: Phase,
    commands: &[HostCommand],
    vars: &Vars,
) -> Result<()> {
    if commands.is_empty() {
        return Ok(());
    }
    // sbx indents the whole block by two more on a terminal.
    let pad = if terminal { "  " } else { "" };
    writeln!(out, "\n{pad}{}", phase.heading())?;
    for (i, c) in commands.iter().enumerate() {
        let label = match &c.name {
            Some(name) => format!("{} ({name})", c.command),
            None => c.command.clone(),
        };
        let running = if terminal { " — running…" } else { "" };
        writeln!(out, "{pad}  ○ {label}{running}")?;
        out.flush()?;
        let started = Instant::now();
        let result = run_one(&mut out, terminal, phase, c, vars);
        let took = if terminal {
            String::new()
        } else {
            format!(" ({}s)", started.elapsed().as_secs())
        };
        let mark = if result.is_ok() { '✓' } else { '✗' };
        writeln!(out, "{pad}  {mark} {label}{took}")?;
        if let Err(e) = result {
            bail!("{}[{i}] ({}): {e:#}", phase.name(), c.command);
        }
    }
    Ok(())
}

/// One command through `sh -c`, its output written as it arrives. The error says how it failed.
fn run_one(
    out: &mut impl Write,
    terminal: bool,
    phase: Phase,
    c: &HostCommand,
    vars: &Vars,
) -> Result<()> {
    let timeout = c
        .timeout
        .as_deref()
        .map(humantime::parse_duration)
        .transpose()
        .context("timeout")?;
    let mut command = Command::new("sh");
    command
        // One stream, in the order the command wrote it.
        .args(["-c", &format!("exec 2>&1\n{}", c.command)])
        .envs(vars.env(phase))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        // Its own group, so a timeout ends what it started too.
        .process_group(0);
    if let Some(dir) = &c.workdir {
        command.current_dir(dir);
    }
    let mut child = command.spawn().context("running sh")?;
    let stdout = child.stdout.take().context("the command's output")?;
    let (lines, received) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).split(b'\n') {
            if line.is_err() || lines.send(line.unwrap_or_default()).is_err() {
                break;
            }
        }
    });
    let deadline = timeout.map(|t| Instant::now() + t);
    let indent = if terminal { "" } else { "      " };
    let timed_out = loop {
        let line = match deadline {
            None => received
                .recv()
                .map_err(|_| mpsc::RecvTimeoutError::Disconnected),
            Some(d) => received.recv_timeout(d.saturating_duration_since(Instant::now())),
        };
        match line {
            Ok(line) => {
                writeln!(out, "{indent}{}", String::from_utf8_lossy(&line))?;
                out.flush()?;
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break false,
            Err(mpsc::RecvTimeoutError::Timeout) => break true,
        }
    };
    if timed_out {
        // SAFETY: signals the group this child leads; nothing else is in it.
        unsafe { libc::kill(-(child.id() as libc::pid_t), libc::SIGKILL) };
        let _ = child.wait();
        bail!(
            "timed out after {}",
            c.timeout.as_deref().unwrap_or_default()
        );
    }
    let status = child.wait().context("waiting for the command")?;
    match status.code() {
        Some(0) => Ok(()),
        Some(code) => bail!("exit status {code}"),
        None => bail!("ended by a signal"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn command(command: &str) -> HostCommand {
        HostCommand {
            name: None,
            command: command.into(),
            workdir: None,
            timeout: None,
        }
    }

    fn vars(dir: &std::path::Path) -> Vars {
        Vars {
            files: vec![dir.join("sbxenv.yaml"), dir.join("local.yaml")],
            project_dir: dir.to_path_buf(),
            sandbox: "web".into(),
            agent: "claude".into(),
            workspace: Some(dir.display().to_string()),
        }
    }

    fn run_in(
        dir: &std::path::Path,
        terminal: bool,
        phase: Phase,
        commands: &[HostCommand],
    ) -> (String, Result<()>) {
        let mut out = Vec::new();
        let result = run(&mut out, terminal, phase, commands, &vars(dir));
        (String::from_utf8(out).unwrap(), result)
    }

    #[test]
    fn both_layouts_of_a_passing_named_command() {
        let d = tempfile::tempdir().unwrap();
        let named = HostCommand {
            name: Some("vars".into()),
            ..command("echo one; echo two >&2")
        };
        let (out, result) = run_in(
            d.path(),
            false,
            Phase::Initialize,
            std::slice::from_ref(&named),
        );
        result.unwrap();
        assert_eq!(
            out,
            "\nHOST INITIALIZE\n  ○ echo one; echo two >&2 (vars)\n      one\n      two\n  \
             ✓ echo one; echo two >&2 (vars) (0s)\n"
        );
        let (out, result) = run_in(d.path(), true, Phase::PostCreate, &[named]);
        result.unwrap();
        assert_eq!(
            out,
            "\n  HOST POST-CREATE\n    ○ echo one; echo two >&2 (vars) — running…\none\ntwo\n    \
             ✓ echo one; echo two >&2 (vars)\n"
        );
    }

    #[test]
    fn nothing_is_printed_without_commands() {
        let d = tempfile::tempdir().unwrap();
        let (out, result) = run_in(d.path(), false, Phase::PreRemove, &[]);
        result.unwrap();
        assert_eq!(out, "");
    }

    #[test]
    fn the_first_failure_stops_the_phase() {
        let d = tempfile::tempdir().unwrap();
        let commands = [
            command("echo ok"),
            command("echo boom >&2; exit 7"),
            command("touch never"),
        ];
        let (out, result) = run_in(d.path(), false, Phase::Initialize, &commands);
        assert_eq!(
            result.unwrap_err().to_string(),
            "initialize[1] (echo boom >&2; exit 7): exit status 7"
        );
        assert!(
            out.ends_with(
                "  ○ echo boom >&2; exit 7\n      boom\n  ✗ echo boom >&2; exit 7 (0s)\n"
            ),
            "{out}"
        );
        assert!(!d.path().join("never").exists());
    }

    #[test]
    fn a_timeout_ends_the_command_and_what_it_started() {
        let d = tempfile::tempdir().unwrap();
        let slow = HostCommand {
            timeout: Some("1s".into()),
            workdir: Some(d.path().display().to_string()),
            ..command("sleep 30 & echo $! > child.pid; wait")
        };
        let (out, result) = run_in(d.path(), false, Phase::Initialize, &[slow]);
        assert_eq!(
            result.unwrap_err().to_string(),
            "initialize[0] (sleep 30 & echo $! > child.pid; wait): timed out after 1s"
        );
        assert!(
            out.contains("  ✗ sleep 30 & echo $! > child.pid; wait (1s)\n"),
            "{out}"
        );
        let pid: libc::pid_t = std::fs::read_to_string(d.path().join("child.pid"))
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        // SAFETY: signal 0 only asks whether the process exists.
        let alive = || unsafe { libc::kill(pid, 0) } == 0;
        let deadline = Instant::now() + Duration::from_secs(5);
        while alive() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(!alive(), "the background child was left running");
    }

    #[test]
    fn commands_get_the_sbx_variables_and_their_workdir() {
        let d = tempfile::tempdir().unwrap();
        let sub = d.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        let show = HostCommand {
            workdir: Some(sub.display().to_string()),
            ..command("env | grep '^SBX_' | sort; pwd -P")
        };
        let (out, result) = run_in(
            d.path(),
            true,
            Phase::PreRemove,
            std::slice::from_ref(&show),
        );
        result.unwrap();
        let dir = d.path().display();
        let real = std::fs::canonicalize(&sub).unwrap();
        assert!(
            out.contains(&format!(
                "SBX_AGENT=claude\nSBX_ENV_DIR={dir}\nSBX_ENV_FILE={dir}/sbxenv.yaml\n\
                 SBX_ENV_FILES={dir}/sbxenv.yaml:{dir}/local.yaml\nSBX_LIFECYCLE_PHASE=preRemove\n\
                 SBX_SANDBOX_NAME=web\nSBX_WORKSPACE={dir}\n{}\n",
                real.display()
            )),
            "{out}"
        );
        // Mountless: no workspace variable.
        let mut out = Vec::new();
        let mountless = Vars {
            workspace: None,
            ..vars(d.path())
        };
        run(&mut out, true, Phase::Initialize, &[show], &mountless).unwrap();
        assert!(!String::from_utf8(out).unwrap().contains("SBX_WORKSPACE"));
    }
}
