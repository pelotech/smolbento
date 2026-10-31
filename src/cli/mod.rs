//! The sbx-compatible command line.

mod args;
mod bridge;
mod diagnose;
mod env;
mod exec;
mod fork;
mod inspect;
mod kit;
mod kit_doc;
pub(crate) mod lifecycle;
mod ls;
pub(crate) mod plan;
mod policy;
mod ports;
pub(crate) mod progress;
mod run;
pub(crate) mod secret;
mod settings;
mod skills;
mod template;
#[cfg(test)]
pub(crate) mod testutil;
mod upload_pack;

pub use args::*;

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::{BufRead, IsTerminal, Write};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Result, bail};
use clap::{CommandFactory, Parser};

use crate::config::{Paths, Settings};
use crate::smolvm::{ProcessRunner, Runner, Smolvm};

/// The oldest smolvm smolbento supports.
pub const MIN_SMOLVM: &str = "1.32.4";

/// A command or flag that smolbento doesn't support (yet, or ever). Exits with status 2.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct Unsupported(pub String);

pub fn exit_code(err: &anyhow::Error) -> u8 {
    if err.downcast_ref::<Unsupported>().is_some() {
        2
    } else {
        1
    }
}

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

pub fn main(args: impl IntoIterator<Item = OsString>) -> Result<i32> {
    let args: Vec<OsString> = args.into_iter().collect();
    let cli = Cli::parse_from(&args);
    let env: BTreeMap<String, String> = std::env::vars().collect();
    let paths = Paths::from_env(&env)?;
    let (settings, config_error) = Settings::load(&paths, env.clone());
    let store = crate::secrets::store::platform(&paths, &env);
    let runner = with_image_cache(
        ProcessRunner::new(settings.value("smolvm.path")?).debug(cli.debug),
        &settings,
        &env,
    );
    let mut ctx = Ctx {
        vm: Smolvm::new(runner),
        settings,
        paths,
        cwd: std::env::current_dir()?,
        env,
        now: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64,
        stdin_tty: std::io::stdin().is_terminal(),
        stdout_tty: std::io::stdout().is_terminal(),
        uid: crate::sandbox::host_uid(),
        gid: crate::sandbox::host_gid(),
        store,
        config_error,
        out: Out::Stdout,
        input: In::Stdin,
        args: args
            .iter()
            .skip(1)
            .map(|a| a.to_string_lossy().into_owned())
            .collect(),
    };
    dispatch(&mut ctx, cli)
}

/// smolvm's own `SMOLVM_IMAGE_SEED_MAX_BYTES` wins; else `smolvm.image-cache-size` sets it. A bad
/// size only warns, so `sbt settings` can still fix it.
fn with_image_cache(
    runner: ProcessRunner,
    settings: &Settings,
    env: &BTreeMap<String, String>,
) -> ProcessRunner {
    const SEED_MAX: &str = "SMOLVM_IMAGE_SEED_MAX_BYTES";
    if env.contains_key(SEED_MAX) {
        return runner;
    }
    match settings.image_cache_bytes() {
        Ok(bytes) => runner.env(SEED_MAX, bytes.to_string()),
        Err(e) => {
            eprintln!("warning: {e:#}; using smolvm's default");
            runner
        }
    }
}

pub fn dispatch<R: Runner>(ctx: &mut Ctx<R>, cli: Cli) -> Result<i32> {
    if cli.cloud {
        return Err(Unsupported("--cloud: Docker Cloud sandboxes are not supported".into()).into());
    }
    let cmd = cli.command.unwrap_or_else(|| Cmd::Ls(LsArgs::default()));
    match &cmd {
        Cmd::Run(a) => run::check_args(a)?,
        Cmd::Create(a) => a.opts.check_supported()?,
        _ => {}
    }
    if let Some(err) = &ctx.config_error {
        let path = ctx.paths.config_file();
        if !matches!(cmd, Cmd::Diagnose | Cmd::Settings(_)) {
            bail!("{}: {err}", path.display());
        }
        if matches!(cmd, Cmd::Settings(_)) {
            eprintln!("warning: ignoring {}: {err}", path.display());
        }
    }
    if cmd.needs_smolvm() {
        refuse_root(ctx.uid)?;
        check_smolvm(&ctx.vm)?;
    }
    if cmd.is_cloud_only() {
        return Err(Unsupported(format!(
            "`sbt {}` is a Docker Cloud feature and is not supported",
            cmd.name()
        ))
        .into());
    }
    match cmd {
        Cmd::Run(a) => run::run(ctx, &a),
        Cmd::Create(a) => lifecycle::create(ctx, &a),
        Cmd::Exec(a) => exec::exec(ctx, &a),
        Cmd::Cp(a) => exec::cp(ctx, &a),
        Cmd::Fork(a) => fork::run(ctx, &a),
        Cmd::Ls(a) => ls::run(ctx, &a),
        Cmd::Inspect(a) => inspect::run(ctx, &a),
        Cmd::Start { sandboxes } => lifecycle::start(ctx, &sandboxes),
        Cmd::Stop { sandboxes } => lifecycle::stop(ctx, &sandboxes),
        Cmd::Rm(a) => lifecycle::rm(ctx, &a),
        Cmd::Prune(a) => lifecycle::prune(ctx, &a),
        Cmd::Reset(a) => lifecycle::reset(ctx, &a),
        Cmd::Version => version(ctx),
        Cmd::Completion { shell } => {
            clap_complete::generate(shell, &mut Cli::command(), "sbt", &mut &ctx.out);
            Ok(0)
        }
        Cmd::Diagnose => diagnose::run(ctx),
        Cmd::Settings(s) => settings::run(ctx, s),
        Cmd::Policy(p) => policy::run(ctx, p),
        Cmd::Secret(s) => secret::run(ctx, s),
        Cmd::Skills(s) => skills::run(ctx, s),
        Cmd::Template(t) => template::run(ctx, t),
        Cmd::Ports(a) => ports::run(ctx, &a),
        Cmd::Kit(k) => kit::run(ctx, k),
        Cmd::Env(e) => env::run(ctx, e),
        Cmd::UploadPack { sandbox, .. } => upload_pack::run(ctx, &sandbox),
        Cmd::Bridge { sandbox } => bridge::run(ctx, &sandbox),
        Cmd::Daemon(_) => {
            writeln!(
                &ctx.out,
                "smolbento needs no daemon; smolvm manages each sandbox directly"
            )?;
            Ok(0)
        }
        other => Err(Unsupported(format!("`sbt {}` is not implemented yet", other.name())).into()),
    }
}

fn version<R: Runner>(ctx: &Ctx<R>) -> Result<i32> {
    let mut out = &ctx.out;
    writeln!(out, "smolbento version v{}", env!("CARGO_PKG_VERSION"))?;
    match ctx.vm.version() {
        Ok(v) => writeln!(out, "smolvm version v{v}")?,
        Err(e) => writeln!(out, "smolvm not available: {e:#}")?,
    }
    Ok(0)
}

/// The sandbox's `agent` takes the caller's uid (see `sandbox::identity_cmd`), so running as root
/// would make the agent root too.
fn refuse_root(uid: u32) -> Result<()> {
    if uid == 0 {
        bail!(
            "don't run sbt as root: the sandbox's agent user takes your uid; run it as your normal user"
        );
    }
    Ok(())
}

fn check_smolvm<R: Runner>(vm: &Smolvm<R>) -> Result<()> {
    let v = vm.version()?;
    if !version_at_least(&v, MIN_SMOLVM) {
        bail!("smolvm {v} is too old; smolbento needs {MIN_SMOLVM} or newer (brew upgrade smolvm)");
    }
    Ok(())
}

pub fn version_at_least(version: &str, min: &str) -> bool {
    let parse = |s: &str| -> Vec<u64> {
        s.trim_start_matches('v')
            .split('.')
            .map(|p| {
                p.chars()
                    .take_while(char::is_ascii_digit)
                    .collect::<String>()
                    .parse()
                    .unwrap_or(0)
            })
            .collect()
    };
    parse(version) >= parse(min)
}

/// Asks before destructive actions. sbx behaviour: fails without a terminal unless forced, and
/// declining is an error.
pub fn confirm<R: Runner>(ctx: &Ctx<R>, question: &str, force: bool) -> Result<()> {
    if force {
        return Ok(());
    }
    if !ctx.stdin_tty {
        bail!("{question} Refusing without a terminal; pass -f to confirm");
    }
    let mut out = &ctx.out;
    write!(out, "{question} [y/N] ")?;
    out.flush()?;
    if is_yes(&ctx.read_line()?) {
        Ok(())
    } else {
        bail!("aborted")
    }
}

/// sbx's prompt rule: unless `force`, ask on a terminal, else fail with the command's own
/// `refusal`.
pub fn confirm_or<R: Runner>(
    ctx: &Ctx<R>,
    question: &str,
    force: bool,
    refusal: &str,
) -> Result<()> {
    if !force && !ctx.stdin_tty {
        bail!("{refusal}");
    }
    confirm(ctx, question, force)
}

/// Whether a prompt's answer is yes.
pub fn is_yes(answer: &str) -> bool {
    matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

/// Left-aligned columns separated by three spaces, like sbx's tables.
pub fn table(rows: Vec<Vec<String>>) -> String {
    let cols = rows.iter().map(Vec::len).max().unwrap_or(0);
    let widths: Vec<usize> = (0..cols)
        .map(|c| {
            rows.iter()
                .filter_map(|r| r.get(c))
                .map(|s| s.chars().count())
                .max()
                .unwrap_or(0)
        })
        .collect();
    let mut out = String::new();
    for row in rows {
        let mut line = String::new();
        for (i, cell) in row.iter().enumerate() {
            line.push_str(cell);
            if i + 1 < row.len() {
                line.push_str(&" ".repeat(widths[i] - cell.chars().count() + 3));
            }
        }
        out.push_str(line.trim_end());
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::testutil::*;
    use super::*;

    #[test]
    fn versions_compare_numerically() {
        assert!(version_at_least("1.32.2", "1.32.2"));
        assert!(version_at_least("1.32.10", "1.32.2"));
        assert!(version_at_least("v2.0.0", "1.32.2"));
        assert!(!version_at_least("1.31.9", "1.32.2"));
    }

    #[test]
    fn old_smolvm_is_refused() {
        let mut t = test_env(&[]);
        t.runner().ok(&["--version"], "smolvm 1.30.0\n");
        let err = t.sbt(&["ls"]).unwrap_err();
        assert!(err.to_string().contains("too old"));
    }

    #[test]
    fn pending_and_cloud_commands_exit_2() {
        let mut t = test_env(&[]);
        let err = t.sbt(&["mcp", "ls"]).unwrap_err();
        assert_eq!(err.to_string(), "`sbt mcp` is not implemented yet");
        assert_eq!(exit_code(&err), 2);
        let err = t.sbt(&["kit", "pack", "./my-kit"]).unwrap_err();
        assert_eq!(err.to_string(), "`sbt kit pack` is not implemented yet");
        assert_eq!(exit_code(&err), 2);
        let err = t.sbt(&["move", "x", "--to", "cloud"]).unwrap_err();
        assert!(err.to_string().contains("Docker Cloud"));
        assert_eq!(exit_code(&err), 2);
        let Some(Cmd::Run(run)) =
            Cli::try_parse_from(["sbt", "run", "claude", "--static-mcp", "x"])
                .unwrap()
                .command
        else {
            panic!("expected run");
        };
        let err = run.opts.check_supported().unwrap_err();
        assert_eq!(err.to_string(), "--static-mcp is not implemented yet");
        assert_eq!(exit_code(&err), 2);
    }

    #[test]
    fn bare_sbt_hits_the_same_version_gate_as_ls() {
        for args in [&[][..], &["ls"][..]] {
            let mut t = test_env(&[]);
            t.runner().ok(&["--version"], "smolvm 1.30.0\n");
            let err = t.sbt(args).unwrap_err();
            assert!(err.to_string().contains("too old"), "{args:?}");
        }
    }

    #[test]
    fn root_is_refused() {
        assert!(
            refuse_root(0)
                .unwrap_err()
                .to_string()
                .contains("don't run sbt as root")
        );
        refuse_root(501).unwrap();
        let mut t = test_env(&[]);
        t.ctx.uid = 0;
        let err = t.sbt(&["ls"]).unwrap_err();
        assert!(err.to_string().contains("don't run sbt as root"), "{err}");
    }

    #[test]
    fn invalid_config_blocks_commands_but_not_diagnose_or_settings() {
        let mut t = test_env(&[]);
        break_config(&mut t);
        let file = t.ctx.paths.config_file().display().to_string();
        let err = t.sbt_err(&["ls"]);
        assert!(err.starts_with(&file), "{err}");
        assert!(err.contains("TOML parse error"), "{err}");
        assert!(t.runner().calls().is_empty());

        t.sbt(&["diagnose"]).unwrap();
        t.sbt(&["settings", "ls"]).unwrap();
        assert_eq!(t.sbt(&["settings", "unset", "docker.enabled"]).unwrap(), 0);
        let (_, err) = Settings::load(&t.ctx.paths, t.ctx.env.clone());
        assert_eq!(err, None, "unset rewrote a valid config.toml");
    }

    #[test]
    fn daemon_is_a_no_op() {
        let mut t = test_env(&[]);
        assert_eq!(t.sbt(&["daemon", "status"]).unwrap(), 0);
        assert!(t.runner().calls().is_empty());
    }

    #[test]
    fn table_aligns_columns() {
        let t = table(vec![
            vec!["A".into(), "BB".into()],
            vec!["CCC".into(), "D".into()],
        ]);
        assert_eq!(t, "A     BB\nCCC   D\n");
    }
}
