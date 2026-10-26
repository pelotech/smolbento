//! The sbx-compatible command line.

mod args;
mod diagnose;
mod exec;
mod lifecycle;
mod ls;
mod plan;
mod run;
mod settings;
#[cfg(test)]
mod testutil;

pub use args::*;

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Result, bail};
use clap::{CommandFactory, Parser};

use crate::config::{Paths, Settings};
use crate::smolvm::{ProcessRunner, Runner, Smolvm};

/// The oldest smolvm smolbento supports.
pub const MIN_SMOLVM: &str = "1.32.2";

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
    /// The host user's uid; the sandbox's `agent` user takes it.
    pub uid: u32,
    /// Where stored secret values live (OS keychain, or the 0600 file).
    pub store: Box<dyn crate::secrets::store::SecretStore>,
    /// Why config.toml couldn't be loaded; only `diagnose` and `settings` run despite it.
    pub config_error: Option<String>,
}

pub fn main(args: impl IntoIterator<Item = OsString>) -> Result<i32> {
    let cli = Cli::parse_from(args);
    let env: BTreeMap<String, String> = std::env::vars().collect();
    let paths = Paths::from_env(&env)?;
    let (settings, config_error) = Settings::load(&paths, env.clone());
    let store = crate::secrets::store::platform(&paths, &env);
    let runner = ProcessRunner::new(settings.value("smolvm.path")?).debug(cli.debug);
    let mut ctx = Ctx {
        vm: Smolvm::new(runner),
        settings,
        paths,
        cwd: std::env::current_dir()?,
        env,
        now: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64,
        stdin_tty: std::io::stdin().is_terminal(),
        uid: crate::sandbox::host_uid(),
        store,
        config_error,
    };
    dispatch(&mut ctx, cli)
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
        Cmd::Ls(a) => ls::run(ctx, &a),
        Cmd::Start { sandboxes } => lifecycle::start(ctx, &sandboxes),
        Cmd::Stop { sandboxes } => lifecycle::stop(ctx, &sandboxes),
        Cmd::Rm(a) => lifecycle::rm(ctx, &a),
        Cmd::Prune(a) => lifecycle::prune(ctx, &a),
        Cmd::Reset(a) => lifecycle::reset(ctx, &a),
        Cmd::Version => version(ctx),
        Cmd::Completion { shell } => {
            clap_complete::generate(shell, &mut Cli::command(), "sbt", &mut std::io::stdout());
            Ok(0)
        }
        Cmd::Diagnose => diagnose::run(ctx),
        Cmd::Settings(s) => settings::run(ctx, s),
        Cmd::Daemon(_) => {
            println!("smolbento needs no daemon; smolvm manages each sandbox directly");
            Ok(0)
        }
        other => Err(Unsupported(format!("`sbt {}` is not implemented yet", other.name())).into()),
    }
}

fn version<R: Runner>(ctx: &Ctx<R>) -> Result<i32> {
    println!("smolbento version v{}", env!("CARGO_PKG_VERSION"));
    match ctx.vm.version() {
        Ok(v) => println!("smolvm version v{v}"),
        Err(e) => println!("smolvm not available: {e:#}"),
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
    print!("{question} [y/N] ");
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    if matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
        Ok(())
    } else {
        bail!("aborted")
    }
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
        t.ctx.vm.runner().ok(&["--version"], "smolvm 1.30.0\n");
        let err = sbt(&mut t.ctx, &["ls"]).unwrap_err();
        assert!(err.to_string().contains("too old"));
    }

    #[test]
    fn pending_and_cloud_commands_exit_2() {
        let mut t = test_env(&[]);
        let err = sbt(&mut t.ctx, &["policy", "init", "balanced"]).unwrap_err();
        assert_eq!(err.to_string(), "`sbt policy` is not implemented yet");
        assert_eq!(exit_code(&err), 2);
        let err = sbt(&mut t.ctx, &["move", "x", "--to", "cloud"]).unwrap_err();
        assert!(err.to_string().contains("Docker Cloud"));
        assert_eq!(exit_code(&err), 2);
        let Some(Cmd::Run(run)) = Cli::try_parse_from(["sbt", "run", "claude", "--clone"])
            .unwrap()
            .command
        else {
            panic!("expected run");
        };
        let err = run.opts.check_supported().unwrap_err();
        assert_eq!(err.to_string(), "--clone is not implemented yet");
        assert_eq!(exit_code(&err), 2);
    }

    #[test]
    fn bare_sbt_hits_the_same_version_gate_as_ls() {
        for args in [&[][..], &["ls"][..]] {
            let mut t = test_env(&[]);
            t.ctx.vm.runner().ok(&["--version"], "smolvm 1.30.0\n");
            let err = sbt(&mut t.ctx, args).unwrap_err();
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
        let err = sbt(&mut t.ctx, &["ls"]).unwrap_err();
        assert!(err.to_string().contains("don't run sbt as root"), "{err}");
    }

    #[test]
    fn invalid_config_blocks_commands_but_not_diagnose_or_settings() {
        let mut t = test_env(&[]);
        break_config(&mut t);
        let file = t.ctx.paths.config_file().display().to_string();
        let err = sbt(&mut t.ctx, &["ls"]).unwrap_err().to_string();
        assert!(err.starts_with(&file), "{err}");
        assert!(err.contains("TOML parse error"), "{err}");
        assert!(t.ctx.vm.runner().calls().is_empty());

        sbt(&mut t.ctx, &["diagnose"]).unwrap();
        sbt(&mut t.ctx, &["settings", "ls"]).unwrap();
        assert_eq!(
            sbt(&mut t.ctx, &["settings", "unset", "docker.enabled"]).unwrap(),
            0
        );
        let (_, err) = Settings::load(&t.ctx.paths, t.ctx.env.clone());
        assert_eq!(err, None, "unset rewrote a valid config.toml");
    }

    #[test]
    fn daemon_is_a_no_op() {
        let mut t = test_env(&[]);
        assert_eq!(sbt(&mut t.ctx, &["daemon", "status"]).unwrap(), 0);
        assert!(t.ctx.vm.runner().calls().is_empty());
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
