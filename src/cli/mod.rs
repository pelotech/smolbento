//! The sbx-compatible command line.

mod args;
mod bridge;
mod diagnose;
mod env;
mod env_spec;
mod exec;
mod fork;
mod inspect;
mod kit;
mod kit_doc;
pub(crate) mod lifecycle;
mod ls;
mod mcp;
mod policy;
mod ports;
pub(crate) mod progress;
pub(crate) mod request;
mod run;
pub(crate) mod secret;
mod serve;
mod settings;
mod setup;
mod skills;
mod ssh;
mod template;
mod upload_pack;

pub use crate::ctx::{Ctx, In, Out, Unsupported};
pub use args::*;

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::{IsTerminal, Write};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Result, bail};
use clap::{CommandFactory, Parser};

use crate::config::{Paths, Settings};
use crate::smolvm::{ProcessRunner, Runner, Smolvm};

pub fn exit_code(err: &anyhow::Error) -> u8 {
    if err.downcast_ref::<Unsupported>().is_some() {
        2
    } else {
        1
    }
}

/// The name completions are generated for: the one the binary was run as when it is one of ours
/// (`bento`, or `sbt` and `sbx` when linked or aliased), else `bento`.
fn program_name(argv0: Option<&OsString>) -> String {
    argv0
        .and_then(|a| std::path::Path::new(a).file_name()?.to_str())
        .filter(|n| ["sbt", "sbx", "bento"].contains(n))
        .unwrap_or("bento")
        .to_string()
}

/// A hint to print under an error: what to do about the smolvm error it came from, if anything.
pub fn hint(err: &anyhow::Error) -> Option<&'static str> {
    err.chain()
        .find_map(|e| e.downcast_ref::<crate::smolvm::SmolvmError>())
        .and_then(|e| e.hint())
}

pub fn main(args: impl IntoIterator<Item = OsString>) -> Result<i32> {
    let args: Vec<OsString> = args.into_iter().collect();
    let cli = Cli::parse_from(&args);
    let env: BTreeMap<String, String> = std::env::vars().collect();
    let paths = Paths::from_env(&env)?;
    let (settings, config_error) = Settings::load(&paths, env.clone());
    let store = crate::secrets::store::platform(&paths, &env);
    let smolvm = crate::smolvm::locate::locate(&settings, &env)?;
    let runner = with_image_cache(
        ProcessRunner::for_cmd(&smolvm).debug(cli.debug),
        &settings,
        &env,
    );
    let mut ctx = Ctx {
        vm: Smolvm::new(runner),
        settings,
        smolvm,
        services: crate::host_service::HostServices::detect(
            &paths,
            &env,
            args.first().map(OsString::as_os_str),
        ),
        paths,
        cwd: std::env::current_dir()?,
        env,
        now: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64,
        stdin_tty: std::io::stdin().is_terminal(),
        no_input: false,
        stdout_tty: std::io::stdout().is_terminal(),
        uid: crate::util::host_uid(),
        store,
        config_error,
        out: Out::Stdout,
        input: In::Stdin,
        args: args
            .iter()
            .skip(1)
            .map(|a| a.to_string_lossy().into_owned())
            .collect(),
        program: program_name(args.first()),
    };
    dispatch(&mut ctx, cli)
}

/// smolvm's own `SMOLVM_IMAGE_SEED_MAX_BYTES` wins; else `smolvm.image-cache-size` sets it. A bad
/// size only warns, so `bento settings` can still fix it.
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
            crate::warning!("{e:#}; using smolvm's default");
            runner
        }
    }
}

pub fn dispatch<R: Runner>(ctx: &mut Ctx<R>, cli: Cli) -> Result<i32> {
    if cli.cloud {
        return Err(Unsupported("--cloud: Docker Cloud sandboxes are not supported".into()).into());
    }
    ctx.no_input = cli.no_input;
    crate::kits::warn::show(crate::kits::warn::wanted(&ctx.settings, cli.debug));
    let cmd = cli.command.unwrap_or_else(|| Cmd::Ls(LsArgs::default()));
    match &cmd {
        Cmd::Run(a) => run::check_args(a)?,
        Cmd::Create(a) => a.opts.check_supported()?,
        _ => {}
    }
    if let Some(err) = &ctx.config_error {
        let path = ctx.paths.config_file();
        if !matches!(cmd, Cmd::Diagnose(_) | Cmd::Settings(_)) {
            bail!("{}: {err}", path.display());
        }
        if matches!(cmd, Cmd::Settings(_)) {
            crate::warning!("ignoring {}: {err}", path.display());
        }
    }
    if cmd.needs_smolvm() {
        refuse_root(ctx.uid)?;
        crate::smolvm::locate::check_home(&ctx.smolvm)?;
        crate::smolvm::locate::ensure_installed(&ctx.smolvm, &ctx.env)?;
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
        Cmd::Stop { sandboxes, output } => lifecycle::stop(ctx, &sandboxes, &output),
        Cmd::Rm(a) => lifecycle::rm(ctx, &a),
        Cmd::Prune(a) => lifecycle::prune(ctx, &a),
        Cmd::Reset(a) => lifecycle::reset(ctx, &a),
        Cmd::Version(o) => version(ctx, &o),
        Cmd::Completion { shell } => {
            clap_complete::generate(shell, &mut Cli::command(), &ctx.program, &mut &ctx.out);
            Ok(0)
        }
        Cmd::Diagnose(o) => diagnose::run(ctx, &o),
        Cmd::Settings(s) => settings::run(ctx, s),
        Cmd::Policy(p) => policy::run(ctx, p),
        Cmd::Secret(s) => secret::run(ctx, s),
        Cmd::Skills(s) => skills::run(ctx, s),
        Cmd::Mcp(m) => mcp::run(ctx, m),
        Cmd::Template(t) => template::run(ctx, t),
        Cmd::Ports(a) => ports::run(ctx, &a),
        Cmd::Kit(k) => kit::run(ctx, k),
        Cmd::Env(e) => env::run(ctx, e),
        Cmd::UploadPack { sandbox, .. } => upload_pack::run(ctx, &sandbox),
        Cmd::Bridge { sandbox } => bridge::run(ctx, &sandbox),
        Cmd::Ssh(s) => ssh::run(ctx, s),
        Cmd::Serve { kind, sandbox } => serve::run(ctx, &kind, &sandbox),
        Cmd::Smolvm(p) => ctx.vm.runner().interactive(&p.args),
        Cmd::Daemon(_) => {
            writeln!(
                &ctx.out,
                "smolbento needs no daemon; smolvm manages each sandbox directly"
            )?;
            Ok(0)
        }
        Cmd::Login(_) => cloud("login"),
        Cmd::Logout(_) => cloud("logout"),
        Cmd::Move(_) => cloud("move"),
        Cmd::Ttl(_) => cloud("ttl"),
        Cmd::Attach(_) => cloud("attach"),
        Cmd::Volume(_) => cloud("volume"),
        Cmd::Setup(s) => setup::run(ctx, s),
        Cmd::Tui(_) => pending("tui"),
    }
}

fn cloud(cmd: &str) -> Result<i32> {
    Err(Unsupported(format!(
        "`bento {cmd}` is a Docker Cloud feature and is not supported"
    ))
    .into())
}

fn pending(cmd: &str) -> Result<i32> {
    Err(Unsupported(format!("`bento {cmd}` is not implemented yet")).into())
}

fn version<R: Runner>(ctx: &Ctx<R>, output: &OutputArgs) -> Result<i32> {
    let mut out = &ctx.out;
    let smolvm = ctx.vm.version();
    // sbx's shape has `client` and `server`; smolbento has no server, and names its smolvm.
    let doc = serde_json::json!({
        "client": { "version": concat!("v", env!("CARGO_PKG_VERSION")) },
        "smolvm": { "version": smolvm.as_ref().ok().map(|v| format!("v{v}")) },
    });
    if let Some(text) = output.structured(&doc)? {
        write!(out, "{text}")?;
        return Ok(0);
    }
    writeln!(out, "smolbento version v{}", env!("CARGO_PKG_VERSION"))?;
    match smolvm {
        Ok(v) => writeln!(out, "smolvm version v{v}")?,
        Err(e) => writeln!(out, "smolvm not available: {e:#}")?,
    }
    Ok(0)
}

/// smolvm shows a workspace as owned by the sandbox's workload user only when it runs as a normal
/// user: as root, or on a directory owned by root, it maps nothing, so the agent couldn't write.
fn refuse_root(uid: u32) -> Result<()> {
    if uid == 0 {
        bail!(
            "don't run bento as root: smolvm doesn't map a workspace owned by root to the agent user, so \
the agent couldn't write it; run it as your normal user"
        );
    }
    Ok(())
}

/// Asks before destructive actions. sbx behaviour: fails without a terminal unless forced, and
/// declining is an error.
pub fn confirm<R: Runner>(ctx: &Ctx<R>, question: &str, force: bool) -> Result<()> {
    if force {
        return Ok(());
    }
    if !ctx.can_prompt() {
        bail!("{question} Refusing without a terminal; pass -f to confirm");
    }
    // A question, not command output: stderr, so stdout stays clean for `--json` and pipes.
    let mut err = std::io::stderr().lock();
    write!(err, "{question} [y/N] ")?;
    err.flush()?;
    drop(err);
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
    if !force && !ctx.can_prompt() {
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

    #[test]
    fn a_command_that_needs_smolvm_installs_it_first() {
        // Short, so its sockets fit macOS's limit (an explicit home is checked).
        let home = tempfile::tempdir_in("/tmp").unwrap();
        // Not the pinned release, so it fails the checksum: proof that `ls` went to download it.
        let (url, seen) = crate::testutil::http_server(b"not smolvm".to_vec());
        let home_s = home.path().display().to_string();
        let mut t = crate::testutil::test_env(&[
            ("SMOLBENTO_SMOLVM_HOME", &home_s),
            ("SMOLBENTO_SMOLVM_URL", &url),
        ]);
        t.use_managed_smolvm();
        let err = t.sbt_err(&["ls"]);
        assert!(err.contains("checksum"), "{err}");
        assert_eq!(seen.lock().unwrap().len(), 1);
    }

    #[test]
    fn settings_and_help_never_download() {
        let (url, seen) = crate::testutil::http_server(b"not smolvm".to_vec());
        let mut t = crate::testutil::test_env(&[("SMOLBENTO_SMOLVM_URL", &url)]);
        t.use_managed_smolvm();
        t.sbt(&["settings", "ls"]).unwrap();
        t.sbt(&["version"]).unwrap();
        assert!(seen.lock().unwrap().is_empty(), "nothing was downloaded");
    }
    use super::*;
    use crate::testutil::*;

    #[test]
    fn pending_and_cloud_commands_exit_2() {
        let mut t = test_env(&[]);
        let err = t.sbt(&["tui"]).unwrap_err();
        assert_eq!(err.to_string(), "`bento tui` is not implemented yet");
        assert_eq!(exit_code(&err), 2);
        let err = t.sbt(&["move", "x", "--to", "cloud"]).unwrap_err();
        assert!(err.to_string().contains("Docker Cloud"));
        assert_eq!(exit_code(&err), 2);
        let Some(Cmd::Run(run)) = Cli::try_parse_from(["sbt", "run", "claude", "--ttl", "1h"])
            .unwrap()
            .command
        else {
            panic!("expected run");
        };
        let err = run.opts.check_supported().unwrap_err();
        assert_eq!(err.to_string(), "--ttl is a Docker Cloud option");
        assert_eq!(exit_code(&err), 2);
    }

    #[test]
    fn bare_sbt_installs_smolvm_like_ls() {
        for args in [&[][..], &["ls"][..]] {
            let (url, seen) = http_server(b"not smolvm".to_vec());
            let mut t = test_env(&[("SMOLBENTO_SMOLVM_URL", &url)]);
            t.use_managed_smolvm();
            let err = t.sbt(args).unwrap_err();
            assert!(format!("{err:#}").contains("checksum"), "{args:?}: {err:#}");
            assert_eq!(seen.lock().unwrap().len(), 1, "{args:?}");
        }
    }

    #[test]
    fn version_as_json_names_both_versions() {
        let mut t = test_env(&[]);
        t.sbt(&["version", "--json"]).unwrap();
        let v: serde_json::Value = serde_json::from_str(&t.stdout()).unwrap();
        assert_eq!(
            v["client"]["version"],
            concat!("v", env!("CARGO_PKG_VERSION"))
        );
        assert_eq!(v["smolvm"]["version"], "v1.35.1");
        t.sbt(&["version"]).unwrap();
        assert!(t.stdout().starts_with("smolbento version v"));
    }

    #[test]
    fn root_is_refused() {
        assert!(
            refuse_root(0)
                .unwrap_err()
                .to_string()
                .contains("don't run bento as root")
        );
        refuse_root(501).unwrap();
        let mut t = test_env(&[]);
        t.ctx.uid = 0;
        let err = t.sbt(&["ls"]).unwrap_err();
        assert!(err.to_string().contains("don't run bento as root"), "{err}");
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
    fn smolvm_passes_args_and_exit_code_through() {
        let mut t = test_env(&[]);
        t.runner().interactive_exit(7);
        assert_eq!(t.sbt(&["smolvm", "machine", "ls", "--json"]).unwrap(), 7);
        assert_eq!(
            t.runner().interactive_calls(),
            [vec!["machine".to_string(), "ls".into(), "--json".into()]]
        );
    }

    #[test]
    fn smolvm_reserves_no_words() {
        let mut t = test_env(&[]);
        t.sbt(&["smolvm", "install"]).unwrap();
        t.sbt(&["smolvm", "--version"]).unwrap();
        assert_eq!(
            t.runner().interactive_calls(),
            [vec!["install".to_string()], vec!["--version".to_string()]]
        );
    }

    #[test]
    fn daemon_is_a_no_op() {
        let mut t = test_env(&[]);
        assert_eq!(t.sbt(&["daemon", "status"]).unwrap(), 0);
        assert!(t.runner().calls().is_empty());
    }

    #[test]
    fn a_hint_is_found_through_added_context() {
        use anyhow::Context;
        let err = crate::smolvm::SmolvmError {
            code: "KVM_UNAVAILABLE".into(),
            message: "no kvm".into(),
        };
        let wrapped = Err::<(), _>(err)
            .context("starting the sandbox")
            .unwrap_err();
        assert!(hint(&wrapped).unwrap().contains("kvm"));
        assert_eq!(hint(&anyhow::anyhow!("plain")), None);
    }

    #[test]
    fn completions_are_for_the_name_the_binary_was_run_as() {
        for (argv0, name) in [
            ("/usr/local/bin/sbx", "sbx"),
            ("bento", "bento"),
            ("sbt", "sbt"),
            ("/x/smolbento", "bento"),
        ] {
            assert_eq!(program_name(Some(&OsString::from(argv0))), name);
        }
        assert_eq!(program_name(None), "bento");
        let mut t = test_env(&[]);
        t.ctx.program = "sbx".into();
        t.sbt(&["completion", "zsh"]).unwrap();
        let out = t.stdout();
        assert!(out.starts_with("#compdef sbx\n"), "{}", &out[..40]);
        assert!(out.contains("_sbx"), "{}", &out[..200]);
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
