//! run: create the sandbox if needed, start it, attach to the agent, and stop it when the last
//! session ends (unless it was started with -d).

use std::io::Write;
use std::path::Path;

use anyhow::{Result, bail};

use super::lifecycle::create_reported;
use super::progress::Progress;
use super::request::{has_kit_flags, kit_target, settle_default_name};
use super::{Ctx, RunArgs, Unsupported};
use crate::agents;
use crate::bridge;
use crate::provision;
use crate::sandbox::{self, Sandbox, session};
use crate::smolvm::{ExecSpec, Runner, SmolvmError};
use crate::workspace::clone;

/// Flag checks that need no smolvm; `dispatch` runs them before its smolvm gate.
pub fn check_args(a: &RunArgs) -> Result<()> {
    a.opts.check_supported()?;
    if a.new {
        return Err(Unsupported("--new is a Docker Cloud option".into()).into());
    }
    if a.detach_keys.is_some() {
        return Err(Unsupported("--detach-keys is not supported".into()).into());
    }
    if a.rm && a.detach {
        bail!("--rm can't be combined with -d");
    }
    Ok(())
}

pub fn run<R: Runner>(ctx: &mut Ctx<R>, a: &RunArgs) -> Result<i32> {
    super::request::check_kit_args(&a.targets, &a.opts)?;
    let existing = match &a.opts.name {
        Some(n) => sandbox::find(&ctx.vm, n)?,
        None => None,
    };
    let warn_ignored = |sb: &Sandbox| {
        let warnings = [
            ignored_kits_warning(a, sb.name()),
            ignored_mount_warning(a, sb.name()),
            ignored_options_warning(a, sb.name()),
        ];
        for w in warnings.into_iter().flatten() {
            eprintln!("{w}");
        }
    };
    let (mut sb, created) = match existing {
        Some(sb) => {
            warn_ignored(&sb);
            (sb, false)
        }
        None => {
            if a.targets.is_empty() {
                bail!(
                    "specify an agent (e.g. `bento run claude`) or the --name of an existing sandbox"
                );
            }
            // The name first: attaching to an existing sandbox loads no kits.
            let (mut req, workload) = kit_target(ctx, &a.targets, &a.opts, true)?;
            let existing = match settle_default_name(ctx, &mut req, &a.opts, true)? {
                Some(sb) => Some(sb),
                None => sandbox::find(&ctx.vm, &req.name)?,
            };
            match existing {
                Some(sb) => {
                    warn_ignored(&sb);
                    (sb, false)
                }
                None => {
                    let p = Progress::for_ctx(ctx, a.no_progress);
                    let sb = create_reported(ctx, &p, &mut req, workload, &a.opts)?;
                    p.finish(&format!("Created sandbox {}", sb.name()));
                    (sb, true)
                }
            }
        }
    };
    if !a.opts.deny_network.is_empty() && !created {
        crate::warning!(
            "--deny-network only adds rules when a sandbox is created; {} already exists \
             (use `bento policy deny network --sandbox {}`)",
            sb.name(),
            sb.name()
        );
    }
    // What to launch, with the arguments given: an environment's `entrypoint`, else the agent's
    // command (`sbx.command`; a sandbox without one is from before agents were kits). Looked up before the start, so a sandbox
    // with no known agent isn't started and left running.
    sb.check_current()?;
    let command: Option<Vec<String>> = match (&a.entrypoint, &sb.meta.command, a.detach) {
        (_, _, true) | (None, None, false) => None,
        (Some(e), _, false) => Some([e.as_slice(), a.agent_args.as_slice()].concat()),
        (None, Some(c), false) => Some(command_with_args(c, &a.agent_args)),
    };
    // A closed terminal must not end this process once the sandbox may be running: it has the
    // cleanup below to do. The agent still ends with the terminal (`interactive` gives it the
    // default handling back).
    let _hangup = crate::smolvm::IgnoreSignals::new(&[libc::SIGHUP]);
    provision::ensure_running(ctx, &mut sb)?;

    let sessions = ctx.paths.sessions();
    let Some(command) = command else {
        session::mark_detached(&sessions, sb.name())?;
        writeln!(&ctx.out, "{}", sb.name())?;
        return Ok(0);
    };

    // Whatever `attach` returns, the sandbox is cleaned up below: nothing after the start may
    // return early and leave it running, or skip `--rm`.
    // Closing the terminal ends the agent, not this process, which has the cleanup still to do.
    let result = attach(ctx, a, &sb, command);

    // Fetch before `--rm` deletes the sandbox, and while it still runs for `_upload-pack`.
    if fetch_on_exit(ctx, &sb)
        && let Some(repo) = &sb.meta.clone_repo
        && let Err(e) = clone::fetch(Path::new(repo), sb.name())
    {
        crate::warning!("fetching the agent's commits: {e:#}");
    }

    // The agent's exit code is the result; failing to clean up after it only warrants a warning.
    if session::live_sessions(&sessions, sb.name()) > 0 {
        if a.rm {
            crate::warning!(
                "sandbox {} is in use by another session; not removed",
                sb.name()
            );
        }
    } else if a.rm {
        if let Err(e) = super::lifecycle::delete_keeping_remote(ctx, &sb, true) {
            crate::warning!("removing sandbox {}: {e:#}", sb.name());
        }
    } else if !sb.meta.long_running
        && session::idle(&sessions, sb.name())
        && let Err(e) = ctx.vm.stop(&sb.machine)
    {
        crate::warning!("stopping sandbox {}: {e:#}", sb.name());
    }
    result
}

/// Where the session starts: `--workdir` (absolute, or relative to the workspace), else the
/// workspace.
fn session_dir(sb: &Sandbox, workdir: Option<&str>) -> String {
    match workdir {
        Some(w) if w.starts_with('/') => w.to_string(),
        Some(w) => format!("{}/{w}", sb.workdir().trim_end_matches('/')),
        None => sb.workdir(),
    }
}

/// Attaches the user to the agent and returns its exit code.
fn attach<R: Runner>(ctx: &Ctx<R>, a: &RunArgs, sb: &Sandbox, command: Vec<String>) -> Result<i32> {
    let sessions = ctx.paths.sessions();
    let mut spec = ExecSpec {
        name: sb.machine.clone(),
        user: Some(sb.meta.session_user().into()),
        workdir: Some(session_dir(sb, a.workdir.as_deref())),
        interactive: true,
        tty: ctx.stdin_tty,
        cmd: command,
        ..Default::default()
    };
    spec.env.extend(a.session_env.iter().cloned());
    sandbox::env::session_env(&ctx.env, spec.tty, sb.meta.bridge, &mut spec.env);
    // A v3 workload runs as its image user, through bash so the image's BASH_ENV is sourced.
    let image_user = sb.meta.user.is_some();
    if image_user {
        spec.cmd = [BASH, "-c", "exec -- \"$@\"", "bash"]
            .into_iter()
            .map(String::from)
            .chain(spec.cmd)
            .collect();
    }
    let _session = session::Session::register(&sessions, sb.name())?;
    // Opens URLs and copies text on the host for the agent while the user is attached.
    let _bridge = bridge::attach(&ctx.env, &ctx.settings, &ctx.smolvm, sb);
    // A runtime `ssh-agent@1` grant: the filtered host agent, while the user is attached.
    let _agent = crate::ssh_agent::filter::attach(&ctx.env, &ctx.paths, sb);
    match image_user.then(|| has_bash(ctx, sb)) {
        Some(Err(e)) => Err(e),
        Some(Ok(false)) => {
            // sbx's error for such an image, and the code its agent exits with.
            eprintln!("executable file '{BASH}' not found");
            Ok(127)
        }
        _ => ctx.vm.exec(&spec),
    }
}

const BASH: &str = "/bin/bash";

/// Whether the guest can run `/bin/bash`, which a v3 workload's agent is launched through.
/// Runs bash itself, so the image needs no `/bin/sh` for the check. An error smolvm reports (the
/// machine gone, say) is that error, not a missing bash.
fn has_bash<R: Runner>(ctx: &Ctx<R>, sb: &Sandbox) -> Result<bool> {
    let out = ctx.vm.exec_output(&ExecSpec {
        name: sb.machine.clone(),
        cmd: vec![BASH.into(), "-c".into(), ":".into()],
        ..Default::default()
    })?;
    if out.code == 0 {
        return Ok(true);
    }
    match SmolvmError::from_json(&out) {
        Some(e) => Err(e.into()),
        None => Ok(false),
    }
}

/// sbx's rule for `-- ARGS`: flags are appended to the agent's command; a bare word replaces its
/// flags.
fn command_with_args<S: AsRef<str>>(command: &[S], args: &[String]) -> Vec<String> {
    let mut cmd: Vec<String> = command.iter().map(|s| s.as_ref().to_string()).collect();
    match args.first() {
        None => {}
        Some(first) if first.starts_with('-') => cmd.extend(args.iter().cloned()),
        Some(_) => {
            cmd.truncate(1);
            cmd.extend(args.iter().cloned());
        }
    }
    cmd
}

/// The warning for kits given to `run` of a sandbox that already exists: kit flags, or a workload
/// kit as the target.
fn ignored_kits_warning(a: &RunArgs, name: &str) -> Option<String> {
    let kit_target = a.targets.first().is_some_and(|t| !agents::is_agent(t));
    (has_kit_flags(&a.opts) || kit_target).then(|| {
        format!("warning: kits only apply when a sandbox is created; {name} already exists")
    })
}

/// The warning for the other create options given to `run` of a sandbox that already exists:
/// they would be silently dropped otherwise.
fn ignored_options_warning(a: &RunArgs, name: &str) -> Option<String> {
    // Every field is named, with no `..`: a new create option fails to compile here until someone
    // decides whether `run` on an existing sandbox warns about it.
    let super::SandboxOpts {
        // Selects the sandbox.
        name: _,
        cpus,
        memory,
        env,
        env_file,
        publish,
        template,
        pull,
        clone,
        skills,
        static_mcp,
        // Kits, --mount and --deny-network have their own warnings.
        kit: _,
        kit_arg: _,
        kit_args_file: _,
        kit_pins: _,
        // Set only by an environment file, which `env run` applies at create.
        no_fuse: _,
        read_only_files: _,
        disk: _,
        mount: _,
        deny_network: _,
        // Docker Cloud options: refused before any sandbox is looked up.
        allow_network: _,
        image_ref: _,
        platform: _,
        ttl: _,
        on_timeout: _,
        volume: _,
        // Not implemented: refused the same way.
        profile: _,
    } = &a.opts;
    let given: Vec<&str> = [
        (cpus.is_some(), "--cpus"),
        (memory.is_some(), "--memory"),
        (!env.is_empty(), "--env"),
        (!env_file.is_empty(), "--env-file"),
        (!publish.is_empty(), "--publish"),
        (template.is_some(), "--template"),
        (pull.is_some(), "--pull"),
        (*clone, "--clone"),
        (skills.is_some(), "--skills"),
        (static_mcp.is_some(), "--static-mcp"),
    ]
    .into_iter()
    .filter_map(|(on, flag)| on.then_some(flag))
    .collect();
    let verb = match given.len() {
        0 => return None,
        1 => "applies",
        _ => "apply",
    };
    Some(format!(
        "warning: {} only {verb} when a sandbox is created; {name} already exists",
        given.join(", ")
    ))
}

/// The warning for `--mount` given to `run` of a sandbox that already exists.
fn ignored_mount_warning(a: &RunArgs, name: &str) -> Option<String> {
    (!a.opts.mount.is_empty()).then(|| {
        format!("warning: --mount only applies when a sandbox is created; {name} already exists")
    })
}

/// A bad setting value only skips the fetch: the stop or `--rm` and the agent's status still apply.
fn fetch_on_exit<R: Runner>(ctx: &Ctx<R>, sb: &Sandbox) -> bool {
    sb.meta.clone_repo.is_some()
        && ctx
            .settings
            .bool("clone.fetch-on-exit")
            .unwrap_or_else(|e| {
                crate::warning!("not fetching the agent's commits: {e:#}");
                false
            })
}

#[cfg(test)]
#[path = "run_tests.rs"]
mod tests;
