//! The private dockerd a `dockerd@1` grant gives a sandbox (`sbx.docker`).

use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};

use super::Sandbox;
use crate::kits::guest::startup_script;
use crate::kits::model::{Hook, HookCmd};
use crate::smolvm::{ExecSpec, Runner, Smolvm};
use crate::util::sh_quote;

/// How long the engine has to answer before a start fails.
pub const ENGINE_BOUND: Duration = Duration::from_secs(60);

/// The gap between probes; tests don't wait.
const ENGINE_POLL: Duration = if cfg!(test) {
    Duration::ZERO
} else {
    Duration::from_secs(1)
};

/// No flags: the image's `daemon.json` configures it.
const LAUNCH: &str = "pgrep -x dockerd >/dev/null || { rm -f /var/run/docker.pid; exec dockerd >/var/log/dockerd.log 2>&1; }";

/// The image may have no curl; the docker CLI comes with dockerd.
const PROBE: &str = "curl -sf --unix-socket /var/run/docker.sock http://localhost/_ping >/dev/null \
                     2>&1 || docker version >/dev/null 2>&1";

/// How long one probe may take.
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// Starts the engine unless it runs, waits up to `ENGINE_BOUND` for it to answer (probing every
/// `poll`), then hands its socket to `user`'s group unless `user` is root.
pub fn start_engine<R: Runner>(
    vm: &Smolvm<R>,
    machine: &str,
    user: Option<&str>,
    poll: Duration,
) -> Result<()> {
    let hook = Hook {
        command: HookCmd::Shell(LAUNCH.into()),
        user: Some("0".into()),
        env: vec![],
        background: true,
        clean_env: false,
    };
    vm.exec_captured(&ExecSpec::sh(
        machine,
        "root",
        startup_script("dockerd", &[&hook]),
    ))
    .context("starting dockerd")?;
    let deadline = Instant::now() + ENGINE_BOUND;
    let mut answered = false;
    // At most one probe a second of the bound, so a zero `poll` (tests) ends too.
    for i in 0..ENGINE_BOUND.as_secs() {
        if i > 0 {
            if Instant::now() >= deadline {
                break;
            }
            std::thread::sleep(poll);
        }
        // Bounded by smolvm: a hung engine can block curl or `docker version` past the bound.
        let probe = ExecSpec {
            timeout: Some(PROBE_TIMEOUT),
            ..ExecSpec::sh(machine, "root", PROBE)
        };
        if vm.exec_captured(&probe).is_ok() {
            answered = true;
            break;
        }
    }
    if !answered {
        bail!(
            "dockerd didn't answer within {}s; see /var/log/dockerd.log in the sandbox",
            ENGINE_BOUND.as_secs()
        );
    }
    if let Some(u) = user.filter(|u| !matches!(*u, "root" | "0")) {
        let q = sh_quote(u);
        let cmd = format!(
            "chgrp \"$(id -gn {q})\" /var/run/docker.sock && chmod g+rw /var/run/docker.sock"
        );
        vm.exec_captured(&ExecSpec::sh(machine, "root", cmd))
            .with_context(|| format!("giving {u} the docker socket"))?;
    }
    Ok(())
}

/// `start_engine` for a sandbox whose `dockerd@1` grant starts it on its own.
pub(super) fn start_granted<R: Runner>(vm: &Smolvm<R>, sb: &Sandbox) -> Result<()> {
    if !sb.meta.docker || sb.meta.docker_manual {
        return Ok(());
    }
    let user = super::create::workload_user(&sb.meta);
    start_engine(vm, &sb.machine, Some(&user), ENGINE_POLL)
}
