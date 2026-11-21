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

/// Starts the engine unless it runs, waits up to `ENGINE_BOUND` for it to answer, then hands its
/// socket to `user`'s group unless `user` is root.
pub fn start_engine<R: Runner>(vm: &Smolvm<R>, machine: &str, user: Option<&str>) -> Result<()> {
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
    if !answers(vm, machine) {
        bail!(
            "dockerd didn't answer within {}s; see /var/log/dockerd.log in the sandbox",
            ENGINE_BOUND.as_secs()
        );
    }
    // An image user may be `user:group` (`somebody:1001`, `0:0`).
    let Some(u) = user else { return Ok(()) };
    let (name, group) = u.split_once(':').map_or((u, None), |(n, g)| (n, Some(g)));
    if matches!(name, "root" | "0") {
        return Ok(());
    }
    let group = match group {
        Some(g) => sh_quote(g),
        None => format!("\"$(id -gn -- {})\"", sh_quote(name)),
    };
    let cmd = format!("chgrp {group} /var/run/docker.sock && chmod g+rw /var/run/docker.sock");
    vm.exec_captured(&ExecSpec::sh(machine, "root", cmd))
        .with_context(|| format!("giving {u} the docker socket"))?;
    Ok(())
}

/// Probes every `ENGINE_POLL` until the engine answers or `ENGINE_BOUND` passes.
fn answers<R: Runner>(vm: &Smolvm<R>, machine: &str) -> bool {
    let deadline = Instant::now() + ENGINE_BOUND;
    // At most one probe a second of the bound, so a zero `ENGINE_POLL` (tests) ends too.
    for i in 0..ENGINE_BOUND.as_secs() {
        if i > 0 {
            if Instant::now() >= deadline {
                break;
            }
            std::thread::sleep(ENGINE_POLL);
        }
        // Bounded by smolvm: a hung engine can block curl or `docker version` past the bound.
        let probe = ExecSpec {
            timeout: Some(PROBE_TIMEOUT),
            ..ExecSpec::sh(machine, "root", PROBE)
        };
        if vm.exec_captured(&probe).is_ok() {
            return true;
        }
    }
    false
}

/// `start_engine` for a sandbox whose `dockerd@1` grant starts it on its own.
pub(super) fn start_granted<R: Runner>(vm: &Smolvm<R>, sb: &Sandbox) -> Result<()> {
    if !sb.meta.docker || sb.meta.docker_manual {
        return Ok(());
    }
    let user = super::create::workload_user(&sb.meta);
    start_engine(vm, &sb.machine, Some(&user))
}
