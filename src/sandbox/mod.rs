//! Sandboxes: smolvm machines that smolbento created, identified by their `sbx.*` labels.

mod clone_step;
pub mod create;
pub mod env;
mod identity;
mod kit_steps;
pub mod labels;
pub mod name;
pub mod options;
pub mod session;

use std::path::Path;

use anyhow::{Context, Result, anyhow};

use crate::bridge;
use crate::kits::apply::KitSteps;
use crate::smolvm::{
    ExecSpec, Machine, MachineState, NetworkSpec, PublishedPort, PullProgress, Runner, Smolvm,
};
use crate::workspace::MOUNTLESS_WORKDIR;

pub use clone_step::*;
pub use create::CreateRequest;
pub use identity::*;
pub use kit_steps::*;
pub use labels::Meta;

/// Started detached as root after each start of a pre-4a docker sandbox (`sbx.docker=true`, no
/// `sbx.kits`). Newer ones get dockerd from the docker kit's startup hook (`kits/docker`).
pub const DOCKER_START: &str = "pgrep -x dockerd >/dev/null || { rm -f /var/run/docker.pid; exec dockerd >/var/log/dockerd.log 2>&1; }";

/// What a create or start is doing, for the caller's progress output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event<'a> {
    /// `machine start` begins; smolvm pulls the image first when it's missing.
    Boot,
    /// smolvm's image pull progress.
    Pull(PullProgress),
    /// The machine is up; the guest setup begins.
    Setup,
    /// A kit's part of the first start begins: its install hooks, and for the last kit the
    /// rest of the first start.
    Install(&'a str),
}

/// What a start needs beyond the machine: its network, the secret values for its credentials
/// (only ever passed as env to `machine start`), and the uid and gid for the agent user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartPlan {
    pub network: NetworkSpec,
    pub env: Vec<(String, String)>,
    /// Credential env vars without a value, removed from the inherited environment so the host
    /// shell's same-named variables can't stand in for them.
    pub remove: Vec<String>,
    pub uid: u32,
    pub gid: u32,
    /// Set for a clone sandbox; the clone itself is skipped once it exists, the remote copy is not.
    pub clone: Option<CloneStep>,
    /// Start with `--branchable` so `sbt fork` can copy it; only for forkable sandboxes.
    pub branchable: bool,
    /// Kit steps for the first start; only `create` runs them.
    pub kit: Option<KitFirstStart>,
}

/// A kit sandbox's first start, after the usual setup (spec "Data flow" 7).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KitFirstStart {
    pub steps: KitSteps,
    /// Install-only credential env vars (`sbx.credential-install`): set for the install hooks,
    /// then the machine restarts without them.
    pub restart_without: Vec<String>,
    /// Every policy rule id the kits added, removed again by `provision::create` when the create
    /// fails.
    pub rule_ids: Vec<String>,
    /// Where an install-phase `ssh-agent@1` grant (`sbx.ssh-agent`) finds the host agent while
    /// the install hooks run.
    pub agent_backing: Option<crate::ssh_agent::filter::Backing>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Sandbox {
    pub meta: Meta,
    pub machine: String,
    pub state: MachineState,
    /// Filled from `machine status` for running sandboxes.
    pub ports: Vec<PublishedPort>,
    /// The machine's image, when smolvm reports one.
    pub image: Option<String>,
}

impl Sandbox {
    pub fn from_machine(m: &Machine) -> Option<Sandbox> {
        Some(Sandbox {
            meta: Meta::from_labels(&m.labels)?,
            machine: m.name.clone(),
            state: m.state,
            ports: m.published_ports.clone(),
            image: m.image.clone(),
        })
    }

    pub fn name(&self) -> &str {
        &self.meta.name
    }

    pub fn is_running(&self) -> bool {
        self.state == MachineState::Running
    }

    /// The primary workspace, or sbx's mountless directory.
    pub fn workdir(&self) -> String {
        self.meta
            .workspace
            .clone()
            .unwrap_or_else(|| MOUNTLESS_WORKDIR.into())
    }
}

pub fn find<R: Runner>(vm: &Smolvm<R>, name: &str) -> Result<Option<Sandbox>> {
    Ok(vm
        .status(&name::machine_name(name))?
        .as_ref()
        .and_then(Sandbox::from_machine))
}

pub fn get<R: Runner>(vm: &Smolvm<R>, name: &str) -> Result<Sandbox> {
    find(vm, name)?.ok_or_else(|| not_found(name))
}

/// `name` among already listed sandboxes (from `list`), with `get`'s error.
pub fn pick<'a>(all: &'a [Sandbox], name: &str) -> Result<&'a Sandbox> {
    all.iter()
        .find(|sb| sb.name() == name)
        .ok_or_else(|| not_found(name))
}

fn not_found(name: &str) -> anyhow::Error {
    anyhow::anyhow!("sandbox '{name}' not found (see `sbt ls`)")
}

/// All sandboxes, sorted by name; running ones include their published ports.
pub fn list<R: Runner>(vm: &Smolvm<R>) -> Result<Vec<Sandbox>> {
    let mut out = Vec::new();
    for m in vm.list()? {
        let Some(mut sb) = Sandbox::from_machine(&m) else {
            continue;
        };
        if sb.is_running()
            && let Some(full) = vm.status(&m.name)?
        {
            sb.ports = full.published_ports;
        }
        out.push(sb);
    }
    out.sort_by(|a, b| a.meta.name.cmp(&b.meta.name));
    Ok(out)
}

/// Applies the network to the stopped machine, starts it with the secret env, then its setup steps.
/// A failed setup step stops the machine again: left running half set up, later commands would
/// skip `start` and never retry it.
pub fn start<R: Runner>(vm: &Smolvm<R>, sb: &Sandbox, plan: &StartPlan) -> Result<()> {
    start_with(vm, sb, plan, &mut |_| {})
}

/// `start`, telling `on` what it's doing.
pub fn start_with<R: Runner>(
    vm: &Smolvm<R>,
    sb: &Sandbox,
    plan: &StartPlan,
    on: &mut dyn FnMut(Event),
) -> Result<()> {
    start_checked(vm, sb, plan, on, &bridge::ensure_private_dir)
}

/// `start_with`, with `private` deciding whether the bridge's socket directory is safe.
fn start_checked<R: Runner>(
    vm: &Smolvm<R>,
    sb: &Sandbox,
    plan: &StartPlan,
    on: &mut dyn FnMut(Event),
    private: &dyn Fn(&Path) -> bool,
) -> Result<()> {
    vm.update_network(&sb.machine, &plan.network)
        .context("applying the network policy")?;
    on(Event::Boot);
    vm.start_with_progress(
        &sb.machine,
        plan.branchable,
        &plan.env,
        &plan.remove,
        &mut |p| on(Event::Pull(p)),
    )?;
    on(Event::Setup);
    if let Err(e) = setup(vm, sb, plan, private) {
        if let Err(stop) = vm.stop(&sb.machine) {
            eprintln!(
                "warning: stopping {} after the failed start: {stop:#}",
                sb.name()
            );
        }
        return Err(e);
    }
    Ok(())
}

/// What follows `machine start`: a v3 workload's image user's uid, then the agent user's, dockerd
/// for a pre-4a sandbox, the clone, then the kits' startup hooks (a no-op without kits; deferred
/// during a kit first start). A failed blocking startup hook fails the start.
fn setup<R: Runner>(
    vm: &Smolvm<R>,
    sb: &Sandbox,
    plan: &StartPlan,
    private: &dyn Fn(&Path) -> bool,
) -> Result<()> {
    if let Some(user) = &sb.meta.user
        && let Some(w) = map_image_user(vm, sb, user, plan.uid, plan.gid)?
    {
        eprintln!("{w}");
    }
    vm.exec_captured(&ExecSpec::sh(
        &sb.machine,
        "root",
        identity_cmd(plan.uid, plan.gid),
    ))
    .context("matching the sandbox's agent user to your host uid")?;
    // Not fatal: an image without a writable /etc/hosts still works, just without the name.
    if let Err(e) = vm.exec_captured(&ExecSpec::sh(&sb.machine, "root", hosts_cmd())) {
        eprintln!(
            "warning: {}: couldn't add host.docker.internal to /etc/hosts: {e:#}",
            sb.name()
        );
    }
    // Not fatal: an image without `mount` keeps the files writable, as they were before.
    if let Some(cmd) = lockdown_cmd(sb.meta.no_fuse, &sb.meta.read_only_files)
        && let Err(e) = vm.exec_captured(&ExecSpec::sh(&sb.machine, "root", cmd))
    {
        eprintln!(
            "warning: {}: couldn't apply the environment file's sandbox options: {e:#}",
            sb.name()
        );
    }
    // Not fatal either: without the shims the agent prints URLs instead of opening them. Without
    // the bridge, any shims a fork's disk came with are removed (they'd reach its parent).
    // The socket directory is checked on every start: /tmp can be emptied (macOS does on reboot)
    // and another user can create it first, then the mount would reach them. The SSH agent's
    // socket is in the same directory; a start only warns for it, as sessions serve it and
    // `listener::bind` checks the directory again then.
    let dir = bridge::socket_dir();
    let safe = !(sb.meta.bridge || sb.meta.ssh_agent.is_some()) || private(&dir);
    if !safe {
        for w in unsafe_dir_warnings(sb, &dir) {
            eprintln!("{w}");
        }
    }
    let (shims, what) = if sb.meta.bridge && safe {
        (bridge::install_cmd(), "install")
    } else {
        (bridge::remove_cmd(), "remove")
    };
    if let Err(e) = vm.exec_captured(&ExecSpec::sh(&sb.machine, "root", shims)) {
        eprintln!(
            "warning: {}: couldn't {what} the browser and clipboard shims: {e:#}",
            sb.name()
        );
    }
    // Not fatal: without the links the agent just doesn't see the shared skills this start.
    // As root, as in sbx; the script hands the directories and links to the agent's uid.
    if let Some(script) = sb
        .meta
        .skills
        .as_ref()
        .and_then(|l| crate::skills::link_script(&l.dirs))
        && let Err(e) = vm.exec_captured(&ExecSpec::sh(&sb.machine, "root", script))
    {
        eprintln!("warning: {}: couldn't link shared skills: {e:#}", sb.name());
    }
    // The pre-4a path: a docker sandbox created before the docker kit has no startup runner.
    // With kits, the docker kit's startup hook starts dockerd (no second start here).
    if sb.meta.docker && sb.meta.kits.is_empty() {
        vm.exec_captured(&ExecSpec {
            detach: true,
            ..ExecSpec::sh(&sb.machine, "root", DOCKER_START)
        })
        .context("starting dockerd")?;
    }
    if let Some(step) = &plan.clone {
        for w in run_clone(vm, sb, step)? {
            eprintln!("{w}");
        }
    }
    // A kit first start runs them once its startup scripts are written.
    if plan.kit.is_none() {
        run_startup(vm, sb, None)?;
    }
    Ok(())
}

/// What a start says when the socket directory isn't private: per socket the sandbox has.
fn unsafe_dir_warnings(sb: &Sandbox, dir: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let mut warn = |what: &str| {
        out.push(format!(
            "warning: {} isn't a private directory owned by you; {} gets no {what} unless \
             it can be made private",
            dir.display(),
            sb.name()
        ))
    };
    if sb.meta.bridge {
        warn("browser or clipboard bridge");
    }
    if sb.meta.ssh_agent.is_some() {
        warn("SSH agent");
    }
    out
}

/// Starts the sandbox if needed. The plan is only computed for a start, because resolving secrets
/// can ask for Touch ID.
pub fn ensure_running<R: Runner>(
    vm: &Smolvm<R>,
    sb: &mut Sandbox,
    plan: impl FnOnce() -> Result<StartPlan>,
) -> Result<()> {
    if !sb.is_running() {
        start(vm, sb, &plan()?)?;
        sb.state = MachineState::Running;
    }
    Ok(())
}

/// Creates and starts a new sandbox (the caller checked the name is free), then runs its kit
/// steps. `drop_install_rules` removes the install-phase rules from the policy and returns this
/// sandbox's network without them. A failed first start (the start itself, its setup, or a kit
/// step) removes the sandbox.
/// `on` hears what the start and the kit steps are doing.
pub fn create<R: Runner>(
    vm: &Smolvm<R>,
    req: &CreateRequest,
    plan: &StartPlan,
    drop_install_rules: impl FnOnce(&[String]) -> Result<NetworkSpec>,
    on: &mut dyn FnMut(Event),
) -> Result<Sandbox> {
    let mut checked = req.clone();
    if let Some(warning) = create::drop_unsafe_bridge(&mut checked, bridge::ensure_private_dir) {
        eprintln!("{warning}");
    }
    vm.create(&create::spec(&checked))?;
    let mut sb = get(vm, &req.name)?;
    // A sandbox whose first start failed isn't usable, so it is removed (as sbx does) and the
    // same command can simply be run again. The cause, which names the step that failed, stays
    // in the chain, where a smolvm error's hint is looked up.
    let removed = |e: anyhow::Error| match vm.delete(&sb.machine) {
        Ok(()) => e.context("the first start failed (the sandbox was removed)"),
        Err(d) => anyhow!(
            "the first start failed: {e:#}\nremoving the sandbox failed too ({d:#}); remove it \
             with `sbt rm -f {}`",
            sb.name()
        ),
    };
    let Some(kit) = &plan.kit else {
        start_with(vm, &sb, plan, on).map_err(removed)?;
        sb.state = MachineState::Running;
        return Ok(sb);
    };
    start_with(vm, &sb, plan, on)
        .and_then(|()| first_start(vm, &sb, plan, kit, drop_install_rules, on))
        .map_err(removed)?;
    sb.state = MachineState::Running;
    if let Err(e) = run_startup(vm, &sb, None) {
        // Kept, as in sbx, but stopped: the next start runs the hooks again and fails until
        // they succeed, rather than running the agent without them.
        eprintln!("{}", create_warning(&e));
        match vm.stop(&sb.machine) {
            Ok(()) => sb.state = MachineState::Stopped,
            Err(stop) => eprintln!(
                "warning: stopping {} after its startup hooks failed: {stop:#}",
                sb.name()
            ),
        }
    }
    Ok(sb)
}

/// Steps 3–8 of the first start (spec "Data flow" 7); the caller removes the sandbox on error.
fn first_start<R: Runner>(
    vm: &Smolvm<R>,
    sb: &Sandbox,
    plan: &StartPlan,
    kit: &KitFirstStart,
    drop_install_rules: impl FnOnce(&[String]) -> Result<NetworkSpec>,
    on: &mut dyn FnMut(Event),
) -> Result<()> {
    // An install-phase `ssh-agent@1` grant is served while the install hooks run only.
    let agent = install_agent(sb, kit);
    let after_install = || -> Result<()> {
        drop(agent);
        let mut network = plan.network.clone();
        if !kit.steps.install_rules.is_empty() {
            network = drop_install_rules(&kit.steps.install_rules)
                .context("removing the install-phase network rules")?;
        }
        // A restart below applies `network` itself (`start` sends it to the stopped machine).
        if !kit.steps.install_rules.is_empty() && kit.restart_without.is_empty() {
            // R11: smolvm resolves each allowed host to CIDRs, and `--remove-allow-host` leaves
            // those behind, so the host would stay reachable by IP. `update_network` sends
            // `--reset-allow-list` with the whole list, which clears the stored hosts and CIDRs
            // and replaces the running allow list (learned IPs of names no longer allowed are
            // dropped too; a list left without hosts needs smolvm's workaround in
            // `NO_HOSTS_PLACEHOLDER`).
            vm.update_network(&sb.machine, &network)
                .context("removing the install-phase network rules")?;
        }
        if !kit.restart_without.is_empty() {
            vm.stop(&sb.machine)
                .context("restarting without install-only credentials")?;
            let without = |v: &String| kit.restart_without.contains(v);
            let restart = StartPlan {
                network,
                env: plan
                    .env
                    .iter()
                    .filter(|(k, _)| !without(k))
                    .cloned()
                    .collect(),
                remove: plan
                    .remove
                    .iter()
                    .chain(&kit.restart_without)
                    .cloned()
                    .collect(),
                ..plan.clone()
            };
            start(vm, sb, &restart).context("restarting without install-only credentials")?;
        }
        Ok(())
    };
    apply_kit_steps(vm, sb, &kit.steps, after_install, on).map_err(|(_, e)| e)
}

/// Serves the sandbox's install-phase agent grant, if it has one and install hooks to run.
/// `kit.agent_backing` is `None` only in tests.
fn install_agent(sb: &Sandbox, kit: &KitFirstStart) -> Option<bridge::Server> {
    let access = sb.meta.ssh_agent.as_ref()?.install.clone()?;
    let backing = kit.agent_backing.clone()?;
    if kit.steps.install.is_empty() {
        return None;
    }
    crate::ssh_agent::filter::serve_for(sb.name(), access, backing)
}

/// sbx's warning when a create's startup hooks fail (the sandbox is kept).
fn create_warning(e: &anyhow::Error) -> String {
    format!(
        "warning: StartRuntime after create failed; kit commands.startup will fire on first run: \
         {e:#}"
    )
}

#[cfg(test)]
mod tests;
