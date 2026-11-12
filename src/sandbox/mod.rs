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
    /// Every policy rule id the kits added, removed again by `cli::plan::create` when the create
    /// fails.
    pub rule_ids: Vec<String>,
    /// Where an install-phase `ssh-agent@1` grant (`sbx.ssh-agent`) finds the host agent while
    /// the install hooks run.
    pub agent_backing: Option<bridge::filter::Backing>,
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
/// sandbox's network without them. A failing kit step removes the sandbox (spec Decision 6).
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
    let Some(kit) = &plan.kit else {
        start_with(vm, &sb, plan, on)?;
        sb.state = MachineState::Running;
        return Ok(sb);
    };
    // A kit sandbox isn't usable until its steps ran, so a failed first start removes it too and
    // the same command can simply run again.
    let steps = start_with(vm, &sb, plan, on)
        .and_then(|()| first_start(vm, &sb, plan, kit, drop_install_rules, on));
    if let Err(e) = steps {
        // Every Docker sandbox takes this path (the docker kit), most without install hooks.
        let what = if kit.steps.install.is_empty() {
            "the first start failed"
        } else {
            "kit install failed"
        };
        return Err(match vm.delete(&sb.machine) {
            Ok(()) => anyhow!("{what} (the sandbox was removed): {e:#}"),
            Err(d) => anyhow!(
                "{what}: {e:#}\nremoving the sandbox failed too ({d:#}); remove it with `sbt rm {}`",
                sb.name()
            ),
        });
    }
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
    bridge::filter::serve_for(sb.name(), access, backing)
}

/// sbx's warning when a create's startup hooks fail (the sandbox is kept).
fn create_warning(e: &anyhow::Error) -> String {
    format!(
        "warning: StartRuntime after create failed; kit commands.startup will fire on first run: \
         {e:#}"
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn hosts_line_stays_apart_and_is_added_once() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("hosts");
        std::fs::write(&f, "127.0.0.1 localhost").unwrap(); // no trailing newline
        let cmd = hosts_script(f.to_str().unwrap());
        for _ in 0..2 {
            let st = std::process::Command::new("sh")
                .args(["-c", &cmd])
                .status()
                .unwrap();
            assert!(st.success());
        }
        let got = std::fs::read_to_string(&f).unwrap();
        let lines: Vec<&str> = got.lines().filter(|l| !l.is_empty()).collect();
        assert_eq!(
            lines,
            ["127.0.0.1 localhost", "100.96.0.1 host.docker.internal"]
        );
    }

    use super::*;
    use crate::kits::apply::InstallStep;
    use crate::kits::guest;
    use crate::smolvm::NetworkSpec;
    use crate::smolvm::fake::FakeRunner;
    use crate::testutil::root_sh;
    use crate::util::sh_quote;
    use crate::workspace::clone::WorktreeHead;

    const STATUS: &str = include_str!("../../tests/fixtures/smolvm/status.json");

    /// The fixture sandbox, stopped.
    fn stopped() -> String {
        STATUS.replace("\"state\": \"running\"", "\"state\": \"stopped\"")
    }

    /// A fake smolvm whose `machine status` answers with `status`.
    fn vm_with(status: &str) -> Smolvm<FakeRunner> {
        let fake = FakeRunner::new();
        fake.ok(&["machine", "status"], status);
        Smolvm::new(fake)
    }

    #[test]
    fn find_maps_name_and_reads_labels() {
        let fake = FakeRunner::new();
        fake.ok(&["machine", "status", "-n", "sbx-claude-myrepo"], STATUS);
        let vm = Smolvm::new(fake);
        let sb = find(&vm, "claude-myrepo").unwrap().unwrap();
        assert_eq!(sb.meta.agent, "claude");
        assert!(sb.is_running());
        assert_eq!(sb.workdir(), "/Users/dev/myrepo");
        assert_eq!(sb.ports[0].host, 18080);
    }

    #[test]
    fn get_missing_is_a_clear_error() {
        let fake = FakeRunner::new();
        fake.fail(&["machine", "status"], "NOT_FOUND", "vm not found");
        let err = get(&Smolvm::new(fake), "nope").unwrap_err().to_string();
        assert!(err.contains("sandbox 'nope' not found"), "{err}");
    }

    #[test]
    fn list_skips_foreign_machines_and_adds_ports() {
        let fake = FakeRunner::new();
        fake.ok(
            &["machine", "ls", "--json"],
            include_str!("../../tests/fixtures/smolvm/ls.json"),
        );
        fake.ok(&["machine", "status", "-n", "sbx-claude-myrepo"], STATUS);
        let list = list(&Smolvm::new(fake)).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name(), "claude-myrepo");
        assert_eq!(list[0].ports.len(), 1);
    }

    fn plan() -> StartPlan {
        StartPlan {
            network: NetworkSpec::Open,
            env: vec![("TOK".into(), "secret".into())],
            remove: vec!["GONE".into()],
            uid: 501,
            gid: 20,
            clone: None,
            branchable: true,
            kit: None,
        }
    }

    /// The fixture is a pre-4a docker sandbox: `sbx.docker=true` and no `sbx.kits`, so `setup`
    /// starts dockerd itself.
    #[test]
    fn start_applies_network_then_starts_with_env_then_setup() {
        let vm = vm_with(&stopped());
        let mut sb = get(&vm, "claude-myrepo").unwrap();
        ensure_running(&vm, &mut sb, || Ok(plan())).unwrap();
        assert!(sb.is_running());
        let lines = vm.runner().call_lines();
        assert_eq!(
            lines[1],
            "machine update -n sbx-claude-myrepo --net --reset-allow-list"
        );
        assert_eq!(lines[2], "machine start -n sbx-claude-myrepo --branchable");
        assert!(
            lines[3].ends_with("usermod -o -u 501 agent"),
            "{}",
            lines[3]
        );
        assert!(lines[4].ends_with(&hosts_cmd()), "{lines:#?}");
        assert!(lines[5].ends_with(&bridge::remove_cmd()), "{lines:#?}");
        assert_eq!(
            lines[6],
            format!("machine exec --name sbx-claude-myrepo -u root -d -- sh -c {DOCKER_START}")
        );
        assert_eq!(
            lines[7],
            format!(
                "machine exec --name sbx-claude-myrepo -u root -- sh -c {}",
                startup_cmd(None)
            )
        );
        assert_eq!(lines.len(), 8, "{lines:#?}");
        assert_eq!(
            vm.runner().envs(),
            vec![vec![("TOK".to_string(), "secret".to_string())]]
        );
        assert_eq!(vm.runner().removed(), vec![vec!["GONE".to_string()]]);
    }

    #[test]
    fn starts_install_the_bridge_shims_or_remove_ours() {
        for bridged in [true, false] {
            let fake = FakeRunner::new();
            let status = stopped();
            let status = if bridged {
                status.replace(
                    "\"sbx.docker\"",
                    "\"sbx.bridge\": \"true\",\n    \"sbx.docker\"",
                )
            } else {
                status
            };
            fake.ok(&["machine", "status"], &status);
            let vm = Smolvm::new(fake);
            let sb = get(&vm, "claude-myrepo").unwrap();
            assert_eq!(sb.meta.bridge, bridged);
            start_checked(&vm, &sb, &plan(), &mut |_| {}, &|_| true).unwrap();
            let install = format!(
                "machine exec --name sbx-claude-myrepo -u root -- sh -c {}",
                bridge::install_cmd()
            );
            let remove = format!(
                "machine exec --name sbx-claude-myrepo -u root -- sh -c {}",
                bridge::remove_cmd()
            );
            let lines = vm.runner().call_lines();
            // Right after the hosts step: the install, or without the bridge the removal.
            let hosts = lines
                .iter()
                .position(|l| l.ends_with(&hosts_cmd()))
                .unwrap();
            let expected = if bridged { &install } else { &remove };
            assert_eq!(&lines[hosts + 1], expected, "{lines:#?}");
            assert_eq!(lines.contains(&install), bridged, "{lines:#?}");
        }
    }

    fn bridged_status() -> String {
        stopped().replace(
            "\"sbx.docker\"",
            "\"sbx.bridge\": \"true\",\n    \"sbx.docker\"",
        )
    }

    #[test]
    fn a_start_checks_the_socket_dir_and_installs_the_shims_when_it_is_private() {
        let vm = vm_with(&bridged_status());
        let sb = get(&vm, "claude-myrepo").unwrap();
        let checked = std::cell::RefCell::new(Vec::new());
        start_checked(&vm, &sb, &plan(), &mut |_| {}, &|d| {
            checked.borrow_mut().push(d.to_path_buf());
            true
        })
        .unwrap();
        assert_eq!(*checked.borrow(), vec![bridge::socket_dir()]);
        let install = format!(
            "machine exec --name sbx-claude-myrepo -u root -- sh -c {}",
            bridge::install_cmd()
        );
        assert!(vm.runner().call_lines().contains(&install));
    }

    /// A sandbox with an SSH agent: the directory is checked even without the bridge, and an
    /// unsafe one warns that this start gets no agent.
    #[test]
    fn a_start_checks_the_socket_dir_for_the_ssh_agent_too() {
        let fake = FakeRunner::new();
        let status = stopped().replace(
            "\"sbx.docker\"",
            "\"sbx.ssh-agent\": \"{\\\"runtime\\\":{\\\"sign\\\":null}}\",\n    \"sbx.docker\"",
        );
        fake.ok(&["machine", "status"], &status);
        let vm = Smolvm::new(fake);
        let sb = get(&vm, "claude-myrepo").unwrap();
        assert!(sb.meta.ssh_agent.is_some() && !sb.meta.bridge);
        let checked = std::cell::RefCell::new(Vec::new());
        start_checked(&vm, &sb, &plan(), &mut |_| {}, &|d| {
            checked.borrow_mut().push(d.to_path_buf());
            false
        })
        .unwrap();
        let dir = bridge::socket_dir();
        assert_eq!(*checked.borrow(), vec![dir.clone()]);
        let unsafe_dir = |what: &str| {
            format!(
                "warning: {} isn't a private directory owned by you; claude-myrepo gets no {what} \
                 unless it can be made private",
                dir.display()
            )
        };
        // What `setup` prints: an agent-only sandbox's warning, and no shims, private or not.
        assert_eq!(
            unsafe_dir_warnings(&sb, &dir),
            vec![unsafe_dir("SSH agent")]
        );
        let shims =
            |cmd: String| format!("machine exec --name sbx-claude-myrepo -u root -- sh -c {cmd}");
        let lines = vm.runner().call_lines();
        assert!(lines.contains(&shims(bridge::remove_cmd())), "{lines:#?}");
        let vm = vm_with(&status);
        start_checked(&vm, &sb, &plan(), &mut |_| {}, &|_| true).unwrap();
        let lines = vm.runner().call_lines();
        assert!(lines.contains(&shims(bridge::remove_cmd())), "{lines:#?}");
        assert!(!lines.contains(&shims(bridge::install_cmd())), "{lines:#?}");
        let mut both = sb.clone();
        both.meta.bridge = true;
        assert_eq!(
            unsafe_dir_warnings(&both, &dir),
            vec![
                unsafe_dir("browser or clipboard bridge"),
                unsafe_dir("SSH agent")
            ]
        );
        // Neither: nothing to check.
        let mut neither = sb.clone();
        neither.meta.ssh_agent = None;
        let vm = vm_with(&stopped());
        start_checked(&vm, &neither, &plan(), &mut |_| {}, &|_| panic!("checked")).unwrap();
    }

    #[test]
    fn a_start_with_an_unsafe_socket_dir_removes_the_shims() {
        let vm = vm_with(&bridged_status());
        let sb = get(&vm, "claude-myrepo").unwrap();
        start_checked(&vm, &sb, &plan(), &mut |_| {}, &|_| false).unwrap();
        let lines = vm.runner().call_lines();
        let exec =
            |cmd: String| format!("machine exec --name sbx-claude-myrepo -u root -- sh -c {cmd}");
        assert!(lines.contains(&exec(bridge::remove_cmd())), "{lines:#?}");
        assert!(!lines.contains(&exec(bridge::install_cmd())), "{lines:#?}");
    }

    #[test]
    fn failing_to_install_the_shims_warns_and_the_start_goes_on() {
        let fake = FakeRunner::new();
        fake.ok(
            &["machine", "status"],
            &stopped().replace(
                "\"sbx.docker\"",
                "\"sbx.bridge\": \"true\",\n    \"sbx.docker\"",
            ),
        );
        fake.fail(
            &root_sh("sbx-claude-myrepo", &bridge::install_cmd()),
            "EXEC_FAILED",
            "Read-only file system",
        );
        let vm = Smolvm::new(fake);
        let mut sb = get(&vm, "claude-myrepo").unwrap();
        ensure_running(&vm, &mut sb, || Ok(plan())).unwrap();
        assert!(sb.is_running());
    }

    #[test]
    fn every_start_names_the_host_after_the_agent_user() {
        let vm = vm_with(&stopped());
        let mut sb = get(&vm, "claude-myrepo").unwrap();
        ensure_running(&vm, &mut sb, || Ok(plan())).unwrap();
        let lines = vm.runner().call_lines();
        assert!(lines[3].ends_with("usermod -o -u 501 agent"), "{lines:#?}");
        assert_eq!(
            lines[4],
            "machine exec --name sbx-claude-myrepo -u root -- sh -c grep -q ' host.docker.internal$' \
             /etc/hosts || printf '\\n%s\\n' '100.96.0.1 host.docker.internal' >> /etc/hosts"
        );
    }

    fn skills_status(label: &str) -> String {
        let l = label.replace('"', "\\\"");
        stopped().replace(
            "\"sbx.docker\"",
            &format!("\"sbx.skills\": \"{l}\",\n    \"sbx.docker\""),
        )
    }

    const RO_LABEL: &str = r#"{"mode":"readonly","shared":"ro","dirs":[{"path":"/home/agent/.claude/skills","access":"link"}]}"#;

    #[test]
    fn a_linking_skills_sandbox_links_the_store_as_root_at_start() {
        let vm = vm_with(&skills_status(RO_LABEL));
        let mut sb = get(&vm, "claude-myrepo").unwrap();
        ensure_running(&vm, &mut sb, || Ok(plan())).unwrap();
        let script = crate::skills::link_script(&sb.meta.skills.as_ref().unwrap().dirs).unwrap();
        let lines = vm.runner().call_lines();
        let want = format!("machine exec --name sbx-claude-myrepo -u root -- sh -c {script}");
        assert_eq!(
            lines.iter().filter(|l| **l == want).count(),
            1,
            "{lines:#?}"
        );
        assert!(script.contains("/home/agent/.claude/skills"));
        let at = |f: &dyn Fn(&String) -> bool| lines.iter().position(f).unwrap();
        let hosts = at(&|l| l.ends_with(&hosts_cmd()));
        let link = at(&|l| *l == want);
        assert!(hosts < link, "{lines:#?}");
    }

    #[test]
    fn a_failed_skills_link_only_warns() {
        let fake = FakeRunner::new();
        fake.ok(&["machine", "status"], &skills_status(RO_LABEL));
        let script = crate::skills::link_script(&[crate::skills::Dir {
            path: "/home/agent/.claude/skills".into(),
            access: crate::skills::Access::Link,
        }])
        .unwrap();
        fake.fail(
            &root_sh("sbx-claude-myrepo", &script),
            "EXEC_FAILED",
            "boom",
        );
        let vm = Smolvm::new(fake);
        let mut sb = get(&vm, "claude-myrepo").unwrap();
        ensure_running(&vm, &mut sb, || Ok(plan())).unwrap();
        assert!(sb.is_running());
    }

    #[test]
    fn a_sandbox_without_a_skills_label_gets_no_link_exec() {
        let vm = vm_with(&stopped());
        let mut sb = get(&vm, "claude-myrepo").unwrap();
        ensure_running(&vm, &mut sb, || Ok(plan())).unwrap();
        let lines = vm.runner().call_lines();
        assert!(
            !lines.iter().any(|l| l.contains("skills-shared")),
            "{lines:#?}"
        );
    }

    #[test]
    fn a_read_only_etc_hosts_warns_and_the_start_goes_on() {
        let fake = FakeRunner::new();
        fake.ok(&["machine", "status"], &stopped());
        fake.fail(
            &root_sh("sbx-claude-myrepo", &hosts_cmd()),
            "EXEC_FAILED",
            "Read-only file system",
        );
        let vm = Smolvm::new(fake);
        let mut sb = get(&vm, "claude-myrepo").unwrap();
        ensure_running(&vm, &mut sb, || Ok(plan())).unwrap();
        assert!(sb.is_running());
        let lines = vm.runner().call_lines();
        assert!(
            lines.iter().any(|l| l.ends_with(&startup_cmd(None))),
            "{lines:#?}"
        );
        assert!(
            !lines.iter().any(|l| l.starts_with("machine stop")),
            "{lines:#?}"
        );
    }

    #[test]
    fn a_v3_workloads_image_user_is_resolved_before_agent_moves() {
        let vm = vm_with(&stopped());
        let mut sb = get(&vm, "claude-myrepo").unwrap();
        sb.meta.user = Some("1000".into());
        ensure_running(&vm, &mut sb, || Ok(plan())).unwrap();
        let lines = vm.runner().call_lines();
        // Before `identity_cmd`: uid 1000 is still `agent` the first time.
        assert_eq!(
            lines[3],
            format!(
                "machine exec --name sbx-claude-myrepo -u root -- sh -c {}",
                image_user_cmd("1000", 501, 20)
            )
        );
        assert!(lines[4].ends_with("usermod -o -u 501 agent"), "{lines:#?}");
        assert_eq!(lines.len(), 9, "{lines:#?}");
    }

    /// Runs `image_user_script` (uid 501, gid 20) on the host against `etc`, with `id`, `usermod`
    /// and `groupmod` shims that read `etc/passwd` and `etc/group` and log to
    /// `etc/<command>.log`. Returns the exit code.
    fn run_image_user_script(etc: &std::path::Path, user: &str) -> i32 {
        let bin = etc.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let shim = |name: &str, body: &str| {
            let p = bin.join(name);
            std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        };
        shim(
            "id",
            r#"case $1 in -u) f=3;; *) f=4;; esac
g=$(awk -F: -v n="$2" -v f=$f '$1 == n { print $f; x = 1 } END { exit !x }' "$ETC/passwd") || exit 1
[ "$1" = -gn ] && g=$(awk -F: -v g="$g" '$3 == g { print $1 }' "$ETC/group")
echo "$g""#,
        );
        shim("usermod", r#"echo "$@" >> "$ETC/usermod.log""#);
        shim("groupmod", r#"echo "$@" >> "$ETC/groupmod.log""#);
        let script = image_user_script(user, 501, 20, &etc.display().to_string());
        let path = format!("{}:{}", bin.display(), std::env::var("PATH").unwrap());
        std::process::Command::new("sh")
            .args(["-c", &script])
            .env("PATH", path)
            .env("ETC", etc)
            .status()
            .unwrap()
            .code()
            .unwrap()
    }

    #[test]
    fn a_numeric_image_user_is_resolved_once_and_kept_after_agent_moves() {
        let d = tempfile::tempdir().unwrap();
        let etc = d.path();
        let passwd = |agent_uid: u32| {
            std::fs::write(
                etc.join("passwd"),
                format!(
                    "root:x:0:0::/root:/bin/sh\nagent:x:{agent_uid}:1000::/home/agent:/bin/sh\n"
                ),
            )
            .unwrap()
        };
        std::fs::write(etc.join("group"), "root:x:0:\nagent:x:1000:\n").unwrap();
        // First start: uid 1000 is `agent` (sandbox-templates); it's recorded and mapped.
        passwd(1000);
        assert_eq!(run_image_user_script(etc, "1000"), 0);
        let name = std::fs::read_to_string(etc.join("smolbento/image-user")).unwrap();
        assert_eq!(name, "agent\n");
        let log = std::fs::read_to_string(etc.join("usermod.log")).unwrap();
        assert_eq!(log, "-o -u 501 agent\n");
        // Its group takes the host gid too: Linux virtiofs creates files as the caller's gid.
        let groups = std::fs::read_to_string(etc.join("groupmod.log")).unwrap();
        assert_eq!(groups, "-o -g 20 agent\n");
        // Later starts: `agent` is 501 now and uid 1000 is nobody, yet the record still names it.
        passwd(501);
        assert_eq!(run_image_user_script(etc, "1000"), 0);
        assert_eq!(
            std::fs::read_to_string(etc.join("usermod.log")).unwrap(),
            log
        );
        // A uid without a passwd entry can't be mapped; root needs no mapping.
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("passwd"), "root:x:0:0::/root:/bin/sh\n").unwrap();
        assert_eq!(run_image_user_script(d.path(), "1001"), 3);
        assert_eq!(run_image_user_script(d.path(), "0"), 0);
    }

    #[test]
    fn a_failing_usermod_names_its_error() {
        let fake = FakeRunner::new();
        fake.ok(&["machine", "status"], STATUS);
        fake.on(
            &[
                "machine",
                "exec",
                "--name",
                "sbx-claude-myrepo",
                "-u",
                "root",
            ],
            crate::smolvm::Output {
                code: 8,
                stderr: "usermod: user somebody is currently used by process 7\n".into(),
                ..Default::default()
            },
        );
        let vm = Smolvm::new(fake);
        let sb = get(&vm, "claude-myrepo").unwrap();
        let e = format!(
            "{:#}",
            map_image_user(&vm, &sb, "somebody", 501, 20).unwrap_err()
        );
        assert!(
            e.contains("usermod: user somebody is currently used by process 7"),
            "{e}"
        );
    }

    #[test]
    fn launch_user_ignores_a_hostile_record() {
        let long = "a".repeat(33);
        for record in ["-x", "a:b", "a b", long.as_str(), "a\u{7}b", ""] {
            let fake = FakeRunner::new();
            fake.ok(&["machine", "status"], STATUS);
            fake.download(format!("{record}\n").as_bytes());
            let vm = Smolvm::new(fake);
            let mut sb = get(&vm, "claude-myrepo").unwrap();
            sb.meta.user = Some("1001:staff".into());
            assert_eq!(
                launch_user(&vm, &sb).as_deref(),
                Some("1001:staff"),
                "{record:?}"
            );
        }
        // The longest name allowed, and a trailing `$` (machine accounts).
        for ok in ["a".repeat(32), "_svc.x-1$".to_string()] {
            let fake = FakeRunner::new();
            fake.ok(&["machine", "status"], STATUS);
            fake.download(format!("{ok}\n").as_bytes());
            let vm = Smolvm::new(fake);
            let mut sb = get(&vm, "claude-myrepo").unwrap();
            sb.meta.user = Some("1001".into());
            assert_eq!(launch_user(&vm, &sb).as_deref(), Some(ok.as_str()));
        }
    }

    #[test]
    fn launch_user_names_a_numeric_image_users_account() {
        let vm = vm_with(STATUS);
        let mut sb = get(&vm, "claude-myrepo").unwrap();
        assert_eq!(launch_user(&vm, &sb), None);
        sb.meta.user = Some("somebody".into());
        assert_eq!(launch_user(&vm, &sb).as_deref(), Some("somebody"));
        sb.meta.user = Some("0".into());
        assert_eq!(launch_user(&vm, &sb).as_deref(), Some("0"));
        assert!(
            vm.runner()
                .call_lines()
                .iter()
                .all(|l| !l.contains("machine cp"))
        );
        vm.runner().download(b"agent\n");
        sb.meta.user = Some("1000:staff".into());
        assert_eq!(launch_user(&vm, &sb).as_deref(), Some("agent:staff"));
        assert!(
            vm.runner()
                .call_lines()
                .last()
                .unwrap()
                .starts_with(&format!("machine cp sbx-claude-myrepo:{IMAGE_USER_FILE} ")),
        );
        // No record (no passwd entry): the raw uid.
        let fake = FakeRunner::new();
        fake.ok(&["machine", "status"], STATUS);
        fake.fail(&["machine", "cp"], "NOT_FOUND", "no such file");
        let vm = Smolvm::new(fake);
        let mut sb = get(&vm, "claude-myrepo").unwrap();
        sb.meta.user = Some("1001".into());
        assert_eq!(launch_user(&vm, &sb).as_deref(), Some("1001"));
    }

    #[test]
    fn an_unmappable_image_user_is_a_warning() {
        let vm = vm_with(STATUS);
        let sb = get(&vm, "claude-myrepo").unwrap();
        assert_eq!(map_image_user(&vm, &sb, "somebody", 501, 20).unwrap(), None);
        vm.runner().on(
            &[
                "machine",
                "exec",
                "--name",
                "sbx-claude-myrepo",
                "-u",
                "root",
            ],
            crate::smolvm::Output {
                code: 3,
                ..Default::default()
            },
        );
        assert_eq!(
            map_image_user(&vm, &sb, "1001", 501, 20)
                .unwrap()
                .as_deref(),
            Some(
                "warning: claude-myrepo: couldn't map the image user 1001 to your uid; the \
                 workspace may not be writable"
            )
        );
    }

    #[test]
    fn a_docker_kit_sandbox_leaves_dockerd_to_its_startup_runner() {
        let vm = vm_with(&stopped().replace(
            "\"sbx.docker\": \"true\",",
            "\"sbx.docker\": \"true\", \"sbx.kits\": \"[\\\"builtin:docker\\\"]\",",
        ));
        let mut sb = get(&vm, "claude-myrepo").unwrap();
        assert_eq!(sb.meta.kits, ["builtin:docker"]);
        ensure_running(&vm, &mut sb, || Ok(plan())).unwrap();
        let lines = vm.runner().call_lines();
        assert!(
            !lines.iter().any(|l| l.ends_with(DOCKER_START)),
            "no second dockerd start: {lines:#?}"
        );
        assert!(
            lines.last().unwrap().ends_with(&startup_cmd(None)),
            "{lines:#?}"
        );
    }

    #[test]
    fn running_sandboxes_skip_the_plan() {
        let vm = vm_with(STATUS);
        let mut sb = get(&vm, "claude-myrepo").unwrap();
        ensure_running(&vm, &mut sb, || panic!("plan must not be computed")).unwrap();
    }

    #[test]
    fn a_failed_setup_step_stops_the_machine() {
        let fake = FakeRunner::new();
        fake.ok(&["machine", "status"], &stopped());
        fake.fail(
            &[
                "machine",
                "exec",
                "--name",
                "sbx-claude-myrepo",
                "-u",
                "root",
                "-d",
            ],
            "EXEC_FAILED",
            "dockerd: not found",
        );
        let vm = Smolvm::new(fake);
        let mut sb = get(&vm, "claude-myrepo").unwrap();
        assert!(sb.meta.docker);
        let err = ensure_running(&vm, &mut sb, || Ok(plan())).unwrap_err();
        assert!(format!("{err:#}").contains("starting dockerd"), "{err:#}");
        assert!(!sb.is_running());
        assert_eq!(
            vm.runner().call_lines().last().unwrap(),
            "machine stop -n sbx-claude-myrepo"
        );
    }

    #[test]
    fn identity_cmd_targets_the_host_uid_and_gid() {
        assert_eq!(
            identity_cmd(501, 20),
            "id -u agent >/dev/null 2>&1 || exit 0; g=$(id -g agent); [ \"$g\" = 0 ] || \
             [ \"$g\" = 20 ] || ! command -v groupmod >/dev/null 2>&1 || \
             groupmod -o -g 20 \"$(id -gn agent)\" || exit; \
             [ \"$(id -u agent)\" = 501 ] || usermod -o -u 501 agent"
        );
    }

    #[test]
    fn create_creates_and_starts() {
        let req = create::CreateRequest {
            name: "claude-myrepo".into(),
            agent: "claude".into(),
            image: "img".into(),
            cpus: 1,
            memory_mib: 1024,
            created: 1,
            ..Default::default()
        };
        let fake = FakeRunner::new();
        let created = STATUS
            .replace("\"state\": \"running\"", "\"state\": \"created\"")
            .replace("\"true\"", "\"false\"");
        fake.ok(&["machine", "status"], &created);
        let vm = Smolvm::new(fake);
        let sb = create(&vm, &req, &plan(), |_| unreachable!(), &mut |_| {}).unwrap();
        assert!(sb.is_running());
        let lines = vm.runner().call_lines();
        assert!(
            lines[0].starts_with("machine create -n sbx-claude-myrepo --image img"),
            "{}",
            lines[0]
        );
        assert_eq!(
            lines[2],
            "machine update -n sbx-claude-myrepo --net --reset-allow-list"
        );
        assert_eq!(lines[3], "machine start -n sbx-claude-myrepo --branchable");
        assert_eq!(
            lines.len(),
            8,
            "no dockerd for a non-docker sandbox: {lines:?}"
        );
        assert!(lines[7].ends_with(&startup_cmd(None)), "{lines:?}");
    }

    #[test]
    fn clone_commands_quote_and_copy_remotes() {
        let step = CloneStep {
            dir: "/w/my repo".into(),
            head: Some(WorktreeHead::Branch("feat".into())),
            remotes: vec![("origin".into(), "https://github.com/o/r.git".into())],
        };
        assert_eq!(
            clone_prep_cmd(&step),
            "[ -d '/w/my repo/.git' ] && exit 0; rmdir '/w/my repo/lost+found' 2>/dev/null; chown agent '/w/my repo'"
        );
        assert_eq!(
            clone_cmd(&step),
            "set -e; [ -d '/w/my repo/.git' ] || \
             git -c safe.directory=/run/sandbox/source clone -q --branch 'feat' /run/sandbox/source '/w/my repo'; \
             cd '/w/my repo'; \
             git remote set-url -- 'origin' 'https://github.com/o/r.git' 2>/dev/null || git remote add -- 'origin' 'https://github.com/o/r.git'"
        );
        assert_eq!(sh_quote("it's"), r"'it'\''s'");
    }

    #[test]
    fn a_detached_worktree_clone_checks_out_its_commit_or_falls_back() {
        let detached = CloneStep {
            head: Some(WorktreeHead::Detached(
                "0123456789abcdef0123456789abcdef01234567".into(),
            )),
            ..step("/w/r")
        };
        assert_eq!(
            clone_cmd(&detached),
            "set -e; [ -d '/w/r/.git' ] || \
             { git -c safe.directory=/run/sandbox/source clone -q --no-checkout /run/sandbox/source '/w/r' || exit 1; \
             git -C '/w/r' checkout -q --detach '0123456789abcdef0123456789abcdef01234567' -- 2>/dev/null || { \
             git -C '/w/r' reset -q --hard || { rm -rf '/w/r/.git'; exit 1; }; \
             echo \"warning: commit 0123456789ab isn't in the clone; the agent starts \
             from $(git -C '/w/r' symbolic-ref -q --short HEAD || echo HEAD) instead\" >&2; }; }; \
             cd '/w/r'"
        );
        // Anything but a hex id is cloned plainly rather than echoed.
        let odd = CloneStep {
            head: Some(WorktreeHead::Detached("\"$(x)".into())),
            ..step("/w/r")
        };
        assert_eq!(clone_cmd(&odd), clone_cmd(&step("/w/r")));
    }

    #[test]
    fn run_clone_returns_the_guests_warning_lines() {
        let fake = FakeRunner::new();
        fake.ok(&["machine"], "");
        fake.ok_with_stderr(
            &["machine", "exec", "--name", "sbx-r", "-u", "agent"],
            "",
            "Cloning...\nwarning: commit abc isn't in the clone; the agent starts from main instead\n",
        );
        let vm = Smolvm::new(fake);
        let (sb, plan) = clone_sandbox();
        assert_eq!(
            run_clone(&vm, &sb, plan.clone.as_ref().unwrap()).unwrap(),
            vec!["warning: commit abc isn't in the clone; the agent starts from main instead"]
        );
    }

    fn step(dir: &str) -> CloneStep {
        CloneStep {
            dir: dir.into(),
            head: None,
            remotes: vec![],
        }
    }

    /// A stopped clone sandbox `r` of `/w/r`, and a plan that clones it.
    fn clone_sandbox() -> (Sandbox, StartPlan) {
        let sb = Sandbox {
            meta: Meta {
                name: "r".into(),
                workspace: Some("/w/r".into()),
                clone_repo: Some("/w/r".into()),
                ..Default::default()
            },
            machine: "sbx-r".into(),
            state: MachineState::Stopped,
            ports: vec![],
            image: None,
        };
        let plan = StartPlan {
            clone: Some(step("/w/r")),
            ..plan()
        };
        (sb, plan)
    }

    #[test]
    fn start_runs_the_clone_step_after_setup() {
        let fake = FakeRunner::new();
        fake.ok(&["machine"], "");
        let vm = Smolvm::new(fake);
        let (sb, plan) = clone_sandbox();
        start(&vm, &sb, &plan).unwrap();
        let lines = vm.runner().call_lines();
        // The startup hooks follow the clone.
        assert!(
            lines.last().unwrap().ends_with(&startup_cmd(None)),
            "{lines:?}"
        );
        let last2 = &lines[lines.len() - 3..lines.len() - 1];
        assert!(
            last2[0].contains("-u root") && last2[0].contains("chown agent"),
            "{last2:?}"
        );
        assert!(
            last2[1].contains("-u agent")
                && last2[1].contains("clone -q /run/sandbox/source '/w/r'"),
            "{last2:?}"
        );
    }

    #[test]
    fn a_failed_clone_stops_the_machine_and_reports_gits_first_line() {
        let fake = FakeRunner::new();
        fake.fail(
            &["machine", "exec", "--name", "sbx-r", "-u", "agent"],
            "EXEC_FAILED",
            "fatal: repository not found\nhint: more",
        );
        let vm = Smolvm::new(fake);
        let (sb, p) = clone_sandbox();
        let err = start(&vm, &sb, &p).unwrap_err();
        assert_eq!(
            err.to_string(),
            "cloning the repo in the sandbox: fatal: repository not found"
        );
        let lines = vm.runner().call_lines();
        assert!(
            lines.last().unwrap().starts_with("machine stop"),
            "{lines:?}"
        );
    }

    #[test]
    fn a_failed_clone_prep_reports_the_first_line_and_stops() {
        let prep = clone_prep_cmd(&step("/w/r"));
        let fake = FakeRunner::new();
        fake.spawn_fail(
            &root_sh("sbx-r", &prep),
            "could not run smolvm\nsecond line",
        );
        let vm = Smolvm::new(fake);
        let (sb, p) = clone_sandbox();
        let err = start(&vm, &sb, &p).unwrap_err();
        assert_eq!(
            err.to_string(),
            "cloning the repo in the sandbox: could not run smolvm"
        );
        let lines = vm.runner().call_lines();
        assert!(
            lines.last().unwrap().starts_with("machine stop"),
            "{lines:?}"
        );
        assert!(
            !lines.iter().any(|l| l.contains("-u agent -- sh")),
            "{lines:?}"
        );
    }

    const MACHINE: &str = "sbx-claude-myrepo";

    /// A fake whose `status` answers with a freshly created (non-docker) `claude-myrepo`.
    fn created_vm() -> Smolvm<FakeRunner> {
        let fake = FakeRunner::new();
        let created = STATUS
            .replace("\"state\": \"running\"", "\"state\": \"created\"")
            .replace("\"true\"", "\"false\"");
        fake.ok(&["machine", "status"], &created);
        Smolvm::new(fake)
    }

    fn request() -> CreateRequest {
        CreateRequest {
            name: "claude-myrepo".into(),
            agent: "claude".into(),
            image: "img".into(),
            cpus: 1,
            memory_mib: 1024,
            created: 1,
            ..Default::default()
        }
    }

    fn restricted(hosts: &[&str]) -> NetworkSpec {
        NetworkSpec::Restricted(crate::smolvm::AllowList::new(
            hosts.iter().map(|h| h.to_string()),
            vec![],
            vec![],
        ))
    }

    fn hook(n: usize, user: Option<&str>, script: &str) -> InstallStep {
        InstallStep {
            label: format!("kit k install hook {n}"),
            kit: Some("k".into()),
            user: user.map(String::from),
            script: script.into(),
            relay_stderr: false,
        }
    }

    fn kit_plan(restart_without: &[&str]) -> StartPlan {
        StartPlan {
            network: restricted(&["api.example.com", "registry.npmjs.org"]),
            env: vec![
                ("TOK".into(), "secret".into()),
                ("KEEP".into(), "kept".into()),
            ],
            remove: vec![],
            kit: Some(KitFirstStart {
                steps: KitSteps {
                    install_rules: vec!["r-npm".into()],
                    install: vec![
                        hook(1, None, "echo install-1"),
                        hook(2, Some("agent"), "echo install-2"),
                    ],
                    files: vec!["echo files-1".into()],
                    context: vec!["echo context-1".into()],
                    startup_d: vec![("01-k.sh".into(), "echo startup".into())],
                    kits_record: "k\tref@sha256:00\tnpm\n".into(),
                },
                restart_without: restart_without.iter().map(|v| v.to_string()).collect(),
                rule_ids: vec!["r-npm".into(), "r-api".into()],
                agent_backing: None,
            }),
            ..plan()
        }
    }

    fn exec_line(user: &str, detach: bool, script: &str) -> String {
        let d = if detach { " -d" } else { "" };
        format!("machine exec --name {MACHINE} -u {user}{d} -- sh -c {script}")
    }

    fn position(lines: &[String], what: &str, pred: impl Fn(&String) -> bool) -> usize {
        lines
            .iter()
            .position(pred)
            .unwrap_or_else(|| panic!("no {what} in {lines:#?}"))
    }

    #[test]
    fn create_tells_what_it_is_doing() {
        let vm = created_vm();
        vm.runner().progress(
            &["machine", "start"],
            &[
                "Pulling image img... [==>      ] 10%",
                "Pulling image img... [=========] 100% — syncing...",
            ],
        );
        let mut plan = kit_plan(&[]);
        let kit = plan.kit.as_mut().unwrap();
        // The docker kit, without install hooks, comes after the kit whose hooks run.
        kit.steps.kits_record = "docker\tbuiltin:docker\tdocker\nk\tref@sha256:00\tnpm\n".into();
        kit.steps.install.insert(
            0,
            InstallStep {
                kit: None,
                ..hook(0, None, "echo git-identity")
            },
        );
        // A hook of another kit between k's: k still gets one step.
        kit.steps.install.insert(
            2,
            InstallStep {
                kit: Some("j".into()),
                ..hook(0, None, "echo j")
            },
        );
        let mut events = Vec::new();
        create(&vm, &request(), &plan, |_| Ok(restricted(&[])), &mut |e| {
            events.push(format!("{e:?}"))
        })
        .unwrap();
        assert_eq!(
            events,
            [
                "Boot",
                "Pull(Percent(10))",
                "Pull(Syncing)",
                "Setup",
                "Install(\"k\")",
                "Install(\"j\")",
                "Install(\"docker\")"
            ]
        );
    }

    #[test]
    fn an_install_grant_is_served_only_while_the_install_hooks_run() {
        let both = r#"{"install":{"sign":["git"]},"runtime":{"sign":null}}"#;
        let runtime = r#"{"runtime":{"sign":null}}"#;
        for (tag, grant, want) in [
            ("both", both, [true, true, false, false]),
            ("runtime", runtime, [false; 4]),
        ] {
            let name = format!("agent-{}-first-{tag}", std::process::id());
            let label = serde_json::to_string(grant).unwrap();
            let status = STATUS
                .replace("\"state\": \"running\"", "\"state\": \"created\"")
                .replace("\"true\"", "\"false\"")
                .replace(
                    "\"sbx.name\": \"claude-myrepo\"",
                    &format!("\"sbx.name\": \"{name}\", \"sbx.ssh-agent\": {label}"),
                );
            let fake = FakeRunner::new();
            fake.ok(&["machine", "status"], &status);
            let (seen, probe) = crate::testutil::socket_probe(bridge::agent_socket(&name));
            fake.during(&["machine", "exec"], move |args| {
                let script = args.last().unwrap();
                if ["install-1", "install-2", "files-1", "context-1"]
                    .iter()
                    .any(|w| script == &format!("echo {w}"))
                {
                    probe();
                }
            });
            let vm = Smolvm::new(fake);
            let (_dir, paths) = crate::config::test_paths();
            let mut plan = kit_plan(&[]);
            plan.kit.as_mut().unwrap().agent_backing =
                Some(bridge::filter::Backing::new(&paths, &Default::default()));
            let sb = create(
                &vm,
                &request(),
                &plan,
                |_| Ok(plan.network.clone()),
                &mut |_| {},
            )
            .unwrap();
            assert!(sb.meta.ssh_agent.is_some());
            assert_eq!(*seen.borrow(), want, "{tag}");
            assert!(!bridge::agent_socket(&name).exists(), "{tag}");
        }
    }

    #[test]
    fn create_runs_kit_steps_in_lifecycle_order() {
        let vm = created_vm();
        let dropped = std::cell::RefCell::new(Vec::new());
        create(
            &vm,
            &request(),
            &kit_plan(&[]),
            |ids| {
                dropped.borrow_mut().extend_from_slice(ids);
                Ok(restricted(&["api.example.com"]))
            },
            &mut |_| {},
        )
        .unwrap();
        assert_eq!(*dropped.borrow(), vec!["r-npm".to_string()]);
        let lines = vm.runner().call_lines();
        let start = position(&lines, "start", |l| l.starts_with("machine start"));
        let uid = position(&lines, "usermod", |l| {
            l.ends_with("usermod -o -u 501 agent")
        });
        let install1 = position(&lines, "install 1", |l| {
            *l == exec_line("root", false, "echo install-1")
        });
        let install2 = position(&lines, "install 2", |l| {
            *l == exec_line("agent", false, "echo install-2")
        });
        let update = position(&lines, "post-install update", |l| {
            l.starts_with("machine update")
                && l.contains("--allow-host api.example.com")
                && !l.contains("registry.npmjs.org")
        });
        let files = position(&lines, "files", |l| {
            *l == exec_line("root", false, "echo files-1")
        });
        let context = position(&lines, "context", |l| {
            *l == exec_line("root", false, "echo context-1")
        });
        let startup_d = position(&lines, "startup.d cp", |l| {
            l.starts_with("machine cp ")
                && l.ends_with(&format!("{MACHINE}:/etc/smolbento/startup.d/01-k.sh"))
        });
        let runner = exec_line("root", false, &startup_cmd(None));
        assert!(
            start < uid
                && uid < install1
                && install1 < install2
                && install2 < update
                && update < files
                && files < context
                && context < startup_d,
            "{lines:#?}"
        );
        assert_eq!(lines.last().unwrap(), &runner, "{lines:#?}");
        assert_eq!(
            lines.iter().filter(|l| **l == runner).count(),
            1,
            "only after the kit files: {lines:#?}"
        );
        // R11: the post-install update replaces the whole list, so the CIDRs smolvm resolved
        // for the install host go with it.
        assert!(
            lines[update].contains("--reset-allow-list"),
            "{}",
            lines[update]
        );
        assert!(
            !lines.iter().any(|l| l.contains("machine stop")),
            "{lines:#?}"
        );
        let uploads: std::collections::BTreeMap<String, String> =
            vm.runner().uploads().into_iter().collect();
        let at = |p: &str| uploads.get(&format!("{MACHINE}:{p}")).cloned();
        assert_eq!(
            at("/etc/smolbento/startup.d/01-k.sh").as_deref(),
            Some("echo startup")
        );
        assert_eq!(
            at(guest::STARTUP_PATH).as_deref(),
            Some(guest::STARTUP_RUNNER)
        );
        assert_eq!(
            at(guest::KITS_FILE).as_deref(),
            Some("k\tref@sha256:00\tnpm\n")
        );
        assert!(
            lines[startup_d..]
                .iter()
                .any(|l| l.contains("chmod 755 '/etc/smolbento/startup'")),
            "{lines:#?}"
        );
    }

    #[test]
    fn install_only_credentials_restart_the_machine_without_them() {
        let vm = created_vm();
        create(
            &vm,
            &request(),
            &kit_plan(&["TOK"]),
            |_| Ok(restricted(&["api.example.com"])),
            &mut |_| {},
        )
        .unwrap();
        let lines = vm.runner().call_lines();
        let install2 = position(&lines, "install 2", |l| {
            *l == exec_line("agent", false, "echo install-2")
        });
        let stop = position(&lines, "stop", |l| l.starts_with("machine stop"));
        let restart = lines
            .iter()
            .rposition(|l| l.starts_with("machine start"))
            .unwrap();
        let files = position(&lines, "files", |l| {
            *l == exec_line("root", false, "echo files-1")
        });
        assert!(
            install2 < stop && stop < restart && restart < files,
            "{lines:#?}"
        );
        // The network without the install rules goes once, to the stopped machine, by `start`.
        let updates: Vec<usize> = (install2..restart)
            .filter(|&i| lines[i].starts_with("machine update"))
            .collect();
        assert!(
            updates.len() == 1
                && stop < updates[0]
                && lines[updates[0]].contains("api.example.com"),
            "{lines:#?}"
        );
        assert!(
            lines[restart..files]
                .iter()
                .any(|l| l.ends_with("usermod -o -u 501 agent")),
            "setup runs again: {lines:#?}"
        );
        assert_eq!(
            lines
                .iter()
                .filter(|l| l.ends_with(&startup_cmd(None)))
                .count(),
            1,
            "not on the restart either: {lines:#?}"
        );
        let envs = vm.runner().envs();
        let removed = vm.runner().removed();
        assert_eq!(envs.len(), 2);
        assert!(
            envs[0].iter().any(|(k, _)| k == "TOK"),
            "the first start has it"
        );
        assert!(!envs[1].iter().any(|(k, _)| k == "TOK"), "{:?}", envs[1]);
        assert!(envs[1].iter().any(|(k, _)| k == "KEEP"));
        assert!(removed[1].contains(&"TOK".to_string()), "{:?}", removed[1]);
    }

    #[test]
    fn only_the_bundled_skills_step_relays_its_stderr() {
        let fake = FakeRunner::new();
        fake.ok(&["machine", "status"], STATUS);
        fake.ok_with_stderr(
            &["machine", "exec"],
            "",
            "warning: skipping skill review: /x/review already exists\n",
        );
        let vm = Smolvm::new(fake);
        let sb = get(&vm, "claude-myrepo").unwrap();
        let mut run = Steps {
            vm: &vm,
            sb: &sb,
            n: 0,
        };
        let own = InstallStep {
            label: "bundled agent skills".into(),
            kit: None,
            user: None,
            script: "true".into(),
            relay_stderr: true,
        };
        assert_eq!(
            run.install(&own).unwrap(),
            ["warning: skipping skill review: /x/review already exists"]
        );
        assert!(run.install(&hook(1, None, "true")).unwrap().is_empty());
        let git_identity = InstallStep {
            label: "the git identity step".into(),
            kit: None,
            user: None,
            script: "true".into(),
            relay_stderr: false,
        };
        assert!(run.install(&git_identity).unwrap().is_empty());
    }

    #[test]
    fn a_failed_install_hook_removes_the_sandbox() {
        let vm = created_vm();
        let stderr: Vec<String> = (1..=25).map(|i| format!("line {i}")).collect();
        vm.runner().fail(
            &root_sh(MACHINE, "echo install-1"),
            "EXEC_FAILED",
            &stderr.join("\n"),
        );
        let err = create(
            &vm,
            &request(),
            &kit_plan(&[]),
            |_| panic!("install rules stay until the hooks succeed"),
            &mut |_| {},
        )
        .unwrap_err()
        .to_string();
        assert_eq!(
            err,
            format!(
                "kit install failed (the sandbox was removed): kit k install hook 1 failed:\n{}",
                stderr[5..].join("\n")
            )
        );
        let lines = vm.runner().call_lines();
        assert_eq!(
            lines.last().unwrap(),
            &format!("machine delete -n {MACHINE} -f")
        );
        assert!(!lines.iter().any(|l| l.contains("install-2")), "{lines:#?}");
    }

    #[test]
    fn failing_to_drop_the_install_rules_or_write_files_removes_the_sandbox() {
        let vm = created_vm();
        let err = create(
            &vm,
            &request(),
            &kit_plan(&[]),
            |_| anyhow::bail!("policy.toml: permission denied"),
            &mut |_| {},
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .starts_with("kit install failed (the sandbox was removed): "),
            "{err}"
        );
        assert!(format!("{err:#}").contains("permission denied"), "{err:#}");
        assert_eq!(
            vm.runner().call_lines().last().unwrap(),
            &format!("machine delete -n {MACHINE} -f")
        );

        let vm = created_vm();
        vm.runner()
            .fail(&["machine", "cp"], "CP_FAILED", "no space left");
        let err = create(
            &vm,
            &request(),
            &kit_plan(&[]),
            |_| Ok(restricted(&["api.example.com"])),
            &mut |_| {},
        )
        .unwrap_err();
        assert!(
            err.to_string().starts_with("kit install failed")
                && format!("{err:#}").contains("no space left"),
            "{err:#}"
        );
        assert_eq!(
            vm.runner().call_lines().last().unwrap(),
            &format!("machine delete -n {MACHINE} -f")
        );
    }

    #[test]
    fn a_failed_first_start_without_install_hooks_says_so_neutrally() {
        // Like a default Docker sandbox: the docker kit has no install hooks.
        let vm = created_vm();
        vm.runner()
            .fail(&["machine", "cp"], "CP_FAILED", "no space left");
        let mut plan = kit_plan(&[]);
        let kit = plan.kit.as_mut().unwrap();
        kit.steps.install.clear();
        kit.steps.install_rules.clear();
        let err = create(&vm, &request(), &plan, |_| unreachable!(), &mut |_| {}).unwrap_err();
        assert!(
            err.to_string()
                .starts_with("the first start failed (the sandbox was removed): ")
                && format!("{err:#}").contains("no space left"),
            "{err:#}"
        );
    }

    #[test]
    fn a_large_script_is_copied_in_rather_than_passed_in_argv() {
        let vm = created_vm();
        let big = format!("echo {}", "x".repeat(70 * 1024));
        let mut plan = kit_plan(&[]);
        let kit = plan.kit.as_mut().unwrap();
        kit.steps.install = vec![hook(1, Some("agent"), &big)];
        create(
            &vm,
            &request(),
            &plan,
            |_| Ok(restricted(&["api.example.com"])),
            &mut |_| {},
        )
        .unwrap();
        let lines = vm.runner().call_lines();
        assert!(!lines.iter().any(|l| l.contains(&big)), "inline");
        let run = position(&lines, "step exec", |l| {
            *l == format!("machine exec --name {MACHINE} -u agent -- sh /run/smolbento/step-1.sh")
        });
        let cp = position(&lines, "step cp", |l| {
            l.starts_with("machine cp ")
                && l.ends_with(&format!("{MACHINE}:/run/smolbento/step-1.sh"))
        });
        assert!(cp < run, "{lines:#?}");
        let rm = position(&lines, "step rm", |l| {
            *l == format!("machine exec --name {MACHINE} -u root -- rm -f /run/smolbento/step-1.sh")
        });
        assert!(run < rm, "{lines:#?}");
        let uploads = vm.runner().uploads();
        assert!(
            uploads
                .iter()
                .any(|(p, c)| p.ends_with(":/run/smolbento/step-1.sh") && *c == big)
        );
    }

    #[test]
    fn a_plain_start_runs_the_startup_hooks_in_one_blocking_exec() {
        let fake = FakeRunner::new();
        fake.ok(&["machine"], "");
        let vm = Smolvm::new(fake);
        let (mut sb, plan) = clone_sandbox();
        sb.meta.clone_repo = None;
        start(
            &vm,
            &sb,
            &StartPlan {
                clone: None,
                ..plan
            },
        )
        .unwrap();
        let lines = vm.runner().call_lines();
        assert_eq!(lines.len(), 6, "{lines:#?}");
        assert!(lines[2].ends_with("usermod -o -u 501 agent"), "{lines:#?}");
        assert!(lines[3].ends_with(&hosts_cmd()), "{lines:#?}");
        assert!(lines[4].ends_with(&bridge::remove_cmd()), "{lines:#?}");
        // A no-op without kits (no runner).
        assert_eq!(
            lines[5],
            "machine exec --name sbx-r -u root -- sh -c \
             [ -x /etc/smolbento/startup ] || exit 0; exec /etc/smolbento/startup"
        );
    }

    /// The startup runner in `machine`, answering with exit `code`.
    fn failing_startup(fake: &FakeRunner, machine: &str, code: i32) {
        fake.on(
            &root_sh(machine, &startup_cmd(None)),
            crate::smolvm::Output {
                code,
                ..Default::default()
            },
        );
    }

    #[test]
    fn a_failing_startup_hook_fails_the_start_and_stops_the_machine() {
        let fake = FakeRunner::new();
        fake.ok(&["machine"], "");
        failing_startup(&fake, "sbx-r", 3);
        let vm = Smolvm::new(fake);
        let (mut sb, plan) = clone_sandbox();
        sb.meta.clone_repo = None;
        let err = start(
            &vm,
            &sb,
            &StartPlan {
                clone: None,
                ..plan
            },
        )
        .unwrap_err();
        assert_eq!(format!("{err:#}"), "kit startup exited with code 3");
        let lines = vm.runner().call_lines();
        assert_eq!(lines.last().unwrap(), "machine stop -n sbx-r", "{lines:#?}");
    }

    #[test]
    fn a_failing_startup_hook_at_create_warns_and_keeps_the_sandbox_stopped() {
        let vm = created_vm();
        failing_startup(vm.runner(), MACHINE, 1);
        let sb = create(
            &vm,
            &request(),
            &kit_plan(&[]),
            |_| Ok(restricted(&["api.example.com"])),
            &mut |_| {},
        )
        .unwrap();
        // Stopped, so the next run starts it and runs the hooks again (and fails like sbx).
        assert_eq!(sb.state, MachineState::Stopped);
        let lines = vm.runner().call_lines();
        assert_eq!(
            lines.last().unwrap(),
            &format!("machine stop -n {MACHINE}"),
            "{lines:#?}"
        );
        assert!(
            !lines.iter().any(|l| l.starts_with("machine delete")),
            "{lines:#?}"
        );
        assert_eq!(
            create_warning(&anyhow!("kit startup exited with code 1")),
            "warning: StartRuntime after create failed; kit commands.startup will fire on first \
             run: kit startup exited with code 1"
        );
    }

    #[test]
    fn one_kits_startup_hooks_run_by_script() {
        let fake = FakeRunner::new();
        fake.ok(&["machine"], "");
        let vm = Smolvm::new(fake);
        let (sb, _) = clone_sandbox();
        let script = "/etc/smolbento/startup.d/02-net.sh";
        run_startup(&vm, &sb, Some(script)).unwrap();
        assert_eq!(
            vm.runner().call_lines(),
            vec![
                "machine exec --name sbx-r -u root -- sh -c [ -x /etc/smolbento/startup ] || \
                 exit 0; exec /etc/smolbento/startup '/etc/smolbento/startup.d/02-net.sh'",
            ]
        );
    }

    #[test]
    fn a_smolvm_error_running_the_startup_hooks_is_named() {
        let fake = FakeRunner::new();
        fake.ok(&["machine"], "");
        fake.fail(
            &["machine", "exec", "--name", "sbx-r", "-u", "root", "--"],
            "EXEC_FAILED",
            "agent gone",
        );
        let vm = Smolvm::new(fake);
        let (sb, _) = clone_sandbox();
        let err = run_startup(&vm, &sb, None).unwrap_err();
        assert_eq!(
            format!("{err:#}"),
            "running the kits' startup hooks: agent gone"
        );
    }

    /// Guest stderr (here the shell's, before the runner's redirect) isn't smolvm's error.
    #[test]
    fn startup_stderr_without_a_smolvm_error_gets_sbxs_text() {
        let fake = FakeRunner::new();
        fake.ok(&["machine"], "");
        fake.on(
            &["machine", "exec", "--name", "sbx-r", "-u", "root", "--"],
            crate::smolvm::Output {
                code: 2,
                stderr: "sh: can't create /var/log/sbx-kit-startup.log: Read-only file system\n"
                    .into(),
                ..Default::default()
            },
        );
        let vm = Smolvm::new(fake);
        let (sb, _) = clone_sandbox();
        let err = run_startup(&vm, &sb, None).unwrap_err();
        assert_eq!(format!("{err:#}"), "kit startup exited with code 2");
    }

    #[test]
    fn a_failed_hook_with_no_stderr_reports_its_stdout() {
        let vm = created_vm();
        vm.runner().on(
            &root_sh(MACHINE, "echo install-1"),
            crate::smolvm::Output {
                code: 2,
                stdout: "resolving\nE: package not found\n".into(),
                stderr: String::new(),
            },
        );
        let err = create(
            &vm,
            &request(),
            &kit_plan(&[]),
            |_| unreachable!(),
            &mut |_| {},
        )
        .unwrap_err()
        .to_string();
        assert_eq!(
            err,
            "kit install failed (the sandbox was removed): kit k install hook 1 failed:\n\
             resolving\nE: package not found"
        );
    }

    #[test]
    fn a_failed_first_start_of_a_kit_sandbox_removes_it() {
        let vm = created_vm();
        vm.runner().fail(
            &root_sh(MACHINE, &identity_cmd(501, 20)),
            "EXEC_FAILED",
            "usermod: busy",
        );
        let err = create(
            &vm,
            &request(),
            &kit_plan(&[]),
            |_| unreachable!(),
            &mut |_| {},
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .starts_with("kit install failed (the sandbox was removed): "),
            "{err:#}"
        );
        assert!(format!("{err:#}").contains("usermod: busy"), "{err:#}");
        let lines = vm.runner().call_lines();
        assert_eq!(
            lines.last().unwrap(),
            &format!("machine delete -n {MACHINE} -f")
        );
        assert!(!lines.iter().any(|l| l.contains("install-1")), "{lines:#?}");
    }
}
