//! Sandboxes: smolvm machines that smolbento created, identified by their `sbx.*` labels.

pub mod create;
pub mod labels;
pub mod name;
pub mod options;
pub mod session;

use anyhow::{Context, Result, bail};

use crate::smolvm::{ExecSpec, Machine, MachineState, NetworkSpec, PublishedPort, Runner, Smolvm};
use crate::workspace::MOUNTLESS_WORKDIR;

pub use create::CreateRequest;
pub use labels::Meta;

/// Started detached as root after each start of a sandbox with `sbx.docker=true`.
pub const DOCKER_START: &str = "pgrep -x dockerd >/dev/null || { rm -f /var/run/docker.pid; exec dockerd >/var/log/dockerd.log 2>&1; }";

/// Gives the image's `agent` user the host user's uid. virtiofs passes host uids through, so
/// without this uid 1000 can't write a workspace owned by, say, uid 501 (verified on smolvm
/// 1.32.2). Idempotent; skipped for images without an `agent` user.
pub fn identity_cmd(uid: u32) -> String {
    format!(
        "id -u agent >/dev/null 2>&1 || exit 0; [ \"$(id -u agent)\" = {uid} ] || usermod -o -u {uid} agent"
    )
}

pub fn host_uid() -> u32 {
    // SAFETY: getuid has no preconditions and cannot fail.
    unsafe { libc::getuid() }
}

/// What a start needs beyond the machine: its network, the secret values for its credentials
/// (only ever passed as env to `machine start`), and the uid for the agent user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartPlan {
    pub network: NetworkSpec,
    pub env: Vec<(String, String)>,
    /// Credential env vars without a value, removed from the inherited environment so the host
    /// shell's same-named variables can't stand in for them.
    pub remove: Vec<String>,
    pub uid: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Sandbox {
    pub meta: Meta,
    pub machine: String,
    pub state: MachineState,
    /// Filled from `machine status` for running sandboxes.
    pub ports: Vec<PublishedPort>,
}

impl Sandbox {
    pub fn from_machine(m: &Machine) -> Option<Sandbox> {
        Some(Sandbox {
            meta: Meta::from_labels(&m.labels)?,
            machine: m.name.clone(),
            state: m.state,
            ports: m.published_ports.clone(),
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
    find(vm, name)?.with_context(|| format!("sandbox '{name}' not found (see `sbt ls`)"))
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
pub fn start<R: Runner>(vm: &Smolvm<R>, sb: &Sandbox, plan: &StartPlan) -> Result<()> {
    vm.update_network(&sb.machine, &plan.network)
        .context("applying the network policy")?;
    vm.start(&sb.machine, &plan.env, &plan.remove)?;
    vm.exec_captured(&ExecSpec {
        name: sb.machine.clone(),
        user: Some("root".into()),
        cmd: vec!["sh".into(), "-c".into(), identity_cmd(plan.uid)],
        ..Default::default()
    })
    .context("matching the sandbox's agent user to your host uid")?;
    if sb.meta.docker {
        vm.exec_captured(&ExecSpec {
            name: sb.machine.clone(),
            user: Some("root".into()),
            detach: true,
            cmd: vec!["sh".into(), "-c".into(), DOCKER_START.into()],
            ..Default::default()
        })
        .context("starting dockerd")?;
    }
    Ok(())
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

/// Creates and starts a new sandbox.
pub fn create<R: Runner>(vm: &Smolvm<R>, req: &CreateRequest, plan: &StartPlan) -> Result<Sandbox> {
    if find(vm, &req.name)?.is_some() {
        bail!("sandbox '{}' already exists", req.name);
    }
    vm.create(&create::spec(req))?;
    let mut sb = get(vm, &req.name)?;
    start(vm, &sb, plan)?;
    sb.state = MachineState::Running;
    Ok(sb)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smolvm::NetworkSpec;
    use crate::smolvm::fake::FakeRunner;

    const STATUS: &str = include_str!("../../tests/fixtures/smolvm/status.json");

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
        }
    }

    #[test]
    fn start_applies_network_then_starts_with_env_then_setup() {
        let fake = FakeRunner::new();
        fake.ok(
            &["machine", "status"],
            &STATUS.replace("\"state\": \"running\"", "\"state\": \"stopped\""),
        );
        let vm = Smolvm::new(fake);
        let mut sb = get(&vm, "claude-myrepo").unwrap();
        ensure_running(&vm, &mut sb, || Ok(plan())).unwrap();
        assert!(sb.is_running());
        let lines = vm.runner().call_lines();
        assert_eq!(
            lines[1],
            "machine update -n sbx-claude-myrepo --net --reset-allow-list"
        );
        assert_eq!(lines[2], "machine start -n sbx-claude-myrepo");
        assert!(
            lines[3].ends_with("usermod -o -u 501 agent"),
            "{}",
            lines[3]
        );
        assert_eq!(
            lines[4],
            format!("machine exec --name sbx-claude-myrepo -u root -d -- sh -c {DOCKER_START}")
        );
        assert_eq!(
            vm.runner().envs(),
            vec![vec![("TOK".to_string(), "secret".to_string())]]
        );
        assert_eq!(vm.runner().removed(), vec![vec!["GONE".to_string()]]);
    }

    #[test]
    fn running_sandboxes_skip_the_plan() {
        let fake = FakeRunner::new();
        fake.ok(&["machine", "status"], STATUS);
        let vm = Smolvm::new(fake);
        let mut sb = get(&vm, "claude-myrepo").unwrap();
        ensure_running(&vm, &mut sb, || panic!("plan must not be computed")).unwrap();
    }

    #[test]
    fn identity_cmd_targets_the_host_uid() {
        assert_eq!(
            identity_cmd(501),
            "id -u agent >/dev/null 2>&1 || exit 0; [ \"$(id -u agent)\" = 501 ] || usermod -o -u 501 agent"
        );
    }

    #[test]
    fn create_refuses_existing_then_creates_and_starts() {
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
        fake.ok(&["machine", "status"], STATUS);
        assert!(
            create(&Smolvm::new(fake), &req, &plan())
                .unwrap_err()
                .to_string()
                .contains("already exists")
        );

        let fake = FakeRunner::new();
        let created = STATUS
            .replace("\"state\": \"running\"", "\"state\": \"created\"")
            .replace("\"true\"", "\"false\"");
        fake.ok(&["machine", "status"], &created).once_fail(
            &["machine", "status"],
            "NOT_FOUND",
            "vm not found",
        );
        let vm = Smolvm::new(fake);
        let sb = create(&vm, &req, &plan()).unwrap();
        assert!(sb.is_running());
        let lines = vm.runner().call_lines();
        assert!(
            lines[1].starts_with("machine create -n sbx-claude-myrepo --image img"),
            "{}",
            lines[1]
        );
        assert_eq!(
            lines[3],
            "machine update -n sbx-claude-myrepo --net --reset-allow-list"
        );
        assert_eq!(lines[4], "machine start -n sbx-claude-myrepo");
        assert_eq!(
            lines.len(),
            6,
            "no dockerd for a non-docker sandbox: {lines:?}"
        );
    }
}
