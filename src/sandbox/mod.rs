//! Sandboxes: smolvm machines that smolbento created, identified by their `sbx.*` labels.

pub mod create;
pub mod labels;
pub mod name;
pub mod options;
pub mod session;

use anyhow::{Context, Result};

use crate::smolvm::{
    ExecSpec, Machine, MachineState, NetworkSpec, PublishedPort, Runner, Smolvm, SmolvmError,
};
use crate::workspace::MOUNTLESS_WORKDIR;
use crate::workspace::clone::SOURCE_MOUNT;

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
    /// Set for a clone sandbox; the clone itself is skipped once it exists, the remote copy is not.
    pub clone: Option<CloneStep>,
}

/// The first start of a clone sandbox clones the host repo inside the VM (as sbx).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloneStep {
    /// Where the clone goes: a guest-only volume at the host repo's path.
    pub dir: String,
    /// Only for a linked worktree, whose source HEAD is the main worktree's.
    pub branch: Option<String>,
    /// Host remotes to copy (local ones and credentials already left out).
    pub remotes: Vec<(String, String)>,
}

/// Single-quotes `s` for `sh -c`.
pub fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// As root: the volume is root-owned and may hold `lost+found`, which `git clone` won't clone into.
fn clone_prep_cmd(step: &CloneStep) -> String {
    let d = sh_quote(&step.dir);
    let lf = sh_quote(&format!("{}/lost+found", step.dir));
    let git = sh_quote(&format!("{}/.git", step.dir));
    format!("[ -d {git} ] && exit 0; rmdir {lf} 2>/dev/null; chown agent {d}")
}

/// As `agent`: sbx's clone command (skipped once cloned), then its remote copy, which runs on
/// every start so a failed add is retried and host remote changes arrive (as sbx's setup script).
fn clone_cmd(step: &CloneStep) -> String {
    let d = sh_quote(&step.dir);
    let git = sh_quote(&format!("{}/.git", step.dir));
    let branch = step
        .branch
        .as_ref()
        .map(|b| format!("--branch {} ", sh_quote(b)))
        .unwrap_or_default();
    let mut s = format!(
        "set -e; [ -d {git} ] || \
         git -c safe.directory={SOURCE_MOUNT} clone -q {branch}{SOURCE_MOUNT} {d}; cd {d}"
    );
    for (n, u) in &step.remotes {
        let (n, u) = (sh_quote(n), sh_quote(u));
        s.push_str(&format!(
            "; git remote set-url -- {n} {u} 2>/dev/null || git remote add -- {n} {u}"
        ));
    }
    s
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
    if let Some(step) = &plan.clone
        && let Err(e) = run_clone(vm, sb, step)
    {
        // Left running without a clone, later commands would skip `start` and never retry it.
        if let Err(stop) = vm.stop(&sb.machine) {
            eprintln!(
                "warning: stopping {} after the failed clone: {stop:#}",
                sb.name()
            );
        }
        return Err(e);
    }
    Ok(())
}

fn run_clone<R: Runner>(vm: &Smolvm<R>, sb: &Sandbox, step: &CloneStep) -> Result<()> {
    for (user, cmd) in [("root", clone_prep_cmd(step)), ("agent", clone_cmd(step))] {
        vm.exec_captured(&ExecSpec {
            name: sb.machine.clone(),
            user: Some(user.into()),
            cmd: vec!["sh".into(), "-c".into(), cmd],
            ..Default::default()
        })
        .map_err(|e| {
            // git's first error line, not the whole stderr.
            let text = match e.downcast_ref::<SmolvmError>() {
                Some(s) => s.message.clone(),
                None => format!("{e:#}"),
            };
            let line = text
                .lines()
                .find(|l| !l.trim().is_empty())
                .unwrap_or("failed");
            anyhow::anyhow!("cloning the repo in the sandbox: {}", line.trim())
        })?;
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

/// Creates and starts a new sandbox (the caller checked the name is free).
pub fn create<R: Runner>(vm: &Smolvm<R>, req: &CreateRequest, plan: &StartPlan) -> Result<Sandbox> {
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
            clone: None,
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
        let sb = create(&vm, &req, &plan()).unwrap();
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
        assert_eq!(lines[3], "machine start -n sbx-claude-myrepo");
        assert_eq!(
            lines.len(),
            5,
            "no dockerd for a non-docker sandbox: {lines:?}"
        );
    }

    #[test]
    fn clone_commands_quote_and_copy_remotes() {
        let step = CloneStep {
            dir: "/w/my repo".into(),
            branch: Some("feat".into()),
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
    fn start_runs_the_clone_step_after_setup() {
        let fake = FakeRunner::new();
        fake.ok(&["machine"], "");
        let vm = Smolvm::new(fake);
        let sb = Sandbox {
            meta: Meta {
                name: "r".into(),
                workspace: Some("/w/r".into()),
                clone: true,
                ..Default::default()
            },
            machine: "sbx-r".into(),
            state: MachineState::Stopped,
            ports: vec![],
        };
        let plan = StartPlan {
            network: NetworkSpec::Open,
            env: vec![],
            remove: vec![],
            uid: 501,
            clone: Some(CloneStep {
                dir: "/w/r".into(),
                branch: None,
                remotes: vec![],
            }),
        };
        start(&vm, &sb, &plan).unwrap();
        let lines = vm.runner().call_lines();
        let last2 = &lines[lines.len() - 2..];
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
        let sb = Sandbox {
            meta: Meta {
                name: "r".into(),
                clone: true,
                ..Default::default()
            },
            machine: "sbx-r".into(),
            state: MachineState::Stopped,
            ports: vec![],
        };
        let mut p = plan();
        p.clone = Some(CloneStep {
            dir: "/w/r".into(),
            branch: None,
            remotes: vec![],
        });
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
        let step = CloneStep {
            dir: "/w/r".into(),
            branch: None,
            remotes: vec![],
        };
        let prep = clone_prep_cmd(&step);
        let fake = FakeRunner::new();
        fake.spawn_fail(
            &[
                "machine", "exec", "--name", "sbx-r", "-u", "root", "--", "sh", "-c", &prep,
            ],
            "could not run smolvm\nsecond line",
        );
        let vm = Smolvm::new(fake);
        let sb = Sandbox {
            meta: Meta {
                name: "r".into(),
                clone: true,
                ..Default::default()
            },
            machine: "sbx-r".into(),
            state: MachineState::Stopped,
            ports: vec![],
        };
        let mut p = plan();
        p.clone = Some(step);
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
}
