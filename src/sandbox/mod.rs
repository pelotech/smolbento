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
use crate::workspace::clone::{SOURCE_MOUNT, WorktreeHead};

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
    pub head: Option<WorktreeHead>,
    /// Host remotes to copy (local ones and credentials already left out).
    pub remotes: Vec<(String, String)>,
}

impl CloneStep {
    /// The clone dir and its `.git`, quoted for `sh -c`.
    fn quoted(&self) -> (String, String) {
        (sh_quote(&self.dir), sh_quote(&format!("{}/.git", self.dir)))
    }
}

/// Single-quotes `s` for `sh -c`.
fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// As root: the volume is root-owned and may hold `lost+found`, which `git clone` won't clone into.
fn clone_prep_cmd(step: &CloneStep) -> String {
    let (d, git) = step.quoted();
    let lf = sh_quote(&format!("{}/lost+found", step.dir));
    format!("[ -d {git} ] && exit 0; rmdir {lf} 2>/dev/null; chown agent {d}")
}

/// As `agent`: sbx's clone command (skipped once cloned), then its remote copy, which runs on
/// every start so a failed add is retried and host remote changes arrive (as sbx's setup script).
/// A detached worktree's commit is checked out after the clone (a local clone copies every object,
/// so commits made while detached are there too). If that checkout still fails, the clone keeps
/// its default HEAD, with a warning, rather than failing every start. Only a hex commit id takes
/// that path: it's echoed unquoted inside the warning.
fn clone_cmd(step: &CloneStep) -> String {
    let (d, git) = step.quoted();
    let clone = format!("git -c safe.directory={SOURCE_MOUNT} clone -q");
    let clone = match &step.head {
        Some(WorktreeHead::Branch(b)) => {
            format!("{clone} --branch {} {SOURCE_MOUNT} {d}", sh_quote(b))
        }
        Some(WorktreeHead::Detached(c)) if c.bytes().all(|b| b.is_ascii_hexdigit()) => format!(
            "{{ {clone} --no-checkout {SOURCE_MOUNT} {d} || exit 1; \
             git -C {d} checkout -q --detach {q} -- 2>/dev/null || {{ \
             git -C {d} reset -q --hard || {{ rm -rf {git}; exit 1; }}; \
             echo \"warning: commit {short} isn't in the clone; the agent starts \
             from $(git -C {d} symbolic-ref -q --short HEAD || echo HEAD) instead\" >&2; }}; }}",
            q = sh_quote(c),
            short = c.get(..12).unwrap_or(c),
        ),
        _ => format!("{clone} {SOURCE_MOUNT} {d}"),
    };
    let mut s = format!("set -e; [ -d {git} ] || {clone}; cd {d}");
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
/// A failed setup step stops the machine again: left running half set up, later commands would
/// skip `start` and never retry it.
pub fn start<R: Runner>(vm: &Smolvm<R>, sb: &Sandbox, plan: &StartPlan) -> Result<()> {
    vm.update_network(&sb.machine, &plan.network)
        .context("applying the network policy")?;
    vm.start(&sb.machine, &plan.env, &plan.remove)?;
    if let Err(e) = setup(vm, sb, plan) {
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

/// What follows `machine start`: the agent user's uid, dockerd, then the clone.
fn setup<R: Runner>(vm: &Smolvm<R>, sb: &Sandbox, plan: &StartPlan) -> Result<()> {
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
    if let Some(step) = &plan.clone {
        for w in run_clone(vm, sb, step)? {
            eprintln!("{w}");
        }
    }
    Ok(())
}

/// Returns the guest's `warning:` lines for the caller to print: the detached-commit fallback's,
/// and any git prints itself (worth seeing too). The rest of git's stderr stays quiet.
fn run_clone<R: Runner>(vm: &Smolvm<R>, sb: &Sandbox, step: &CloneStep) -> Result<Vec<String>> {
    let mut warnings = Vec::new();
    for (user, cmd) in [("root", clone_prep_cmd(step)), ("agent", clone_cmd(step))] {
        let out = vm
            .exec_captured(&ExecSpec {
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
        warnings.extend(
            out.stderr
                .lines()
                .filter(|l| l.starts_with("warning: "))
                .map(String::from),
        );
    }
    Ok(warnings)
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
        assert_eq!(lines[2], "machine start -n sbx-claude-myrepo --branchable");
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
    fn a_failed_setup_step_stops_the_machine() {
        let fake = FakeRunner::new();
        fake.ok(
            &["machine", "status"],
            &STATUS.replace("\"state\": \"running\"", "\"state\": \"stopped\""),
        );
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
        assert_eq!(lines[3], "machine start -n sbx-claude-myrepo --branchable");
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
            &[
                "machine", "exec", "--name", "sbx-r", "-u", "root", "--", "sh", "-c", &prep,
            ],
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
}
