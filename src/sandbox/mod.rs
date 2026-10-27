//! Sandboxes: smolvm machines that smolbento created, identified by their `sbx.*` labels.

pub mod create;
pub mod labels;
pub mod name;
pub mod options;
pub mod session;

use anyhow::{Context, Result, anyhow};

use crate::kits::apply::{InstallStep, KitSteps};
use crate::kits::guest;
use crate::smolvm::{
    ExecSpec, Machine, MachineState, NetworkSpec, PublishedPort, Runner, Smolvm, SmolvmError,
};
use crate::workspace::MOUNTLESS_WORKDIR;
use crate::workspace::clone::{SOURCE_MOUNT, WorktreeHead};

pub use create::CreateRequest;
pub use labels::Meta;

/// Started detached as root after each start of a pre-4a docker sandbox (`sbx.docker=true`, no
/// `sbx.kits`). Newer ones get dockerd from the docker kit's startup hook (`kits/docker`).
pub const DOCKER_START: &str = "pgrep -x dockerd >/dev/null || { rm -f /var/run/docker.pid; exec dockerd >/var/log/dockerd.log 2>&1; }";

/// Started detached as root after every start: the kits' startup runner, when the sandbox has one.
pub const STARTUP_START: &str =
    "[ -x /etc/smolbento/startup ] || exit 0; exec /etc/smolbento/startup";

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
pub(crate) fn sh_quote(s: &str) -> String {
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
    vm.update_network(&sb.machine, &plan.network)
        .context("applying the network policy")?;
    vm.start(&sb.machine, plan.branchable, &plan.env, &plan.remove)?;
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

/// What follows `machine start`: the agent user's uid, dockerd for a pre-4a sandbox, the clone,
/// then the kits' startup runner (a no-op without kits; deferred during a kit first start).
fn setup<R: Runner>(vm: &Smolvm<R>, sb: &Sandbox, plan: &StartPlan) -> Result<()> {
    vm.exec_captured(&ExecSpec {
        name: sb.machine.clone(),
        user: Some("root".into()),
        cmd: vec!["sh".into(), "-c".into(), identity_cmd(plan.uid)],
        ..Default::default()
    })
    .context("matching the sandbox's agent user to your host uid")?;
    // The pre-4a path: a docker sandbox created before the docker kit has no startup runner.
    // With kits, the docker kit's startup hook starts dockerd (no second start here).
    if sb.meta.docker && sb.meta.kits.is_empty() {
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
    // A kit first start runs it once its startup scripts are written.
    if plan.kit.is_none() {
        run_startup(vm, sb);
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

/// Creates and starts a new sandbox (the caller checked the name is free), then runs its kit
/// steps. `drop_install_rules` removes the install-phase rules from the policy and returns this
/// sandbox's network without them. A failing kit step removes the sandbox (spec Decision 6).
pub fn create<R: Runner>(
    vm: &Smolvm<R>,
    req: &CreateRequest,
    plan: &StartPlan,
    drop_install_rules: impl FnOnce(&[String]) -> Result<NetworkSpec>,
) -> Result<Sandbox> {
    vm.create(&create::spec(req))?;
    let mut sb = get(vm, &req.name)?;
    let Some(kit) = &plan.kit else {
        start(vm, &sb, plan)?;
        sb.state = MachineState::Running;
        return Ok(sb);
    };
    // A kit sandbox isn't usable until its steps ran, so a failed first start removes it too and
    // the same command can simply run again.
    let steps =
        start(vm, &sb, plan).and_then(|()| first_start(vm, &sb, plan, kit, drop_install_rules));
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
    run_startup(vm, &sb);
    Ok(sb)
}

/// Steps 3–8 of the first start (spec "Data flow" 7); the caller removes the sandbox on error.
fn first_start<R: Runner>(
    vm: &Smolvm<R>,
    sb: &Sandbox,
    plan: &StartPlan,
    kit: &KitFirstStart,
    drop_install_rules: impl FnOnce(&[String]) -> Result<NetworkSpec>,
) -> Result<()> {
    let after_install = || -> Result<()> {
        let mut network = plan.network.clone();
        if !kit.steps.install_rules.is_empty() {
            network = drop_install_rules(&kit.steps.install_rules)
                .context("removing the install-phase network rules")?;
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
    apply_kit_steps(vm, sb, &kit.steps, after_install).map_err(|(_, e)| e)
}

/// Where `apply_kit_steps` failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KitPhase {
    /// An install hook (hooks that ran may have changed the guest).
    Install,
    /// The caller's step between the hooks and the files.
    AfterInstall,
    /// Files, agent context, startup scripts or the kits record.
    Write,
}

/// Applies kit steps to a running sandbox, for a create's first start and for `kit add`: install
/// hooks, then `after_install` (dropping the install-phase rules), then files, agent context, the
/// `startup.d` scripts, the startup runner and the kits record (written whole).
pub fn apply_kit_steps<R: Runner>(
    vm: &Smolvm<R>,
    sb: &Sandbox,
    steps: &KitSteps,
    after_install: impl FnOnce() -> Result<()>,
) -> std::result::Result<(), (KitPhase, anyhow::Error)> {
    let mut run = Steps { vm, sb, n: 0 };
    for step in &steps.install {
        run.install(step).map_err(|e| (KitPhase::Install, e))?;
    }
    after_install().map_err(|e| (KitPhase::AfterInstall, e))?;
    let mut write = || -> Result<()> {
        for script in &steps.files {
            run.run("root", script).context("writing kit files")?;
        }
        for script in &steps.context {
            run.run("root", script).context("writing agent context")?;
        }
        let mut files: Vec<(String, &str, &str)> = steps
            .startup_d
            .iter()
            .map(|(name, body)| {
                (
                    format!("{}/{name}", guest::STARTUP_DIR),
                    body.as_str(),
                    "644",
                )
            })
            .collect();
        files.push((guest::STARTUP_PATH.into(), guest::STARTUP_RUNNER, "755"));
        files.push((guest::KITS_FILE.into(), &steps.kits_record, "644"));
        put_files(vm, sb, &files).context("writing the kits' startup scripts")
    };
    write().map_err(|e| (KitPhase::Write, e))
}

/// Larger scripts are copied in rather than passed as `sh -c` argv, well under Linux's 128 KiB
/// limit per argument.
const INLINE_MAX: usize = 64 * 1024;
const STEP_DIR: &str = "/run/smolbento";

/// Runs guest scripts, numbering the ones copied in.
struct Steps<'a, R: Runner> {
    vm: &'a Smolvm<R>,
    sb: &'a Sandbox,
    n: usize,
}

impl<R: Runner> Steps<'_, R> {
    fn spec(&mut self, user: &str, script: &str) -> Result<ExecSpec> {
        let cmd = if script.len() > INLINE_MAX {
            self.n += 1;
            let path = format!("{STEP_DIR}/step-{}.sh", self.n);
            put_files(self.vm, self.sb, &[(path.clone(), script, "644")])?;
            vec!["sh".into(), path]
        } else {
            vec!["sh".into(), "-c".into(), script.into()]
        };
        Ok(ExecSpec {
            name: self.sb.machine.clone(),
            user: Some(user.into()),
            cmd,
            ..Default::default()
        })
    }

    fn run(&mut self, user: &str, script: &str) -> Result<()> {
        let spec = self.spec(user, script)?;
        self.vm.exec_captured(&spec)?;
        Ok(())
    }

    /// An install step; a failure names it and carries the end of its output.
    fn install(&mut self, step: &InstallStep) -> Result<()> {
        let spec = self.spec(step.user.as_deref().unwrap_or("root"), &step.script)?;
        let out = self
            .vm
            .exec_output(&spec)
            .with_context(|| format!("{} failed", step.label))?;
        if out.code == 0 {
            return Ok(());
        }
        let text = if out.stderr.trim().is_empty() {
            out.stdout.clone()
        } else {
            SmolvmError::from_output(&out).message
        };
        let tail = last_lines(&text, 20);
        if tail.is_empty() {
            anyhow::bail!("{} failed (exit {})", step.label, out.code);
        }
        anyhow::bail!("{} failed:\n{tail}", step.label)
    }
}

/// Writes `(guest path, content, mode)` files as root via host temp files and `machine cp`
/// (which copies single files only).
fn put_files<R: Runner>(
    vm: &Smolvm<R>,
    sb: &Sandbox,
    files: &[(String, &str, &str)],
) -> Result<()> {
    let root = |script: String| {
        vm.exec_captured(&ExecSpec {
            name: sb.machine.clone(),
            user: Some("root".into()),
            cmd: vec!["sh".into(), "-c".into(), script],
            ..Default::default()
        })
    };
    let mut dirs: Vec<String> = files
        .iter()
        .filter_map(|(p, _, _)| std::path::Path::new(p).parent())
        .map(|d| sh_quote(&d.display().to_string()))
        .collect();
    dirs.sort();
    dirs.dedup();
    root(format!("mkdir -p {}", dirs.join(" ")))?;
    let tmp = tempfile::tempdir().context("creating a temp dir")?;
    for (i, (path, content, _)) in files.iter().enumerate() {
        let host = tmp.path().join(i.to_string());
        std::fs::write(&host, content).with_context(|| format!("writing {}", host.display()))?;
        vm.cp(
            &host.display().to_string(),
            &format!("{}:{path}", sb.machine),
        )
        .with_context(|| format!("copying {path} into the sandbox"))?;
    }
    let chmod: Vec<String> = files
        .iter()
        .map(|(p, _, mode)| format!("chmod {mode} {}", sh_quote(p)))
        .collect();
    root(chmod.join(" && "))?;
    Ok(())
}

/// The last `n` lines of `text`.
fn last_lines(text: &str, n: usize) -> String {
    let lines: Vec<&str> = text.trim_end().lines().collect();
    lines[lines.len().saturating_sub(n)..].join("\n")
}

/// Starts the kits' startup runner, detached as root. A failure only warns: the agent can run
/// without its startup hooks, as in sbx.
fn run_startup<R: Runner>(vm: &Smolvm<R>, sb: &Sandbox) {
    let exec = vm.exec_captured(&ExecSpec {
        name: sb.machine.clone(),
        user: Some("root".into()),
        detach: true,
        cmd: vec!["sh".into(), "-c".into(), STARTUP_START.into()],
        ..Default::default()
    });
    if let Err(e) = exec {
        eprintln!(
            "warning: starting the kits' startup hooks in {}: {e:#}",
            sb.name()
        );
    }
}

/// Starts one kit's `startup.d` script, detached as root and logging like the startup runner (a
/// kit added to a running sandbox). A failure only warns, as for `run_startup`.
pub fn run_kit_startup<R: Runner>(vm: &Smolvm<R>, sb: &Sandbox, script: &str) {
    let exec = vm.exec_captured(&ExecSpec {
        name: sb.machine.clone(),
        user: Some("root".into()),
        detach: true,
        cmd: vec![
            "sh".into(),
            "-c".into(),
            format!(
                "mkdir -p /var/log/smolbento && exec sh {} >>/var/log/smolbento/startup.log 2>&1",
                sh_quote(script)
            ),
        ],
        ..Default::default()
    });
    if let Err(e) = exec {
        eprintln!(
            "warning: starting the kit's startup hooks in {}: {e:#}",
            sb.name()
        );
    }
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
            branchable: true,
            kit: None,
        }
    }

    /// The fixture is a pre-4a docker sandbox: `sbx.docker=true` and no `sbx.kits`, so `setup`
    /// starts dockerd itself.
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
            lines[5],
            format!("machine exec --name sbx-claude-myrepo -u root -d -- sh -c {STARTUP_START}")
        );
        assert_eq!(lines.len(), 6, "{lines:#?}");
        assert_eq!(
            vm.runner().envs(),
            vec![vec![("TOK".to_string(), "secret".to_string())]]
        );
        assert_eq!(vm.runner().removed(), vec![vec!["GONE".to_string()]]);
    }

    #[test]
    fn a_docker_kit_sandbox_leaves_dockerd_to_its_startup_runner() {
        let fake = FakeRunner::new();
        fake.ok(
            &["machine", "status"],
            &STATUS
                .replace("\"state\": \"running\"", "\"state\": \"stopped\"")
                .replace(
                    "\"sbx.docker\": \"true\",",
                    "\"sbx.docker\": \"true\", \"sbx.kits\": \"[\\\"builtin:docker\\\"]\",",
                ),
        );
        let vm = Smolvm::new(fake);
        let mut sb = get(&vm, "claude-myrepo").unwrap();
        assert_eq!(sb.meta.kits, ["builtin:docker"]);
        ensure_running(&vm, &mut sb, || Ok(plan())).unwrap();
        let lines = vm.runner().call_lines();
        assert!(
            !lines.iter().any(|l| l.ends_with(DOCKER_START)),
            "no second dockerd start: {lines:#?}"
        );
        assert!(lines.last().unwrap().ends_with(STARTUP_START), "{lines:#?}");
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
        let sb = create(&vm, &req, &plan(), |_| unreachable!()).unwrap();
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
            6,
            "no dockerd for a non-docker sandbox: {lines:?}"
        );
        assert!(lines[5].ends_with(STARTUP_START), "{lines:?}");
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
        // The startup runner follows the clone.
        assert!(lines.last().unwrap().ends_with(STARTUP_START), "{lines:?}");
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
            user: user.map(String::from),
            script: script.into(),
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
    fn create_runs_kit_steps_in_lifecycle_order() {
        let vm = created_vm();
        let dropped = std::cell::RefCell::new(Vec::new());
        create(&vm, &request(), &kit_plan(&[]), |ids| {
            dropped.borrow_mut().extend_from_slice(ids);
            Ok(restricted(&["api.example.com"]))
        })
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
        let runner = exec_line("root", true, STARTUP_START);
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
        create(&vm, &request(), &kit_plan(&["TOK"]), |_| {
            Ok(restricted(&["api.example.com"]))
        })
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
        assert!(
            lines[restart..files]
                .iter()
                .any(|l| l.ends_with("usermod -o -u 501 agent")),
            "setup runs again: {lines:#?}"
        );
        assert_eq!(
            lines.iter().filter(|l| l.ends_with(STARTUP_START)).count(),
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
    fn a_failed_install_hook_removes_the_sandbox() {
        let vm = created_vm();
        let stderr: Vec<String> = (1..=25).map(|i| format!("line {i}")).collect();
        vm.runner().fail(
            &[
                "machine",
                "exec",
                "--name",
                MACHINE,
                "-u",
                "root",
                "--",
                "sh",
                "-c",
                "echo install-1",
            ],
            "EXEC_FAILED",
            &stderr.join("\n"),
        );
        let err = create(&vm, &request(), &kit_plan(&[]), |_| {
            panic!("install rules stay until the hooks succeed")
        })
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
        let err = create(&vm, &request(), &kit_plan(&[]), |_| {
            anyhow::bail!("policy.toml: permission denied")
        })
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
        let err = create(&vm, &request(), &kit_plan(&[]), |_| {
            Ok(restricted(&["api.example.com"]))
        })
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
        let err = create(&vm, &request(), &plan, |_| unreachable!()).unwrap_err();
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
        create(&vm, &request(), &plan, |_| {
            Ok(restricted(&["api.example.com"]))
        })
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
        let uploads = vm.runner().uploads();
        assert!(
            uploads
                .iter()
                .any(|(p, c)| p.ends_with(":/run/smolbento/step-1.sh") && *c == big)
        );
    }

    #[test]
    fn a_plain_start_only_adds_the_detached_startup_runner() {
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
        assert_eq!(lines.len(), 4, "{lines:#?}");
        assert!(lines[2].ends_with("usermod -o -u 501 agent"), "{lines:#?}");
        assert_eq!(
            lines[3],
            "machine exec --name sbx-r -u root -d -- sh -c \
             [ -x /etc/smolbento/startup ] || exit 0; exec /etc/smolbento/startup"
        );
        assert!(STARTUP_START.contains(guest::STARTUP_PATH));
    }

    #[test]
    fn a_failed_startup_runner_exec_is_only_a_warning() {
        let fake = FakeRunner::new();
        fake.ok(&["machine"], "");
        fake.fail(
            &["machine", "exec", "--name", "sbx-r", "-u", "root", "-d"],
            "EXEC_FAILED",
            "no such file",
        );
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
        assert!(
            !vm.runner()
                .call_lines()
                .iter()
                .any(|l| l.starts_with("machine stop")),
            "the sandbox stays up"
        );
    }

    #[test]
    fn a_failed_hook_with_no_stderr_reports_its_stdout() {
        let vm = created_vm();
        vm.runner().on(
            &[
                "machine",
                "exec",
                "--name",
                MACHINE,
                "-u",
                "root",
                "--",
                "sh",
                "-c",
                "echo install-1",
            ],
            crate::smolvm::Output {
                code: 2,
                stdout: "resolving\nE: package not found\n".into(),
                stderr: String::new(),
            },
        );
        let err = create(&vm, &request(), &kit_plan(&[]), |_| unreachable!())
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
            &[
                "machine",
                "exec",
                "--name",
                MACHINE,
                "-u",
                "root",
                "--",
                "sh",
                "-c",
                &identity_cmd(501),
            ],
            "EXEC_FAILED",
            "usermod: busy",
        );
        let err = create(&vm, &request(), &kit_plan(&[]), |_| unreachable!()).unwrap_err();
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
