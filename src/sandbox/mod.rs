//! Sandboxes: smolvm machines that smolbento created, identified by their `sbx.*` labels.

pub mod create;
pub mod env;
pub mod labels;
pub mod name;
pub mod options;
pub mod session;

use anyhow::{Context, Result, anyhow};

use crate::kits::apply::{InstallStep, KitSteps};
use crate::kits::guest;
use crate::policy::compile::HOST_GATEWAY;
use crate::smolvm::{
    ExecSpec, Machine, MachineState, NetworkSpec, PublishedPort, PullProgress, Runner, Smolvm,
    SmolvmError,
};
use crate::workspace::MOUNTLESS_WORKDIR;
use crate::workspace::clone::{SOURCE_MOUNT, WorktreeHead};

pub use create::CreateRequest;
pub use labels::Meta;

/// Started detached as root after each start of a pre-4a docker sandbox (`sbx.docker=true`, no
/// `sbx.kits`). Newer ones get dockerd from the docker kit's startup hook (`kits/docker`).
pub const DOCKER_START: &str = "pgrep -x dockerd >/dev/null || { rm -f /var/run/docker.pid; exec dockerd >/var/log/dockerd.log 2>&1; }";

/// Gives the image's `agent` user the host user's uid and its primary group the host gid.
/// virtiofs passes host uids through, so without this uid 1000 can't write a workspace owned by,
/// say, uid 501 (verified on smolvm 1.32.2). Idempotent; skipped for images without an `agent`
/// user.
pub fn identity_cmd(uid: u32, gid: u32) -> String {
    format!(
        "id -u agent >/dev/null 2>&1 || exit 0; {group}[ \"$(id -u agent)\" = {uid} ] || usermod -o -u {uid} agent",
        group = group_cmd("agent", gid),
    )
}

/// Gives `user`'s primary group the host gid. On Linux, virtiofs creates files as the caller's
/// uid and gid, and the unprivileged VMM can't take on another gid, so any other gid gets EPERM
/// even in a workspace the uid owns. Root's group stays 0; images without `groupmod` (busybox)
/// are left alone. `user` is a shell word.
fn group_cmd(user: &str, gid: u32) -> String {
    format!(
        "g=$(id -g {user}); [ \"$g\" = 0 ] || [ \"$g\" = {gid} ] || \
         ! command -v groupmod >/dev/null 2>&1 || groupmod -o -g {gid} \"$(id -gn {user})\" || exit; "
    )
}

/// Names the host `host.docker.internal` in the guest, as sbx does: the guest gateway reaches the
/// host's loopback for sandboxes with host access (`policy::compile::HOST_GATEWAY`). Idempotent.
pub fn hosts_cmd() -> String {
    hosts_script("/etc/hosts")
}

/// `hosts_cmd` against the hosts file at `file` (tests use a temp file). The leading newline keeps
/// the line apart when the file doesn't end in one.
fn hosts_script(file: &str) -> String {
    format!(
        "grep -q ' host.docker.internal$' {file} || \
         printf '\\n%s\\n' '{HOST_GATEWAY} host.docker.internal' >> {file}"
    )
}

/// Where a start records the account a v3 workload's image user resolved to, so a numeric
/// `USER` still names it after its uid moved to the host's (or `agent`'s move took it).
pub const IMAGE_USER_FILE: &str = "/etc/smolbento/image-user";

/// `identity_cmd` for a v3 workload's image user (`sbx.user`: `name`, `uid` or either with
/// `:group`). Run before `identity_cmd`, so a `USER 1000` image still finds `agent` there.
pub fn image_user_cmd(user: &str, uid: u32, gid: u32) -> String {
    image_user_script(user, uid, gid, "/etc")
}

/// `image_user_cmd` against the passwd file and record under `etc` (tests use a temp dir). The
/// first start resolves the user (a uid through `passwd`) and records the account; later starts
/// read the record. Root keeps uid 0. Exits `UNMAPPED` when there's no account or no `usermod`.
fn image_user_script(user: &str, uid: u32, gid: u32, etc: &str) -> String {
    let token = user.split(':').next().unwrap_or(user);
    format!(
        "f={file}; n=; [ -r \"$f\" ] && read -r n < \"$f\"; \
         if [ -z \"$n\" ]; then n={token}; case \"$n\" in *[!0-9]*) ;; \
         *) n=$(awk -F: -v u=\"$n\" '$3 == u {{ print $1; exit }}' {passwd});; esac; \
         [ -n \"$n\" ] && mkdir -p {dir} && echo \"$n\" > \"$f\"; fi; \
         [ -n \"$n\" ] && u=$(id -u \"$n\" 2>/dev/null) || exit {UNMAPPED}; \
         [ \"$u\" = 0 ] && exit 0; {group}[ \"$u\" = {uid} ] && exit 0; \
         command -v usermod >/dev/null 2>&1 || exit {UNMAPPED}; usermod -o -u {uid} \"$n\"",
        group = group_cmd("\"$n\"", gid),
        file = sh_quote(&format!("{etc}/smolbento/image-user")),
        dir = sh_quote(&format!("{etc}/smolbento")),
        passwd = sh_quote(&format!("{etc}/passwd")),
        token = sh_quote(token),
    )
}

/// The user `run` and `exec` use for a v3 workload: `sbx.user`, except that a non-root uid is
/// replaced by the account the start recorded for it (keeping any `:group`). Without a record
/// (the uid has no passwd entry; the start warned) the raw uid.
pub fn launch_user<R: Runner>(vm: &Smolvm<R>, sb: &Sandbox) -> Option<String> {
    let spec = sb.meta.user.clone()?;
    let (user, group) = match spec.split_once(':') {
        Some((u, g)) => (u, Some(g)),
        None => (spec.as_str(), None),
    };
    if user.is_empty() || !user.bytes().all(|b| b.is_ascii_digit()) || user.parse() == Ok(0u32) {
        return Some(spec);
    }
    // The guest wrote the record, so it only counts as a plain account name.
    let Some(name) = read_guest_file(vm, sb, IMAGE_USER_FILE).filter(|n| is_account_name(n)) else {
        return Some(spec);
    };
    Some(match group {
        Some(g) => format!("{name}:{g}"),
        None => name,
    })
}

/// A POSIX-style account name: `[A-Za-z_][A-Za-z0-9_.-]*` with an optional trailing `$`, at
/// most 32 characters. Nothing that `-u` could read as a flag, a group or more than one word.
fn is_account_name(name: &str) -> bool {
    let body = name.strip_suffix('$').unwrap_or(name);
    let mut bytes = body.bytes();
    name.len() <= 32
        && bytes
            .next()
            .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        && bytes.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

/// A small guest file's first line via `machine cp` (no guest shell needed); `None` when it's
/// missing or empty.
fn read_guest_file<R: Runner>(vm: &Smolvm<R>, sb: &Sandbox, path: &str) -> Option<String> {
    let dir = tempfile::tempdir().ok()?;
    let local = dir.path().join("file");
    vm.cp(
        &format!("{}:{path}", sb.machine),
        &local.display().to_string(),
    )
    .ok()?;
    let text = std::fs::read_to_string(&local).ok()?;
    let line = text.lines().next()?.trim();
    (!line.is_empty()).then(|| line.to_string())
}

/// `image_user_cmd`'s exit code when it can't map the user.
const UNMAPPED: i32 = 3;

/// Runs `image_user_cmd` as root. Returns the warning for a user it couldn't map: the agent then
/// runs with the image's uid, which may not be able to write the host workspace.
pub fn map_image_user<R: Runner>(
    vm: &Smolvm<R>,
    sb: &Sandbox,
    user: &str,
    uid: u32,
    gid: u32,
) -> Result<Option<String>> {
    let out = vm.exec_output(&ExecSpec {
        name: sb.machine.clone(),
        user: Some("root".into()),
        cmd: vec!["sh".into(), "-c".into(), image_user_cmd(user, uid, gid)],
        ..Default::default()
    })?;
    match out.code {
        0 => Ok(None),
        UNMAPPED => Ok(Some(format!(
            "warning: {}: couldn't map the image user {user} to your uid; the workspace may not \
             be writable",
            sb.name()
        ))),
        _ => Err(anyhow::anyhow!(SmolvmError::from_output(&out).message))
            .context("matching the sandbox's image user to your host uid"),
    }
}

pub fn host_uid() -> u32 {
    // SAFETY: getuid has no preconditions and cannot fail.
    unsafe { libc::getuid() }
}

pub fn host_gid() -> u32 {
    // SAFETY: getgid has no preconditions and cannot fail.
    unsafe { libc::getgid() }
}

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

/// What follows `machine start`: a v3 workload's image user's uid, then the agent user's, dockerd
/// for a pre-4a sandbox, the clone, then the kits' startup hooks (a no-op without kits; deferred
/// during a kit first start). A failed blocking startup hook fails the start.
fn setup<R: Runner>(vm: &Smolvm<R>, sb: &Sandbox, plan: &StartPlan) -> Result<()> {
    if let Some(user) = &sb.meta.user
        && let Some(w) = map_image_user(vm, sb, user, plan.uid, plan.gid)?
    {
        eprintln!("{w}");
    }
    vm.exec_captured(&ExecSpec {
        name: sb.machine.clone(),
        user: Some("root".into()),
        cmd: vec!["sh".into(), "-c".into(), identity_cmd(plan.uid, plan.gid)],
        ..Default::default()
    })
    .context("matching the sandbox's agent user to your host uid")?;
    // Not fatal: an image without a writable /etc/hosts still works, just without the name.
    if let Err(e) = vm.exec_captured(&ExecSpec {
        name: sb.machine.clone(),
        user: Some("root".into()),
        cmd: vec!["sh".into(), "-c".into(), hosts_cmd()],
        ..Default::default()
    }) {
        eprintln!(
            "warning: {}: couldn't add host.docker.internal to /etc/hosts: {e:#}",
            sb.name()
        );
    }
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
    // A kit first start runs them once its startup scripts are written.
    if plan.kit.is_none() {
        run_startup(vm, sb, None)?;
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
/// `on` hears what the start and the kit steps are doing.
pub fn create<R: Runner>(
    vm: &Smolvm<R>,
    req: &CreateRequest,
    plan: &StartPlan,
    drop_install_rules: impl FnOnce(&[String]) -> Result<NetworkSpec>,
    on: &mut dyn FnMut(Event),
) -> Result<Sandbox> {
    vm.create(&create::spec(req))?;
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
    let after_install = || -> Result<()> {
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
/// `startup.d` scripts, the startup runner and the kits record (written whole). `on` hears
/// `Install` for each kit: before its first install hook, and after the hooks for kits with none.
pub fn apply_kit_steps<R: Runner>(
    vm: &Smolvm<R>,
    sb: &Sandbox,
    steps: &KitSteps,
    after_install: impl FnOnce() -> Result<()>,
    on: &mut dyn FnMut(Event),
) -> std::result::Result<(), (KitPhase, anyhow::Error)> {
    let mut run = Steps { vm, sb, n: 0 };
    let mut told: Vec<&str> = Vec::new();
    for step in &steps.install {
        if let Some(kit) = step.kit.as_deref()
            && told.last() != Some(&kit)
        {
            on(Event::Install(kit));
            told.push(kit);
        }
        run.install(step).map_err(|e| (KitPhase::Install, e))?;
    }
    // The kits record's first column is each kit's name.
    for kit in steps
        .kits_record
        .lines()
        .filter_map(|l| l.split('\t').next())
    {
        if !told.contains(&kit) {
            on(Event::Install(kit));
            told.push(kit);
        }
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
    /// The exec for `script`, and the guest path it was copied to (if it was).
    fn spec(&mut self, user: &str, script: &str) -> Result<(ExecSpec, Option<String>)> {
        let (cmd, copied) = if script.len() > INLINE_MAX {
            self.n += 1;
            let path = format!("{STEP_DIR}/step-{}.sh", self.n);
            put_files(self.vm, self.sb, &[(path.clone(), script, "644")])?;
            (vec!["sh".into(), path.clone()], Some(path))
        } else {
            (vec!["sh".into(), "-c".into(), script.into()], None)
        };
        let spec = ExecSpec {
            name: self.sb.machine.clone(),
            user: Some(user.into()),
            cmd,
            ..Default::default()
        };
        Ok((spec, copied))
    }

    /// Removes a copied-in script once it ran, as root (`/run/smolbento` is root's). Best effort:
    /// the step's own result is what matters.
    fn remove(&self, copied: Option<String>) {
        if let Some(path) = copied {
            let _ = self.vm.exec_captured(&ExecSpec {
                name: self.sb.machine.clone(),
                user: Some("root".into()),
                cmd: vec!["rm".into(), "-f".into(), path],
                ..Default::default()
            });
        }
    }

    fn run(&mut self, user: &str, script: &str) -> Result<()> {
        let (spec, copied) = self.spec(user, script)?;
        let result = self.vm.exec_captured(&spec);
        self.remove(copied);
        result?;
        Ok(())
    }

    /// An install step; a failure names it and carries the end of its output.
    fn install(&mut self, step: &InstallStep) -> Result<()> {
        let (spec, copied) = self.spec(step.user.as_deref().unwrap_or("root"), &step.script)?;
        let out = self.vm.exec_output(&spec);
        self.remove(copied);
        let out = out.with_context(|| format!("{} failed", step.label))?;
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

/// The startup runner's command, as root; `script` limits it to one kit's `startup.d` script. A
/// no-op without kits.
pub fn startup_cmd(script: Option<&str>) -> String {
    let script = script
        .map(|s| format!(" {}", sh_quote(s)))
        .unwrap_or_default();
    format!(
        "[ -x {p} ] || exit 0; exec {p}{script}",
        p = guest::STARTUP_PATH
    )
}

/// Runs the kits' startup hooks (or one kit's `script`) as sbx does on every start: one pass in
/// kit order that waits for each blocking hook and starts each background one detached at its
/// position. A failed blocking hook is an error with sbx's text (its output is in the guest's
/// startup log).
pub fn run_startup<R: Runner>(vm: &Smolvm<R>, sb: &Sandbox, script: Option<&str>) -> Result<()> {
    let what = "running the kits' startup hooks";
    let out = vm
        .exec_output(&ExecSpec {
            name: sb.machine.clone(),
            user: Some("root".into()),
            cmd: vec!["sh".into(), "-c".into(), startup_cmd(script)],
            ..Default::default()
        })
        .context(what)?;
    if out.code != 0 {
        // The runner writes only to its log; a smolvm error envelope means smolvm failed. Any
        // other stderr comes from the guest, so the start gets sbx's text.
        if let Some(e) = SmolvmError::from_json(&out) {
            return Err(anyhow!(e.message).context(what));
        }
        anyhow::bail!("kit startup exited with code {}", out.code);
    }
    Ok(())
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
        assert!(lines[4].ends_with(&hosts_cmd()), "{lines:#?}");
        assert_eq!(
            lines[5],
            format!("machine exec --name sbx-claude-myrepo -u root -d -- sh -c {DOCKER_START}")
        );
        assert_eq!(
            lines[6],
            format!(
                "machine exec --name sbx-claude-myrepo -u root -- sh -c {}",
                startup_cmd(None)
            )
        );
        assert_eq!(lines.len(), 7, "{lines:#?}");
        assert_eq!(
            vm.runner().envs(),
            vec![vec![("TOK".to_string(), "secret".to_string())]]
        );
        assert_eq!(vm.runner().removed(), vec![vec!["GONE".to_string()]]);
    }

    #[test]
    fn every_start_names_the_host_after_the_agent_user() {
        let fake = FakeRunner::new();
        fake.ok(
            &["machine", "status"],
            &STATUS.replace("\"state\": \"running\"", "\"state\": \"stopped\""),
        );
        let vm = Smolvm::new(fake);
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

    #[test]
    fn a_read_only_etc_hosts_warns_and_the_start_goes_on() {
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
                "--",
                "sh",
                "-c",
                &hosts_cmd(),
            ],
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
        let fake = FakeRunner::new();
        fake.ok(
            &["machine", "status"],
            &STATUS.replace("\"state\": \"running\"", "\"state\": \"stopped\""),
        );
        let vm = Smolvm::new(fake);
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
        assert_eq!(lines.len(), 8, "{lines:#?}");
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
        let fake = FakeRunner::new();
        fake.ok(&["machine", "status"], STATUS);
        let vm = Smolvm::new(fake);
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
        let fake = FakeRunner::new();
        fake.ok(&["machine", "status"], STATUS);
        let vm = Smolvm::new(fake);
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
        assert!(
            lines.last().unwrap().ends_with(&startup_cmd(None)),
            "{lines:#?}"
        );
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
            7,
            "no dockerd for a non-docker sandbox: {lines:?}"
        );
        assert!(lines[6].ends_with(&startup_cmd(None)), "{lines:?}");
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
            kit: Some("k".into()),
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
                "Install(\"docker\")"
            ]
        );
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
        assert_eq!(lines.len(), 5, "{lines:#?}");
        assert!(lines[2].ends_with("usermod -o -u 501 agent"), "{lines:#?}");
        assert!(lines[3].ends_with(&hosts_cmd()), "{lines:#?}");
        // A no-op without kits (no runner).
        assert_eq!(
            lines[4],
            "machine exec --name sbx-r -u root -- sh -c \
             [ -x /etc/smolbento/startup ] || exit 0; exec /etc/smolbento/startup"
        );
    }

    /// The startup runner in `machine`, answering with exit `code`.
    fn failing_startup(fake: &FakeRunner, machine: &str, code: i32) {
        fake.on(
            &[
                "machine",
                "exec",
                "--name",
                machine,
                "-u",
                "root",
                "--",
                "sh",
                "-c",
                &startup_cmd(None),
            ],
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
                &identity_cmd(501, 20),
            ],
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
