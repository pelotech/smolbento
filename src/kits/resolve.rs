//! Resolves one workload plus mixins into an ordered, merged `Plan` ready to apply.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, bail};

use crate::kits::args::{ArgValues, expand, expand_value};
use crate::kits::capability;
use crate::kits::host_mount;
use crate::kits::model::{
    AgentContextReq, Cap, CapBody, CredReq, FileReq, Format, Group, Hook, ImageConfig, Kind, Kit,
    Lifecycle, NetRule, Rules, Source, SshPhase,
};
use crate::kits::v3;
use crate::sandbox::Engine;
use crate::skills::Mode;
use crate::ssh_agent::{AgentGrant, PhaseGrant};
use crate::util::union;

#[derive(Debug)]
pub struct Plan {
    /// The workload kit: a built-in agent's or the one given.
    pub workload: Kit,
    /// Dependency order.
    pub mixins: Vec<Kit>,
    /// Kit name to effective args.
    pub args: BTreeMap<String, BTreeMap<String, String>>,
    pub merged: Merged,
    /// Optional capabilities that are skipped.
    pub skipped: Vec<Skipped>,
}

/// One kit's `agent-context` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KitContext {
    pub kit: String,
    /// The contract it was declared under: 1 (a per-kit index) or 2 (inline).
    pub version: u8,
    pub optional: bool,
    pub req: AgentContextReq,
}

/// The version of an `agent-context@N` type; smolbento reads `@1` and `@2` only.
fn context_version(ty: &str) -> u8 {
    if ty.ends_with("@1") { 1 } else { 2 }
}

/// A `volume@1` request: a directory on the sandbox's disk, or a tmpfs with `mode`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Volume {
    pub path: String,
    pub tmpfs: bool,
    pub mode: Option<String>,
}

/// An optional capability smolbento skips: the kit, and what of it (usually its type).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skipped {
    pub kit: String,
    pub what: String,
    /// Why, for the warning.
    pub reason: &'static str,
}

const NOT_SUPPORTED: &str = "not supported";

impl Skipped {
    fn new(kit: &str, what: impl Into<String>) -> Skipped {
        Skipped {
            kit: kit.into(),
            what: what.into(),
            reason: NOT_SUPPORTED,
        }
    }
}

/// Tests compare with `"kit: what"`.
#[cfg(test)]
impl PartialEq<&str> for Skipped {
    fn eq(&self, other: &&str) -> bool {
        format!("{}: {}", self.kit, self.what) == *other
    }
}

impl Plan {
    /// One stderr line per skipped optional capability, when kit warnings are shown.
    pub fn warn_skipped(&self) {
        for w in self.skipped_warnings() {
            crate::kit_warning!("{w}");
        }
    }

    /// A kit whose `network-policy@2` request rules were kept: the plan was resolved for hosted
    /// egress, which alone enforces them.
    pub fn request_rules_kit(&self) -> Option<&str> {
        self.merged
            .network
            .iter()
            .find(|k| rules(&k.install, &k.runtime).any(is_qualified))
            .map(|k| k.kit.as_str())
    }

    /// The same, without the `warning: ` prefix.
    pub fn skipped_warnings(&self) -> Vec<String> {
        self.skipped
            .iter()
            .map(|s| format!("kit {}: skipping {} ({})", s.kit, s.what, s.reason))
            .collect()
    }
}

#[derive(Debug, Default)]
pub struct Merged {
    /// Network rules per kit (each kit's rules are tagged with it in the policy).
    pub network: Vec<KitRules>,
    pub credentials: Vec<KitCred>,
    pub ports: Vec<(u16, bool)>,
    pub volumes: Vec<Volume>,
    /// In kit order.
    pub host_mounts: Vec<HostMount>,
    /// `agent-skills@1` directories, in kit order; `skills::plan` merges a path's requests.
    pub skill_dirs: Vec<SkillDir>,
    /// `agent-skill@1` skills, one per name.
    pub bundled: Vec<Bundled>,
    pub cpus: Option<String>,
    pub memory: Option<String>,
    pub env: Vec<(String, String)>,
    /// `(kit name, hook)` in dependency order.
    pub install_hooks: Vec<(String, Hook)>,
    pub startup_hooks: Vec<(String, Hook)>,
    pub files: Vec<FileReq>,
    /// Every kit's `agent-context` request, in dependency order. `apply` keeps one version's.
    pub contexts: Vec<KitContext>,
    pub git_identity: bool,
    pub long_running: bool,
    /// `dockerd@1`: `Off` unless a kit declares it; one `autoStart: true` makes it `Auto`.
    pub dockerd: Engine,
    /// `ssh-agent@1` entries merged per phase, plus a built-in agent's implicit runtime grant.
    pub ssh_agent: AgentGrant,
    /// The kit that first declared each volume path: a host mount there conflicts with it.
    volume_kits: BTreeMap<String, String>,
    /// The kit that first declared `dockerd@1`: it owns `/var/lib/docker` and below.
    dockerd_kit: Option<String>,
}

const ENGINE_STORE: &str = "/var/lib/docker";
/// Paths reach here canonical: volume@1's cleaned at parse, host-mount@1's required canonical.
fn in_engine_store(path: &str) -> bool {
    std::path::Path::new(path).starts_with(ENGINE_STORE)
}

impl Merged {
    fn add_port(&mut self, container: u16, udp: bool) {
        if !self.ports.contains(&(container, udp)) {
            self.ports.push((container, udp));
        }
    }

    fn add_volume(
        &mut self,
        kit: &str,
        path: &str,
        tmpfs: bool,
        mode: &Option<String>,
    ) -> Result<()> {
        self.check_engine_store(kit, path)?;
        if let Some(h) = self.host_mounts.iter().find(|h| h.path == path) {
            bail!("{}", one_owner(&h.kit, kit, path));
        }
        match self.volumes.iter().find(|v| v.path == path) {
            Some(v) if v.tmpfs != tmpfs || v.mode != *mode => {
                bail!("kit {kit}: volume {path} conflicts with another kit's request")
            }
            Some(_) => {}
            None => {
                self.volumes.push(Volume {
                    path: path.into(),
                    tmpfs,
                    mode: mode.clone(),
                });
                self.volume_kits.insert(path.into(), kit.into());
            }
        }
        Ok(())
    }

    fn add_host_mount(&mut self, k: &Kit, path: &str, mode: &Option<String>) -> Result<()> {
        self.check_engine_store(&k.name, path)?;
        let owner = self.host_mounts.iter().find(|h| h.path == path);
        if let Some(a) = owner.map(|h| &h.kit).or(self.volume_kits.get(path)) {
            bail!("{}", one_owner(a, &k.name, path));
        }
        self.host_mounts.push(HostMount {
            kit: k.name.clone(),
            identity: host_mount::identity(k)?,
            path: path.into(),
            mode: mode.clone(),
        });
        Ok(())
    }

    /// dockerd@1/engine-store-owned: no other kit's volume or host mount sits in the engine store.
    fn check_engine_store(&self, kit: &str, path: &str) -> Result<()> {
        match &self.dockerd_kit {
            Some(d) if in_engine_store(path) => {
                bail!("kit {kit}: {path} is in {ENGINE_STORE}, which kit {d}'s dockerd@1 owns")
            }
            _ => Ok(()),
        }
    }

    /// Elevation and a private, persistent engine store; the engine starts if any kit says so.
    fn add_dockerd(&mut self, kit: &str, auto_start: bool) -> Result<()> {
        if self.dockerd_kit.is_none() {
            if let Some(v) = self.volumes.iter().find(|v| in_engine_store(&v.path)) {
                let owner = self.volume_kits.get(&v.path).map_or("another kit", |o| o);
                bail!(
                    "kit {kit}: dockerd@1 owns {ENGINE_STORE}, but {owner} uses {}",
                    v.path
                );
            }
            if let Some(h) = self.host_mounts.iter().find(|h| in_engine_store(&h.path)) {
                bail!(
                    "kit {kit}: dockerd@1 owns {ENGINE_STORE}, but {} uses {}",
                    h.kit,
                    h.path
                );
            }
            for dir in [ENGINE_STORE, "/var/lib/containerd"] {
                self.add_volume(kit, dir, false, &None)?;
            }
            self.dockerd_kit = Some(kit.into());
        }
        self.dockerd = self.dockerd.max(if auto_start {
            Engine::Auto
        } else {
            Engine::Manual
        });
        Ok(())
    }

    fn add_bundled(&mut self, kit: &str, name: &str, source: &str, optional: bool) -> Result<()> {
        match self.bundled.iter_mut().find(|b| b.name == name) {
            Some(b) if b.source == source => b.optional &= optional,
            Some(b) => bail!(
                "kits {} and {kit} both bundle a skill named {name:?} from different paths",
                b.kit
            ),
            None => self.bundled.push(Bundled {
                kit: kit.into(),
                name: name.into(),
                source: source.into(),
                optional,
            }),
        }
        Ok(())
    }

    /// The largest value any kit states, so a mixin never lowers the workload's (resources@1).
    fn set_resources(&mut self, cpus: &Option<String>, memory: &Option<String>) {
        keep_larger(&mut self.cpus, cpus, |v| v.trim().parse::<f64>().ok());
        keep_larger(&mut self.memory, memory, |v| {
            crate::util::parse_size(v, "memory").ok()
        });
    }
}

/// Sets `current` to `new` unless both parse (`read`) and `current` is at least as large. A value
/// that doesn't parse stays only if no later kit states one, for `apply` to refuse.
fn keep_larger<T: PartialOrd>(
    current: &mut Option<String>,
    new: &Option<String>,
    read: impl Fn(&str) -> Option<T>,
) {
    let Some(n) = new else { return };
    let at_least = |c: &str| matches!((read(c), read(n)), (Some(c), Some(n)) if c >= n);
    if !current.as_deref().is_some_and(at_least) {
        *current = Some(n.clone());
    }
}

fn one_owner(a: &str, b: &str, path: &str) -> String {
    format!("kits {a} and {b} both declare storage at {path}; a host mount has one owner")
}

/// A `host-mount@1` and the kit that declared it, which keys its managed directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostMount {
    /// Kit name.
    pub kit: String,
    /// `host_mount::identity` of the kit.
    pub identity: String,
    pub path: String,
    pub mode: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillDir {
    pub path: String,
    /// The widest mode declared for the path.
    pub mode: Mode,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bundled {
    pub kit: String,
    pub name: String,
    pub source: String,
    pub optional: bool,
}

/// `agent-sessions@2` is exclusive with `@1` across kits too (`v3::check_caps` refuses both in one).
fn check_sessions(all: &[Kit]) -> Result<()> {
    let by = |v: &str| {
        let ty = format!("com.docker.sandbox/agent-sessions@{v}");
        all.iter().find(|k| k.caps.iter().any(|c| c.ty == ty))
    };
    if let (Some(a), Some(b)) = (by("1"), by("2")) {
        bail!(
            "agent-sessions@1 and agent-sessions@2 are exclusive: kits {} and {} declare one each",
            a.name,
            b.name
        );
    }
    Ok(())
}

/// Within one kit, a skills path or a bundled skill name may appear once.
fn check_skill_caps(k: &Kit) -> Result<()> {
    let mut paths = BTreeSet::new();
    let mut names = BTreeSet::new();
    for c in &k.caps {
        match &c.body {
            CapBody::AgentSkills { path, .. } if !paths.insert((c.scope(), path)) => {
                bail!("kit {}: agent-skills@1 names {path} twice", k.name)
            }
            CapBody::AgentSkill { name, .. } if !names.insert((c.scope(), name)) => {
                bail!("kit {}: two agent-skill@1 entries are named {name}", k.name)
            }
            _ => {}
        }
    }
    Ok(())
}

#[derive(Debug)]
pub struct KitRules {
    pub kit: String,
    pub install: Rules,
    pub runtime: Rules,
}

/// One `ssh-agent@1` entry; `kit` is `None` for a built-in agent's implicit grant.
struct SshEntry<'a> {
    kit: Option<&'a str>,
    optional: bool,
    phases: &'a [SshPhase],
    unrestricted: bool,
    sign: &'a [String],
    authenticate: &'a [String],
}

/// sbx's built-in agents (`shell`, …) get the agent at runtime unless it's unavailable.
const BUILT_IN: SshEntry<'static> = SshEntry {
    kit: None,
    optional: true,
    phases: &[SshPhase::Runtime],
    unrestricted: true,
    sign: &[],
    authenticate: &[],
};

/// A built-in agent's own grant, for a create with no plan (`resolve` adds it to a plan).
pub fn built_in_ssh_agent() -> AgentGrant {
    AgentGrant {
        runtime: ssh_phase(&[BUILT_IN], SshPhase::Runtime),
        install: None,
    }
}

#[derive(Debug)]
pub struct KitCred {
    pub kit: String,
    pub optional: bool,
    pub req: CredReq,
}

/// `${{ kit.env.WORKSPACE }}` when there's no sandbox (`kit validate`, tests): the mountless
/// working directory, so a kit validates the same way it applies to a mountless sandbox.
pub const NO_SANDBOX_WORKDIR: &str = crate::workspace::MOUNTLESS_WORKDIR;

/// For `docker.enabled=false`: `kit` without its `dockerd@1` requests. A required one (or one in a
/// required group) refuses the create; an optional one is skipped, with its whole group
/// (SPEC-v3 §7.1.1).
pub fn without_dockerd(kit: &mut Kit) -> Result<Vec<Skipped>> {
    let ty = format!("{}dockerd@1", super::CAP_NS);
    if let Some(c) = kit.caps.iter().find(|c| c.ty == ty && !c.optional) {
        let group =
            (c.group.as_ref()).map_or(String::new(), |g| format!("group {}: ", group_label(g)));
        bail!(
            "kit {}: {group}dockerd@1: Docker is disabled (docker.enabled=false); turn it on with \
             `bento settings set docker.enabled true`",
            kit.name
        );
    }
    const REASON: &str = "Docker is disabled: docker.enabled=false";
    let mut skipped = Vec::new();
    if kit.caps.iter().any(|c| c.ty == ty && c.group.is_none()) {
        skipped.push(Skipped {
            reason: REASON,
            ..Skipped::new(&kit.name, ty.clone())
        });
    }
    kit.caps.retain(|c| c.ty != ty || c.group.is_some());
    // Every required one bailed above, so this only skips: the why and the error go unused.
    skipped.extend(drop_groups(kit, |c| (c.ty == ty).then_some(""), REASON)?);
    Ok(skipped)
}

/// `resolve_for` without a sandbox, for checking kits: `WORKSPACE` is `NO_SANDBOX_WORKDIR`, and
/// egress is smolvm's.
pub fn resolve(workload: Kit, mixins: Vec<Kit>, args: &ArgValues) -> Result<Plan> {
    resolve_for(workload, mixins, args, NO_SANDBOX_WORKDIR, &[], false)
}

/// The workload's `HOME` (sbx@1/honors-image-user): the image's `ENV HOME`, else its user's home,
/// where that's known without the image's passwd file (root's, or the spec's `agent`); `None`
/// when only that file knows.
fn image_home(config: Option<&ImageConfig>) -> Option<String> {
    let Some(c) = config else {
        return Some(super::AGENT_HOME.into());
    };
    if let Some((_, h)) = c.env.iter().rev().find(|(k, _)| k == "HOME") {
        return Some(h.clone());
    }
    match crate::sandbox::labels::split_user(&c.user).0 {
        "agent" => Some(super::AGENT_HOME.into()),
        "" | "0" | "root" => Some("/root".into()),
        _ => None,
    }
}

/// Resolves the kits for a sandbox whose working directory in the guest is `workdir`: v2's
/// `files/workspace` and `${WORKDIR}` expand to it as `${{ kit.env.WORKSPACE }}`. `create_env` is
/// the create's own environment (`-e`), which `${{ kit.env.* }}` reads last. `hosted`: the sandbox
/// may use hosted egress, which enforces `network-policy@2` request rules, unless the kits make it
/// fall back to smolvm's (`falls_back`).
pub fn resolve_for(
    workload: Kit,
    mixins: Vec<Kit>,
    args: &ArgValues,
    workdir: &str,
    create_env: &[(String, String)],
    hosted: bool,
) -> Result<Plan> {
    if workload.kind != Kind::Workload {
        bail!(
            "{}",
            capability::incoherent(&[capability::NO_WORKLOAD.to_string()])
        );
    }
    check_names(&workload, &mixins)?;
    let mut kit_args = BTreeMap::new();
    // The workload, then the mixins: as given until `order` sorts the mixins.
    let mut all: Vec<Kit> = std::iter::once(workload).chain(mixins).collect();
    args.check_unknown(&all)?;
    for k in &all {
        // An optional arg with no value and no default stays out: using it is an error.
        kit_args.insert(k.name.clone(), args.for_kit(k)?);
    }
    let workload = all.remove(0);
    let mixins = order(&workload, all)?;
    let mut all: Vec<Kit> = std::iter::once(workload).chain(mixins).collect();
    let env = merge_env(&all, &kit_args);
    // The final container environment (SPEC-v3 §6.1): the image's, then the kits' exports, then
    // the create's own; `HOME` and `WORKSPACE` last, as the guest has them.
    let image = all[0].config.iter().flat_map(|c| c.env.iter().cloned());
    let mut env_map: BTreeMap<String, String> = image.chain(env.iter().cloned()).collect();
    env_map.extend(create_env.iter().cloned());
    match image_home(all[0].config.as_ref()) {
        Some(h) => env_map.insert("HOME".into(), h),
        None => env_map.remove("HOME"),
    };
    env_map.insert("WORKSPACE".into(), workdir.into());
    // Every declaration is expanded and checked before selection (SPEC-v3 §6, §7.1.1), then
    // groups are selected whole, so nothing after this sees a reference or a skipped group.
    let mut skipped = Vec::new();
    for k in &mut all {
        expand_caps(k, &kit_args[&k.name], &env_map).with_context(|| format!("kit {}", k.name))?;
    }
    // Before groups are selected, so a group the selection drops still counts: refusing a request
    // rule a hosted sandbox could have had is safe, the reverse isn't.
    let hosted = hosted && !all.iter().flat_map(|k| &k.caps).any(falls_back);
    for k in &mut all {
        check_skill_caps(k)?;
        skipped.extend(select_groups(k, hosted)?);
    }
    check_sessions(&all)?;
    check_lifecycle_conflicts(&all, workdir)?;

    let mut merged = Merged {
        env,
        ..Default::default()
    };

    let mut ssh_entries = Vec::new();
    if all[0].is_builtin_agent() {
        ssh_entries.push(BUILT_IN);
    }
    for k in &all {
        for cap in &k.caps {
            match &cap.body {
                CapBody::Unsupported => {
                    if cap.optional {
                        skipped.push(Skipped::new(&k.name, &cap.ty));
                        continue;
                    }
                    bail!("kit {}: {} is not supported by smolbento", k.name, cap.ty);
                }
                CapBody::Credential(c) => {
                    // OAuth without passthrough (sbx's sentinel tokens) needs smolvm support: its
                    // API key part binds as usual, and logins happen inside the sandbox.
                    merged.credentials.push(KitCred {
                        kit: k.name.clone(),
                        optional: cap.optional,
                        req: c.clone(),
                    });
                }
                CapBody::Network { install, runtime } => {
                    let (install, runtime, skip) = enforceable(k, cap, install, runtime, hosted)?;
                    skipped.extend(skip);
                    merged.network.push(KitRules {
                        kit: k.name.clone(),
                        install,
                        runtime,
                    });
                }
                CapBody::Port { container, udp } => merged.add_port(*container, *udp),
                CapBody::Volume { path, tmpfs, mode } => {
                    merged.add_volume(&k.name, path, *tmpfs, mode)?;
                }
                CapBody::HostMount { path, mode } => merged.add_host_mount(k, path, mode)?,
                CapBody::AgentSkills { path, mode } => merged.skill_dirs.push(SkillDir {
                    path: path.clone(),
                    mode: *mode,
                }),
                CapBody::AgentSkill { source, name } => {
                    merged.add_bundled(&k.name, name, source, cap.optional)?;
                }
                CapBody::Resources { cpus, memory } => merged.set_resources(cpus, memory),
                CapBody::Lifecycle(l) => add_lifecycle(&mut merged, k, l, workdir),
                CapBody::AgentContext(c) => merged.contexts.push(KitContext {
                    kit: k.name.clone(),
                    version: context_version(&cap.ty),
                    optional: cap.optional,
                    req: c.clone(),
                }),
                CapBody::SshAgent {
                    phases,
                    unrestricted,
                    sign,
                    authenticate,
                } => ssh_entries.push(SshEntry {
                    kit: Some(k.name.as_str()),
                    optional: cap.optional,
                    phases,
                    unrestricted: *unrestricted,
                    sign,
                    authenticate,
                }),
                CapBody::GitIdentity => merged.git_identity = true,
                CapBody::LongRunning => merged.long_running = true,
                CapBody::Dockerd { auto_start } => merged.add_dockerd(&k.name, *auto_start)?,
                // Nothing to merge; `privileged@1` because a machine already runs its startup
                // steps as root.
                CapBody::Privileged | CapBody::Sbx | CapBody::AgentSessions => {}
                CapBody::Pending => unreachable!("expand_caps reads every pending config"),
            }
        }
    }

    merged.ssh_agent = AgentGrant {
        install: ssh_phase(&ssh_entries, SshPhase::Install),
        runtime: ssh_phase(&ssh_entries, SshPhase::Runtime),
    };
    add_oauth_hosts(&mut merged);

    let mut it = all.into_iter();
    let workload = it.next().expect("workload is first");
    Ok(Plan {
        workload,
        mixins: it.collect(),
        args: kit_args,
        merged,
        skipped,
    })
}

/// Each kit once, names unique (they scope `--kit-arg`s and tag policy rules), and one workload.
/// As in sbx, v2 and v3 kits don't go into one sandbox; the built-in agents are v3 kits, and the
/// shipped docker kit goes with either. For a create, where every kit was just loaded: `kit add`
/// can't tell the format of the kits a sandbox already has.
pub fn check_formats(workload: &Kit, mixins: &[Kit]) -> Result<()> {
    let named: Vec<(&str, Option<Format>)> = std::iter::once(workload)
        .chain(mixins)
        .map(|k| (k.name.as_str(), mixing_format(k)))
        .collect();
    check_named_formats(&named)
}

/// The format `check_formats` counts a kit as: none for the shipped docker kit or a Smolfile.
/// `kit add` records it for each kit of a sandbox.
pub fn mixing_format(k: &Kit) -> Option<Format> {
    match k.source {
        Source::Builtin(_) => None,
        _ => k.format(),
    }
}

/// `check_formats` for kits known by name and format (`kit add`: the sandbox's record).
pub fn check_named_formats(kits: &[(&str, Option<Format>)]) -> Result<()> {
    let names = |want: Format| -> Vec<&str> {
        let of = kits.iter().filter(|(_, f)| *f == Some(want));
        of.map(|(name, _)| *name).collect()
    };
    let (v2, v3) = (names(Format::V2), names(Format::V3));
    if !v3.is_empty() && !v2.is_empty() {
        bail!(
            "cannot mix v3 kits with v1/v2 kits in one sandbox; compositions are single-format \
             (v3: {}; v1/v2: {}). Use a v3 version of the v1/v2 kit",
            v3.join(", "),
            v2.join(", ")
        );
    }
    Ok(())
}

fn check_names(workload: &Kit, mixins: &[Kit]) -> Result<()> {
    let named: Vec<&Kit> = std::iter::once(workload).chain(mixins).collect();
    for (i, k) in named.iter().enumerate() {
        if named[..i].iter().any(|o| o.source == k.source) {
            bail!("{}", capability::listed_twice(k.label()));
        }
    }
    let mut seen = BTreeSet::new();
    for k in named {
        if !seen.insert(k.name.as_str()) {
            bail!("two kits are named {}; rename one of them", k.name);
        }
    }
    if let Some(m) = mixins.iter().find(|m| m.kind == Kind::Workload) {
        bail!(
            "two workloads: {} and {}; pass a workload kit as the agent argument",
            workload.name,
            m.name
        );
    }
    Ok(())
}

/// The kits' env vars in kit order; a later kit's value wins. A kit's own are its plain ones (v2
/// `environment.variables`), then each arg that declares `env:` and has a value (v3, as Docker's
/// claude mixin exports `model` as `CLAUDE_MODEL`); a default counts as a value, an empty one too.
fn merge_env<'a>(
    kits: impl IntoIterator<Item = &'a Kit>,
    kit_args: &BTreeMap<String, BTreeMap<String, String>>,
) -> Vec<(String, String)> {
    let mut env: Vec<(String, String)> = Vec::new();
    let mut set = |name: &String, value: &String| match env.iter_mut().find(|(n, _)| n == name) {
        Some(e) => e.1 = value.clone(),
        None => env.push((name.clone(), value.clone())),
    };
    for k in kits {
        for (name, value) in &k.env {
            set(name, value);
        }
        let values = &kit_args[&k.name];
        for (arg, def) in &k.args {
            if let (Some(name), Some(value)) = (&def.env, values.get(arg)) {
                set(name, value);
            }
        }
    }
    env
}

/// SPEC-v3 §7.1.1: a group is selected only when smolbento can apply every member as asked. A
/// rejected optional group is skipped whole; a rejected required one refuses the kit. The answer
/// is a static list of what smolbento supports, which the spec allows.
fn select_groups(k: &mut Kit, hosted: bool) -> Result<Vec<Skipped>> {
    drop_groups(k, |c| unsupported(c, hosted), NOT_SUPPORTED)
}

/// Drops each group with a member `rejects` (which says why): an optional group is skipped with
/// `reason`, a required one refuses the kit.
fn drop_groups(
    k: &mut Kit,
    rejects: impl Fn(&Cap) -> Option<&'static str>,
    reason: &'static str,
) -> Result<Vec<Skipped>> {
    let mut rejected = Vec::new();
    let mut skipped = Vec::new();
    for c in &k.caps {
        let Some(g) = &c.group else { continue };
        if rejected.contains(&g.index) {
            continue;
        }
        let Some(why) = rejects(c) else {
            continue;
        };
        rejected.push(g.index);
        if !c.optional {
            bail!(
                "kit {}: required group {}: {} {} {why}",
                k.name,
                group_label(g),
                g.member_path(),
                c.ty
            );
        }
        skipped.push(group_skip(&k.name, g, &c.ty, reason));
    }
    k.caps.retain(|c| {
        c.group
            .as_ref()
            .is_none_or(|g| !rejected.contains(&g.index))
    });
    Ok(skipped)
}

/// A group as warnings name it: `capabilities[0] (Feature)`.
fn group_label(g: &Group) -> String {
    match &g.name {
        Some(n) => format!("{} ({n})", g.path()),
        None => g.path(),
    }
}

/// The warning for an optional group skipped for its `ty` member.
fn group_skip(kit: &str, g: &Group, ty: &str, reason: &'static str) -> Skipped {
    let what = format!(
        "optional group {}, for its {} {ty}",
        group_label(g),
        g.member_path()
    );
    Skipped {
        reason,
        ..Skipped::new(kit, what)
    }
}

/// Whether smolbento can provide `c` as asked: `resolve_for` fails a required one it can't.
/// `hosted` as for `resolve_for`.
pub fn supported(c: &Cap, hosted: bool) -> bool {
    unsupported(c, hosted).is_none()
}

/// Why smolbento can't apply `c` as asked, if it can't. `hosted` as for `resolve_for`.
fn unsupported(c: &Cap, hosted: bool) -> Option<&'static str> {
    match c.body {
        CapBody::Unsupported => Some("is not supported by smolbento"),
        _ if qualified(c) && !(hosted && unenforceable(c).is_none()) => {
            Some("has method/path rules, which smolbento doesn't enforce")
        }
        _ => None,
    }
}

/// What makes a sandbox fall back to smolvm egress (see `provision`): an install-only credential.
/// A credential the user also has stays at runtime and doesn't, but that isn't known here.
fn falls_back(c: &Cap) -> bool {
    matches!(&c.body, CapBody::Credential(r) if r.install && !r.runtime)
}

/// The first of a `network-policy@2` capability's request rules that hosted egress can't
/// enforce, and why: one on `*`, or a bounded allow on a host glob.
fn unenforceable(c: &Cap) -> Option<String> {
    use crate::policy::{Decision, rules::Resource};
    let CapBody::Network { install, runtime } = &c.body else {
        return None;
    };
    let rules = [install, runtime].into_iter().flat_map(|r| {
        (r.allow.iter().map(|n| (Decision::Allow, n)))
            .chain(r.deny.iter().map(|n| (Decision::Deny, n)))
    });
    for (decision, n) in rules.filter(|(_, n)| is_qualified(n)) {
        let method = (!n.methods.is_empty()).then(|| n.methods.join(","));
        let paths: Vec<Option<&str>> = if n.paths.is_empty() {
            vec![None]
        } else {
            n.paths.iter().map(|p| Some(p.as_str())).collect()
        };
        let checked = Resource::parse(&n.host)
            .map_err(|e| format!("{e:#}"))
            .and_then(|res| {
                paths.iter().try_for_each(|path| {
                    crate::egress::request_rules::check(
                        decision,
                        std::slice::from_ref(&res),
                        method.as_deref(),
                        *path,
                        None,
                    )
                })
            });
        if let Err(e) = checked {
            return Some(format!("rule on {}: {e}", n.host));
        }
    }
    None
}

/// A `network-policy@2` capability with a method or path rule.
fn qualified(c: &Cap) -> bool {
    let CapBody::Network { install, runtime } = &c.body else {
        return false;
    };
    c.ty.ends_with("network-policy@2") && rules(install, runtime).any(is_qualified)
}

/// Every allow and deny rule of both phases.
fn rules<'a>(install: &'a Rules, runtime: &'a Rules) -> impl Iterator<Item = &'a NetRule> {
    [install, runtime]
        .into_iter()
        .flat_map(|r| r.allow.iter().chain(&r.deny))
}

fn is_qualified(n: &NetRule) -> bool {
    !n.methods.is_empty() || !n.paths.is_empty()
}

/// What of a kit's network rules smolbento can enforce. Hosted egress (`hosted`) enforces
/// `network-policy@2` method and path qualifiers; smolvm's enforces hosts only. A capability whose
/// qualifiers can't be enforced is refused, or, when optional, downgraded to host-only (with a
/// `Skipped` note): allows widen to their host, and qualified denies are dropped, since widening
/// one would block the whole host, the opposite of what the kit asked for.
fn enforceable(
    k: &Kit,
    cap: &Cap,
    install: &Rules,
    runtime: &Rules,
    hosted: bool,
) -> Result<(Rules, Rules, Option<Skipped>)> {
    if !qualified(cap) {
        return Ok((install.clone(), runtime.clone(), None));
    }
    let why = if hosted { unenforceable(cap) } else { None };
    if hosted && why.is_none() {
        return Ok((install.clone(), runtime.clone(), None));
    }
    if !cap.optional {
        let why = why
            .as_deref()
            .unwrap_or("method/path rules are enforced under hosted egress only");
        bail!("kit {}: network-policy@2 {why}", k.name);
    }
    let host_only = |r: &Rules| Rules {
        allow: r
            .allow
            .iter()
            .map(|n| NetRule::host(n.host.clone()))
            .collect(),
        deny: r
            .deny
            .iter()
            .filter(|n| !is_qualified(n))
            .cloned()
            .collect(),
    };
    let dropped = [install, runtime]
        .iter()
        .flat_map(|r| &r.deny)
        .filter(|n| is_qualified(n))
        .count();
    let note = match dropped {
        0 => String::new(),
        1 => "; 1 qualified deny rule dropped".into(),
        d => format!("; {d} qualified deny rules dropped"),
    };
    let skip = Skipped::new(
        &k.name,
        format!("network-policy@2 method/path (host-only{note})"),
    );
    Ok((host_only(install), host_only(runtime), Some(skip)))
}

/// A kit's install and startup hooks and init files. sbx runs a v3 kit's install hooks in a clean
/// environment; its startup hooks, and all of a v2 kit's, get the container's (a v3 startup hook
/// less the runtime-owned names it doesn't list: sbx@1). A relative file path (only a v2 kit's
/// `files/workspace` has one) is under the sandbox's working directory, `workdir`.
fn add_lifecycle(merged: &mut Merged, k: &Kit, l: &Lifecycle, workdir: &str) {
    let tagged = |clean_env: bool, listed_runtime_env: bool| {
        move |h: &Hook| {
            let h = Hook {
                clean_env,
                listed_runtime_env,
                ..h.clone()
            };
            (k.name.clone(), h)
        }
    };
    let v3 = k.format() != Some(Format::V2);
    merged
        .install_hooks
        .extend(l.install.iter().map(tagged(v3, false)));
    merged
        .startup_hooks
        .extend(l.startup.iter().map(tagged(false, v3)));
    merged.files.extend(l.files.iter().map(|f| FileReq {
        path: file_path(f, workdir),
        ..f.clone()
    }));
}

/// Where a lifecycle file goes: a v2 kit's relative path is under `workdir`.
fn file_path(f: &FileReq, workdir: &str) -> String {
    if f.path.starts_with('/') {
        f.path.clone()
    } else {
        format!("{workdir}/{}", f.path)
    }
}

/// tck: lifecycle@1/shared-paths-avoided. Composition refuses two lifecycle entries writing one
/// file path, or two declaring `interactive`, selected groups included; the error names both.
fn check_lifecycle_conflicts(kits: &[Kit], workdir: &str) -> Result<()> {
    let source = |k: &Kit, c: &Cap| match &c.group {
        Some(g) => format!("kit {} {}", k.name, g.member_path()),
        None => format!("kit {} {}", k.name, c.ty),
    };
    let mut seen: Vec<(String, String)> = Vec::new();
    for k in kits {
        for c in &k.caps {
            let CapBody::Lifecycle(l) = &c.body else {
                continue;
            };
            let what = l
                .files
                .iter()
                .map(|f| format!("file {}", file_path(f, workdir)));
            for what in what.chain(l.interactive.then(|| "interactive".to_string())) {
                if let Some((_, first)) = seen.iter().find(|(w, _)| *w == what) {
                    bail!("{first} and {} both declare {what}", source(k, c));
                }
                seen.push((what, source(k, c)));
            }
        }
    }
    Ok(())
}

/// Expands `k`'s `${{ kit.args.* }}` and `${{ kit.env.* }}` references, each once, then checks the
/// result: a config holding one is expanded as a document and read again, strictly (SPEC-v3 §6).
/// A v2 kit's capabilities are configs too, except its credentials; its `files/` are copied as is.
fn expand_caps(
    k: &mut Kit,
    args: &BTreeMap<String, String>,
    env: &BTreeMap<String, String>,
) -> Result<()> {
    let unresolved = unresolved(k, args);
    let ex = |s: &str| expand(s, args, &unresolved, env);
    for c in &mut k.caps {
        if let Some(config) = c.config.take() {
            let config = expand_value(&config, v3::text_fields(&c.ty), &ex)?;
            // A group member is named by its place, as the spec's diagnostics do.
            let at =
                (c.group.as_ref()).map_or(String::new(), |g| format!(" at {}", g.member_path()));
            c.body = v3::body(&c.ty, Some(config))
                .with_context(|| format!("capability {}{at}", c.ty))?;
        }
    }
    v3::check_caps(&k.name, &k.caps)?;
    if k.v2 {
        return Ok(());
    }
    v3::check_mixin_profiles(&k.name, k.kind, &k.caps)
}

/// An OAuth credential's token and resource hosts join its kit's network rules (the first entry
/// for that kit), and its install rules too when the credential is used during install: the guest
/// talks to them itself (passthrough, or a login inside the sandbox).
fn add_oauth_hosts(merged: &mut Merged) {
    let Merged {
        credentials,
        network,
        ..
    } = merged;
    for kc in credentials.iter() {
        let Some(o) = kc.req.oauth.as_ref() else {
            continue;
        };
        let hosts: Vec<NetRule> = o
            .token_host
            .iter()
            .chain(&o.resource_hosts)
            .map(|h| NetRule::host(h.clone()))
            .collect();
        let i = match network.iter().position(|r| r.kit == kc.kit) {
            Some(i) => i,
            None => {
                network.push(KitRules {
                    kit: kc.kit.clone(),
                    install: Rules::default(),
                    runtime: Rules::default(),
                });
                network.len() - 1
            }
        };
        network[i].runtime.allow.extend(hosts.iter().cloned());
        if kc.req.install {
            network[i].install.allow.extend(hosts);
        }
    }
}

/// Merges the `ssh-agent@1` entries for `phase` (kit spec "Composition"): unrestricted when any
/// entry is, else the union of their namespaces and of their `authenticate` entries; required when
/// any entry is.
fn ssh_phase(entries: &[SshEntry], phase: SshPhase) -> Option<PhaseGrant> {
    let es: Vec<&SshEntry> = entries
        .iter()
        .filter(|e| e.phases.contains(&phase))
        .collect();
    if es.is_empty() {
        return None;
    }
    let unrestricted = es.iter().any(|e| e.unrestricted);
    let sign = (!unrestricted).then(|| union(es.iter().flat_map(|e| e.sign)));
    let authenticate = if unrestricted {
        vec![]
    } else {
        union(es.iter().flat_map(|e| e.authenticate))
    };
    let required = es.iter().any(|e| !e.optional);
    let kit = es
        .iter()
        .find(|e| !e.optional)
        .or_else(|| es.iter().find(|e| e.kit.is_some()))
        .and_then(|e| e.kit.map(String::from));
    Some(PhaseGrant {
        sign,
        authenticate,
        required,
        kit,
    })
}

/// The arguments `k` declares that `args` gives no value.
fn unresolved(k: &Kit, args: &BTreeMap<String, String>) -> BTreeSet<String> {
    let missing = k.args.keys().filter(|n| !args.contains_key(*n));
    missing.cloned().collect()
}

/// Checks the set's capabilities like the spec's resolver (SPEC-v3 §5.3: one provider per name,
/// requires met by another kit, a present provider within `integrates`, no `conflicts`), then
/// orders the mixins: providers before the kits that require or integrate with them, otherwise as
/// given. Every problem is reported, one per line.
fn order(workload: &Kit, mixins: Vec<Kit>) -> Result<Vec<Kit>> {
    let all: Vec<&Kit> = std::iter::once(workload).chain(&mixins).collect();
    let mut problems = Vec::new();

    // Normalized name to (kit index, provide), in set order.
    let mut index: BTreeMap<String, Vec<(usize, capability::Provide)>> = BTreeMap::new();
    for (i, k) in all.iter().enumerate() {
        for s in &k.provides {
            match capability::parse_provide(s) {
                Ok(p) => index.entry(p.name.clone()).or_default().push((i, p)),
                Err(e) => problems.push(format!("{}: {e}", k.label())),
            }
        }
    }
    for (name, ps) in &index {
        let mut offers: Vec<(&str, Option<&str>)> = Vec::new();
        let mut owners = BTreeSet::new();
        for (i, p) in ps {
            if owners.insert(*i) {
                offers.push((all[*i].label(), p.version.as_deref()));
            }
        }
        if owners.len() > 1 {
            problems.push(capability::duplicate(name, &offers));
        }
    }
    let others = |name: &str, me: usize| -> Vec<&(usize, capability::Provide)> {
        index
            .get(name)
            .into_iter()
            .flatten()
            .filter(|(i, _)| *i != me)
            .collect()
    };
    // The kit (not `me`) whose provide meets `r`.
    let provider = |r: &capability::Require, me: usize| -> Option<usize> {
        others(&r.name, me)
            .into_iter()
            .find(|(_, p)| capability::satisfies(p, r))
            .map(|(i, _)| *i)
    };
    let offered = |name: &str, me: usize| -> Vec<String> {
        others(name, me)
            .into_iter()
            .map(|(i, p)| capability::describe(p, all[*i].label()))
            .collect()
    };

    let mut deps: Vec<BTreeSet<usize>> = vec![BTreeSet::new(); all.len()];
    // Every kit's `requires`, then every kit's `integrates`: they differ only when unmet.
    for required in [true, false] {
        for (me, k) in all.iter().enumerate() {
            for s in if required { &k.requires } else { &k.integrates } {
                let r = match capability::parse_require(s) {
                    Ok(r) => r,
                    Err(e) => {
                        problems.push(format!("{}: {e}", k.label()));
                        continue;
                    }
                };
                if let Some(p) = provider(&r, me) {
                    deps[me].insert(p);
                } else if !required {
                    let present = offered(&r.name, me);
                    if !present.is_empty() {
                        problems.push(capability::integrates_violated(k.label(), s, &present));
                    }
                } else if let Some(ps) = index.get(&r.name) {
                    let offers: Vec<_> = ps
                        .iter()
                        .map(|(i, p)| capability::describe(p, all[*i].label()))
                        .collect();
                    problems.push(capability::unmet_version(k.label(), s, &offers));
                } else {
                    problems.push(capability::unmet(k.label(), s, &r.name));
                }
            }
        }
    }
    for (me, k) in all.iter().enumerate() {
        for s in &k.conflicts {
            for (i, _) in others(&capability::normalize(s), me) {
                problems.push(capability::conflict(k.label(), s, all[*i].label()));
            }
        }
    }
    if !problems.is_empty() {
        bail!("{}", capability::incoherent(&problems));
    }

    // Index 0 is the workload, always first.
    let mut placed = BTreeSet::from([0]);
    let mut rest: Vec<(usize, Kit)> = mixins
        .into_iter()
        .enumerate()
        .map(|(i, k)| (i + 1, k))
        .collect();
    let mut out = Vec::with_capacity(rest.len());
    while !rest.is_empty() {
        let Some(i) = rest
            .iter()
            .position(|(me, _)| deps[*me].iter().all(|d| placed.contains(d)))
        else {
            let kits: Vec<_> = rest.iter().map(|(_, k)| k.label()).collect();
            bail!("{}", capability::cycle(&kits));
        };
        let (me, k) = rest.remove(i);
        placed.insert(me);
        out.push(k);
    }
    Ok(out)
}

#[cfg(test)]
#[path = "resolve_tests.rs"]
mod tests;
