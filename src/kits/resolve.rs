//! Resolves one workload plus mixins into an ordered, merged `Plan` ready to apply.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, bail};

use crate::bridge::agent::{AgentGrant, PhaseGrant};
use crate::kits::args::{ArgValues, expand};
use crate::kits::capability;
use crate::kits::host_mount;
use crate::kits::model::{
    AgentContextReq, CapBody, CredReq, FileReq, Hook, HookCmd, Kind, Kit, NetRule, Rules, SshPhase,
};

/// The agent user's home in the platform floor; the host can't see the guest's real env.
const AGENT_HOME: &str = "/home/agent";

#[derive(Debug)]
pub struct Plan {
    /// The agent preset as a synthetic workload kit, or a workload kit.
    pub workload: Kit,
    /// Dependency order.
    pub mixins: Vec<Kit>,
    /// Kit name to effective args.
    pub args: BTreeMap<String, BTreeMap<String, String>>,
    pub merged: Merged,
    /// Optional capabilities that are skipped.
    pub skipped: Vec<Skipped>,
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
}

impl Skipped {
    fn new(kit: &str, what: impl Into<String>) -> Skipped {
        Skipped {
            kit: kit.into(),
            what: what.into(),
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
    /// One stderr line per skipped optional capability.
    pub fn warn_skipped(&self) {
        for w in self.skipped_warnings() {
            eprintln!("warning: {w}");
        }
    }

    /// The same, without the `warning: ` prefix.
    pub fn skipped_warnings(&self) -> Vec<String> {
        self.skipped
            .iter()
            .map(|s| format!("kit {}: skipping {} (not supported)", s.kit, s.what))
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
    /// `agent-skills@1` directories, one per path (widest mode).
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
    pub contexts: Vec<(String, AgentContextReq)>,
    pub git_identity: bool,
    pub long_running: bool,
    pub privileged: bool,
    /// `ssh-agent@1` entries merged per phase, plus a built-in agent's implicit runtime grant.
    pub ssh_agent: AgentGrant,
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
    pub readwrite: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bundled {
    pub kit: String,
    pub name: String,
    pub source: String,
    pub optional: bool,
}

/// Within one kit, a skills path or a bundled skill name may appear once.
fn check_skill_caps(k: &Kit) -> Result<()> {
    let mut paths = BTreeSet::new();
    let mut names = BTreeSet::new();
    for c in &k.caps {
        match &c.body {
            CapBody::AgentSkills { path, .. } if !paths.insert(path) => {
                bail!("kit {}: agent-skills@1 names {path} twice", k.name)
            }
            CapBody::AgentSkill { name, .. } if !names.insert(name) => {
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
        runtime: ssh_phase(&[BUILT_IN], SshPhase::Runtime, &mut vec![])
            .expect("the built-in grant has no authenticate limits"),
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

/// `resolve_for` without a sandbox, for checking kits: `WORKSPACE` is `NO_SANDBOX_WORKDIR`.
pub fn resolve(workload: Kit, mixins: Vec<Kit>, args: &ArgValues) -> Result<Plan> {
    resolve_for(workload, mixins, args, NO_SANDBOX_WORKDIR)
}

/// Resolves the kits for a sandbox whose working directory in the guest is `workdir`: v2's
/// `files/workspace` and `${WORKDIR}` expand to it as `${{ kit.env.WORKSPACE }}`.
pub fn resolve_for(
    workload: Kit,
    mixins: Vec<Kit>,
    args: &ArgValues,
    workdir: &str,
) -> Result<Plan> {
    if workload.kind != Kind::Workload {
        bail!(
            "{}",
            capability::incoherent(&[capability::NO_WORKLOAD.to_string()])
        );
    }
    // Names scope `--kit-arg`s and tag policy rules. An agent preset isn't a kit, so a kit may
    // share its name.
    use crate::kits::model::Source;
    let named: Vec<&Kit> = std::iter::once(&workload)
        .filter(|w| !matches!(w.source, Source::Preset(_)))
        .chain(&mixins)
        .collect();
    for (i, k) in named.iter().enumerate() {
        if named[..i].iter().any(|o| o.source == k.source) {
            bail!("{}", capability::listed_twice(k.label()));
        }
    }
    let mut seen = BTreeSet::new();
    for k in named {
        if !seen.insert(k.name.as_str()) {
            // Most likely a user's own docker kit beside the shipped one a Docker image gets.
            let shipped = std::iter::once(&workload)
                .chain(&mixins)
                .any(|k| k.source == Source::Builtin("docker"));
            if k.name == "docker" && shipped {
                bail!(
                    "two kits are named docker: yours and the shipped one a Docker-enabled image \
                     gets; rename your kit, or have it provide docker \
                     (`provides: [docker@<version>]`) to replace the shipped one"
                );
            }
            bail!("two kits are named {}", k.name);
        }
    }
    if let Some(m) = mixins.iter().find(|m| m.kind == Kind::Workload) {
        bail!(
            "two workloads: {} and {}; pass a workload kit as the agent argument",
            workload.name,
            m.name
        );
    }
    // Args first: a `provides` entry may name one (`claude@${{ kit.args.version }}`), and
    // ordering parses the expanded entries.
    let mut workload = workload;
    let mut mixins = mixins;
    let mut kit_args = BTreeMap::new();
    let unordered: Vec<Kit> = std::iter::once(workload.clone())
        .chain(mixins.iter().cloned())
        .collect();
    args.check_unknown(&unordered)?;
    for k in &unordered {
        // An optional arg with no value and no default stays out: using it is an error.
        kit_args.insert(k.name.clone(), args.for_kit(k)?);
    }
    for k in std::iter::once(&mut workload).chain(mixins.iter_mut()) {
        expand_provides(k, &kit_args[&k.name])?;
    }
    let mixins = order(&workload, mixins)?;

    let all: Vec<Kit> = std::iter::once(workload.clone())
        .chain(mixins.iter().cloned())
        .collect();

    let mut merged = Merged::default();
    for k in &all {
        for (name, value) in &k.env {
            match merged.env.iter_mut().find(|(n, _)| n == name) {
                Some(e) => e.1 = value.clone(),
                None => merged.env.push((name.clone(), value.clone())),
            }
        }
    }
    let mut env_map: BTreeMap<String, String> = merged.env.iter().cloned().collect();
    env_map.insert("HOME".into(), AGENT_HOME.into());
    env_map.insert("WORKSPACE".into(), workdir.into());

    let mut skipped = Vec::new();
    let mut ssh_entries = Vec::new();
    if matches!(workload.source, Source::Preset(_)) {
        ssh_entries.push(BUILT_IN);
    }
    // The kit that first declared each volume path: a host mount there conflicts with it.
    let mut volume_kits: BTreeMap<String, String> = BTreeMap::new();
    let one_owner = |a: &str, b: &str, path: &str| {
        format!("kits {a} and {b} both declare storage at {path}; a host mount has one owner")
    };
    for k in &all {
        let a = &kit_args[&k.name];
        let unresolved: BTreeSet<String> = k
            .args
            .keys()
            .filter(|n| !a.contains_key(*n))
            .cloned()
            .collect();
        let ex = |s: &str| -> Result<String> {
            expand(s, a, &unresolved, &env_map).with_context(|| format!("kit {}", k.name))
        };
        check_skill_caps(k)?;
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
                    if c.oauth.as_ref().is_some_and(|o| !o.passthrough) {
                        if cap.optional {
                            skipped.push(Skipped::new(&k.name, &cap.ty));
                            continue;
                        }
                        bail!(
                            "kit {}: {} oauth without passthrough is not supported by smolbento",
                            k.name,
                            cap.ty
                        );
                    }
                    merged.credentials.push(KitCred {
                        kit: k.name.clone(),
                        optional: cap.optional,
                        req: c.clone(),
                    });
                }
                CapBody::Network { install, runtime } => {
                    // Method and path qualifiers can't be enforced, only hosts can.
                    let is_qualified = |n: &NetRule| !n.methods.is_empty() || !n.paths.is_empty();
                    let qualified = [install, runtime]
                        .iter()
                        .flat_map(|r| r.allow.iter().chain(&r.deny))
                        .any(is_qualified);
                    // Allows widen to their host. Qualified denies are dropped: widening one
                    // would block the whole host, the opposite of what the kit asked for.
                    let host_only = |r: &Rules| Rules {
                        allow: r
                            .allow
                            .iter()
                            .map(|n| NetRule {
                                host: n.host.clone(),
                                methods: vec![],
                                paths: vec![],
                            })
                            .collect(),
                        deny: r
                            .deny
                            .iter()
                            .filter(|n| !is_qualified(n))
                            .cloned()
                            .collect(),
                    };
                    let (install, runtime) = if qualified && cap.ty.ends_with("network-policy@2") {
                        if !cap.optional {
                            bail!(
                                "kit {}: network-policy@2 method/path rules are not enforced by \
                                 smolbento",
                                k.name
                            );
                        }
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
                        skipped.push(Skipped::new(
                            &k.name,
                            format!("network-policy@2 method/path (host-only{note})"),
                        ));
                        (host_only(install), host_only(runtime))
                    } else {
                        (install.clone(), runtime.clone())
                    };
                    merged.network.push(KitRules {
                        kit: k.name.clone(),
                        install,
                        runtime,
                    });
                }
                CapBody::Port { container, udp } => {
                    if !merged.ports.contains(&(*container, *udp)) {
                        merged.ports.push((*container, *udp));
                    }
                }
                CapBody::Volume { path, tmpfs, mode } => {
                    if let Some(h) = merged.host_mounts.iter().find(|h| &h.path == path) {
                        bail!("{}", one_owner(&h.kit, &k.name, path));
                    }
                    match merged.volumes.iter().find(|v| &v.path == path) {
                        Some(v) if v.tmpfs != *tmpfs || v.mode != *mode => bail!(
                            "kit {}: volume {path} conflicts with another kit's request",
                            k.name
                        ),
                        Some(_) => {}
                        None => {
                            merged.volumes.push(Volume {
                                path: path.clone(),
                                tmpfs: *tmpfs,
                                mode: mode.clone(),
                            });
                            volume_kits.insert(path.clone(), k.name.clone());
                        }
                    }
                }
                CapBody::HostMount { path, mode } => {
                    let owner = merged.host_mounts.iter().find(|h| &h.path == path);
                    if let Some(a) = owner.map(|h| &h.kit).or(volume_kits.get(path)) {
                        bail!("{}", one_owner(a, &k.name, path));
                    }
                    merged.host_mounts.push(HostMount {
                        kit: k.name.clone(),
                        identity: host_mount::identity(k)?,
                        path: path.clone(),
                        mode: mode.clone(),
                    });
                }
                CapBody::AgentSkills { path, readwrite } => {
                    match merged.skill_dirs.iter_mut().find(|d| &d.path == path) {
                        Some(d) => d.readwrite |= readwrite,
                        None => merged.skill_dirs.push(SkillDir {
                            path: path.clone(),
                            readwrite: *readwrite,
                        }),
                    }
                }
                CapBody::AgentSkill { source, name } => {
                    match merged.bundled.iter_mut().find(|b| &b.name == name) {
                        Some(b) if &b.source == source => b.optional &= cap.optional,
                        Some(b) => bail!(
                            "kits {} and {} both bundle a skill named {name:?} from different paths",
                            b.kit,
                            k.name
                        ),
                        None => merged.bundled.push(Bundled {
                            kit: k.name.clone(),
                            name: name.clone(),
                            source: source.clone(),
                            optional: cap.optional,
                        }),
                    }
                }
                CapBody::Resources { cpus, memory } => {
                    if cpus.is_some() {
                        merged.cpus = cpus.clone();
                    }
                    if memory.is_some() {
                        merged.memory = memory.clone();
                    }
                }
                CapBody::Lifecycle(l) => {
                    for h in &l.install {
                        merged
                            .install_hooks
                            .push((k.name.clone(), expand_hook(h, &ex)?));
                    }
                    for h in &l.startup {
                        merged
                            .startup_hooks
                            .push((k.name.clone(), expand_hook(h, &ex)?));
                    }
                    for f in &l.files {
                        // Only text can hold `${{ }}` references; other bytes pass through.
                        let content = match std::str::from_utf8(&f.content) {
                            Ok(text) => ex(text)?.into_bytes(),
                            Err(_) => f.content.clone(),
                        };
                        merged.files.push(FileReq {
                            path: ex(&f.path)?,
                            content,
                            ..f.clone()
                        });
                    }
                }
                CapBody::AgentContext(c) => {
                    merged.contexts.push((
                        k.name.clone(),
                        AgentContextReq {
                            content: ex(&c.content)?,
                            ..c.clone()
                        },
                    ));
                }
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
                CapBody::Privileged => merged.privileged = true,
                CapBody::Sbx | CapBody::AgentSessions => {}
            }
        }
    }

    merged.ssh_agent = AgentGrant {
        install: ssh_phase(&ssh_entries, SshPhase::Install, &mut skipped)?,
        runtime: ssh_phase(&ssh_entries, SshPhase::Runtime, &mut skipped)?,
    };

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

/// Merges the `ssh-agent@1` entries for `phase` (kit spec "Composition"): unrestricted when any
/// entry is, else the union of their namespaces; required when any entry is. `authenticate`
/// limits (Phase 5g) can't be enforced yet: under a bounded merge a required entry with them
/// refuses, an optional one is skipped.
fn ssh_phase(
    entries: &[SshEntry],
    phase: SshPhase,
    skipped: &mut Vec<Skipped>,
) -> Result<Option<PhaseGrant>> {
    let mut es: Vec<&SshEntry> = entries
        .iter()
        .filter(|e| e.phases.contains(&phase))
        .collect();
    if !es.iter().any(|e| e.unrestricted) {
        for e in es.iter().filter(|e| !e.authenticate.is_empty()) {
            let kit = e.kit.unwrap_or("?");
            if !e.optional {
                bail!("kit {kit}: ssh-agent@1 authenticate limits aren't supported yet");
            }
            let note = Skipped::new(
                kit,
                format!(
                    "com.docker.sandbox/ssh-agent@1 with authenticate limits in the {} phase",
                    phase.as_str()
                ),
            );
            if !skipped.contains(&note) {
                skipped.push(note);
            }
        }
        es.retain(|e| e.authenticate.is_empty());
    }
    if es.is_empty() {
        return Ok(None);
    }
    let sign = if es.iter().any(|e| e.unrestricted) {
        None
    } else {
        let mut union: Vec<String> = Vec::new();
        for ns in es.iter().flat_map(|e| e.sign) {
            if !union.contains(ns) {
                union.push(ns.clone());
            }
        }
        Some(union)
    };
    let required = es.iter().any(|e| !e.optional);
    let kit = es
        .iter()
        .find(|e| !e.optional)
        .or_else(|| es.iter().find(|e| e.kit.is_some()))
        .and_then(|e| e.kit.map(String::from));
    Ok(Some(PhaseGrant {
        sign,
        required,
        kit,
    }))
}

fn expand_hook(h: &Hook, ex: &dyn Fn(&str) -> Result<String>) -> Result<Hook> {
    let command = match &h.command {
        HookCmd::Shell(s) => HookCmd::Shell(ex(s)?),
        HookCmd::Argv(v) => HookCmd::Argv(v.iter().map(|s| ex(s)).collect::<Result<_>>()?),
    };
    Ok(Hook {
        command,
        ..h.clone()
    })
}

/// Expands the arg references in `k.provides` (the only capability field that may carry them).
fn expand_provides(k: &mut Kit, args: &BTreeMap<String, String>) -> Result<()> {
    if !k.provides.iter().any(|s| capability::has_arg_ref(s)) {
        return Ok(());
    }
    let unresolved: BTreeSet<String> = k
        .args
        .keys()
        .filter(|n| !args.contains_key(*n))
        .cloned()
        .collect();
    let env = BTreeMap::new();
    let provides = k
        .provides
        .iter()
        .map(|s| expand(s, args, &unresolved, &env))
        .collect::<Result<Vec<_>>>()
        .with_context(|| format!("kit {}", k.name))?;
    k.provides = provides;
    Ok(())
}

/// Stable topological sort: repeatedly take the first mixin whose requirements are provided.
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
    for (me, k) in all.iter().enumerate() {
        for s in &k.requires {
            let r = match capability::parse_require(s) {
                Ok(r) => r,
                Err(e) => {
                    problems.push(format!("{}: {e}", k.label()));
                    continue;
                }
            };
            match provider(&r, me) {
                Some(p) => {
                    deps[me].insert(p);
                }
                None if index.contains_key(&r.name) => problems.push(capability::unmet_version(
                    k.label(),
                    s,
                    &index[&r.name]
                        .iter()
                        .map(|(i, p)| capability::describe(p, all[*i].label()))
                        .collect::<Vec<_>>(),
                )),
                None => problems.push(capability::unmet(k.label(), s, &r.name)),
            }
        }
    }
    for (me, k) in all.iter().enumerate() {
        for s in &k.integrates {
            let r = match capability::parse_require(s) {
                Ok(r) => r,
                Err(e) => {
                    problems.push(format!("{}: {e}", k.label()));
                    continue;
                }
            };
            let present = offered(&r.name, me);
            match provider(&r, me) {
                Some(p) => {
                    deps[me].insert(p);
                }
                None if !present.is_empty() => {
                    problems.push(capability::integrates_violated(k.label(), s, &present))
                }
                None => {}
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
mod tests {
    use super::*;
    use crate::bridge::agent::PhaseGrant;
    use crate::kits::model::{ArgDef, Cap, Lifecycle, NetRule, OAuthReq, Source, SshPhase};

    fn base(name: &str, kind: Kind) -> Kit {
        Kit::new(name, kind, Source::Registry(name.into()))
    }
    fn mixin(name: &str) -> Kit {
        base(name, Kind::Mixin)
    }
    fn workload(name: &str) -> Kit {
        base(name, Kind::Workload)
    }

    trait KitExt {
        fn requires(self, r: &[&str]) -> Self;
        fn provides(self, p: &[&str]) -> Self;
        fn cap(self, ty: &str, optional: bool, body: CapBody) -> Self;
    }
    impl KitExt for Kit {
        fn requires(mut self, r: &[&str]) -> Self {
            self.requires = r.iter().map(|s| s.to_string()).collect();
            self
        }
        fn provides(mut self, p: &[&str]) -> Self {
            self.provides = p.iter().map(|s| s.to_string()).collect();
            self
        }
        fn cap(mut self, ty: &str, optional: bool, body: CapBody) -> Self {
            self.caps.push(Cap {
                ty: ty.into(),
                optional,
                body,
            });
            self
        }
    }

    /// Every kit's runtime network rules, in kit order.
    fn runtime(p: &Plan) -> Rules {
        let mut all = Rules::default();
        for k in &p.merged.network {
            all.allow.extend(k.runtime.allow.iter().cloned());
            all.deny.extend(k.runtime.deny.iter().cloned());
        }
        all
    }

    /// A kit the user named by `reference`.
    fn typed(mut k: Kit, reference: &str) -> Kit {
        k.reference = Some(reference.into());
        k
    }
    /// One problem in sbx's coherence block.
    fn incoherent(problem: &str) -> String {
        format!("resolve: the kit set is not coherent:\n  - {problem}")
    }

    fn run(w: Kit, m: Vec<Kit>) -> Result<Plan> {
        resolve(w, m, &ArgValues::default())
    }
    fn names(p: &Plan) -> Vec<&str> {
        p.mixins.iter().map(|k| k.name.as_str()).collect()
    }
    fn rule(host: &str) -> NetRule {
        NetRule {
            host: host.into(),
            methods: vec![],
            paths: vec![],
        }
    }
    fn vol(path: &str, tmpfs: bool) -> CapBody {
        CapBody::Volume {
            path: path.into(),
            tmpfs,
            mode: None,
        }
    }
    fn shell_hook(s: &str) -> Hook {
        Hook {
            command: HookCmd::Shell(s.into()),
            user: None,
            env: vec![],
            background: false,
            clean_env: true,
        }
    }

    #[test]
    fn mixins_follow_requires_not_flag_order() {
        let a = mixin("a").requires(&["b"]);
        let b = mixin("b").provides(&["b"]);
        let p = run(workload("w"), vec![a, b]).unwrap();
        assert_eq!(names(&p), ["b", "a"]);
    }

    #[test]
    fn independent_mixins_keep_given_order() {
        let p = run(workload("w"), vec![mixin("z"), mixin("a")]).unwrap();
        assert_eq!(names(&p), ["z", "a"]);
    }

    #[test]
    fn a_mixin_may_require_what_the_workload_provides() {
        let w = workload("w").provides(&["node"]);
        let p = run(w, vec![mixin("a").requires(&["node"])]).unwrap();
        assert_eq!(names(&p), ["a"]);
    }

    #[test]
    fn a_provide_naming_a_kit_arg_expands_before_ordering() {
        let mut c = mixin("c").provides(&["claude@${{ kit.args.version }}"]);
        c.args.insert(
            "version".into(),
            ArgDef {
                default: Some("2.1.0".into()),
                ..Default::default()
            },
        );
        let u = mixin("u").requires(&["claude >= 2.0"]);
        let p = run(workload("w"), vec![u.clone(), c.clone()]).unwrap();
        assert_eq!(names(&p), ["c", "u"]);
        assert_eq!(p.mixins[0].provides, ["claude@2.1.0"]);
        let v = ArgValues::parse(&[], &["version=1.9.0".into()]).unwrap();
        let e = resolve(workload("w"), vec![u, c.clone()], &v).unwrap_err();
        assert!(format!("{e:#}").contains("only offers"), "{e:#}");
        c.args.get_mut("version").unwrap().default = None;
        let e = run(workload("w"), vec![c]).unwrap_err();
        assert_eq!(
            format!("{e:#}"),
            "kit c: create-phase kit arg \"version\" has no resolved value"
        );
    }

    #[test]
    fn duplicate_provides_fail_like_sbx_at_any_versions() {
        let a = typed(mixin("a").provides(&["x@1.0.0"]), "./chkdupa");
        let b = mixin("b").provides(&["com.docker.kit/x@2.0"]);
        let e = run(workload("w"), vec![a, b]).unwrap_err();
        assert_eq!(
            format!("{e:#}"),
            "resolve: the kit set is not coherent:\n  - capability \"com.docker.kit/x\" is \
             provided by more than one kit: ./chkdupa (1.0.0), b (2.0); one name has one owner, so \
             drop the redundant kit"
        );
        let a = mixin("a").provides(&["x"]);
        let b = mixin("b").provides(&["x@1"]);
        let e = run(workload("w"), vec![a, b]).unwrap_err();
        assert!(
            format!("{e:#}").contains(": a (unversioned), b (1);"),
            "{e:#}"
        );
    }

    #[test]
    fn unmet_requires_fails_like_sbx() {
        let a = typed(mixin("a").requires(&["nothing >= 1.0.0"]), "./chkreq");
        let e = run(workload("w"), vec![a]).unwrap_err();
        assert_eq!(
            format!("{e:#}"),
            "resolve: the kit set is not coherent:\n  - ./chkreq requires \"nothing >= 1.0.0\" but \
             nothing in the set provides it; add a kit that provides com.docker.kit/nothing"
        );
    }

    #[test]
    fn a_require_is_met_only_by_a_version_in_its_constraints() {
        let w = workload("w").provides(&["node@20.11.1"]);
        let ok = mixin("a").requires(&["node >= 20.0.0, < 21.0.0"]);
        assert_eq!(names(&run(w.clone(), vec![ok]).unwrap()), ["a"]);
        let qualified = mixin("a").requires(&["com.docker.kit/node = 20.11.1"]);
        assert_eq!(names(&run(w.clone(), vec![qualified]).unwrap()), ["a"]);

        let too_new = mixin("a").requires(&["node >= 21"]);
        let e = run(w, vec![too_new]).unwrap_err();
        assert_eq!(
            format!("{e:#}"),
            incoherent("a requires \"node >= 21\" but the set only offers node@20.11.1 (from w)")
        );
        // An unversioned provide satisfies only an unconstrained require.
        let w = workload("w").provides(&["node"]);
        assert!(run(w.clone(), vec![mixin("a").requires(&["node"])]).is_ok());
        let e = run(w, vec![mixin("a").requires(&["node > 0"])]).unwrap_err();
        assert_eq!(
            format!("{e:#}"),
            incoherent(
                "a requires \"node > 0\" but the set only offers node (unversioned, from w)"
            )
        );
        // Another namespace's name never matches the default one.
        let w = workload("w").provides(&["com.example/node@20"]);
        assert!(run(w, vec![mixin("a").requires(&["node"])]).is_err());
    }

    #[test]
    fn a_kit_cannot_meet_its_own_require() {
        let a = mixin("a").provides(&["x@1"]).requires(&["x"]);
        let e = run(workload("w"), vec![a]).unwrap_err();
        assert_eq!(
            format!("{e:#}"),
            incoherent("a requires \"x\" but the set only offers x@1 (from a)")
        );
    }

    #[test]
    fn every_problem_is_reported_and_bad_entries_name_their_kit() {
        let a = typed(mixin("a").requires(&["x", "Y"]), "./a");
        let e = run(workload("w"), vec![a]).unwrap_err();
        assert_eq!(
            format!("{e:#}"),
            "resolve: the kit set is not coherent:\n  - ./a requires \"x\" but nothing in the set \
             provides it; add a kit that provides com.docker.kit/x\n  - ./a: requires entry \"Y\": \
             invalid capability name \"Y\""
        );
    }

    #[test]
    fn a_present_provider_must_meet_integrates_and_conflicts_must_be_absent() {
        let w = workload("w").provides(&["docker-engine@24.0.7"]);
        let mut a = mixin("a");
        a.integrates = vec!["docker-engine >= 25.0.0".into()];
        assert!(run(workload("bare"), vec![a.clone()]).is_ok());
        let e = run(w, vec![a]).unwrap_err();
        assert_eq!(
            format!("{e:#}"),
            incoherent(
                "a integrates with \"docker-engine >= 25.0.0\" but the set only offers \
                 docker-engine@24.0.7 (from w); upgrade the provider or drop it from the set"
            )
        );

        let w = workload("w").provides(&["podman@5"]);
        let mut a = mixin("a");
        a.conflicts = vec!["podman".into()];
        let e = run(w, vec![a]).unwrap_err();
        assert_eq!(
            format!("{e:#}"),
            incoherent("a conflicts with \"podman\", which w provides; the two cannot compose")
        );
    }

    #[test]
    fn a_met_integrates_orders_like_requires() {
        let mut a = mixin("a");
        a.integrates = vec!["b >= 1".into()];
        let b = mixin("b").provides(&["b@1.2"]);
        assert_eq!(names(&run(workload("w"), vec![a, b]).unwrap()), ["b", "a"]);
    }

    #[test]
    fn circular_requires_fail_like_sbx() {
        let a = typed(mixin("a").requires(&["b"]).provides(&["a@1"]), "./chkcyca");
        let b = typed(mixin("b").requires(&["a"]).provides(&["b@1"]), "./chkcycb");
        let e = run(workload("w"), vec![a, b]).unwrap_err();
        assert_eq!(
            format!("{e:#}"),
            "resolve: dependency cycle among ./chkcyca, ./chkcycb"
        );
    }

    #[test]
    fn a_kit_listed_twice_fails_like_sbx() {
        let a = || typed(mixin("a"), "./chkallow");
        let e = run(workload("w"), vec![a(), a()]).unwrap_err();
        assert_eq!(format!("{e:#}"), "kit ./chkallow is listed more than once");
        // The same kit by another spelling is still listed twice; sbx names the later one.
        let e = run(workload("w"), vec![a(), typed(mixin("a"), "./chkallow/")]).unwrap_err();
        assert_eq!(format!("{e:#}"), "kit ./chkallow/ is listed more than once");
        let docker = || crate::kits::load::builtin("docker").unwrap().unwrap();
        let e = run(workload("w"), vec![docker(), docker()]).unwrap_err();
        assert_eq!(format!("{e:#}"), "kit docker is listed more than once");
    }

    #[test]
    fn a_mixin_as_the_workload_and_two_kits_of_one_name_are_rejected() {
        let e = run(mixin("m"), vec![]).unwrap_err();
        assert_eq!(
            format!("{e:#}"),
            "resolve: the kit set is not coherent:\n  - no workload kit in the set; every \
             composition needs exactly one kind: workload base"
        );
        let mut other = mixin("a");
        other.source = Source::Registry("other/a".into());
        let e = run(workload("w"), vec![mixin("a"), other.clone()]).unwrap_err();
        assert_eq!(format!("{e:#}"), "two kits are named a");
        let e = run(workload("a"), vec![other]).unwrap_err();
        assert_eq!(format!("{e:#}"), "two kits are named a");
        let shipped = crate::kits::load::builtin("docker").unwrap().unwrap();
        let e = run(workload("w"), vec![mixin("docker"), shipped]).unwrap_err();
        assert_eq!(
            format!("{e:#}"),
            "two kits are named docker: yours and the shipped one a Docker-enabled image gets; \
             rename your kit, or have it provide docker (`provides: [docker@<version>]`) to \
             replace the shipped one"
        );
        // A preset agent's name is free for a kit.
        let mut preset = workload("claude");
        preset.source = Source::Preset("img:1".into());
        run(preset, vec![mixin("claude")]).unwrap();
    }

    #[test]
    fn a_second_workload_is_rejected() {
        let e = run(workload("w"), vec![workload("other")]).unwrap_err();
        assert_eq!(
            format!("{e:#}"),
            "two workloads: w and other; pass a workload kit as the agent argument"
        );
    }

    #[test]
    fn a_required_unsupported_capability_fails_closed() {
        let k = mixin("m").cap(
            "com.docker.sandbox/usb-device@1",
            false,
            CapBody::Unsupported,
        );
        let e = run(workload("w"), vec![k]).unwrap_err();
        assert_eq!(
            format!("{e:#}"),
            "kit m: com.docker.sandbox/usb-device@1 is not supported by smolbento"
        );
    }

    #[test]
    fn an_optional_unsupported_capability_is_skipped() {
        let k = mixin("m").cap(
            "com.docker.sandbox/usb-device@1",
            true,
            CapBody::Unsupported,
        );
        let p = run(workload("w"), vec![k]).unwrap();
        assert_eq!(p.skipped, ["m: com.docker.sandbox/usb-device@1"]);
    }

    const SSH: &str = "com.docker.sandbox/ssh-agent@1";

    fn grant(sign: Option<&[&str]>, required: bool, kit: Option<&str>) -> Option<PhaseGrant> {
        Some(PhaseGrant::new(sign, required, kit))
    }
    fn preset() -> Kit {
        let mut w = workload("shell");
        w.source = Source::Preset("img:1".into());
        w
    }

    #[test]
    fn a_built_in_agent_gets_an_implicit_optional_runtime_grant() {
        let p = run(preset(), vec![]).unwrap();
        assert_eq!(
            p.merged.ssh_agent,
            AgentGrant {
                runtime: grant(None, false, None),
                install: None,
            }
        );
        // The same grant a create with no plan uses.
        assert_eq!(built_in_ssh_agent(), p.merged.ssh_agent);
        // A workload kit gets nothing unless it asks.
        assert!(
            run(workload("w"), vec![])
                .unwrap()
                .merged
                .ssh_agent
                .is_empty()
        );
    }

    #[test]
    fn ssh_agent_grants_merge_per_phase() {
        use SshPhase::{Install, Runtime};
        // Bounded entries union their namespaces; required wins and names its kit.
        let a = mixin("a").cap(SSH, true, CapBody::ssh_agent(&[Runtime], &["git"], &[]));
        let b = mixin("b").cap(
            SSH,
            false,
            CapBody::ssh_agent(&[Install, Runtime], &["file", "git"], &[]),
        );
        let p = run(workload("w"), vec![a, b]).unwrap();
        assert_eq!(
            p.merged.ssh_agent,
            AgentGrant {
                install: grant(Some(&["file", "git"]), true, Some("b")),
                runtime: grant(Some(&["git", "file"]), true, Some("b")),
            }
        );

        // Unrestricted wins over bounded; optional entries name the first kit.
        let a = mixin("a").cap(SSH, true, CapBody::ssh_agent(&[Runtime], &["git"], &[]));
        let b = mixin("b").cap(SSH, true, CapBody::ssh_agent(&[Runtime], &[], &[]));
        let p = run(workload("w"), vec![a, b]).unwrap();
        assert_eq!(p.merged.ssh_agent.runtime, grant(None, false, Some("a")));
        assert_eq!(p.merged.ssh_agent.install, None);

        // A built-in agent's implicit grant is unrestricted; a kit's bounded entry joins it.
        let m = mixin("m").cap(SSH, false, CapBody::ssh_agent(&[Runtime], &["git"], &[]));
        let p = run(preset(), vec![m]).unwrap();
        assert_eq!(p.merged.ssh_agent.runtime, grant(None, true, Some("m")));
    }

    #[test]
    fn authenticate_limits_refuse_a_required_entry_and_skip_an_optional_one() {
        use SshPhase::Runtime;
        let req = mixin("m").cap(
            SSH,
            false,
            CapBody::ssh_agent(&[Runtime], &["git"], &["github.com"]),
        );
        let e = run(workload("w"), vec![req.clone()]).unwrap_err();
        assert_eq!(
            format!("{e:#}"),
            "kit m: ssh-agent@1 authenticate limits aren't supported yet"
        );

        let opt = mixin("o").cap(
            SSH,
            true,
            CapBody::ssh_agent(&[Runtime], &[], &["github.com"]),
        );
        let plain = mixin("p").cap(SSH, true, CapBody::ssh_agent(&[Runtime], &["git"], &[]));
        let p = run(workload("w"), vec![opt, plain]).unwrap();
        assert_eq!(
            p.merged.ssh_agent.runtime,
            grant(Some(&["git"]), false, Some("p"))
        );
        assert_eq!(
            p.skipped_warnings(),
            [
                "kit o: skipping com.docker.sandbox/ssh-agent@1 with authenticate limits in the \
                 runtime phase (not supported)"
            ]
        );

        // Under an unrestricted grant for the phase, the limits don't matter.
        let p = run(preset(), vec![req]).unwrap();
        assert_eq!(p.merged.ssh_agent.runtime, grant(None, true, Some("m")));
        assert!(p.skipped.is_empty());
    }

    #[test]
    fn an_optional_authenticate_entry_is_skipped_only_in_bounded_phases() {
        use SshPhase::{Install, Runtime};
        // `o` spans both phases; `u` makes runtime unrestricted, so only install skips `o`.
        let o = mixin("o").cap(
            SSH,
            true,
            CapBody::ssh_agent(&[Install, Runtime], &["git"], &["github.com"]),
        );
        let u = mixin("u").cap(SSH, true, CapBody::ssh_agent(&[Runtime], &[], &[]));
        let p = run(workload("w"), vec![o, u]).unwrap();
        assert_eq!(p.merged.ssh_agent.install, None);
        assert_eq!(p.merged.ssh_agent.runtime, grant(None, false, Some("o")));
        assert_eq!(
            p.skipped_warnings(),
            [
                "kit o: skipping com.docker.sandbox/ssh-agent@1 with authenticate limits in the \
                 install phase (not supported)"
            ]
        );
    }

    fn cred(oauth: Option<OAuthReq>) -> CapBody {
        CapBody::Credential(CredReq {
            service: "svc".into(),
            install: false,
            runtime: true,
            env: None,
            inject: vec![],
            oauth,
        })
    }
    fn oauth(passthrough: bool) -> Option<OAuthReq> {
        Some(OAuthReq {
            passthrough,
            token_host: None,
            resource_hosts: vec![],
        })
    }

    #[test]
    fn oauth_passthrough_is_accepted_and_without_is_not() {
        let ty = "com.docker.sandbox/credential@1";
        let ok = mixin("m").cap(ty, false, cred(oauth(true)));
        assert_eq!(
            run(workload("w"), vec![ok])
                .unwrap()
                .merged
                .credentials
                .len(),
            1
        );

        let bad = mixin("m").cap(ty, false, cred(oauth(false)));
        let e = run(workload("w"), vec![bad]).unwrap_err();
        assert!(
            format!("{e:#}").contains("kit m: com.docker.sandbox/credential@1 oauth without passthrough is not supported by smolbento"),
            "{e:#}"
        );

        let opt = mixin("m").cap(ty, true, cred(oauth(false)));
        let p = run(workload("w"), vec![opt]).unwrap();
        assert_eq!(p.skipped, ["m: com.docker.sandbox/credential@1"]);
        assert!(p.merged.credentials.is_empty());
    }

    #[test]
    fn network_rules_union_and_deny_is_kept() {
        let n = |allow: &str, deny: &str| CapBody::Network {
            install: Rules::default(),
            runtime: Rules {
                allow: vec![rule(allow)],
                deny: vec![rule(deny)],
            },
        };
        let w = workload("w").cap("n@1", false, n("a.com", "bad.com"));
        let m = mixin("m").cap("n@1", false, n("b.com", "worse.com"));
        let p = run(w, vec![m]).unwrap();
        let hosts = |r: &[NetRule]| r.iter().map(|x| x.host.clone()).collect::<Vec<_>>();
        assert_eq!(hosts(&runtime(&p).allow), ["a.com", "b.com"]);
        assert_eq!(hosts(&runtime(&p).deny), ["bad.com", "worse.com"]);
        let per_kit: Vec<(&str, Vec<String>)> = p
            .merged
            .network
            .iter()
            .map(|k| (k.kit.as_str(), hosts(&k.runtime.allow)))
            .collect();
        assert_eq!(
            per_kit,
            [
                ("w", vec!["a.com".to_string()]),
                ("m", vec!["b.com".into()])
            ]
        );
    }

    #[test]
    fn network_policy_2_method_and_path_rules_need_to_be_optional() {
        let n = |host: &str, methods: &[&str]| CapBody::Network {
            install: Rules::default(),
            runtime: Rules {
                allow: vec![NetRule {
                    host: host.into(),
                    methods: methods.iter().map(|s| s.to_string()).collect(),
                    paths: vec![],
                }],
                deny: vec![],
            },
        };
        let ty = "com.docker.sandbox/network-policy@2";
        let req = mixin("m").cap(ty, false, n("a.com", &["GET"]));
        let e = run(workload("w"), vec![req]).unwrap_err();
        assert_eq!(
            format!("{e:#}"),
            "kit m: network-policy@2 method/path rules are not enforced by smolbento"
        );
        let opt = mixin("m").cap(ty, true, n("a.com", &["GET"]));
        let p = run(workload("w"), vec![opt]).unwrap();
        assert_eq!(p.skipped, ["m: network-policy@2 method/path (host-only)"]);
        assert!(runtime(&p).allow[0].methods.is_empty());
        // Host-only entries and @1 are unaffected.
        let plain = mixin("m").cap(ty, false, n("a.com", &[]));
        assert!(run(workload("w"), vec![plain]).unwrap().skipped.is_empty());
    }

    #[test]
    fn host_only_downgrade_drops_qualified_denies_instead_of_widening_them() {
        let rule = |host: &str, methods: &[&str], paths: &[&str]| NetRule {
            host: host.into(),
            methods: methods.iter().map(|s| s.to_string()).collect(),
            paths: paths.iter().map(|s| s.to_string()).collect(),
        };
        let body = CapBody::Network {
            install: Rules::default(),
            runtime: Rules {
                allow: vec![rule("registry.npmjs.org", &["GET", "HEAD"], &[])],
                deny: vec![
                    rule("registry.npmjs.org", &["POST", "PUT"], &[]),
                    rule("github.com", &["POST"], &["/**/git-receive-pack"]),
                    rule("evil.com", &[], &[]),
                ],
            },
        };
        let ty = "com.docker.sandbox/network-policy@2";
        let p = run(workload("w"), vec![mixin("m").cap(ty, true, body)]).unwrap();
        assert_eq!(
            p.skipped,
            ["m: network-policy@2 method/path (host-only; 2 qualified deny rules dropped)"]
        );
        let hosts = |l: &[NetRule]| l.iter().map(|n| n.host.clone()).collect::<Vec<_>>();
        // The allow survives, widened to its host; only the host-only deny is kept.
        assert_eq!(hosts(&runtime(&p).allow), ["registry.npmjs.org"]);
        assert_eq!(hosts(&runtime(&p).deny), ["evil.com"]);
        assert_eq!(hosts(&p.merged.network[0].runtime.deny), ["evil.com"]);
    }

    #[test]
    fn conflicting_volume_configs_fail_and_identical_ones_merge() {
        let a = mixin("a").cap("v@1", false, vol("/data", false));
        let b = mixin("b").cap("v@1", false, vol("/data", true));
        assert!(run(workload("w"), vec![a.clone(), b]).is_err());
        let c = mixin("c").cap("v@1", false, vol("/data", false));
        let p = run(workload("w"), vec![a, c]).unwrap();
        assert_eq!(
            p.merged.volumes,
            [Volume {
                path: "/data".into(),
                tmpfs: false,
                mode: None
            }]
        );
    }

    fn host(path: &str, mode: Option<&str>) -> CapBody {
        CapBody::HostMount {
            path: path.into(),
            mode: mode.map(Into::into),
        }
    }

    #[test]
    fn host_mounts_are_collected_in_kit_order_with_their_kit_s_identity() {
        const HM: &str = "com.docker.sandbox/host-mount@1";
        let mut a = mixin("a")
            .requires(&["b"])
            .cap(HM, false, host("/home/agent/.a", None));
        a.source = Source::LocalV3("/kits/a".into());
        let b =
            mixin("b")
                .provides(&["b@1.0.0"])
                .cap(HM, false, host("/home/agent/.b", Some("0700")));
        let w = workload("w").cap(HM, false, host("/w", None));
        let p = run(w, vec![a, b]).unwrap();
        let got: Vec<_> = p
            .merged
            .host_mounts
            .iter()
            .map(|m| (&*m.kit, &*m.identity, &*m.path, m.mode.as_deref()))
            .collect();
        assert_eq!(
            got,
            [
                ("w", "docker.io/library/w", "/w", None),
                ("b", "docker.io/library/b", "/home/agent/.b", Some("0700")),
                ("a", "/kits/a", "/home/agent/.a", None),
            ]
        );
    }

    #[test]
    fn a_host_mount_path_has_one_owner() {
        const HM: &str = "com.docker.sandbox/host-mount@1";
        let msg = "kits a and b both declare storage at /data; a host mount has one owner";
        let cases = [
            // Two host mounts, even identical ones.
            (host("/data", None), host("/data", Some("0700"))),
            (host("/data", None), host("/data", None)),
            // A host mount and a volume, either order.
            (host("/data", None), vol("/data", false)),
            (vol("/data", false), host("/data", None)),
        ];
        for (first, second) in cases {
            let a = mixin("a").cap(HM, false, first);
            let b = mixin("b").cap(HM, false, second);
            let e = run(workload("w"), vec![a, b]).unwrap_err();
            assert_eq!(format!("{e:#}"), msg);
        }
    }

    fn skills_dir(path: &str, rw: bool) -> CapBody {
        CapBody::AgentSkills {
            path: path.into(),
            readwrite: rw,
        }
    }
    fn skill(source: &str, name: &str) -> CapBody {
        CapBody::AgentSkill {
            source: source.into(),
            name: name.into(),
        }
    }

    #[test]
    fn skill_dirs_merge_to_the_widest_mode_and_one_kit_names_a_path_once() {
        const AS: &str = "com.docker.sandbox/agent-skills@1";
        let a = mixin("a").cap(AS, false, skills_dir("/s", false));
        let b = mixin("b").cap(AS, false, skills_dir("/s", true));
        let p = run(workload("w"), vec![a, b]).unwrap();
        assert_eq!(
            p.merged.skill_dirs,
            [SkillDir {
                path: "/s".into(),
                readwrite: true
            }]
        );
        let k = mixin("k").cap(AS, false, skills_dir("/s", false)).cap(
            AS,
            false,
            skills_dir("/s", true),
        );
        let e = run(workload("w"), vec![k]).unwrap_err();
        assert_eq!(format!("{e:#}"), "kit k: agent-skills@1 names /s twice");
    }

    #[test]
    fn bundled_skills_merge_by_name_and_conflict_on_different_sources() {
        const AK: &str = "com.docker.sandbox/agent-skill@1";
        let k = mixin("k")
            .cap(AK, false, skill("/a/x", "x"))
            .cap(AK, false, skill("/b/y", "x"));
        let e = run(workload("w"), vec![k]).unwrap_err();
        assert_eq!(
            format!("{e:#}"),
            "kit k: two agent-skill@1 entries are named x"
        );

        let a = mixin("a").cap(AK, true, skill("/s/x", "x"));
        let b = mixin("b").cap(AK, false, skill("/s/x", "x"));
        let p = run(workload("w"), vec![a, b]).unwrap();
        assert_eq!(p.merged.bundled.len(), 1);
        assert_eq!(p.merged.bundled[0].name, "x");
        assert!(!p.merged.bundled[0].optional);

        let a = mixin("a").cap(AK, false, skill("/s/x", "x"));
        let b = mixin("b").cap(AK, false, skill("/t/x", "x"));
        let e = run(workload("w"), vec![a, b]).unwrap_err();
        assert_eq!(
            format!("{e:#}"),
            "kits a and b both bundle a skill named \"x\" from different paths"
        );
    }

    #[test]
    fn resources_last_wins_and_flags_are_set() {
        let res = |c: Option<&str>, m: Option<&str>| CapBody::Resources {
            cpus: c.map(String::from),
            memory: m.map(String::from),
        };
        let w = workload("w").cap("r@1", false, res(Some("2"), Some("1g")));
        let m = mixin("m")
            .cap("r@1", false, res(Some("4"), None))
            .cap("g@1", false, CapBody::GitIdentity)
            .cap("l@1", false, CapBody::LongRunning)
            .cap("p@1", false, CapBody::Privileged);
        let p = run(w, vec![m]).unwrap();
        assert_eq!(p.merged.cpus.as_deref(), Some("4"));
        assert_eq!(p.merged.memory.as_deref(), Some("1g"));
        assert!(p.merged.git_identity && p.merged.long_running && p.merged.privileged);
    }

    #[test]
    fn env_merges_with_later_winning() {
        let mut w = workload("w");
        w.env = vec![("A".into(), "1".into()), ("B".into(), "1".into())];
        let mut m = mixin("m");
        m.env = vec![("B".into(), "2".into())];
        let p = run(w, vec![m]).unwrap();
        assert_eq!(
            p.merged.env,
            [("A".into(), "1".into()), ("B".into(), "2".into())]
        );
    }

    #[test]
    fn hooks_files_and_contexts_expand_args_and_env() {
        let mut m = mixin("m");
        m.args.insert(
            "name".into(),
            ArgDef {
                default: Some("bob".into()),
                ..Default::default()
            },
        );
        m.args.insert("opt".into(), ArgDef::default());
        m.env = vec![("TOOL".into(), "x".into())];
        // `opt` is declared with no value but never used: not an error.
        let m = m
            .cap(
                "l@1",
                false,
                CapBody::Lifecycle(Lifecycle {
                    install: vec![shell_hook("hi ${{ kit.args.name }}")],
                    startup: vec![Hook {
                        command: HookCmd::Argv(vec!["echo".into(), "${{ kit.env.HOME }}".into()]),
                        ..shell_hook("")
                    }],
                    files: vec![FileReq {
                        path: "/f/${{ kit.args.name }}".into(),
                        content: "${{ kit.env.TOOL }}".into(),
                        mode: None,
                        overwrite: true,
                    }],
                }),
            )
            .cap(
                "c@1",
                false,
                CapBody::AgentContext(AgentContextReq {
                    filename: None,
                    directory: None,
                    content: "for ${{ kit.args.name }}".into(),
                }),
            );
        let v = ArgValues::parse(&[], &["name=alice".into()]).unwrap();
        let p = resolve(workload("w"), vec![m], &v).unwrap();
        assert_eq!(
            p.merged.install_hooks[0].1.command,
            HookCmd::Shell("hi alice".into())
        );
        assert_eq!(
            p.merged.startup_hooks[0].1.command,
            HookCmd::Argv(vec!["echo".into(), "/home/agent".into()])
        );
        assert_eq!(p.merged.files[0].path, "/f/alice");
        assert_eq!(p.merged.files[0].content, b"x");
        assert_eq!(p.merged.contexts[0].1.content, "for alice");
        assert!(!p.args["m"].contains_key("opt"));
    }

    fn opt_hook_kit() -> Kit {
        let mut m = mixin("m");
        m.args.insert("opt".into(), ArgDef::default());
        m.cap(
            "l@1",
            false,
            CapBody::Lifecycle(Lifecycle {
                install: vec![shell_hook("x${{ kit.args.opt }}y")],
                startup: vec![],
                files: vec![],
            }),
        )
    }

    #[test]
    fn a_used_optional_arg_with_no_value_is_an_error_but_empty_is_a_value() {
        let e = resolve(workload("w"), vec![opt_hook_kit()], &ArgValues::default()).unwrap_err();
        assert_eq!(
            format!("{e:#}"),
            "kit m: create-phase kit arg \"opt\" has no resolved value"
        );
        let v = ArgValues::parse(&[], &["opt=".into()]).unwrap();
        let p = resolve(workload("w"), vec![opt_hook_kit()], &v).unwrap();
        assert_eq!(
            p.merged.install_hooks[0].1.command,
            HookCmd::Shell("xy".into())
        );
    }

    #[test]
    fn unknown_args_and_undeclared_placeholders_fail() {
        let v = ArgValues::parse(&[], &["nope=1".into()]).unwrap();
        assert!(resolve(workload("w"), vec![], &v).is_err());
        let m = mixin("m").cap(
            "c@1",
            false,
            CapBody::AgentContext(AgentContextReq {
                filename: None,
                directory: None,
                content: "${{ kit.args.zzz }}".into(),
            }),
        );
        assert!(run(workload("w"), vec![m]).is_err());
    }

    #[test]
    fn v2_workspace_files_and_workdir_expand_to_the_workdir() {
        let dir = std::path::Path::new("tests/fixtures/kits/v2/workspace-files");
        let yaml = std::fs::read_to_string(dir.join("spec.yaml")).unwrap();
        let kit = crate::kits::v2::parse(&yaml, dir).unwrap();
        let files = |p: &Plan| -> Vec<(String, Vec<u8>)> {
            p.merged
                .files
                .iter()
                .map(|f| (f.path.clone(), f.content.clone()))
                .collect()
        };
        let p = resolve_for(
            workload("w"),
            vec![kit.clone()],
            &ArgValues::default(),
            "/w/repo",
        )
        .unwrap();
        assert_eq!(
            files(&p),
            [
                ("/home/agent/.wsrc".into(), "workdir=/w/repo\n".into()),
                (
                    "/w/repo/docs/NOTES.md".into(),
                    "Notes for the workspace.\n".into()
                ),
            ]
        );
        // Without a sandbox (`kit validate`): the mountless directory.
        let p = resolve(workload("w"), vec![kit], &ArgValues::default()).unwrap();
        assert_eq!(files(&p)[1].0, "/home/agent/workspace/docs/NOTES.md");
    }
}
