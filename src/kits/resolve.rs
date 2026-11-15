//! Resolves one workload plus mixins into an ordered, merged `Plan` ready to apply.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, bail};

use crate::kits::args::{ArgValues, expand};
use crate::kits::capability;
use crate::kits::host_mount;
use crate::kits::model::{
    AgentContextReq, Cap, CapBody, CredReq, FileReq, Format, Hook, HookCmd, Kind, Kit, Lifecycle,
    NetRule, Rules, Source, SshPhase,
};
use crate::ssh_agent::{AgentGrant, PhaseGrant};

/// The agent user's home in the platform floor; the host can't see the guest's real env.
const AGENT_HOME: &str = "/home/agent";

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
    /// One stderr line per skipped optional capability, when kit warnings are shown.
    pub fn warn_skipped(&self) {
        for w in self.skipped_warnings() {
            crate::kit_warning!("warning: {w}");
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
    /// The kit that first declared each volume path: a host mount there conflicts with it.
    volume_kits: BTreeMap<String, String>,
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

    fn add_skill_dir(&mut self, path: &str, readwrite: bool) {
        match self.skill_dirs.iter_mut().find(|d| d.path == path) {
            Some(d) => d.readwrite |= readwrite,
            None => self.skill_dirs.push(SkillDir {
                path: path.into(),
                readwrite,
            }),
        }
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

    /// The last kit to set a value wins.
    fn set_resources(&mut self, cpus: &Option<String>, memory: &Option<String>) {
        if cpus.is_some() {
            self.cpus.clone_from(cpus);
        }
        if memory.is_some() {
            self.memory.clone_from(memory);
        }
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
        runtime: ssh_phase(&[BUILT_IN], SshPhase::Runtime).expect("the built-in grant merges"),
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
    check_names(&workload, &mixins)?;
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

    let mut merged = Merged {
        env: merge_env(&all, &kit_args),
        ..Default::default()
    };
    let mut env_map: BTreeMap<String, String> = merged.env.iter().cloned().collect();
    env_map.insert("HOME".into(), AGENT_HOME.into());
    env_map.insert("WORKSPACE".into(), workdir.into());

    let mut skipped = Vec::new();
    let mut ssh_entries = Vec::new();
    if matches!(workload.source, Source::Agent(_)) {
        ssh_entries.push(BUILT_IN);
    }
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
                    // OAuth without passthrough (sbx's sentinel tokens) needs smolvm support: its
                    // API key part binds as usual, and logins happen inside the sandbox.
                    merged.credentials.push(KitCred {
                        kit: k.name.clone(),
                        optional: cap.optional,
                        req: c.clone(),
                    });
                }
                CapBody::Network { install, runtime } => {
                    let (install, runtime, skip) = enforceable(k, cap, install, runtime)?;
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
                CapBody::AgentSkills { path, readwrite } => {
                    merged.add_skill_dir(path, *readwrite);
                }
                CapBody::AgentSkill { source, name } => {
                    merged.add_bundled(&k.name, name, source, cap.optional)?;
                }
                CapBody::Resources { cpus, memory } => merged.set_resources(cpus, memory),
                CapBody::Lifecycle(l) => add_lifecycle(&mut merged, &k.name, l, &ex)?,
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
        install: ssh_phase(&ssh_entries, SshPhase::Install)?,
        runtime: ssh_phase(&ssh_entries, SshPhase::Runtime)?,
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
            // Most likely a user's own docker kit beside the shipped one a Docker image gets.
            let shipped = std::iter::once(workload)
                .chain(mixins)
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
    Ok(())
}

/// The kits' env vars in kit order; a later kit's value wins. A kit's own are its plain ones (v2
/// `environment.variables`), then each arg that declares `env:` and has a value (v3, as Docker's
/// claude mixin exports `model` as `CLAUDE_MODEL`); a default counts as a value, an empty one too.
fn merge_env(
    kits: &[Kit],
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

/// What of a kit's network rules smolbento can enforce: hosts, not methods or paths. A
/// `network-policy@2` capability with method or path qualifiers is refused, or, when optional,
/// downgraded to host-only (with a `Skipped` note): allows widen to their host, and qualified
/// denies are dropped, since widening one would block the whole host, the opposite of what the
/// kit asked for.
fn enforceable(
    k: &Kit,
    cap: &Cap,
    install: &Rules,
    runtime: &Rules,
) -> Result<(Rules, Rules, Option<Skipped>)> {
    let is_qualified = |n: &NetRule| !n.methods.is_empty() || !n.paths.is_empty();
    let qualified = [install, runtime]
        .iter()
        .flat_map(|r| r.allow.iter().chain(&r.deny))
        .any(is_qualified);
    if !qualified || !cap.ty.ends_with("network-policy@2") {
        return Ok((install.clone(), runtime.clone(), None));
    }
    if !cap.optional {
        bail!(
            "kit {}: network-policy@2 method/path rules are not enforced by smolbento",
            k.name
        );
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

/// A kit's install and startup hooks and init files, with `${{ }}` references expanded by `ex`.
fn add_lifecycle(
    merged: &mut Merged,
    kit: &str,
    l: &Lifecycle,
    ex: &dyn Fn(&str) -> Result<String>,
) -> Result<()> {
    for h in &l.install {
        merged.install_hooks.push((kit.into(), expand_hook(h, ex)?));
    }
    for h in &l.startup {
        merged.startup_hooks.push((kit.into(), expand_hook(h, ex)?));
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
    Ok(())
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
fn ssh_phase(entries: &[SshEntry], phase: SshPhase) -> Result<Option<PhaseGrant>> {
    let es: Vec<&SshEntry> = entries
        .iter()
        .filter(|e| e.phases.contains(&phase))
        .collect();
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
    let unrestricted = es.iter().any(|e| e.unrestricted);
    let mut authenticate: Vec<String> = Vec::new();
    if !unrestricted {
        for d in es.iter().flat_map(|e| e.authenticate) {
            if !authenticate.contains(d) {
                authenticate.push(d.clone());
            }
        }
    }
    let required = es.iter().any(|e| !e.optional);
    let kit = es
        .iter()
        .find(|e| !e.optional)
        .or_else(|| es.iter().find(|e| e.kit.is_some()))
        .and_then(|e| e.kit.map(String::from));
    Ok(Some(PhaseGrant {
        sign,
        authenticate,
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
#[path = "resolve_tests.rs"]
mod tests;
