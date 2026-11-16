//! Kit v3 descriptor parser (docker/sandbox-kit-spec SPEC-v3, `spec/types.go`).
//!
//! Well-known capability configs reject unknown keys, so a typo like `sise` fails loudly instead
//! of silently dropping a limit. The top level and unknown capability types stay lenient.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};
use serde::Deserialize;
use serde_json::Value;

use super::descriptor::{ApiKeyCfg, ResourcesCfg, TokenEndpoint};
use crate::kits::capability;
use crate::kits::model::*;

const NS: &str = "com.docker.sandbox/";

/// Parses a YAML descriptor. YAML goes through `serde_json::Value` so it shares one path with the
/// JSON form carried in manifest annotations.
pub fn parse(yaml: &str, source: Source) -> Result<Kit> {
    let v: Value = serde_saphyr::from_str(yaml).context("reading the kit descriptor")?;
    from_value(v, source)
}

pub fn parse_json(json: &str, source: Source) -> Result<Kit> {
    from_value(
        serde_json::from_str(json).context("reading the kit descriptor")?,
        source,
    )
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Descriptor {
    schema_version: String,
    kind: String,
    /// The version of unversioned `provides` when the reference carries none.
    #[serde(default, deserialize_with = "opt_scalar")]
    version: Option<String>,
    #[serde(default)]
    provides: Vec<String>,
    #[serde(default)]
    requires: Vec<String>,
    #[serde(default)]
    integrates: Vec<String>,
    #[serde(default)]
    conflicts: Vec<String>,
    #[serde(default)]
    capabilities: Vec<CapabilityItem>,
    #[serde(default)]
    args: BTreeMap<String, Arg>,
}

#[derive(Deserialize)]
struct CapabilityItem {
    #[serde(default, rename = "type")]
    ty: String,
    #[serde(default)]
    optional: bool,
    #[serde(default)]
    config: Option<Value>,
}

// Lenient like the descriptor's top level: an unknown arg key is ignored.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
// Some fields are only accepted, so published descriptors parse.
#[allow(dead_code)]
struct Arg {
    #[serde(default, deserialize_with = "opt_scalar")]
    default: Option<String>,
    #[serde(default)]
    required: bool,
    pattern: Option<String>,
    #[serde(default, rename = "enum", deserialize_with = "scalar_list")]
    enum_values: Vec<String>,
    env: Option<String>,
    // Accepted so published descriptors parse.
    description: Option<String>,
    /// Set for an argument the build takes.
    build_arg: Option<String>,
}

fn from_value(v: Value, source: Source) -> Result<Kit> {
    let d: Descriptor = serde_json::from_value(v).context("reading the kit descriptor")?;
    if d.schema_version != "3" {
        bail!("schemaVersion must be \"3\" (got {:?})", d.schema_version);
    }
    let kind = match d.kind.as_str() {
        "workload" | "sandbox" => Kind::Workload,
        "mixin" => Kind::Mixin,
        "set" => bail!("kind: set must be published (docker buildx build) before it can be run"),
        k => bail!("unknown kind '{k}'"),
    };
    let provides = provides(&d, &source)?;
    let caps = d
        .capabilities
        .into_iter()
        .enumerate()
        .map(|(i, c)| {
            if c.ty.trim().is_empty() {
                bail!("capability {i} has no type");
            }
            cap(c)
        })
        .collect::<Result<Vec<_>>>()?;
    let caps = newest_versions(caps);
    let name = name_from_source(&source)?;
    for c in &caps {
        if let CapBody::Lifecycle(l) = &c.body {
            check_hooks(&name, l)?;
        }
    }
    check_ssh_phases(&name, &caps)?;
    // A published kit is built: an argument that only fed the build needs no value now (sbx
    // creates docker.io/sbx/antigravity without its required `version`).
    let published = matches!(source, Source::Registry(_));
    let args = d
        .args
        .into_iter()
        .map(|(name, a)| {
            let def = ArgDef {
                default: a.default,
                required: a.required && !(published && a.build_arg.is_some()),
                pattern: a.pattern,
                enum_values: a.enum_values,
                env: a.env,
            };
            (name, def)
        })
        .collect();
    Ok(Kit {
        provides,
        requires: d.requires,
        integrates: d.integrates,
        conflicts: d.conflicts,
        args,
        caps,
        ..Kit::new(&name, kind, source)
    })
}

/// Checks the capability entries (SPEC-v3 §5) and gives each unversioned provide its version: a
/// version-shaped registry tag's, else the descriptor's `version:`. A kit sbx would build here
/// (local or shipped) must leave none unversioned, as the spec's frontend refuses; a published kit
/// that still has one keeps it, and it then satisfies only unconstrained requires.
fn provides(d: &Descriptor, source: &Source) -> Result<Vec<String>> {
    let mut errs = Vec::new();
    if let Some(v) = &d.version
        && !capability::has_arg_ref(v)
        && !capability::is_version(v)
    {
        errs.push(format!("version: invalid version {:?}", v.trim()));
    }
    errs.extend(capability::validate(
        &d.provides,
        &d.requires,
        &d.integrates,
        &d.conflicts,
    ));
    if !errs.is_empty() {
        bail!("{}", errs.join("\n"));
    }
    let fallback = match source {
        Source::Registry(r) => capability::version_from_reference(r),
        _ => None,
    }
    .or_else(|| d.version.clone().filter(|v| capability::is_version(v)));
    let unversioned = |s: &str| !s.contains('@') && !capability::has_arg_ref(s);
    if fallback.is_none() && !matches!(source, Source::Registry(_)) {
        let errs: Vec<String> = d
            .provides
            .iter()
            .enumerate()
            .filter(|(_, s)| unversioned(s))
            .map(|(i, s)| capability::unversioned(i, s))
            .collect();
        if !errs.is_empty() {
            bail!("{}", errs.join("\n"));
        }
    }
    Ok(d.provides
        .iter()
        .map(|s| match &fallback {
            Some(v) if unversioned(s) => format!("{}@{v}", s.trim()),
            _ => s.clone(),
        })
        .collect())
}

/// A short token naming the kit: it scopes `--kit-arg` and tags policy rule origins, so it comes
/// from the source, never from the free-text `displayName`.
pub(crate) fn name_from_source(source: &Source) -> Result<String> {
    check_name(raw_name(source))
}

/// Kit names land in guest scripts, file names, markers and the tab-separated kits record.
pub(crate) fn check_name(name: String) -> Result<String> {
    let ok = |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-');
    if name.is_empty() || !name.chars().all(ok) {
        bail!("kit name '{name}' may only contain letters, digits, '.', '_' and '-'");
    }
    Ok(name)
}

fn raw_name(source: &Source) -> String {
    match source {
        Source::Registry(r) | Source::Agent(r) => {
            let last = r.rsplit('/').next().unwrap_or(r);
            let last = last.split('@').next().unwrap_or(last);
            last.split(':').next().unwrap_or(last).to_string()
        }
        Source::Builtin(n) => n.to_string(),
        Source::LocalV3(p) | Source::LocalV2(p) => path_name(p),
        Source::Smolfile(p) => {
            if p.file_name().is_some_and(|n| n == "Smolfile")
                && let Some(n) = project_dir_name(p)
            {
                return n;
            }
            path_name(p)
        }
    }
}

/// Name of the directory holding `p`. A bare or `./` path has a parent with no name of its own,
/// so that case resolves the parent against the filesystem.
fn project_dir_name(p: &Path) -> Option<String> {
    let parent = p.parent()?;
    let name = |d: &Path| Some(d.file_name()?.to_str()?.to_string());
    if let Some(n) = name(parent) {
        return Some(n);
    }
    let parent = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };
    let dir = std::fs::canonicalize(parent)
        .or_else(|_| std::env::current_dir())
        .ok()?;
    name(&dir)
}

/// Directory basename, or the file stem when the path is a file.
fn path_name(p: &Path) -> String {
    let part = if p.is_dir() {
        p.file_name()
    } else {
        p.file_stem()
    };
    part.and_then(|n| n.to_str()).unwrap_or("kit").to_string()
}

/// Of a capability declared in several versions, only the newest one smolbento understands
/// counts: kits declare older versions for older runtimes (sbx's agents give their guide as
/// agent-context@1 and @2 alike), and applying both would apply it twice. Entries of that one
/// version all stay (several volume@1, say); unknown capabilities are left as they are.
fn newest_versions(caps: Vec<Cap>) -> Vec<Cap> {
    let versioned = |c: &Cap| {
        if matches!(c.body, CapBody::Unsupported) {
            return None;
        }
        let (base, v) = c.ty.rsplit_once('@')?;
        Some((base.to_string(), v.parse::<u32>().ok()?))
    };
    let mut newest: BTreeMap<String, u32> = BTreeMap::new();
    for (base, v) in caps.iter().filter_map(versioned) {
        let n = newest.entry(base).or_insert(v);
        *n = (*n).max(v);
    }
    caps.into_iter()
        .filter(|c| versioned(c).is_none_or(|(base, v)| newest[&base] == v))
        .collect()
}

fn cap(item: CapabilityItem) -> Result<Cap> {
    let body = body(&item.ty, item.config).with_context(|| format!("capability {}", item.ty))?;
    Ok(Cap {
        ty: item.ty,
        optional: item.optional,
        body,
    })
}

/// Decodes a known config type, rejecting unknown keys (the structs carry `deny_unknown_fields`).
fn decode<T: serde::de::DeserializeOwned>(config: Option<Value>) -> Result<T> {
    let v = config.unwrap_or_else(|| Value::Object(Default::default()));
    serde_json::from_value(v).map_err(|e| anyhow!("{e}"))
}

fn no_config(config: Option<Value>) -> Result<()> {
    if config.is_some_and(|c| !c.is_null()) {
        bail!("takes no config");
    }
    Ok(())
}

fn body(ty: &str, config: Option<Value>) -> Result<CapBody> {
    let Some(name) = ty.strip_prefix(NS) else {
        return Ok(CapBody::Unsupported);
    };
    Ok(match name {
        "network-policy@1" => {
            let c: NetworkV1 = decode(config)?;
            CapBody::Network {
                install: c.install.unwrap_or_default().into_rules(),
                runtime: c.runtime.unwrap_or_default().into_rules(),
            }
        }
        "network-policy@2" => {
            let c: NetworkV2 = decode(config)?;
            CapBody::Network {
                install: c.install.unwrap_or_default().into_rules(),
                runtime: c.runtime.unwrap_or_default().into_rules(),
            }
        }
        "credential@1" => CapBody::Credential(credential(decode(config)?)?),
        "port@1" => {
            let c: PortCfg = decode(config)?;
            if c.container == 0 {
                bail!("container must be 1..65535");
            }
            let udp = match c.transport.as_deref() {
                None | Some("") | Some("tcp") => false,
                Some("udp") => true,
                Some(t) => bail!("transport must be tcp or udp (got {t:?})"),
            };
            CapBody::Port {
                container: c.container,
                udp,
            }
        }
        "volume@1" => {
            let c: VolumeCfg = decode(config)?;
            CapBody::Volume {
                path: c.path,
                tmpfs: c.tmpfs,
                mode: c.mode,
            }
        }
        "host-mount@1" => {
            let c: HostMountCfg = decode(config)?;
            if !canonical_abs(&c.path) {
                bail!(
                    "host-mount@1 path {:?} must be absolute and canonical",
                    c.path
                );
            }
            if let Some(m) = &c.mode
                && !((3..=4).contains(&m.len()) && m.bytes().all(|b| (b'0'..=b'7').contains(&b)))
            {
                bail!("host-mount@1 mode {m:?} must be octal");
            }
            CapBody::HostMount {
                path: c.path,
                mode: c.mode,
            }
        }
        "resources@1" => {
            let c: ResourcesCfg = decode(config)?;
            CapBody::Resources {
                cpus: c.cpu.map(|n| n.to_string()),
                memory: c.memory,
            }
        }
        "lifecycle@1" => CapBody::Lifecycle(lifecycle(decode(config)?)),
        "agent-context@1" => {
            let c: AgentContextV1 = decode(config)?;
            let content = match (c.content, c.content_file) {
                (Some(_), Some(_)) => bail!("content and contentFile are mutually exclusive"),
                (Some(c), None) => c,
                // The body is staged in the kit image; later code reads it from there.
                (None, Some(f)) => format!("file:{f}"),
                (None, None) => String::new(),
            };
            CapBody::AgentContext(AgentContextReq {
                filename: c.filename,
                directory: c.directory,
                content,
            })
        }
        "agent-context@2" => {
            let c: AgentContextV2 = decode(config)?;
            CapBody::AgentContext(AgentContextReq {
                filename: c.filename,
                directory: c.directory,
                content: c.content.unwrap_or_default(),
            })
        }
        "sbx@1" => {
            no_config(config)?;
            CapBody::Sbx
        }
        "git-identity@1" => {
            no_config(config)?;
            CapBody::GitIdentity
        }
        "long-running@1" => {
            no_config(config)?;
            CapBody::LongRunning
        }
        "privileged@1" => {
            no_config(config)?;
            CapBody::Privileged
        }
        // Its command templates matter to the agent launcher, not to the kit model.
        "agent-sessions@1" => CapBody::AgentSessions,
        "ssh-agent@1" => ssh_agent(decode(config)?)?,
        "agent-skills@1" => {
            let c: AgentSkillsCfg = decode(config)?;
            if !canonical_abs(&c.path) {
                bail!(
                    "agent-skills@1 path {:?} must be absolute and canonical",
                    c.path
                );
            }
            // `-v host:guest[:ro]` would misread a `:`.
            if c.path.contains(':') {
                bail!("agent-skills@1 path {:?} must not contain ':'", c.path);
            }
            let shared = crate::skills::SHARED;
            if c.path == shared || c.path.starts_with(&format!("{shared}/")) {
                bail!(
                    "agent-skills@1 path {:?} must not be {shared} or under it",
                    c.path
                );
            }
            let readwrite = match c.mode.as_deref() {
                None | Some("readonly") => false,
                Some("readwrite") => true,
                Some(m) => bail!("agent-skills@1 mode {m:?} must be readonly or readwrite"),
            };
            CapBody::AgentSkills {
                path: c.path,
                readwrite,
            }
        }
        "agent-skill@1" => {
            let c: AgentSkillCfg = decode(config)?;
            // Literal (no create-time `${...}`), and safe inside the bundled script's messages.
            // No `:` either, as for agent-skills@1.
            if !canonical_abs(&c.path) || c.path.contains(['$', '"', '`', '\\', ':']) {
                bail!(
                    "agent-skill@1 path {:?} must be a literal absolute canonical path",
                    c.path
                );
            }
            let name = c
                .name
                .unwrap_or_else(|| c.path.rsplit('/').next().unwrap_or_default().to_string());
            if !crate::skills::valid_name(&name) {
                bail!(
                    "agent-skill@1 name {name:?} must match [A-Za-z0-9][A-Za-z0-9._-]* (at most 255 bytes)"
                );
            }
            CapBody::AgentSkill {
                source: c.path,
                name,
            }
        }
        // usb-device, kit-registry, agent-interactive-sessions, acp and anything unknown.
        _ => CapBody::Unsupported,
    })
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct NetworkV1 {
    install: Option<RulesV1>,
    runtime: Option<RulesV1>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RulesV1 {
    #[serde(default)]
    allow: Vec<String>,
    #[serde(default)]
    deny: Vec<String>,
}

impl RulesV1 {
    fn into_rules(self) -> Rules {
        Rules {
            allow: self.allow.into_iter().map(NetRule::host).collect(),
            deny: self.deny.into_iter().map(NetRule::host).collect(),
        }
    }
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct NetworkV2 {
    install: Option<RulesV2>,
    runtime: Option<RulesV2>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RulesV2 {
    #[serde(default)]
    allow: Vec<EntryV2>,
    #[serde(default)]
    deny: Vec<EntryV2>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EntryV2 {
    hosts: Vec<String>,
    #[serde(default)]
    methods: Vec<String>,
    #[serde(default)]
    paths: Vec<String>,
}

impl RulesV2 {
    fn into_rules(self) -> Rules {
        // One rule per host, each carrying the entry's methods and paths.
        let flat = |entries: Vec<EntryV2>| {
            entries
                .into_iter()
                .flat_map(|e| {
                    let (methods, paths) = (e.methods, e.paths);
                    e.hosts.into_iter().map(move |host| NetRule {
                        host,
                        methods: methods.clone(),
                        paths: paths.clone(),
                    })
                })
                .collect()
        };
        Rules {
            allow: flat(self.allow),
            deny: flat(self.deny),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CredCfg {
    service: String,
    phase: OneOrMany,
    #[serde(rename = "apiKey")]
    api_key: Option<ApiKeyCfg>,
    oauth: Option<OAuthCfg>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum OneOrMany {
    One(String),
    Many(Vec<String>),
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
// Some fields are only accepted, so published descriptors parse.
#[allow(dead_code)]
struct OAuthCfg {
    token_endpoint: Option<TokenEndpoint>,
    #[serde(default)]
    resource_hosts: Vec<String>,
    #[serde(default)]
    passthrough: bool,
    // Sentinel and credential-file plumbing is the proxy's business; accepted and ignored.
    sentinels: Option<Value>,
    credential_file: Option<Value>,
    response_fields: Option<Value>,
}

fn credential(c: CredCfg) -> Result<CredReq> {
    if c.api_key.is_none() && c.oauth.is_none() {
        bail!("one of apiKey or oauth is required");
    }
    let phases = phases(c.phase, false)?;
    let (env, inject) = match c.api_key {
        Some(k) => {
            let inject = k
                .inject
                .into_iter()
                .map(|i| Inject {
                    domain: i.domain,
                    header: i.header,
                    format: i.format,
                    basic_user: i.username,
                })
                .collect();
            ((!k.name.is_empty()).then_some(k.name), inject)
        }
        None => (None, vec![]),
    };
    let oauth = c.oauth.map(|o| OAuthReq {
        passthrough: o.passthrough,
        token_host: o.token_endpoint.map(|t| t.host),
        resource_hosts: o.resource_hosts,
    });
    Ok(CredReq {
        service: c.service,
        install: phases.contains(&SshPhase::Install),
        runtime: phases.contains(&SshPhase::Runtime),
        env,
        inject,
        oauth,
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SshAgentCfg {
    phase: OneOrMany,
    unrestricted: Option<bool>,
    sign: Option<Vec<String>>,
    authenticate: Option<Vec<String>>,
}

/// The phases a capability's `phase:` names; `unique` (ssh-agent@1) refuses one listed twice.
fn phases(phase: OneOrMany, unique: bool) -> Result<Vec<SshPhase>> {
    let names = match phase {
        OneOrMany::One(p) => vec![p],
        OneOrMany::Many(p) => p,
    };
    let mut phases = Vec::new();
    for p in &names {
        let phase = match p.as_str() {
            "install" => SshPhase::Install,
            "runtime" => SshPhase::Runtime,
            other => bail!("phase must be install or runtime (got {other:?})"),
        };
        if unique && phases.contains(&phase) {
            bail!("phase {p} is listed twice");
        }
        phases.push(phase);
    }
    if phases.is_empty() {
        bail!("phase must name install, runtime or both");
    }
    Ok(phases)
}

fn ssh_agent(c: SshAgentCfg) -> Result<CapBody> {
    let phases = phases(c.phase, true)?;
    let unrestricted = c.unrestricted.unwrap_or(true);
    if unrestricted && (c.sign.is_some() || c.authenticate.is_some()) {
        bail!("an unrestricted entry can't state sign or authenticate");
    }
    if !unrestricted && c.sign.is_none() && c.authenticate.is_none() {
        bail!("a bounded entry (unrestricted: false) needs sign or authenticate");
    }
    distinct("sign", &c.sign)?;
    distinct("authenticate", &c.authenticate)?;
    let sign = c.sign.unwrap_or_default();
    let authenticate = c.authenticate.unwrap_or_default();
    for ns in &sign {
        if ns.is_empty() || !ns.bytes().all(|b| b.is_ascii_graphic()) {
            bail!("sign namespace {ns:?} must be printable ASCII without spaces");
        }
    }
    for dest in &authenticate {
        if !login_destination(dest) {
            bail!(
                "authenticate entry {dest:?} must be host or user@host, with host a lowercase DNS \
                 name (no wildcard, port or IP address)"
            );
        }
    }
    Ok(CapBody::SshAgent {
        phases,
        unrestricted,
        sign,
        authenticate,
    })
}

/// A present list must be non-empty and without duplicates.
fn distinct(field: &str, list: &Option<Vec<String>>) -> Result<()> {
    let Some(list) = list else { return Ok(()) };
    if list.is_empty() {
        bail!("{field} must not be empty");
    }
    for (i, v) in list.iter().enumerate() {
        if list[..i].contains(v) {
            bail!("{field} lists {v:?} twice");
        }
    }
    Ok(())
}

/// `host` or `user@host`: a literal lowercase DNS name, optionally after an account name.
fn login_destination(dest: &str) -> bool {
    let host = match dest.split_once('@') {
        Some((user, host)) => {
            if user.is_empty() || !user.bytes().all(|b| b.is_ascii_graphic()) {
                return false;
            }
            host
        }
        None => dest,
    };
    let label_ok = |l: &str| {
        (1..=63).contains(&l.len())
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    };
    let labels: Vec<&str> = host.split('.').collect();
    // An all-digit last label is an IPv4 address (or would be read as one), not a name.
    host.len() <= 253
        && labels.iter().all(|l| label_ok(l))
        && !labels
            .last()
            .is_some_and(|l| l.bytes().all(|b| b.is_ascii_digit()))
}

/// SPEC-v3: one kit's `ssh-agent@1` entries may not name the same phase twice.
fn check_ssh_phases(kit: &str, caps: &[Cap]) -> Result<()> {
    let mut seen = Vec::new();
    for c in caps {
        if let CapBody::SshAgent { phases, .. } = &c.body {
            for p in phases {
                if seen.contains(p) {
                    bail!(
                        "kit {kit}: ssh-agent@1 entries overlap in phase {}",
                        p.as_str()
                    );
                }
                seen.push(*p);
            }
        }
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
// Some fields are only accepted, so published descriptors parse.
#[allow(dead_code)]
struct PortCfg {
    // Labels and the address family describe the service; the model does not need them.
    name: Option<String>,
    container: u16,
    transport: Option<String>,
    family: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
// Some fields are only accepted, so published descriptors parse.
#[allow(dead_code)]
struct VolumeCfg {
    path: String,
    // smolvm volumes are not sized per mount.
    size: Option<String>,
    #[serde(default)]
    tmpfs: bool,
    mode: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HostMountCfg {
    path: String,
    mode: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentSkillsCfg {
    path: String,
    mode: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentSkillCfg {
    path: String,
    name: Option<String>,
}

/// Absolute with no `.`/`..`/empty components (so no `//` or trailing `/`), not `/`, no NUL.
fn canonical_abs(path: &str) -> bool {
    path.strip_prefix('/').is_some_and(|rest| {
        !path.contains('\0') && rest.split('/').all(|c| !matches!(c, "" | "." | ".."))
    })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AgentContextV1 {
    filename: Option<String>,
    directory: Option<String>,
    content: Option<String>,
    content_file: Option<String>,
}

// `contentFile` is rejected here by `deny_unknown_fields`, as the spec requires.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentContextV2 {
    filename: Option<String>,
    directory: Option<String>,
    content: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
// Some fields are only accepted, so published descriptors parse.
#[allow(dead_code)]
struct LifecycleCfg {
    #[serde(default)]
    install: Vec<HookCfg>,
    #[serde(default)]
    startup: Vec<HookCfg>,
    #[serde(default)]
    files: Vec<FileCfg>,
    // The launch-argv tail for interactive sessions belongs to the agent launcher.
    interactive: Option<Vec<String>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
// Some fields are only accepted, so published descriptors parse.
#[allow(dead_code)]
struct HookCfg {
    command: CommandCfg,
    user: Option<String>,
    #[serde(default)]
    env: Vec<String>,
    // Meaningful for startup hooks only.
    background: Option<bool>,
    description: Option<String>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum CommandCfg {
    Shell(String),
    Argv(Vec<String>),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
// Some fields are only accepted, so published descriptors parse.
#[allow(dead_code)]
struct FileCfg {
    path: String,
    content: String,
    mode: Option<String>,
    overwrite: Option<bool>,
    description: Option<String>,
}

fn lifecycle(c: LifecycleCfg) -> Lifecycle {
    // sbx runs only install hooks in a clean environment.
    let hook = |h: HookCfg, clean_env: bool| Hook {
        command: match h.command {
            CommandCfg::Shell(s) => HookCmd::Shell(s),
            CommandCfg::Argv(a) => HookCmd::Argv(a),
        },
        user: h.user,
        env: h.env,
        background: h.background.unwrap_or(false),
        clean_env,
    };
    Lifecycle {
        install: c.install.into_iter().map(|h| hook(h, true)).collect(),
        startup: c.startup.into_iter().map(|h| hook(h, false)).collect(),
        files: c
            .files
            .into_iter()
            .map(|f| FileReq {
                path: f.path,
                content: f.content.into_bytes(),
                mode: f.mode,
                // The spec defaults to overwriting.
                overwrite: f.overwrite.unwrap_or(true),
            })
            .collect(),
    }
}

#[cfg(test)]
#[path = "v3_tests.rs"]
mod tests;
