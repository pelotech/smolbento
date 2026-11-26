//! Kit v3 descriptor parser (docker/sandbox-kit-spec SPEC-v3, `spec/types.go`).
//!
//! Well-known capability configs reject unknown keys, so a typo like `sise` fails loudly instead
//! of silently dropping a limit. The top level and unknown capability types stay lenient.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::LazyLock;

use anyhow::{Context, Result, anyhow, bail};
use regex_lite::Regex;
use serde::Deserialize;
use serde_json::Value;

use super::descriptor::{ApiKeyCfg, ResourcesCfg, TokenEndpoint};
use crate::kits::model::*;
use crate::kits::{CAP_NS, args, capability};
use crate::skills::Mode;

/// Parses a published descriptor (SPEC-v3 §9): the one Docker's kit frontend wrote into a kit
/// image's manifest annotation (a registry kit, an agent's, or a local kit smolbento built), or
/// one of smolbento's shipped kits, written in that form. YAML reads the annotation's JSON too,
/// and §9.3 has consumers decode annotations as YAML so older YAML-valued ones still load.
///
/// Publishing expanded the arg references in `provides` and `version:`, and built the image, so
/// an argument that only fed the build needs no value now (sbx creates docker.io/sbx/antigravity
/// without its required `version`).
pub fn parse(yaml: &str, source: Source) -> Result<Kit> {
    let v: Value = serde_saphyr::from_str(yaml).context("reading the kit descriptor")?;
    from_value(v, source)
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

/// An ordinary request, or a `group` of them (SPEC-v3 §7.1.1). Lenient like the top level: a
/// published set's `source` attribution is accepted and ignored.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CapabilityItem {
    #[serde(default, rename = "type")]
    ty: String,
    /// Kept as given: a group member may not state it, even as false.
    optional: Option<bool>,
    #[serde(default)]
    config: Option<Value>,
    group: Option<GroupItem>,
    /// Only checked to be absent on group members; smolbento doesn't use the blocks.
    declaration_blocks: Option<Value>,
}

/// Strict (SPEC-v3 §1.2); `name` and `description` are display metadata (§7.1.1).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GroupItem {
    name: Option<String>,
    #[allow(dead_code)]
    description: Option<String>,
    #[serde(default)]
    optional: bool,
    #[serde(default)]
    capabilities: Vec<CapabilityItem>,
}

// Lenient like the descriptor's top level: an unknown arg key is ignored.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Arg {
    #[serde(default, deserialize_with = "opt_scalar")]
    default: Option<String>,
    #[serde(default)]
    required: bool,
    pattern: Option<String>,
    #[serde(default, rename = "enum", deserialize_with = "scalar_list")]
    enum_values: Vec<String>,
    env: Option<String>,
    /// Set for an argument the build takes.
    build_arg: Option<String>,
    /// A BuildKit secret ID: the build's input alone (SPEC-v3 §6.2).
    build_secret: Option<String>,
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
    let caps = caps(d.capabilities)?;
    let name = name_from_source(&source)?;
    check_caps(&name, &caps)?;
    check_mixin_profiles(&name, kind, &caps)?;
    // A build secret is no create-time input: left out, `--kit-arg` and references to it fail
    // as for an undeclared argument, and nothing exports it (SPEC-v3 §6/build-secret-no-expansion).
    let args = d
        .args
        .into_iter()
        .filter(|(_, a)| a.build_secret.is_none())
        .map(|(name, a)| {
            let def = ArgDef {
                default: a.default,
                required: a.required && a.build_arg.is_none(),
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
/// version-shaped registry tag's, else the descriptor's `version:`. One with neither (sbx's
/// published `github-ssh` has one) satisfies only unconstrained requires.
fn provides(d: &Descriptor, source: &Source) -> Result<Vec<String>> {
    let mut errs = Vec::new();
    if let Some(v) = &d.version
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
    .or_else(|| d.version.clone());
    let unversioned = |s: &str| !s.contains('@');
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
        Source::Local(p) => path_name(p),
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

/// The `capabilities` list with each group's members in its place. SPEC-v3 §7.1.1's grammar: an
/// item is a request or a group, never both; a group is neither empty nor nested, and its members
/// don't state `optional` (the group does) or `declarationBlocks`.
fn caps(items: Vec<CapabilityItem>) -> Result<Vec<Cap>> {
    let mut caps = Vec::new();
    for (i, item) in items.into_iter().enumerate() {
        let path = format!("capabilities[{i}]");
        let Some(g) = item.group else {
            caps.push(cap(item, &path)?);
            continue;
        };
        if !item.ty.is_empty() || item.config.is_some() || item.optional.is_some() {
            bail!("{path}: a group can't also have type, config or optional");
        }
        if g.capabilities.is_empty() {
            bail!("{path}: the group has no capabilities");
        }
        for (j, m) in g.capabilities.into_iter().enumerate() {
            let group = Group {
                index: i,
                member: j,
                name: g.name.clone(),
            };
            let at = group.member_path();
            if m.group.is_some() {
                bail!("{at}: groups can't be nested");
            }
            if m.optional.is_some() {
                bail!("{at}: a group member can't set optional; the group does");
            }
            if m.declaration_blocks.is_some() {
                bail!("{at}: a group member can't set declarationBlocks");
            }
            caps.push(Cap {
                optional: g.optional,
                group: Some(group),
                ..cap(m, &at)?
            });
        }
    }
    Ok(caps)
}

/// An ordinary request at `at`. A config with a reference is kept, and read again once `resolve`
/// expands it (SPEC-v3 §6). Until then it's read as written, so `kit inspect` and `kit add` see
/// it, or is `Pending` when it can't be (a reference where a number goes, say).
fn cap(item: CapabilityItem, at: &str) -> Result<Cap> {
    if item.ty.trim().is_empty() {
        bail!("{at} has no type");
    }
    // The spec validator's pattern (spec/validate.go `needType`).
    static TYPE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"^[a-z0-9]([a-z0-9.-]*[a-z0-9])?/[a-z0-9]([a-z0-9-]*[a-z0-9])?@[1-9][0-9]*$")
            .unwrap()
    });
    if !TYPE.is_match(&item.ty) {
        bail!(
            "{at}: type {:?} is not <namespace>/<name>@<version>",
            item.ty
        );
    }
    request(item.ty, item.optional.unwrap_or(false), item.config)
}

/// A capability request from its type and config, as `cap` describes. A v2 kit's capabilities,
/// other than its credentials and `files/` copies, are translated to v3 configs and built through
/// it too.
pub(crate) fn request(ty: String, optional: bool, config: Option<Value>) -> Result<Cap> {
    let refs = config.as_ref().is_some_and(args::has_ref);
    let body = match body(&ty, config.clone()) {
        Ok(b) => b,
        Err(_) if refs => CapBody::Pending,
        Err(e) => return Err(e).with_context(|| format!("capability {ty}")),
    };
    // Nothing reads an unsupported type's config.
    let config = config.filter(|_| refs && body != CapBody::Unsupported);
    Ok(Cap {
        config,
        ..Cap::new(ty, optional, body)
    })
}

/// SPEC agent-context@1 and @2 `filename`: without `directory`, workload kits only. Not for a v2
/// kit, whose mixin `filename` is warned about and not used.
pub(crate) fn check_mixin_profiles(kit: &str, kind: Kind, caps: &[Cap]) -> Result<()> {
    for c in caps {
        if let CapBody::AgentContext(r) = &c.body
            && kind == Kind::Mixin
            && r.filename.is_some()
            && r.directory.is_none()
        {
            bail!("kit {kit}: a mixin's agent-context filename needs a directory");
        }
    }
    Ok(())
}

/// The checks that span a kit's capabilities: when it loads, and again once `resolve` has
/// expanded them.
pub(crate) fn check_caps(kit: &str, caps: &[Cap]) -> Result<()> {
    for c in caps {
        if let CapBody::Lifecycle(l) = &c.body {
            check_hooks(kit, l)?;
        }
    }
    // SPEC-v3 §7.1: each pair describes the same thing, so a descriptor states one of them.
    let has = |ty: &str| caps.iter().any(|c| c.ty.strip_prefix(CAP_NS) == Some(ty));
    for name in ["network-policy", "agent-sessions"] {
        if has(&format!("{name}@1")) && has(&format!("{name}@2")) {
            bail!("kit {kit}: {name}@1 and {name}@2 are exclusive; declare one");
        }
    }
    check_ssh_phases(kit, caps)
}

/// `directory` needs a single-component `filename` in the same entry (SPEC agent-context@1 and @2).
fn profile_dir_needs_filename(filename: &Option<String>, directory: &Option<String>) -> Result<()> {
    let plain = |f: &str| !f.is_empty() && !f.contains('/') && f != "." && f != "..";
    if directory.is_some() && !filename.as_deref().is_some_and(plain) {
        bail!("agent-context directory needs a single-component filename in the same entry");
    }
    Ok(())
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

/// The top-level config fields of `ty` that stay text when a whole reference fills them (SPEC-v3
/// §6): a volume's size and octal mode, which would otherwise read as numbers.
pub(crate) fn text_fields(ty: &str) -> &'static [&'static str] {
    if ty == "com.docker.sandbox/volume@1" {
        &["size", "mode"]
    } else {
        &[]
    }
}

/// Reads a capability's config: strictly, with unknown keys and bad values refused.
pub(crate) fn body(ty: &str, config: Option<Value>) -> Result<CapBody> {
    let Some(name) = ty.strip_prefix(CAP_NS) else {
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
                install: c.install.unwrap_or_default().into_rules("install")?,
                runtime: c.runtime.unwrap_or_default().into_rules("runtime")?,
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
            no_colon("volume@1", &c.path)?;
            // Cleaned as the storage key is (SPEC-v3 §7.1).
            let path = clean_path(&c.path);
            if !path.starts_with('/') || path == "/" {
                bail!(
                    "volume@1 path {:?} must be an absolute path other than /",
                    c.path
                );
            }
            check_octal_mode("volume@1", c.mode.as_deref())?;
            CapBody::Volume {
                path,
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
            no_colon("host-mount@1", &c.path)?;
            check_octal_mode("host-mount@1", c.mode.as_deref())?;
            CapBody::HostMount {
                path: c.path,
                mode: c.mode,
            }
        }
        "resources@1" => {
            let c: ResourcesCfg = decode(config)?;
            // The YAML and JSON readers never produce infinity or NaN.
            if let Some(cpu) = c.cpu
                && cpu < 0.0
            {
                bail!("resources@1 cpu must be a non-negative number of cores (got {cpu})");
            }
            CapBody::Resources {
                cpus: c.cpu.map(|n| n.to_string()),
                memory: c.memory,
            }
        }
        "lifecycle@1" => CapBody::Lifecycle(lifecycle(decode(config)?)?),
        // Not provided (no host clipboard reads, nor images), but checked as the spec reads it.
        "clipboard@1" => {
            check_clipboard(config)?;
            CapBody::Unsupported
        }
        "agent-context@1" => {
            let c: AgentContextV1 = decode(config)?;
            if c.content.is_some() && c.content_file.is_some() {
                bail!("content and contentFile are mutually exclusive");
            }
            profile_dir_needs_filename(&c.filename, &c.directory)?;
            CapBody::AgentContext(AgentContextReq {
                filename: c.filename,
                directory: c.directory,
                content: c.content.unwrap_or_default(),
                content_file: c.content_file,
                delivery: Delivery::Progressive,
            })
        }
        "agent-context@2" => {
            let c: AgentContextV2 = decode(config)?;
            // `body()` sees expanded configs only: a reference stays `Pending` until then.
            let delivery = match c.delivery.as_deref() {
                None | Some("progressive") => Delivery::Progressive,
                Some("inline") => Delivery::Inline,
                Some(d) => {
                    bail!("agent-context@2 delivery must be progressive or inline (got {d:?})")
                }
            };
            profile_dir_needs_filename(&c.filename, &c.directory)?;
            // tck: agent-context@2/inline-only
            if c.filename.is_none()
                && c.directory.is_none()
                && c.content.as_deref().is_none_or(str::is_empty)
            {
                bail!("agent-context@2 needs a profile (filename) or a nonempty content");
            }
            CapBody::AgentContext(AgentContextReq {
                filename: c.filename,
                directory: c.directory,
                content: c.content.unwrap_or_default(),
                content_file: None,
                delivery,
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
        "dockerd@1" => {
            let c: DockerdCfg = decode(config)?;
            CapBody::Dockerd {
                auto_start: c.auto_start.unwrap_or(true),
            }
        }
        // Its command templates matter to the agent launcher, not to the kit model.
        "agent-sessions@1" | "agent-sessions@2" => CapBody::AgentSessions,
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
            // An omitted mode is `off` (agent-skills@1/off-default-honored).
            let mode = c.mode.as_deref().map_or(Ok(Mode::Off), Mode::parse)?;
            CapBody::AgentSkills { path: c.path, mode }
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

/// A kit's host pattern: `*` means everything, as `**` does (SPEC network-policy@1).
fn kit_host(host: String) -> String {
    if host.trim() == "*" {
        "**".into()
    } else {
        host
    }
}

impl RulesV1 {
    fn into_rules(self) -> Rules {
        let host = |h| NetRule::host(kit_host(h));
        Rules {
            allow: self.allow.into_iter().map(host).collect(),
            deny: self.deny.into_iter().map(host).collect(),
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
    // Each a host, or an `EntryV2` object; `into_rules` decodes them, naming the entry in errors.
    #[serde(default)]
    allow: Vec<Value>,
    #[serde(default)]
    deny: Vec<Value>,
}

/// A `network-policy@2` entry: hosts, and the requests they're bounded to.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EntryV2 {
    #[serde(default)]
    hosts: Vec<String>,
    // `None` is omitted (every method or path); `Some(vec![])` is an error.
    methods: Option<Vec<String>>,
    paths: Option<Vec<String>>,
}

/// The HTTP methods a `network-policy@2` entry may name, besides `ANY` on its own.
const HTTP_METHODS: [&str; 9] = [
    "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT",
];

impl EntryV2 {
    /// SPEC network-policy@2 "Validation". `what` names the entry in errors.
    fn check(&self, what: &str, allow: bool) -> Result<()> {
        if self.hosts.is_empty() || self.hosts.iter().any(|h| h.trim().is_empty()) {
            bail!("{what}: hosts must name at least one host, none empty");
        }
        let methods = self.methods.as_deref();
        if methods.is_some_and(<[String]>::is_empty) {
            bail!("{what}: an empty methods list grants nothing; omit it, or name the methods");
        }
        if self.paths.as_deref().is_some_and(<[String]>::is_empty) {
            bail!("{what}: an empty paths list grants nothing; omit it, or name the paths");
        }
        if self.paths.is_some() && methods.is_none() {
            bail!("{what}: paths need methods; name them, or use methods: [ANY]");
        }
        let methods = methods.unwrap_or_default();
        for (i, m) in methods.iter().enumerate() {
            if m != "ANY" && !HTTP_METHODS.contains(&m.as_str()) {
                bail!("{what}: method {m:?} is not an uppercase HTTP method or ANY");
            }
            if methods[..i].contains(m) {
                bail!("{what}: method {m:?} is listed twice");
            }
        }
        if methods.len() > 1 && methods.iter().any(|m| m == "ANY") {
            bail!("{what}: ANY covers every method; list it alone");
        }
        if let Some(p) = self.paths.iter().flatten().find(|p| !p.starts_with('/')) {
            bail!("{what}: path {p:?} must start with /");
        }
        let bounded = self.methods.is_some() || self.paths.is_some();
        if allow
            && bounded
            && let Some(h) = self.hosts.iter().find(|h| h.contains('*'))
        {
            bail!("{what}: a bounded allow entry names its hosts exactly, not {h:?}");
        }
        Ok(())
    }
}

impl RulesV2 {
    /// One rule per host, each carrying its entry's methods and paths. `phase` names the
    /// entries in errors.
    fn into_rules(self, phase: &str) -> Result<Rules> {
        let flat = |entries: Vec<Value>, kind: &str| -> Result<Vec<NetRule>> {
            let mut rules = Vec::new();
            for (i, v) in entries.into_iter().enumerate() {
                let what = format!("{phase} {kind} entry {i}");
                let e = match v {
                    // A host string is shorthand for an entry naming that host alone.
                    Value::String(host) => EntryV2 {
                        hosts: vec![host],
                        methods: None,
                        paths: None,
                    },
                    v => serde_json::from_value(v).with_context(|| what.clone())?,
                };
                e.check(&what, kind == "allow")?;
                let (methods, paths) = (e.methods.unwrap_or_default(), e.paths.unwrap_or_default());
                rules.extend(e.hosts.into_iter().map(|host| NetRule {
                    host: kit_host(host),
                    methods: methods.clone(),
                    paths: paths.clone(),
                }));
            }
            Ok(rules)
        };
        Ok(Rules {
            allow: flat(self.allow, "allow")?,
            deny: flat(self.deny, "deny")?,
        })
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
    // `split` gives one empty word for an empty name, so that's refused too.
    let kebab = |s: &str| {
        s.split('-').all(|w| {
            !w.is_empty()
                && w.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        })
    };
    if !kebab(&c.service) {
        bail!(
            "credential@1 service {:?} must be a lowercase-kebab name",
            c.service
        );
    }
    let phases = phases(c.phase)?;
    let (env, inject) = match c.api_key {
        Some(k) => {
            let inject = k
                .inject
                .into_iter()
                .enumerate()
                .map(|(n, i)| {
                    i.into_inject()
                        .with_context(|| format!("apiKey.inject[{n}]"))
                })
                .collect::<Result<_>>()?;
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

/// The phases a capability's `phase:` names, each at most once.
fn phases(phase: OneOrMany) -> Result<Vec<SshPhase>> {
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
        if phases.contains(&phase) {
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
    let phases = phases(c.phase)?;
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

/// SPEC-v3: one kit's `ssh-agent@1` entries may not name the same phase twice (top-level entries
/// and each group's members apart).
fn check_ssh_phases(kit: &str, caps: &[Cap]) -> Result<()> {
    let mut seen = Vec::new();
    for c in caps {
        if let CapBody::SshAgent { phases, .. } = &c.body {
            for p in phases {
                let p = (c.scope(), *p);
                if seen.contains(&p) {
                    bail!(
                        "kit {kit}: ssh-agent@1 entries overlap in phase {}",
                        p.1.as_str()
                    );
                }
                seen.push(p);
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

/// `clipboard@1`: the media types each direction admits; a missing list admits every type.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClipboardCfg {
    read: Option<Vec<String>>,
    write: Option<Vec<String>>,
}

/// clipboard@1's config rules: each entry a lowercase media type, `type/*` or `*/*`, by its
/// canonical name and once, and an entry that turns both directions off is refused.
fn check_clipboard(config: Option<Value>) -> Result<()> {
    static PATTERN: std::sync::LazyLock<regex_lite::Regex> = std::sync::LazyLock::new(|| {
        let token = "[a-z0-9][a-z0-9!#$&^_.+-]*";
        regex_lite::Regex::new(&format!(r"^(\*/\*|{token}/(\*|{token}))$")).unwrap()
    });
    let Some(config) = config else { return Ok(()) };
    // A null would read as the default, which grants every type.
    let Some(fields) = config.as_object() else {
        bail!("config must be an object");
    };
    for d in ["read", "write"] {
        if fields.get(d).is_some_and(Value::is_null) {
            bail!("{d} must be a list of media types");
        }
    }
    let c: ClipboardCfg = decode(Some(config))?;
    for (d, list) in [("read", &c.read), ("write", &c.write)] {
        for (i, t) in list.iter().flatten().enumerate() {
            if !PATTERN.is_match(t) {
                bail!("{d}: {t:?} is not a lowercase media type, type/*, or */*");
            }
            // Requests are judged by canonical type, so an alias would admit nothing.
            if t == "image/x-png" {
                bail!("{d}: {t:?} is an alias; write \"image/png\"");
            }
            if list.iter().flatten().take(i).any(|e| e == t) {
                bail!("{d}: {t:?} is listed twice");
            }
        }
    }
    if c.read.is_some_and(|l| l.is_empty()) && c.write.is_some_and(|l| l.is_empty()) {
        bail!("read and write both admit nothing; an entry granting nothing is refused");
    }
    Ok(())
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
struct DockerdCfg {
    #[serde(rename = "autoStart")]
    auto_start: Option<bool>,
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

/// A mode is 3 or 4 octal digits (`755`, `1777`): it goes to a `chmod`-style mount option.
fn check_octal_mode(cap: &str, mode: Option<&str>) -> Result<()> {
    if let Some(m) = mode
        && !((3..=4).contains(&m.len()) && m.bytes().all(|b| (b'0'..=b'7').contains(&b)))
    {
        bail!("{cap} mode {m:?} must be octal");
    }
    Ok(())
}

/// smolvm's `-v` reads `:` as the host:guest separator, so a guest path can't hold one.
fn no_colon(ty: &str, path: &str) -> Result<()> {
    if path.contains(':') {
        bail!("{ty} path {path:?} can't contain ':' (smolvm reads it as host:guest)");
    }
    Ok(())
}

/// `path` cleaned lexically: `.` dropped, `..` taking the component before it (none above the
/// root), repeated and trailing `/` collapsed. No file system access, so links aren't followed.
fn clean_path(path: &str) -> String {
    use std::path::{Component, PathBuf};
    let mut clean = PathBuf::new();
    for c in std::path::Path::new(path).components() {
        match c {
            Component::ParentDir => {
                clean.pop();
            }
            Component::CurDir => {}
            c => clean.push(c),
        }
    }
    clean.to_string_lossy().into_owned()
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
    delivery: Option<String>,
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
    // The launch-argv tail for interactive sessions belongs to the agent launcher; only whether
    // it's declared is kept.
    interactive: Option<Vec<String>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
// Some fields are only accepted, so published descriptors parse.
#[allow(dead_code)]
struct HookCfg {
    command: HookCmd,
    user: Option<String>,
    #[serde(default)]
    env: Vec<String>,
    // Meaningful for startup hooks only.
    background: Option<bool>,
    description: Option<String>,
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

/// A file's path must be absolute (once its references expand: a config holding one is read
/// again then).
fn lifecycle(c: LifecycleCfg) -> Result<Lifecycle> {
    if let Some(f) = c.files.iter().find(|f| !f.path.starts_with('/')) {
        bail!("lifecycle@1 file path {:?} must be absolute", f.path);
    }
    // `clean_env` is decided when hooks are merged (`resolve`).
    let hook = |h: HookCfg| Hook {
        command: h.command,
        user: h.user,
        env: h.env,
        background: h.background.unwrap_or(false),
        clean_env: false,
        listed_runtime_env: false,
    };
    Ok(Lifecycle {
        interactive: c.interactive.is_some(),
        install: c.install.into_iter().map(hook).collect(),
        startup: c.startup.into_iter().map(hook).collect(),
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
    })
}

#[cfg(test)]
#[path = "v3_tests.rs"]
mod tests;
