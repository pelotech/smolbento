//! Format-neutral kit model. Parsers (v3, v2) produce it; the resolver and apply code consume it.

use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::{Result, bail};
use serde::{Deserialize, Deserializer};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Workload,
    Mixin,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    Registry(String),
    /// A kit directory or file on this host: a v3 descriptor or a v2 `spec.yaml` (`Kit.v2`).
    Local(PathBuf),
    Smolfile(PathBuf),
    /// A built-in agent's published kit (`load::agent`), by the ref it was loaded from: trusted
    /// like smolbento's own kits, and the only kind that gets the built-in agent's extras.
    Agent(String),
    /// A kit shipped inside smolbento (`load::builtin`), by name: only `docker` so far.
    Builtin(&'static str),
}

/// The kit file format a kit was written in; `v2` or `v3` in a sandbox's kit records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    V2,
    V3,
}

impl Format {
    /// `v2` or `v3`, as `kit inspect` writes it.
    pub fn name(self) -> &'static str {
        match self {
            Format::V2 => "v2",
            Format::V3 => "v3",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Content {
    /// Declaration-only.
    None,
    /// OCI layout dir in the kit cache (registry pull or build).
    Oci(PathBuf),
    /// v2 `sandbox.image`, or a `-t IMAGE` in place of a kit's: a plain image ref.
    Image(String),
    Smolfile(PathBuf),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Kit {
    /// Descriptor name, else the last path/ref segment without tag.
    pub name: String,
    pub source: Source,
    /// `sha256:...` of the manifest, when known.
    pub digest: Option<String>,
    pub kind: Kind,
    /// `name@version` (`kits::capability`); unversioned only from a published kit or a v2 one.
    pub provides: Vec<String>,
    /// `name` or `name <op> version, ...`.
    pub requires: Vec<String>,
    /// `name` or `name <op> version, ...`: works with a provider when present (SPEC-v3 §5).
    pub integrates: Vec<String>,
    /// Bare names that must be absent from the set.
    pub conflicts: Vec<String>,
    pub args: BTreeMap<String, ArgDef>,
    pub caps: Vec<Cap>,
    /// Plain environment variables (v2 `environment.variables`), set at start.
    pub env: Vec<(String, String)>,
    pub content: Content,
    /// Image Entrypoint+Cmd (sbx@1), filled by registry/compose.
    pub command: Option<Vec<String>>,
    /// The image config's `User` and `WorkingDir`, for a kit read from an OCI layout (v3).
    pub config: Option<ImageConfig>,
    /// Its manifest asks for a Docker engine (`com.docker.sandboxes.start-docker: "true"`), as
    /// sbx's published agent kits do.
    pub starts_docker: bool,
    /// The reference the user gave (`--kit`, the agent argument), as typed: resolver messages name
    /// kits by it, as sbx does. None for kits already in a sandbox.
    pub reference: Option<String>,
    /// Read from a v2 `spec.yaml`, local or published: the kit's one record of its format.
    pub v2: bool,
}

impl Kit {
    /// A kit with nothing in it but its name, kind and source; set the rest with `..Kit::new(..)`.
    pub fn new(name: &str, kind: Kind, source: Source) -> Kit {
        Kit {
            name: name.into(),
            source,
            digest: None,
            kind,
            provides: vec![],
            requires: vec![],
            integrates: vec![],
            conflicts: vec![],
            args: BTreeMap::new(),
            caps: vec![],
            env: vec![],
            content: Content::None,
            command: None,
            config: None,
            starts_docker: false,
            reference: None,
            v2: false,
        }
    }

    /// A published, digested kit for tests: `Registry("acme/<name>:1")`, `sha256:abab…`.
    #[cfg(test)]
    pub fn test(name: &str, kind: Kind) -> Kit {
        Kit {
            digest: Some(format!("sha256:{}", "ab".repeat(32))),
            ..Kit::new(name, kind, Source::Registry(format!("acme/{name}:1")))
        }
    }

    /// A built-in agent's published kit for tests: `Agent("docker.io/sbx/<name>:latest")`, image
    /// `img:1`, launching `<name>`.
    #[cfg(test)]
    pub fn agent_test(name: &str) -> Kit {
        Kit {
            content: Content::Image("img:1".into()),
            command: Some(vec![name.into()]),
            digest: Some(format!("sha256:{}", "ab".repeat(32))),
            ..Kit::new(
                name,
                Kind::Workload,
                Source::Agent(format!("docker.io/sbx/{name}:latest")),
            )
        }
    }

    /// The kit file format it was written in: `None` for a Smolfile, which isn't a kit file.
    pub fn format(&self) -> Option<Format> {
        match (&self.source, self.v2) {
            (Source::Smolfile(_), _) => None,
            (_, true) => Some(Format::V2),
            (_, false) => Some(Format::V3),
        }
    }

    /// How messages name the kit: its reference as typed, else its name.
    pub fn label(&self) -> &str {
        self.reference.as_deref().unwrap_or(&self.name)
    }
}

/// The runtime fields of a kit image's config that sbx honours besides its command.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImageConfig {
    /// `User`, as written (`name`, `uid`, `name:group`); empty for root.
    pub user: String,
    /// `WorkingDir`; empty for `/`.
    pub workdir: String,
    /// `Env`, in order: the base of `${{ kit.env.* }}` (SPEC-v3 §6.1).
    pub env: Vec<(String, String)>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ArgDef {
    pub default: Option<String>,
    pub required: bool,
    pub pattern: Option<String>,
    pub enum_values: Vec<String>,
    pub env: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cap {
    /// Full capability type, e.g. `com.docker.sandbox/volume@1`.
    pub ty: String,
    /// A group member's is its group's.
    pub optional: bool,
    /// Read from the config as written. One with a reference is read again from `config` once
    /// `resolve` expands it.
    pub body: CapBody,
    /// Set for a member of a capability group: its members are selected together.
    pub group: Option<Group>,
    /// A v3 config holding a `${{ kit.args.* }}` or `${{ kit.env.* }}` reference, kept for
    /// `resolve` to expand and read strictly (SPEC-v3 §6).
    pub config: Option<serde_json::Value>,
}

impl Cap {
    /// A top-level capability of type `ty`, with no kept config.
    pub fn new(ty: impl Into<String>, optional: bool, body: CapBody) -> Self {
        Self {
            ty: ty.into(),
            optional,
            body,
            group: None,
            config: None,
        }
    }

    /// Which entries a kit's per-entry checks compare it with: the top-level ones (`None`), or
    /// its group's (SPEC-v3 §7.1.1).
    pub fn scope(&self) -> Option<usize> {
        self.group.as_ref().map(|g| g.index)
    }
}

/// Where a group member sits in its descriptor (SPEC-v3 §7.1.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    /// The group's index in `capabilities`.
    pub index: usize,
    /// The member's index in the group's `capabilities`.
    pub member: usize,
    pub name: Option<String>,
}

impl Group {
    /// `capabilities[i]`, the spec's path for the group.
    pub fn path(&self) -> String {
        format!("capabilities[{}]", self.index)
    }

    /// `capabilities[i].group.capabilities[j]`, the spec's path for the member.
    pub fn member_path(&self) -> String {
        format!("{}.group.capabilities[{}]", self.path(), self.member)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapBody {
    Network {
        install: Rules,
        runtime: Rules,
    },
    Credential(CredReq),
    Port {
        container: u16,
        udp: bool,
    },
    Volume {
        path: String,
        tmpfs: bool,
        mode: Option<String>,
    },
    /// A runtime-owned host directory at `path`, shared by the kit's sandboxes. `mode` is applied
    /// when the directory is created (default `0755`).
    HostMount {
        path: String,
        mode: Option<String>,
    },
    /// `cpus` stays text so the model can be `Eq`; apply parses it.
    Resources {
        cpus: Option<String>,
        memory: Option<String>,
    },
    Lifecycle(Lifecycle),
    AgentContext(AgentContextReq),
    Sbx,
    GitIdentity,
    LongRunning,
    Privileged,
    /// `dockerd@1`: an engine in the sandbox, as `privileged@1` plus a store at `/var/lib/docker`.
    Dockerd {
        auto_start: bool,
    },
    AgentSessions,
    /// `ssh-agent@1`: the user's SSH agent in these phases. Unrestricted signs anything; a
    /// bounded entry signs only `sign` namespaces and `authenticate` logins.
    SshAgent {
        phases: Vec<SshPhase>,
        unrestricted: bool,
        sign: Vec<String>,
        authenticate: Vec<String>,
    },
    /// `agent-skills@1`: a directory the agent reads skills from.
    AgentSkills {
        path: String,
        readwrite: bool,
    },
    /// `agent-skill@1`: a skill in the image at `source`, exposed as `name`.
    AgentSkill {
        source: String,
        name: String,
    },
    /// Known-unsupported or unknown type.
    Unsupported,
    /// A config that can't be read until its references expand (a reference where a number
    /// goes, say); `Cap::config` holds it.
    Pending,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SshPhase {
    Install,
    Runtime,
}

#[cfg(test)]
impl CapBody {
    /// An `ssh-agent@1` entry; unrestricted when it has neither limit.
    pub fn ssh_agent(phases: &[SshPhase], sign: &[&str], authenticate: &[&str]) -> CapBody {
        let list = |l: &[&str]| l.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        CapBody::SshAgent {
            phases: phases.to_vec(),
            unrestricted: sign.is_empty() && authenticate.is_empty(),
            sign: list(sign),
            authenticate: list(authenticate),
        }
    }
}

impl SshPhase {
    pub fn as_str(self) -> &'static str {
        match self {
            SshPhase::Install => "install",
            SshPhase::Runtime => "runtime",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Rules {
    pub allow: Vec<NetRule>,
    pub deny: Vec<NetRule>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetRule {
    pub host: String,
    pub methods: Vec<String>,
    pub paths: Vec<String>,
}

impl NetRule {
    /// A rule for a whole host: any method, any path.
    pub fn host(host: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            methods: vec![],
            paths: vec![],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredReq {
    pub service: String,
    pub install: bool,
    pub runtime: bool,
    pub env: Option<String>,
    pub inject: Vec<Inject>,
    pub oauth: Option<OAuthReq>,
}

impl CredReq {
    /// Outbound rewrites only (an `apiKey` with `inject` and no `name`, and no OAuth): the guest
    /// gets no variable for it (`tck: credential@1/inject-only-no-env`).
    pub fn inject_only(&self) -> bool {
        self.env.is_none() && self.oauth.is_none() && !self.inject.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthReq {
    pub passthrough: bool,
    pub token_host: Option<String>,
    pub resource_hosts: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inject {
    pub domain: String,
    pub header: Option<String>,
    pub format: Option<String>,
    pub basic_user: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Lifecycle {
    pub install: Vec<Hook>,
    pub startup: Vec<Hook>,
    pub files: Vec<FileReq>,
    /// Declares an `interactive` tail. smolbento doesn't use it, but two in one composition are
    /// refused (`resolve`).
    pub interactive: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hook {
    pub command: HookCmd,
    pub user: Option<String>,
    pub env: Vec<String>,
    pub background: bool,
    /// sbx's v3 install-hook environment: `env -i` with a small baseline plus the declared `env`.
    /// Set when hooks are merged (`resolve::add_lifecycle`); a parsed hook has it off.
    pub clean_env: bool,
}

/// A hook's command, read from a v3 `lifecycle@1` config as a string or an argv list.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
// The name a refused command has always been reported under.
#[serde(untagged, rename = "CommandCfg")]
pub enum HookCmd {
    /// A string command, run via `sh -c`.
    Shell(String),
    Argv(Vec<String>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileReq {
    /// Absolute, or relative to the sandbox's workspace (a v2 kit's `files/workspace`).
    pub path: String,
    /// Bytes, not text: a kit's `files/` directory can hold anything (sbx copies it as is).
    pub content: Vec<u8>,
    pub mode: Option<String>,
    pub overwrite: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentContextReq {
    pub filename: Option<String>,
    pub directory: Option<String>,
    /// The inline body; empty for none.
    pub content: String,
    /// `agent-context@1` `contentFile`: the body's path in the kit image, where the agent reads it.
    pub content_file: Option<String>,
}

/// A YAML scalar: sbx accepts an unquoted number or bool where an arg default or enum value is
/// a string, and coerces it (`5` is `"5"`).
#[derive(Deserialize)]
#[serde(untagged)]
enum Scalar {
    Str(String),
    Int(i64),
    Uint(u64),
    Float(f64),
    Bool(bool),
}

impl Scalar {
    fn into_string(self) -> String {
        match self {
            Scalar::Str(s) => s,
            Scalar::Int(n) => n.to_string(),
            Scalar::Uint(n) => n.to_string(),
            Scalar::Float(n) => n.to_string(),
            Scalar::Bool(b) => b.to_string(),
        }
    }
}

/// `deserialize_with` for an optional string that may be written as a number or bool.
pub(crate) fn opt_scalar<'de, D: Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    Ok(Option::<Scalar>::deserialize(d)?.map(Scalar::into_string))
}

/// `deserialize_with` for a list of strings that may be written as numbers or bools.
pub(crate) fn scalar_list<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<String>, D::Error> {
    Ok(Vec::<Scalar>::deserialize(d)?
        .into_iter()
        .map(Scalar::into_string)
        .collect())
}

/// Rejects a hook with nothing to run: an empty argv or a blank shell string. Hooks are numbered
/// from 1 within their list.
pub(crate) fn check_hooks(kit: &str, l: &Lifecycle) -> Result<()> {
    for (phase, hooks) in [("install", &l.install), ("startup", &l.startup)] {
        for (i, h) in hooks.iter().enumerate() {
            let empty = match &h.command {
                HookCmd::Shell(s) => s.trim().is_empty(),
                HookCmd::Argv(a) => a.is_empty(),
            };
            if empty {
                bail!("kit {kit}: {phase} hook {} has an empty command", i + 1);
            }
        }
    }
    Ok(())
}
