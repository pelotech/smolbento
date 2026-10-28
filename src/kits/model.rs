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
    LocalV3(PathBuf),
    LocalV2(PathBuf),
    Smolfile(PathBuf),
    /// An agent preset as the workload (`load::preset_kit`), with its image: not a kit the user
    /// chose.
    Preset(String),
    /// A kit shipped inside smolbento (`load::builtin`), by name: only `docker` so far.
    Builtin(&'static str),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Content {
    /// Declaration-only.
    None,
    /// OCI layout dir in the kit cache (registry pull or build).
    Oci(PathBuf),
    /// v2 `sandbox.image` / agent preset: a plain image ref.
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
    /// The reference the user gave (`--kit`, the agent argument), as typed: resolver messages name
    /// kits by it, as sbx does. None for presets and kits already in a sandbox.
    pub reference: Option<String>,
}

impl Kit {
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
    pub optional: bool,
    pub body: CapBody,
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
    AgentSessions,
    /// Known-unsupported or unknown type.
    Unsupported,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredReq {
    pub service: String,
    pub install: bool,
    pub runtime: bool,
    pub env: Option<String>,
    pub inject: Vec<Inject>,
    pub oauth: Option<OAuthReq>,
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hook {
    pub command: HookCmd,
    pub user: Option<String>,
    pub env: Vec<String>,
    pub background: bool,
    /// sbx's v3 install-hook environment: `env -i` with a small baseline plus the declared `env`.
    /// Off for v3 startup hooks and all v2 hooks, which get the full container environment.
    pub clean_env: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HookCmd {
    /// A string command, run via `sh -c`.
    Shell(String),
    Argv(Vec<String>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileReq {
    pub path: String,
    pub content: String,
    pub mode: Option<String>,
    pub overwrite: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentContextReq {
    pub filename: Option<String>,
    pub directory: Option<String>,
    /// Inline body, or `file:<path>` for a `contentFile` staged in the kit image.
    pub content: String,
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
