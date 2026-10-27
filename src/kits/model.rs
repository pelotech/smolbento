//! Format-neutral kit model. Parsers (v3, v2) produce it; the resolver and apply code consume it.

use std::collections::BTreeMap;
use std::path::PathBuf;

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
    pub provides: Vec<String>,
    pub requires: Vec<String>,
    pub args: BTreeMap<String, ArgDef>,
    pub caps: Vec<Cap>,
    /// Plain environment variables (v2 `environment.variables`), set at start.
    pub env: Vec<(String, String)>,
    pub content: Content,
    /// Image Entrypoint+Cmd (sbx@1), filled by registry/compose.
    pub command: Option<Vec<String>>,
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
