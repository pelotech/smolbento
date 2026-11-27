use std::collections::BTreeMap;

use crate::ssh_agent::AgentLabel;

pub const NAME: &str = "sbx.name";
pub const AGENT: &str = "sbx.agent";
pub const WORKSPACES: &str = "sbx.workspaces";
pub const CREATED: &str = "sbx.created";
/// The sandbox's `SANDBOX_ID`, minted at create: kept across restarts, new for a new sandbox.
pub const ID: &str = "sbx.id";
/// The smolbento version that created the sandbox (sbx's `created_version`).
pub const VERSION: &str = "sbx.version";
pub const DOCKER: &str = "sbx.docker";
pub const SECRETS: &str = "sbx.secrets";
pub const CREDENTIAL_HOSTS: &str = "sbx.credential-hosts";
pub const CREDENTIAL_ENV: &str = "sbx.credential-env";
/// The kit builder's stored registry hosts, sorted: its header bindings, fixed at create.
pub const REGISTRIES: &str = "sbx.registries";
/// The published ports whose host port was picked (`-p PORT`, a kit's ports), as `HOST:PORT[/udp]`:
/// a start picks new ones, as sbx does.
pub const AUTO_PORTS: &str = "sbx.auto-ports";
pub const CLONE: &str = "sbx.clone";
pub const FORK_OF: &str = "sbx.fork-of";
/// The setup that created it (`host_service::namespace`): policy changes reach only their own setup's
/// sandboxes, though setups can share a smolvm home. A fork inherits it.
pub const SETUP: &str = "sbx.setup";
pub const KITS: &str = "sbx.kits";

/// The `sbx.kits` value for `kits`.
pub fn kits_value(kits: &[KitRecord]) -> String {
    serde_json::to_string(kits).expect("kit records serialize")
}

/// One applied kit in the `sbx.kits` label: what `kit add` checks a new kit against.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct KitRecord {
    pub name: String,
    /// The pinned ref (`REF@sha256:…`), or a local kit's path.
    #[serde(rename = "ref")]
    pub reference: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub provides: Vec<String>,
    /// The workload format the kit mixes with; none when it mixes with either.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<crate::kits::model::Format>,
    /// The kit's arguments as the sandbox was created with them (defaults included): a template
    /// recreates the kit with these.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub args: BTreeMap<String, String>,
}
pub const COMMAND: &str = "sbx.command";
/// The image config's `User` a v3 workload kit's agent runs as (`0` for root).
pub const USER: &str = "sbx.user";
/// A v3 workload kit's image WORKDIR, when not `/`.
pub const WORKDIR: &str = "sbx.workdir";
/// The agent files in the guest that the kits' `agent-context` names, comma-separated (`kit add`
/// writes a new kit's context to each).
pub const AGENT_FILE: &str = "sbx.agent-file";
/// The `agent-context` version the sandbox's kits were applied under (`1` or `2`): a sandbox
/// uses one, so `kit add` keeps to it.
pub const AGENT_CONTEXT: &str = "sbx.agent-context";
pub const CREDENTIAL_INSTALL: &str = "sbx.credential-install";
pub const LONG_RUNNING: &str = "sbx.long-running";
/// Created without the host loopback deny, because a `localhost` rule applied: only such a
/// sandbox gets the gateway from `localhost` rules (see `policy::compile::HOST_GATEWAY`).
pub const HOST_ACCESS: &str = "sbx.host-access";
/// Created with the browser and clipboard bridge socket (`bridge::GUEST_SOCKET`).
pub const BRIDGE: &str = "sbx.bridge";
/// The host sockets are owned by service-manager units (`host_service`), so they answer while the
/// sandbox runs, not only while a session is attached.
pub const SERVICE: &str = "sbx.service";
/// The SSH agent granted at create, per phase (`ssh_agent::AgentLabel`, JSON).
pub const SSH_AGENT: &str = "sbx.ssh-agent";
/// The hosted-egress port and bindings (`egress::Label`, JSON); absent unless `network.egress` is `hosted`.
pub const EGRESS: &str = "sbx.egress";
/// Kit host mounts: a JSON object of guest path to host directory.
pub const HOST_MOUNTS: &str = "sbx.host-mounts";
/// Created with `/dev/fuse` taken away (an environment file's `sandboxOptions.fuse: false`).
pub const NO_FUSE: &str = "sbx.no-fuse";
/// Files in mounted workspaces made read-only in the guest at each start: an environment's
/// files, as sbx mounts them unless `writableEnvFiles` (a JSON list).
pub const READ_ONLY_FILES: &str = "sbx.read-only-files";
/// How the sandbox shares the skills store (`skills::Label`, JSON), fixed at create.
pub const SKILLS: &str = "sbx.skills";
/// The saved template the sandbox was created from (`docker.io/library/t:v1`).
pub const TEMPLATE: &str = "sbx.template";
/// The registered MCP servers chosen with `--static-mcp` (comma list; empty for `none`). Absent
/// when the flag wasn't given.
pub const MCP: &str = "sbx.mcp";
/// Prefix of the labels that bind a guest env var to an `--static-mcp` server's secret.
pub const MCP_SECRET: &str = "sbx.mcp-secret.";
/// Prefix of `sbx.credential-format.<ENV>`: how a kit credential's value is formatted.
pub const CREDENTIAL_FORMAT: &str = "sbx.credential-format.";
/// Prefix of `sbx.credential-service.<ENV>`: the secret service behind a kit credential's env var
/// when it isn't one of that service's own env vars.
pub const CREDENTIAL_SERVICE: &str = "sbx.credential-service.";

/// How a kit credential's value becomes its header value (`:set-header`), applied at start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredFormat {
    /// `%s` stands for the value, e.g. `Bearer %s`.
    Format(String),
    /// HTTP basic auth with this user name and the value as the password.
    Basic(String),
}

impl CredFormat {
    fn to_label(&self) -> String {
        match self {
            CredFormat::Format(f) => format!("format:{f}"),
            CredFormat::Basic(u) => format!("basic:{u}"),
        }
    }

    fn from_label(s: &str) -> Option<CredFormat> {
        if let Some(f) = s.strip_prefix("format:") {
            return Some(CredFormat::Format(f.to_string()));
        }
        s.strip_prefix("basic:")
            .map(|u| CredFormat::Basic(u.to_string()))
    }

    /// The header value for `value`.
    pub fn apply(&self, value: &str) -> String {
        match self {
            CredFormat::Format(f) => f.replace("%s", value),
            CredFormat::Basic(user) => {
                use base64::Engine;
                let raw = format!("{user}:{value}");
                format!(
                    "Basic {}",
                    base64::engine::general_purpose::STANDARD.encode(raw)
                )
            }
        }
    }
}

/// The fields recorded as labels at create just as the `CreateRequest` gives them, shared by it
/// and `Meta`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Recorded {
    /// Read only: smolvm reports the machine holds no credential bindings.
    pub no_credential_bindings: bool,
    /// Read only: `sbx.egress` is present but unreadable, so a start must refuse.
    pub egress_unreadable: bool,
    /// Services whose credentials were bound at create (`sbx.secrets`).
    pub secrets: Vec<String>,
    /// Hosts of those credentials as bound at create, sorted (`sbx.credential-hosts`). The
    /// machine's credentials keep them, so its allow list must too, whatever secrets.toml says now.
    pub credential_hosts: Vec<String>,
    /// Env vars of those credentials as bound at create, sorted (`sbx.credential-env`). A start
    /// removes the ones without a value, even after their service is gone from secrets.toml.
    pub credential_env: Vec<String>,
    /// The kit builder's stored registry hosts, sorted (`sbx.registries`).
    pub registries: Vec<String>,
    /// Published ports a start picks a new host port for (`sbx.auto-ports`), as `HOST:PORT[/udp]`.
    pub auto_ports: Vec<String>,
    /// Applied kits in dependency order (a preset agent isn't a kit), as `kit add` added to them
    /// (`sbx.kits`).
    pub kits: Vec<KitRecord>,
    /// The workload kit's launch argv, when it replaced the agent preset's (`sbx.command`).
    pub command: Option<Vec<String>>,
    /// A v3 workload kit's image user: the agent and `exec` run as it, the agent under
    /// `/bin/bash` (`sbx.user`).
    pub user: Option<String>,
    /// A v3 workload's image WORKDIR, where install hooks run (`kit add` too); `None` for `/`
    /// (`sbx.workdir`).
    pub image_workdir: Option<String>,
    /// `sbx.id`.
    pub id: Option<String>,
    /// The kits' agent files in the guest; empty when no kit declares one (`sbx.agent-file`).
    /// `kits::apply` uses those already set (`kit add`) instead of deriving them.
    pub agent_files: Vec<String>,
    /// The `agent-context` version in use; `None` when no kit gave agent context
    /// (`sbx.agent-context`). `kits::apply` keeps to one already set (`kit add`) instead of
    /// choosing.
    pub agent_context: Option<u8>,
    /// Env vars of install-only credentials, left out of every start after the first
    /// (`sbx.credential-install`).
    pub credential_install: Vec<String>,
    /// Don't stop the sandbox when its last session ends (`long-running@1`, `sbx.long-running`).
    pub long_running: bool,
    /// Created without the host loopback deny, as a `localhost` rule applied (`sbx.host-access`).
    pub host_access: bool,
    /// Kit credentials whose value is formatted before smolvm sets it as a header, by env var
    /// (`sbx.credential-format.<ENV>`).
    pub credential_formats: BTreeMap<String, CredFormat>,
    /// Kit credential env vars outside their service's own env vars, to their service
    /// (`sbx.credential-service.<ENV>`).
    pub credential_services: BTreeMap<String, String>,
    /// Starts take `/dev/fuse` away (`sbx.no-fuse`).
    pub no_fuse: bool,
    /// Starts make these guest files read-only (`sbx.read-only-files`).
    pub read_only_files: Vec<String>,
    /// The saved template it was created from (`sbx.template`); `template save` refuses these.
    pub template: Option<String>,
    /// Guest env var to the `mcp:` secret whose placeholder it holds (`sbx.mcp-secret.<VAR>`).
    /// Only `--static-mcp` writes these; kits can't.
    pub mcp_secrets: BTreeMap<String, String>,
}

impl Recorded {
    /// The user agent sessions run as: a v3 workload's image user, else `agent`. It may name a
    /// group (`somebody:1001`), which smolvm's `-u` takes; a guest shell wants `split_user`.
    pub fn session_user(&self) -> &str {
        self.user.as_deref().unwrap_or("agent")
    }

    /// The machine's workload user, which smolvm maps the workspace to: the session user, root
    /// for an internal sandbox (`_builder`).
    pub fn workload_user(&self, name: &str) -> &str {
        if super::name::is_internal(name) {
            return "root";
        }
        self.session_user()
    }
}

/// A `user[:group]` spec (an image's `USER`) as its user and group.
pub fn split_user(spec: &str) -> (&str, Option<&str>) {
    spec.split_once(':')
        .map_or((spec, None), |(u, g)| (u, Some(g)))
}

/// Whether a `user[:group]` spec runs as root: `root`, `0`, or no user.
pub fn is_root_user(spec: &str) -> bool {
    matches!(split_user(spec).0, "" | "0" | "root")
}

/// A sandbox's private dockerd, from its `dockerd@1` grant (the `sbx.docker` label).
/// Ordered Off < Manual < Auto, so merging grants takes the max.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum Engine {
    /// No engine: `"false"`, absent or unknown.
    #[default]
    Off,
    /// Installed but not started on its own (`autoStart: false`): `"manual"`.
    Manual,
    /// Started after each start (`autoStart: true`): `"true"`.
    Auto,
}

impl Engine {
    fn label(self) -> &'static str {
        match self {
            Engine::Off => "false",
            Engine::Auto => "true",
            Engine::Manual => "manual",
        }
    }

    fn from_label(v: Option<&str>) -> Engine {
        match v {
            Some("true") => Engine::Auto,
            Some("manual") => Engine::Manual,
            _ => Engine::Off,
        }
    }
}

/// Sandbox metadata, fixed at create and stored as smolvm machine labels.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Meta {
    pub name: String,
    pub agent: String,
    /// Every mounted workspace, primary first, as `path` or `path:ro`.
    pub workspaces: Vec<String>,
    /// Unix seconds.
    pub created: i64,
    /// The smolbento version that created it.
    pub version: String,
    /// The sandbox's private dockerd (`sbx.docker`).
    pub engine: Engine,
    /// What the `CreateRequest` gave, recorded unchanged.
    pub rec: Recorded,
    /// `--clone`: the host repo's top, which is also the clone's path in the guest (`sbx.clone`).
    pub clone_repo: Option<String>,
    /// The sandbox this one was forked from.
    pub fork_of: Option<String>,
    /// `sbx.setup`: the setup (`host_service::namespace`) whose policy applies to it.
    pub setup: Option<String>,
    /// Created with the bridge socket mounted: starts install the guest shims (`sbx.bridge`).
    pub bridge: bool,
    /// Its host sockets are served by units, not by an attached session (`sbx.service`).
    pub service: bool,
    /// Kit host mounts: guest path to host directory.
    pub host_mounts: BTreeMap<String, String>,
    /// The SSH agent phases granted at create and what each may sign (`sbx.ssh-agent`).
    pub ssh_agent: Option<AgentLabel>,
    /// Hosted egress recorded at create (`sbx.egress`).
    pub egress: Option<crate::egress::Label>,
    /// The skills mode and directories set at create (`sbx.skills`).
    pub skills: Option<crate::skills::Label>,
    /// The registered MCP servers chosen at create (`sbx.mcp`); `None` without `--static-mcp`.
    pub mcp: Option<Vec<String>>,
}

impl Meta {
    pub fn to_labels(&self) -> BTreeMap<String, String> {
        fn json(v: &impl serde::Serialize) -> String {
            serde_json::to_string(v).expect("strings serialize")
        }
        let list = |v: &[String]| (!v.is_empty()).then(|| v.join(","));
        let flag = |on: bool| on.then(|| "true".to_string());
        let mut labels = BTreeMap::from([
            (NAME.to_string(), self.name.clone()),
            (AGENT.to_string(), self.agent.clone()),
            (WORKSPACES.to_string(), json(&self.workspaces)),
            (CREATED.to_string(), self.created.to_string()),
            (DOCKER.to_string(), self.engine.label().into()),
        ]);
        // Everything else is written only when set, so a sandbox's labels don't change when a
        // field it doesn't use is added. Kit labels exist only on sandboxes created with kits.
        let optional = [
            (SECRETS, list(&self.rec.secrets)),
            (CREDENTIAL_HOSTS, list(&self.rec.credential_hosts)),
            (CREDENTIAL_ENV, list(&self.rec.credential_env)),
            (REGISTRIES, list(&self.rec.registries)),
            (AUTO_PORTS, list(&self.rec.auto_ports)),
            (CLONE, self.clone_repo.clone()),
            (FORK_OF, self.fork_of.clone()),
            (SETUP, self.setup.clone()),
            (
                KITS,
                (!self.rec.kits.is_empty()).then(|| json(&self.rec.kits)),
            ),
            (VERSION, Some(self.version.clone())),
            (COMMAND, self.rec.command.as_ref().map(json)),
            (USER, self.rec.user.clone()),
            (WORKDIR, self.rec.image_workdir.clone()),
            (ID, self.rec.id.clone()),
            (AGENT_FILE, list(&self.rec.agent_files)),
            (AGENT_CONTEXT, self.rec.agent_context.map(|v| v.to_string())),
            (CREDENTIAL_INSTALL, list(&self.rec.credential_install)),
            (LONG_RUNNING, flag(self.rec.long_running)),
            (HOST_ACCESS, flag(self.rec.host_access)),
            (BRIDGE, flag(self.bridge)),
            (SERVICE, flag(self.service)),
            (
                HOST_MOUNTS,
                (!self.host_mounts.is_empty()).then(|| json(&self.host_mounts)),
            ),
            (NO_FUSE, flag(self.rec.no_fuse)),
            (
                READ_ONLY_FILES,
                (!self.rec.read_only_files.is_empty()).then(|| json(&self.rec.read_only_files)),
            ),
            (SSH_AGENT, self.ssh_agent.as_ref().map(|a| a.to_label())),
            (EGRESS, self.egress.as_ref().map(|e| e.to_label())),
            (SKILLS, self.skills.as_ref().map(|s| s.to_label())),
            (TEMPLATE, self.rec.template.clone()),
            (MCP, self.mcp.as_ref().map(|names| names.join(","))),
        ];
        for (key, value) in optional {
            if let Some(value) = value {
                labels.insert(key.to_string(), value);
            }
        }
        for (env, f) in &self.rec.credential_formats {
            labels.insert(format!("{CREDENTIAL_FORMAT}{env}"), f.to_label());
        }
        for (env, service) in &self.rec.credential_services {
            labels.insert(format!("{CREDENTIAL_SERVICE}{env}"), service.clone());
        }
        for (env, secret) in &self.rec.mcp_secrets {
            labels.insert(format!("{MCP_SECRET}{env}"), secret.clone());
        }
        labels
    }

    /// `None` for machines smolbento didn't create.
    pub fn from_labels(labels: &BTreeMap<String, String>) -> Option<Meta> {
        fn json<T: serde::de::DeserializeOwned>(
            labels: &BTreeMap<String, String>,
            key: &str,
        ) -> Option<T> {
            labels.get(key).and_then(|j| serde_json::from_str(j).ok())
        }
        let text = |key: &str| labels.get(key).cloned();
        let flag = |key: &str| labels.get(key).is_some_and(|v| v == "true");
        let egress = text(EGRESS).and_then(|j| crate::egress::Label::from_label(&j));
        let egress_unreadable = labels.contains_key(EGRESS) && egress.is_none();
        Some(Meta {
            name: labels.get(NAME)?.clone(),
            agent: text(AGENT).unwrap_or_default(),
            workspaces: json(labels, WORKSPACES).unwrap_or_default(),
            created: labels
                .get(CREATED)
                .and_then(|c| c.parse().ok())
                .unwrap_or(0),
            version: text(VERSION).unwrap_or_default(),
            engine: Engine::from_label(labels.get(DOCKER).map(String::as_str)),
            // Not a path (an older sandbox's `true`): no repo to touch.
            clone_repo: text(CLONE).filter(|p| std::path::Path::new(p).is_absolute()),
            fork_of: text(FORK_OF),
            setup: text(SETUP),
            bridge: flag(BRIDGE),
            service: flag(SERVICE),
            host_mounts: json(labels, HOST_MOUNTS).unwrap_or_default(),
            ssh_agent: text(SSH_AGENT).and_then(|j| AgentLabel::from_label(&j)),
            egress,
            skills: text(SKILLS).and_then(|j| crate::skills::Label::from_label(&j)),
            mcp: labels.get(MCP).map(|names| list(Some(names))),
            rec: Recorded {
                no_credential_bindings: false,
                egress_unreadable,
                secrets: list(labels.get(SECRETS)),
                credential_hosts: list(labels.get(CREDENTIAL_HOSTS)),
                credential_env: list(labels.get(CREDENTIAL_ENV)),
                registries: list(labels.get(REGISTRIES)),
                auto_ports: list(labels.get(AUTO_PORTS)),
                kits: json(labels, KITS).unwrap_or_default(),
                command: json(labels, COMMAND),
                user: text(USER),
                image_workdir: text(WORKDIR),
                id: text(ID),
                agent_files: list(labels.get(AGENT_FILE)),
                agent_context: text(AGENT_CONTEXT).and_then(|v| v.parse().ok()),
                credential_install: list(labels.get(CREDENTIAL_INSTALL)),
                long_running: flag(LONG_RUNNING),
                host_access: flag(HOST_ACCESS),
                credential_formats: labels
                    .iter()
                    .filter_map(|(k, v)| {
                        let env = k.strip_prefix(CREDENTIAL_FORMAT)?;
                        Some((env.to_string(), CredFormat::from_label(v)?))
                    })
                    .collect(),
                credential_services: labels
                    .iter()
                    .filter_map(|(k, v)| {
                        Some((k.strip_prefix(CREDENTIAL_SERVICE)?.to_string(), v.clone()))
                    })
                    .collect(),
                mcp_secrets: labels
                    .iter()
                    .filter_map(|(k, v)| Some((k.strip_prefix(MCP_SECRET)?.to_string(), v.clone())))
                    .collect(),
                no_fuse: flag(NO_FUSE),
                read_only_files: json(labels, READ_ONLY_FILES).unwrap_or_default(),
                template: text(TEMPLATE),
            },
        })
    }

    /// The primary workspace: the first of `workspaces`, without `:ro`; `None` for a mountless
    /// sandbox.
    pub fn workspace(&self) -> Option<&str> {
        (self.workspaces.first()).map(|w| w.strip_suffix(":ro").unwrap_or(w))
    }

    /// A mounted host folder the sandbox can write: a copy would share it with the original.
    pub fn writable_host_folder(&self) -> bool {
        self.workspaces
            .iter()
            .enumerate()
            .any(|(i, w)| !w.ends_with(":ro") && !(i == 0 && self.clone_repo.is_some()))
    }

    /// Whether `bento fork` can copy it: no writable host folder, not itself a fork, and not an
    /// internal sandbox (`_builder`), which would only pay branchable's memory cost.
    pub fn forkable(&self) -> bool {
        self.fork_of.is_none()
            && !self.writable_host_folder()
            && !super::name::is_internal(&self.name)
    }
}

/// A comma-joined label value.
fn list(value: Option<&String>) -> Vec<String> {
    value
        .map(|s| {
            s.split(',')
                .filter(|x| !x.is_empty())
                .map(String::from)
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta() -> Meta {
        Meta {
            name: "claude-repo".into(),
            agent: "claude".into(),
            workspaces: vec!["/w/repo".into(), "/w/docs:ro".into()],
            created: 1000,
            engine: Engine::Auto,
            ..Default::default()
        }
    }

    #[test]
    fn a_sandbox_without_kits_has_no_kits_label() {
        let labels = meta().to_labels();
        assert!(!labels.contains_key("sbx.kits"), "{labels:?}");
        assert!(Meta::from_labels(&labels).unwrap().rec.kits.is_empty());
    }

    #[test]
    fn docker_label_round_trips() {
        for (engine, value) in [
            (Engine::Auto, "true"),
            (Engine::Manual, "manual"),
            (Engine::Off, "false"),
        ] {
            let m = Meta { engine, ..meta() };
            let labels = m.to_labels();
            assert_eq!(labels["sbx.docker"], value);
            assert_eq!(Meta::from_labels(&labels), Some(m));
        }
        for value in [None, Some("yes")] {
            let mut labels = meta().to_labels();
            labels.remove("sbx.docker");
            if let Some(v) = value {
                labels.insert("sbx.docker".into(), v.into());
            }
            assert_eq!(Meta::from_labels(&labels).unwrap().engine, Engine::Off);
        }
    }

    #[test]
    fn round_trip() {
        let labels = meta().to_labels();
        assert_eq!(labels["sbx.workspaces"], r#"["/w/repo","/w/docs:ro"]"#);
        assert!(!labels.contains_key("sbx.workspace"));
        assert_eq!(labels["sbx.docker"], "true");
        assert_eq!(Meta::from_labels(&labels), Some(meta()));
    }

    #[test]
    fn the_workspace_is_the_first_of_the_workspaces() {
        let mut labels = meta().to_labels();
        labels.insert("sbx.workspaces".into(), r#"["/w/a:ro","/w/b"]"#.into());
        let m = Meta::from_labels(&labels).unwrap();
        assert_eq!(m.workspace(), Some("/w/a"));
    }

    #[test]
    fn mountless_has_no_workspace() {
        let m = Meta {
            workspaces: vec![],
            ..meta()
        };
        assert_eq!(Meta::from_labels(&m.to_labels()), Some(m));
    }

    #[test]
    fn clone_labels_round_trip() {
        // A subdirectory was given: the label is the repo's top, not the workspace.
        let mut m = meta();
        m.clone_repo = Some("/w".into());
        let labels = m.to_labels();
        assert_eq!(labels["sbx.clone"], "/w");
        assert_eq!(Meta::from_labels(&labels), Some(m));
        assert!(!meta().to_labels().contains_key("sbx.clone"));
        let mut old = meta().to_labels();
        old.insert("sbx.clone".into(), "true".into());
        assert_eq!(Meta::from_labels(&old).unwrap().clone_repo, None);
        assert_eq!(
            Meta::from_labels(&meta().to_labels()).unwrap().clone_repo,
            None
        );
    }

    #[test]
    fn optional_fields_round_trip() {
        use crate::ssh_agent::Access;
        let m = Meta {
            rec: Recorded {
                template: Some("docker.io/library/t:v1".into()),
                host_access: true,
                secrets: vec!["anthropic".into(), "github".into()],
                credential_hosts: vec!["api.github.com".into(), "github.com".into()],
                credential_env: vec!["GH_TOKEN".into(), "GITHUB_TOKEN".into()],
                registries: vec!["dhi.io".into(), "ghcr.io".into()],
                kits: vec![
                    KitRecord {
                        name: "a".into(),
                        reference: "acme/a:1@sha256:ab".into(),
                        provides: vec!["agent".into()],
                        format: Some(crate::kits::model::Format::V3),
                        args: [("model".to_string(), "x".to_string())].into(),
                    },
                    KitRecord {
                        name: "b".into(),
                        reference: "/k/b".into(),
                        provides: vec![],
                        format: None,
                        args: Default::default(),
                    },
                ],
                command: Some(vec!["wl".into(), "--a b".into()]),
                user: Some("somebody".into()),
                image_workdir: Some("/x".into()),
                id: Some("af577721-672a-4708-9be0-178813f4cea3".into()),
                agent_files: vec!["/w/AGENTS.md".into(), "/home/agent/.codex/AGENTS.md".into()],
                credential_install: vec!["GH_TOKEN".into(), "NPM_TOKEN".into()],
                long_running: true,
                credential_formats: BTreeMap::from([
                    ("SBX_KIT_X".into(), CredFormat::Format("Bearer %s".into())),
                    (
                        "GH_TOKEN".into(),
                        CredFormat::Basic("x-access-token".into()),
                    ),
                ]),
                credential_services: BTreeMap::from([("SBX_KIT_X".into(), "x".into())]),
                mcp_secrets: BTreeMap::from([(
                    "SBX_MCP_LINEAR_API_KEY".into(),
                    "mcp:linear:api-key".into(),
                )]),
                ..Default::default()
            },
            bridge: true,
            service: true,
            ssh_agent: Some(AgentLabel {
                runtime: Some(Access {
                    sign: None,
                    authenticate: vec![],
                }),
                install: Some(Access {
                    sign: Some(vec!["git".into()]),
                    authenticate: vec![],
                }),
            }),
            host_mounts: BTreeMap::from([("/home/agent/x".into(), "/data/x".into())]),
            fork_of: Some("a".into()),
            mcp: Some(vec!["linear".into(), "files".into()]),
            ..meta()
        };
        let labels = m.to_labels();
        for (key, want) in [
            ("sbx.template", "docker.io/library/t:v1"),
            ("sbx.host-access", "true"),
            ("sbx.bridge", "true"),
            ("sbx.service", "true"),
            (
                "sbx.ssh-agent",
                r#"{"runtime":{"sign":null},"install":{"sign":["git"]}}"#,
            ),
            ("sbx.host-mounts", r#"{"/home/agent/x":"/data/x"}"#),
            ("sbx.secrets", "anthropic,github"),
            ("sbx.credential-hosts", "api.github.com,github.com"),
            ("sbx.credential-env", "GH_TOKEN,GITHUB_TOKEN"),
            ("sbx.registries", "dhi.io,ghcr.io"),
            ("sbx.fork-of", "a"),
            ("sbx.mcp", "linear,files"),
            (
                "sbx.kits",
                r#"[{"name":"a","ref":"acme/a:1@sha256:ab","provides":["agent"],"format":"v3","args":{"model":"x"}},{"name":"b","ref":"/k/b"}]"#,
            ),
            ("sbx.command", r#"["wl","--a b"]"#),
            ("sbx.user", "somebody"),
            ("sbx.workdir", "/x"),
            (
                "sbx.agent-file",
                "/w/AGENTS.md,/home/agent/.codex/AGENTS.md",
            ),
            ("sbx.credential-install", "GH_TOKEN,NPM_TOKEN"),
            ("sbx.long-running", "true"),
            ("sbx.credential-format.SBX_KIT_X", "format:Bearer %s"),
            ("sbx.credential-format.GH_TOKEN", "basic:x-access-token"),
            ("sbx.credential-service.SBX_KIT_X", "x"),
            (
                "sbx.mcp-secret.SBX_MCP_LINEAR_API_KEY",
                "mcp:linear:api-key",
            ),
        ] {
            assert_eq!(labels[key], want, "{key}");
        }
        assert_eq!(Meta::from_labels(&labels), Some(m));
        // None of them is written for a sandbox that doesn't use it, so its labels don't change.
        let plain = meta().to_labels();
        assert_eq!(plain.len(), 6, "{plain:?}");
    }

    #[test]
    fn a_garbled_egress_label_is_marked_unreadable() {
        let labels: BTreeMap<String, String> = [("sbx.name", "w"), ("sbx.egress", "{nope")]
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .into();
        let m = Meta::from_labels(&labels).unwrap();
        assert!(m.egress.is_none() && m.rec.egress_unreadable);
    }

    #[test]
    fn a_sandbox_with_an_egress_label_round_trips() {
        let m = Meta {
            egress: Some(crate::egress::Label {
                port: 4455,
                bindings: vec![crate::egress::Binding {
                    name: "gh_token".into(),
                    env: "GH_TOKEN".into(),
                    hosts: vec!["api.github.com".into()],
                    set_header: Some("Authorization".into()),
                    placeholder: "bento-gh_token".into(),
                }],
            }),
            ..meta()
        };
        let labels = m.to_labels();
        assert!(labels["sbx.egress"].starts_with(r#"{"port":4455,"bindings":[{"name":"gh_token""#));
        assert_eq!(Meta::from_labels(&labels), Some(m));
    }

    #[test]
    fn static_mcp_none_is_recorded_as_an_empty_label() {
        // `--static-mcp none` differs from no flag: the set was chosen, and it is empty.
        let m = Meta {
            mcp: Some(vec![]),
            ..meta()
        };
        let labels = m.to_labels();
        assert_eq!(labels["sbx.mcp"], "");
        assert_eq!(Meta::from_labels(&labels), Some(m));
        assert_eq!(Meta::from_labels(&meta().to_labels()).unwrap().mcp, None);
    }

    #[test]
    fn credential_formats_apply_to_the_value() {
        assert_eq!(
            CredFormat::Format("Bearer %s".into()).apply("t0k"),
            "Bearer t0k"
        );
        assert_eq!(
            CredFormat::Basic("x-access-token".into()).apply("ghp"),
            "Basic eC1hY2Nlc3MtdG9rZW46Z2hw"
        );
    }

    #[test]
    fn foreign_machine_is_none() {
        assert_eq!(Meta::from_labels(&BTreeMap::new()), None);
    }

    #[test]
    fn forkable_needs_no_writable_host_folder_and_no_parent() {
        let mounted = meta();
        assert!(mounted.writable_host_folder() && !mounted.forkable());
        let clone = Meta {
            clone_repo: Some("/w/repo".into()),
            ..meta()
        };
        assert!(clone.forkable());
        let mountless = Meta {
            workspaces: vec![],
            ..meta()
        };
        assert!(mountless.forkable());
        let internal = Meta {
            name: "_builder".into(),
            ..mountless.clone()
        };
        assert!(!internal.forkable());
        let fork = Meta {
            fork_of: Some("a".into()),
            ..mountless.clone()
        };
        assert!(!fork.forkable());
    }
}
