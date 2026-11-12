use std::collections::BTreeMap;

use crate::ssh_agent::AgentLabel;

pub const NAME: &str = "sbx.name";
pub const AGENT: &str = "sbx.agent";
pub const WORKSPACE: &str = "sbx.workspace";
pub const WORKSPACES: &str = "sbx.workspaces";
pub const CREATED: &str = "sbx.created";
pub const DOCKER: &str = "sbx.docker";
pub const SECRETS: &str = "sbx.secrets";
pub const CREDENTIAL_HOSTS: &str = "sbx.credential-hosts";
pub const CREDENTIAL_ENV: &str = "sbx.credential-env";
/// The kit builder's stored registry hosts, sorted: its header bindings, fixed at create.
pub const REGISTRIES: &str = "sbx.registries";
pub const CLONE: &str = "sbx.clone";
pub const CLONE_TOP: &str = "sbx.clone-top";
pub const FORK_OF: &str = "sbx.fork-of";
pub const KITS: &str = "sbx.kits";
pub const COMMAND: &str = "sbx.command";
/// The image config's `User` a v3 workload kit's agent runs as (`0` for root).
pub const USER: &str = "sbx.user";
/// A v3 workload kit's image WORKDIR, when not `/`.
pub const WORKDIR: &str = "sbx.workdir";
/// The agent file in the guest of a workload kit that declares one (`kit add` indexes into it).
pub const AGENT_FILE: &str = "sbx.agent-file";
pub const CREDENTIAL_INSTALL: &str = "sbx.credential-install";
pub const LONG_RUNNING: &str = "sbx.long-running";
/// Created without the host loopback deny, because a `localhost` rule applied: only such a
/// sandbox gets the gateway from `localhost` rules (see `policy::compile::HOST_GATEWAY`).
pub const HOST_ACCESS: &str = "sbx.host-access";
/// Created with the browser and clipboard bridge socket (`bridge::GUEST_SOCKET`).
pub const BRIDGE: &str = "sbx.bridge";
/// The SSH agent granted at create, per phase (`ssh_agent::AgentLabel`, JSON).
pub const SSH_AGENT: &str = "sbx.ssh-agent";
/// Kit host mounts: a JSON object of guest path to host directory.
pub const HOST_MOUNTS: &str = "sbx.host-mounts";
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

/// Sandbox metadata, fixed at create and stored as smolvm machine labels.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Meta {
    pub name: String,
    pub agent: String,
    /// Primary workspace; `None` for a mountless sandbox.
    pub workspace: Option<String>,
    /// Every mounted workspace, primary first, as `path` or `path:ro`.
    pub workspaces: Vec<String>,
    /// Unix seconds.
    pub created: i64,
    /// Whether the sandbox runs a private dockerd.
    pub docker: bool,
    /// Services whose credentials were bound at create.
    pub secrets: Vec<String>,
    /// Hosts of those credentials as bound at create, sorted. The machine's credentials keep
    /// them, so its allow list must too, whatever secrets.toml says now.
    pub credential_hosts: Vec<String>,
    /// Env vars of those credentials as bound at create, sorted. A start removes the ones without
    /// a value, even after their service is gone from secrets.toml.
    pub credential_env: Vec<String>,
    /// The kit builder's registry hosts, sorted (see `REGISTRIES`).
    pub registries: Vec<String>,
    /// `--clone`: the host repo's top, which is also the clone's path in the guest. Stored as
    /// `sbx.clone=true` plus `sbx.clone-top` when it differs from `workspace` (a subdirectory was
    /// given).
    pub clone_repo: Option<String>,
    /// The sandbox this one was forked from.
    pub fork_of: Option<String>,
    /// Applied kits as pinned refs (`REF@sha256:…`, or a local kit's path), dependency order.
    pub kits: Vec<String>,
    /// The workload kit's launch argv, when it replaced the agent preset's.
    pub command: Option<Vec<String>>,
    /// A v3 workload kit's image user: the agent and `exec` run as it, the agent under `/bin/bash`.
    pub user: Option<String>,
    /// A v3 workload's image WORKDIR, where install hooks run (`kit add` too); `None` for `/`.
    pub image_workdir: Option<String>,
    /// A workload kit's agent file in the guest; `None` for a preset (its file follows from its
    /// name) or a workload that declares none.
    pub agent_file: Option<String>,
    /// Env vars of install-only credentials, left out of every start after the first.
    pub credential_install: Vec<String>,
    /// Don't stop the sandbox when its last session ends (`long-running@1`).
    pub long_running: bool,
    /// Created without the host loopback deny (the `sbx.host-access` label).
    pub host_access: bool,
    /// Created with the bridge socket mounted: starts install the guest shims (`sbx.bridge`).
    pub bridge: bool,
    /// Kit credentials whose value is formatted before smolvm sets it as a header, by env var.
    pub credential_formats: BTreeMap<String, CredFormat>,
    /// Kit credential env vars outside their service's own env vars, to their service.
    pub credential_services: BTreeMap<String, String>,
    /// Kit host mounts: guest path to host directory.
    pub host_mounts: BTreeMap<String, String>,
    /// The SSH agent phases granted at create and what each may sign (`sbx.ssh-agent`).
    pub ssh_agent: Option<AgentLabel>,
    /// The skills mode and directories set at create (`sbx.skills`).
    pub skills: Option<crate::skills::Label>,
    /// The saved template it was created from (`sbx.template`); `template save` refuses these.
    pub template: Option<String>,
    /// The registered MCP servers chosen at create (`sbx.mcp`); `None` without `--static-mcp`.
    pub mcp: Option<Vec<String>>,
    /// Guest env var to the `mcp:` secret whose placeholder it holds (`sbx.mcp-secret.<VAR>`).
    /// Only `--static-mcp` writes these; kits can't.
    pub mcp_secrets: BTreeMap<String, String>,
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
            (DOCKER.to_string(), self.docker.to_string()),
        ]);
        // Everything else is written only when set, so a sandbox's labels don't change when a
        // field it doesn't use is added. Kit labels exist only on sandboxes created with kits.
        let clone_top = self
            .clone_repo
            .as_ref()
            .filter(|top| Some(*top) != self.workspace.as_ref());
        let optional = [
            (WORKSPACE, self.workspace.clone()),
            (SECRETS, list(&self.secrets)),
            (CREDENTIAL_HOSTS, list(&self.credential_hosts)),
            (CREDENTIAL_ENV, list(&self.credential_env)),
            (REGISTRIES, list(&self.registries)),
            (CLONE, flag(self.clone_repo.is_some())),
            (CLONE_TOP, clone_top.cloned()),
            (FORK_OF, self.fork_of.clone()),
            (KITS, (!self.kits.is_empty()).then(|| json(&self.kits))),
            (COMMAND, self.command.as_ref().map(json)),
            (USER, self.user.clone()),
            (WORKDIR, self.image_workdir.clone()),
            (AGENT_FILE, self.agent_file.clone()),
            (CREDENTIAL_INSTALL, list(&self.credential_install)),
            (LONG_RUNNING, flag(self.long_running)),
            (HOST_ACCESS, flag(self.host_access)),
            (BRIDGE, flag(self.bridge)),
            (
                HOST_MOUNTS,
                (!self.host_mounts.is_empty()).then(|| json(&self.host_mounts)),
            ),
            (SSH_AGENT, self.ssh_agent.as_ref().map(|a| a.to_label())),
            (SKILLS, self.skills.as_ref().map(|s| s.to_label())),
            (TEMPLATE, self.template.clone()),
            (MCP, self.mcp.as_ref().map(|names| names.join(","))),
        ];
        for (key, value) in optional {
            if let Some(value) = value {
                labels.insert(key.to_string(), value);
            }
        }
        for (env, f) in &self.credential_formats {
            labels.insert(format!("{CREDENTIAL_FORMAT}{env}"), f.to_label());
        }
        for (env, service) in &self.credential_services {
            labels.insert(format!("{CREDENTIAL_SERVICE}{env}"), service.clone());
        }
        for (env, secret) in &self.mcp_secrets {
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
        Some(Meta {
            name: labels.get(NAME)?.clone(),
            agent: text(AGENT).unwrap_or_default(),
            workspace: text(WORKSPACE),
            workspaces: json(labels, WORKSPACES).unwrap_or_default(),
            created: labels
                .get(CREATED)
                .and_then(|c| c.parse().ok())
                .unwrap_or(0),
            docker: flag(DOCKER),
            secrets: list(labels.get(SECRETS)),
            credential_hosts: list(labels.get(CREDENTIAL_HOSTS)),
            credential_env: list(labels.get(CREDENTIAL_ENV)),
            registries: list(labels.get(REGISTRIES)),
            clone_repo: flag(CLONE)
                .then(|| text(CLONE_TOP).or(text(WORKSPACE)))
                .flatten(),
            fork_of: text(FORK_OF),
            kits: json(labels, KITS).unwrap_or_default(),
            command: json(labels, COMMAND),
            user: text(USER),
            image_workdir: text(WORKDIR),
            agent_file: text(AGENT_FILE),
            credential_install: list(labels.get(CREDENTIAL_INSTALL)),
            long_running: flag(LONG_RUNNING),
            host_access: flag(HOST_ACCESS),
            bridge: flag(BRIDGE),
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
                .filter(|(var, service)| !is_old_mcp_secret(var, service))
                .collect(),
            mcp_secrets: labels
                .iter()
                .filter_map(|(k, v)| {
                    if let Some(var) = k.strip_prefix(MCP_SECRET) {
                        return Some((var.to_string(), v.clone()));
                    }
                    let var = k.strip_prefix(CREDENTIAL_SERVICE)?;
                    is_old_mcp_secret(var, v).then(|| (var.to_string(), v.clone()))
                })
                .collect(),
            host_mounts: json(labels, HOST_MOUNTS).unwrap_or_default(),
            ssh_agent: text(SSH_AGENT).and_then(|j| AgentLabel::from_label(&j)),
            skills: text(SKILLS).and_then(|j| crate::skills::Label::from_label(&j)),
            template: text(TEMPLATE),
            mcp: labels.get(MCP).map(|names| list(Some(names))),
        })
    }

    /// A mounted host folder the sandbox can write: a copy would share it with the original.
    pub fn writable_host_folder(&self) -> bool {
        // A workspace label without a readable list (an empty or garbled `sbx.workspaces`) still
        // names a folder; assume it's writable.
        if self.workspaces.is_empty() && self.clone_repo.is_none() && self.workspace.is_some() {
            return true;
        }
        self.workspaces
            .iter()
            .enumerate()
            .any(|(i, w)| !w.ends_with(":ro") && !(i == 0 && self.clone_repo.is_some()))
    }

    /// Whether `sbt fork` can copy it: no writable host folder, not itself a fork, and not an
    /// internal sandbox (`_builder`), which would only pay branchable's memory cost.
    pub fn forkable(&self) -> bool {
        self.fork_of.is_none()
            && !self.writable_host_folder()
            && !super::name::is_internal(&self.name)
    }
}

/// A comma-joined label value.
/// smolbento 0.15.0 and 0.15.1 recorded a `--static-mcp` secret among the kit credential
/// services (`sbx.credential-service.SBX_MCP_…=mcp:…`). Kits can't name an `mcp:` service, so
/// such a label is one of those.
fn is_old_mcp_secret(var: &str, service: &str) -> bool {
    var.starts_with("SBX_MCP_") && service.starts_with("mcp:")
}

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
            workspace: Some("/w/repo".into()),
            workspaces: vec!["/w/repo".into(), "/w/docs:ro".into()],
            created: 1000,
            docker: true,
            ..Default::default()
        }
    }

    #[test]
    fn round_trip() {
        let labels = meta().to_labels();
        assert_eq!(labels["sbx.workspaces"], r#"["/w/repo","/w/docs:ro"]"#);
        assert_eq!(labels["sbx.docker"], "true");
        assert_eq!(Meta::from_labels(&labels), Some(meta()));
    }

    #[test]
    fn mountless_has_no_workspace_label() {
        let m = Meta {
            workspace: None,
            workspaces: vec![],
            ..meta()
        };
        let labels = m.to_labels();
        assert!(!labels.contains_key("sbx.workspace"));
        assert_eq!(Meta::from_labels(&labels), Some(m));
    }

    #[test]
    fn clone_labels_round_trip() {
        // At the repo top: no `sbx.clone-top`, the workspace is the top.
        let mut m = meta();
        m.clone_repo = Some("/w/repo".into());
        let labels = m.to_labels();
        assert_eq!(labels["sbx.clone"], "true");
        assert!(!labels.contains_key("sbx.clone-top"));
        assert_eq!(Meta::from_labels(&labels), Some(m.clone()));
        // A subdirectory was given: the top is its own label.
        m.clone_repo = Some("/w".into());
        let labels = m.to_labels();
        assert_eq!(labels["sbx.clone-top"], "/w");
        assert_eq!(Meta::from_labels(&labels), Some(m));
        assert!(!meta().to_labels().contains_key("sbx.clone"));
        assert_eq!(
            Meta::from_labels(&meta().to_labels()).unwrap().clone_repo,
            None
        );
    }

    #[test]
    fn optional_fields_round_trip() {
        use crate::ssh_agent::Access;
        let m = Meta {
            template: Some("docker.io/library/t:v1".into()),
            host_access: true,
            bridge: true,
            ssh_agent: Some(AgentLabel {
                runtime: Some(Access { sign: None }),
                install: Some(Access {
                    sign: Some(vec!["git".into()]),
                }),
            }),
            host_mounts: BTreeMap::from([("/home/agent/x".into(), "/data/x".into())]),
            secrets: vec!["anthropic".into(), "github".into()],
            credential_hosts: vec!["api.github.com".into(), "github.com".into()],
            credential_env: vec!["GH_TOKEN".into(), "GITHUB_TOKEN".into()],
            registries: vec!["dhi.io".into(), "ghcr.io".into()],
            fork_of: Some("a".into()),
            mcp: Some(vec!["linear".into(), "files".into()]),
            kits: vec!["acme/a:1@sha256:ab".into(), "/k/b".into()],
            command: Some(vec!["wl".into(), "--a b".into()]),
            user: Some("somebody".into()),
            image_workdir: Some("/x".into()),
            agent_file: Some("/w/AGENTS.md".into()),
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
            ..meta()
        };
        let labels = m.to_labels();
        for (key, want) in [
            ("sbx.template", "docker.io/library/t:v1"),
            ("sbx.host-access", "true"),
            ("sbx.bridge", "true"),
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
            ("sbx.kits", r#"["acme/a:1@sha256:ab","/k/b"]"#),
            ("sbx.command", r#"["wl","--a b"]"#),
            ("sbx.user", "somebody"),
            ("sbx.workdir", "/x"),
            ("sbx.agent-file", "/w/AGENTS.md"),
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
    fn an_mcp_secret_recorded_by_0_15_is_still_read() {
        // 0.15.0 and 0.15.1 recorded it among the kit credential services.
        let mut labels = meta().to_labels();
        labels.insert(
            "sbx.credential-service.SBX_MCP_LINEAR_API_KEY".into(),
            "mcp:linear:api-key".into(),
        );
        labels.insert("sbx.credential-service.SBX_KIT_X".into(), "x".into());
        let m = Meta::from_labels(&labels).unwrap();
        assert_eq!(
            m.mcp_secrets,
            BTreeMap::from([(
                "SBX_MCP_LINEAR_API_KEY".to_string(),
                "mcp:linear:api-key".to_string()
            )])
        );
        assert_eq!(
            m.credential_services,
            BTreeMap::from([("SBX_KIT_X".to_string(), "x".to_string())])
        );
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
            workspace: None,
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

    #[test]
    fn a_workspace_without_a_readable_list_counts_as_writable() {
        let from = |workspaces: Option<&str>| {
            let mut labels = BTreeMap::from([
                (NAME.to_string(), "a".to_string()),
                (WORKSPACE.to_string(), "/w/p".to_string()),
            ]);
            if let Some(w) = workspaces {
                labels.insert(WORKSPACES.to_string(), w.to_string());
            }
            Meta::from_labels(&labels).unwrap()
        };
        for w in [None, Some(""), Some("[]"), Some("not json")] {
            assert!(
                from(w).writable_host_folder() && !from(w).forkable(),
                "{w:?}"
            );
        }
        assert!(from(Some("[\"/w/p:ro\"]")).forkable());
        // A clone's workspace is its own copy, whatever the list says.
        let labels = BTreeMap::from([
            (NAME.to_string(), "a".to_string()),
            (WORKSPACE.to_string(), "/w/p".to_string()),
            (CLONE.to_string(), "true".to_string()),
        ]);
        assert!(Meta::from_labels(&labels).unwrap().forkable());
    }
}
