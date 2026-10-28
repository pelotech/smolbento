use std::collections::BTreeMap;

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
/// Kit host mounts: a JSON object of guest path to host directory.
pub const HOST_MOUNTS: &str = "sbx.host-mounts";
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
    /// Kit credentials whose value is formatted before smolvm sets it as a header, by env var.
    pub credential_formats: BTreeMap<String, CredFormat>,
    /// Kit credential env vars outside their service's own env vars, to their service.
    pub credential_services: BTreeMap<String, String>,
    /// Kit host mounts: guest path to host directory.
    pub host_mounts: BTreeMap<String, String>,
}

impl Meta {
    pub fn to_labels(&self) -> BTreeMap<String, String> {
        let mut labels = BTreeMap::from([
            (NAME.to_string(), self.name.clone()),
            (AGENT.to_string(), self.agent.clone()),
            (
                WORKSPACES.to_string(),
                serde_json::to_string(&self.workspaces).expect("strings serialize"),
            ),
            (CREATED.to_string(), self.created.to_string()),
            (DOCKER.to_string(), self.docker.to_string()),
        ]);
        if let Some(w) = &self.workspace {
            labels.insert(WORKSPACE.to_string(), w.clone());
        }
        if !self.secrets.is_empty() {
            labels.insert(SECRETS.to_string(), self.secrets.join(","));
        }
        if !self.credential_hosts.is_empty() {
            labels.insert(
                CREDENTIAL_HOSTS.to_string(),
                self.credential_hosts.join(","),
            );
        }
        if !self.credential_env.is_empty() {
            labels.insert(CREDENTIAL_ENV.to_string(), self.credential_env.join(","));
        }
        if !self.registries.is_empty() {
            labels.insert(REGISTRIES.to_string(), self.registries.join(","));
        }
        if let Some(top) = &self.clone_repo {
            labels.insert(CLONE.to_string(), "true".into());
            if Some(top) != self.workspace.as_ref() {
                labels.insert(CLONE_TOP.to_string(), top.clone());
            }
        }
        if let Some(f) = &self.fork_of {
            labels.insert(FORK_OF.to_string(), f.clone());
        }
        // Kit labels exist only on sandboxes created with kits.
        if !self.kits.is_empty() {
            labels.insert(
                KITS.to_string(),
                serde_json::to_string(&self.kits).expect("strings serialize"),
            );
        }
        if let Some(c) = &self.command {
            labels.insert(
                COMMAND.to_string(),
                serde_json::to_string(c).expect("strings serialize"),
            );
        }
        if let Some(u) = &self.user {
            labels.insert(USER.to_string(), u.clone());
        }
        if let Some(w) = &self.image_workdir {
            labels.insert(WORKDIR.to_string(), w.clone());
        }
        if let Some(f) = &self.agent_file {
            labels.insert(AGENT_FILE.to_string(), f.clone());
        }
        if !self.credential_install.is_empty() {
            labels.insert(
                CREDENTIAL_INSTALL.to_string(),
                self.credential_install.join(","),
            );
        }
        if self.long_running {
            labels.insert(LONG_RUNNING.to_string(), "true".into());
        }
        if self.host_access {
            labels.insert(HOST_ACCESS.to_string(), "true".into());
        }
        if !self.host_mounts.is_empty() {
            labels.insert(
                HOST_MOUNTS.to_string(),
                serde_json::to_string(&self.host_mounts).expect("strings serialize"),
            );
        }
        for (env, f) in &self.credential_formats {
            labels.insert(format!("{CREDENTIAL_FORMAT}{env}"), f.to_label());
        }
        for (env, service) in &self.credential_services {
            labels.insert(format!("{CREDENTIAL_SERVICE}{env}"), service.clone());
        }
        labels
    }

    /// `None` for machines smolbento didn't create.
    pub fn from_labels(labels: &BTreeMap<String, String>) -> Option<Meta> {
        Some(Meta {
            name: labels.get(NAME)?.clone(),
            agent: labels.get(AGENT).cloned().unwrap_or_default(),
            workspace: labels.get(WORKSPACE).cloned(),
            workspaces: labels
                .get(WORKSPACES)
                .and_then(|j| serde_json::from_str(j).ok())
                .unwrap_or_default(),
            created: labels
                .get(CREATED)
                .and_then(|c| c.parse().ok())
                .unwrap_or(0),
            docker: labels.get(DOCKER).is_some_and(|d| d == "true"),
            secrets: list(labels.get(SECRETS)),
            credential_hosts: list(labels.get(CREDENTIAL_HOSTS)),
            credential_env: list(labels.get(CREDENTIAL_ENV)),
            registries: list(labels.get(REGISTRIES)),
            clone_repo: labels
                .get(CLONE)
                .filter(|c| *c == "true")
                .and_then(|_| labels.get(CLONE_TOP).or(labels.get(WORKSPACE)).cloned()),
            fork_of: labels.get(FORK_OF).cloned(),
            kits: labels
                .get(KITS)
                .and_then(|j| serde_json::from_str(j).ok())
                .unwrap_or_default(),
            command: labels
                .get(COMMAND)
                .and_then(|j| serde_json::from_str(j).ok()),
            user: labels.get(USER).cloned(),
            image_workdir: labels.get(WORKDIR).cloned(),
            agent_file: labels.get(AGENT_FILE).cloned(),
            credential_install: list(labels.get(CREDENTIAL_INSTALL)),
            long_running: labels.get(LONG_RUNNING).is_some_and(|v| v == "true"),
            host_access: labels.get(HOST_ACCESS).is_some_and(|v| v == "true"),
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
            host_mounts: labels
                .get(HOST_MOUNTS)
                .and_then(|j| serde_json::from_str(j).ok())
                .unwrap_or_default(),
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
    fn host_access_label_round_trips() {
        assert!(!meta().to_labels().contains_key("sbx.host-access"));
        let m = Meta {
            host_access: true,
            ..meta()
        };
        let labels = m.to_labels();
        assert_eq!(labels["sbx.host-access"], "true");
        assert_eq!(Meta::from_labels(&labels), Some(m));
    }

    #[test]
    fn host_mounts_label_round_trips() {
        assert!(!meta().to_labels().contains_key("sbx.host-mounts"));
        let m = Meta {
            host_mounts: BTreeMap::from([("/home/agent/x".into(), "/data/x".into())]),
            ..meta()
        };
        let labels = m.to_labels();
        assert_eq!(labels["sbx.host-mounts"], r#"{"/home/agent/x":"/data/x"}"#);
        assert_eq!(Meta::from_labels(&labels), Some(m));
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
    fn secrets_label_round_trips() {
        let m = Meta {
            secrets: vec!["anthropic".into(), "github".into()],
            ..meta()
        };
        let labels = m.to_labels();
        assert_eq!(labels["sbx.secrets"], "anthropic,github");
        assert_eq!(Meta::from_labels(&labels).unwrap().secrets, m.secrets);
    }

    #[test]
    fn credential_hosts_label_round_trips() {
        let m = Meta {
            credential_hosts: vec!["api.github.com".into(), "github.com".into()],
            ..meta()
        };
        let labels = m.to_labels();
        assert_eq!(labels["sbx.credential-hosts"], "api.github.com,github.com");
        assert_eq!(Meta::from_labels(&labels), Some(m));
        assert!(!meta().to_labels().contains_key("sbx.credential-hosts"));
    }

    #[test]
    fn credential_env_label_round_trips() {
        let m = Meta {
            credential_env: vec!["GH_TOKEN".into(), "GITHUB_TOKEN".into()],
            ..meta()
        };
        let labels = m.to_labels();
        assert_eq!(labels["sbx.credential-env"], "GH_TOKEN,GITHUB_TOKEN");
        assert_eq!(Meta::from_labels(&labels), Some(m));
        assert!(!meta().to_labels().contains_key("sbx.credential-env"));
    }

    #[test]
    fn registries_label_round_trips() {
        let m = Meta {
            registries: vec!["dhi.io".into(), "ghcr.io".into()],
            ..meta()
        };
        let labels = m.to_labels();
        assert_eq!(labels["sbx.registries"], "dhi.io,ghcr.io");
        assert_eq!(Meta::from_labels(&labels), Some(m));
        assert!(!meta().to_labels().contains_key("sbx.registries"));
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
    fn fork_of_label_round_trips() {
        let m = Meta {
            fork_of: Some("a".into()),
            ..meta()
        };
        let labels = m.to_labels();
        assert_eq!(labels["sbx.fork-of"], "a");
        assert_eq!(Meta::from_labels(&labels), Some(m));
        assert!(!meta().to_labels().contains_key("sbx.fork-of"));
    }

    #[test]
    fn kit_labels_round_trip() {
        let m = Meta {
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
            ..meta()
        };
        let labels = m.to_labels();
        assert_eq!(labels["sbx.kits"], r#"["acme/a:1@sha256:ab","/k/b"]"#);
        assert_eq!(labels["sbx.command"], r#"["wl","--a b"]"#);
        assert_eq!(labels["sbx.user"], "somebody");
        assert_eq!(labels["sbx.workdir"], "/x");
        assert_eq!(labels["sbx.agent-file"], "/w/AGENTS.md");
        assert_eq!(labels["sbx.credential-install"], "GH_TOKEN,NPM_TOKEN");
        assert_eq!(labels["sbx.long-running"], "true");
        assert_eq!(
            labels["sbx.credential-format.SBX_KIT_X"],
            "format:Bearer %s"
        );
        assert_eq!(
            labels["sbx.credential-format.GH_TOKEN"],
            "basic:x-access-token"
        );
        assert_eq!(labels["sbx.credential-service.SBX_KIT_X"], "x");
        assert_eq!(Meta::from_labels(&labels), Some(m));
        // Absent when empty, so sandboxes without kits keep their labels.
        let plain = meta().to_labels();
        assert_eq!(plain.len(), 6, "{plain:?}");
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
