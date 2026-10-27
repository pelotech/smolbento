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
pub const CLONE: &str = "sbx.clone";
pub const CLONE_TOP: &str = "sbx.clone-top";

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
    /// `--clone`: the host repo's top, which is also the clone's path in the guest. Stored as
    /// `sbx.clone=true` plus `sbx.clone-top` when it differs from `workspace` (a subdirectory was
    /// given).
    pub clone_repo: Option<String>,
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
        if let Some(top) = &self.clone_repo {
            labels.insert(CLONE.to_string(), "true".into());
            if Some(top) != self.workspace.as_ref() {
                labels.insert(CLONE_TOP.to_string(), top.clone());
            }
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
            clone_repo: labels
                .get(CLONE)
                .filter(|c| *c == "true")
                .and_then(|_| labels.get(CLONE_TOP).or(labels.get(WORKSPACE)).cloned()),
        })
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
    fn foreign_machine_is_none() {
        assert_eq!(Meta::from_labels(&BTreeMap::new()), None);
    }
}
