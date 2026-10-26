use std::collections::BTreeMap;

pub const NAME: &str = "sbx.name";
pub const AGENT: &str = "sbx.agent";
pub const WORKSPACE: &str = "sbx.workspace";
pub const WORKSPACES: &str = "sbx.workspaces";
pub const CREATED: &str = "sbx.created";
pub const DOCKER: &str = "sbx.docker";
pub const SECRETS: &str = "sbx.secrets";
pub const CREDENTIAL_HOSTS: &str = "sbx.credential-hosts";

/// Sandbox metadata, fixed at create and stored as smolvm machine labels.
#[derive(Debug, Clone, PartialEq, Eq)]
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
            secrets: vec![],
            credential_hosts: vec![],
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
    fn foreign_machine_is_none() {
        assert_eq!(Meta::from_labels(&BTreeMap::new()), None);
    }
}
