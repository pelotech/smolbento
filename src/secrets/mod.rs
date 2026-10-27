//! Secret sources in `secrets.toml`. Values live in the OS keychain (see `store`) or come from a
//! reference or command at start; this file never holds a value.

pub mod resolve;
pub mod services;
pub mod store;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::config::Paths;
use services::Service;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "source", rename_all = "lowercase")]
pub enum Source {
    /// The value is in the secret store under this entry's account.
    Keychain,
    /// `op://…` or an AWS Secrets Manager ARN.
    Ref {
        #[serde(rename = "ref")]
        reference: String,
    },
    /// A host command whose trimmed stdout is the value.
    Command { command: String },
}

impl Source {
    pub fn describe(&self) -> String {
        match self {
            Source::Keychain => "stored value".into(),
            Source::Ref { reference } => reference.clone(),
            Source::Command { command } => format!("command: {command}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretEntry {
    pub service: String,
    /// "global" or "sandbox:<name>".
    pub scope: String,
    #[serde(flatten)]
    pub source: Source,
}

impl SecretEntry {
    /// Key in the secret store.
    pub fn account(&self) -> String {
        format!("{}/{}", self.scope, self.service)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustomService {
    pub name: String,
    pub env: String,
    pub hosts: Vec<String>,
}

pub fn scope_for(sandbox: Option<&str>) -> String {
    match sandbox {
        Some(s) => format!("sandbox:{s}"),
        None => "global".into(),
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretsFile {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secrets: Vec<SecretEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub custom: Vec<CustomService>,
}

impl SecretsFile {
    pub fn load(paths: &Paths) -> Result<SecretsFile> {
        crate::config::load_toml(&paths.secrets_file())
    }

    pub fn save(&self, paths: &Paths) -> Result<()> {
        crate::config::save_toml(&paths.secrets_file(), self)
    }

    /// A built-in or custom service.
    pub fn service(&self, name: &str) -> Option<Service> {
        services::builtin(name).or_else(|| {
            self.custom
                .iter()
                .find(|c| c.name == name)
                .map(|c| Service {
                    name: c.name.clone(),
                    env_vars: vec![c.env.clone()],
                    hosts: c.hosts.clone(),
                })
        })
    }

    /// Adds or replaces the entry for the same service and scope.
    pub fn set(&mut self, entry: SecretEntry) {
        self.secrets
            .retain(|e| !(e.service == entry.service && e.scope == entry.scope));
        self.secrets.push(entry);
    }

    /// Removes one entry; a custom service's definition goes with its last entry in any scope.
    pub fn remove(&mut self, service: &str, scope: &str) -> Option<SecretEntry> {
        let i = self
            .secrets
            .iter()
            .position(|e| e.service == service && e.scope == scope)?;
        let gone = self.secrets.remove(i);
        self.prune_custom();
        Some(gone)
    }

    /// Drops custom services no entry uses any more.
    fn prune_custom(&mut self) {
        let secrets = &self.secrets;
        self.custom
            .retain(|c| secrets.iter().any(|e| e.service == c.name));
    }

    /// The entry in exactly one scope (`None` = global), with no fallback.
    pub fn scoped_entry(&self, sandbox: Option<&str>, service: &str) -> Option<&SecretEntry> {
        let scope = scope_for(sandbox);
        self.secrets
            .iter()
            .find(|e| e.service == service && e.scope == scope)
    }

    /// The entry a sandbox uses for a service: its own scope first, then global.
    pub fn entry_for(&self, sandbox: &str, service: &str) -> Option<&SecretEntry> {
        self.scoped_entry(Some(sandbox), service)
            .or_else(|| self.scoped_entry(None, service))
    }

    /// Services with a secret in this sandbox's scope (its own or global), sorted.
    pub fn services_for(&self, sandbox: &str) -> Vec<String> {
        let own = scope_for(Some(sandbox));
        let mut out: Vec<String> = self
            .secrets
            .iter()
            .filter(|e| e.scope == "global" || e.scope == own)
            .map(|e| e.service.clone())
            .collect();
        out.sort();
        out.dedup();
        out
    }

    pub fn remove_sandbox(&mut self, sandbox: &str) -> Vec<SecretEntry> {
        let own = scope_for(Some(sandbox));
        let (gone, kept) = std::mem::take(&mut self.secrets)
            .into_iter()
            .partition(|e| e.scope == own);
        self.secrets = kept;
        self.prune_custom();
        gone
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(service: &str, scope: &str, source: Source) -> SecretEntry {
        SecretEntry {
            service: service.into(),
            scope: scope.into(),
            source,
        }
    }

    #[test]
    fn round_trip_and_toml_shape() {
        let (_d, paths) = crate::config::test_paths();
        let mut f = SecretsFile::load(&paths).unwrap();
        f.set(entry("anthropic", "global", Source::Keychain));
        f.set(entry(
            "github",
            "global",
            Source::Command {
                command: "gh auth token".into(),
            },
        ));
        f.set(entry(
            "claude",
            "sandbox:claude-repo",
            Source::Ref {
                reference: "op://P/c/credential".into(),
            },
        ));
        f.custom.push(CustomService {
            name: "tok".into(),
            env: "TOK".into(),
            hosts: vec!["httpbin.org".into()],
        });
        f.save(&paths).unwrap();
        assert_eq!(SecretsFile::load(&paths).unwrap(), f);
        let text = std::fs::read_to_string(paths.secrets_file()).unwrap();
        assert!(
            text.contains("source = \"ref\"") && text.contains("ref = \"op://P/c/credential\""),
            "{text}"
        );
    }

    #[test]
    fn scopes_and_lookup() {
        let mut f = SecretsFile::default();
        f.set(entry("github", "global", Source::Keychain));
        f.set(entry(
            "github",
            "sandbox:s1",
            Source::Command {
                command: "x".into(),
            },
        ));
        f.set(entry("openai", "sandbox:s2", Source::Keychain));
        assert_eq!(f.entry_for("s1", "github").unwrap().scope, "sandbox:s1");
        assert_eq!(f.entry_for("s3", "github").unwrap().scope, "global");
        assert_eq!(f.services_for("s1"), vec!["github"]);
        assert_eq!(f.services_for("s2"), vec!["github", "openai"]);
        assert_eq!(
            f.entry_for("s1", "github").unwrap().account(),
            "sandbox:s1/github"
        );
        assert_eq!(f.remove_sandbox("s1").len(), 1);
        assert!(f.remove("github", "global").is_some());
        assert_eq!(scope_for(Some("s1")), "sandbox:s1");
        assert_eq!(scope_for(None), "global");
    }

    #[test]
    fn scoped_entry_is_exact() {
        let mut f = SecretsFile::default();
        f.set(entry("github", "global", Source::Keychain));
        f.set(entry("github", "sandbox:a", Source::Keychain));
        assert!(f.scoped_entry(Some("a"), "github").is_some());
        assert!(f.scoped_entry(Some("b"), "github").is_none());
        assert!(f.scoped_entry(None, "github").is_some());
    }

    #[test]
    fn custom_services_resolve() {
        let mut f = SecretsFile::default();
        f.custom.push(CustomService {
            name: "tok".into(),
            env: "TOK".into(),
            hosts: vec!["httpbin.org".into()],
        });
        let s = f.service("tok").unwrap();
        assert_eq!(
            (s.env_vars, s.hosts),
            (vec!["TOK".to_string()], vec!["httpbin.org".to_string()])
        );
        assert!(f.service("anthropic").is_some());
        assert!(f.service("nope").is_none());
    }
}
