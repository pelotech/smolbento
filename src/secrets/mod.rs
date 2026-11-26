//! Secret sources in `secrets.toml`. Values live in the OS keychain (see `store`) or come from a
//! reference or command at start; this file never holds a value.

pub mod resolve;
pub mod services;
pub mod store;

use anyhow::{Result, bail};
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::config::Paths;
use crate::policy::rules::{SmolvmHost, check_host};
use services::Service;

/// Validates and normalizes one credential host (bare DNS name or `*.domain` below the TLD).
/// smolvm takes them as `--credential NAME=ENV@HOST,…` and `--allow-host`, so schemes, ports,
/// commas, IPs and arbitrary globs are refused.
pub fn check_credential_host(raw: &str) -> Result<String> {
    let host = raw.trim().to_ascii_lowercase();
    let unbracketed = host.trim_start_matches('[').trim_end_matches(']');
    if unbracketed.parse::<std::net::IpAddr>().is_ok() {
        bail!("'{raw}': smolvm only substitutes secrets for host names, not IP addresses");
    }
    if host.contains("://") || host.contains([':', '/', '@', ',']) {
        bail!("'{raw}': use a bare host name like api.x.com (no scheme, port or path)");
    }
    // smolvm takes `*.domain` (every subdomain, not the domain itself) and no other wildcard.
    let (prefix, name) = match SmolvmHost::parse(&host) {
        SmolvmHost::Subdomains(name) => ("*.", name),
        SmolvmHost::Exact(name) => ("", name),
    };
    if name.contains(['*', '?', '[', ']']) {
        bail!(
            "'{raw}': the only wildcard a secret host takes is a leading `*.`, like *.x.com \
             (every subdomain of x.com)"
        );
    }
    check_host(name, raw)?;
    let name = name.strip_suffix('.').unwrap_or(name);
    if !prefix.is_empty() && !name.contains('.') {
        bail!("'{raw}': a wildcard needs a domain below the top level, like *.x.com");
    }
    Ok(format!("{prefix}{name}"))
}

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

/// A registry pull credential. The value is in the secret store under `account()`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryEntry {
    pub host: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_endpoint: Option<String>,
    /// The sandbox it belongs to (an environment file's `registries`); `None` is host-wide.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sandbox: Option<String>,
}

impl RegistryEntry {
    /// Key in the secret store for its password or token.
    pub fn account(&self) -> String {
        match &self.sandbox {
            None => registry_account(&self.host),
            // Not under `registry:`, where a host-wide login's host could spell the same key.
            Some(sandbox) => format!("sandbox-registry:{sandbox}/{}", self.host),
        }
    }
}

/// Key in the secret store for a host-wide registry login's password or token.
pub fn registry_account(host: &str) -> String {
    format!("registry:{host}")
}

/// The stored password or token for a registry host, if any.
pub fn registry_secret(store: &dyn store::SecretStore, host: &str) -> Result<Option<String>> {
    store.get(&registry_account(host))
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub registries: Vec<RegistryEntry>,
    /// Service name to more domains its credential may be sent to (sbx's bindings, from an
    /// environment file). Global: every sandbox created afterwards uses them.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub bindings: BTreeMap<String, ServiceBinding>,
}

/// The domains bound to one service, by kind of credential.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceBinding {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub api_key: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub oauth: Vec<String>,
}

impl SecretsFile {
    pub fn load(paths: &Paths) -> Result<SecretsFile> {
        crate::config::load_toml(&paths.secrets_file())
    }

    pub fn save(&self, paths: &Paths) -> Result<()> {
        crate::config::save_toml(&paths.secrets_file(), self)
    }

    /// Loads, changes and saves the file under its lock (`config::update_toml`).
    pub fn update<T>(paths: &Paths, f: impl FnOnce(&mut SecretsFile) -> Result<T>) -> Result<T> {
        crate::config::update_toml(&paths.secrets_file(), f)
    }

    /// A built-in or custom service, with the domains bound to it added to its hosts.
    pub fn service(&self, name: &str) -> Option<Service> {
        let mut service = services::builtin(name).or_else(|| {
            self.custom
                .iter()
                .find(|c| c.name == name)
                .map(|c| Service {
                    name: c.name.clone(),
                    env_vars: vec![c.env.clone()],
                    hosts: c.hosts.clone(),
                })
        })?;
        if let Some(b) = self.bindings.get(name) {
            // Only API-key domains: smolbento resolves API keys only (no OAuth credentials), so
            // injecting the API key on oauth.domains would send it to the wrong host.
            for domain in &b.api_key {
                if !service.hosts.contains(domain) {
                    service.hosts.push(domain.clone());
                }
            }
        }
        Some(service)
    }

    /// Adds `domains` to the service's bindings (sbx merges an environment's bindings into
    /// the global ones).
    pub fn bind(&mut self, service: &str, api_key: &[String], oauth: &[String]) {
        let b = self.bindings.entry(service.to_string()).or_default();
        for (list, add) in [(&mut b.api_key, api_key), (&mut b.oauth, oauth)] {
            for d in add {
                let d = check_credential_host(d).unwrap_or_else(|_| d.trim().to_ascii_lowercase());
                if !list.contains(&d) {
                    list.push(d);
                }
            }
        }
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

    /// The global entry for a name, whatever a sandbox's own scope holds.
    pub fn global_entry(&self, service: &str) -> Option<&SecretEntry> {
        self.scoped_entry(None, service)
    }

    /// The entry a sandbox uses for a service: its own scope, then its fork parent's (`fork_of`),
    /// then global.
    pub fn entry_for(
        &self,
        sandbox: &str,
        fork_of: Option<&str>,
        service: &str,
    ) -> Option<&SecretEntry> {
        self.scoped_entry(Some(sandbox), service)
            .or_else(|| fork_of.and_then(|p| self.scoped_entry(Some(p), service)))
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

    /// The host-wide registry logins: what host-side pulls with no sandbox use.
    pub fn host_registries(&self) -> Vec<RegistryEntry> {
        let host_wide = self.registries.iter().filter(|r| r.sandbox.is_none());
        host_wide.cloned().collect()
    }

    /// The registry logins a sandbox's pulls use: its own, then the host-wide ones for hosts it
    /// has none for.
    pub fn registries_for(&self, sandbox: &str) -> Vec<RegistryEntry> {
        let own = |r: &&RegistryEntry| r.sandbox.as_deref() == Some(sandbox);
        let mut out: Vec<RegistryEntry> = self.registries.iter().filter(own).cloned().collect();
        for r in self.host_registries() {
            if !out.iter().any(|o| o.host == r.host) {
                out.push(r);
            }
        }
        out
    }

    /// Removes and returns the registry logins scoped to `sandbox`.
    pub fn remove_sandbox_registries(&mut self, sandbox: &str) -> Vec<RegistryEntry> {
        let (gone, kept) = std::mem::take(&mut self.registries)
            .into_iter()
            .partition(|r| r.sandbox.as_deref() == Some(sandbox));
        self.registries = kept;
        gone
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
        assert_eq!(
            f.entry_for("s1", None, "github").unwrap().scope,
            "sandbox:s1"
        );
        assert_eq!(f.entry_for("s3", None, "github").unwrap().scope, "global");
        assert_eq!(f.services_for("s1"), vec!["github"]);
        assert_eq!(f.services_for("s2"), vec!["github", "openai"]);
        assert_eq!(
            f.entry_for("s1", None, "github").unwrap().account(),
            "sandbox:s1/github"
        );
        // A fork falls back to its parent's scope before global, but its own scope wins.
        assert_eq!(
            f.entry_for("f1", Some("s1"), "github").unwrap().scope,
            "sandbox:s1"
        );
        assert_eq!(
            f.entry_for("s1", Some("s3"), "github").unwrap().scope,
            "sandbox:s1"
        );
        assert_eq!(
            f.entry_for("f3", Some("s3"), "github").unwrap().scope,
            "global"
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

    #[test]
    fn a_sandboxs_registry_login_comes_before_the_host_wide_one() {
        let entry = |host: &str, sandbox: Option<&str>| RegistryEntry {
            host: host.into(),
            username: None,
            auth_endpoint: None,
            sandbox: sandbox.map(String::from),
        };
        let mut f = SecretsFile {
            registries: vec![
                entry("ghcr.io", None),
                entry("quay.io", None),
                entry("ghcr.io", Some("web")),
                entry("ghcr.io", Some("other")),
            ],
            ..Default::default()
        };
        assert_eq!(
            f.registries_for("web"),
            [entry("ghcr.io", Some("web")), entry("quay.io", None)]
        );
        assert_eq!(f.host_registries().len(), 2);
        assert_eq!(entry("ghcr.io", None).account(), "registry:ghcr.io");
        assert_eq!(
            entry("ghcr.io", Some("web")).account(),
            "sandbox-registry:web/ghcr.io"
        );
        assert_eq!(
            f.remove_sandbox_registries("web"),
            [entry("ghcr.io", Some("web"))]
        );
        assert_eq!(f.registries.len(), 3);
    }

    #[test]
    fn bindings_only_add_api_key_domains_to_service_hosts() {
        let mut f = SecretsFile::default();
        f.bind(
            "github",
            &["api.corp.example".into()],
            &["oauth.corp.example".into()],
        );
        let s = f.service("github").unwrap();
        assert!(s.hosts.contains(&"api.corp.example".to_string()));
        assert!(
            !s.hosts.contains(&"oauth.corp.example".to_string()),
            "API key must not be injected on oauth domains: {:?}",
            s.hosts
        );
    }
}
