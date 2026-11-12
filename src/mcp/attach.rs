//! What giving a sandbox's agent the selected servers takes at create.

use std::collections::BTreeMap;

use anyhow::{Context, Result, bail};

use super::registrar::{has_registrar, register_script};
use super::{McpFile, Server, env_var, placeholder, secret_name};
use crate::kits::apply::InstallStep;
use crate::smolvm::Credential;

/// What a create applies for `--static-mcp`. How it was made (the agent's own config today; a
/// gateway would be another way) stays inside this module.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Attachment {
    /// The selected servers, in the order given; the `sbx.mcp` label.
    pub names: Vec<String>,
    /// Hosts the sandbox must be allowed to reach, sorted and unique.
    pub hosts: Vec<String>,
    /// One per header secret: the guest gets a placeholder, the server's host gets the value.
    pub credentials: Vec<Credential>,
    /// Guest env var to the `mcp:` secret it stands for (`sbx.credential-service.*`).
    pub credential_services: BTreeMap<String, String>,
    /// First-start steps, after the kits' install hooks.
    pub steps: Vec<InstallStep>,
}

/// Resolves a `--static-mcp` value (`none`, or comma-separated registered names) for `agent`.
/// `has_secret` says whether an `mcp:` secret is set.
pub fn attach(
    file: &McpFile,
    selection: &str,
    agent: &str,
    has_secret: &dyn Fn(&str) -> bool,
) -> Result<Attachment> {
    let mut names: Vec<&str> = Vec::new();
    for name in selection
        .split(',')
        .map(str::trim)
        .filter(|n| !n.is_empty())
    {
        if !names.contains(&name) {
            names.push(name);
        }
    }
    if names == ["none"] {
        names.clear();
    }
    let mut a = Attachment::default();
    if names.is_empty() {
        return Ok(a);
    }
    let servers: Vec<(&str, &Server)> = names
        .iter()
        .map(|n| {
            let server = file.servers.get(*n).with_context(|| {
                if *n == "none" {
                    "--static-mcp none can't be combined with server names".to_string()
                } else {
                    format!("no MCP server named '{n}' (see `sbt mcp ls`)")
                }
            })?;
            Ok((*n, server))
        })
        .collect::<Result<_>>()?;
    if !has_registrar(agent) {
        bail!("--static-mcp isn't supported for agent {agent} yet");
    }
    for (name, server) in servers {
        if let Server::Remote { headers, .. } = server {
            let host = server.host().context("a registered URL has a host")?;
            for p in headers.values().filter_map(|v| placeholder(v)) {
                let secret = secret_name(name, p);
                if !has_secret(&secret) {
                    bail!(
                        "MCP server {name} needs the secret {secret}; set it with `sbt secret \
                         set {secret}`"
                    );
                }
                let var = env_var(name, p);
                a.credentials.push(Credential {
                    name: var.trim_start_matches("SBX_").to_ascii_lowercase(),
                    env_var: var.clone(),
                    hosts: vec![host.clone()],
                    set_header: None,
                });
                a.credential_services.insert(var, secret);
            }
            a.hosts.push(host);
        }
        a.steps.push(InstallStep {
            label: format!("MCP server {name}"),
            kit: None,
            user: Some("agent".into()),
            script: register_script(agent, name, server).context("the agent has a registrar")?,
            relay_stderr: false,
        });
        a.names.push(name.to_string());
    }
    a.hosts.sort();
    a.hosts.dedup();
    Ok(a)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp::Server;

    fn file() -> McpFile {
        let mut f = McpFile::default();
        f.servers.insert(
            "linear".into(),
            Server::Remote {
                url: "https://mcp.linear.app/sse".into(),
                headers: BTreeMap::from([("Authorization".into(), "Bearer ${api-key}".into())]),
            },
        );
        f.servers.insert(
            "docs".into(),
            Server::Remote {
                url: "https://docs.example.com/mcp".into(),
                headers: BTreeMap::new(),
            },
        );
        f.servers.insert(
            "files".into(),
            Server::Command {
                command: "npx".into(),
                args: vec![],
            },
        );
        f
    }

    #[test]
    fn attach_collects_hosts_credentials_and_steps() {
        let a = attach(&file(), "linear,files,docs,linear", "claude", &|_| true).unwrap();
        assert_eq!(a.names, ["linear", "files", "docs"]);
        assert_eq!(a.hosts, ["docs.example.com", "mcp.linear.app"]);
        assert_eq!(
            a.credentials,
            [Credential {
                name: "mcp_linear_api_key".into(),
                env_var: "SBX_MCP_LINEAR_API_KEY".into(),
                hosts: vec!["mcp.linear.app".into()],
                set_header: None,
            }]
        );
        assert_eq!(
            a.credential_services,
            BTreeMap::from([(
                "SBX_MCP_LINEAR_API_KEY".to_string(),
                "mcp:linear:api-key".to_string()
            )])
        );
        let labels: Vec<&str> = a.steps.iter().map(|s| s.label.as_str()).collect();
        assert_eq!(
            labels,
            ["MCP server linear", "MCP server files", "MCP server docs"]
        );
        assert!(
            a.steps
                .iter()
                .all(|s| s.kit.is_none() && s.user.as_deref() == Some("agent") && !s.relay_stderr)
        );
        assert!(a.steps[0].script.starts_with("claude mcp add "));
    }

    #[test]
    fn attach_refusals() {
        let f = file();
        let err = |sel: &str, agent: &str, has: bool| {
            attach(&f, sel, agent, &|_| has).unwrap_err().to_string()
        };
        assert_eq!(
            err("nope", "claude", true),
            "no MCP server named 'nope' (see `sbt mcp ls`)"
        );
        assert_eq!(
            err("linear", "claude", false),
            "MCP server linear needs the secret mcp:linear:api-key; set it with `sbt secret set \
             mcp:linear:api-key`"
        );
        assert_eq!(
            err("docs", "codex", true),
            "--static-mcp isn't supported for agent codex yet"
        );
        // The secret is only asked about when a selected server needs it.
        attach(&f, "docs", "claude", &|_| false).unwrap();
        for sel in ["none", "", " "] {
            let a = attach(&f, sel, "codex", &|_| false).unwrap();
            assert_eq!(a, Attachment::default(), "{sel:?}");
        }
        assert!(err("none,docs", "claude", true).contains("none"));
    }
}
