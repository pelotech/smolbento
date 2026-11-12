//! `~/.config/smolbento/mcp.toml`: the registered servers. It holds no secret values.

use std::collections::BTreeMap;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::config::{self, Paths};

/// A registered MCP server: reached at a URL, or run as a command inside the sandbox.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "Raw", into = "Raw")]
pub enum Server {
    Remote {
        url: String,
        /// Header name to value. A value may hold one `${placeholder}` for a secret.
        headers: BTreeMap<String, String>,
    },
    Command {
        command: String,
        args: Vec<String>,
    },
}

impl Server {
    /// A remote server's host name or address, lowercased.
    pub fn host(&self) -> Option<String> {
        match self {
            Server::Remote { url, .. } => reqwest::Url::parse(url)
                .ok()?
                .host_str()
                .map(|h| h.trim_start_matches('[').trim_end_matches(']').to_string()),
            Server::Command { .. } => None,
        }
    }
}

/// The file's shape for one server.
#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Raw {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    url: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    headers: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    command: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    args: Vec<String>,
}

impl TryFrom<Raw> for Server {
    type Error = String;

    fn try_from(r: Raw) -> Result<Self, String> {
        match (r.url, r.command) {
            (Some(url), None) if r.args.is_empty() => Ok(Server::Remote {
                url,
                headers: r.headers,
            }),
            (None, Some(command)) if r.headers.is_empty() => Ok(Server::Command {
                command,
                args: r.args,
            }),
            (Some(_), None) => Err("a server with a url takes no args".into()),
            (None, Some(_)) => Err("a server with a command takes no headers".into()),
            _ => Err("a server needs a url or a command, not both".into()),
        }
    }
}

impl From<Server> for Raw {
    fn from(s: Server) -> Raw {
        match s {
            Server::Remote { url, headers } => Raw {
                url: Some(url),
                headers,
                ..Raw::default()
            },
            Server::Command { command, args } => Raw {
                command: Some(command),
                args,
                ..Raw::default()
            },
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpFile {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub servers: BTreeMap<String, Server>,
}

impl McpFile {
    pub fn load(paths: &Paths) -> Result<McpFile> {
        config::load_toml(&paths.mcp_file())
    }

    pub fn save(&self, paths: &Paths) -> Result<()> {
        config::save_toml(&paths.mcp_file(), self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::test_paths;
    use std::collections::BTreeMap;

    #[test]
    fn round_trips_both_kinds() {
        let (_d, paths) = test_paths();
        let mut f = McpFile::default();
        f.servers.insert(
            "linear".into(),
            Server::Remote {
                url: "https://mcp.linear.app/sse".into(),
                headers: BTreeMap::from([("Authorization".into(), "Bearer ${api-key}".into())]),
            },
        );
        f.servers.insert(
            "files".into(),
            Server::Command {
                command: "npx".into(),
                args: vec!["-y".into(), "srv".into()],
            },
        );
        f.save(&paths).unwrap();
        let text = std::fs::read_to_string(paths.mcp_file()).unwrap();
        assert!(text.contains("[servers.linear]"), "{text}");
        assert!(
            text.contains("url = \"https://mcp.linear.app/sse\""),
            "{text}"
        );
        assert_eq!(McpFile::load(&paths).unwrap(), f);
    }

    #[test]
    fn a_missing_file_is_empty() {
        let (_d, paths) = test_paths();
        assert!(McpFile::load(&paths).unwrap().servers.is_empty());
    }

    #[test]
    fn a_server_is_a_url_or_a_command() {
        let (_d, paths) = test_paths();
        std::fs::create_dir_all(paths.mcp_file().parent().unwrap()).unwrap();
        for bad in [
            "[servers.x]\nurl = \"https://a.b/\"\ncommand = \"npx\"\n",
            "[servers.x]\n",
            "[servers.x]\ncommand = \"npx\"\nheaders = { A = \"b\" }\n",
            "[servers.x]\nurl = \"https://a.b/\"\nargs = [\"a\"]\n",
        ] {
            std::fs::write(paths.mcp_file(), bad).unwrap();
            assert!(McpFile::load(&paths).is_err(), "{bad}");
        }
    }
}
