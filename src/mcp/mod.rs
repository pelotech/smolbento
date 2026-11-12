//! MCP servers registered on the host (`sbt mcp`) and given to a sandbox's agent at create
//! (`--static-mcp`). smolbento doesn't speak MCP: a server is written into the agent's own MCP
//! config, and a header secret travels as a smolvm credential placeholder.

mod store;

pub use store::{McpFile, Server};

use std::collections::BTreeMap;

use anyhow::{Context, Result, bail};

/// A server's name: what `--static-mcp` and the agent's config call it.
pub fn check_name(name: &str) -> Result<()> {
    let ok = (1..=64).contains(&name.len())
        && name.starts_with(|c: char| c.is_ascii_alphanumeric())
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if !ok {
        bail!(
            "invalid MCP server name '{name}': use up to 64 letters, digits, '-' and '_', \
             starting with a letter or digit"
        );
    }
    Ok(())
}

/// The secret a header's `${placeholder}` takes its value from.
pub fn secret_name(server: &str, placeholder: &str) -> String {
    format!("mcp:{server}:{placeholder}")
}

/// The guest env var that holds smolvm's placeholder for that secret.
pub fn env_var(server: &str, placeholder: &str) -> String {
    let part = |s: &str| -> String {
        s.chars()
            .map(|c| match c.to_ascii_uppercase() {
                u if u.is_ascii_alphanumeric() => u,
                _ => '_',
            })
            .collect()
    };
    format!("SBX_MCP_{}_{}", part(server), part(placeholder))
}

/// The name in a header value's single `${placeholder}`; `None` when it has none, several, or a
/// malformed one (`placeholders` says which).
pub fn placeholder(value: &str) -> Option<&str> {
    match placeholders(value) {
        Ok(names) if names.len() == 1 => Some(names[0]),
        _ => None,
    }
}

/// Every `${name}` in a header value; an unclosed or oddly named one is an error.
fn placeholders(value: &str) -> Result<Vec<&str>> {
    let mut names = Vec::new();
    let mut rest = value;
    while let Some(start) = rest.find("${") {
        let after = &rest[start + 2..];
        let end = after
            .find('}')
            .with_context(|| format!("'{value}' has an unclosed ${{"))?;
        let name = &after[..end];
        let ok = !name.is_empty()
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.');
        if !ok {
            bail!("'{value}': a placeholder is ${{name}}, with letters, digits, '-', '_' and '.'");
        }
        names.push(name);
        rest = &after[end + 1..];
    }
    Ok(names)
}

/// Checks a remote server's URL and headers at `mcp add`.
pub fn check_remote(url: &str, headers: &BTreeMap<String, String>) -> Result<()> {
    let parsed = reqwest::Url::parse(url).with_context(|| format!("invalid URL '{url}'"))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        bail!("'{url}': an MCP server URL starts with https:// or http://");
    }
    let host = parsed
        .host_str()
        .with_context(|| format!("'{url}' has no host"))?
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase();
    let (is_ip, local) = match host.parse::<std::net::IpAddr>() {
        Ok(a) => (true, a.is_loopback() || a.is_unspecified()),
        Err(_) => (
            false,
            host == "localhost" || host.ends_with(".localhost") || host == "host.docker.internal",
        ),
    };
    if local {
        bail!(
            "'{url}': inside a sandbox that address is the sandbox itself, not your machine; \
             to run the server in the sandbox, register it with --command"
        );
    }
    for (name, value) in headers {
        let token = !name.is_empty()
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "!#$%&'*+-.^_`|~".contains(c));
        if !token {
            bail!("'{name}' isn't a valid header name");
        }
        if value.chars().any(char::is_control) {
            bail!("header {name}: the value has control characters");
        }
        let secrets = placeholders(value).with_context(|| format!("header {name}"))?;
        if secrets.len() > 1 {
            bail!("header {name}: only one ${{placeholder}} per header is supported");
        }
        if secrets.is_empty() {
            continue;
        }
        // smolvm substitutes a secret only on HTTPS (port 443) requests to a host name.
        if parsed.scheme() != "https" {
            bail!("header {name} has a secret: the URL must be https://");
        }
        if parsed.port().is_some() {
            bail!("header {name} has a secret: smolvm can't bind one to a host with a port yet");
        }
        if is_ip {
            bail!("header {name} has a secret: the URL needs a host name, not an IP address");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn names() {
        for ok in ["linear", "my-db_2", "9lives"] {
            check_name(ok).unwrap();
        }
        let long = "a".repeat(65);
        for bad in ["", "-x", "_x", "a b", "a;rm", "a$(x)", "a/b", long.as_str()] {
            assert!(check_name(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn remote_checks() {
        let none = BTreeMap::new();
        for ok in ["https://mcp.linear.app/sse", "http://10.0.0.5:8080/mcp"] {
            check_remote(ok, &none).unwrap();
        }
        for bad in [
            "ftp://x",
            "not a url",
            "https://localhost/mcp",
            "https://api.localhost/mcp",
            "http://127.0.0.1:9/",
            "https://[::1]/",
            "https://host.docker.internal/x",
        ] {
            assert!(check_remote(bad, &none).is_err(), "{bad}");
        }
        let err = check_remote("https://localhost/mcp", &none)
            .unwrap_err()
            .to_string();
        assert!(err.contains("--command"), "{err}");

        let secret = headers(&[("Authorization", "Bearer ${api-key}")]);
        check_remote("https://mcp.linear.app/sse", &secret).unwrap();
        check_remote("https://mcp.linear.app:443/sse", &secret).unwrap();
        for bad in ["http://x.com/", "https://x.com:8443/", "https://10.0.0.5/"] {
            assert!(check_remote(bad, &secret).is_err(), "{bad}");
        }
        for (name, value) in [
            ("Authorization", "Bearer ${a}${b}"),
            ("Authorization", "Bearer ${}"),
            ("Authorization", "Bearer ${a b}"),
            ("Authorization", "Bearer ${open"),
            ("Bad Name", "x"),
            ("", "x"),
            ("X", "line\nbreak"),
        ] {
            let h = headers(&[(name, value)]);
            assert!(
                check_remote("https://x.com/", &h).is_err(),
                "{name}: {value}"
            );
        }
        // A plain header needs no HTTPS host name.
        check_remote("http://10.0.0.5/", &headers(&[("X-Team", "a b")])).unwrap();
    }

    #[test]
    fn names_for_secrets_and_env() {
        assert_eq!(secret_name("linear", "api-key"), "mcp:linear:api-key");
        assert_eq!(env_var("my-db", "api.key"), "SBX_MCP_MY_DB_API_KEY");
        assert_eq!(placeholder("Bearer ${api-key}"), Some("api-key"));
        assert_eq!(placeholder("plain"), None);
        assert_eq!(placeholder("${a}${b}"), None);
    }

    #[test]
    fn a_remote_servers_host() {
        let s = Server::Remote {
            url: "https://MCP.Linear.app/sse".into(),
            headers: BTreeMap::new(),
        };
        assert_eq!(s.host().as_deref(), Some("mcp.linear.app"));
        let c = Server::Command {
            command: "npx".into(),
            args: vec![],
        };
        assert_eq!(c.host(), None);
    }
}
