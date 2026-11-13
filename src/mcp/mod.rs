//! MCP servers registered on the host (`sbt mcp`) and given to a sandbox's agent at create
//! (`--static-mcp`). smolbento doesn't speak MCP: a server is written into the agent's own MCP
//! config, and a header secret travels as a smolvm credential placeholder.

mod attach;
mod registrar;
mod store;

pub use attach::{Attachment, attach};
pub use store::{McpFile, Server};

use std::collections::BTreeMap;

use anyhow::{Context, Result, bail};

/// Fails when nothing answers at `url`: any HTTP response will do, as only reaching the server
/// is checked (sbx contacts it when it registers it, for OAuth discovery).
pub fn check_reachable(name: &str, url: &str) -> Result<()> {
    connect(url).map_err(|e| {
        anyhow::anyhow!(
            "register mcp server \"{name}\": server \"{name}\": discovery failed: connecting to \
             server {url}: {e:#}"
        )
    })
}

#[cfg(not(test))]
fn connect(url: &str) -> Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("starting the HTTP client")?;
    rt.block_on(async {
        // Same TLS setup as the registry client. Err means a provider is already installed.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(std::time::Duration::from_secs(15))
            .timeout(std::time::Duration::from_secs(30))
            .build()?;
        client.get(url).send().await?;
        Ok(())
    })
}

/// Tests don't reach the network: a `.invalid` host is unreachable, any other answers.
#[cfg(test)]
fn connect(url: &str) -> Result<()> {
    let host = reqwest::Url::parse(url)?
        .host_str()
        .unwrap_or_default()
        .to_string();
    if host.ends_with(".invalid") {
        bail!("dns error: failed to lookup address information");
    }
    Ok(())
}

/// Registers `server` as `name`: nothing to do when it is already, refused when `name` is
/// registered differently.
pub fn register(paths: &crate::config::Paths, name: &str, server: Server) -> Result<()> {
    check_server(name, &server)?;
    let mut file = McpFile::load(paths)?;
    match file.servers.get(name) {
        Some(existing) if *existing == server => Ok(()),
        Some(_) => {
            bail!("MCP server {name} is already registered differently; `sbt mcp rm {name}` first")
        }
        None => {
            file.servers.insert(name.to_string(), server);
            file.save(paths)
        }
    }
}

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

/// Checks a registration as `mcp add` does: the file can be edited by hand.
pub fn check_server(name: &str, server: &Server) -> Result<()> {
    check_name(name)?;
    match server {
        Server::Remote { url, headers } => check_remote(url, headers),
        Server::Command { command, .. } if command.trim().is_empty() => {
            bail!("the command is empty")
        }
        Server::Command { .. } => Ok(()),
    }
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
    if !parsed.username().is_empty() || parsed.password().is_some() {
        bail!(
            "'{url}' has credentials in it; they would be stored and passed around in clear. \
             Send them in a header instead: --header 'Authorization: Bearer ${{name}}'"
        );
    }
    let host = parsed
        .host_str()
        .with_context(|| format!("'{url}' has no host"))?
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim_end_matches('.')
        .to_ascii_lowercase();
    let (is_ip, local) = match host.parse::<std::net::IpAddr>() {
        Ok(a) => {
            // `::ffff:127.0.0.1` is 127.0.0.1.
            let a = a.to_canonical();
            (true, a.is_loopback() || a.is_unspecified())
        }
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
    let mut seen: Vec<String> = Vec::new();
    let mut secret_header: Option<&str> = None;
    for (name, value) in headers {
        // A leading `-` would read as an option of the agent's own `mcp add` command.
        let token = !name.is_empty()
            && !name.starts_with('-')
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "!#$%&'*+-.^_`|~".contains(c));
        if !token {
            bail!("'{name}' isn't a valid header name");
        }
        let lower = name.to_ascii_lowercase();
        if seen.contains(&lower) {
            bail!("header {name} is given twice");
        }
        seen.push(lower);
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
        // smolvm refuses a request that carries two placeholders, and every request to the
        // server carries all its headers.
        if let Some(other) = secret_header.replace(name) {
            bail!(
                "headers {other} and {name} both have a secret: only one header of a server \
                 can carry one"
            );
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
            "https://localhost./mcp",
            "https://host.docker.internal./x",
            "http://[::ffff:127.0.0.1]/",
            // Credentials in a URL would be stored and passed around in clear.
            "https://user:pass@mcp.example.com/mcp",
            "https://token@mcp.example.com/mcp",
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
            ("-x", "v"),
            ("", "x"),
            ("X", "line\nbreak"),
        ] {
            let h = headers(&[(name, value)]);
            assert!(
                check_remote("https://x.com/", &h).is_err(),
                "{name}: {value}"
            );
        }
        // One secret per server: smolvm refuses a request that carries two placeholders.
        let two = headers(&[("Authorization", "Bearer ${a}"), ("X-Key", "${b}")]);
        let err = check_remote("https://x.com/", &two)
            .unwrap_err()
            .to_string();
        assert!(err.contains("one header"), "{err}");
        let same = headers(&[("Authorization", "Bearer ${a}"), ("X-Key", "${a}")]);
        assert!(check_remote("https://x.com/", &same).is_err());
        // Header names differing only in case are one header.
        let dup = headers(&[("Authorization", "a"), ("authorization", "b")]);
        assert!(check_remote("https://x.com/", &dup).is_err());
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
        // A trailing dot names the same host; the rule and the credential use the plain name.
        let dotted = Server::Remote {
            url: "https://mcp.linear.app./sse".into(),
            headers: BTreeMap::new(),
        };
        assert_eq!(dotted.host().as_deref(), Some("mcp.linear.app"));
        let c = Server::Command {
            command: "npx".into(),
            args: vec![],
        };
        assert_eq!(c.host(), None);
    }
}
