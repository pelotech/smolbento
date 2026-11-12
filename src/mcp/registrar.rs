//! Guest scripts that write a server into an agent's own MCP config, one per supported agent.

use super::{Server, env_var, placeholder};
use crate::util::sh_quote;

/// Whether `--static-mcp` can register servers for this agent.
pub fn has_registrar(agent: &str) -> bool {
    agent == "claude"
}

/// The guest script (run as the agent's user) that adds `server` to the agent's MCP config, or
/// `None` for an agent without a registrar. A header's `${placeholder}` becomes the guest's
/// `$SBX_MCP_…` variable, which holds smolvm's placeholder for the secret, never its value.
pub fn register_script(agent: &str, name: &str, server: &Server) -> Option<String> {
    match agent {
        "claude" => Some(claude(name, server)),
        _ => None,
    }
}

/// `claude mcp add`, as in Claude Code's docs: options, the name, then the URL (and `--header`s
/// last, since that option takes several values) or `--` and the command.
fn claude(name: &str, server: &Server) -> String {
    match server {
        Server::Remote { url, headers } => {
            // Claude Code's SSE transport is for servers that still serve the older protocol,
            // by convention at a path ending in /sse.
            let path = url.split(['?', '#']).next().unwrap_or(url);
            let transport = if path.trim_end_matches('/').ends_with("/sse") {
                "sse"
            } else {
                "http"
            };
            let mut script = format!(
                "claude mcp add --transport {transport} --scope user {} {}",
                sh_quote(name),
                sh_quote(url)
            );
            for (header, value) in headers {
                script.push_str(" --header ");
                script.push_str(&header_arg(name, header, value));
            }
            script
        }
        Server::Command { command, args } => {
            let mut script = format!(
                "claude mcp add --scope user {} -- {}",
                sh_quote(name),
                sh_quote(command)
            );
            for arg in args {
                script.push(' ');
                script.push_str(&sh_quote(arg));
            }
            script
        }
    }
}

/// One `Name: value` shell word. Without a secret it is single-quoted. With one, it is
/// double-quoted so that only the secret's variable expands; everything else is escaped.
fn header_arg(server: &str, header: &str, value: &str) -> String {
    let Some(secret) = placeholder(value) else {
        return sh_quote(&format!("{header}: {value}"));
    };
    let (before, after) = value
        .split_once(&format!("${{{secret}}}"))
        .unwrap_or((value, ""));
    format!(
        "\"{}: {}${{{}}}{}\"",
        dq_escape(header),
        dq_escape(before),
        env_var(server, secret),
        dq_escape(after)
    )
}

/// Escapes text for the inside of a double-quoted shell word.
fn dq_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if matches!(c, '\\' | '"' | '$' | '`') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn remote(url: &str, headers: &[(&str, &str)]) -> Server {
        Server::Remote {
            url: url.into(),
            headers: headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect::<BTreeMap<_, _>>(),
        }
    }

    #[test]
    fn claude_remote_script() {
        let s = remote(
            "https://mcp.linear.app/sse",
            &[("Authorization", "Bearer ${api-key}")],
        );
        assert_eq!(
            register_script("claude", "linear", &s).unwrap(),
            "claude mcp add --transport sse --scope user 'linear' 'https://mcp.linear.app/sse' \
             --header \"Authorization: Bearer ${SBX_MCP_LINEAR_API_KEY}\""
        );
    }

    #[test]
    fn claude_http_and_command_scripts() {
        assert_eq!(
            register_script("claude", "x", &remote("https://x.dev/mcp", &[])).unwrap(),
            "claude mcp add --transport http --scope user 'x' 'https://x.dev/mcp'"
        );
        let c = Server::Command {
            command: "npx".into(),
            args: vec!["-y".into(), "it's".into()],
        };
        assert_eq!(
            register_script("claude", "files", &c).unwrap(),
            r"claude mcp add --scope user 'files' -- 'npx' '-y' 'it'\''s'"
        );
    }

    #[test]
    fn other_agents_have_no_registrar_yet() {
        assert_eq!(
            register_script("codex", "x", &remote("https://x.dev/mcp", &[])),
            None
        );
        assert!(has_registrar("claude"));
        assert!(!has_registrar("shell"));
    }

    /// What `sh` makes of the script's `--header` arguments, with the secret's variable set.
    fn headers_as_sh_sees_them(script: &str) -> Vec<String> {
        let args = script
            .split_once(" --header ")
            .map(|(_, rest)| rest)
            .unwrap();
        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!(
                "printf '%s\\n' {}",
                args.replace(" --header ", " ")
            ))
            .env("SBX_MCP_X_K", "PLACEHOLDER")
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout)
            .unwrap()
            .lines()
            .map(String::from)
            .collect()
    }

    #[test]
    fn header_values_are_never_executed() {
        let s = remote(
            "https://x.dev/mcp",
            &[
                ("A-Plain", "a`id`$(id)\"'$HOME"),
                ("B-Secret", "pre\"$(id)`id`\\$HOME ${k} post$(id)"),
            ],
        );
        let script = register_script("claude", "x", &s).unwrap();
        assert_eq!(
            headers_as_sh_sees_them(&script),
            [
                "A-Plain: a`id`$(id)\"'$HOME",
                "B-Secret: pre\"$(id)`id`\\$HOME PLACEHOLDER post$(id)"
            ]
        );
    }
}
