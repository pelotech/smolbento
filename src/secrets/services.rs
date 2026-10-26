//! Built-in services (sbx's table, plus `claude` for Claude Code's subscription token).

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Service {
    pub name: String,
    pub env_vars: Vec<String>,
    pub hosts: Vec<String>,
}

const BUILTIN: &[(&str, &[&str], &[&str])] = &[
    (
        "anthropic",
        &["ANTHROPIC_API_KEY"],
        &[
            "api.anthropic.com",
            "console.anthropic.com",
            "claude.ai",
            "mcp-proxy.anthropic.com",
        ],
    ),
    (
        "claude",
        &["CLAUDE_CODE_OAUTH_TOKEN"],
        &["api.anthropic.com"],
    ),
    (
        "cursor",
        &["CURSOR_API_KEY"],
        &[
            "api2.cursor.sh",
            "api3.cursor.sh",
            "repo42.cursor.sh",
            "cursor.com",
        ],
    ),
    (
        "droid",
        &["FACTORY_API_KEY"],
        &["api.factory.ai", "app.factory.ai", "relay.factory.ai"],
    ),
    (
        "github",
        &["GH_TOKEN", "GITHUB_TOKEN"],
        &[
            "api.github.com",
            "github.com",
            "raw.githubusercontent.com",
            "gist.github.com",
            "copilot.github.com",
            "api.githubcopilot.com",
        ],
    ),
    (
        "google",
        &["GEMINI_API_KEY", "GOOGLE_API_KEY"],
        &[
            "generativelanguage.googleapis.com",
            "oauth2.googleapis.com",
            "aiplatform.googleapis.com",
            "vertexai.googleapis.com",
        ],
    ),
    ("groq", &["GROQ_API_KEY"], &["api.groq.com"]),
    ("mistral", &["MISTRAL_API_KEY"], &["api.mistral.ai"]),
    (
        "nebius",
        &["NEBIUS_API_KEY"],
        &["api.studio.nebius.com", "api.tokenfactory.nebius.com"],
    ),
    (
        "openai",
        &["OPENAI_API_KEY"],
        &[
            "api.openai.com",
            "openai.com",
            "chatgpt.com",
            "www.chatgpt.com",
        ],
    ),
    ("openrouter", &["OPENROUTER_API_KEY"], &["openrouter.ai"]),
    ("xai", &["XAI_API_KEY"], &["api.x.ai"]),
];

fn to_vec(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| s.to_string()).collect()
}

pub fn builtin(name: &str) -> Option<Service> {
    BUILTIN
        .iter()
        .find(|(n, _, _)| *n == name)
        .map(|(n, vars, hosts)| Service {
            name: n.to_string(),
            env_vars: to_vec(vars),
            hosts: to_vec(hosts),
        })
}

pub fn builtin_names() -> Vec<&'static str> {
    BUILTIN.iter().map(|(n, _, _)| *n).collect()
}

/// The built-in service that already uses an env var, if any.
pub fn env_var_owner(var: &str) -> Option<&'static str> {
    BUILTIN
        .iter()
        .find(|(_, vars, _)| vars.contains(&var))
        .map(|(n, _, _)| *n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table() {
        assert_eq!(builtin_names().len(), 12);
        assert_eq!(
            builtin("github").unwrap().env_vars,
            vec!["GH_TOKEN", "GITHUB_TOKEN"]
        );
        assert!(
            builtin("claude")
                .unwrap()
                .hosts
                .contains(&"api.anthropic.com".to_string())
        );
        assert_eq!(env_var_owner("OPENAI_API_KEY"), Some("openai"));
        assert!(builtin("nope").is_none());
    }
}
