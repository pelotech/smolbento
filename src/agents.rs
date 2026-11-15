//! Built-in agent names: each is a kit sbx publishes as `docker.io/sbx/<name>:latest`, loaded like
//! any registry kit (`kits::load::agent`). Retired agents are refused with sbx's message.

/// The agent file's name for a workload kit's `agent-context` without a `filename`.
pub const DEFAULT_CONTEXT_FILE: &str = "AGENTS.md";

/// The built-in agent names, each a kit sbx publishes as `docker.io/sbx/<name>:latest`.
pub const NAMES: [&str; 10] = [
    "claude",
    "codex",
    "copilot",
    "cursor",
    "devin",
    "docker-agent",
    "droid",
    "kiro",
    "opencode",
    "shell",
];

/// Set (by tests) to a directory of prebuilt stand-in kits, one OCI layout per agent name, read
/// instead of Docker Hub.
pub const KITS_DIR_ENV: &str = "SMOLBENTO_AGENT_KITS_DIR";

/// Whether `name` is a built-in agent.
pub fn is_agent(name: &str) -> bool {
    NAMES.contains(&name)
}

/// The kit a built-in agent name loads: sbx's published `docker.io/sbx/<name>:latest`, or its
/// stand-in under `SMOLBENTO_AGENT_KITS_DIR`. `None` for any other name.
pub fn kit_ref(env: &std::collections::BTreeMap<String, String>, name: &str) -> Option<String> {
    if !is_agent(name) {
        return None;
    }
    Some(match env.get(KITS_DIR_ENV) {
        Some(dir) => format!("{}/{name}", dir.trim_end_matches('/')),
        None => format!("docker.io/sbx/{name}:latest"),
    })
}

/// Agents sbx no longer offers (v0.53): a new sandbox with one is refused.
const RETIRED: &[Retired] = &[Retired {
    name: "gemini",
    replacement: "antigravity",
    replacement_kit: "docker.io/sbx/antigravity:latest",
    kit: "docker.io/sbx/gemini-kit:latest",
}];

pub struct Retired {
    name: &'static str,
    replacement: &'static str,
    replacement_kit: &'static str,
    /// The kit that still runs it.
    pub kit: &'static str,
}

impl Retired {
    /// sbx's refusal of a new sandbox with this agent.
    pub fn refusal(&self) -> String {
        let name = self.name;
        format!(
            "\"{name}\" is retired and is no longer a built-in agent; prefer {} with `sbt create \
             \"{}\"`, or keep running {name} with `sbt create \"{}\"`",
            self.replacement, self.replacement_kit, self.kit
        )
    }

    /// The same, for an environment file, which keeps it with the kit in `kits:`.
    pub fn env_file_refusal(&self) -> String {
        let name = self.name;
        format!(
            "\"{name}\" is retired and is no longer a built-in agent; its replacement is {} ({}). \
             To keep running {name}, add {} to the environment file's `kits:` (beside `agent: \
             {name}`)",
            self.replacement, self.replacement_kit, self.kit
        )
    }
}

/// The retired agent called `name`, if it is one.
pub fn retired(name: &str) -> Option<&'static Retired> {
    RETIRED.iter().find(|r| r.name == name)
}

/// The error for a name that is no agent.
pub fn unknown(name: &str) -> String {
    format!("unknown agent \"{name}\"")
}

fn split_tag(image: &str) -> Option<(&str, &str)> {
    image.rsplit_once(':').filter(|(_, tag)| !tag.contains('/'))
}

/// True for Docker's `-docker` template variants, which bundle a Docker engine: how an image given
/// with `-t` (not a kit) is judged.
pub fn is_docker_image(image: &str) -> bool {
    split_tag(image).is_some_and(|(_, tag)| tag.ends_with("-docker") || tag.contains("-docker-"))
}

/// sbx's rule for `-- ARGS`: flags are appended to the agent's command; a bare word replaces its
/// flags.
pub fn command_with_args<S: AsRef<str>>(command: &[S], args: &[String]) -> Vec<String> {
    let mut cmd: Vec<String> = command.iter().map(|s| s.as_ref().to_string()).collect();
    match args.first() {
        None => {}
        Some(first) if first.starts_with('-') => cmd.extend(args.iter().cloned()),
        Some(_) => {
            cmd.truncate(1);
            cmd.extend(args.iter().cloned());
        }
    }
    cmd
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gemini_is_retired_as_in_sbx() {
        assert!(!is_agent("gemini"), "no new gemini sandboxes");
        assert_eq!(
            retired("gemini").unwrap().refusal(),
            "\"gemini\" is retired and is no longer a built-in agent; prefer antigravity with \
             `sbt create \"docker.io/sbx/antigravity:latest\"`, or keep running gemini with `sbt \
             create \"docker.io/sbx/gemini-kit:latest\"`"
        );
        assert!(retired("claude").is_none());
    }

    #[test]
    fn docker_image_detection() {
        assert!(is_docker_image("docker/sandbox-templates:shell-docker"));
        assert!(is_docker_image(
            "docker/sandbox-templates:docker-agent-docker-0.11.0"
        ));
        assert!(!is_docker_image(
            "docker/sandbox-templates:docker-agent-0.11.0"
        ));
        assert!(!is_docker_image("alpine"));
        assert!(!is_docker_image("localhost:5000/x"));
    }

    #[test]
    fn agent_args_rule() {
        let base = &["claude", "--dangerously-skip-permissions"];
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        assert_eq!(command_with_args(base, &[]), s(base));
        assert_eq!(
            command_with_args(base, &s(&["-c"])),
            s(&["claude", "--dangerously-skip-permissions", "-c"])
        );
        assert_eq!(
            command_with_args(base, &s(&["mcp", "list"])),
            s(&["claude", "mcp", "list"])
        );
    }
}

#[cfg(test)]
mod kit_ref_tests {
    use super::*;

    #[test]
    fn kit_ref_defaults_to_docker_hub() {
        let mut env = std::collections::BTreeMap::new();
        assert_eq!(
            kit_ref(&env, "codex").as_deref(),
            Some("docker.io/sbx/codex:latest")
        );
        assert_eq!(kit_ref(&env, "nope"), None);
        assert_eq!(kit_ref(&env, "gemini"), None);
        env.insert("SMOLBENTO_AGENT_KITS_DIR".to_string(), "/kits".to_string());
        assert_eq!(kit_ref(&env, "codex").as_deref(), Some("/kits/codex"));
        assert!(is_agent("docker-agent") && !is_agent("antigravity"));
    }
}
