//! Built-in agent names: each is a kit sbx publishes as `docker.io/sbx/<name>:latest`, loaded like
//! any registry kit (`kits::load::agent`). Retired agents are refused with sbx's message.

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

/// Writes a stand-in for every built-in agent's kit under `dir`, for tests (unit and e2e), which
/// read them with `SMOLBENTO_AGENT_KITS_DIR` instead of Docker Hub: a prebuilt v3 workload with
/// no layers (booted with `-t <image>`), launching as sbx's kits do as `agent`, asking for Docker,
/// and declaring `sbx@1`. Their agent files and skills directories are where the real kits keep
/// them: `shell`'s `AGENTS.md` beside the workspace, `claude`'s in `~/.claude`.
#[doc(hidden)]
pub fn write_stand_ins(dir: &std::path::Path) -> std::io::Result<()> {
    for name in NAMES {
        let descriptor = match name {
            "claude" => STAND_IN_CLAUDE,
            "shell" => STAND_IN_SHELL,
            _ => {
                r#"{"schemaVersion":"3","kind":"workload","capabilities":[
                {"type":"com.docker.sandbox/sbx@1"}]}"#
            }
        };
        write_stand_in(dir, name, descriptor)?;
    }
    Ok(())
}

/// The `shell` stand-in's descriptor: the real kit's `sbx@1` and agent file.
pub(crate) const STAND_IN_SHELL: &str = r#"{"schemaVersion":"3","kind":"workload","capabilities":[
  {"type":"com.docker.sandbox/sbx@1"},
  {"type":"com.docker.sandbox/agent-context@1","optional":true,
   "config":{"content":"","filename":"AGENTS.md"}},
  {"type":"com.docker.sandbox/agent-context@2","optional":true,
   "config":{"content":"","filename":"AGENTS.md"}}]}"#;

/// The `claude` stand-in's descriptor: the real kit's `sbx@1`, agent file and skills directory.
pub(crate) const STAND_IN_CLAUDE: &str = r#"{"schemaVersion":"3","kind":"workload","capabilities":[
  {"type":"com.docker.sandbox/sbx@1"},
  {"type":"com.docker.sandbox/agent-skills@1","optional":true,
   "config":{"path":"/home/agent/.claude/skills"}},
  {"type":"com.docker.sandbox/agent-context@1","optional":true,
   "config":{"content":"","directory":"/home/agent/.claude","filename":"CLAUDE.md"}},
  {"type":"com.docker.sandbox/agent-context@2","optional":true,
   "config":{"content":"","directory":"/home/agent/.claude","filename":"CLAUDE.md"}}]}"#;

/// Writes (or replaces) agent `name`'s stand-in under `dir` with `descriptor`.
#[doc(hidden)]
pub fn write_stand_in(dir: &std::path::Path, name: &str, descriptor: &str) -> std::io::Result<()> {
    let kit = dir.join(name);
    if kit.exists() {
        std::fs::remove_dir_all(&kit)?;
    }
    let entrypoint: &[&str] = if name == "shell" {
        &["bash", "-l"]
    } else {
        &[name]
    };
    let config =
        serde_json::json!({"config": {"Entrypoint": entrypoint, "User": "agent"}}).to_string();
    let extra = [("com.docker.sandboxes.start-docker", "true")];
    crate::kits::registry::write_layout(&kit, Some(descriptor), &extra, &[], &config).map(drop)
}

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
            "\"{name}\" is retired and is no longer a built-in agent; prefer {} with `bento create \
             \"{}\"`, or keep running {name} with `bento create \"{}\"`",
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gemini_is_retired_as_in_sbx() {
        assert!(!is_agent("gemini"), "no new gemini sandboxes");
        assert_eq!(
            retired("gemini").unwrap().refusal(),
            "\"gemini\" is retired and is no longer a built-in agent; prefer antigravity with \
             `bento create \"docker.io/sbx/antigravity:latest\"`, or keep running gemini with `bento \
             create \"docker.io/sbx/gemini-kit:latest\"`"
        );
        assert!(retired("claude").is_none());
    }

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
