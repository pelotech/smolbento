//! sbx agent presets. Tags are pinned; Renovate bumps them (see renovate.json5). Real sbx uses
//! the `-docker` variants (verified against sbx v0.49.2), so every preset does too.

pub struct Agent {
    pub name: &'static str,
    pub image: &'static str,
    pub command: &'static [&'static str],
    /// The agent file's name. Like sbx, it sits in the parent of the workspace path in the
    /// guest; kit agent context goes there.
    pub context_file: &'static str,
    /// Where the agent reads skills (sbx's table); `None` for agents without skills.
    pub skills_dir: Option<&'static str>,
}

/// The agent file's name for presets without their own, and for a workload kit's
/// `agent-context` without a `filename`.
pub const DEFAULT_CONTEXT_FILE: &str = "AGENTS.md";

pub const AGENTS: &[Agent] = &[
    Agent {
        name: "claude",
        image: "docker/sandbox-templates:claude-code-docker-0.10.0",
        context_file: "CLAUDE.md",
        skills_dir: Some("/home/agent/.claude/skills"),
        command: &["claude", "--dangerously-skip-permissions"],
    },
    Agent {
        name: "codex",
        image: "docker/sandbox-templates:codex-docker-0.11.0",
        context_file: DEFAULT_CONTEXT_FILE,
        skills_dir: Some("/home/agent/.agents/skills"),
        command: &["codex", "--dangerously-bypass-approvals-and-sandbox"],
    },
    Agent {
        name: "copilot",
        image: "docker/sandbox-templates:copilot-docker-0.11.0",
        context_file: DEFAULT_CONTEXT_FILE,
        skills_dir: Some("/home/agent/.copilot/skills"),
        command: &["copilot", "--yolo"],
    },
    Agent {
        name: "cursor",
        image: "docker/sandbox-templates:cursor-agent-docker-0.11.0",
        context_file: DEFAULT_CONTEXT_FILE,
        skills_dir: Some("/home/agent/.cursor/skills"),
        command: &["cursor-agent", "--yolo"],
    },
    Agent {
        name: "devin",
        image: "docker/sandbox-templates:devin-docker-0.11.0",
        context_file: DEFAULT_CONTEXT_FILE,
        skills_dir: Some("/home/agent/.agents/skills"),
        command: &[
            "devin",
            "--permission-mode",
            "dangerous",
            "--respect-workspace-trust=false",
        ],
    },
    Agent {
        name: "docker-agent",
        image: "docker/sandbox-templates:docker-agent-docker-0.11.0",
        context_file: DEFAULT_CONTEXT_FILE,
        skills_dir: None,
        command: &["docker-agent", "run", "--yolo"],
    },
    Agent {
        name: "droid",
        image: "docker/sandbox-templates:droid-docker-0.11.0",
        context_file: DEFAULT_CONTEXT_FILE,
        skills_dir: Some("/home/agent/.factory/skills"),
        command: &["droid"],
    },
    Agent {
        name: "kiro",
        image: "docker/sandbox-templates:kiro-docker-0.4.0",
        context_file: DEFAULT_CONTEXT_FILE,
        skills_dir: None,
        command: &["kiro", "chat", "--trust-all-tools"],
    },
    Agent {
        name: "opencode",
        image: "docker/sandbox-templates:opencode-docker-0.11.0",
        context_file: DEFAULT_CONTEXT_FILE,
        skills_dir: Some("/home/agent/.config/opencode/skills"),
        command: &["opencode"],
    },
    Agent {
        name: "shell",
        image: "docker/sandbox-templates:shell-docker-0.10.0",
        context_file: DEFAULT_CONTEXT_FILE,
        skills_dir: None,
        command: &["bash", "-l"],
    },
];

/// Agents sbx no longer offers (v0.53): no new sandbox gets one, and sandboxes created with one
/// keep working.
const RETIRED: &[Retired] = &[Retired {
    agent: Agent {
        name: "gemini",
        image: "docker/sandbox-templates:gemini-docker-0.10.0",
        context_file: "GEMINI.md",
        skills_dir: None,
        command: &["gemini", "--yolo"],
    },
    replacement: "antigravity",
    replacement_kit: "docker.io/sbx/antigravity:latest",
    kit: "docker.io/sbx/gemini-kit:latest",
}];

pub struct Retired {
    agent: Agent,
    replacement: &'static str,
    replacement_kit: &'static str,
    /// The kit that still runs it.
    pub kit: &'static str,
}

impl Retired {
    /// sbx's refusal of a new sandbox with this agent.
    pub fn refusal(&self) -> String {
        let name = self.agent.name;
        format!(
            "\"{name}\" is retired and is no longer a built-in agent; prefer {} with `sbt create \
             \"{}\"`, or keep running {name} with `sbt create \"{}\"`",
            self.replacement, self.replacement_kit, self.kit
        )
    }

    /// The same, for an environment file, which keeps it with the kit in `kits:`.
    pub fn env_file_refusal(&self) -> String {
        let name = self.agent.name;
        format!(
            "\"{name}\" is retired and is no longer a built-in agent; its replacement is {} ({}). \
             To keep running {name}, add {} to the environment file's `kits:` (beside `agent: \
             {name}`)",
            self.replacement, self.replacement_kit, self.kit
        )
    }
}

/// A built-in agent a new sandbox can have.
pub fn find(name: &str) -> Option<&'static Agent> {
    AGENTS.iter().find(|a| a.name == name)
}

/// The agent of a sandbox that exists, retired ones included.
pub fn find_any(name: &str) -> Option<&'static Agent> {
    find(name).or_else(|| RETIRED.iter().map(|r| &r.agent).find(|a| a.name == name))
}

/// The retired agent called `name`, if it is one.
pub fn retired(name: &str) -> Option<&'static Retired> {
    RETIRED.iter().find(|r| r.agent.name == name)
}

/// The error for a name that is no agent.
pub fn unknown(name: &str) -> String {
    format!("unknown agent \"{name}\"")
}

fn split_tag(image: &str) -> Option<(&str, &str)> {
    image.rsplit_once(':').filter(|(_, tag)| !tag.contains('/'))
}

/// True for Docker's `-docker` template variants, which bundle a Docker engine.
pub fn is_docker_image(image: &str) -> bool {
    split_tag(image).is_some_and(|(_, tag)| tag.ends_with("-docker") || tag.contains("-docker-"))
}

/// The plain variant of a `-docker` tag (`shell-docker-0.10.0` → `shell-0.10.0`).
pub fn plain_image(image: &str) -> String {
    let Some((repo, tag)) = split_tag(image) else {
        return image.to_string();
    };
    let plain = if let Some(base) = tag.strip_suffix("-docker") {
        base.to_string()
    } else if let Some(i) = tag.rfind("-docker-") {
        format!("{}{}", &tag[..i], &tag[i + "-docker".len()..])
    } else {
        tag.to_string()
    };
    format!("{repo}:{plain}")
}

/// sbx's rule for `-- ARGS`: flags are appended to the preset; a bare word replaces its flags.
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
    fn every_preset_is_a_pinned_docker_variant() {
        // sbx 0.53's built-in agents.
        let names: Vec<&str> = AGENTS.iter().map(|a| a.name).collect();
        assert_eq!(
            names,
            [
                "claude",
                "codex",
                "copilot",
                "cursor",
                "devin",
                "docker-agent",
                "droid",
                "kiro",
                "opencode",
                "shell"
            ]
        );
        for a in AGENTS.iter().chain(RETIRED.iter().map(|r| &r.agent)) {
            assert!(
                a.image.starts_with("docker/sandbox-templates:"),
                "{}",
                a.name
            );
            assert!(is_docker_image(a.image), "{}", a.image);
            assert!(
                a.image.rsplit('-').next().unwrap().contains('.'),
                "{} is not pinned",
                a.image
            );
        }
    }

    #[test]
    fn skills_dirs_follow_sbx() {
        let d = |n: &str| find(n).unwrap().skills_dir;
        assert_eq!(d("claude"), Some("/home/agent/.claude/skills"));
        assert_eq!(d("codex"), Some("/home/agent/.agents/skills"));
        assert_eq!(d("devin"), Some("/home/agent/.agents/skills"));
        assert_eq!(d("copilot"), Some("/home/agent/.copilot/skills"));
        assert_eq!(d("cursor"), Some("/home/agent/.cursor/skills"));
        assert_eq!(d("droid"), Some("/home/agent/.factory/skills"));
        assert_eq!(d("opencode"), Some("/home/agent/.config/opencode/skills"));
        for n in ["kiro", "docker-agent", "shell"] {
            assert_eq!(d(n), None, "{n}");
        }
    }

    #[test]
    fn gemini_is_retired_as_in_sbx() {
        assert!(find("gemini").is_none(), "no new gemini sandboxes");
        assert_eq!(
            retired("gemini").unwrap().refusal(),
            "\"gemini\" is retired and is no longer a built-in agent; prefer antigravity with \
             `sbt create \"docker.io/sbx/antigravity:latest\"`, or keep running gemini with `sbt \
             create \"docker.io/sbx/gemini-kit:latest\"`"
        );
        assert!(retired("claude").is_none());
        // Sandboxes created before keep their agent.
        assert_eq!(find_any("gemini").unwrap().command, &["gemini", "--yolo"]);
        assert!(find_any("claude").is_some());
    }

    #[test]
    fn find_by_name() {
        assert_eq!(
            find("claude").unwrap().command,
            &["claude", "--dangerously-skip-permissions"]
        );
        assert!(find("nope").is_none());
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
    fn plain_variants() {
        assert_eq!(
            plain_image("docker/sandbox-templates:shell-docker-0.10.0"),
            "docker/sandbox-templates:shell-0.10.0"
        );
        assert_eq!(
            plain_image("docker/sandbox-templates:docker-agent-docker-0.11.0"),
            "docker/sandbox-templates:docker-agent-0.11.0"
        );
        assert_eq!(
            plain_image("docker/sandbox-templates:shell-docker"),
            "docker/sandbox-templates:shell"
        );
        assert_eq!(plain_image("alpine"), "alpine");
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
