//! sbx agent presets. Tags are pinned; Renovate bumps them (see renovate.json5). Real sbx uses
//! the `-docker` variants (verified against sbx v0.49.2), so every preset does too.

pub struct Agent {
    pub name: &'static str,
    pub image: &'static str,
    pub command: &'static [&'static str],
    /// The profile file `agent-context@1` writes into (a managed section per kit).
    pub context_file: &'static str,
}

/// The context file of workloads that aren't a preset.
pub const DEFAULT_CONTEXT_FILE: &str = "/home/agent/AGENTS.md";

pub const AGENTS: &[Agent] = &[
    Agent {
        name: "claude",
        image: "docker/sandbox-templates:claude-code-docker-0.10.0",
        context_file: "/home/agent/.claude/CLAUDE.md",
        command: &["claude", "--dangerously-skip-permissions"],
    },
    Agent {
        name: "codex",
        image: "docker/sandbox-templates:codex-docker-0.7.0",
        context_file: "/home/agent/.codex/AGENTS.md",
        command: &["codex", "--dangerously-bypass-approvals-and-sandbox"],
    },
    Agent {
        name: "copilot",
        image: "docker/sandbox-templates:copilot-docker-0.4.0",
        context_file: DEFAULT_CONTEXT_FILE,
        command: &["copilot", "--yolo"],
    },
    Agent {
        name: "cursor",
        image: "docker/sandbox-templates:cursor-agent-docker-0.7.0",
        context_file: DEFAULT_CONTEXT_FILE,
        command: &["cursor-agent", "--yolo"],
    },
    Agent {
        name: "devin",
        image: "docker/sandbox-templates:devin-docker-0.7.0",
        context_file: DEFAULT_CONTEXT_FILE,
        command: &[
            "devin",
            "--permission-mode",
            "dangerous",
            "--respect-workspace-trust=false",
        ],
    },
    Agent {
        name: "docker-agent",
        image: "docker/sandbox-templates:docker-agent-docker-0.7.0",
        context_file: DEFAULT_CONTEXT_FILE,
        command: &["docker-agent", "run", "--yolo"],
    },
    Agent {
        name: "droid",
        image: "docker/sandbox-templates:droid-docker-0.4.0",
        context_file: DEFAULT_CONTEXT_FILE,
        command: &["droid"],
    },
    Agent {
        name: "gemini",
        image: "docker/sandbox-templates:gemini-docker-0.10.0",
        context_file: "/home/agent/.gemini/GEMINI.md",
        command: &["gemini", "--yolo"],
    },
    Agent {
        name: "kiro",
        image: "docker/sandbox-templates:kiro-docker-0.4.0",
        context_file: DEFAULT_CONTEXT_FILE,
        command: &["kiro", "chat", "--trust-all-tools"],
    },
    Agent {
        name: "opencode",
        image: "docker/sandbox-templates:opencode-docker-0.7.0",
        context_file: DEFAULT_CONTEXT_FILE,
        command: &["opencode"],
    },
    Agent {
        name: "shell",
        image: "docker/sandbox-templates:shell-docker-0.10.0",
        context_file: DEFAULT_CONTEXT_FILE,
        command: &["bash", "-l"],
    },
];

pub fn find(name: &str) -> Option<&'static Agent> {
    AGENTS.iter().find(|a| a.name == name)
}

pub fn names() -> Vec<&'static str> {
    AGENTS.iter().map(|a| a.name).collect()
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
        assert_eq!(AGENTS.len(), 11);
        for a in AGENTS {
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
            "docker/sandbox-templates:docker-agent-docker-0.7.0"
        ));
        assert!(!is_docker_image(
            "docker/sandbox-templates:docker-agent-0.7.0"
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
            plain_image("docker/sandbox-templates:docker-agent-docker-0.7.0"),
            "docker/sandbox-templates:docker-agent-0.7.0"
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
