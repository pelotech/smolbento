use std::path::Path;

use anyhow::{Result, bail};

pub const MACHINE_PREFIX: &str = "sbx-";

/// Checks a sandbox name against sbx's rules and smolvm's machine-name rules.
pub fn validate(name: &str) -> Result<()> {
    if name.len() < 2 {
        bail!("sandbox name '{name}' is too short (minimum 2 characters)");
    }
    if name.len() > 124 {
        bail!("sandbox name '{name}' is too long (maximum 124 characters)");
    }
    if name == "default" {
        bail!("'default' is a reserved sandbox name");
    }
    if !name.starts_with(|c: char| c.is_ascii_alphanumeric()) {
        bail!("sandbox name '{name}' must start with a letter or digit");
    }
    if let Some(c) = name
        .chars()
        .find(|c| !(c.is_ascii_alphanumeric() || *c == '-' || *c == '.'))
    {
        bail!("sandbox name '{name}' contains '{c}'; use letters, digits, '-' and '.'");
    }
    if name.contains("--") {
        bail!("sandbox name '{name}' contains '--', which smolvm machine names can't");
    }
    if name.ends_with('-') {
        bail!("sandbox name '{name}' ends with '-', which smolvm machine names can't");
    }
    Ok(())
}

/// smolbento's own sandboxes, such as the kit builder (`_builder`): a leading `_`, which user
/// names can't have. They're hidden from `ls`, not forkable, and get no secrets.
pub fn is_internal(name: &str) -> bool {
    name.starts_with('_')
}

/// smolvm allows `_` but not `.`; sbx allows `.` but not `_`, so the mapping is reversible.
pub fn machine_name(name: &str) -> String {
    format!("{MACHINE_PREFIX}{}", name.replace('.', "_"))
}

/// sbx's default name, `<agent>-<workspace basename>`, with disallowed characters turned into `-`.
pub fn default_name(agent: &str, workspace: &Path) -> String {
    let base = workspace
        .file_name()
        .map(|b| b.to_string_lossy().into_owned())
        .unwrap_or_else(|| "root".into());
    let mut out = String::new();
    for c in format!("{agent}-{base}").chars() {
        let c = if c.is_ascii_alphanumeric() || c == '.' {
            c
        } else {
            '-'
        };
        if c == '-' && out.ends_with('-') {
            continue;
        }
        out.push(c);
    }
    out.trim_matches('-').to_string()
}

/// A name for a sandbox of `workspace` when its default name belongs to another folder's:
/// `<agent>-<parent>-<folder>`, then `-2`, `-3`… past names `taken` says are in use.
pub fn suggest_name(agent: &str, workspace: &Path, taken: impl Fn(&str) -> bool) -> String {
    let folder = |p: &Path| p.file_name().map(|b| b.to_string_lossy().into_owned());
    let joined = match (workspace.parent().and_then(folder), folder(workspace)) {
        (Some(parent), Some(base)) => format!("{parent}-{base}"),
        (_, base) => base.unwrap_or_else(|| "root".into()),
    };
    let first = default_name(agent, Path::new(&joined));
    (1..)
        .map(|n| {
            if n == 1 {
                first.clone()
            } else {
                format!("{first}-{n}")
            }
        })
        .find(|n| !taken(n))
        .expect("an unused name")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internal_names_start_with_an_underscore() {
        assert!(is_internal("_builder"));
        assert!(!is_internal("claude-repo"));
        assert!(
            validate("_builder").is_err(),
            "users can't take internal names"
        );
    }

    #[test]
    fn valid_names() {
        for n in ["claude-myrepo", "a.b", "ab", "x1-y2.z"] {
            validate(n).unwrap();
        }
    }

    #[test]
    fn invalid_names() {
        for (n, why) in [
            ("a", "too short"),
            ("default", "reserved"),
            ("-ab", "must start"),
            ("a_b", "contains '_'"),
            ("a--b", "contains '--'"),
            ("ab-", "ends with '-'"),
        ] {
            let err = validate(n).unwrap_err().to_string();
            assert!(err.contains(why), "{n}: {err}");
        }
    }

    #[test]
    fn machine_name_round_trip() {
        assert_eq!(machine_name("my.app"), "sbx-my_app");
    }

    #[test]
    fn a_suggested_name_adds_the_parent_folder_then_a_number() {
        let ws = Path::new("/src/uki-code/infrastructure");
        assert_eq!(
            suggest_name("claude", ws, |_| false),
            "claude-uki-code-infrastructure"
        );
        assert_eq!(
            suggest_name("claude", ws, |n| n == "claude-uki-code-infrastructure"),
            "claude-uki-code-infrastructure-2"
        );
    }

    #[test]
    fn default_names() {
        assert_eq!(
            default_name("claude", Path::new("/Users/x/myrepo")),
            "claude-myrepo"
        );
        assert_eq!(
            default_name("claude", Path::new("/Users/x/My Repo_1")),
            "claude-My-Repo-1"
        );
        assert_eq!(default_name("shell", Path::new("/")), "shell-root");
    }
}
