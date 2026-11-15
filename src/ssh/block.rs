//! The managed block in `~/.ssh/config`, and editing the file around it.

use anyhow::{Result, bail};

pub const BEGIN: &str = "# >>> smolbento (managed) >>>";
pub const END: &str = "# <<< smolbento (managed) <<<";
/// sbx's own markers; its block claims `Host *.sbx` too.
pub const SBX_BEGIN: &str = "# >>> docker sandboxes (managed) >>>";

/// The block for `bin` (smolbento's absolute path) and the `env` its ProxyCommand sets (only the
/// smolvm settings the user set explicitly). Paths are absolute because an IDE started from the
/// Dock runs the ProxyCommand with a minimal PATH. It ends
/// with `Host *`, so settings that follow it (or precede it, when it is first in the file) keep
/// their scope: the block goes first so that its settings win over a user's `Host *` (ssh uses the
/// first value it finds).
pub fn render(bin: &str, env: &[(String, String)]) -> String {
    let env = if env.is_empty() {
        String::new()
    } else {
        let vars: Vec<String> = env
            .iter()
            .map(|(k, v)| format!("{k}={}", quote(v)))
            .collect();
        format!("env {} ", vars.join(" "))
    };
    let lines = [
        BEGIN.to_string(),
        "Host *.sbx".into(),
        "    User _default_user_".into(),
        format!("    ProxyCommand {env}{} ssh proxy %n", quote(bin)),
        "    IdentityFile /dev/null".into(),
        "    IdentitiesOnly yes".into(),
        "    ControlMaster no".into(),
        "    ControlPath none".into(),
        // The server is our own process on a pipe, so there is no host key worth checking.
        "    StrictHostKeyChecking no".into(),
        "    UserKnownHostsFile /dev/null".into(),
        "    LogLevel ERROR".into(),
        "Host *".into(),
        END.to_string(),
    ];
    lines.join("\n") + "\n"
}

/// `s` as one shell word (ssh runs the ProxyCommand through the user's shell), with `%` doubled so
/// ssh doesn't read it as a token.
fn quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''").replace('%', "%%"))
}

/// Whether `config` has an sbx block.
pub fn has_sbx_block(config: &str) -> bool {
    config.lines().any(|l| l.trim_end() == SBX_BEGIN)
}

/// Where our block is in `config`: the byte range of its lines, markers included.
fn find(config: &str) -> Result<Option<(usize, usize)>> {
    let mut start = None;
    let mut pos = 0;
    for line in config.split_inclusive('\n') {
        let end = pos + line.len();
        match (line.trim_end() == BEGIN, line.trim_end() == END, start) {
            (true, _, None) => start = Some(pos),
            (true, _, Some(_)) => bail!("{BEGIN} appears twice; fix the file by hand"),
            (_, true, Some(s)) => return Ok(Some((s, end))),
            (_, true, None) => bail!("{END} without {BEGIN}; fix the file by hand"),
            _ => {}
        }
        pos = end;
    }
    if start.is_some() {
        bail!("{BEGIN} without {END}; fix the file by hand");
    }
    Ok(None)
}

/// `config` with the block set to `block`: replaced where it is, else added at the top. Everything
/// outside the markers stays byte for byte.
pub fn upsert(config: &str, block: &str) -> Result<String> {
    Ok(match find(config)? {
        Some((s, e)) => format!("{}{block}{}", &config[..s], &config[e..]),
        None if config.is_empty() => block.to_string(),
        None => format!("{block}\n{config}"),
    })
}

/// `config` without the block (and the blank line that separated it), or `None` when there is
/// none.
pub fn remove(config: &str) -> Result<Option<String>> {
    let Some((s, mut e)) = find(config)? else {
        return Ok(None);
    };
    if config[e..].starts_with('\n') {
        e += 1;
    }
    Ok(Some(format!("{}{}", &config[..s], &config[e..])))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_proxy_command_sets_only_what_was_set_explicitly() {
        let env = |pairs: &[(&str, &str)]| -> Vec<(String, String)> {
            pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect()
        };
        assert!(render("/bin/sbt", &[]).contains("    ProxyCommand '/bin/sbt' ssh proxy %n\n"));
        let b = render(
            "/bin/sbt",
            &env(&[
                ("SMOLBENTO_SMOLVM", "/opt/s"),
                ("SMOLBENTO_SMOLVM_HOME", "/h/x"),
            ]),
        );
        assert!(
            b.contains(
                "    ProxyCommand env SMOLBENTO_SMOLVM='/opt/s' SMOLBENTO_SMOLVM_HOME='/h/x' \
                 '/bin/sbt' ssh proxy %n\n"
            ),
            "{b}"
        );
    }

    #[test]
    fn renders_sbxs_options_with_our_paths() {
        let b = render(
            "/bin/sbt",
            &[("SMOLBENTO_SMOLVM".to_string(), "/opt/smolvm".to_string())],
        );
        assert!(b.starts_with(&format!("{BEGIN}\nHost *.sbx\n")));
        assert!(!b.contains("IdentityAgent"), "{b}");
        for line in [
            "    User _default_user_",
            "    ProxyCommand env SMOLBENTO_SMOLVM='/opt/smolvm' '/bin/sbt' ssh proxy %n",
            "    IdentityFile /dev/null",
            "    IdentitiesOnly yes",
            "    ControlMaster no",
            "    ControlPath none",
            "    StrictHostKeyChecking no",
            "    UserKnownHostsFile /dev/null",
            "    LogLevel ERROR",
        ] {
            assert!(b.lines().any(|l| l == line), "missing {line}");
        }
        assert!(b.ends_with(&format!("Host *\n{END}\n")));
    }

    #[test]
    fn quotes_paths_for_the_shell_and_doubles_percent_signs() {
        assert!(render("/a b/sbt", &[]).contains("    ProxyCommand '/a b/sbt' ssh proxy %n\n"));
        let smolvm = [("SMOLBENTO_SMOLVM".to_string(), "/y z/smolvm".to_string())];
        assert!(render("/x/it's%/sbt", &smolvm).contains(
            "ProxyCommand env SMOLBENTO_SMOLVM='/y z/smolvm' '/x/it'\\''s%%/sbt' ssh proxy %n"
        ));
    }

    #[test]
    fn adds_at_the_top_and_keeps_the_rest() {
        let user = "ServerAliveInterval 5\n\nHost gh\n  User git\n";
        let out = upsert(user, &render("/bin/sbt", &[])).unwrap();
        assert!(out.starts_with(BEGIN));
        assert!(out.ends_with(&format!("{END}\n\n{user}")));
    }

    #[test]
    fn an_empty_file_gets_just_the_block() {
        assert_eq!(
            upsert("", &render("/bin/sbt", &[])).unwrap(),
            render("/bin/sbt", &[])
        );
    }

    #[test]
    fn replaces_in_place_and_is_idempotent() {
        let user = "Host a\n  User x\n";
        let once = upsert(user, &render("/bin/old", &[])).unwrap();
        let moved = format!("{user}\n{}", &once[..once.len() - user.len() - 1]);
        let twice = upsert(&moved, &render("/bin/sbt", &[])).unwrap();
        assert!(twice.starts_with(user));
        assert!(twice.contains("'/bin/sbt' ssh proxy"));
        assert!(!twice.contains("/bin/old"));
        assert_eq!(upsert(&twice, &render("/bin/sbt", &[])).unwrap(), twice);
    }

    #[test]
    fn remove_restores_the_original() {
        let user = "ServerAliveInterval 5\n\nHost gh\n  User git\n";
        let with = upsert(user, &render("/bin/sbt", &[])).unwrap();
        assert_eq!(remove(&with).unwrap().unwrap(), user);
        assert_eq!(remove(user).unwrap(), None);
        assert_eq!(remove(&render("/bin/sbt", &[])).unwrap().unwrap(), "");
    }

    #[test]
    fn a_broken_block_is_an_error_not_a_guess() {
        assert!(upsert(&format!("{BEGIN}\nHost x\n"), "b").is_err());
        assert!(remove(&format!("{END}\n")).is_err());
        assert!(find(&format!("{BEGIN}\n{BEGIN}\n{END}\n")).is_err());
    }

    #[test]
    fn spots_sbxs_block() {
        assert!(has_sbx_block(&format!("a\n{SBX_BEGIN}\nHost *.sbx\n")));
        assert!(!has_sbx_block(&render("/bin/sbt", &[])));
    }
}
