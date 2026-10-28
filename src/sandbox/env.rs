//! The variables sbx sets in every sandbox (measured: `docs/sbx-compatibility.md`).

use std::collections::BTreeMap;

use anyhow::{Context, Result};

use super::CreateRequest;

/// `SBX_CRED_<SVC>_MODE` services by agent preset, as sbx sets them: `shell` all eight, `claude`
/// only anthropic. Other presets aren't measured and get none; kits get none, whatever their name.
fn credential_services(agent: &str) -> &'static [&'static str] {
    match agent {
        "shell" => &[
            "anthropic",
            "github",
            "google",
            "mistral",
            "nebius",
            "openai",
            "openrouter",
            "xai",
        ],
        "claude" => &["anthropic"],
        _ => &[],
    }
}

/// A random (v4) UUID.
pub fn new_uuid() -> Result<String> {
    use std::io::Read;
    let mut b = [0u8; 16];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut b))
        .context("reading /dev/urandom for the sandbox id")?;
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    ))
}

/// The sandbox variables for `req` (after its secrets are bound), with `id` as `SANDBOX_ID`.
/// `preset`: the workload is the agent preset `req.agent`, not a kit; only presets get the
/// credential modes and `IS_SANDBOX`. Never a secret value: a mode is `apikey` (the service's
/// secret is bound) or `none`.
pub fn defaults(req: &CreateRequest, id: &str, preset: bool) -> Vec<(String, String)> {
    let mut env = vec![
        ("SANDBOX_NAME".to_string(), req.name.clone()),
        ("SANDBOX_VM_ID".to_string(), req.name.clone()),
        ("SANDBOX_ID".to_string(), id.to_string()),
        ("WORKSPACE_DIR".to_string(), req.workdir()),
        ("SBX_AGENT".to_string(), req.agent.clone()),
    ];
    let agent = if preset { req.agent.as_str() } else { "" };
    for svc in credential_services(agent) {
        let mode = if req.secrets.iter().any(|s| s == svc) {
            "apikey"
        } else {
            "none"
        };
        env.push((
            format!("SBX_CRED_{}_MODE", svc.to_ascii_uppercase()),
            mode.into(),
        ));
    }
    if agent == "claude" {
        env.push(("IS_SANDBOX".into(), "1".into()));
    }
    env
}

/// Adds the defaults to `req.env`, behind anything already there (the user's `-e` wins).
pub fn apply(req: &mut CreateRequest, preset: bool) -> Result<()> {
    let id = new_uuid()?;
    for (k, v) in defaults(req, &id, preset) {
        if !req.env.iter().any(|(n, _)| *n == k) {
            req.env.push((k, v));
        }
    }
    Ok(())
}

/// A TTY session gets the host's `TZ`, if set (sbx also derives one when unset; we don't).
pub fn session_tz(host: &BTreeMap<String, String>, tty: bool, env: &mut Vec<(String, String)>) {
    if !tty || env.iter().any(|(k, _)| k == "TZ") {
        return;
    }
    if let Some(tz) = host.get("TZ").filter(|v| !v.is_empty()) {
        env.push(("TZ".into(), tz.clone()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workspace::Workspace;

    fn req(agent: &str, secrets: &[&str]) -> CreateRequest {
        CreateRequest {
            name: "my-sb".into(),
            agent: agent.into(),
            workspaces: vec![Workspace {
                path: "/w/repo".into(),
                read_only: false,
            }],
            secrets: secrets.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    fn get<'a>(env: &'a [(String, String)], k: &str) -> Option<&'a str> {
        env.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str())
    }

    #[test]
    fn claude_gets_identity_one_mode_and_is_sandbox() {
        let env = defaults(&req("claude", &["anthropic"]), "ID", true);
        assert_eq!(get(&env, "SANDBOX_NAME"), Some("my-sb"));
        assert_eq!(get(&env, "SANDBOX_VM_ID"), Some("my-sb"));
        assert_eq!(get(&env, "SANDBOX_ID"), Some("ID"));
        assert_eq!(get(&env, "WORKSPACE_DIR"), Some("/w/repo"));
        assert_eq!(get(&env, "SBX_AGENT"), Some("claude"));
        assert_eq!(get(&env, "SBX_CRED_ANTHROPIC_MODE"), Some("apikey"));
        assert_eq!(get(&env, "SBX_CRED_OPENAI_MODE"), None);
        assert_eq!(get(&env, "IS_SANDBOX"), Some("1"));
    }

    #[test]
    fn shell_gets_all_eight_modes_none_without_secrets() {
        let env = defaults(&req("shell", &["github"]), "ID", true);
        let modes: Vec<_> = env
            .iter()
            .filter(|(k, _)| k.starts_with("SBX_CRED_"))
            .collect();
        assert_eq!(modes.len(), 8);
        assert_eq!(get(&env, "SBX_CRED_GITHUB_MODE"), Some("apikey"));
        assert_eq!(get(&env, "SBX_CRED_XAI_MODE"), Some("none"));
        assert_eq!(get(&env, "IS_SANDBOX"), None);
    }

    #[test]
    fn kits_and_mountless_sandboxes() {
        let mut r = req("mykit", &["anthropic"]);
        r.workspaces.clear();
        let env = defaults(&r, "ID", false);
        assert!(env.iter().all(|(k, _)| !k.starts_with("SBX_CRED_")));
        assert_eq!(get(&env, "SBX_AGENT"), Some("mykit"));
        assert_eq!(
            get(&env, "WORKSPACE_DIR"),
            Some(crate::workspace::MOUNTLESS_WORKDIR)
        );
    }

    #[test]
    fn a_kit_named_like_a_preset_gets_no_preset_variables() {
        for agent in ["claude", "shell"] {
            let env = defaults(&req(agent, &["anthropic"]), "ID", false);
            assert!(
                env.iter().all(|(k, _)| !k.starts_with("SBX_CRED_")),
                "{env:?}"
            );
            assert_eq!(get(&env, "IS_SANDBOX"), None);
            assert_eq!(get(&env, "SBX_AGENT"), Some(agent));
        }
    }

    #[test]
    fn user_env_wins_and_values_are_never_secrets() {
        let mut r = req("claude", &["anthropic"]);
        r.env = vec![("SBX_AGENT".into(), "mine".into())];
        apply(&mut r, true).unwrap();
        assert_eq!(get(&r.env, "SBX_AGENT"), Some("mine"));
        assert_eq!(r.env.iter().filter(|(k, _)| k == "SBX_AGENT").count(), 1);
        assert!(get(&r.env, "SANDBOX_ID").is_some());
    }

    #[test]
    fn uuid_is_v4() {
        let a = new_uuid().unwrap();
        assert_eq!(a.len(), 36);
        assert_eq!(&a[14..15], "4");
        assert!("89ab".contains(&a[19..20]));
        assert_ne!(a, new_uuid().unwrap());
    }

    #[test]
    fn tz_only_on_a_tty_with_host_tz() {
        let host: BTreeMap<_, _> = [("TZ".to_string(), "Asia/Kolkata".to_string())].into();
        let mut e = Vec::new();
        session_tz(&host, false, &mut e);
        assert!(e.is_empty());
        session_tz(&BTreeMap::new(), true, &mut e);
        assert!(e.is_empty());
        session_tz(&host, true, &mut e);
        assert_eq!(e, vec![("TZ".to_string(), "Asia/Kolkata".to_string())]);
        session_tz(&host, true, &mut e);
        assert_eq!(e.len(), 1);
    }
}
