//! The variables sbx sets in every sandbox (measured: `docs/sbx-compatibility.md`).

use std::collections::BTreeMap;

use super::CreateRequest;
use crate::util::env_default;

/// A random (v4) UUID.
pub fn new_uuid() -> String {
    let mut b: [u8; 16] = rand::random();
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h = crate::util::hex(&b);
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

/// The sandbox variables for `req` (after its secrets are bound), with `id` as `SANDBOX_ID`.
/// `services` are those its kits declare a credential for: each gets `SBX_CRED_<SVC>_MODE`,
/// `apikey` when the service's secret is bound, else `none` (sbx 0.53: `claude` gets anthropic's,
/// `shell` none). Never a secret value.
pub fn defaults(req: &CreateRequest, id: &str, services: &[String]) -> Vec<(String, String)> {
    let mut env = vec![
        ("SANDBOX_NAME".to_string(), req.name.clone()),
        ("SANDBOX_VM_ID".to_string(), req.name.clone()),
        ("SANDBOX_ID".to_string(), id.to_string()),
        ("WORKSPACE_DIR".to_string(), req.workdir()),
        ("SBX_AGENT".to_string(), req.agent.clone()),
    ];
    for svc in services {
        let mode = if req.rec.secrets.contains(svc) {
            "apikey"
        } else {
            "none"
        };
        env.push((
            format!(
                "SBX_CRED_{}_MODE",
                svc.to_ascii_uppercase().replace('-', "_")
            ),
            mode.into(),
        ));
    }
    env
}

/// Adds the defaults to `req.env`, behind anything already there (the user's `-e` wins).
pub fn apply(req: &mut CreateRequest, services: &[String]) {
    for (k, v) in defaults(req, &new_uuid(), services) {
        env_default(&mut req.env, &k, v);
    }
}

/// What a TTY session takes from the host, as sbx: `TZ` (sbx also derives one when unset; we
/// don't) and the terminal's identity, which agents read to print clickable (OSC 8) links.
const TTY_HOST_VARS: [&str; 4] = ["TZ", "TERM_PROGRAM", "TERM_PROGRAM_VERSION", "COLORTERM"];

/// Adds a session's variables to `env`, never over one it already sets (`-e` wins): the host's
/// `TTY_HOST_VARS` on a TTY, and, in a sandbox with the browser bridge, `BROWSER=xdg-open`.
/// Without a `DISPLAY` a Linux agent assumes it has no browser and only prints the URL; `BROWSER`
/// makes it call the bridge's `xdg-open` (sbx sets `WAYLAND_DISPLAY` for its compositor instead).
pub fn session_env(
    host: &BTreeMap<String, String>,
    tty: bool,
    bridge: bool,
    env: &mut Vec<(String, String)>,
) {
    if tty {
        for k in TTY_HOST_VARS {
            if let Some(v) = host.get(k).filter(|v| !v.is_empty()) {
                env_default(env, k, v);
            }
        }
    }
    if bridge {
        env_default(env, "BROWSER", "xdg-open");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::Recorded;
    use crate::workspace::Workspace;

    fn req(agent: &str, secrets: &[&str]) -> CreateRequest {
        CreateRequest {
            rec: Recorded {
                secrets: secrets.iter().map(|s| s.to_string()).collect(),
                ..Default::default()
            },
            name: "my-sb".into(),
            agent: agent.into(),
            workspaces: vec![Workspace {
                path: "/w/repo".into(),
                read_only: false,
            }],
            ..Default::default()
        }
    }

    fn get<'a>(env: &'a [(String, String)], k: &str) -> Option<&'a str> {
        env.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str())
    }

    fn svcs(names: &[&str]) -> Vec<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn identity_and_the_kits_credential_modes() {
        let env = defaults(&req("claude", &["anthropic"]), "ID", &svcs(&["anthropic"]));
        assert_eq!(get(&env, "SANDBOX_NAME"), Some("my-sb"));
        assert_eq!(get(&env, "SANDBOX_VM_ID"), Some("my-sb"));
        assert_eq!(get(&env, "SANDBOX_ID"), Some("ID"));
        assert_eq!(get(&env, "WORKSPACE_DIR"), Some("/w/repo"));
        assert_eq!(get(&env, "SBX_AGENT"), Some("claude"));
        assert_eq!(get(&env, "SBX_CRED_ANTHROPIC_MODE"), Some("apikey"));
        assert_eq!(get(&env, "SBX_CRED_OPENAI_MODE"), None);
        // sbx 0.53's claude image sets it in its own environment.
        assert_eq!(get(&env, "IS_SANDBOX"), None);
    }

    #[test]
    fn modes_follow_the_kits_credentials() {
        let env = defaults(
            &req("tool", &["anthropic", "github"]),
            "ID",
            &svcs(&["anthropic", "openai"]),
        );
        assert_eq!(get(&env, "SBX_CRED_ANTHROPIC_MODE"), Some("apikey"));
        assert_eq!(get(&env, "SBX_CRED_OPENAI_MODE"), Some("none"));
        // A bound secret no kit asks for gets no mode.
        assert_eq!(get(&env, "SBX_CRED_GITHUB_MODE"), None);
        // A custom service's `-` isn't valid in a shell variable name: it becomes `_`.
        let env = defaults(&req("tool", &["my-api"]), "ID", &svcs(&["my-api"]));
        assert_eq!(get(&env, "SBX_CRED_MY_API_MODE"), Some("apikey"));
        // No credential in any kit (sbx 0.53's shell): no modes at all.
        let env = defaults(&req("shell", &["github"]), "ID", &[]);
        assert!(
            env.iter().all(|(k, _)| !k.starts_with("SBX_CRED_")),
            "{env:?}"
        );
    }

    #[test]
    fn mountless_sandboxes_get_the_mountless_workdir() {
        let mut r = req("mykit", &[]);
        r.workspaces.clear();
        let env = defaults(&r, "ID", &[]);
        assert_eq!(get(&env, "SBX_AGENT"), Some("mykit"));
        assert_eq!(
            get(&env, "WORKSPACE_DIR"),
            Some(crate::workspace::MOUNTLESS_WORKDIR)
        );
    }

    #[test]
    fn user_env_wins_and_values_are_never_secrets() {
        let mut r = req("claude", &["anthropic"]);
        r.env = vec![("SBX_AGENT".into(), "mine".into())];
        apply(&mut r, &svcs(&["anthropic"]));
        assert_eq!(get(&r.env, "SBX_AGENT"), Some("mine"));
        assert_eq!(r.env.iter().filter(|(k, _)| k == "SBX_AGENT").count(), 1);
        assert!(get(&r.env, "SANDBOX_ID").is_some());
    }

    #[test]
    fn uuid_is_v4() {
        let a = new_uuid();
        assert_eq!(a.len(), 36);
        assert_eq!(&a[14..15], "4");
        assert!("89ab".contains(&a[19..20]));
        assert_ne!(a, new_uuid());
    }

    fn vars(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn tz_only_on_a_tty_with_host_tz() {
        let host: BTreeMap<_, _> = [("TZ".to_string(), "Asia/Kolkata".to_string())].into();
        let mut e = Vec::new();
        session_env(&host, false, false, &mut e);
        assert!(e.is_empty());
        session_env(&BTreeMap::new(), true, false, &mut e);
        assert!(e.is_empty());
        session_env(&host, true, false, &mut e);
        assert_eq!(e, vars(&[("TZ", "Asia/Kolkata")]));
        session_env(&host, true, false, &mut e);
        assert_eq!(e.len(), 1);
    }

    #[test]
    fn a_tty_session_gets_the_host_terminal_so_links_are_clickable() {
        let host: BTreeMap<_, _> = [
            ("TERM_PROGRAM", "iTerm.app"),
            ("TERM_PROGRAM_VERSION", "3.5.0"),
            ("COLORTERM", "truecolor"),
            ("LC_TERMINAL", "iTerm2"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        let mut e = Vec::new();
        session_env(&host, false, false, &mut e);
        assert!(e.is_empty(), "{e:?}");
        session_env(&host, true, false, &mut e);
        assert_eq!(
            e,
            vars(&[
                ("TERM_PROGRAM", "iTerm.app"),
                ("TERM_PROGRAM_VERSION", "3.5.0"),
                ("COLORTERM", "truecolor"),
            ])
        );
        // `-e` wins over the host's value.
        let mut e = vars(&[("COLORTERM", "256")]);
        session_env(&host, true, false, &mut e);
        assert_eq!(e.iter().filter(|(k, _)| k == "COLORTERM").count(), 1);
        assert!(e.contains(&("COLORTERM".into(), "256".into())));
    }

    #[test]
    fn a_bridged_sandbox_points_browser_at_the_shim() {
        let mut e = Vec::new();
        session_env(&BTreeMap::new(), false, true, &mut e);
        assert_eq!(e, vars(&[("BROWSER", "xdg-open")]));
        let mut e = Vec::new();
        session_env(&BTreeMap::new(), true, false, &mut e);
        assert!(e.is_empty(), "no bridge, no BROWSER: {e:?}");
        let mut e = vars(&[("BROWSER", "w3m")]);
        session_env(&BTreeMap::new(), true, true, &mut e);
        assert_eq!(e, vars(&[("BROWSER", "w3m")]));
    }
}
