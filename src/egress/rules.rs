//! The egress process's per-flow verdict, from the user's `policy.toml`.

use crate::config::Paths;
use crate::policy::Policy;
use crate::policy::compile::{HOST_GATEWAY, decide};
use egress_front::{Decision, Flow};
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::SystemTime;

/// `policy.toml`'s mtime (`None`: no file) and what loading it gave.
type Loaded = (Option<SystemTime>, Result<Policy, String>);

/// One sandbox's rules, reloaded whenever `policy.toml`'s mtime changes.
pub struct Rules {
    sandbox: String,
    host_access: bool,
    credential_hosts: Vec<String>,
    paths: Paths,
    loaded: Mutex<Option<Loaded>>,
}

impl Rules {
    pub fn new(
        paths: &Paths,
        sandbox: &str,
        host_access: bool,
        credential_hosts: Vec<String>,
    ) -> Rules {
        Rules {
            sandbox: sandbox.to_string(),
            host_access,
            credential_hosts,
            paths: paths.clone(),
            loaded: Mutex::new(None),
        }
    }

    /// The flow's decision and why, for the log.
    pub fn decide(&self, flow: &Flow) -> (Decision, String) {
        let mut loaded = self.loaded.lock().unwrap_or_else(|e| e.into_inner());
        let mtime = match std::fs::metadata(self.paths.policy_file()).and_then(|m| m.modified()) {
            Ok(t) => Some(t),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => {
                *loaded = None;
                return (Decision::Deny, format!("policy.toml unreadable: {e}"));
            }
        };
        let fresh = loaded.take().filter(|(t, _)| *t == mtime);
        let (_, policy) = loaded.insert(fresh.unwrap_or_else(|| {
            (
                mtime,
                Policy::load(&self.paths).map_err(|e| format!("{e:#}")),
            )
        }));
        let policy = match policy {
            Ok(p) => &*p,
            Err(e) => return (Decision::Deny, format!("policy.toml unreadable: {e}")),
        };
        let verdict = |target: &str| {
            decide(
                policy,
                &self.sandbox,
                &self.credential_hosts,
                self.host_access,
                target,
            )
        };
        // A gateway flow is the host's `localhost:PORT`, judged strictly: no rule, no flow, and the
        // guest's name for it (any SNI or `Host:` it likes) plays no part.
        if flow.ip.to_string() == HOST_GATEWAY {
            let v = verdict(&format!("localhost:{}", flow.port));
            let d = if v.allowed {
                Decision::Allow
            } else {
                Decision::Deny
            };
            return (d, v.reason);
        }
        let addr = SocketAddr::new(flow.ip, flow.port).to_string();
        if let Some(name) = &flow.name {
            let v = verdict(&format!("{name}:{}", flow.port));
            if !v.allowed {
                return (Decision::Deny, v.reason);
            }
        }
        // By address, only a deny rule refuses: smolvm's allow list already admitted the flow.
        let v = verdict(&addr);
        if v.allowed || v.implicit {
            return (Decision::Allow, v.reason);
        }
        (Decision::Deny, v.reason)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Mode;
    use std::collections::BTreeMap;
    use std::time::Duration;

    const SB: &str = "sb";

    fn paths(dir: &std::path::Path) -> Paths {
        let e: BTreeMap<String, String> = [
            ("SMOLBENTO_CONFIG_DIR", dir.to_str().unwrap()),
            ("SMOLBENTO_CACHE_DIR", "/k"),
            ("SMOLBENTO_DATA_DIR", "/d"),
        ]
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .into();
        Paths::from_env(&e).unwrap()
    }

    /// Saves a deny-all policy with these `(allow?, resource)` sandbox rules.
    fn save(p: &Paths, rules: &[(bool, &str)]) {
        let mut policy = Policy {
            mode: Some(Mode::DenyAll),
            ..Policy::default()
        };
        for (allow, res) in rules {
            if *allow {
                policy.allow(Some(SB), res);
            } else {
                policy.deny(Some(SB), res);
            }
        }
        policy.save(p).unwrap();
    }

    fn flow(name: Option<&str>, ip: &str, port: u16) -> Flow {
        Flow {
            name: name.map(String::from),
            ip: ip.parse().unwrap(),
            port,
        }
    }

    fn ask(r: &Rules, f: &Flow) -> Decision {
        r.decide(f).0
    }

    /// Moves `policy.toml`'s mtime forward, so a rewrite within the clock's granularity is seen.
    fn touch_later(p: &Paths, secs: u64) {
        let f = std::fs::File::options()
            .write(true)
            .open(p.policy_file())
            .unwrap();
        f.set_modified(SystemTime::now() + Duration::from_secs(secs))
            .unwrap();
    }

    #[test]
    fn a_port_rule_refuses_other_ports() {
        let d = tempfile::tempdir().unwrap();
        let p = paths(d.path());
        save(&p, &[(true, "github.com:443")]);
        let r = Rules::new(&p, SB, false, vec![]);
        assert_eq!(
            ask(&r, &flow(Some("github.com"), "140.82.1.1", 443)),
            Decision::Allow
        );
        assert_eq!(
            ask(&r, &flow(Some("github.com"), "140.82.1.1", 80)),
            Decision::Deny
        );
    }

    #[test]
    fn a_host_deny_beats_a_wildcard_allow() {
        let d = tempfile::tempdir().unwrap();
        let p = paths(d.path());
        save(&p, &[(true, "**.github.com"), (false, "gist.github.com")]);
        let r = Rules::new(&p, SB, false, vec![]);
        assert_eq!(
            ask(&r, &flow(Some("api.github.com"), "140.82.1.1", 443)),
            Decision::Allow
        );
        let (d, why) = r.decide(&flow(Some("gist.github.com"), "140.82.1.1", 443));
        assert_eq!(d, Decision::Deny);
        assert!(why.contains("deny rule"), "{why}");
    }

    #[test]
    fn the_gateway_is_localhost() {
        let d = tempfile::tempdir().unwrap();
        let p = paths(d.path());
        save(&p, &[(true, "localhost:8080")]);
        let r = Rules::new(&p, SB, true, vec![]);
        assert_eq!(ask(&r, &flow(None, HOST_GATEWAY, 8080)), Decision::Allow);
        assert_eq!(ask(&r, &flow(None, HOST_GATEWAY, 9090)), Decision::Deny);
    }

    #[test]
    fn a_gateway_flow_ignores_its_name() {
        let d = tempfile::tempdir().unwrap();
        let p = paths(d.path());
        save(&p, &[(true, "localhost:8080"), (true, "github.com")]);
        let r = Rules::new(&p, SB, true, vec![]);
        let gh = |port| flow(Some("github.com"), HOST_GATEWAY, port);
        assert_eq!(ask(&r, &gh(8080)), Decision::Allow);
        assert_eq!(ask(&r, &gh(9090)), Decision::Deny);
    }

    #[test]
    fn a_nameless_flow_keeps_smolvms_decision() {
        let d = tempfile::tempdir().unwrap();
        let p = paths(d.path());
        save(&p, &[]);
        let r = Rules::new(&p, SB, false, vec![]);
        // Deny-all with no rules denies implicitly; smolvm already admitted the flow.
        assert_eq!(ask(&r, &flow(None, "203.0.113.5", 22)), Decision::Allow);
        assert_eq!(
            ask(&r, &flow(Some("example.com"), "203.0.113.5", 443)),
            Decision::Deny
        );
    }

    #[test]
    fn a_cidr_deny_refuses_a_nameless_flow() {
        let d = tempfile::tempdir().unwrap();
        let p = paths(d.path());
        save(&p, &[(true, "**.example.com"), (false, "10.0.0.0/8")]);
        let r = Rules::new(&p, SB, false, vec![]);
        assert_eq!(ask(&r, &flow(None, "10.1.2.3", 443)), Decision::Deny);
        // An allowed name doesn't lift an explicit address deny.
        assert_eq!(
            ask(&r, &flow(Some("api.example.com"), "10.1.2.3", 443)),
            Decision::Deny
        );
        assert_eq!(ask(&r, &flow(None, "192.0.2.1", 443)), Decision::Allow);
    }

    #[test]
    fn the_gateway_is_closed_without_host_access() {
        let d = tempfile::tempdir().unwrap();
        let p = paths(d.path());
        save(&p, &[(true, "localhost:8080")]);
        let r = Rules::new(&p, SB, false, vec![]);
        assert_eq!(
            ask(&r, &flow(Some("localhost"), HOST_GATEWAY, 8080)),
            Decision::Deny
        );
    }

    #[test]
    fn an_unreadable_policy_denies_then_recovers() {
        let d = tempfile::tempdir().unwrap();
        let p = paths(d.path());
        std::fs::write(p.policy_file(), "mode = [garbage").unwrap();
        let r = Rules::new(&p, SB, false, vec![]);
        for f in [
            flow(None, "192.0.2.1", 443),
            flow(Some("a.com"), "192.0.2.1", 443),
        ] {
            let (d, why) = r.decide(&f);
            assert_eq!(d, Decision::Deny);
            assert!(why.starts_with("policy.toml unreadable: "), "{why}");
        }
        save(&p, &[(true, "github.com")]);
        touch_later(&p, 10);
        assert_eq!(
            ask(&r, &flow(Some("github.com"), "140.82.1.1", 443)),
            Decision::Allow
        );
    }

    #[test]
    fn a_missing_policy_is_the_default() {
        let d = tempfile::tempdir().unwrap();
        let r = Rules::new(&paths(d.path()), SB, false, vec![]);
        // No mode chosen yet: open, as before policies existed.
        assert_eq!(
            ask(&r, &flow(Some("example.com"), "192.0.2.1", 443)),
            Decision::Allow
        );
    }

    #[test]
    fn a_policy_change_applies_to_the_next_flow() {
        let d = tempfile::tempdir().unwrap();
        let p = paths(d.path());
        save(&p, &[(true, "github.com")]);
        let r = Rules::new(&p, SB, false, vec![]);
        let f = flow(Some("github.com"), "140.82.1.1", 443);
        assert_eq!(ask(&r, &f), Decision::Allow);
        save(&p, &[(false, "github.com")]);
        touch_later(&p, 10);
        assert_eq!(ask(&r, &f), Decision::Deny);
    }
}
