//! The egress process's per-flow verdict, from the user's `policy.toml`.

use crate::config::Paths;
use crate::policy::Policy;
use crate::policy::compile::{HOST_GATEWAY, decide};
use egress_front::{Decision, Flow};
use std::net::SocketAddr;

/// One sandbox's rules, read from `policy.toml` on every decision.
pub struct Rules {
    sandbox: String,
    host_access: bool,
    credential_hosts: Vec<String>,
    paths: Paths,
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
        }
    }

    /// The flow's decision and why, for the log.
    pub fn decide(&self, flow: &Flow) -> (Decision, String) {
        // `policy save` writes atomically, so a read never sees half a file.
        let policy = match Policy::load(&self.paths) {
            Ok(p) => p,
            Err(e) => return (Decision::Deny, format!("policy.toml unreadable: {e:#}")),
        };
        let verdict = |target: &str| {
            decide(
                &policy,
                &self.sandbox,
                &self.credential_hosts,
                self.host_access,
                target,
            )
        };
        let (allowed, reason) = if flow.ip.to_string() == HOST_GATEWAY {
            // A gateway flow is the host's `localhost:PORT`, judged strictly: no rule, no flow,
            // and the guest's name for it (any SNI or `Host:` it likes) plays no part.
            let g = verdict(&format!("localhost:{}", flow.port));
            (g.allowed, g.reason)
        } else {
            let v = verdict(&SocketAddr::new(flow.ip, flow.port).to_string());
            let n = flow
                .name
                .as_ref()
                .map(|name| verdict(&format!("{name}:{}", flow.port)));
            match n {
                // An IP or CIDR allow rule still admits a name no rule mentions; a deny always
                // wins. Allow-all and presets never reach here, as they would have allowed the
                // name.
                Some(n) if !n.allowed && !(n.implicit && v.allowed) => (false, n.reason),
                // By address, only a deny rule refuses: smolvm's allow list already admitted it.
                _ => (v.allowed || v.implicit, v.reason),
            }
        };
        let d = if allowed {
            Decision::Allow
        } else {
            Decision::Deny
        };
        (d, reason)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::test_paths;
    use crate::policy::Mode;
    use Decision::{Allow, Deny};

    const SB: &str = "sb";

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
            kind: egress_front::FlowKind::Other,
            ip: ip.parse().unwrap(),
            port,
        }
    }

    fn ask(r: &Rules, f: &Flow) -> Decision {
        r.decide(f).0
    }

    /// Sandbox rules, host access, then the flow's name, address and port, and its decision.
    type Case = (
        &'static [(bool, &'static str)],
        bool,
        Option<&'static str>,
        &'static str,
        u16,
        Decision,
    );

    #[test]
    fn rule_combinations() {
        const GH: &str = "140.82.1.1";
        let gw = HOST_GATEWAY;
        #[rustfmt::skip]
        let cases: &[Case] = &[
            // A port rule refuses other ports.
            (&[(true, "github.com:443")], false, Some("github.com"), GH, 443, Allow),
            (&[(true, "github.com:443")], false, Some("github.com"), GH, 80, Deny),
            // A host deny beats a wildcard allow.
            (&[(true, "**.github.com"), (false, "gist.github.com")], false, Some("api.github.com"), GH, 443, Allow),
            (&[(true, "**.github.com"), (false, "gist.github.com")], false, Some("gist.github.com"), GH, 443, Deny),
            // The gateway is localhost.
            (&[(true, "localhost:8080")], true, None, gw, 8080, Allow),
            (&[(true, "localhost:8080")], true, None, gw, 9090, Deny),
            // A gateway flow ignores its name.
            (&[(true, "localhost:8080"), (true, "github.com")], true, Some("github.com"), gw, 8080, Allow),
            (&[(true, "localhost:8080"), (true, "github.com")], true, Some("github.com"), gw, 9090, Deny),
            // Deny-all with no rules denies implicitly: a nameless flow keeps smolvm's admission,
            // a named one is refused.
            (&[], false, None, "203.0.113.5", 22, Allow),
            (&[], false, Some("example.com"), "203.0.113.5", 443, Deny),
            // A CIDR deny refuses a nameless flow, and an allowed name doesn't lift it.
            (&[(true, "**.example.com"), (false, "10.0.0.0/8")], false, None, "10.1.2.3", 443, Deny),
            (&[(true, "**.example.com"), (false, "10.0.0.0/8")], false, Some("api.example.com"), "10.1.2.3", 443, Deny),
            (&[(true, "**.example.com"), (false, "10.0.0.0/8")], false, None, "192.0.2.1", 443, Allow),
            // A CIDR allow admits a named flow to its range; outside it, the name alone decides.
            (&[(true, "10.0.0.0/8")], false, Some("gitlab.corp"), "10.1.2.3", 443, Allow),
            (&[(true, "10.0.0.0/8")], false, Some("gitlab.corp"), "192.0.2.1", 443, Deny),
            // A name deny beats a CIDR allow.
            (&[(true, "10.0.0.0/8"), (false, "gitlab.corp")], false, Some("gitlab.corp"), "10.1.2.3", 443, Deny),
            // A proxy CONNECT names its target, not the proxy, and the proxy's CIDR admits it.
            (&[(true, "10.9.9.0/24")], false, Some("example.com"), "10.9.9.9", 3128, Allow),
            // The gateway is closed without host access.
            (&[(true, "localhost:8080")], false, Some("localhost"), gw, 8080, Deny),
        ];
        for (rules, host_access, name, ip, port, want) in cases {
            let (_d, p) = test_paths();
            save(&p, rules);
            let r = Rules::new(&p, SB, *host_access, vec![]);
            let f = flow(*name, ip, *port);
            assert_eq!(
                ask(&r, &f),
                *want,
                "{rules:?} host_access={host_access} {f:?}"
            );
        }
    }

    #[test]
    fn a_host_deny_says_deny_rule() {
        let (_d, p) = test_paths();
        save(&p, &[(true, "**.github.com"), (false, "gist.github.com")]);
        let r = Rules::new(&p, SB, false, vec![]);
        let (d, why) = r.decide(&flow(Some("gist.github.com"), "140.82.1.1", 443));
        assert_eq!(d, Deny);
        assert!(why.contains("deny rule"), "{why}");
    }

    #[test]
    fn an_unreadable_policy_denies_then_recovers() {
        let (_d, p) = test_paths();
        std::fs::write(p.policy_file(), "mode = [garbage").unwrap();
        let r = Rules::new(&p, SB, false, vec![]);
        for f in [
            flow(None, "192.0.2.1", 443),
            flow(Some("a.com"), "192.0.2.1", 443),
        ] {
            let (d, why) = r.decide(&f);
            assert_eq!(d, Deny);
            assert!(why.starts_with("policy.toml unreadable: "), "{why}");
        }
        save(&p, &[(true, "github.com")]);
        assert_eq!(ask(&r, &flow(Some("github.com"), "140.82.1.1", 443)), Allow);
    }

    #[test]
    fn a_missing_policy_is_the_default() {
        let (_d, p) = test_paths();
        let r = Rules::new(&p, SB, false, vec![]);
        // No mode chosen yet: open, as before policies existed.
        assert_eq!(ask(&r, &flow(Some("example.com"), "192.0.2.1", 443)), Allow);
    }

    #[test]
    fn a_policy_change_applies_to_the_next_flow() {
        let (_d, p) = test_paths();
        save(&p, &[(true, "github.com")]);
        let r = Rules::new(&p, SB, false, vec![]);
        let f = flow(Some("github.com"), "140.82.1.1", 443);
        assert_eq!(ask(&r, &f), Allow);
        save(&p, &[(false, "github.com")]);
        assert_eq!(ask(&r, &f), Deny);
    }
}
