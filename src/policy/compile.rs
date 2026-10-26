//! Turns the policy into what smolvm enforces for one sandbox, and explains decisions.

use std::collections::BTreeSet;

use super::rules::{Allow, Pattern, Resource};
use super::{Decision, Mode, Policy, presets};
use crate::smolvm::{AllowList, NetworkSpec};

fn resources(policy: &Policy, sandbox: &str, decision: Decision) -> Vec<Resource> {
    policy
        .rules_for(sandbox)
        .into_iter()
        .filter(|(r, _)| r.decision == decision)
        .flat_map(|(r, _)| {
            r.resources
                .iter()
                .filter_map(|x| Resource::parse(x).ok())
                .collect::<Vec<_>>()
        })
        .collect()
}

/// An allow entry is dropped when a deny repeats it or matches its host.
fn denied(allow: &Resource, denies: &[Resource]) -> bool {
    denies.iter().any(|d| {
        d.raw.eq_ignore_ascii_case(&allow.raw)
            || match &allow.pattern {
                Pattern::Exact(h) | Pattern::Subdomains(h) => d.matches(h),
                _ => false,
            }
    })
}

/// What smolvm should allow for a sandbox. A bound credential's hosts are always included: smolvm
/// requires them.
pub fn network(policy: &Policy, sandbox: &str, credential_hosts: &[String]) -> NetworkSpec {
    let mode = policy.mode_for(sandbox);
    if mode == Mode::AllowAll {
        return NetworkSpec::Open;
    }
    let mut allows = if mode == Mode::Balanced {
        presets::balanced()
    } else {
        Vec::new()
    };
    allows.extend(resources(policy, sandbox, Decision::Allow));
    if allows.iter().any(|r| r.pattern == Pattern::Everything) {
        return NetworkSpec::Open;
    }
    let denies = resources(policy, sandbox, Decision::Deny);
    let (mut hosts, mut patterns, mut cidrs) = (BTreeSet::new(), BTreeSet::new(), BTreeSet::new());
    for r in allows.iter().filter(|r| !denied(r, &denies)) {
        match r.to_allow() {
            Allow::Host(h) => {
                hosts.insert(h);
            }
            Allow::Pattern(p) => {
                patterns.insert(p);
            }
            Allow::Cidr(c) => {
                cidrs.insert(c);
            }
            Allow::Everything => {}
        }
    }
    hosts.extend(credential_hosts.iter().cloned());
    NetworkSpec::Restricted(AllowList::new(hosts, patterns, cidrs))
}

/// Deny CIDRs for `machine create` (smolvm accepts them at create only), sorted and unique.
pub fn deny_cidrs(policy: &Policy, sandbox: &str) -> Vec<String> {
    resources(policy, sandbox, Decision::Deny)
        .into_iter()
        .filter_map(|r| match r.to_allow() {
            Allow::Cidr(c) => Some(c),
            _ => None,
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// Why a compiled network still lets `host` through, if it does (the way smolvm matches).
fn admits(spec: &NetworkSpec, host: &str, everything_rule: bool) -> Option<String> {
    let NetworkSpec::Restricted(list) = spec else {
        return Some(
            if everything_rule {
                "an allow-everything rule"
            } else {
                "allow-all mode"
            }
            .into(),
        );
    };
    let under = |d: &str| host.strip_suffix(d).is_some_and(|p| p.ends_with('.'));
    let entry = list
        .hosts()
        .iter()
        .find(|h| host == h.as_str() || under(h))
        .cloned()
        .or_else(|| {
            list.patterns()
                .iter()
                .find(|p| p.strip_prefix("*.").is_some_and(under))
                .cloned()
        })
        .or_else(|| {
            list.cidrs()
                .iter()
                .find(|c| Resource::parse(c).is_ok_and(|r| r.matches(host)))
                .cloned()
        })?;
    Some(format!("allow entry {entry}"))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub allowed: bool,
    pub reason: String,
}

fn verdict(allowed: bool, reason: impl Into<String>) -> Verdict {
    Verdict {
        allowed,
        reason: reason.into(),
    }
}

/// sbx semantics: bound secrets, then deny rules, then the mode, allow rules and the preset.
pub fn check(
    policy: &Policy,
    sandbox: Option<&str>,
    credential_hosts: &[String],
    target: &str,
) -> Verdict {
    let host = target.trim().to_ascii_lowercase();
    if credential_hosts
        .iter()
        .any(|h| h.to_ascii_lowercase() == host)
    {
        return verdict(true, "a secret bound to this sandbox uses this host");
    }
    // No sandbox: compile with the global rules only (an empty name has no per-sandbox entry).
    let (mode, rules) = match sandbox {
        Some(s) => (policy.mode_for(s), policy.rules_for(s)),
        None => (
            policy.mode.unwrap_or(Mode::AllowAll),
            policy
                .rules
                .iter()
                .map(|r| (r, "global".to_string()))
                .collect(),
        ),
    };
    let hit = |decision: Decision| {
        rules.iter().find_map(|(r, scope)| {
            if r.decision != decision {
                return None;
            }
            r.resources
                .iter()
                .filter_map(|x| Resource::parse(x).ok())
                .find(|res| res.matches(&host))
                .map(|res| (r, scope, res))
        })
    };
    if let Some((r, scope, res)) = hit(Decision::Deny) {
        let text = format!("deny rule {} ({scope})", r.id);
        if matches!(res.pattern, Pattern::Cidr { .. }) {
            return verdict(false, text);
        }
        // smolvm has no host deny: a host deny only removes allow entries.
        let spec = network(policy, sandbox.unwrap_or(""), credential_hosts);
        let everything = mode != Mode::AllowAll;
        return match admits(&spec, &host, everything) {
            Some(why) => verdict(
                true,
                format!("{text} isn't enforced: smolvm still allows it via {why}"),
            ),
            None => verdict(false, text),
        };
    }
    if mode == Mode::AllowAll {
        let why = if policy.mode.is_none() {
            "no policy chosen yet (open)"
        } else {
            "allow-all mode"
        };
        return verdict(true, why);
    }
    if let Some((r, scope, _)) = hit(Decision::Allow) {
        return verdict(true, format!("allow rule {} ({scope})", r.id));
    }
    if mode == Mode::Balanced
        && let Some(group) = presets::group_for(&host)
    {
        return verdict(true, format!("balanced preset ({group})"));
    }
    verdict(false, format!("no rule allows it ({} mode)", mode.name()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{Decision, Mode, Policy};
    use crate::smolvm::NetworkSpec;

    fn policy(mode: Mode) -> Policy {
        Policy {
            mode: Some(mode),
            ..Default::default()
        }
    }

    fn list(spec: &NetworkSpec) -> &crate::smolvm::AllowList {
        match spec {
            NetworkSpec::Restricted(l) => l,
            NetworkSpec::Open => panic!("expected a restricted list"),
        }
    }

    #[test]
    fn allow_all_and_unchosen_are_open() {
        assert_eq!(network(&Policy::default(), "s1", &[]), NetworkSpec::Open);
        assert_eq!(
            network(&policy(Mode::AllowAll), "s1", &[]),
            NetworkSpec::Open
        );
    }

    #[test]
    fn deny_all_is_loopback_plus_rules_and_credentials() {
        let mut p = policy(Mode::DenyAll);
        p.add_rule(
            Some("s1"),
            Decision::Allow,
            "*.npmjs.org",
            "added",
            None,
            None,
        )
        .unwrap();
        let spec = network(&p, "s1", &["api.anthropic.com".to_string()]);
        let l = list(&spec);
        assert_eq!(l.hosts(), ["api.anthropic.com"]);
        assert_eq!(l.patterns(), ["*.npmjs.org"]);
        assert_eq!(l.cidrs(), ["127.0.0.0/8", "::1/128"]);
        assert_eq!(list(&network(&p, "other", &[])).hosts().len(), 0);
    }

    #[test]
    fn balanced_has_the_preset_and_widens_globs() {
        let spec = network(&policy(Mode::Balanced), "s1", &[]);
        let l = list(&spec);
        assert!(l.hosts().contains(&"registry.npmjs.org".to_string()));
        assert!(
            l.hosts().contains(&"openai.com".to_string()),
            "**.openai.com -> openai.com"
        );
        assert!(l.patterns().contains(&"*.digicert.com".to_string()));
        assert!(!l.hosts().contains(&"example.com".to_string()));
    }

    #[test]
    fn deny_rules_subtract_and_sandbox_deny_network_wins() {
        let mut p = policy(Mode::Balanced);
        p.add_rule(
            None,
            Decision::Deny,
            "registry.npmjs.org",
            "added",
            None,
            None,
        )
        .unwrap();
        assert!(
            !list(&network(&p, "s1", &[]))
                .hosts()
                .contains(&"registry.npmjs.org".to_string())
        );
        p.set_deny_network("s2", true);
        assert_eq!(list(&network(&p, "s2", &[])).hosts().len(), 0);
    }

    #[test]
    fn everything_rule_opens() {
        let mut p = policy(Mode::DenyAll);
        p.add_rule(None, Decision::Allow, "**", "added", None, None)
            .unwrap();
        assert_eq!(network(&p, "s1", &[]), NetworkSpec::Open);
    }

    #[test]
    fn deny_cidrs_for_create() {
        let mut p = policy(Mode::AllowAll);
        p.add_rule(
            None,
            Decision::Deny,
            "10.0.0.0/8, bad.com",
            "added",
            None,
            None,
        )
        .unwrap();
        p.add_rule(
            Some("s1"),
            Decision::Deny,
            "192.168.0.0/16",
            "added",
            None,
            None,
        )
        .unwrap();
        assert_eq!(deny_cidrs(&p, "s1"), vec!["10.0.0.0/8", "192.168.0.0/16"]);
        p.add_rule(
            Some("s1"),
            Decision::Deny,
            "10.0.0.0/8",
            "again",
            None,
            None,
        )
        .unwrap();
        assert_eq!(deny_cidrs(&p, "s1"), vec!["10.0.0.0/8", "192.168.0.0/16"]);
        assert_eq!(deny_cidrs(&p, "s2"), vec!["10.0.0.0/8"]);
    }

    #[test]
    fn check_explains() {
        let mut p = policy(Mode::Balanced);
        let deny = p
            .add_rule(None, Decision::Deny, "evil.com", "added", None, None)
            .unwrap();
        let allow = p
            .add_rule(
                Some("s1"),
                Decision::Allow,
                "api.x.com",
                "added",
                None,
                None,
            )
            .unwrap();
        let v = check(&p, Some("s1"), &[], "evil.com");
        assert!(!v.allowed && v.reason.contains(&deny), "{}", v.reason);
        let v = check(&p, Some("s1"), &[], "api.x.com");
        assert!(v.allowed && v.reason.contains(&allow), "{}", v.reason);
        assert!(
            check(&p, Some("s1"), &[], "pypi.org")
                .reason
                .contains("default-package-managers")
        );
        assert!(!check(&p, None, &[], "example.com").allowed);
        let v = check(&p, Some("s1"), &["example.com".into()], "example.com");
        assert!(v.allowed && v.reason.contains("secret"), "{}", v.reason);
        assert!(check(&Policy::default(), None, &[], "example.com").allowed);
    }

    #[test]
    fn check_reports_what_is_enforced() {
        let mut p = policy(Mode::AllowAll);
        p.add_rule(None, Decision::Deny, "evil.com", "added", None, None)
            .unwrap();
        p.add_rule(None, Decision::Deny, "10.0.0.0/8", "added", None, None)
            .unwrap();
        let v = check(&p, Some("s1"), &[], "evil.com");
        assert!(
            v.allowed && v.reason.contains("isn't enforced") && v.reason.contains("allow-all"),
            "{}",
            v.reason
        );
        let v = check(&p, Some("s1"), &[], "10.1.2.3");
        assert!(!v.allowed && v.reason.contains("deny rule"), "{}", v.reason);

        let mut p = policy(Mode::Balanced);
        p.add_rule(None, Decision::Deny, "api.openai.com", "added", None, None)
            .unwrap();
        let v = check(&p, Some("s1"), &[], "api.openai.com");
        assert!(
            v.allowed && v.reason.contains("isn't enforced") && v.reason.contains("openai.com"),
            "{}",
            v.reason
        );

        let mut p = policy(Mode::DenyAll);
        p.add_rule(None, Decision::Allow, "**", "added", None, None)
            .unwrap();
        p.add_rule(None, Decision::Deny, "evil.com", "added", None, None)
            .unwrap();
        let v = check(&p, None, &[], "evil.com");
        assert!(
            v.allowed && v.reason.contains("allow-everything"),
            "{}",
            v.reason
        );
    }

    #[test]
    fn credential_hosts_match_case_insensitively() {
        let v = check(
            &policy(Mode::DenyAll),
            Some("s1"),
            &["API.Example.com".into()],
            "api.example.COM",
        );
        assert!(v.allowed && v.reason.contains("secret"), "{}", v.reason);
    }
}
