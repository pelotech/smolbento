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

/// The patterns smolvm gets in deny-all mode for these global allows and denies.
fn patterns(allows: &str, denies: &str) -> Vec<String> {
    let mut p = policy(Mode::DenyAll);
    p.add_rule(None, Decision::Allow, allows, "added", None, None)
        .unwrap();
    p.add_rule(None, Decision::Deny, denies, "added", None, None)
        .unwrap();
    list(&network(&p, "s1", &[], false)).patterns().to_vec()
}

fn reaches(deny: &str, cred: &str) -> bool {
    deny_reaches_credential_host(&Resource::parse(deny).unwrap(), cred)
}

#[test]
fn allow_all_and_unchosen_are_open() {
    assert_eq!(
        network(&Policy::default(), "s1", &[], false),
        NetworkSpec::Open
    );
    assert_eq!(
        network(&policy(Mode::AllowAll), "s1", &[], false),
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
    let spec = network(&p, "s1", &["api.anthropic.com".to_string()], false);
    let l = list(&spec);
    assert_eq!(l.hosts(), ["api.anthropic.com"]);
    assert_eq!(l.patterns(), ["*.npmjs.org"]);
    assert_eq!(l.cidrs(), ["127.0.0.0/8", "::1/128"]);
    assert_eq!(list(&network(&p, "other", &[], false)).patterns().len(), 0);
}

#[test]
fn balanced_has_the_preset_and_widens_globs() {
    let spec = network(&policy(Mode::Balanced), "s1", &[], false);
    let l = list(&spec);
    assert!(l.hosts().is_empty(), "rules never become --allow-host");
    assert!(l.patterns().contains(&"registry.npmjs.org".to_string()));
    assert!(
        l.patterns().contains(&"*.openai.com".to_string()),
        "**.openai.com -> *.openai.com"
    );
    assert!(
        l.patterns()
            .contains(&"*.blob.core.windows.net".to_string())
    );
    assert!(l.patterns().contains(&"*.digicert.com".to_string()));
    assert!(!l.patterns().contains(&"example.com".to_string()));
}

#[test]
fn deny_rules_subtract() {
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
        !list(&network(&p, "s1", &[], false))
            .patterns()
            .contains(&"registry.npmjs.org".to_string())
    );
}

#[test]
fn a_deny_drops_a_wildcard_allow_only_when_it_covers_the_whole_subtree() {
    // The apex isn't the subtree.
    assert_eq!(patterns("**.x.com", "x.com"), ["*.x.com"]);
    assert_eq!(patterns("*.x.com", "x.com"), ["*.x.com"]);
    // A one-label deny doesn't cover every depth.
    assert_eq!(patterns("**.x.com", "*.x.com"), ["*.x.com"]);
    assert!(patterns("**.a.x.com, api.x.com, *.b.x.com", "**.x.com").is_empty());
    assert!(patterns("**.x.com", "**.X.com").is_empty());
    assert!(patterns("*.x.com", "*.x.com").is_empty());
    assert!(patterns("crl*.x.com", "**.x.com").is_empty());
    assert_eq!(patterns("**.x.com", "**.a.x.com"), ["*.x.com"]);
    assert_eq!(patterns("**.notx.com", "**.x.com"), ["*.notx.com"]);
}

#[test]
fn a_port_scoped_deny_never_removes_a_host_allow() {
    // smolvm can't deny one port: dropping the host would block every port.
    assert_eq!(patterns("api.x.com", "api.x.com:8080"), ["api.x.com"]);
    assert_eq!(patterns("api.x.com", "api.x.com:443"), ["api.x.com"]);
    assert_eq!(patterns("**.x.com", "**.x.com:22"), ["*.x.com"]);
    // The same port-scoped entry allowed and denied leaves nothing allowed.
    assert!(patterns("api.x.com:8080", "api.x.com:8080").is_empty());
}

#[test]
fn a_port_scoped_deny_cidr_isnt_a_create_deny() {
    let mut p = policy(Mode::AllowAll);
    p.add_rule(
        None,
        Decision::Deny,
        "10.0.0.0/8:22, 192.168.0.0/16",
        "added",
        None,
        None,
    )
    .unwrap();
    assert_eq!(
        deny_cidrs(&p, "s1", host_access(&p, "s1")),
        with_loopback(&["192.168.0.0/16"])
    );
    let v = check(&p, Some("s1"), &[], "10.1.2.3:22");
    assert!(
        v.allowed && v.reason.contains("isn't enforced"),
        "{}",
        v.reason
    );
}

#[test]
fn check_honours_ports() {
    let mut p = policy(Mode::Balanced);
    p.add_rule(None, Decision::Allow, "api.x.com", "added", None, None)
        .unwrap();
    let deny = p
        .add_rule(None, Decision::Deny, "api.x.com:8080", "added", None, None)
        .unwrap();
    let v = check(&p, Some("s1"), &[], "api.x.com:8080");
    assert!(
        v.allowed && v.reason.contains(&deny) && v.reason.contains("isn't enforced"),
        "{}",
        v.reason
    );
    let v = check(&p, Some("s1"), &[], "api.x.com:9090");
    assert!(v.allowed && !v.reason.contains(&deny), "{}", v.reason);
    let v = check(&p, Some("s1"), &[], "api.x.com");
    assert!(v.allowed && !v.reason.contains(&deny), "{}", v.reason);
    // A bound secret's host with a port is still that host.
    let v = check(&p, Some("s1"), &["cred.example".into()], "cred.example:443");
    assert!(v.allowed && v.reason.contains("secret"), "{}", v.reason);
    // The preset allows ocsp.digicert.com:80 only, in sbx; smolvm allows every port.
    let v = check(&p, Some("s1"), &[], "ocsp.digicert.com:80");
    assert!(v.allowed && v.reason.contains("balanced"), "{}", v.reason);
    let v = check(&p, Some("s1"), &[], "ocsp.digicert.com");
    assert!(
        v.allowed && v.reason.contains("smolvm still allows"),
        "{}",
        v.reason
    );
}

#[test]
fn check_prefers_an_enforced_cidr_deny() {
    let mut p = policy(Mode::AllowAll);
    p.add_rule(None, Decision::Deny, "**", "added", None, None)
        .unwrap();
    let cidr = p
        .add_rule(None, Decision::Deny, "10.0.0.0/8", "added", None, None)
        .unwrap();
    let v = check(&p, Some("s1"), &[], "10.1.2.3");
    assert!(!v.allowed && v.reason.contains(&cidr), "{}", v.reason);
    assert!(!v.reason.contains("isn't enforced"), "{}", v.reason);
}

#[test]
fn everything_rule_opens() {
    let mut p = policy(Mode::DenyAll);
    p.add_rule(None, Decision::Allow, "**", "added", None, None)
        .unwrap();
    assert_eq!(network(&p, "s1", &[], false), NetworkSpec::Open);
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
    assert_eq!(
        deny_cidrs(&p, "s1", host_access(&p, "s1")),
        with_loopback(&["10.0.0.0/8", "192.168.0.0/16"])
    );
    p.add_rule(
        Some("s1"),
        Decision::Deny,
        "10.0.0.0/8",
        "again",
        None,
        None,
    )
    .unwrap();
    assert_eq!(
        deny_cidrs(&p, "s1", host_access(&p, "s1")),
        with_loopback(&["10.0.0.0/8", "192.168.0.0/16"])
    );
    assert_eq!(
        deny_cidrs(&p, "s2", host_access(&p, "s2")),
        with_loopback(&["10.0.0.0/8"])
    );
    // An install-phase deny counts only for the create that passes its id.
    let id = p
        .add_rule(
            Some("s1"),
            Decision::Deny,
            "172.16.0.0/12",
            "kit-install:k",
            None,
            None,
        )
        .unwrap();
    assert!(!deny_cidrs(&p, "s1", host_access(&p, "s1")).contains(&"172.16.0.0/12".to_string()));
    let cidrs = deny_cidrs_with(&p, "s1", host_access(&p, "s1"), std::slice::from_ref(&id));
    assert!(cidrs.contains(&"172.16.0.0/12".to_string()));
    assert_eq!(
        install_deny_cidr_notes(&p, "s1", host_access(&p, "s1"), &[id]),
        ["note: kit k's install-phase deny of 172.16.0.0/12 stays for this sandbox's life"]
    );
    // One a lasting rule denies anyway needs no note.
    let id = p
        .add_rule(
            Some("s1"),
            Decision::Deny,
            "10.0.0.0/8, bad.example",
            "kit-install:k",
            None,
            None,
        )
        .unwrap();
    assert!(install_deny_cidr_notes(&p, "s1", host_access(&p, "s1"), &[id]).is_empty());
}

fn with_loopback(cidrs: &[&str]) -> Vec<String> {
    let all: BTreeSet<String> = cidrs
        .iter()
        .chain(&HOST_LOOPBACK)
        .map(|c| c.to_string())
        .collect();
    all.into_iter().collect()
}

#[test]
fn host_loopback_is_denied_in_every_mode_without_a_localhost_rule() {
    for p in [
        Policy::default(),
        policy(Mode::AllowAll),
        policy(Mode::Balanced),
        policy(Mode::DenyAll),
    ] {
        assert_eq!(
            deny_cidrs(&p, "s1", host_access(&p, "s1")),
            with_loopback(&[]),
            "{:?}",
            p.mode
        );
        assert!(!host_access(&p, "s1"));
    }
    // A broad allow CIDR covering the gateway doesn't give host access.
    let mut p = policy(Mode::DenyAll);
    p.add_rule(
        None,
        Decision::Allow,
        "100.64.0.0/10, 0.0.0.0/0",
        "added",
        None,
        None,
    )
    .unwrap();
    assert_eq!(
        deny_cidrs(&p, "s1", host_access(&p, "s1")),
        with_loopback(&[])
    );
    assert!(!host_access(&p, "s1"));
    // A rule for the same range doesn't repeat it.
    let mut p = policy(Mode::AllowAll);
    p.add_rule(None, Decision::Deny, "127.0.0.0/8", "added", None, None)
        .unwrap();
    assert_eq!(
        deny_cidrs(&p, "s1", host_access(&p, "s1")),
        with_loopback(&[])
    );
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
    // Deny CIDRs reach smolvm at create only.
    assert!(
        v.reason
            .ends_with("enforced for sandboxes created after it was added"),
        "{}",
        v.reason
    );

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
fn admits_matches_the_way_smolvm_does() {
    let spec = NetworkSpec::Restricted(crate::smolvm::AllowList::new(
        vec!["cred.example".to_string()],
        vec!["api.x.com".to_string(), "*.y.com".to_string()],
        vec![],
    ));
    assert!(admits(&spec, "api.x.com", Mode::DenyAll).is_some());
    assert!(
        admits(&spec, "a.api.x.com", Mode::DenyAll).is_none(),
        "exact only"
    );
    assert!(admits(&spec, "a.b.y.com", Mode::DenyAll).is_some());
    assert!(
        admits(&spec, "y.com", Mode::DenyAll).is_none(),
        "*.y.com excludes the apex"
    );
    assert!(admits(&spec, "sub.cred.example", Mode::DenyAll).is_some());
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

#[test]
fn credential_hosts_cover_their_subdomains_as_smolvm_does() {
    let bound = ["github.com".to_string()];
    let v = check(&policy(Mode::DenyAll), Some("s1"), &bound, "foo.github.com");
    assert!(v.allowed && v.reason.contains("secret"), "{}", v.reason);
    let v = check(&policy(Mode::DenyAll), Some("s1"), &bound, "notgithub.com");
    assert!(!v.allowed, "{}", v.reason);
}

#[test]
fn wildcard_credential_hosts_are_patterns() {
    let bound = ["*.notion.com".to_string(), "api.y.example".to_string()];
    let spec = network(&policy(Mode::DenyAll), "s1", &bound, false);
    let l = list(&spec);
    assert_eq!(l.hosts(), ["api.y.example"]);
    assert!(l.patterns().contains(&"*.notion.com".to_string()));
    assert!(!l.hosts().iter().any(|h| h.contains('*')));
}

#[test]
fn wildcard_credential_hosts_cover_subdomains_only() {
    let bound = ["*.notion.com".to_string()];
    let v = check(&policy(Mode::DenyAll), Some("s1"), &bound, "api.notion.com");
    assert!(v.allowed && v.reason.contains("secret"), "{}", v.reason);
    let v = check(&policy(Mode::DenyAll), Some("s1"), &bound, "a.b.notion.com");
    assert!(v.allowed && v.reason.contains("secret"), "{}", v.reason);
    let v = check(&policy(Mode::DenyAll), Some("s1"), &bound, "notion.com");
    assert!(!v.allowed, "the apex isn't covered: {}", v.reason);
    let spec = network(&policy(Mode::DenyAll), "s1", &bound, false);
    assert!(admits(&spec, "api.notion.com", Mode::DenyAll).is_some());
    assert!(admits(&spec, "notion.com", Mode::DenyAll).is_none());
}

#[test]
fn denies_that_reach_a_credential_host() {
    for deny in [
        "api.notion.com",
        "a.b.notion.com",
        "*.notion.com",
        "**.notion.com",
        "**.com",
        "*.api.notion.com",
        "crl*.notion.com",
        "**",
    ] {
        assert!(reaches(deny, "*.notion.com"), "{deny}");
    }
    for deny in ["notion.com", "*.com", "api.other.com", "10.0.0.0/8"] {
        assert!(!reaches(deny, "*.notion.com"), "{deny}");
    }
    assert!(reaches("api.github.com", "api.github.com"));
    assert!(!reaches("github.com", "api.github.com"));
}

#[test]
fn port_scoped_denies_never_reach_a_credential_host() {
    // They're never applied, so they can't take a bound secret's host away.
    for deny in [
        "api.github.com:8080",
        "foo.api.github.com:8080",
        "**.github.com:443",
    ] {
        assert!(!reaches(deny, "api.github.com"), "{deny}");
    }
    assert!(!reaches("api.notion.com:8080", "*.notion.com"));
    assert!(reaches("api.github.com", "api.github.com"));
    assert!(reaches("foo.api.github.com", "api.github.com"));
}

#[test]
fn denies_under_an_exact_credential_host_reach_it() {
    // An exact credential host is `--allow-host`, which smolvm widens to its subdomains.
    let hits = |deny: &str| reaches(deny, "api.github.com");
    for deny in [
        "api.github.com",
        "foo.api.github.com",
        "a.b.api.github.com",
        "*.api.github.com",
        "**.api.github.com",
        "**.github.com",
        "*.github.com",
        "x*.api.github.com",
        "**",
    ] {
        assert!(hits(deny), "{deny}");
    }
    for deny in [
        "github.com",
        "*.com",
        "notapi.github.com",
        "api.github.co",
        "10.0.0.0/8",
    ] {
        assert!(!hits(deny), "{deny}");
    }
}

const GATEWAY: &str = "100.96.0.1/32";

fn has_gateway(spec: &NetworkSpec) -> bool {
    list(spec).cidrs().contains(&GATEWAY.to_string())
}

#[test]
fn localhost_rules_open_the_gateway_with_host_access_only() {
    for rule in ["localhost:11434", "localhost", "LOCALHOST:11434"] {
        let mut p = policy(Mode::DenyAll);
        p.add_rule(None, Decision::Allow, rule, "added", None, None)
            .unwrap();
        for sb in ["s1", "s2"] {
            let spec = network(&p, sb, &[], true);
            assert!(has_gateway(&spec), "{rule} {sb}");
            let l = list(&spec);
            assert!(l.patterns().is_empty() && l.hosts().is_empty(), "{rule}");
            // Created without host access: never the gateway.
            let spec = network(&p, sb, &[], false);
            assert!(!has_gateway(&spec), "{rule} {sb}");
            assert!(list(&spec).patterns().is_empty(), "{rule}");
            assert!(host_access(&p, sb), "{rule}");
        }
    }
    // Scoped to one sandbox: only that one.
    let mut p = policy(Mode::Balanced);
    let id = p
        .add_rule(
            Some("s1"),
            Decision::Allow,
            "localhost:8080",
            "added",
            None,
            None,
        )
        .unwrap();
    assert!(has_gateway(&network(&p, "s1", &[], true)));
    assert!(!has_gateway(&network(&p, "s2", &[], true)));
    assert!(host_access(&p, "s1") && !host_access(&p, "s2"));
    assert!(
        !list(&network(&p, "s1", &[], true))
            .patterns()
            .contains(&"localhost".to_string())
    );
    // Removed: gone.
    p.remove_rules(Some("s1"), Some(&id), None, None, None);
    assert!(!has_gateway(&network(&p, "s1", &[], true)));
}

#[test]
fn other_loopback_spellings_are_not_host_services() {
    let rules = "127.0.0.1:80, host.docker.internal:80";
    let mut p = policy(Mode::DenyAll);
    p.add_rule(None, Decision::Allow, rules, "added", None, None)
        .unwrap();
    let spec = network(&p, "s1", &[], true);
    let l = list(&spec);
    assert_eq!(l.patterns(), ["host.docker.internal"]);
    assert_eq!(l.cidrs(), ["127.0.0.0/8", "127.0.0.1/32", "::1/128"]);
    assert_eq!(
        deny_cidrs(&p, "s1", host_access(&p, "s1")),
        with_loopback(&[])
    );
    assert!(!host_access(&p, "s1"));
}

#[test]
fn a_localhost_rule_drops_the_host_loopback_deny_in_every_mode() {
    for mode in [Mode::AllowAll, Mode::Balanced, Mode::DenyAll] {
        let mut p = policy(mode);
        p.add_rule(
            Some("s1"),
            Decision::Allow,
            "localhost:11434",
            "added",
            None,
            None,
        )
        .unwrap();
        assert!(
            deny_cidrs(&p, "s1", host_access(&p, "s1")).is_empty(),
            "{mode:?}"
        );
        assert_eq!(
            deny_cidrs(&p, "s2", host_access(&p, "s2")),
            with_loopback(&[]),
            "{mode:?}"
        );
        // A deny of localhost wins.
        p.add_rule(Some("s1"), Decision::Deny, "localhost", "added", None, None)
            .unwrap();
        assert_eq!(
            deny_cidrs(&p, "s1", host_access(&p, "s1")),
            with_loopback(&[]),
            "{mode:?}"
        );
        assert!(!host_access(&p, "s1"));
    }
}

#[test]
fn host_services_rules_are_localhost_in_any_case() {
    for (r, yes) in [
        ("localhost", true),
        ("LOCALHOST:11434", true),
        ("localhost.example.com", false),
        ("127.0.0.1:80", false),
    ] {
        assert_eq!(is_host_services(&Resource::parse(r).unwrap()), yes, "{r}");
    }
}

#[test]
fn kit_rules_never_grant_host_access() {
    let mut p = policy(Mode::DenyAll);
    let install = p
        .add_rule(
            Some("s1"),
            Decision::Allow,
            "localhost:11434",
            "kit-install:k",
            None,
            None,
        )
        .unwrap();
    p.add_rule(
        Some("s1"),
        Decision::Allow,
        "LOCALHOST:8080",
        "kit:k",
        None,
        None,
    )
    .unwrap();
    let ids = std::slice::from_ref(&install);
    assert!(!host_access(&p, "s1"));
    assert_eq!(
        deny_cidrs_with(&p, "s1", host_access(&p, "s1"), ids),
        with_loopback(&[])
    );
    assert_eq!(
        deny_cidrs(&p, "s1", host_access(&p, "s1")),
        with_loopback(&[])
    );
    for spec in [
        network_with(&p, "s1", &[], ids, true),
        network(&p, "s1", &[], true),
    ] {
        assert!(!has_gateway(&spec), "{spec:?}");
        assert!(list(&spec).patterns().is_empty(), "{spec:?}");
    }
    // A user rule alongside still works.
    p.add_rule(
        Some("s1"),
        Decision::Allow,
        "localhost:3000",
        "added",
        None,
        None,
    )
    .unwrap();
    assert!(host_access(&p, "s1"));
    assert!(deny_cidrs_with(&p, "s1", host_access(&p, "s1"), ids).is_empty());
    assert!(has_gateway(&network_with(&p, "s1", &[], ids, true)));
    // An approved rule is the user's too.
    let mut p = policy(Mode::DenyAll);
    p.add_rule(None, Decision::Allow, "localhost", "approval", None, None)
        .unwrap();
    assert!(host_access(&p, "s1"));
}
