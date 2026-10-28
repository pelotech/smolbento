//! Turns the policy into what smolvm enforces for one sandbox, and explains decisions.

use std::collections::BTreeSet;

use super::rules::{Allow, Pattern, Resource, is_under, split_port};
use super::{Decision, Mode, Policy, Rule, presets};
use crate::smolvm::{AllowList, NetworkSpec};

/// The rules that apply to a sandbox (`None`: the global rules only): every rule but install-phase
/// kit rules, of which only those in `install` (the ids the running install step added) apply.
fn active<'a>(
    policy: &'a Policy,
    sandbox: Option<&'a str>,
    install: &'a [String],
) -> impl Iterator<Item = (&'a Rule, Option<&'a str>)> {
    policy
        .rules_for(sandbox)
        .filter(move |(r, _)| !r.is_kit_install() || install.contains(&r.id))
}

/// The resources of a sandbox's active rules with this decision.
fn resources(
    policy: &Policy,
    sandbox: Option<&str>,
    install: &[String],
    decision: Decision,
) -> Vec<Resource> {
    active(policy, sandbox, install)
        .filter(|(r, _)| r.decision == decision)
        .flat_map(|(r, _)| r.parsed())
        .collect()
}

/// Whether `deny` covers every host under `domain` (at any depth when `any_depth`, else one
/// label below it).
fn covers(deny: &Resource, domain: &str, any_depth: bool) -> bool {
    match &deny.pattern {
        Pattern::Everything => true,
        Pattern::Subdomains(p) => domain == p || is_under(domain, p),
        Pattern::OneLabel(p) => !any_depth && domain == p,
        _ => false,
    }
}

/// Whether a deny with a port cancels `allow`: only an allow of exactly the same text. smolvm
/// can't deny one port, and dropping the host would block all its other ports too.
pub fn cancels(deny: &Resource, allow: &Resource) -> bool {
    deny.port.is_some() && deny.port == allow.port && deny.raw.eq_ignore_ascii_case(&allow.raw)
}

/// An allow entry is dropped when a deny repeats it or covers all it allows: an exact host the
/// deny matches, or a wildcard's whole subtree. A deny with a port only `cancels`.
fn denied(allow: &Resource, denies: &[Resource]) -> bool {
    denies.iter().any(|d| {
        if d.port.is_some() {
            return cancels(d, allow);
        }
        d.raw.eq_ignore_ascii_case(&allow.raw)
            || match &allow.pattern {
                Pattern::Exact(h) => d.matches(h),
                Pattern::Subdomains(h) => covers(d, h, true),
                Pattern::OneLabel(h) | Pattern::Glob { parent: h, .. } => covers(d, h, false),
                _ => false,
            }
    })
}

/// The allow entries a sandbox's network (`None`: the global one) is built from: the balanced
/// preset when it applies, and the allow rules.
pub fn allows(policy: &Policy, sandbox: Option<&str>) -> Vec<Resource> {
    allows_with(policy, sandbox, &[])
}

fn allows_with(policy: &Policy, sandbox: Option<&str>, install: &[String]) -> Vec<Resource> {
    let mut allows = if policy.mode_for(sandbox) == Mode::Balanced {
        presets::balanced()
    } else {
        Vec::new()
    };
    allows.extend(resources(policy, sandbox, install, Decision::Allow));
    allows
}

/// What smolvm should allow for a sandbox. A bound credential's hosts are always included: smolvm
/// requires them. Install-phase kit rules are left out (see `network_with`).
pub fn network(
    policy: &Policy,
    sandbox: &str,
    credential_hosts: &[String],
    host_access: bool,
) -> NetworkSpec {
    network_for(policy, Some(sandbox), credential_hosts, &[], host_access)
}

/// `network` plus the install-phase kit rules with these ids: only for the steps that run a kit's
/// install hooks (a create's first start, `kit add`), which pass their own kits' ids.
pub fn network_with(
    policy: &Policy,
    sandbox: &str,
    credential_hosts: &[String],
    install: &[String],
    host_access: bool,
) -> NetworkSpec {
    network_for(
        policy,
        Some(sandbox),
        credential_hosts,
        install,
        host_access,
    )
}

/// `network` for a sandbox, or with `None` for the global policy alone.
fn network_for(
    policy: &Policy,
    sandbox: Option<&str>,
    credential_hosts: &[String],
    install: &[String],
    host_access: bool,
) -> NetworkSpec {
    if policy.mode_for(sandbox) == Mode::AllowAll {
        return NetworkSpec::Open;
    }
    let allows = allows_with(policy, sandbox, install);
    if allows.iter().any(|r| r.pattern == Pattern::Everything) {
        return NetworkSpec::Open;
    }
    let denies = resources(policy, sandbox, install, Decision::Deny);
    let (mut patterns, mut cidrs) = (BTreeSet::new(), BTreeSet::new());
    for r in allows.iter().filter(|r| !denied(r, &denies)) {
        if is_host_services(r) {
            if host_access {
                cidrs.insert(format!("{HOST_GATEWAY}/32"));
            }
            continue;
        }
        match r.to_allow() {
            Allow::Pattern(p) => {
                patterns.insert(p);
            }
            Allow::Cidr(c) => {
                cidrs.insert(c);
            }
            Allow::Everything => {}
        }
    }
    // Exact credential hosts stay `--allow-host`, as before: they must resolve for the secret to
    // work. A `*.x` one can't be resolved, so it's the pattern smolvm wants for it.
    let (wild, hosts): (Vec<String>, Vec<String>) = credential_hosts
        .iter()
        .cloned()
        .partition(|h| h.starts_with("*."));
    patterns.extend(wild);
    NetworkSpec::Restricted(AllowList::new(hosts, patterns, cidrs))
}

/// Whether a bound credential host admits `host`: an exact one (`--allow-host`) the host and its
/// subdomains, a `*.x` one (a pattern) only the subdomains of x.
fn credential_admits(cred: &str, host: &str) -> bool {
    let cred = cred.to_ascii_lowercase();
    match cred.strip_prefix("*.") {
        Some(domain) => is_under(host, domain),
        None => host == cred || is_under(host, &cred),
    }
}

/// Whether `deny` names a host a bound credential host keeps reachable, so it can't be honoured.
/// For `*.x`, any deny that matches some host under x does. An exact one is `--allow-host`, which
/// smolvm widens to its subdomains: a deny matching the host or any host under it does (a deny
/// of a parent domain alone doesn't reach it). A deny with a port is never applied (see
/// `denied`), so it reaches nothing.
pub fn deny_reaches_credential_host(deny: &Resource, cred: &str) -> bool {
    if deny.port.is_some() {
        return false;
    }
    let cred = cred.to_ascii_lowercase();
    match cred.strip_prefix("*.") {
        Some(x) => reaches_under(deny, x),
        None => deny.matches(&cred) || reaches_under(deny, &cred),
    }
}

/// Whether `deny` matches some host strictly under `x`.
fn reaches_under(deny: &Resource, x: &str) -> bool {
    match &deny.pattern {
        Pattern::Everything => true,
        Pattern::Exact(h) => is_under(h, x),
        Pattern::Subdomains(p) => p == x || is_under(p, x) || is_under(x, p),
        Pattern::OneLabel(p) | Pattern::Glob { parent: p, .. } => p == x || is_under(p, x),
        Pattern::Cidr { .. } => false,
    }
}

/// The guest's gateway, which smolvm forwards to the host's loopback (measured in
/// docs/superpowers/notes/2026-10-28-host-services-spike.md). A restricted machine reaches it only
/// while `HOST_GATEWAY/32` is in its allow list, which `machine update` changes live.
pub const HOST_GATEWAY: &str = "100.96.0.1";

/// Whether an allow entry is a host-services rule: `localhost`, with any port or none. It becomes
/// the gateway in the allow list (smolvm can't open one port, so every host port opens). Other
/// spellings of loopback (`127.0.0.1`, `host.docker.internal`) aren't: sbx doesn't treat them so.
pub(crate) fn is_host_services(r: &Resource) -> bool {
    matches!(&r.pattern, Pattern::Exact(h) if h == "localhost")
}

/// `host_access` with the install-phase kit rules of these ids, as for `network_with`.
pub fn host_access_with(policy: &Policy, sandbox: &str, install: &[String]) -> bool {
    let denies = resources(policy, Some(sandbox), install, Decision::Deny);
    allows_with(policy, Some(sandbox), install)
        .iter()
        .any(|r| is_host_services(r) && !denied(r, &denies))
}

/// Whether a sandbox created now gets host access: an active, undenied `localhost` allow rule
/// applies to it. It's then created without the `HOST_LOOPBACK` deny and labelled
/// `sbx.host-access`; only such a sandbox gets the gateway from `localhost` rules.
pub fn host_access(policy: &Policy, sandbox: &str) -> bool {
    host_access_with(policy, sandbox, &[])
}

/// Denied at create for every sandbox, whatever the mode, unless it gets host access
/// (`host_access`): smolvm dials host loopback for a guest connecting to its gateway, and sbx
/// doesn't let sandboxes reach the host's localhost. A restricted allow list alone isn't enough:
/// a broad allow CIDR, a later switch to allow-all, or a DNS answer of the gateway would reach it.
pub const HOST_LOOPBACK: [&str; 2] = ["127.0.0.0/8", "::1/128"];

/// Deny CIDRs for `machine create` (smolvm accepts them at create only), sorted and unique:
/// `HOST_LOOPBACK` when it applies and the deny rules' CIDRs. One with a port is left out: smolvm
/// would deny every port of the range.
pub fn deny_cidrs(policy: &Policy, sandbox: &str) -> Vec<String> {
    deny_cidrs_with(policy, sandbox, &[])
}

/// `deny_cidrs` plus those of the install-phase kit rules with these ids: a create passes its
/// own, as for `network_with`. smolvm fixes deny CIDRs at create, so they outlast the install.
pub fn deny_cidrs_with(policy: &Policy, sandbox: &str, install: &[String]) -> Vec<String> {
    let loopback = !host_access_with(policy, sandbox, install);
    resources(policy, Some(sandbox), install, Decision::Deny)
        .into_iter()
        .filter(|r| r.port.is_none())
        .filter_map(|r| match r.to_allow() {
            Allow::Cidr(c) => Some(c),
            _ => None,
        })
        .chain(
            HOST_LOOPBACK
                .iter()
                .filter(|_| loopback)
                .map(|c| c.to_string()),
        )
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// For a create: one note per kit whose install-phase rules (of these ids) deny CIDRs that no
/// other rule denies. smolvm keeps a create's deny CIDRs, so they outlast the install phase.
pub fn install_deny_cidr_notes(policy: &Policy, sandbox: &str, install: &[String]) -> Vec<String> {
    let lasting = deny_cidrs(policy, sandbox);
    let mut per_kit: Vec<(&str, Vec<String>)> = Vec::new();
    for (r, _) in policy.rules_for(Some(sandbox)) {
        let Some(kit) = r.created_via.strip_prefix(super::KIT_INSTALL_VIA) else {
            continue;
        };
        if r.decision != Decision::Deny || !install.contains(&r.id) {
            continue;
        }
        for res in r.parsed().filter(|x| x.port.is_none()) {
            let Allow::Cidr(c) = res.to_allow() else {
                continue;
            };
            if lasting.contains(&c) {
                continue;
            }
            let i = match per_kit.iter().position(|(k, _)| *k == kit) {
                Some(i) => i,
                None => {
                    per_kit.push((kit, Vec::new()));
                    per_kit.len() - 1
                }
            };
            if !per_kit[i].1.contains(&c) {
                per_kit[i].1.push(c);
            }
        }
    }
    per_kit
        .into_iter()
        .map(|(kit, cidrs)| {
            format!(
                "note: kit {kit}'s install-phase deny of {} stays for this sandbox's life",
                cidrs.join(", ")
            )
        })
        .collect()
}

/// Why a network compiled under `mode` still lets `host` through, if it does (the way smolvm
/// matches).
fn admits(spec: &NetworkSpec, host: &str, mode: Mode) -> Option<String> {
    let NetworkSpec::Restricted(list) = spec else {
        // Open in a restricted mode: an allow rule for `**`.
        return Some(
            if mode == Mode::AllowAll {
                "allow-all mode"
            } else {
                "an allow-everything rule"
            }
            .into(),
        );
    };
    let entry = list
        .hosts()
        .iter()
        .find(|h| host == h.as_str() || is_under(host, h))
        .cloned()
        .or_else(|| {
            list.patterns()
                .iter()
                .find(|p| match p.strip_prefix("*.") {
                    Some(d) => is_under(host, d),
                    None => host == p.as_str(),
                })
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
    let target = target.trim().to_ascii_lowercase();
    // Rules match the target with its port; smolvm's allow list and credentials see the host.
    let host = split_port(&target)
        .map_or(target.as_str(), |(h, _)| h)
        .to_string();
    if credential_hosts.iter().any(|h| credential_admits(h, &host)) {
        return verdict(true, "a secret bound to this sandbox uses this host");
    }
    // No sandbox: the global rules only.
    let mode = policy.mode_for(sandbox);
    let hits = |decision: Decision| {
        active(policy, sandbox, &[])
            .filter(move |(r, _)| r.decision == decision)
            .flat_map(|(r, scope)| {
                r.parsed()
                    .filter(|res| res.matches(&target))
                    .map(move |res| (r, scope.unwrap_or("global"), res))
            })
    };
    // A CIDR deny without a port is enforced (at create); report it before any other deny.
    let enforced =
        |res: &Resource| matches!(res.pattern, Pattern::Cidr { .. }) && res.port.is_none();
    let spec = || network_for(policy, sandbox, credential_hosts, &[], false);
    let mut denies: Vec<_> = hits(Decision::Deny).collect();
    denies.sort_by_key(|(_, _, res)| !enforced(res));
    if let Some((r, scope, res)) = denies.first() {
        let text = format!("deny rule {} ({scope})", r.id);
        if enforced(res) {
            // Rules don't record when they were added, so an older sandbox can't be told apart.
            return verdict(
                false,
                format!("{text}, enforced for sandboxes created after it was added"),
            );
        }
        // smolvm has no host or port deny: a host deny only removes allow entries.
        return match admits(&spec(), &host, mode) {
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
    if let Some((r, scope, _)) = hits(Decision::Allow).next() {
        return verdict(true, format!("allow rule {} ({scope})", r.id));
    }
    if mode == Mode::Balanced
        && let Some(group) = presets::group_for(&target)
    {
        return verdict(true, format!("balanced preset ({group})"));
    }
    let text = format!("no rule allows it ({} mode)", mode.name());
    // smolvm allows a host on every port, and widens wildcards: say so when it lets this through.
    match admits(&spec(), &host, mode) {
        Some(why) => verdict(
            true,
            format!("{text}, but smolvm still allows it via {why}"),
        ),
        None => verdict(false, text),
    }
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
            !list(&network(&p, "s1", &[], false))
                .patterns()
                .contains(&"registry.npmjs.org".to_string())
        );
        p.set_deny_network("s2", true);
        assert_eq!(list(&network(&p, "s2", &[], false)).patterns().len(), 0);
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
        assert_eq!(deny_cidrs(&p, "s1"), with_loopback(&["192.168.0.0/16"]));
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
            deny_cidrs(&p, "s1"),
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
            deny_cidrs(&p, "s1"),
            with_loopback(&["10.0.0.0/8", "192.168.0.0/16"])
        );
        assert_eq!(deny_cidrs(&p, "s2"), with_loopback(&["10.0.0.0/8"]));
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
        assert!(!deny_cidrs(&p, "s1").contains(&"172.16.0.0/12".to_string()));
        let cidrs = deny_cidrs_with(&p, "s1", std::slice::from_ref(&id));
        assert!(cidrs.contains(&"172.16.0.0/12".to_string()));
        assert_eq!(
            install_deny_cidr_notes(&p, "s1", &[id]),
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
        assert!(install_deny_cidr_notes(&p, "s1", &[id]).is_empty());
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
            assert_eq!(deny_cidrs(&p, "s1"), with_loopback(&[]), "{:?}", p.mode);
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
        assert_eq!(deny_cidrs(&p, "s1"), with_loopback(&[]));
        assert!(!host_access(&p, "s1"));
        // A rule for the same range doesn't repeat it.
        let mut p = policy(Mode::AllowAll);
        p.add_rule(None, Decision::Deny, "127.0.0.0/8", "added", None, None)
            .unwrap();
        assert_eq!(deny_cidrs(&p, "s1"), with_loopback(&[]));
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
        p.remove_rules(Some("s1"), Some(&id), None);
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
        assert_eq!(deny_cidrs(&p, "s1"), with_loopback(&[]));
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
            assert!(deny_cidrs(&p, "s1").is_empty(), "{mode:?}");
            assert_eq!(deny_cidrs(&p, "s2"), with_loopback(&[]), "{mode:?}");
            // A deny of localhost wins.
            p.add_rule(Some("s1"), Decision::Deny, "localhost", "added", None, None)
                .unwrap();
            assert_eq!(deny_cidrs(&p, "s1"), with_loopback(&[]), "{mode:?}");
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
}
