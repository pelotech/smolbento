//! Turns the policy into what smolvm enforces for one sandbox, and explains decisions.

use std::collections::BTreeSet;

use super::rules::{Allow, Pattern, Resource, SmolvmHost, is_under, split_port};
use super::{Decision, Mode, Policy, Rule, presets};
use crate::sandbox::name::is_internal;
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

/// Whether a deny with a port cancels `allow`: only an allow of the same pattern and port. smolvm
/// can't deny one port, and dropping the host would block all its other ports too.
pub fn cancels(deny: &Resource, allow: &Resource) -> bool {
    deny.port.is_some() && deny.port == allow.port && deny.pattern == allow.pattern
}

/// An allow entry is dropped when a deny repeats it or covers all it allows: an exact host the
/// deny matches, or a wildcard's whole subtree. A deny with a port only `cancels`.
fn denied(allow: &Resource, denies: &[Resource]) -> bool {
    denies.iter().any(|d| {
        if d.port.is_some() {
            return cancels(d, allow);
        }
        d.pattern == Pattern::Everything
            || d.pattern == allow.pattern
            || match &allow.pattern {
                Pattern::Exact(h) => d.matches(h),
                Pattern::Subdomains(h) => covers(d, h, true),
                Pattern::OneLabel(h) | Pattern::Glob { parent: h, .. } => covers(d, h, false),
                Pattern::Everything | Pattern::Cidr { .. } => false,
            }
    })
}

/// The allow entries a sandbox's network (`None`: the global one) is built from: the balanced
/// preset when it applies, and the allow rules.
pub fn allows(policy: &Policy, sandbox: Option<&str>) -> Vec<Resource> {
    allows_with(policy, sandbox, &[])
}

fn allows_with(policy: &Policy, sandbox: Option<&str>, install: &[String]) -> Vec<Resource> {
    let mut allows = if policy.current_mode() == Mode::Balanced {
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
    if policy.current_mode() == Mode::AllowAll {
        return NetworkSpec::Open;
    }
    let allows = allows_with(policy, sandbox, install);
    let denies = resources(policy, sandbox, install, Decision::Deny);
    if allows
        .iter()
        .any(|r| r.pattern == Pattern::Everything && !denied(r, &denies))
    {
        return NetworkSpec::Open;
    }
    let (mut patterns, mut cidrs) = (BTreeSet::new(), BTreeSet::new());
    for r in allows.iter().filter(|r| !denied(r, &denies)) {
        // Host services come from the user's own rules only (`user_host_services`), never a
        // `localhost` pattern.
        if is_host_services(r) {
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
    // Exact credential hosts are `--allow-host`: they must resolve for the secret to work. A
    // `*.x` one can't be resolved, so it's the pattern smolvm wants for it.
    let (wild, hosts): (Vec<String>, Vec<String>) = credential_hosts
        .iter()
        .cloned()
        .partition(|h| h.starts_with("*."));
    patterns.extend(wild);
    if host_access && user_host_services(policy, sandbox) {
        cidrs.insert(format!("{HOST_GATEWAY}/32"));
    }
    NetworkSpec::Restricted(AllowList::new(hosts, patterns, cidrs))
}

/// Whether a bound credential host admits `host`: an exact one (`--allow-host`) the host and its
/// subdomains, a `*.x` one (a pattern) only the subdomains of x.
fn credential_admits(cred: &str, host: &str) -> bool {
    SmolvmHost::parse(&cred.to_ascii_lowercase()).covers(host)
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
    match SmolvmHost::parse(&cred) {
        SmolvmHost::Subdomains(x) => reaches_under(deny, x),
        SmolvmHost::Exact(h) => deny.matches(h) || reaches_under(deny, h),
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

/// The guest's gateway, which smolvm forwards to the host's loopback. A restricted machine reaches
/// it only while `HOST_GATEWAY/32` is in its allow list, which `machine update` changes live.
pub const HOST_GATEWAY: &str = "100.96.0.1";

/// Whether an allow entry is a host-services rule: `localhost`, with any port or none. It becomes
/// the gateway in the allow list (smolvm can't open one port, so every host port opens). Other
/// spellings of loopback (`127.0.0.1`, `host.docker.internal`) aren't: sbx doesn't treat them so.
pub(crate) fn is_host_services(r: &Resource) -> bool {
    matches!(&r.pattern, Pattern::Exact(h) if h == "localhost")
}

/// Whether one of the user's own `localhost` allow rules applies to a sandbox (`None`: the global
/// rules), and no deny drops it. Kit rules (runtime or install phase) never count: a kit is less
/// trusted than the user, and host access outlasts it (no create-time deny).
fn user_host_services(policy: &Policy, sandbox: Option<&str>) -> bool {
    let denies = resources(policy, sandbox, &[], Decision::Deny);
    policy
        .rules_for(sandbox)
        .filter(|(r, _)| r.decision == Decision::Allow && r.source() == "local")
        .flat_map(|(r, _)| r.parsed())
        .any(|x| is_host_services(&x) && !denied(&x, &denies))
}

/// Whether a sandbox created now gets host access: one of the user's own `localhost` allow rules
/// applies to it, and no deny drops it. It's then created without the `HOST_LOOPBACK` deny and labelled
/// `sbx.host-access`; only such a sandbox gets the gateway from `localhost` rules. Internal sandboxes (the kit
/// builder) never do: it builds untrusted kits and needs nothing on the host.
pub fn host_access(policy: &Policy, sandbox: &str) -> bool {
    !is_internal(sandbox) && user_host_services(policy, Some(sandbox))
}

/// Denied at create for every sandbox, whatever the mode, unless it gets host access
/// (`host_access`): smolvm dials host loopback for a guest connecting to its gateway, and sbx
/// doesn't let sandboxes reach the host's localhost. A restricted allow list alone isn't enough:
/// a broad allow CIDR, a later switch to allow-all, or a DNS answer of the gateway would reach it.
pub const HOST_LOOPBACK: [&str; 2] = ["127.0.0.0/8", "::1/128"];

/// Deny CIDRs for `machine create` (smolvm accepts them at create only), sorted and unique:
/// `HOST_LOOPBACK` when it applies and the deny rules' CIDRs. One with a port is left out: smolvm
/// would deny every port of the range.
pub fn deny_cidrs(policy: &Policy, sandbox: &str, host_access: bool) -> Vec<String> {
    deny_cidrs_with(policy, sandbox, host_access, &[])
}

/// `deny_cidrs` plus those of the install-phase kit rules with these ids: a create passes its
/// own, as for `network_with`. smolvm fixes deny CIDRs at create, so they outlast the install.
pub fn deny_cidrs_with(
    policy: &Policy,
    sandbox: &str,
    host_access: bool,
    install: &[String],
) -> Vec<String> {
    let loopback = !host_access;
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
pub fn install_deny_cidr_notes(
    policy: &Policy,
    sandbox: &str,
    host_access: bool,
    install: &[String],
) -> Vec<String> {
    let lasting = deny_cidrs(policy, sandbox, host_access);
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
    /// Denied with no deny rule involved (sbx's `deny_kind: implicit`).
    pub implicit: bool,
}

fn verdict(allowed: bool, reason: impl Into<String>) -> Verdict {
    Verdict {
        allowed,
        reason: reason.into(),
        implicit: false,
    }
}

/// A denial no deny rule made.
fn implicit_deny(reason: &str) -> Verdict {
    Verdict {
        implicit: true,
        ..verdict(false, reason)
    }
}

/// `check` for a UDP destination. smolvm's allow list admits UDP wherever it admits TCP, so the
/// rules decide the same way. The exception is port 53, where the rules allow it: smolvm answers
/// DNS itself and never relays a datagram there. A hosted sandbox's machine drops every datagram
/// but DNS, so an allow says so.
pub fn check_udp(
    policy: &Policy,
    sandbox: Option<&str>,
    credential_hosts: &[String],
    host_access: Option<bool>,
    target: &str,
) -> Verdict {
    let mut v = check(policy, sandbox, credential_hosts, host_access, target);
    if v.allowed && split_port(target.trim()).is_ok_and(|(_, port)| port == Some(53)) {
        return implicit_deny("smolvm answers DNS itself; UDP to port 53 never reaches the target");
    }
    if v.allowed {
        v.reason
            .push_str("; not from hosted sandboxes, which send no UDP but DNS");
    }
    v
}

/// Whether `host` is the host's loopback as a guest reaches it: `localhost` (host services),
/// a loopback address, or the gateway smolvm forwards to it.
fn is_host_loopback(host: &str) -> bool {
    host == "localhost"
        || host == HOST_GATEWAY
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

/// sbx semantics: bound secrets, then deny rules, then the mode, allow rules and the preset. The
/// host's loopback comes first: it's denied at create, whatever the rules, unless the sandbox has
/// host access (`host_access`: the sandbox's record; `None` predicts one created now).
pub fn check(
    policy: &Policy,
    sandbox: Option<&str>,
    credential_hosts: &[String],
    host_access: Option<bool>,
    target: &str,
) -> Verdict {
    verdict_for(policy, sandbox, credential_hosts, host_access, target, true)
}

/// The sbx verdict alone, as the egress process enforces it per flow: smolvm's allow list
/// (`admits`) and its enforced-CIDR wording play no part.
pub fn decide(
    policy: &Policy,
    sandbox: &str,
    credential_hosts: &[String],
    host_access: bool,
    target: &str,
) -> Verdict {
    verdict_for(
        policy,
        Some(sandbox),
        credential_hosts,
        Some(host_access),
        target,
        false,
    )
}

/// `smolvm`: layer on what smolvm actually enforces (`check`), or stay pure sbx (`decide`).
fn verdict_for(
    policy: &Policy,
    sandbox: Option<&str>,
    credential_hosts: &[String],
    host_access: Option<bool>,
    target: &str,
    smolvm: bool,
) -> Verdict {
    let target = target.trim().to_ascii_lowercase();
    // Rules match the target with its port; smolvm's allow list and credentials see the host.
    let host = split_port(&target).map_or(target.as_str(), |(h, _)| h);
    let host = host.strip_suffix('.').unwrap_or(host).to_string();
    if credential_hosts.iter().any(|h| credential_admits(h, &host)) {
        return verdict(true, "a secret bound to this sandbox uses this host");
    }
    let host_access = host_access.unwrap_or_else(|| match sandbox {
        Some(s) => self::host_access(policy, s),
        None => user_host_services(policy, None),
    });
    if is_host_loopback(&host) && !host_access {
        return implicit_deny(
            "the host's loopback is closed to sandboxes created without a localhost allow rule",
        );
    }
    // No sandbox: the global rules only.
    let mode = policy.current_mode();
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
        if !smolvm {
            return verdict(false, text);
        }
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
    // sbx's wording.
    let text = "no matching allow rule (default deny)";
    if !smolvm {
        return implicit_deny(text);
    }
    // smolvm allows a host on every port, and widens wildcards: say so when it lets this through.
    match admits(&spec(), &host, mode) {
        Some(why) => verdict(
            true,
            format!("{text}, but smolvm still allows it via {why}"),
        ),
        None => implicit_deny(text),
    }
}

#[cfg(test)]
#[path = "compile_tests.rs"]
mod tests;
