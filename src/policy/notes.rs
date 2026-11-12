//! Checks and user notes for deny rules: what smolvm can't enforce, and denies that would cut off
//! a bound secret's hosts.

use anyhow::{Context, Result, bail};

use super::rules::{Allow, Resource, parse_list};
use super::{Decision, Policy, compile};
use crate::secrets::SecretsFile;

/// What to tell the user about a new deny: whether it has a port-less deny CIDR (applied at
/// create), and a note for each port-scoped entry, which smolvm can't enforce (see `compile`).
pub fn deny_notes(
    policy: &Policy,
    scope: Option<&str>,
    denies: &[Resource],
) -> (bool, Vec<String>) {
    // A global deny applies with the global rules alone and in every sandbox.
    let sandboxes: Vec<Option<&str>> = match scope {
        Some(s) => vec![Some(s)],
        None => std::iter::once(None)
            .chain(policy.sandboxes.keys().map(|s| Some(s.as_str())))
            .collect(),
    };
    let allows: Vec<Resource> = sandboxes
        .iter()
        .flat_map(|s| compile::allows(policy, *s))
        .collect();
    let cidr = denies
        .iter()
        .any(|r| r.port.is_none() && matches!(r.to_allow(), Allow::Cidr(_)));
    let notes = denies
        .iter()
        .filter(|r| r.port.is_some())
        .map(|r| {
            let host = r.without_port();
            if allows.iter().any(|a| compile::cancels(r, a)) {
                format!(
                    "note: smolvm can't filter by port, so {} only cancels the allow rule with \
                     the same text; it doesn't block {host} otherwise",
                    r.raw
                )
            } else {
                format!(
                    "note: smolvm can't filter by port, so {} isn't enforced ({host} stays \
                     reachable on every port); deny {host} to block it",
                    r.raw
                )
            }
        })
        .collect();
    (cidr, notes)
}

/// The first of a sandbox's credential `hosts` that one of `denies` reaches, with what's bound to
/// it ("a github secret", or "a secret" when secrets.toml no longer names the service).
pub fn bound_conflict(
    hosts: &[String],
    services: &[String],
    secrets: Option<&SecretsFile>,
    denies: &[Resource],
) -> Option<(String, String)> {
    let host = hosts.iter().find(|h| {
        denies
            .iter()
            .any(|d| compile::deny_reaches_credential_host(d, h))
    })?;
    let service = services
        .iter()
        .find(|name| {
            secrets
                .and_then(|f| f.service(name))
                .is_some_and(|s| s.hosts.iter().any(|h| h == host))
        })
        .map_or_else(|| "a secret".to_string(), |s| format!("a {s} secret"));
    Some((host.clone(), service))
}

/// `--deny-network` values, each parsed as `sbt policy deny network` parses its resources.
pub fn parse_create_denies(values: &[String]) -> Result<Vec<(String, Vec<Resource>)>> {
    values
        .iter()
        .map(|v| {
            let parsed = parse_list(v).with_context(|| format!("--deny-network {v}"))?;
            Ok((v.clone(), parsed))
        })
        .collect()
}

/// `run`/`create --deny-network`: adds each value as a deny rule of the new sandbox `sandbox`, as
/// `sbt policy deny network --sandbox <sandbox> <value>` would, with the same checks and stderr
/// notes. `services` and `credential_hosts` are the secrets the sandbox is about to be created
/// with. Returns the ids of the rules that weren't there yet; the caller saves the policy.
pub fn add_create_denies(
    policy: &mut Policy,
    sandbox: &str,
    denies: &[(String, Vec<Resource>)],
    secrets: &SecretsFile,
    services: &[String],
    credential_hosts: &[String],
) -> Result<Vec<String>> {
    let all: Vec<Resource> = denies.iter().flat_map(|(_, p)| p.iter().cloned()).collect();
    if let Some((host, service)) = bound_conflict(credential_hosts, services, Some(secrets), &all) {
        bail!(
            "can't deny {host}: sandbox {sandbox} would be created with {service} bound to it; remove the secret first"
        );
    }
    let before: Vec<String> = policy
        .sandboxes
        .get(sandbox)
        .map(|s| s.rules.iter().map(|r| r.id.clone()).collect())
        .unwrap_or_default();
    let mut added = Vec::new();
    for (value, _) in denies {
        let id = policy.add_rule(Some(sandbox), Decision::Deny, value, "added", None, None)?;
        if !before.contains(&id) && !added.contains(&id) {
            added.push(id);
        }
    }
    // Only the stderr notes: port-less deny CIDRs are in place before this sandbox is created.
    for n in deny_notes(policy, Some(sandbox), &all).1 {
        eprintln!("{n}");
    }
    Ok(added)
}
