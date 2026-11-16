//! `bento policy`: the network policy.

use anyhow::{Context, Result, bail};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;

use super::{
    ApprovalCmd, CheckArgs, CheckKind, Ctx, PolicyCmd, PolicyLsArgs, PolicyRmKind, RuleArgs,
    RuleKind, Unsupported, confirm, table,
};
use crate::policy::log;
use crate::policy::notes::{bound_conflict, deny_notes};
use crate::policy::rules::{Resource, parse_list};
use crate::policy::{Decision, Mode, Policy, Rule, compile, presets};
use crate::provision;
use crate::provision::builder::BUILDER;
use crate::sandbox::{self, name};
use crate::secrets::SecretsFile;
use crate::smolvm::{NetworkSpec, Runner};

/// Stops every running sandbox, as sbx's `policy reset` does. Failures are warnings: the reset
/// itself must still happen.
fn stop_running<R: Runner>(ctx: &Ctx<R>) {
    let sandboxes = match sandbox::list(&ctx.vm) {
        Ok(s) => s,
        Err(e) => {
            crate::warning!("couldn't list sandboxes to stop them ({e:#})");
            return;
        }
    };
    for sb in sandboxes.iter().filter(|s| s.is_running()) {
        if let Err(e) = super::lifecycle::stop_sandbox(ctx, sb) {
            crate::warning!("couldn't stop {} ({e:#})", sb.name());
        }
    }
}

pub fn run<R: Runner>(ctx: &mut Ctx<R>, cmd: PolicyCmd) -> Result<i32> {
    let mut policy = Policy::load(&ctx.paths)?;
    match cmd {
        PolicyCmd::Init { mode, sandbox } => {
            if sandbox.is_some() {
                return Err(
                    Unsupported("policy init --sandbox is a Docker Cloud option".into()).into(),
                );
            }
            policy.mode = Some(mode);
            policy.save(&ctx.paths)?;
            writeln!(&ctx.out, "Network policy: {}", mode.name())?;
            provision::push_network(ctx, &policy)?;
        }
        PolicyCmd::Allow {
            kind: RuleKind::Network(a),
        } => add(ctx, &mut policy, Decision::Allow, a)?,
        PolicyCmd::Deny {
            kind: RuleKind::Network(a),
        } => add(ctx, &mut policy, Decision::Deny, a)?,
        PolicyCmd::Rm {
            kind: PolicyRmKind::Network(a),
        } => {
            super::refuse(&[
                (a.method.is_some(), "--method"),
                (a.path.is_some(), "--path"),
                (a.query.is_some(), "--query"),
            ])?;
            if a.id.is_none() && a.resource.is_none() {
                bail!("pass --id or --resource");
            }
            if let Some(sb) =
                policy.kit_rule_target(a.sandbox.as_deref(), a.id.as_deref(), a.resource.as_deref())
            {
                bail!(
                    "kit rules can't be removed; add a deny rule instead \
                     (bento policy deny network --sandbox {sb} <host>)"
                );
            }
            // Ids are unique, so --id alone finds a sandbox's rule too.
            let sandbox = match (&a.sandbox, &a.id) {
                (None, Some(id)) => policy.find(id).and_then(|(_, s)| s.map(String::from)),
                _ => a.sandbox.clone(),
            };
            let before = policy.clone();
            let removed =
                policy.remove_rules(sandbox.as_deref(), a.id.as_deref(), a.resource.as_deref());
            if !removed {
                bail!("no matching rules");
            }
            policy.save(&ctx.paths)?;
            writeln!(&ctx.out, "Removed")?;
            print_host_notes(ctx, &before, &policy, None, Decision::Deny, &[]);
            provision::push_network(ctx, &policy)?;
        }
        PolicyCmd::Ls(a) => ls(ctx, &policy, &a)?,
        PolicyCmd::Inspect { id, output } => {
            let (rule, scope) = policy
                .find(&id)
                .with_context(|| format!("no rule '{id}'"))?;
            let doc = serde_json::json!({ "scope": scope.unwrap_or("global"), "rule": rule });
            if let Some(text) = output.structured(&doc)? {
                write!(&ctx.out, "{text}")?;
            } else {
                writeln!(
                    &ctx.out,
                    "ID: {}\nScope: {}\nDecision: {}\nResources: {}\nCreated via: {}",
                    rule.id,
                    scope.unwrap_or("global"),
                    rule.decision.name(),
                    rule.resources.join(", "),
                    rule.created_via
                )?;
            }
        }
        PolicyCmd::Check {
            kind: CheckKind::Network(a),
        } => return check(ctx, &policy, &a),
        PolicyCmd::Reset { force } => {
            confirm(
                ctx,
                "Remove every policy rule and the chosen mode? Running sandboxes will be stopped.",
                force,
            )?;
            stop_running(ctx);
            policy.reset();
            policy.save(&ctx.paths)?;
            writeln!(
                &ctx.out,
                "Policy reset; the next start or create asks for a mode"
            )?;
        }
        PolicyCmd::Log(a) => {
            if a.kind.as_deref().is_some_and(|k| k == "filesystem") {
                return Err(Unsupported("smolbento has no filesystem policy".into()).into());
            }
            let rows = blocked_rows(ctx, a.sandbox.as_deref(), a.limit)?;
            let text = a.output.structured(&rows)?;
            write!(&ctx.out, "{}", text.unwrap_or_else(|| render_log(&rows)))?;
        }
        PolicyCmd::Approval(cmd) => return approval(ctx, &mut policy, cmd),
        PolicyCmd::Refresh(_) => {
            return Err(
                Unsupported("`bento policy refresh` is for organization policies".into()).into(),
            );
        }
    }
    Ok(0)
}

fn add<R: Runner>(
    ctx: &Ctx<R>,
    policy: &mut Policy,
    decision: Decision,
    a: RuleArgs,
) -> Result<()> {
    if a.protocol.as_deref().is_some_and(|p| p != "tcp") {
        return Err(Unsupported("only tcp network rules are supported".into()).into());
    }
    if let Some(s) = &a.sandbox {
        name::validate(s)?;
    }
    add_rule(ctx, policy, decision, a, "added")
}

/// Adds the rule `a` describes (its protocol aside), says so, and applies it to running sandboxes.
fn add_rule<R: Runner>(
    ctx: &Ctx<R>,
    policy: &mut Policy,
    decision: Decision,
    a: RuleArgs,
    created_via: &str,
) -> Result<()> {
    let parsed = parse_list(&a.resources)?;
    if decision == Decision::Deny {
        guard_bound_secrets(ctx, a.sandbox.as_deref(), &parsed)?;
    }
    let before = policy.clone();
    let id = policy.add_rule(
        a.sandbox.as_deref(),
        decision,
        &a.resources,
        created_via,
        a.method,
        a.path,
    )?;
    policy.save(&ctx.paths)?;
    writeln!(&ctx.out, "{} rule {id}: {}", decision.name(), a.resources)?;
    if decision == Decision::Deny {
        print_deny_notes(ctx, policy, a.sandbox.as_deref(), &parsed)?;
    }
    print_host_notes(
        ctx,
        &before,
        policy,
        a.sandbox.as_deref(),
        decision,
        &parsed,
    );
    provision::push_network(ctx, policy)
}

/// For an allow of `localhost[:PORT]` (host services, see `compile::HOST_GATEWAY`): smolvm opens
/// the gateway to every host port, not just this one.
fn localhost_warning(scope: Option<&str>, allows: &[Resource]) -> Option<String> {
    if !allows.iter().any(compile::is_host_services) {
        return None;
    }
    let to = scope.map_or("all sandboxes".to_string(), |s| format!("sandbox {s}"));
    Some(format!(
        "warning: smolvm can't open a single host port yet; this opens every port on your host's \
         localhost to {to}"
    ))
}

/// For an allow of `localhost[:PORT]`: the sandboxes in its scope (of `sandboxes`, name and
/// `sbx.host-access`) created without host access, which never get it. The kit builder never has
/// it, so recreating it wouldn't help.
fn without_access_note(scope: Option<&str>, sandboxes: &[(&str, bool)]) -> Option<String> {
    let names: Vec<&str> = sandboxes
        .iter()
        .filter(|(n, access)| !access && *n != BUILDER && scope.is_none_or(|s| s == *n))
        .map(|(n, _)| *n)
        .collect();
    (!names.is_empty()).then(|| {
        format!(
            "note: {} were created without host access; recreate them to use it",
            names.join(", ")
        )
    })
}

/// One note per open sandbox with host access that a rule change took its `localhost` rule
/// from: without an allow list, it reaches host loopback until it's recreated.
fn keeps_access_notes(before: &Policy, after: &Policy, sandboxes: &[(&str, bool)]) -> Vec<String> {
    sandboxes
        .iter()
        .filter(|(n, access)| {
            *access
                && compile::network(after, n, &[], true) == NetworkSpec::Open
                && compile::host_access(before, n)
                && !compile::host_access(after, n)
        })
        .map(|(n, _)| format!("note: {n} keeps host access until it's recreated"))
        .collect()
}

/// The localhost warning and host access notes (stderr) for a rule change from `before` to
/// `after`: `added` are the resources of a new rule with this decision in `scope` (none for a
/// removal). Sandboxes are listed only when a `localhost` rule is involved; a failure to list is
/// left to `push_network` to report.
fn print_host_notes<R: Runner>(
    ctx: &Ctx<R>,
    before: &Policy,
    after: &Policy,
    scope: Option<&str>,
    decision: Decision,
    added: &[Resource],
) {
    let allowed = decision == Decision::Allow;
    if allowed && let Some(w) = localhost_warning(scope, added) {
        eprintln!("{w}");
    }
    let localhost = |p: &Policy| {
        p.all_rules()
            .any(|(r, _)| r.parsed().any(|x| compile::is_host_services(&x)))
    };
    if !localhost(before) && !localhost(after) {
        return;
    }
    let Ok(sandboxes) = sandbox::list(&ctx.vm) else {
        return;
    };
    let sbs: Vec<(&str, bool)> = sandboxes
        .iter()
        .map(|s| (s.name(), s.meta.host_access))
        .collect();
    if allowed
        && added.iter().any(compile::is_host_services)
        && let Some(n) = without_access_note(scope, &sbs)
    {
        eprintln!("{n}");
    }
    for n in keeps_access_notes(before, after, &sbs) {
        eprintln!("{n}");
    }
}

fn print_deny_notes<R: Runner>(
    ctx: &Ctx<R>,
    policy: &Policy,
    scope: Option<&str>,
    denies: &[Resource],
) -> Result<()> {
    let (cidr, notes) = deny_notes(policy, scope, denies);
    if cidr {
        writeln!(
            &ctx.out,
            "note: deny CIDRs apply to sandboxes created from now on"
        )?;
    }
    // stderr, so stdout stays what sbx prints.
    for n in notes {
        eprintln!("{n}");
    }
    Ok(())
}

/// smolvm keeps a bound credential's hosts reachable, so a deny on them can't be honoured.
fn guard_bound_secrets<R: Runner>(
    ctx: &Ctx<R>,
    scope: Option<&str>,
    denies: &[Resource],
) -> Result<()> {
    let sandboxes = match sandbox::list(&ctx.vm) {
        Ok(s) => s,
        Err(e) => {
            crate::warning!(
                "couldn't check sandboxes for bound secrets ({e:#}); adding the rule anyway"
            );
            return Ok(());
        }
    };
    let secrets = SecretsFile::load(&ctx.paths).ok();
    for sb in sandboxes
        .iter()
        .filter(|s| scope.is_none_or(|n| n == s.name()))
    {
        if let Some((host, service)) = bound_conflict(
            &sb.meta.credential_hosts,
            &sb.meta.secrets,
            secrets.as_ref(),
            denies,
        ) {
            bail!(
                "can't deny {host}: sandbox {} has {service} bound to it; remove the secret and recreate the sandbox first",
                sb.name()
            );
        }
    }
    Ok(())
}

fn blocked_rows<R: Runner>(
    ctx: &Ctx<R>,
    only: Option<&str>,
    limit: usize,
) -> Result<Vec<log::LogRow>> {
    let mut events = Vec::new();
    for sb in sandbox::list(&ctx.vm)?
        .into_iter()
        .filter(|s| only.is_none_or(|n| n == s.name()))
    {
        events.push((
            sb.name().to_string(),
            ctx.vm.egress_events(&sb.machine, limit)?,
        ));
    }
    Ok(log::rows(&events))
}

pub fn render_log(rows: &[log::LogRow]) -> String {
    if rows.is_empty() {
        return "No blocked requests\n".into();
    }
    let head = [
        "SANDBOX",
        "TYPE",
        "HOST",
        "RULE",
        "REASON",
        "LAST SEEN",
        "COUNT",
    ];
    let mut lines = Vec::new();
    for r in rows {
        lines.push(vec![
            r.sandbox.clone(),
            "network".into(),
            r.host.clone(),
            "-".into(),
            "no allow rule".into(),
            r.last_seen.clone(),
            r.count.to_string(),
        ]);
    }
    table(&head, lines)
}

/// How many recent blocked requests per sandbox approvals look at (`policy log` shows 50).
const APPROVAL_EVENTS: usize = 200;

/// Approvals are blocked hosts no rule mentions yet; the host is the id.
fn approval<R: Runner>(ctx: &Ctx<R>, policy: &mut Policy, cmd: ApprovalCmd) -> Result<i32> {
    let rows = blocked_rows(ctx, None, APPROVAL_EVENTS)?;
    let pending = log::pending(policy, &rows);
    match cmd {
        ApprovalCmd::Ls { quiet, output } => {
            if quiet {
                for r in &pending {
                    writeln!(&ctx.out, "{}", r.host)?;
                }
            } else if let Some(text) = output.structured(&pending)? {
                write!(&ctx.out, "{text}")?;
            } else if pending.is_empty() {
                writeln!(&ctx.out, "No pending approvals")?;
            } else {
                let head = ["ID", "SANDBOX", "LAST SEEN", "COUNT"];
                let mut lines = Vec::new();
                for r in &pending {
                    lines.push(vec![
                        r.host.clone(),
                        r.sandbox.clone(),
                        r.last_seen.clone(),
                        r.count.to_string(),
                    ]);
                }
                write!(&ctx.out, "{}", table(&head, lines))?;
            }
        }
        ApprovalCmd::Inspect { id } => {
            let r = rows
                .iter()
                .find(|r| r.host == id)
                .with_context(|| format!("no blocked request for '{id}'"))?;
            writeln!(
                &ctx.out,
                "Host: {}\nSandbox: {}\nBlocked: {} time(s), last {}",
                r.host, r.sandbox, r.count, r.last_seen
            )?;
        }
        ApprovalCmd::Respond {
            id,
            decision,
            sandbox,
        } => {
            let seen: Vec<&str> = rows
                .iter()
                .filter(|r| r.host == id)
                .map(|r| r.sandbox.as_str())
                .collect();
            if seen.is_empty() {
                bail!("no blocked request for '{id}'\n  try: bento policy approval ls");
            }
            if let Some(s) = sandbox.as_deref()
                && !seen.contains(&s)
            {
                bail!(
                    "sandbox {s} has no blocked request for '{id}': it was blocked in {}",
                    seen.join(", ")
                );
            }
            let rule = RuleArgs {
                resources: id,
                sandbox,
                protocol: None,
                method: None,
                path: None,
            };
            add_rule(ctx, policy, decision, rule, "approval")?;
        }
    }
    Ok(0)
}

fn check<R: Runner>(ctx: &Ctx<R>, policy: &Policy, a: &CheckArgs) -> Result<i32> {
    // --verbose is accepted as is: the deciding reason is always printed.
    if a.protocol.as_deref().is_some_and(|p| p != "tcp") {
        return Err(Unsupported("only tcp network rules are supported".into()).into());
    }
    let bound = match &a.sandbox {
        Some(n) => sandbox::find(&ctx.vm, n)
            .ok()
            .flatten()
            .map(|s| s.meta.credential_hosts)
            .unwrap_or_default(),
        None => Vec::new(),
    };
    let v = compile::check(policy, a.sandbox.as_deref(), &bound, &a.target);
    // sbx's shape, plus `reason` (the rule or default that decided). A bare host means port 443.
    let target = match a.target.matches(':').count() {
        0 => format!("{}:443", a.target),
        // A bare IPv6 address.
        n if n > 1 && !a.target.contains(']') => format!("[{}]:443", a.target),
        _ => a.target.clone(),
    };
    let doc = serde_json::json!({
        "action": "net:connect:tcp",
        "allowed": v.allowed,
        "context": a.sandbox.as_deref().unwrap_or("global"),
        "governance": { "active": false },
        "reason": v.reason,
        "resource_type": "net:domain",
        "resource_value": target,
        "target": target,
        "type": "network",
    });
    if let Some(text) = a.output.structured(&doc)? {
        write!(&ctx.out, "{text}")?;
        return Ok(if v.allowed { 0 } else { 1 });
    }
    writeln!(
        &ctx.out,
        "{}: {} ({})",
        a.target,
        if v.allowed { "allowed" } else { "denied" },
        v.reason
    )?;
    Ok(if v.allowed { 0 } else { 1 })
}

/// One rule as sbx 0.53's `policy ls --json` has it, keys in sbx's order.
#[derive(Serialize)]
struct LsRule {
    id: String,
    /// The id, except `approval:<id>` for an approved request and `kit:<sandbox>` for kit rules.
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy_id: Option<String>,
    /// Only the fallback has one, in place of a `policy_id`.
    #[serde(skip_serializing_if = "Option::is_none")]
    policy_name: Option<&'static str>,
    scope: String,
    applies_to: String,
    /// `network`, or `http` for a rule with a method or a path.
    resource_type: &'static str,
    decision: &'static str,
    resources: Vec<String>,
    origin: &'static str,
    /// sbx's source: `local` or `kit` (and smolbento's `mcp`).
    layer: &'static str,
    status: &'static str,
    /// What the fallback is, or how smolvm enforces the rule more loosely than sbx would.
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    editable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    sandbox_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    provenance: Option<Provenance>,
    actions: Vec<&'static str>,
    #[serde(skip)]
    method: Option<String>,
    #[serde(skip)]
    path: Option<String>,
}

#[derive(Serialize)]
struct Provenance {
    created_via: &'static str,
}

const TCP: &str = "net:connect:tcp";
const UDP: &str = "net:connect:udp";
const FALLBACK_REASON: &str = "Implicit fallback when no applicable policy decides the request.";

impl LsRule {
    /// What the POLICY column of the table shows.
    fn policy(&self) -> &str {
        self.policy_id
            .as_deref()
            .or(self.policy_name)
            .unwrap_or("-")
    }

    fn created_via(&self) -> Option<&'static str> {
        self.provenance.as_ref().map(|p| p.created_via)
    }

    fn protocols(&self) -> Vec<&'static str> {
        self.actions
            .iter()
            .map(|a| a.trim_start_matches("net:connect:"))
            .collect()
    }
}

/// A rule of `policy` in `scope` (a sandbox, else global), for the listing.
fn ls_rule(rule: &Rule, scope: Option<&str>) -> LsRule {
    let mut notes: Vec<String> = rule
        .parsed()
        .filter_map(|r| {
            let note = r.note(rule.decision == Decision::Deny)?;
            Some(format!("{}: {note}", r.raw))
        })
        .collect();
    for (label, value) in [("method", &rule.method), ("path", &rule.path)] {
        if let Some(v) = value {
            notes.push(format!("{label} {v} not enforced"));
        }
    }
    let layer = rule.source();
    let policy_id = match (layer, scope) {
        ("local", None) => "local-policy".to_string(),
        ("local", Some(s)) => format!("sandbox:{s}"),
        (layer, Some(s)) => format!("{layer}:{s}"),
        (layer, None) => layer.to_string(),
    };
    let scoped = scope.map(|s| format!("sandbox:{s}"));
    LsRule {
        name: match rule.created_via.as_str() {
            "approval" => format!("approval:{}", rule.id),
            _ => rule.id.clone(),
        },
        id: rule.id.clone(),
        policy_id: Some(policy_id),
        policy_name: None,
        scope: scoped.clone().unwrap_or_else(|| "global".into()),
        applies_to: scoped.unwrap_or_else(|| "all".into()),
        resource_type: if rule.method.is_some() || rule.path.is_some() {
            "http"
        } else {
            "network"
        },
        decision: rule.decision.name(),
        resources: rule.resources.clone(),
        origin: if scope.is_some() { "scoped" } else { "local" },
        layer,
        status: "active",
        reason: (!notes.is_empty()).then(|| notes.join("; ")),
        editable: true,
        sandbox_id: scope.map(String::from),
        provenance: Some(Provenance {
            created_via: match rule.created_via.as_str() {
                "approval" => "approval",
                _ if layer == "local" => "added",
                _ => "provisioned",
            },
        }),
        // As in sbx: an allow opens tcp, a deny closes both.
        actions: match rule.decision {
            Decision::Allow => vec![TCP],
            Decision::Deny => vec![TCP, UDP],
        },
        method: rule.method.clone(),
        path: rule.path.clone(),
    }
}

/// Every rule `policy ls` lists, in sbx's order: the balanced preset's groups, the rules (for
/// `sandbox`: the global ones and its own), each sandbox's kit rules, and last the fallback, which
/// is how sbx shows what happens when no rule decides: the mode.
fn ls_rules(policy: &Policy, sandbox: Option<&str>) -> Vec<LsRule> {
    let mut rows = Vec::new();
    if policy.mode == Some(Mode::Balanced) {
        for (group, resources) in presets::GROUPS {
            rows.push(LsRule {
                id: group.to_string(),
                name: group.to_string(),
                policy_id: Some("local-policy".into()),
                policy_name: None,
                scope: "global".into(),
                applies_to: "all".into(),
                resource_type: "network",
                decision: "allow",
                resources: resources.iter().map(|r| r.to_string()).collect(),
                origin: "local",
                layer: "local",
                status: "active",
                reason: None,
                editable: true,
                sandbox_id: None,
                provenance: Some(Provenance {
                    created_via: "default",
                }),
                actions: vec![TCP],
                method: None,
                path: None,
            });
        }
    }
    let rules: Vec<_> = match sandbox {
        Some(s) => policy.rules_for(Some(s)).collect(),
        None => policy.all_rules().collect(),
    };
    // sbx shows one `kit:<sandbox>` rule per sandbox, whatever kits made it. The per-kit rules
    // stay in the store (rollback and `kit add` need them); only the listing aggregates.
    let mut kit_rows: Vec<LsRule> = Vec::new();
    for (rule, scope) in rules {
        // sbx doesn't list install-only hosts after create.
        if rule.is_kit_install() {
            continue;
        }
        let row = ls_rule(rule, scope);
        let note = row.reason.clone();
        // (Kit rules always carry a sandbox scope; a scopeless one lists as a plain rule.)
        let Some(sandbox) = scope.filter(|_| row.layer == "kit") else {
            rows.push(row);
            continue;
        };
        let name = format!("kit:{sandbox}");
        let at = kit_rows
            .iter()
            .position(|r| r.name == name && r.decision == row.decision);
        let kit = match at {
            Some(i) => &mut kit_rows[i],
            None => {
                // The allow rule is the one sbx shows; a kit deny rule gets its own id.
                let id = match rule.decision {
                    Decision::Allow => crate::policy::kit_rule_id(sandbox),
                    Decision::Deny => crate::policy::kit_rule_id(&format!("{sandbox}|deny")),
                };
                kit_rows.push(LsRule {
                    id,
                    name,
                    resource_type: "network",
                    resources: Vec::new(),
                    reason: None,
                    // They change with their kits, not by `policy rm`.
                    editable: false,
                    method: None,
                    path: None,
                    ..row
                });
                kit_rows.last_mut().expect("just pushed")
            }
        };
        for r in &rule.resources {
            if !kit.resources.contains(r) {
                kit.resources.push(r.clone());
            }
        }
        if let Some(note) = note {
            kit.reason = Some(match kit.reason.take() {
                Some(earlier) => format!("{earlier}; {note}"),
                None => note,
            });
        }
    }
    rows.extend(kit_rows);
    let (id, decision) = match policy.current_mode() {
        Mode::AllowAll => ("default-allow-all", "allow"),
        Mode::Balanced | Mode::DenyAll => ("default-deny-all", "deny"),
    };
    rows.push(LsRule {
        id: id.into(),
        name: id.into(),
        policy_id: None,
        policy_name: Some(id),
        scope: "global".into(),
        applies_to: "all".into(),
        resource_type: "network",
        decision,
        resources: vec!["**".into()],
        origin: "local",
        layer: "local",
        status: "active",
        reason: Some(FALLBACK_REASON.into()),
        editable: false,
        sandbox_id: None,
        provenance: None,
        actions: vec![TCP, UDP],
        method: None,
        path: None,
    });
    rows
}

/// `policy ls`'s filters, each already checked.
#[derive(Default)]
struct LsFilter<'a> {
    decision: Option<&'a str>,
    /// `local`, `org` or `kit` (and smolbento's `mcp`). smolbento has no org rules.
    source: Option<&'a str>,
    created_via: Option<&'a str>,
    /// `network`, `http` or `filesystem` (smolbento has no filesystem rules); `None` for all.
    kind: Option<&'a str>,
    protocol: Option<&'a str>,
}

/// The filters `a` asks for. A bad value is refused in sbx's words where those were observed.
fn ls_filter(a: &PolicyLsArgs) -> Result<LsFilter<'_>> {
    let check =
        |flag: &str, value: &Option<String>, allowed: &[&str], what: &str, list: &str| match value
            .as_deref()
        {
            Some(v) if !allowed.contains(&v) => bail!(
                "invalid argument \"{v}\" for \"{flag}\" flag: invalid {what} \"{v}\": must be \
                 {list}\n  try: bento policy ls --help"
            ),
            _ => Ok(()),
        };
    check(
        "--type",
        &a.kind,
        &["all", "network", "http", "filesystem"],
        "type",
        "one of: all, network, http, filesystem",
    )?;
    check(
        "--created-via",
        &a.created_via,
        &["default", "added", "provisioned", "approval"],
        "creation method",
        "one of: default, added, provisioned, approval",
    )?;
    check(
        "--protocol",
        &a.protocol,
        &["tcp", "udp"],
        "protocol",
        "tcp or udp",
    )?;
    if let Some(d) = a
        .decision
        .as_deref()
        .filter(|d| !["allow", "deny"].contains(d))
    {
        bail!("--decision takes allow or deny, not '{d}'");
    }
    if let Some(s) = a
        .source
        .as_deref()
        .filter(|s| !["local", "org", "kit", "mcp"].contains(s))
    {
        bail!("--source takes local, org, kit or mcp, not '{s}'");
    }
    Ok(LsFilter {
        decision: a.decision.as_deref(),
        source: a.source.as_deref(),
        created_via: a.created_via.as_deref(),
        kind: a.kind.as_deref().filter(|k| *k != "all"),
        protocol: a.protocol.as_deref(),
    })
}

fn filtered(mut rows: Vec<LsRule>, f: &LsFilter) -> Vec<LsRule> {
    rows.retain(|r| {
        f.decision.is_none_or(|d| r.decision == d)
            && f.source.is_none_or(|s| r.layer == s)
            && f.created_via.is_none_or(|v| r.created_via() == Some(v))
            && f.kind.is_none_or(|k| r.resource_type == k)
            && f.protocol.is_none_or(|p| r.protocols().contains(&p))
    });
    rows
}

fn ls<R: Runner>(ctx: &Ctx<R>, policy: &Policy, a: &PolicyLsArgs) -> Result<()> {
    // smolbento has no governance profiles.
    super::refuse(&[(a.profile.is_some(), "--profile")])?;
    // --include-inactive is accepted as is: every smolbento rule is active.
    let filter = ls_filter(a)?;
    if let Some(s) = &a.sandbox {
        sandbox::get(&ctx.vm, s)?;
    }
    let rows = filtered(ls_rules(policy, a.sandbox.as_deref()), &filter);
    if a.quiet {
        for r in &rows {
            writeln!(&ctx.out, "{}", r.id)?;
        }
        return Ok(());
    }
    #[derive(Serialize)]
    struct Doc<'a> {
        rules: &'a [LsRule],
    }
    if let Some(text) = a.output.structured(&Doc { rules: &rows })? {
        write!(&ctx.out, "{text}")?;
        return Ok(());
    }
    if rows.is_empty() {
        writeln!(&ctx.out, "No policies match the selected filters")?;
        return Ok(());
    }
    if a.wide {
        write!(&ctx.out, "{}", render_wide(&rows))?;
        return Ok(());
    }
    match &a.sandbox {
        Some(s) => write!(&ctx.out, "{}", render_sandbox(s, &rows))?,
        None => write!(&ctx.out, "{}", render_policies(&rows))?,
    }
    // stderr, so the table stays what sbx prints.
    if let Some(note) = ls_note(&rows) {
        eprintln!("{note}");
    }
    Ok(())
}

/// For the listings without each rule's status (stderr): how many listed rules smolvm enforces
/// more loosely than sbx would.
fn ls_note(rows: &[LsRule]) -> Option<String> {
    let n = rows
        .iter()
        .filter(|r| r.policy_name.is_none() && r.reason.is_some())
        .count();
    (n > 0)
        .then(|| format!("note: {n} rule(s) aren't fully enforced; see `bento policy ls --wide`"))
}

fn hosts(n: usize) -> String {
    format!("{n} host{}", if n == 1 { "" } else { "s" })
}

/// sbx's table: one row per policy, sorted by name, with how many resources it allows and denies.
fn render_policies(rows: &[LsRule]) -> String {
    let mut policies: BTreeMap<&str, Vec<&LsRule>> = BTreeMap::new();
    for r in rows {
        policies.entry(r.policy()).or_default().push(r);
    }
    let mut lines = Vec::new();
    for (name, rules) in policies {
        let first = rules[0];
        let summary = if first.policy_name.is_some() {
            format!("network: {} when no rule decides", first.decision)
        } else {
            let mut parts = Vec::new();
            for kind in ["network", "http"] {
                let count = |decision: &str| -> usize {
                    rules
                        .iter()
                        .filter(|r| r.resource_type == kind && r.decision == decision)
                        .map(|r| r.resources.len())
                        .sum()
                };
                let counts: Vec<String> = ["allow", "deny"]
                    .iter()
                    .filter(|d| count(d) > 0)
                    .map(|d| format!("{} {d}", count(d)))
                    .collect();
                if !counts.is_empty() {
                    parts.push(format!("{kind}: {}", counts.join(", ")));
                }
            }
            parts.join("; ")
        };
        lines.push(vec![
            name.to_string(),
            first.layer.to_string(),
            first.applies_to.clone(),
            summary,
        ]);
    }
    table(&["POLICY", "SOURCE", "APPLIES TO", "SUMMARY"], lines)
}

/// sbx's `policy ls SANDBOX`: what applies to one sandbox, and from which policies. It has no
/// FILESYSTEM section: smolbento has no filesystem policy.
fn render_sandbox(sandbox: &str, rows: &[LsRule]) -> String {
    let mut out = format!("  Policy for sandbox:  {sandbox}\n\nNETWORK\n");
    for decision in ["allow", "deny"] {
        let rules: Vec<&LsRule> = rows
            .iter()
            .filter(|r| r.policy_name.is_none() && r.decision == decision)
            .collect();
        if rules.is_empty() {
            continue;
        }
        let from: BTreeSet<&str> = rules.iter().map(|r| r.policy()).collect();
        let n = rules.iter().map(|r| r.resources.len()).sum();
        let from: Vec<&str> = from.into_iter().collect();
        out.push_str(&format!(
            "  • {decision} {} from {}\n",
            hosts(n),
            from.join(", ")
        ));
    }
    if let Some(r) = rows.iter().find(|r| r.policy_name.is_some()) {
        out.push_str(&format!(
            "  • fallback: {} when no rule decides from {}\n",
            r.decision, r.id
        ));
    }
    out.push('\n');
    out
}

/// Lines of at most `width` characters, broken at spaces (a longer word gets its own line).
fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    for word in text.split(' ') {
        match lines.last_mut() {
            Some(line) if line.chars().count() + 1 + word.chars().count() <= width => {
                line.push(' ');
                line.push_str(word);
            }
            _ => lines.push(word.to_string()),
        }
    }
    lines
}

/// sbx's `--wide` table: a row per rule, with a line per resource (sorted) and a blank line
/// between rules. STATUS is there only when some rule has more than `active` to say; it wraps
/// at sbx's width. Unlike `table`, lines keep their padding, as sbx's do.
fn render_wide(rows: &[LsRule]) -> String {
    const STATUS: usize = 12;
    let dash = |v: Option<&str>| v.unwrap_or("-").to_string();
    let mut lines: Vec<Vec<String>> = vec![
        [
            "SOURCE",
            "CREATED VIA",
            "APPLIES TO",
            "POLICY",
            "POLICY_ID",
            "RULE",
            "RULE_ID",
            "TYPE",
            "METHOD",
            "PATH",
            "DECISION",
            "PROTOCOLS",
            "STATUS",
            "RESOURCES",
        ]
        .map(String::from)
        .to_vec(),
    ];
    for (i, r) in rows.iter().enumerate() {
        if i > 0 {
            lines.push(vec![String::new(); lines[0].len()]);
        }
        let status = match &r.reason {
            Some(reason) => wrap(&format!("{} — {reason}", r.status), 26),
            None => vec![r.status.to_string()],
        };
        let mut resources = r.resources.clone();
        resources.sort();
        for n in 0..resources.len().max(status.len()) {
            let first = |cell: String| if n == 0 { cell } else { String::new() };
            // Each resource line repeats the method and path.
            let each = |cell: String| {
                if n < resources.len() {
                    cell
                } else {
                    String::new()
                }
            };
            lines.push(vec![
                first(r.layer.to_string()),
                first(dash(r.created_via())),
                first(r.applies_to.clone()),
                first(dash(r.policy_name)),
                first(dash(r.policy_id.as_deref())),
                // Only kit rules have a name of their own to show.
                first(dash((r.layer == "kit").then_some(r.name.as_str()))),
                first(r.id.clone()),
                first(r.resource_type.to_string()),
                each(dash(r.method.as_deref())),
                each(dash(r.path.as_deref())),
                first(r.decision.to_string()),
                first(r.protocols().join(",")),
                status.get(n).cloned().unwrap_or_default(),
                resources.get(n).cloned().unwrap_or_default(),
            ]);
        }
    }
    if rows.iter().all(|r| r.reason.is_none()) {
        for line in &mut lines {
            line.remove(STATUS);
        }
    }
    let widths: Vec<usize> = (0..lines[0].len())
        .map(|c| {
            lines
                .iter()
                .map(|l| l[c].chars().count())
                .max()
                .unwrap_or(0)
        })
        .collect();
    let mut out = String::new();
    for line in lines {
        let last = line.len() - 1;
        for (c, cell) in line.iter().enumerate() {
            out.push_str(cell);
            if c < last {
                out.push_str(&" ".repeat(widths[c] - cell.chars().count() + 3));
            }
        }
        out.push('\n');
    }
    out
}

#[cfg(test)]
#[path = "policy_tests.rs"]
mod tests;
