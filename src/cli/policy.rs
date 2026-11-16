//! `bento policy`: the network policy.

use anyhow::{Context, Result, bail};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;

use super::{
    ApprovalCmd, CheckArgs, CheckKind, Ctx, PolicyCmd, PolicyLsArgs, PolicyRmKind, RuleArgs,
    RuleKind, Unsupported, aligned, confirm, plural, table,
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
    decision: Decision,
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
    /// A network rule for every sandbox, in `local-policy`. Every listed rule starts from this
    /// and changes what differs.
    fn global(id: &str, decision: Decision, resources: Vec<String>) -> Self {
        LsRule {
            id: id.into(),
            name: id.into(),
            policy_id: Some("local-policy".into()),
            policy_name: None,
            scope: "global".into(),
            applies_to: "all".into(),
            resource_type: "network",
            decision,
            resources,
            origin: "local",
            layer: "local",
            status: "active",
            reason: None,
            editable: true,
            sandbox_id: None,
            provenance: None,
            // As in sbx: an allow opens tcp, a deny closes both.
            actions: match decision {
                Decision::Allow => vec![TCP],
                Decision::Deny => vec![TCP, UDP],
            },
            method: None,
            path: None,
        }
    }

    /// The fallback is the one rule with a `policy_name`, and without a `policy_id`.
    fn is_fallback(&self) -> bool {
        self.policy_name.is_some()
    }

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

/// How smolvm enforces `rule` more loosely than sbx would, a note per resource and qualifier.
fn rule_notes(rule: &Rule) -> Vec<String> {
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
    notes
}

/// A rule's `reason`: its notes, if it has any.
fn reason(notes: &[String]) -> Option<String> {
    (!notes.is_empty()).then(|| notes.join("; "))
}

/// A rule of `policy` in `scope` (a sandbox, else global), for the listing.
fn ls_rule(rule: &Rule, scope: Option<&str>) -> LsRule {
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
        policy_id: Some(policy_id),
        scope: scoped.clone().unwrap_or_else(|| "global".into()),
        applies_to: scoped.unwrap_or_else(|| "all".into()),
        resource_type: if rule.method.is_some() || rule.path.is_some() {
            "http"
        } else {
            "network"
        },
        origin: if scope.is_some() { "scoped" } else { "local" },
        layer,
        reason: reason(&rule_notes(rule)),
        sandbox_id: scope.map(String::from),
        provenance: Some(Provenance {
            created_via: match rule.created_via.as_str() {
                "approval" => "approval",
                _ if layer == "local" => "added",
                _ => "provisioned",
            },
        }),
        method: rule.method.clone(),
        path: rule.path.clone(),
        ..LsRule::global(&rule.id, rule.decision, rule.resources.clone())
    }
}

/// The one `kit:<sandbox>` rule sbx shows for a sandbox's kit `rules` with this decision (at
/// least one), whatever kits made them: their resources and notes, each once. The per-kit rules
/// stay in the store (rollback and `kit add` need them); only the listing aggregates.
fn kit_rule(sandbox: &str, decision: Decision, rules: &[&Rule]) -> LsRule {
    let (mut resources, mut notes) = (Vec::new(), Vec::new());
    for rule in rules {
        for (list, new) in [
            (&mut resources, rule.resources.clone()),
            (&mut notes, rule_notes(rule)),
        ] {
            for x in new {
                if !list.contains(&x) {
                    list.push(x);
                }
            }
        }
    }
    LsRule {
        // The allow rule is the one sbx shows; a kit deny rule gets its own id.
        id: match decision {
            Decision::Allow => crate::policy::kit_rule_id(sandbox),
            Decision::Deny => crate::policy::kit_rule_id(&format!("{sandbox}|deny")),
        },
        name: format!("kit:{sandbox}"),
        // Whatever methods and paths its rules have, it lists as one network rule.
        resource_type: "network",
        resources,
        reason: reason(&notes),
        // They change with their kits, not by `policy rm`.
        editable: false,
        method: None,
        path: None,
        ..ls_rule(rules[0], Some(sandbox))
    }
}

/// What happens when no rule decides, which is how sbx shows the mode.
fn fallback_rule(mode: Mode) -> LsRule {
    let (id, decision) = match mode {
        Mode::AllowAll => ("default-allow-all", Decision::Allow),
        Mode::Balanced | Mode::DenyAll => ("default-deny-all", Decision::Deny),
    };
    LsRule {
        policy_id: None,
        policy_name: Some(id),
        reason: Some(FALLBACK_REASON.into()),
        editable: false,
        actions: vec![TCP, UDP],
        ..LsRule::global(id, decision, vec!["**".into()])
    }
}

/// Every rule `policy ls` lists, in sbx's order: the balanced preset's groups, the rules (for
/// `sandbox`: the global ones and its own), each sandbox's kit rules, and last the fallback.
fn ls_rules(policy: &Policy, sandbox: Option<&str>) -> Vec<LsRule> {
    let mut rows = Vec::new();
    if policy.mode == Some(Mode::Balanced) {
        for (group, resources) in presets::GROUPS {
            let resources = resources.iter().map(|r| r.to_string()).collect();
            rows.push(LsRule {
                provenance: Some(Provenance {
                    created_via: "default",
                }),
                ..LsRule::global(group, Decision::Allow, resources)
            });
        }
    }
    let rules: Vec<_> = match sandbox {
        Some(s) => policy.rules_for(Some(s)).collect(),
        None => policy.all_rules().collect(),
    };
    // Each sandbox's kit rules by decision, in the order they first appear.
    let mut kits: Vec<((&str, Decision), Vec<&Rule>)> = Vec::new();
    for (rule, scope) in rules {
        // sbx doesn't list install-only hosts after create.
        if rule.is_kit_install() {
            continue;
        }
        // (Kit rules always carry a sandbox scope; a scopeless one lists as a plain rule.)
        let Some(sandbox) = scope.filter(|_| rule.source() == "kit") else {
            rows.push(ls_rule(rule, scope));
            continue;
        };
        let key = (sandbox, rule.decision);
        match kits.iter_mut().find(|(k, _)| *k == key) {
            Some((_, group)) => group.push(rule),
            None => kits.push((key, vec![rule])),
        }
    }
    rows.extend(
        kits.iter()
            .map(|((sandbox, decision), rules)| kit_rule(sandbox, *decision, rules)),
    );
    rows.push(fallback_rule(policy.current_mode()));
    rows
}

/// Refuses a filter value that sbx refuses, in sbx's words (measured for these three flags).
/// clap checks `--decision`; a bad `--source` is refused in smolbento's own words.
fn check_filters(a: &PolicyLsArgs) -> Result<()> {
    let checks: [(&str, &Option<String>, &str, &[&str]); 3] = [
        (
            "--type",
            &a.kind,
            "type",
            &["all", "network", "http", "filesystem"],
        ),
        (
            "--created-via",
            &a.created_via,
            "creation method",
            &["default", "added", "provisioned", "approval"],
        ),
        ("--protocol", &a.protocol, "protocol", &["tcp", "udp"]),
    ];
    for (flag, value, what, allowed) in checks {
        if let Some(v) = value.as_deref().filter(|v| !allowed.contains(v)) {
            // sbx names two values as `a or b`, and more as `one of: a, b, c`.
            let list = match allowed {
                [a, b] => format!("{a} or {b}"),
                _ => format!("one of: {}", allowed.join(", ")),
            };
            bail!(
                "invalid argument \"{v}\" for \"{flag}\" flag: invalid {what} \"{v}\": must be \
                 {list}\n  try: bento policy ls --help"
            );
        }
    }
    // smolbento has no org rules: `org` matches nothing.
    if let Some(s) = a
        .source
        .as_deref()
        .filter(|s| !["local", "org", "kit", "mcp"].contains(s))
    {
        bail!("--source takes local, org, kit or mcp, not '{s}'");
    }
    Ok(())
}

/// The rows the filters of `a` (already checked) leave.
fn filtered(mut rows: Vec<LsRule>, a: &PolicyLsArgs) -> Vec<LsRule> {
    // `--type all` is every type. smolbento has no filesystem rules.
    let kind = a.kind.as_deref().filter(|k| *k != "all");
    rows.retain(|r| {
        a.decision.is_none_or(|d| r.decision == d)
            && a.source.as_deref().is_none_or(|s| r.layer == s)
            && a.created_via
                .as_deref()
                .is_none_or(|v| r.created_via() == Some(v))
            && kind.is_none_or(|k| r.resource_type == k)
            && a.protocol
                .as_deref()
                .is_none_or(|p| r.protocols().contains(&p))
    });
    rows
}

fn ls<R: Runner>(ctx: &Ctx<R>, policy: &Policy, a: &PolicyLsArgs) -> Result<()> {
    // smolbento has no governance profiles.
    super::refuse(&[(a.profile.is_some(), "--profile")])?;
    // --include-inactive is accepted as is: every smolbento rule is active.
    check_filters(a)?;
    if let Some(s) = &a.sandbox {
        sandbox::get(&ctx.vm, s)?;
    }
    let rows = filtered(ls_rules(policy, a.sandbox.as_deref()), a);
    if a.quiet {
        for r in &rows {
            writeln!(&ctx.out, "{}", r.id)?;
        }
        return Ok(());
    }
    // A struct, not `serde_json::json!`, which would sort each rule's keys.
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
        .filter(|r| !r.is_fallback() && r.reason.is_some())
        .count();
    (n > 0)
        .then(|| format!("note: {n} rule(s) aren't fully enforced; see `bento policy ls --wide`"))
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
        let summary = if first.is_fallback() {
            format!("network: {} when no rule decides", first.decision.name())
        } else {
            let mut parts = Vec::new();
            for kind in ["network", "http"] {
                let counts: Vec<String> = [Decision::Allow, Decision::Deny]
                    .into_iter()
                    .filter_map(|decision| {
                        let n: usize = rules
                            .iter()
                            .filter(|r| r.resource_type == kind && r.decision == decision)
                            .map(|r| r.resources.len())
                            .sum();
                        (n > 0).then(|| format!("{n} {}", decision.name()))
                    })
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
    for decision in [Decision::Allow, Decision::Deny] {
        let rules: Vec<&LsRule> = rows
            .iter()
            .filter(|r| !r.is_fallback() && r.decision == decision)
            .collect();
        if rules.is_empty() {
            continue;
        }
        let from: BTreeSet<&str> = rules.iter().map(|r| r.policy()).collect();
        let n: usize = rules.iter().map(|r| r.resources.len()).sum();
        let from: Vec<&str> = from.into_iter().collect();
        out.push_str(&format!(
            "  • {} {n} host{} from {}\n",
            decision.name(),
            plural(n),
            from.join(", ")
        ));
    }
    if let Some(r) = rows.iter().find(|r| r.is_fallback()) {
        out.push_str(&format!(
            "  • fallback: {} when no rule decides from {}\n",
            r.decision.name(),
            r.id
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
    let head = [
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
    ];
    let dash = |v: Option<&str>| v.unwrap_or("-").to_string();
    let mut lines: Vec<Vec<String>> = vec![head.map(String::from).to_vec()];
    for (i, r) in rows.iter().enumerate() {
        if i > 0 {
            lines.push(vec![String::new(); head.len()]);
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
                first(r.decision.name().to_string()),
                first(r.protocols().join(",")),
                status.get(n).cloned().unwrap_or_default(),
                resources.get(n).cloned().unwrap_or_default(),
            ]);
        }
    }
    if rows.iter().all(|r| r.reason.is_none()) {
        let status = head.iter().position(|h| *h == "STATUS").expect("a column");
        for line in &mut lines {
            line.remove(status);
        }
    }
    aligned(&lines).iter().map(|l| format!("{l}\n")).collect()
}

#[cfg(test)]
#[path = "policy_tests.rs"]
mod tests;
