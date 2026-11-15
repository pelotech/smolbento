//! `bento policy`: the network policy.

use anyhow::{Context, Result, bail};
use serde::Serialize;
use std::io::Write;

use super::{
    ApprovalCmd, CheckArgs, CheckKind, Ctx, Format, PolicyCmd, PolicyRmKind, RuleArgs, RuleKind,
    Unsupported, confirm, table,
};
use crate::policy::log;
use crate::policy::notes::{bound_conflict, deny_notes};
use crate::policy::rules::{Resource, parse_list};
use crate::policy::{Decision, Mode, Policy, compile, presets};
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
            eprintln!("warning: couldn't list sandboxes to stop them ({e:#})");
            return;
        }
    };
    for sb in sandboxes.iter().filter(|s| s.is_running()) {
        if let Err(e) = super::lifecycle::stop_sandbox(ctx, sb) {
            eprintln!("warning: couldn't stop {} ({e:#})", sb.name());
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
        PolicyCmd::Ls(a) => {
            for (flag, set) in [
                ("--created-via", a.created_via.is_some()),
                ("--type", a.kind.is_some()),
                ("--protocol", a.protocol.is_some()),
                ("--include-inactive", a.include_inactive),
            ] {
                if set {
                    return Err(Unsupported(format!(
                        "`bento policy ls {flag}` is not implemented yet"
                    ))
                    .into());
                }
            }
            let decision = match a.decision.as_deref() {
                None => None,
                Some("allow") => Some(Decision::Allow),
                Some("deny") => Some(Decision::Deny),
                Some(other) => bail!("--decision takes allow or deny, not '{other}'"),
            };
            let source = match a.source.as_deref() {
                None => None,
                Some(s @ ("local" | "org" | "kit" | "mcp")) => Some(s),
                Some(other) => bail!("--source takes local, org, kit or mcp, not '{other}'"),
            };
            let format = a.output.pick();
            let opts = LsOpts {
                sandbox: a.sandbox.as_deref(),
                source,
                decision,
                format,
                wide: a.wide,
                quiet: a.quiet,
            };
            let rows = ls_rows(&policy, &opts);
            write!(&ctx.out, "{}", render_ls(&policy, &rows, &opts)?)?;
            // stderr, so the table stays what sbx prints.
            if format == Format::Table
                && !a.wide
                && !a.quiet
                && let Some(note) = ls_note(&rows)
            {
                eprintln!("{note}");
            }
        }
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
    let parsed = parse_list(&a.resources)?;
    if decision == Decision::Deny {
        guard_bound_secrets(ctx, a.sandbox.as_deref(), &parsed)?;
    }
    let before = policy.clone();
    let id = policy.add_rule(
        a.sandbox.as_deref(),
        decision,
        &a.resources,
        "added",
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
            eprintln!(
                "warning: couldn't check sandboxes for bound secrets ({e:#}); adding the rule anyway"
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
    let mut lines = vec![
        [
            "SANDBOX",
            "TYPE",
            "HOST",
            "RULE",
            "REASON",
            "LAST SEEN",
            "COUNT",
        ]
        .map(String::from)
        .to_vec(),
    ];
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
    table(lines)
}

/// How many recent blocked requests per sandbox approvals look at (`policy log` shows 50).
const APPROVAL_EVENTS: usize = 200;

/// Approvals are blocked hosts no rule mentions yet; the host is the id.
fn approval<R: Runner>(ctx: &Ctx<R>, policy: &mut Policy, cmd: ApprovalCmd) -> Result<i32> {
    let rows = blocked_rows(ctx, None, APPROVAL_EVENTS)?;
    let pending = log::pending(policy, &rows);
    match cmd {
        ApprovalCmd::Ls { output } => {
            if let Some(text) = output.structured(&pending)? {
                write!(&ctx.out, "{text}")?;
            } else if pending.is_empty() {
                writeln!(&ctx.out, "No pending approvals")?;
            } else {
                let mut lines = vec![
                    ["ID", "SANDBOX", "LAST SEEN", "COUNT"]
                        .map(String::from)
                        .to_vec(),
                ];
                for r in &pending {
                    lines.push(vec![
                        r.host.clone(),
                        r.sandbox.clone(),
                        r.last_seen.clone(),
                        r.count.to_string(),
                    ]);
                }
                write!(&ctx.out, "{}", table(lines))?;
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
                bail!("no blocked request for '{id}' (see `bento policy approval ls`)");
            }
            if let Some(s) = sandbox.as_deref()
                && !seen.contains(&s)
            {
                bail!(
                    "sandbox {s} has no blocked request for '{id}': it was blocked in {}",
                    seen.join(", ")
                );
            }
            let parsed = parse_list(&id)?;
            if decision == Decision::Deny {
                guard_bound_secrets(ctx, sandbox.as_deref(), &parsed)?;
            }
            let before = policy.clone();
            let rule =
                policy.add_rule(sandbox.as_deref(), decision, &id, "approval", None, None)?;
            policy.save(&ctx.paths)?;
            writeln!(&ctx.out, "{} rule {rule}: {id}", decision.name())?;
            if decision == Decision::Deny {
                print_deny_notes(ctx, policy, sandbox.as_deref(), &parsed)?;
            }
            print_host_notes(ctx, &before, policy, sandbox.as_deref(), decision, &parsed);
            provision::push_network(ctx, policy)?;
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

#[derive(Serialize)]
struct LsRow {
    id: String,
    /// Only kit rows have one: `kit:<sandbox>`.
    #[serde(skip_serializing_if = "String::is_empty")]
    name: String,
    source: String,
    applies_to: String,
    decision: String,
    resources: Vec<String>,
    notes: Vec<String>,
    /// Only kit rows say so (`false`); they change with their kits, not by `policy rm`.
    #[serde(skip_serializing_if = "is_true")]
    editable: bool,
}

fn is_true(b: &bool) -> bool {
    *b
}

/// What `policy ls` lists, and how.
#[derive(Default)]
struct LsOpts<'a> {
    sandbox: Option<&'a str>,
    /// `local`, `org` or `kit`; smolbento has no org rules, and the balanced preset counts as local.
    source: Option<&'a str>,
    decision: Option<Decision>,
    format: Format,
    wide: bool,
    quiet: bool,
}

/// For the table without --wide (stderr): how many listed rules have enforcement notes.
fn ls_note(rows: &[LsRow]) -> Option<String> {
    let n = rows.iter().filter(|r| !r.notes.is_empty()).count();
    (n > 0)
        .then(|| format!("note: {n} rule(s) aren't fully enforced; see `bento policy ls --wide`"))
}

fn ls_rows(policy: &Policy, opts: &LsOpts) -> Vec<LsRow> {
    let mut rows = Vec::new();
    if policy.mode == Some(Mode::Balanced) {
        for (group, resources) in presets::GROUPS {
            rows.push(LsRow {
                id: group.to_string(),
                source: "default".into(),
                applies_to: "all".into(),
                decision: "allow".into(),
                resources: resources.iter().map(|r| r.to_string()).collect(),
                notes: Vec::new(),
                editable: true,
                name: String::new(),
            });
        }
    }
    let rules: Vec<_> = match opts.sandbox {
        Some(s) => policy.rules_for(Some(s)).collect(),
        None => policy.all_rules().collect(),
    };
    // sbx shows one `kit:<sandbox>` policy per sandbox, whatever kits made it. The per-kit rules
    // stay in the store (rollback and `kit add` need them); only the listing aggregates.
    let mut kit_rows: Vec<LsRow> = Vec::new();
    for (rule, scope) in rules {
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
        // sbx doesn't list install-only hosts after create.
        if rule.is_kit_install() {
            continue;
        }
        if rule.source() == "kit"
            && let Some(sandbox) = scope
        {
            // (Kit rules always carry a sandbox scope; a scopeless one lists as a plain rule.)
            let name = format!("kit:{sandbox}");
            let decision = rule.decision.name();
            let at = kit_rows
                .iter()
                .position(|r| r.name == name && r.decision == decision);
            let row = match at {
                Some(i) => &mut kit_rows[i],
                None => {
                    // The allow rule is the one sbx shows; a kit deny rule gets its own id.
                    let id = match rule.decision {
                        Decision::Allow => crate::policy::kit_rule_id(sandbox),
                        Decision::Deny => crate::policy::kit_rule_id(&format!("{sandbox}|deny")),
                    };
                    kit_rows.push(LsRow {
                        id,
                        name,
                        source: "kit".into(),
                        applies_to: format!("sandbox:{sandbox}"),
                        decision: decision.into(),
                        resources: Vec::new(),
                        notes: Vec::new(),
                        editable: false,
                    });
                    kit_rows.last_mut().expect("just pushed")
                }
            };
            for r in &rule.resources {
                if !row.resources.contains(r) {
                    row.resources.push(r.clone());
                }
            }
            row.notes.extend(notes);
            continue;
        }
        rows.push(LsRow {
            id: rule.id.clone(),
            name: String::new(),
            source: rule.source().into(),
            applies_to: scope.unwrap_or("all").into(),
            decision: rule.decision.name().into(),
            resources: rule.resources.clone(),
            notes,
            editable: true,
        });
    }
    rows.extend(kit_rows);
    if let Some(d) = opts.decision {
        rows.retain(|r| r.decision == d.name());
    }
    if let Some(want) = opts.source {
        rows.retain(|r| match r.source.as_str() {
            "default" => want == "local",
            kind => kind == want,
        });
    }
    rows
}

fn render_ls(policy: &Policy, rows: &[LsRow], opts: &LsOpts) -> Result<String> {
    let wide = opts.wide;
    if opts.quiet {
        return Ok(rows.iter().map(|r| format!("{}\n", r.id)).collect());
    }
    match opts.format {
        Format::Json => Ok(format!("{}\n", serde_json::to_string_pretty(rows)?)),
        Format::Yaml => Ok(serde_saphyr::to_string(&rows)?),
        Format::Table => {
            let mode = policy.mode.map_or("not chosen", Mode::name);
            let mut lines = vec![
                ["ID", "SOURCE", "APPLIES TO", "DECISION", "RESOURCES"]
                    .map(String::from)
                    .to_vec(),
            ];
            if wide {
                lines[0].insert(1, "NAME".into());
                lines[0].push("NOTES".into());
            }
            for r in rows {
                let resources = if !r.editable && !wide {
                    format!("network: {} {}", r.resources.len(), r.decision)
                } else if wide || r.resources.len() <= 3 {
                    r.resources.join(", ")
                } else {
                    format!("{} rules", r.resources.len())
                };
                let mut line = vec![
                    r.id.clone(),
                    r.source.clone(),
                    r.applies_to.clone(),
                    r.decision.clone(),
                    resources,
                ];
                if wide {
                    line.insert(
                        1,
                        if r.name.is_empty() {
                            "-".into()
                        } else {
                            r.name.clone()
                        },
                    );
                    line.push(r.notes.join("; "));
                }
                lines.push(line);
            }
            Ok(format!("Mode: {mode}\n{}", table(lines)))
        }
    }
}

#[cfg(test)]
#[path = "policy_tests.rs"]
mod tests;
