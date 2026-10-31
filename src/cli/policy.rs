//! `sbt policy`: the network policy.

use anyhow::{Context, Result, bail};
use serde::Serialize;
use std::io::Write;

use super::{
    ApprovalCmd, CheckArgs, CheckKind, Ctx, Format, PolicyCmd, PolicyRmKind, RuleArgs, RuleKind,
    Unsupported, confirm, plan, table,
};
use crate::kits::builder::BUILDER;
use crate::policy::log;
use crate::policy::rules::{Allow, Resource, parse_list};
use crate::policy::{Decision, Mode, Policy, compile, presets};
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
            plan::push_network(ctx, &policy)?;
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
                     (sbt policy deny network --sandbox {sb} <host>)"
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
            plan::push_network(ctx, &policy)?;
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
                        "`sbt policy ls {flag}` is not implemented yet"
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
                Some(s @ ("local" | "org" | "kit")) => Some(s),
                Some(other) => bail!("--source takes local, org or kit, not '{other}'"),
            };
            let format = if a.json {
                Format::Json
            } else {
                a.format.unwrap_or_default()
            };
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
        PolicyCmd::Inspect { id, json } => {
            let (rule, scope) = policy
                .find(&id)
                .with_context(|| format!("no rule '{id}'"))?;
            if json {
                writeln!(
                    &ctx.out,
                    "{}",
                    serde_json::to_string_pretty(
                        &serde_json::json!({ "scope": scope.unwrap_or("global"), "rule": rule })
                    )?
                )?;
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
            // Sandboxes created with smolbento 0.2.0's `--deny-network` stay deny-all.
            let legacy = if policy.sandboxes.values().any(|s| s.deny_network) {
                " (sandboxes created with smolbento 0.2.0's --deny-network stay deny-all)"
            } else {
                ""
            };
            confirm(
                ctx,
                &format!(
                    "Remove every policy rule and the chosen mode? Running sandboxes will be \
                     stopped{legacy}."
                ),
                force,
            )?;
            stop_running(ctx);
            policy.reset();
            policy.save(&ctx.paths)?;
            writeln!(
                &ctx.out,
                "Policy reset; the next start or create asks for a mode{legacy}"
            )?;
        }
        PolicyCmd::Log(a) => {
            if a.kind.as_deref().is_some_and(|k| k == "filesystem") {
                return Err(Unsupported("smolbento has no filesystem policy".into()).into());
            }
            let rows = blocked_rows(ctx, a.sandbox.as_deref(), a.limit)?;
            if a.json {
                writeln!(&ctx.out, "{}", serde_json::to_string_pretty(&rows)?)?;
            } else {
                write!(&ctx.out, "{}", render_log(&rows))?;
            }
        }
        PolicyCmd::Approval(cmd) => return approval(ctx, &mut policy, cmd),
        PolicyCmd::Refresh(_) => {
            return Err(
                Unsupported("`sbt policy refresh` is for organization policies".into()).into(),
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
    plan::push_network(ctx, policy)
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

/// What to tell the user about a new deny: whether it has a port-less deny CIDR (applied at
/// create), and a note for each port-scoped entry, which smolvm can't enforce (see `compile`).
fn deny_notes(policy: &Policy, scope: Option<&str>, denies: &[Resource]) -> (bool, Vec<String>) {
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
fn bound_conflict(
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

/// `--deny-network` values, each parsed as `sbt policy deny network` parses its resources.
pub(super) fn parse_create_denies(values: &[String]) -> Result<Vec<(String, Vec<Resource>)>> {
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
pub(super) fn add_create_denies(
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
        ApprovalCmd::Ls { json } => {
            if json {
                writeln!(&ctx.out, "{}", serde_json::to_string_pretty(&pending)?)?;
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
                bail!("no blocked request for '{id}' (see `sbt policy approval ls`)");
            }
            if let Some(s) = sandbox.as_deref()
                && !seen.contains(&s)
            {
                bail!(
                    "sandbox {s} has no blocked request for '{id}': it was blocked in {}",
                    seen.join(", ")
                );
            }
            let before = policy.clone();
            let rule =
                policy.add_rule(sandbox.as_deref(), decision, &id, "approval", None, None)?;
            policy.save(&ctx.paths)?;
            writeln!(&ctx.out, "{} rule {rule}: {id}", decision.name())?;
            let parsed = parse_list(&id)?;
            if decision == Decision::Deny {
                print_deny_notes(ctx, policy, sandbox.as_deref(), &parsed)?;
            }
            print_host_notes(ctx, &before, policy, sandbox.as_deref(), decision, &parsed);
            plan::push_network(ctx, policy)?;
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
    (n > 0).then(|| format!("note: {n} rule(s) aren't fully enforced; see `sbt policy ls --wide`"))
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
mod tests {
    use super::super::testutil::*;
    use super::*;
    use crate::secrets::{SecretEntry, Source};

    fn running(t: &TestEnv, labels: &[(&str, &str)]) {
        let m = machine_json("sbx-a1", "running", labels);
        t.runner()
            .ok(&["machine", "ls", "--json"], &format!("[{m}]"));
        t.runner().ok(&["machine", "status", "-n", "sbx-a1"], &m);
    }

    fn ls(p: &Policy, opts: LsOpts) -> String {
        render_ls(p, &ls_rows(p, &opts), &opts).unwrap()
    }

    fn ls_note_for(
        p: &Policy,
        sandbox: Option<&str>,
        decision: Option<Decision>,
    ) -> Option<String> {
        ls_note(&ls_rows(
            p,
            &LsOpts {
                sandbox,
                decision,
                ..Default::default()
            },
        ))
    }

    /// The `machine update` calls that set a whole allow list.
    fn resets(t: &TestEnv) -> Vec<String> {
        updates(t)
            .into_iter()
            .filter(|l| l.contains("--reset-allow-list"))
            .collect()
    }

    fn updates(t: &TestEnv) -> Vec<String> {
        t.calls()
            .into_iter()
            .filter(|l| l.contains("machine update"))
            .collect()
    }

    #[test]
    fn init_saves_and_pushes() {
        let mut t = test_env(&[]);
        running(&t, &[("sbx.name", "a1")]);
        t.sbt(&["policy", "init", "deny-all"]).unwrap();
        assert_eq!(
            Policy::load(&t.ctx.paths).unwrap().mode,
            Some(Mode::DenyAll)
        );
        // No hosts: smolvm's live-reset workaround takes a second call.
        let u = updates(&t);
        assert_eq!(u.len(), 2, "{u:?}");
        assert!(
            u[1].ends_with("--remove-allow-host smolbento.invalid"),
            "{u:?}"
        );
    }

    #[test]
    fn allow_and_rm_push_live() {
        let mut t = test_env(&[]);
        set_policy(&t, "mode = \"deny-all\"");
        running(&t, &[("sbx.name", "a1")]);
        t.sbt(&["policy", "allow", "network", "api.x.com,*.npmjs.org"])
            .unwrap();
        let last = updates(&t).pop().unwrap();
        assert!(
            last.contains("--allow-host-pattern api.x.com")
                && last.contains("--allow-host-pattern *.npmjs.org"),
            "{last}"
        );
        t.sbt(&["policy", "rm", "network", "--resource", "api.x.com"])
            .unwrap();
        assert!(!updates(&t).pop().unwrap().contains("api.x.com"));
        let err = t
            .sbt(&["policy", "rm", "network", "--resource", "nope.com"])
            .unwrap_err();
        assert!(err.to_string().contains("no matching"), "{err}");
    }

    #[test]
    fn deny_refuses_a_bound_secret_host() {
        let mut t = test_env(&[]);
        running(
            &t,
            &[
                ("sbx.name", "a1"),
                ("sbx.secrets", "github"),
                ("sbx.credential-hosts", "api.github.com,github.com"),
            ],
        );
        let mut f = crate::secrets::SecretsFile::default();
        f.set(SecretEntry {
            service: "github".into(),
            scope: "global".into(),
            source: Source::Keychain,
        });
        f.save(&t.ctx.paths).unwrap();
        for deny in ["api.github.com", "foo.api.github.com"] {
            let err = t.sbt(&["policy", "deny", "network", deny]).unwrap_err();
            assert!(err.to_string().contains("github secret"), "{deny}: {err}");
        }
        // Never applied, so accepted (with a stderr note).
        for deny in ["api.github.com:8080", "foo.api.github.com:8080"] {
            t.sbt(&["policy", "deny", "network", deny]).unwrap();
        }
    }

    #[test]
    fn deny_refuses_hosts_under_a_wildcard_secret_host() {
        let mut t = test_env(&[]);
        running(
            &t,
            &[
                ("sbx.name", "a1"),
                ("sbx.secrets", "notion-token"),
                ("sbx.credential-hosts", "*.notion.com"),
            ],
        );
        for deny in ["api.notion.com", "**.notion.com", "*.notion.com"] {
            let err = t.sbt(&["policy", "deny", "network", deny]).unwrap_err();
            let msg = err.to_string();
            // No secrets.toml entry names the service, so the message falls back to "a secret".
            assert!(msg.contains("can't deny *.notion.com"), "{err}");
            assert!(msg.contains("has a secret bound to it"), "{err}");
        }
        t.sbt(&["policy", "deny", "network", "notion.com"]).unwrap();
    }

    #[test]
    fn check_exit_codes() {
        let mut t = test_env(&[]);
        set_policy(&t, "mode = \"balanced\"");
        assert_eq!(
            t.sbt(&["policy", "check", "network", "pypi.org"]).unwrap(),
            0
        );
        assert_eq!(
            t.sbt(&["policy", "check", "network", "example.com"])
                .unwrap(),
            1
        );
    }

    #[test]
    fn ls_table() {
        let mut p = Policy {
            mode: Some(Mode::Balanced),
            ..Default::default()
        };
        p.add_rule(None, Decision::Allow, "api.x.com", "added", None, None)
            .unwrap();
        p.add_rule(
            Some("a1"),
            Decision::Deny,
            "crl*.digicert.com:80",
            "added",
            Some("GET".into()),
            None,
        )
        .unwrap();
        insta::assert_snapshot!(ls(
            &p,
            LsOpts {
                wide: true,
                ..Default::default()
            }
        ));
    }

    #[test]
    fn ls_filters_by_decision_and_refuses_unimplemented_filters() {
        let mut p = Policy {
            mode: Some(Mode::Balanced),
            ..Default::default()
        };
        p.add_rule(None, Decision::Allow, "api.x.com", "added", None, None)
            .unwrap();
        let deny = p
            .add_rule(None, Decision::Deny, "evil.com", "added", None, None)
            .unwrap();
        assert_eq!(
            ls(
                &p,
                LsOpts {
                    quiet: true,
                    decision: Some(Decision::Deny),
                    ..Default::default()
                }
            ),
            format!("{deny}\n")
        );
        let allows = ls(
            &p,
            LsOpts {
                quiet: true,
                decision: Some(Decision::Allow),
                ..Default::default()
            },
        );
        assert!(
            !allows.contains(&deny) && allows.lines().count() > 1,
            "{allows}"
        );

        let mut t = test_env(&[]);
        p.save(&t.ctx.paths).unwrap();
        assert_eq!(
            t.sbt(&["policy", "ls", "--decision", "deny", "-q"])
                .unwrap(),
            0
        );
        assert!(t.sbt(&["policy", "ls", "--decision", "maybe"]).is_err());
        for flag in [
            &["--created-via", "added"][..],
            &["--type", "network"],
            &["--protocol", "tcp"],
            &["--include-inactive"],
        ] {
            let args: Vec<&str> = ["policy", "ls"].iter().chain(flag).copied().collect();
            let err = t.sbt(&args).unwrap_err();
            assert_eq!(super::super::exit_code(&err), 2, "{flag:?}: {err}");
            assert!(err.to_string().contains("not implemented yet"), "{err}");
        }
    }

    #[test]
    fn ls_source_filters_kit_and_local_rules() {
        use crate::kits::model::{NetRule, Rules};
        let mut t = test_env(&[]);
        let mut p = Policy::default();
        p.add_rule(
            Some("my-sb"),
            Decision::Allow,
            "user.com",
            "added",
            None,
            None,
        )
        .unwrap();
        let rules = Rules {
            allow: vec![NetRule {
                host: "kit.com".into(),
                methods: vec![],
                paths: vec![],
            }],
            deny: vec![],
        };
        p.add_kit_rules("my-sb", "gh", &rules, false).unwrap();
        let mut install = rules.clone();
        install.allow[0].host = "pkg.kit.com".into();
        p.add_kit_rules("my-sb", "gh", &install, true).unwrap();
        p.save(&t.ctx.paths).unwrap();
        let mut out = |args: &[&str]| {
            t.sbt(args).unwrap();
            t.stdout()
        };
        // One aggregated rule per sandbox, like sbx: runtime hosts only (install-phase hosts are
        // not listed).
        let kit = out(&["policy", "ls", "my-sb", "--source", "kit"]);
        let rows: Vec<_> = kit.lines().skip(2).collect();
        assert_eq!(rows.len(), 1, "{kit}");
        let id = crate::policy::kit_rule_id("my-sb");
        assert!(rows[0].starts_with(&id), "{kit}");
        assert!(rows[0].contains("sandbox:my-sb"), "{kit}");
        assert!(rows[0].contains("network: 1 allow"), "{kit}");
        assert!(
            !kit.contains("kit:gh") && !kit.contains("user.com"),
            "{kit}"
        );
        let wide = out(&["policy", "ls", "my-sb", "--source", "kit", "--wide"]);
        assert!(wide.contains("kit:my-sb"), "{wide}");
        assert!(
            wide.contains("kit.com") && !wide.contains("pkg.kit.com"),
            "{wide}"
        );
        let json = out(&["policy", "ls", "my-sb", "--source", "kit", "--json"]);
        let json: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(json.as_array().unwrap().len(), 1);
        assert_eq!(json[0]["id"], id.as_str());
        assert_eq!(json[0]["name"], "kit:my-sb");
        assert_eq!(json[0]["source"], "kit");
        assert_eq!(json[0]["applies_to"], "sandbox:my-sb");
        assert_eq!(json[0]["editable"], false);
        assert_eq!(json[0]["resources"].as_array().unwrap().len(), 1);
        let local = out(&["policy", "ls", "my-sb", "--source", "local"]);
        assert!(
            local.contains("user.com") && !local.contains("kit.com"),
            "{local}"
        );
        let org = out(&["policy", "ls", "my-sb", "--source", "org"]);
        assert!(
            !org.contains("user.com") && !org.contains("kit.com"),
            "{org}"
        );
        assert!(t.sbt(&["policy", "ls", "--source", "x"]).is_err());
    }

    #[test]
    fn check_refuses_other_protocols_and_accepts_verbose() {
        let mut t = test_env(&[]);
        let err = t
            .sbt(&["policy", "check", "network", "x.com", "--protocol", "udp"])
            .unwrap_err();
        assert_eq!(super::super::exit_code(&err), 2);
        assert_eq!(
            t.sbt(&[
                "policy",
                "check",
                "network",
                "x.com",
                "--protocol",
                "tcp",
                "--verbose"
            ],)
                .unwrap(),
            0
        );
    }

    #[test]
    fn reset_needs_force_and_refresh_is_unsupported() {
        let mut t = test_env(&[]);
        assert!(t.sbt_err(&["policy", "reset"]).contains("pass -f"));
        t.sbt(&["policy", "reset", "-f"]).unwrap();
        assert_eq!(Policy::load(&t.ctx.paths).unwrap(), Policy::default());
        set_policy(
            &t,
            "mode = \"allow-all\"\n[[rules]]\nid = \"r-1\"\ndecision = \"allow\"\n\
             resources = [\"a.com\"]\n[sandboxes.a1]\ndeny_network = true\n",
        );
        t.sbt(&["policy", "reset", "-f"]).unwrap();
        let p = Policy::load(&t.ctx.paths).unwrap();
        assert!(p.mode.is_none() && p.rules.is_empty(), "{p:?}");
        assert!(p.sandboxes["a1"].deny_network);
        assert!(matches!(
            compile::network(&p, "a1", &[], false),
            crate::smolvm::NetworkSpec::Restricted(_)
        ));
        let err = t.sbt(&["policy", "refresh"]).unwrap_err();
        assert_eq!(super::super::exit_code(&err), 2);
    }

    #[test]
    fn reset_stops_running_sandboxes() {
        let mut t = test_env(&[]);
        running(&t, &[("sbx.name", "a1")]);
        t.sbt(&["policy", "reset", "-f"]).unwrap();
        assert!(t.calls().contains(&"machine stop -n sbx-a1".to_string()));
        assert_eq!(Policy::load(&t.ctx.paths).unwrap().mode, None);
    }

    fn blocked(t: &TestEnv) {
        running(t, &[("sbx.name", "a1")]);
        t.runner().ok(
            &["machine", "egress-events"],
            r#"[{"timestamp":"2026-10-26T10:00:00Z","operation":"resolve","dest":"example.com"},
                {"timestamp":"2026-10-26T11:00:00Z","operation":"resolve","dest":"example.com"}]"#,
        );
    }

    #[test]
    fn log_lists_blocked_hosts() {
        let mut t = test_env(&[]);
        blocked(&t);
        assert_eq!(t.sbt(&["policy", "log"]).unwrap(), 0);
        assert!(
            t.calls()
                .contains(&"machine egress-events --name sbx-a1 --json --limit 50".to_string())
        );
        let err = t
            .sbt(&["policy", "log", "--type", "filesystem"])
            .unwrap_err();
        assert_eq!(super::super::exit_code(&err), 2);
    }

    #[test]
    fn approval_respond_adds_a_rule_and_pushes() {
        let mut t = test_env(&[]);
        set_policy(&t, "mode = \"deny-all\"");
        blocked(&t);
        t.sbt(&[
            "policy",
            "approval",
            "respond",
            "example.com",
            "allow",
            "--sandbox",
            "a1",
        ])
        .unwrap();
        let p = Policy::load(&t.ctx.paths).unwrap();
        let rule = &p.sandboxes["a1"].rules[0];
        assert_eq!(
            (rule.resources[0].as_str(), rule.created_via.as_str()),
            ("example.com", "approval")
        );
        assert!(
            updates(&t)
                .pop()
                .unwrap()
                .contains("--allow-host-pattern example.com")
        );
        let err = t
            .sbt(&["policy", "approval", "inspect", "nothing.com"])
            .unwrap_err();
        assert!(err.to_string().contains("no blocked request"), "{err}");
    }

    #[test]
    fn approval_respond_checks_the_sandbox_that_was_blocked() {
        let mut t = test_env(&[]);
        set_policy(&t, "mode = \"deny-all\"");
        blocked(&t);
        let err = t.sbt_err(&[
            "policy",
            "approval",
            "respond",
            "example.com",
            "allow",
            "--sandbox",
            "b2",
        ]);
        assert!(err.contains("b2") && err.contains("blocked in a1"), "{err}");
        let p = Policy::load(&t.ctx.paths).unwrap();
        assert!(p.sandboxes.is_empty() && p.rules.is_empty());
        assert!(updates(&t).is_empty());
    }

    #[test]
    fn deny_notes_explain_ports_and_cidrs() {
        let res = |s: &str| parse_list(s).unwrap();
        let p = Policy::default();
        // A port-less deny CIDR: the stdout note, as before.
        let (cidr, notes) = deny_notes(&p, None, &res("10.0.0.0/8, evil.com"));
        assert!(cidr && notes.is_empty(), "{notes:?}");
        // A port-scoped one is never applied: no CIDR note, a stderr note instead.
        let (cidr, notes) = deny_notes(&p, None, &res("10.0.0.0/8:22, evil.com:8080"));
        assert!(!cidr);
        assert_eq!(
            notes,
            [
                "note: smolvm can't filter by port, so 10.0.0.0/8:22 isn't enforced (10.0.0.0/8 \
                 stays reachable on every port); deny 10.0.0.0/8 to block it",
                "note: smolvm can't filter by port, so evil.com:8080 isn't enforced (evil.com \
                 stays reachable on every port); deny evil.com to block it",
            ]
        );
        // The same text as an allow cancels that allow.
        let mut p = Policy::default();
        p.add_rule(
            Some("s1"),
            Decision::Allow,
            "api.x.com:8080",
            "added",
            None,
            None,
        )
        .unwrap();
        let (_, notes) = deny_notes(&p, Some("s1"), &res("api.x.com:8080"));
        assert_eq!(
            notes,
            [
                "note: smolvm can't filter by port, so api.x.com:8080 only cancels the allow \
                 rule with the same text; it doesn't block api.x.com otherwise"
            ]
        );
        let (_, notes) = deny_notes(&p, Some("s1"), &res("[::1]:22"));
        assert!(notes[0].contains("deny ::1 to block it"), "{notes:?}");
        // Another sandbox's deny doesn't cancel it; a global deny does.
        let (_, notes) = deny_notes(&p, Some("s2"), &res("api.x.com:8080"));
        assert!(notes[0].contains("isn't enforced"), "{notes:?}");
        let (_, notes) = deny_notes(&p, None, &res("api.x.com:8080"));
        assert!(notes[0].contains("only cancels"), "{notes:?}");
    }

    #[test]
    fn a_port_scoped_deny_cancels_a_balanced_preset_entry() {
        let p = Policy {
            mode: Some(Mode::Balanced),
            ..Default::default()
        };
        let deny = parse_list("crl*.digicert.com:80").unwrap();
        let (_, notes) = deny_notes(&p, None, &deny);
        assert!(notes[0].contains("only cancels"), "{notes:?}");
        // As compile does: the preset entry (widened to *.digicert.com) is gone.
        let mut p = p;
        p.add_rule(
            None,
            Decision::Deny,
            "crl*.digicert.com:80",
            "added",
            None,
            None,
        )
        .unwrap();
        assert!(!compile::check(&p, Some("s1"), &[], "crl3.digicert.com:80").allowed);
    }

    #[test]
    fn ls_note_counts_rules_that_arent_fully_enforced() {
        let mut p = Policy {
            mode: Some(Mode::Balanced),
            ..Default::default()
        };
        p.add_rule(None, Decision::Allow, "a.com", "added", None, None)
            .unwrap();
        assert_eq!(ls_note_for(&p, None, None), None, "the preset has no notes");
        p.add_rule(None, Decision::Deny, "b.com:8080", "added", None, None)
            .unwrap();
        p.add_rule(
            Some("s1"),
            Decision::Allow,
            "crl*.x.com",
            "added",
            None,
            None,
        )
        .unwrap();
        assert_eq!(
            ls_note_for(&p, None, None).as_deref(),
            Some("note: 2 rule(s) aren't fully enforced; see `sbt policy ls --wide`")
        );
        assert_eq!(
            ls_note_for(&p, None, Some(Decision::Allow)).as_deref(),
            Some("note: 1 rule(s) aren't fully enforced; see `sbt policy ls --wide`")
        );
        assert_eq!(ls_note_for(&p, Some("s2"), Some(Decision::Allow)), None);
    }

    #[test]
    fn log_rows_render() {
        let rows = vec![log::LogRow {
            sandbox: "a1".into(),
            host: "example.com".into(),
            count: 2,
            last_seen: "2026-10-26T11:00:00Z".into(),
        }];
        insta::assert_snapshot!(render_log(&rows));
    }

    #[test]
    fn check_allows_a_bound_secret_host_under_deny_all() {
        let mut t = test_env(&[]);
        set_policy(&t, "mode = \"deny-all\"");
        running(
            &t,
            &[
                ("sbx.name", "a1"),
                ("sbx.credential-hosts", "api.github.com"),
            ],
        );
        let code = t
            .sbt(&[
                "policy",
                "check",
                "network",
                "api.github.com",
                "--sandbox",
                "a1",
            ])
            .unwrap();
        assert_eq!(code, 0);
    }

    #[test]
    fn ls_json_and_quiet() {
        let mut p = Policy::default();
        let id = p
            .add_rule(
                Some("a1"),
                Decision::Deny,
                "b.com:8080",
                "added",
                None,
                None,
            )
            .unwrap();
        let json_opts = || LsOpts {
            format: Format::Json,
            ..Default::default()
        };
        let json = ls(&p, json_opts());
        assert!(json.ends_with("]\n"), "{json}");
        let rows: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(rows.as_array().unwrap().len(), 1);
        assert_eq!(rows[0]["id"], id.as_str());
        assert_eq!(rows[0]["applies_to"], "a1");
        assert_eq!(rows[0]["decision"], "deny");
        assert_eq!(rows[0]["resources"][0], "b.com:8080");
        assert!(!rows[0]["notes"].as_array().unwrap().is_empty());
        // --quiet wins over the format: ids only.
        assert_eq!(
            ls(
                &p,
                LsOpts {
                    quiet: true,
                    ..json_opts()
                }
            ),
            format!("{id}\n")
        );
        let empty = ls(&Policy::default(), json_opts());
        assert_eq!(empty, "[]\n");
        let mut t = test_env(&[]);
        assert_eq!(t.sbt(&["policy", "ls", "--json"]).unwrap(), 0);
        assert_eq!(t.sbt(&["policy", "ls", "--quiet"]).unwrap(), 0);
    }

    #[test]
    fn log_empty_and_json() {
        assert_eq!(render_log(&[]), "No blocked requests\n");
        let mut t = test_env(&[]);
        running(&t, &[("sbx.name", "a1")]);
        t.runner().ok(&["machine", "egress-events"], "[]");
        assert_eq!(t.sbt(&["policy", "log"]).unwrap(), 0);
        assert_eq!(t.sbt(&["policy", "log", "--json"]).unwrap(), 0);
    }

    #[test]
    fn warnings_dont_stop_a_rule_change() {
        // Listing sandboxes fails: the bound-secret check and the live push only warn.
        let mut t = test_env(&[]);
        set_policy(&t, "mode = \"deny-all\"");
        t.runner()
            .fail(&["machine", "ls"], "SMOLVM_ERROR", "db locked");
        t.sbt(&["policy", "deny", "network", "evil.com"]).unwrap();
        t.sbt(&["policy", "allow", "network", "ok.com"]).unwrap();
        assert_eq!(Policy::load(&t.ctx.paths).unwrap().rules.len(), 2);
        assert!(updates(&t).is_empty());
        // A reset still resets when the running sandboxes can't be stopped.
        t.sbt(&["policy", "reset", "-f"]).unwrap();
        assert_eq!(Policy::load(&t.ctx.paths).unwrap(), Policy::default());
    }

    #[test]
    fn a_failed_live_update_only_warns() {
        let mut t = test_env(&[]);
        set_policy(&t, "mode = \"deny-all\"");
        blocked(&t);
        t.runner()
            .fail(&["machine", "update"], "SMOLVM_ERROR", "not running");
        t.sbt(&["policy", "approval", "respond", "example.com", "allow"])
            .unwrap();
        assert_eq!(Policy::load(&t.ctx.paths).unwrap().rules.len(), 1);
        assert_eq!(updates(&t).len(), 1);
        // And a stop that fails doesn't keep a reset from happening.
        t.runner()
            .fail(&["machine", "stop"], "SMOLVM_ERROR", "stuck");
        t.sbt(&["policy", "reset", "-f"]).unwrap();
        assert_eq!(Policy::load(&t.ctx.paths).unwrap().mode, None);
    }

    #[test]
    fn approval_ls_and_inspect_list_pending_hosts() {
        let mut t = test_env(&[]);
        set_policy(&t, "mode = \"deny-all\"");
        blocked(&t);
        assert_eq!(t.sbt(&["policy", "approval", "ls"]).unwrap(), 0);
        assert_eq!(t.sbt(&["policy", "approval", "ls", "--json"]).unwrap(), 0);
        assert_eq!(
            t.sbt(&["policy", "approval", "inspect", "example.com"])
                .unwrap(),
            0
        );
    }

    #[test]
    fn rm_by_id_finds_a_sandbox_rule_without_sandbox() {
        let mut t = test_env(&[]);
        set_policy(&t, "mode = \"deny-all\"");
        let mut p = Policy::load(&t.ctx.paths).unwrap();
        let id = p
            .add_rule(Some("a1"), Decision::Allow, "a.com", "added", None, None)
            .unwrap();
        p.save(&t.ctx.paths).unwrap();
        t.sbt(&["policy", "rm", "network", "--id", &id]).unwrap();
        assert!(Policy::load(&t.ctx.paths).unwrap().sandboxes.is_empty());
        let err = t
            .sbt(&["policy", "rm", "network", "--id", &id])
            .unwrap_err();
        assert!(err.to_string().contains("no matching rules"), "{err}");
    }

    #[test]
    fn rm_refuses_kit_rules_by_id_aggregate_id_or_resource() {
        use crate::kits::model::{NetRule, Rules};
        let mut t = test_env(&[]);
        set_policy(&t, "mode = \"deny-all\"");
        let mut p = Policy::load(&t.ctx.paths).unwrap();
        let rules = Rules {
            allow: vec![NetRule {
                host: "kit.com".into(),
                methods: vec![],
                paths: vec![],
            }],
            deny: vec![],
        };
        let (ids, _) = p.add_kit_rules("sb", "gh", &rules, false).unwrap();
        p.save(&t.ctx.paths).unwrap();
        let agg = crate::policy::kit_rule_id("sb");
        for args in [
            vec!["policy", "rm", "network", "--id", ids[0].as_str()],
            vec!["policy", "rm", "network", "--id", agg.as_str()],
            vec![
                "policy",
                "rm",
                "network",
                "--sandbox",
                "sb",
                "--resource",
                "kit.com",
            ],
        ] {
            let err = t.sbt(&args).unwrap_err().to_string();
            assert!(err.contains("kit rules can't be removed"), "{err}");
            assert!(err.contains("policy deny network --sandbox sb"), "{err}");
        }
        let p = Policy::load(&t.ctx.paths).unwrap();
        assert_eq!(p.rules_for(Some("sb")).count(), 1);
    }

    #[test]
    fn rm_accepts_force_for_sbx_compatibility() {
        let mut t = test_env(&[]);
        set_policy(&t, "mode = \"deny-all\"");
        t.sbt(&["policy", "allow", "network", "a.com"]).unwrap();
        t.sbt(&["policy", "rm", "network", "--resource", "a.com", "-f"])
            .unwrap();
        // Nothing left to remove: the error is the missing rule, not an unknown flag.
        let err = t
            .sbt(&["policy", "rm", "network", "--resource", "a.com", "--force"])
            .unwrap_err();
        assert!(err.to_string().contains("no matching rules"), "{err}");
        assert!(Policy::load(&t.ctx.paths).unwrap().rules.is_empty());
    }

    #[test]
    fn allow_and_deny_refuse_protocols_other_than_tcp() {
        let mut t = test_env(&[]);
        for kind in ["allow", "deny"] {
            let err = t
                .sbt(&["policy", kind, "network", "x.com", "--protocol", "udp"])
                .unwrap_err();
            assert_eq!(super::super::exit_code(&err), 2, "{kind}");
        }
        assert!(Policy::load(&t.ctx.paths).unwrap().rules.is_empty());
    }

    #[test]
    fn localhost_rules_push_the_gateway_live_with_host_access_only() {
        for access in [true, false] {
            let mut t = test_env(&[]);
            set_policy(&t, "mode = \"deny-all\"");
            let mut labels = vec![("sbx.name", "a1")];
            if access {
                labels.push(("sbx.host-access", "true"));
            }
            running(&t, &labels);
            t.sbt(&[
                "policy",
                "allow",
                "network",
                "--sandbox",
                "a1",
                "LOCALHOST:11434",
            ])
            .unwrap();
            // No hosts: the list is the first of the two calls (see `NO_HOSTS_PLACEHOLDER`).
            let last = resets(&t).pop().unwrap();
            assert_eq!(
                last.contains("--allow-cidr 100.96.0.1/32"),
                access,
                "{access}: {last}"
            );
            assert!(!last.to_lowercase().contains("localhost"), "{last}");
            t.sbt(&[
                "policy",
                "rm",
                "network",
                "--sandbox",
                "a1",
                "--resource",
                "LOCALHOST:11434",
            ])
            .unwrap();
            let u = resets(&t);
            assert_eq!(u.len(), 2, "{u:?}");
            assert!(!u[1].contains("100.96.0.1"), "{u:?}");
        }
    }

    #[test]
    fn localhost_warning_names_the_scope() {
        let res = |s: &str| parse_list(s).unwrap();
        assert_eq!(
            localhost_warning(None, &res("localhost:11434")).unwrap(),
            "warning: smolvm can't open a single host port yet; this opens every port on your \
             host's localhost to all sandboxes"
        );
        assert_eq!(
            localhost_warning(Some("a1"), &res("api.x.com, LOCALHOST:11434")).unwrap(),
            "warning: smolvm can't open a single host port yet; this opens every port on your \
             host's localhost to sandbox a1"
        );
        for other in ["127.0.0.1:80", "host.docker.internal:80", "api.x.com"] {
            assert!(localhost_warning(None, &res(other)).is_none(), "{other}");
        }
    }

    #[test]
    fn without_access_note_lists_sandboxes_in_scope_without_the_label() {
        let sbs = [("a1", false), ("b2", true), ("c3", false)];
        assert_eq!(
            without_access_note(None, &sbs).unwrap(),
            "note: a1, c3 were created without host access; recreate them to use it"
        );
        assert_eq!(
            without_access_note(Some("c3"), &sbs).unwrap(),
            "note: c3 were created without host access; recreate them to use it"
        );
        assert!(without_access_note(Some("b2"), &sbs).is_none());
        assert!(without_access_note(Some("zz"), &sbs).is_none());
        assert!(without_access_note(None, &[("b2", true)]).is_none());
        assert!(without_access_note(None, &[(BUILDER, false)]).is_none());
    }

    #[test]
    fn keeps_access_notes_name_open_sandboxes_with_host_access_that_lose_the_rule() {
        let mut before = Policy {
            mode: Some(Mode::AllowAll),
            ..Default::default()
        };
        before
            .add_rule(None, Decision::Allow, "localhost:80", "added", None, None)
            .unwrap();
        let mut after = before.clone();
        after.remove_rules(None, None, Some("localhost:80"));
        let sbs = [("a1", true), ("b2", false)];
        assert_eq!(
            keeps_access_notes(&before, &after, &sbs),
            ["note: a1 keeps host access until it's recreated"]
        );
        // No change: no note. A restricted sandbox loses it live: no note.
        assert!(keeps_access_notes(&before, &before, &sbs).is_empty());
        let mut before = before.clone();
        before.mode = Some(Mode::DenyAll);
        let mut after = after.clone();
        after.mode = Some(Mode::DenyAll);
        assert!(keeps_access_notes(&before, &after, &sbs).is_empty());
    }
}
