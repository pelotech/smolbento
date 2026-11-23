//! `bento policy`: the network policy.

use anyhow::{Context, Result, anyhow, bail};
use serde::Serialize;
use std::io::Write;

mod ls;

use super::{
    ApprovalCmd, CheckArgs, CheckKind, Ctx, PolicyCmd, PolicyRmArgs, PolicyRmKind, RuleArgs,
    RuleKind, Unsupported, confirm, table,
};
use crate::egress::request_rules;
use crate::policy::log;
use crate::policy::notes::{bound_conflict, deny_notes};
use crate::policy::rules::{Resource, parse_list};
use crate::policy::{Decision, Policy, compile, normalise_methods, normalise_query};
use crate::provision;
use crate::provision::builder::BUILDER;
use crate::sandbox::{self, name};
use crate::secrets::SecretsFile;
use crate::smolvm::{NetworkSpec, Runner};
use ls::ls;

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
        } => rm(ctx, &mut policy, &a)?,
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

/// `policy rm network`: removes the rules `a` picks, then applies the change to running sandboxes.
fn rm<R: Runner>(ctx: &Ctx<R>, policy: &mut Policy, a: &PolicyRmArgs) -> Result<()> {
    // sbx: the HTTP qualifiers pick one of a resource's rules.
    for (set, flag) in [
        (a.method.is_some(), "--method"),
        (a.path.is_some(), "--path"),
        (a.query.is_some(), "--query"),
    ] {
        if set && a.resource.is_none() {
            bail!("{flag} requires --resource\n  try: bento policy rm network --help");
        }
    }
    // The canonical list. An empty one would pick every rule: smolbento's own error.
    let method = a
        .method
        .as_deref()
        .map(|m| {
            normalise_methods(m)
                .context("--method names no HTTP method\n  try: bento policy rm network --help")
        })
        .transpose()?;
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
    let query = a
        .query
        .as_deref()
        .map(|q| {
            normalise_query(&[q])
                .context("--query names no parameter\n  try: bento policy rm network --help")
        })
        .transpose()?;
    let before = policy.clone();
    let removed = policy.remove_rules(
        sandbox.as_deref(),
        a.id.as_deref(),
        a.resource.as_deref(),
        method.as_deref(),
        a.path.as_deref(),
        query.as_deref(),
    );
    if !removed {
        // sbx's error for a resource no rule has.
        bail!(match a.resource {
            Some(_) => {
                "remove network rule: remove-resource: not found; \
                 use \"bento policy ls --wide\" to find rule IDs"
            }
            None => "no matching rules",
        });
    }
    policy.save(&ctx.paths)?;
    writeln!(&ctx.out, "Removed")?;
    let sandboxes = sandbox::Listing::new(&ctx.vm);
    print_host_notes(&sandboxes, &before, policy, None, Decision::Deny, &[]);
    provision::push_network_with(ctx, policy, &sandboxes)
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
    let query = normalise_query(&a.query);
    let request = a.method.is_some() || a.path.is_some() || query.is_some();
    if request {
        request_rules::check(
            decision,
            &parsed,
            a.method.as_deref(),
            a.path.as_deref(),
            query.as_deref(),
        )
        .map_err(|e| {
            anyhow::anyhow!(
                "{e}\n  try: bento policy {} network --help",
                decision.name()
            )
        })?;
    }
    let sandboxes = sandbox::Listing::new(&ctx.vm);
    // A request deny leaves the host reachable, so a bound secret still works.
    if decision == Decision::Deny && !request {
        guard_bound_secrets(ctx, &sandboxes, a.sandbox.as_deref(), &parsed)?;
    }
    let before = policy.clone();
    let (id, _) = policy.insert_rule(
        a.sandbox.as_deref(),
        decision,
        &a.resources,
        created_via,
        a.method,
        a.path,
        query,
    )?;
    policy.save(&ctx.paths)?;
    writeln!(&ctx.out, "{} rule {id}: {}", decision.name(), a.resources)?;
    if decision == Decision::Deny {
        print_deny_notes(ctx, policy, a.sandbox.as_deref(), &parsed)?;
    }
    print_host_notes(
        &sandboxes,
        &before,
        policy,
        a.sandbox.as_deref(),
        decision,
        &parsed,
    );
    provision::push_network_with(ctx, policy, &sandboxes)
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
                && compile::network(after, n, &[], true, false) == NetworkSpec::Open
                && compile::host_access(before, n)
                && !compile::host_access(after, n)
        })
        .map(|(n, _)| format!("note: {n} keeps host access until it's recreated"))
        .collect()
}

/// The localhost warning and host access notes for a rule change from `before` to `after`:
/// `added` are the resources of a new rule with this decision in `scope` (none for a removal).
/// Sandboxes are listed only when a `localhost` rule is involved; a failure to list is left to
/// `push_network` to report.
fn host_notes<R: Runner>(
    sandboxes: &sandbox::Listing<R>,
    before: &Policy,
    after: &Policy,
    scope: Option<&str>,
    decision: Decision,
    added: &[Resource],
) -> Vec<String> {
    let allowed = decision == Decision::Allow;
    let mut notes: Vec<String> = Vec::new();
    if allowed {
        notes.extend(localhost_warning(scope, added));
    }
    let localhost = |p: &Policy| {
        p.all_rules()
            .any(|(r, _)| r.parsed().any(|x| compile::is_host_services(&x)))
    };
    if !localhost(before) && !localhost(after) {
        return notes;
    }
    let Ok(sandboxes) = sandboxes.get() else {
        return notes;
    };
    let sbs: Vec<(&str, bool)> = sandboxes
        .iter()
        .map(|s| (s.name(), s.meta.rec.host_access))
        .collect();
    if allowed && added.iter().any(compile::is_host_services) {
        notes.extend(without_access_note(scope, &sbs));
    }
    notes.extend(keeps_access_notes(before, after, &sbs));
    notes
}

/// `host_notes`, on stderr.
fn print_host_notes<R: Runner>(
    sandboxes: &sandbox::Listing<R>,
    before: &Policy,
    after: &Policy,
    scope: Option<&str>,
    decision: Decision,
    added: &[Resource],
) {
    for n in host_notes(sandboxes, before, after, scope, decision, added) {
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
    sandboxes: &sandbox::Listing<R>,
    scope: Option<&str>,
    denies: &[Resource],
) -> Result<()> {
    let sandboxes = match sandboxes.get() {
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
            &sb.meta.rec.credential_hosts,
            &sb.meta.rec.secrets,
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

/// One answer an approval takes, as sbx lists them.
#[derive(Clone, Copy, Serialize)]
struct ApprovalOption {
    id: &'static str,
    label: &'static str,
}

/// sbx's options for a network approval.
const OPTIONS: [ApprovalOption; 2] = [
    ApprovalOption {
        id: "allow",
        label: "Allow",
    },
    ApprovalOption {
        id: "dismiss",
        label: "Dismiss",
    },
];

/// sbx's approval (`policy approval ls --json`), keys in its order. smolvm's log has the host
/// only: no port for the title, and no protocol for the detail.
#[derive(Serialize)]
struct Approval<'a> {
    created_at: &'a str,
    detail: String,
    id: &'a str,
    options: [ApprovalOption; 2],
    sandbox_name: &'a str,
    title: &'a str,
}

impl<'a> Approval<'a> {
    fn of(row: &'a log::LogRow) -> Self {
        let kind = if row.host.parse::<std::net::IpAddr>().is_ok() {
            "ip"
        } else {
            "domain"
        };
        Approval {
            created_at: &row.first_seen,
            detail: format!("Resource type: {kind}\nno matching allow rule (default deny)"),
            id: &row.host,
            options: OPTIONS,
            sandbox_name: &row.sandbox,
            title: &row.host,
        }
    }

    /// The detail on one line, as sbx's tables show it.
    fn detail_line(&self) -> String {
        self.detail.replace('\n', " ")
    }
}

/// Approvals are blocked hosts no rule mentions yet; the host is the id.
fn approval<R: Runner>(ctx: &Ctx<R>, policy: &mut Policy, cmd: ApprovalCmd) -> Result<i32> {
    let blocked = || blocked_rows(ctx, None, APPROVAL_EVENTS);
    match cmd {
        ApprovalCmd::Ls { quiet, output } => {
            let rows = blocked()?;
            let pending = log::pending(policy, &rows);
            let list: Vec<Approval> = pending.iter().map(|r| Approval::of(r)).collect();
            if quiet {
                for a in &list {
                    writeln!(&ctx.out, "{}", a.id)?;
                }
            } else if let Some(text) = output.structured(&list)? {
                write!(&ctx.out, "{text}")?;
            } else if list.is_empty() {
                writeln!(&ctx.out, "No pending approvals.")?;
            } else {
                let head = ["APPROVAL", "SANDBOX", "TITLE", "DETAIL", "OPTIONS"];
                let lines = list
                    .iter()
                    .map(|a| {
                        let options: Vec<String> = a
                            .options
                            .iter()
                            .map(|o| format!("{} ({})", o.id, o.label))
                            .collect();
                        vec![
                            a.id.to_string(),
                            a.sandbox_name.to_string(),
                            a.title.to_string(),
                            a.detail_line(),
                            options.join(", "),
                        ]
                    })
                    .collect();
                write!(&ctx.out, "{}", table(&head, lines))?;
            }
        }
        ApprovalCmd::Inspect { id } => {
            let rows = blocked()?;
            let pending = log::pending(policy, &rows);
            // A pending one first; an answered one is still shown.
            let row = pending
                .iter()
                .copied()
                .find(|r| r.host == id)
                .or_else(|| rows.iter().find(|r| r.host == id))
                .with_context(|| format!("no blocked request for '{id}'"))?;
            let a = Approval::of(row);
            writeln!(
                &ctx.out,
                "  ○ APPROVAL {} — sandbox {}\n      {}\n      {}\n",
                a.id,
                a.sandbox_name,
                a.title,
                a.detail_line()
            )?;
            let options = a
                .options
                .iter()
                .map(|o| vec![o.id.to_string(), o.label.to_string()])
                .collect();
            for line in table(&["OPTION", "LABEL"], options).lines() {
                writeln!(&ctx.out, "  {line}")?;
            }
        }
        ApprovalCmd::Respond {
            id,
            decision,
            option,
            sandbox,
        } => {
            // sbx (cobra) checks its required flag before it looks anything up.
            let answer = match (decision, option) {
                (Some(decision), _) => Answer::Rule(decision),
                (None, Some(option)) => Answer::Option(option),
                (None, None) => bail!(
                    "required flag(s) \"option\" not set\n  \
                     try: bento policy approval respond --help"
                ),
            };
            respond(ctx, policy, &blocked()?, id, answer, sandbox)?;
        }
    }
    Ok(0)
}

/// How `approval respond` was answered.
enum Answer {
    /// sbx's `--option OPTION-ID`. An approval belongs to a sandbox, and so does the rule an
    /// allow makes.
    Option(String),
    /// smolbento's older `ID allow|deny`: a rule for every sandbox unless --sandbox.
    Rule(Decision),
}

fn respond<R: Runner>(
    ctx: &Ctx<R>,
    policy: &mut Policy,
    rows: &[log::LogRow],
    id: String,
    answer: Answer,
    sandbox: Option<String>,
) -> Result<()> {
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
    let option = match answer {
        Answer::Rule(decision) => {
            let rule = RuleArgs {
                resources: id,
                sandbox,
                protocol: None,
                method: None,
                path: None,
                query: Vec::new(),
            };
            return add_rule(ctx, policy, decision, rule, "approval");
        }
        Answer::Option(option) => option,
    };
    let waiting: Vec<&log::LogRow> = log::pending(policy, rows)
        .into_iter()
        .filter(|r| r.host == id && sandbox.as_deref().is_none_or(|s| s == r.sandbox))
        .collect();
    if waiting.is_empty() {
        bail!("approval {id:?} is not pending\n  try: bento policy approval ls");
    }
    let Some(answer) = OPTIONS.iter().find(|o| o.id == option) else {
        bail!("approval {id:?} has no option {option:?}\n  try: bento policy approval ls");
    };
    let allow = answer.id == "allow";
    let before = policy.clone();
    for r in &waiting {
        if allow {
            policy.add_rule(
                Some(&r.sandbox),
                Decision::Allow,
                &id,
                "approval",
                None,
                None,
            )?;
        } else {
            policy
                .dismissed
                .entry(r.sandbox.clone())
                .or_default()
                .insert(id.clone(), r.last_seen.clone());
        }
    }
    policy.save(&ctx.paths)?;
    writeln!(&ctx.out, "Recorded answer {}", answer.label)?;
    if allow {
        let sandboxes = sandbox::Listing::new(&ctx.vm);
        for n in approval_notes(&sandboxes, &before, policy, &waiting, &id)? {
            eprintln!("{n}");
        }
        provision::push_network_with(ctx, policy, &sandboxes)?;
    }
    Ok(())
}

/// What `policy allow` would note (`host_notes`) for an approval's allow rule in each of the
/// `waiting` sandboxes, each note once.
fn approval_notes<R: Runner>(
    sandboxes: &sandbox::Listing<R>,
    before: &Policy,
    after: &Policy,
    waiting: &[&log::LogRow],
    id: &str,
) -> Result<Vec<String>> {
    let added = parse_list(id)?;
    let mut notes = Vec::new();
    for r in waiting {
        for n in host_notes(
            sandboxes,
            before,
            after,
            Some(&r.sandbox),
            Decision::Allow,
            &added,
        ) {
            if !notes.contains(&n) {
                notes.push(n);
            }
        }
    }
    Ok(notes)
}

/// sbx's `policy check --json`, keys in its order, plus `reason` when allowed too.
#[derive(Serialize)]
struct CheckDoc<'a> {
    action: &'static str,
    allowed: bool,
    context: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    deny_kind: Option<&'static str>,
    governance: Governance,
    reason: String,
    resource_type: &'static str,
    resource_value: &'a str,
    target: &'a str,
    #[serde(rename = "type")]
    kind: &'static str,
}

/// smolbento has no organization policy: never active.
#[derive(Serialize)]
struct Governance {
    active: bool,
}

/// `policy check network`'s target as sbx 0.54 reads it: `host:port`, the host lowercased (an IPv6
/// one bracketed) and `host.docker.internal` as `localhost`. A bare host is port 443; a URL's
/// scheme gives its port (`http` 80, `https` 443, others must state one) and its path is dropped.
fn check_target(raw: &str) -> Result<String> {
    const SHAPE: &str = "target must be a host, host:port, IP literal, or URL with a port";
    let raw = raw.trim();
    let (authority, default) = match raw.split_once("://") {
        Some((scheme, rest)) => {
            let scheme = scheme.to_ascii_lowercase();
            let port = match scheme.as_str() {
                "http" => Ok(80),
                "https" => Ok(443),
                _ => Err(scheme),
            };
            (rest.split(['/', '?', '#']).next().unwrap_or_default(), port)
        }
        None if raw.contains('/') => bail!("{SHAPE}"),
        None => (raw, Ok(443)),
    };
    // A bare IPv6 address has several colons and no port.
    let (host, port) = if authority.matches(':').count() > 1 && !authority.starts_with('[') {
        (authority, None)
    } else {
        crate::policy::rules::split_port(authority).map_err(|_| anyhow!("{SHAPE}"))?
    };
    let port = match (port, default) {
        (Some(p), _) | (None, Ok(p)) => p,
        (None, Err(scheme)) => bail!("target URL scheme {scheme:?} must include an explicit port"),
    };
    let host = match host.to_ascii_lowercase() {
        h if h.is_empty() => bail!("{SHAPE}"),
        h if h == "host.docker.internal" => "localhost".to_string(),
        h => h,
    };
    Ok(if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    })
}

fn check<R: Runner>(ctx: &Ctx<R>, policy: &Policy, a: &CheckArgs) -> Result<i32> {
    let udp = match a.protocol.as_deref() {
        None | Some("tcp") => false,
        Some("udp") => true,
        Some(other) => {
            let command = "policy check network";
            return Err(invalid_flag(
                "--protocol",
                other,
                "protocol",
                &["tcp", "udp"],
                command,
            ));
        }
    };
    let target = check_target(&a.target)?;
    let found = (a.sandbox.as_deref()).and_then(|n| sandbox::find(&ctx.vm, n).ok().flatten());
    let bound = found
        .as_ref()
        .map(|s| s.meta.rec.credential_hosts.clone())
        .unwrap_or_default();
    let host_access = found.as_ref().map(|s| s.meta.rec.host_access);
    let scope = a.sandbox.as_deref();
    let v = if udp {
        compile::check_udp(policy, scope, &bound, host_access, &target)
    } else {
        compile::check(policy, scope, &bound, host_access, &target)
    };
    let deny_kind = match (v.allowed, v.implicit) {
        (true, _) => None,
        (false, true) => Some("implicit"),
        (false, false) => Some("explicit"),
    };
    let doc = CheckDoc {
        action: if udp {
            "net:connect:udp"
        } else {
            "net:connect:tcp"
        },
        allowed: v.allowed,
        context: scope.unwrap_or("global"),
        deny_kind,
        governance: Governance { active: false },
        // sbx's JSON starts a denial's reason with a capital.
        reason: if v.allowed {
            v.reason.clone()
        } else {
            capitalised(&v.reason)
        },
        resource_type: "net:domain",
        resource_value: &target.replace(['[', ']'], ""),
        target: &target,
        kind: "network",
    };
    let code = if v.allowed { 0 } else { 1 };
    if let Some(text) = a.output.structured(&doc)? {
        write!(&ctx.out, "{text}")?;
        return Ok(code);
    }
    // sbx's block. It prints a reason only for a denial; smolbento always says what decided.
    let mut lines = vec![
        (
            if v.allowed { "Allowed:" } else { "Denied:" },
            target.clone(),
        ),
        ("Governance:", "Local policy only".to_string()),
        ("Context:", doc.context.to_string()),
        ("Reason:", v.reason.clone()),
    ];
    if a.verbose {
        lines.push(("Action:", doc.action.to_string()));
        lines.push(("Resource:", format!("{} {target}", doc.resource_type)));
        if let Some(kind) = deny_kind {
            lines.push(("Deny kind:", kind.to_string()));
        }
    }
    for (label, value) in lines {
        writeln!(&ctx.out, "  {label:<13}{value}")?;
    }
    // stderr, so the block stays what sbx prints.
    if !udp {
        for n in check_notes(policy, scope, &target) {
            eprintln!("{n}");
        }
    }
    Ok(code)
}

/// What `policy check`'s connection verdict leaves out: request rules on the target's host, and
/// that a request deny there still drops the whole host under `network.egress=smolvm`.
fn check_notes(policy: &Policy, scope: Option<&str>, target: &str) -> Vec<String> {
    let ruled: Vec<Decision> = compile::active(policy, scope, &[])
        .filter(|(r, _)| r.is_request() && r.parsed().any(|res| res.matches(target)))
        .map(|(r, _)| r.decision)
        .collect();
    let mut notes = Vec::new();
    if !ruled.is_empty() {
        notes.push("note: request rules apply on this host".to_string());
    }
    if ruled.contains(&Decision::Deny) {
        notes.push(
            "note: with network.egress=smolvm a request deny drops its whole host from the \
             allow list"
                .to_string(),
        );
    }
    notes
}

/// sbx's (cobra's) error for a flag of `command` whose value isn't one of `allowed`.
fn invalid_flag(
    flag: &str,
    value: &str,
    what: &str,
    allowed: &[&str],
    command: &str,
) -> anyhow::Error {
    // sbx names two values as `a or b`, and more as `one of: a, b, c`.
    let list = match allowed {
        [a, b] => format!("{a} or {b}"),
        _ => format!("one of: {}", allowed.join(", ")),
    };
    anyhow!(
        "invalid argument {value:?} for \"{flag}\" flag: invalid {what} {value:?}: must be {list}\n  \
         try: bento {command} --help"
    )
}

fn capitalised(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

#[cfg(test)]
#[path = "policy_tests.rs"]
mod tests;
