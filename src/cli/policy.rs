//! `sbt policy`: the network policy.

use anyhow::{Context, Result, bail};
use serde::Serialize;

use super::{
    ApprovalCmd, CheckArgs, CheckKind, Ctx, Format, PolicyCmd, PolicyRmKind, RuleArgs, RuleKind,
    Unsupported, confirm, plan, table,
};
use crate::policy::log;
use crate::policy::rules::{Allow, Resource, parse_list};
use crate::policy::{Decision, Mode, Policy, compile, presets};
use crate::sandbox::{self, name};
use crate::secrets::SecretsFile;
use crate::smolvm::Runner;

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
            println!("Network policy: {}", mode.name());
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
            let removed =
                policy.remove_rules(a.sandbox.as_deref(), a.id.as_deref(), a.resource.as_deref());
            if !removed {
                bail!("no matching rules");
            }
            policy.save(&ctx.paths)?;
            println!("Removed");
            plan::push_network(ctx, &policy)?;
        }
        PolicyCmd::Ls(a) => {
            for (flag, set) in [
                ("--source", a.source.is_some()),
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
            let format = if a.json {
                Format::Json
            } else {
                a.format.unwrap_or_default()
            };
            let opts = LsOpts {
                sandbox: a.sandbox.as_deref(),
                decision,
                format,
                wide: a.wide,
                quiet: a.quiet,
            };
            let rows = ls_rows(&policy, &opts);
            print!("{}", render_ls(&policy, &rows, &opts)?);
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
                println!(
                    "{}",
                    serde_json::to_string_pretty(
                        &serde_json::json!({ "scope": scope.unwrap_or("global"), "rule": rule })
                    )?
                );
            } else {
                println!(
                    "ID: {}\nScope: {}\nDecision: {}\nResources: {}\nCreated via: {}",
                    rule.id,
                    scope.unwrap_or("global"),
                    rule.decision.name(),
                    rule.resources.join(", "),
                    rule.created_via
                );
            }
        }
        PolicyCmd::Check {
            kind: CheckKind::Network(a),
        } => return check(ctx, &policy, &a),
        PolicyCmd::Reset { force } => {
            confirm(
                ctx,
                "Remove every policy rule and the chosen mode? Running sandboxes will be stopped \
                 (--deny-network sandboxes stay deny-all).",
                force,
            )?;
            stop_running(ctx);
            policy.reset();
            policy.save(&ctx.paths)?;
            println!(
                "Policy reset; the next start or create asks for a mode (--deny-network \
                 sandboxes stay deny-all)"
            );
        }
        PolicyCmd::Log(a) => {
            if a.kind.as_deref().is_some_and(|k| k == "filesystem") {
                return Err(Unsupported("smolbento has no filesystem policy".into()).into());
            }
            let rows = blocked_rows(ctx, a.sandbox.as_deref(), a.limit)?;
            if a.json {
                println!("{}", serde_json::to_string_pretty(&rows)?);
            } else {
                print!("{}", render_log(&rows));
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
    let id = policy.add_rule(
        a.sandbox.as_deref(),
        decision,
        &a.resources,
        "added",
        a.method,
        a.path,
    )?;
    policy.save(&ctx.paths)?;
    println!("{} rule {id}: {}", decision.name(), a.resources);
    if decision == Decision::Deny {
        print_deny_notes(policy, a.sandbox.as_deref(), &parsed);
    }
    plan::push_network(ctx, policy)
}

fn print_deny_notes(policy: &Policy, scope: Option<&str>, denies: &[Resource]) {
    let (cidr, notes) = deny_notes(policy, scope, denies);
    if cidr {
        println!("note: deny CIDRs apply to sandboxes created from now on");
    }
    // stderr, so stdout stays what sbx prints.
    for n in notes {
        eprintln!("{n}");
    }
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
        let Some(host) = sb.meta.credential_hosts.iter().find(|h| {
            denies
                .iter()
                .any(|d| compile::deny_reaches_credential_host(d, h))
        }) else {
            continue;
        };
        let service = sb
            .meta
            .secrets
            .iter()
            .find(|name| {
                secrets
                    .as_ref()
                    .and_then(|f| f.service(name))
                    .is_some_and(|s| s.hosts.iter().any(|h| h == host))
            })
            .map_or_else(|| "a secret".to_string(), |s| format!("a {s} secret"));
        bail!(
            "can't deny {host}: sandbox {} has {service} bound to it; remove the secret and recreate the sandbox first",
            sb.name()
        );
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
        ApprovalCmd::Ls { json } => {
            if json {
                println!("{}", serde_json::to_string_pretty(&pending)?);
            } else if pending.is_empty() {
                println!("No pending approvals");
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
                print!("{}", table(lines));
            }
        }
        ApprovalCmd::Inspect { id } => {
            let r = rows
                .iter()
                .find(|r| r.host == id)
                .with_context(|| format!("no blocked request for '{id}'"))?;
            println!(
                "Host: {}\nSandbox: {}\nBlocked: {} time(s), last {}",
                r.host, r.sandbox, r.count, r.last_seen
            );
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
            let rule =
                policy.add_rule(sandbox.as_deref(), decision, &id, "approval", None, None)?;
            policy.save(&ctx.paths)?;
            println!("{} rule {rule}: {id}", decision.name());
            if decision == Decision::Deny {
                print_deny_notes(policy, sandbox.as_deref(), &parse_list(&id)?);
            }
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
    println!(
        "{}: {} ({})",
        a.target,
        if v.allowed { "allowed" } else { "denied" },
        v.reason
    );
    Ok(if v.allowed { 0 } else { 1 })
}

#[derive(Serialize)]
struct LsRow {
    id: String,
    source: String,
    applies_to: String,
    decision: String,
    resources: Vec<String>,
    notes: Vec<String>,
}

/// What `policy ls` lists, and how.
#[derive(Default)]
struct LsOpts<'a> {
    sandbox: Option<&'a str>,
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
            });
        }
    }
    let rules: Vec<_> = match opts.sandbox {
        Some(s) => policy.rules_for(Some(s)).collect(),
        None => policy.all_rules().collect(),
    };
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
        rows.push(LsRow {
            id: rule.id.clone(),
            source: "local".into(),
            applies_to: scope.unwrap_or("all").into(),
            decision: rule.decision.name().into(),
            resources: rule.resources.clone(),
            notes,
        });
    }
    if let Some(d) = opts.decision {
        rows.retain(|r| r.decision == d.name());
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
                lines[0].push("NOTES".into());
            }
            for r in rows {
                let resources = if wide || r.resources.len() <= 3 {
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
        t.ctx
            .vm
            .runner()
            .ok(&["machine", "ls", "--json"], &format!("[{m}]"));
        t.ctx
            .vm
            .runner()
            .ok(&["machine", "status", "-n", "sbx-a1"], &m);
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

    fn updates(t: &TestEnv) -> Vec<String> {
        t.ctx
            .vm
            .runner()
            .call_lines()
            .into_iter()
            .filter(|l| l.contains("machine update"))
            .collect()
    }

    #[test]
    fn init_saves_and_pushes() {
        let mut t = test_env(&[]);
        running(&t, &[("sbx.name", "a1")]);
        sbt(&mut t.ctx, &["policy", "init", "deny-all"]).unwrap();
        assert_eq!(
            Policy::load(&t.ctx.paths).unwrap().mode,
            Some(Mode::DenyAll)
        );
        assert_eq!(updates(&t).len(), 1);
    }

    #[test]
    fn allow_and_rm_push_live() {
        let mut t = test_env(&[]);
        set_policy(&t, "mode = \"deny-all\"");
        running(&t, &[("sbx.name", "a1")]);
        sbt(
            &mut t.ctx,
            &["policy", "allow", "network", "api.x.com,*.npmjs.org"],
        )
        .unwrap();
        let last = updates(&t).pop().unwrap();
        assert!(
            last.contains("--allow-host-pattern api.x.com")
                && last.contains("--allow-host-pattern *.npmjs.org"),
            "{last}"
        );
        sbt(
            &mut t.ctx,
            &["policy", "rm", "network", "--resource", "api.x.com"],
        )
        .unwrap();
        assert!(!updates(&t).pop().unwrap().contains("api.x.com"));
        let err = sbt(
            &mut t.ctx,
            &["policy", "rm", "network", "--resource", "nope.com"],
        )
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
            let err = sbt(&mut t.ctx, &["policy", "deny", "network", deny]).unwrap_err();
            assert!(err.to_string().contains("github secret"), "{deny}: {err}");
        }
        // Never applied, so accepted (with a stderr note).
        for deny in ["api.github.com:8080", "foo.api.github.com:8080"] {
            sbt(&mut t.ctx, &["policy", "deny", "network", deny]).unwrap();
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
            let err = sbt(&mut t.ctx, &["policy", "deny", "network", deny]).unwrap_err();
            let msg = err.to_string();
            // No secrets.toml entry names the service, so the message falls back to "a secret".
            assert!(msg.contains("can't deny *.notion.com"), "{err}");
            assert!(msg.contains("has a secret bound to it"), "{err}");
        }
        sbt(&mut t.ctx, &["policy", "deny", "network", "notion.com"]).unwrap();
    }

    #[test]
    fn check_exit_codes() {
        let mut t = test_env(&[]);
        set_policy(&t, "mode = \"balanced\"");
        assert_eq!(
            sbt(&mut t.ctx, &["policy", "check", "network", "pypi.org"]).unwrap(),
            0
        );
        assert_eq!(
            sbt(&mut t.ctx, &["policy", "check", "network", "example.com"]).unwrap(),
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
            sbt(&mut t.ctx, &["policy", "ls", "--decision", "deny", "-q"]).unwrap(),
            0
        );
        assert!(sbt(&mut t.ctx, &["policy", "ls", "--decision", "maybe"]).is_err());
        for flag in [
            &["--source", "local"][..],
            &["--created-via", "added"],
            &["--type", "network"],
            &["--protocol", "tcp"],
            &["--include-inactive"],
        ] {
            let args: Vec<&str> = ["policy", "ls"].iter().chain(flag).copied().collect();
            let err = sbt(&mut t.ctx, &args).unwrap_err();
            assert_eq!(super::super::exit_code(&err), 2, "{flag:?}: {err}");
            assert!(err.to_string().contains("not implemented yet"), "{err}");
        }
    }

    #[test]
    fn check_refuses_other_protocols_and_accepts_verbose() {
        let mut t = test_env(&[]);
        let err = sbt(
            &mut t.ctx,
            &["policy", "check", "network", "x.com", "--protocol", "udp"],
        )
        .unwrap_err();
        assert_eq!(super::super::exit_code(&err), 2);
        assert_eq!(
            sbt(
                &mut t.ctx,
                &[
                    "policy",
                    "check",
                    "network",
                    "x.com",
                    "--protocol",
                    "tcp",
                    "--verbose"
                ],
            )
            .unwrap(),
            0
        );
    }

    #[test]
    fn reset_needs_force_and_refresh_is_unsupported() {
        let mut t = test_env(&[]);
        assert!(
            sbt(&mut t.ctx, &["policy", "reset"])
                .unwrap_err()
                .to_string()
                .contains("pass -f")
        );
        sbt(&mut t.ctx, &["policy", "reset", "-f"]).unwrap();
        assert_eq!(Policy::load(&t.ctx.paths).unwrap(), Policy::default());
        set_policy(
            &t,
            "mode = \"allow-all\"\n[[rules]]\nid = \"r-1\"\ndecision = \"allow\"\n\
             resources = [\"a.com\"]\n[sandboxes.a1]\ndeny_network = true\n",
        );
        sbt(&mut t.ctx, &["policy", "reset", "-f"]).unwrap();
        let p = Policy::load(&t.ctx.paths).unwrap();
        assert!(p.mode.is_none() && p.rules.is_empty(), "{p:?}");
        assert!(p.sandboxes["a1"].deny_network);
        assert!(matches!(
            compile::network(&p, "a1", &[]),
            crate::smolvm::NetworkSpec::Restricted(_)
        ));
        let err = sbt(&mut t.ctx, &["policy", "refresh"]).unwrap_err();
        assert_eq!(super::super::exit_code(&err), 2);
    }

    #[test]
    fn reset_stops_running_sandboxes() {
        let mut t = test_env(&[]);
        running(&t, &[("sbx.name", "a1")]);
        sbt(&mut t.ctx, &["policy", "reset", "-f"]).unwrap();
        assert!(
            t.ctx
                .vm
                .runner()
                .call_lines()
                .contains(&"machine stop -n sbx-a1".to_string())
        );
        assert_eq!(Policy::load(&t.ctx.paths).unwrap().mode, None);
    }

    fn blocked(t: &TestEnv) {
        running(t, &[("sbx.name", "a1")]);
        t.ctx.vm.runner().ok(
            &["machine", "egress-events"],
            r#"[{"timestamp":"2026-10-26T10:00:00Z","operation":"resolve","dest":"example.com"},
                {"timestamp":"2026-10-26T11:00:00Z","operation":"resolve","dest":"example.com"}]"#,
        );
    }

    #[test]
    fn log_lists_blocked_hosts() {
        let mut t = test_env(&[]);
        blocked(&t);
        assert_eq!(sbt(&mut t.ctx, &["policy", "log"]).unwrap(), 0);
        assert!(
            t.ctx
                .vm
                .runner()
                .call_lines()
                .contains(&"machine egress-events --name sbx-a1 --json --limit 50".to_string())
        );
        let err = sbt(&mut t.ctx, &["policy", "log", "--type", "filesystem"]).unwrap_err();
        assert_eq!(super::super::exit_code(&err), 2);
    }

    #[test]
    fn approval_respond_adds_a_rule_and_pushes() {
        let mut t = test_env(&[]);
        set_policy(&t, "mode = \"deny-all\"");
        blocked(&t);
        sbt(
            &mut t.ctx,
            &[
                "policy",
                "approval",
                "respond",
                "example.com",
                "allow",
                "--sandbox",
                "a1",
            ],
        )
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
        let err = sbt(
            &mut t.ctx,
            &["policy", "approval", "inspect", "nothing.com"],
        )
        .unwrap_err();
        assert!(err.to_string().contains("no blocked request"), "{err}");
    }

    #[test]
    fn approval_respond_checks_the_sandbox_that_was_blocked() {
        let mut t = test_env(&[]);
        set_policy(&t, "mode = \"deny-all\"");
        blocked(&t);
        let err = sbt(
            &mut t.ctx,
            &[
                "policy",
                "approval",
                "respond",
                "example.com",
                "allow",
                "--sandbox",
                "b2",
            ],
        )
        .unwrap_err()
        .to_string();
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
        let code = sbt(
            &mut t.ctx,
            &[
                "policy",
                "check",
                "network",
                "api.github.com",
                "--sandbox",
                "a1",
            ],
        )
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
        assert_eq!(sbt(&mut t.ctx, &["policy", "ls", "--json"]).unwrap(), 0);
        assert_eq!(sbt(&mut t.ctx, &["policy", "ls", "--quiet"]).unwrap(), 0);
    }

    #[test]
    fn log_empty_and_json() {
        assert_eq!(render_log(&[]), "No blocked requests\n");
        let mut t = test_env(&[]);
        running(&t, &[("sbx.name", "a1")]);
        t.ctx.vm.runner().ok(&["machine", "egress-events"], "[]");
        assert_eq!(sbt(&mut t.ctx, &["policy", "log"]).unwrap(), 0);
        assert_eq!(sbt(&mut t.ctx, &["policy", "log", "--json"]).unwrap(), 0);
        let rows = vec![log::LogRow {
            sandbox: "a1".into(),
            host: "example.com".into(),
            count: 2,
            last_seen: "2026-10-26T11:00:00Z".into(),
        }];
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string_pretty(&rows).unwrap()).unwrap();
        assert_eq!(
            json,
            serde_json::json!([{
                "sandbox": "a1",
                "host": "example.com",
                "count": 2,
                "last_seen": "2026-10-26T11:00:00Z"
            }])
        );
    }

    #[test]
    fn warnings_dont_stop_a_rule_change() {
        // Listing sandboxes fails: the bound-secret check and the live push only warn.
        let mut t = test_env(&[]);
        set_policy(&t, "mode = \"deny-all\"");
        t.ctx
            .vm
            .runner()
            .fail(&["machine", "ls"], "SMOLVM_ERROR", "db locked");
        sbt(&mut t.ctx, &["policy", "deny", "network", "evil.com"]).unwrap();
        sbt(&mut t.ctx, &["policy", "allow", "network", "ok.com"]).unwrap();
        assert_eq!(Policy::load(&t.ctx.paths).unwrap().rules.len(), 2);
        assert!(updates(&t).is_empty());
        // A reset still resets when the running sandboxes can't be stopped.
        sbt(&mut t.ctx, &["policy", "reset", "-f"]).unwrap();
        assert_eq!(Policy::load(&t.ctx.paths).unwrap(), Policy::default());
    }

    #[test]
    fn a_failed_live_update_only_warns() {
        let mut t = test_env(&[]);
        set_policy(&t, "mode = \"deny-all\"");
        blocked(&t);
        t.ctx
            .vm
            .runner()
            .fail(&["machine", "update"], "SMOLVM_ERROR", "not running");
        sbt(
            &mut t.ctx,
            &["policy", "approval", "respond", "example.com", "allow"],
        )
        .unwrap();
        assert_eq!(Policy::load(&t.ctx.paths).unwrap().rules.len(), 1);
        assert_eq!(updates(&t).len(), 1);
        // And a stop that fails doesn't keep a reset from happening.
        t.ctx
            .vm
            .runner()
            .fail(&["machine", "stop"], "SMOLVM_ERROR", "stuck");
        sbt(&mut t.ctx, &["policy", "reset", "-f"]).unwrap();
        assert_eq!(Policy::load(&t.ctx.paths).unwrap().mode, None);
    }

    #[test]
    fn approval_ls_and_inspect_list_pending_hosts() {
        let mut t = test_env(&[]);
        set_policy(&t, "mode = \"deny-all\"");
        blocked(&t);
        assert_eq!(sbt(&mut t.ctx, &["policy", "approval", "ls"]).unwrap(), 0);
        assert_eq!(
            sbt(&mut t.ctx, &["policy", "approval", "ls", "--json"]).unwrap(),
            0
        );
        assert_eq!(
            sbt(
                &mut t.ctx,
                &["policy", "approval", "inspect", "example.com"]
            )
            .unwrap(),
            0
        );
    }

    #[test]
    fn rm_accepts_force_for_sbx_compatibility() {
        let mut t = test_env(&[]);
        set_policy(&t, "mode = \"deny-all\"");
        sbt(&mut t.ctx, &["policy", "allow", "network", "a.com"]).unwrap();
        sbt(
            &mut t.ctx,
            &["policy", "rm", "network", "--resource", "a.com", "-f"],
        )
        .unwrap();
        // Nothing left to remove: the error is the missing rule, not an unknown flag.
        let err = sbt(
            &mut t.ctx,
            &["policy", "rm", "network", "--resource", "a.com", "--force"],
        )
        .unwrap_err();
        assert!(err.to_string().contains("no matching rules"), "{err}");
        assert!(Policy::load(&t.ctx.paths).unwrap().rules.is_empty());
    }

    #[test]
    fn check_protocol_udp_is_unsupported_for_rules_too() {
        let mut t = test_env(&[]);
        for kind in ["allow", "deny"] {
            let err = sbt(
                &mut t.ctx,
                &["policy", kind, "network", "x.com", "--protocol", "udp"],
            )
            .unwrap_err();
            assert_eq!(super::super::exit_code(&err), 2, "{kind}");
        }
        assert!(Policy::load(&t.ctx.paths).unwrap().rules.is_empty());
    }
}
