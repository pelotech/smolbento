//! `sbt policy`: the network policy.

use anyhow::{Context, Result, bail};
use serde::Serialize;

use super::{
    CheckArgs, CheckKind, Ctx, Format, PolicyCmd, PolicyRmKind, RuleArgs, RuleKind, Unsupported,
    confirm, plan, table,
};
use crate::policy::rules::{Allow, Resource, parse_list};
use crate::policy::{Decision, Mode, Policy, compile, presets};
use crate::sandbox::{self, name};
use crate::secrets::SecretsFile;
use crate::smolvm::Runner;

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
            plan::push_network(ctx)?;
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
            if removed == 0 {
                bail!("no matching rules");
            }
            policy.save(&ctx.paths)?;
            println!("Removed");
            plan::push_network(ctx)?;
        }
        PolicyCmd::Ls(a) => {
            let format = if a.json {
                Format::Json
            } else {
                a.format.unwrap_or_default()
            };
            print!(
                "{}",
                render_ls(&policy, a.sandbox.as_deref(), a.wide, format, a.quiet)?
            );
        }
        PolicyCmd::Inspect { id, json } => {
            let (rule, scope) = policy
                .find(&id)
                .with_context(|| format!("no rule '{id}'"))?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(
                        &serde_json::json!({ "scope": scope, "rule": rule })
                    )?
                );
            } else {
                println!(
                    "ID: {}\nScope: {scope}\nDecision: {}\nResources: {}\nCreated via: {}",
                    rule.id,
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
            confirm(ctx, "Remove every policy rule and the chosen mode?", force)?;
            Policy::default().save(&ctx.paths)?;
            println!("Policy reset; the next `sbt run` asks for a mode");
        }
        PolicyCmd::Log(_) | PolicyCmd::Approval(_) => {
            return Err(Unsupported(
                "`sbt policy log` and approvals arrive in the next task".into(),
            )
            .into());
        }
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
    if decision == Decision::Deny
        && parsed
            .iter()
            .any(|r| matches!(r.to_allow(), Allow::Cidr(_)))
    {
        println!("note: deny CIDRs apply to sandboxes created from now on");
    }
    plan::push_network(ctx)
}

/// smolvm keeps a bound credential's hosts reachable, so a deny on them can't be honoured.
fn guard_bound_secrets<R: Runner>(
    ctx: &Ctx<R>,
    scope: Option<&str>,
    denies: &[Resource],
) -> Result<()> {
    let Ok(sandboxes) = sandbox::list(&ctx.vm) else {
        return Ok(());
    };
    let secrets = SecretsFile::load(&ctx.paths)?;
    for sb in sandboxes
        .iter()
        .filter(|s| scope.is_none_or(|n| n == s.name()))
    {
        let Some(host) = sb
            .meta
            .credential_hosts
            .iter()
            .find(|h| denies.iter().any(|d| d.matches(h)))
        else {
            continue;
        };
        let service = sb
            .meta
            .secrets
            .iter()
            .find(|name| {
                secrets
                    .service(name)
                    .is_some_and(|s| s.hosts.iter().any(|h| h == host))
            })
            .map_or_else(|| "a".to_string(), |s| format!("a {s}"));
        bail!(
            "can't deny {host}: sandbox {} has {service} secret bound to it; remove the secret and recreate the sandbox first",
            sb.name()
        );
    }
    Ok(())
}

fn check<R: Runner>(ctx: &Ctx<R>, policy: &Policy, a: &CheckArgs) -> Result<i32> {
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

pub fn render_ls(
    policy: &Policy,
    sandbox: Option<&str>,
    wide: bool,
    format: Format,
    quiet: bool,
) -> Result<String> {
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
    let rules = match sandbox {
        Some(s) => policy.rules_for(s),
        None => policy.all_rules(),
    };
    for (rule, scope) in rules {
        let mut notes: Vec<String> = rule
            .resources
            .iter()
            .filter_map(|r| {
                Resource::parse(r)
                    .ok()
                    .and_then(|p| p.note())
                    .map(|n| format!("{r}: {n}"))
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
            applies_to: if scope == "global" {
                "all".into()
            } else {
                scope
            },
            decision: rule.decision.name().into(),
            resources: rule.resources.clone(),
            notes,
        });
    }
    if quiet {
        return Ok(rows.iter().map(|r| format!("{}\n", r.id)).collect());
    }
    match format {
        Format::Json => Ok(format!("{}\n", serde_json::to_string_pretty(&rows)?)),
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
            for r in &rows {
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
            last.contains("--allow-host api.x.com")
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
        let err = sbt(&mut t.ctx, &["policy", "deny", "network", "api.github.com"]).unwrap_err();
        assert!(err.to_string().contains("github secret"), "{err}");
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
        insta::assert_snapshot!(render_ls(&p, None, true, Format::Table, false).unwrap());
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
        let err = sbt(&mut t.ctx, &["policy", "refresh"]).unwrap_err();
        assert_eq!(super::super::exit_code(&err), 2);
    }
}
