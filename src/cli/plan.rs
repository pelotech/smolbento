//! Glue between sandboxes and the policy and secrets: what each start and create gets.

use std::io::{BufRead, Write};

use anyhow::{Context, Result, bail};

use super::Ctx;
use crate::policy::{Mode, Policy, compile};
use crate::sandbox::{self, CreateRequest, Sandbox, StartPlan};
use crate::secrets::{SecretsFile, resolve::resolve};
use crate::smolvm::{Credential, Runner};

/// Hosts of the given services' credentials.
pub fn credential_hosts(secrets: &SecretsFile, services: &[String]) -> Vec<String> {
    let mut hosts: Vec<String> = services
        .iter()
        .filter_map(|s| secrets.service(s))
        .flat_map(|s| s.hosts)
        .collect();
    hosts.sort();
    hosts.dedup();
    hosts
}

/// One smolvm credential per env var of each service.
pub fn credentials(secrets: &SecretsFile, services: &[String]) -> Result<Vec<Credential>> {
    let mut out = Vec::new();
    for name in services {
        let s = secrets
            .service(name)
            .with_context(|| format!("unknown secret service '{name}'"))?;
        for var in &s.env_vars {
            out.push(Credential {
                name: var.to_ascii_lowercase(),
                env_var: var.clone(),
                hosts: s.hosts.clone(),
            });
        }
    }
    Ok(out)
}

/// Network and secret values for starting `sandbox`, whose credentials came from `bound`.
pub fn start_plan<R: Runner>(ctx: &Ctx<R>, sandbox: &str, bound: &[String]) -> Result<StartPlan> {
    let policy = Policy::load(&ctx.paths)?;
    let secrets = SecretsFile::load(&ctx.paths)?;
    let network = compile::network(&policy, sandbox, &credential_hosts(&secrets, bound));
    let mut env = Vec::new();
    for name in bound {
        let (Some(service), Some(entry)) =
            (secrets.service(name), secrets.entry_for(sandbox, name))
        else {
            eprintln!(
                "warning: {sandbox} was created with a {name} secret that's no longer set; requests using it will fail"
            );
            continue;
        };
        match resolve(entry, ctx.store.as_ref()) {
            Ok(value) => env.extend(service.env_vars.iter().map(|v| (v.clone(), value.clone()))),
            Err(e) => eprintln!(
                "warning: {name} secret for {sandbox}: {e:#}; requests using it will fail"
            ),
        }
    }
    Ok(StartPlan {
        network,
        env,
        uid: ctx.uid,
    })
}

/// `sandbox::ensure_running` with this context's plan.
pub fn ensure_running<R: Runner>(ctx: &Ctx<R>, sb: &mut Sandbox) -> Result<()> {
    let (name, bound) = (sb.name().to_string(), sb.meta.secrets.clone());
    sandbox::ensure_running(&ctx.vm, sb, || start_plan(ctx, &name, &bound))
}

/// Asks for a network policy the first time one is needed (sbx behaviour).
pub fn ensure_policy<R: Runner>(ctx: &Ctx<R>) -> Result<()> {
    let mut policy = Policy::load(&ctx.paths)?;
    if policy.mode.is_some() {
        return Ok(());
    }
    if !ctx.stdin_tty {
        bail!(
            "no network policy chosen yet; run `sbt policy init allow-all|balanced|deny-all` first"
        );
    }
    println!(
        "Choose a network policy for your sandboxes (saved; change it with `sbt policy init`):"
    );
    println!("  1) allow-all  open network");
    println!("  2) balanced   AI APIs, package registries, code hosts and more (recommended)");
    println!("  3) deny-all   nothing unless you allow it");
    print!("Choice [2]: ");
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    policy.mode = Some(match line.trim() {
        "1" | "allow-all" => Mode::AllowAll,
        "" | "2" | "balanced" => Mode::Balanced,
        "3" | "deny-all" => Mode::DenyAll,
        other => bail!("'{other}' isn't 1, 2 or 3"),
    });
    policy.save(&ctx.paths)?;
    Ok(())
}

/// Fills a new sandbox's network, deny CIDRs and credentials from the policy and secrets.
pub fn prepare_create<R: Runner>(
    ctx: &Ctx<R>,
    req: &mut CreateRequest,
    deny_network: bool,
) -> Result<()> {
    ensure_policy(ctx)?;
    let mut policy = Policy::load(&ctx.paths)?;
    if deny_network {
        policy.set_deny_network(&req.name, true);
        policy.save(&ctx.paths)?;
    }
    let secrets = SecretsFile::load(&ctx.paths)?;
    let services: Vec<String> = secrets
        .services_for(&req.name)
        .into_iter()
        .filter(|s| secrets.service(s).is_some())
        .collect();
    req.credentials = credentials(&secrets, &services)?;
    req.network = compile::network(&policy, &req.name, &credential_hosts(&secrets, &services));
    req.deny_cidrs = compile::deny_cidrs(&policy, &req.name);
    req.secrets = services;
    Ok(())
}

/// Pushes the current policy to running sandboxes. Failures are warnings: the policy applies on
/// each sandbox's next start anyway.
// Called by the policy commands once they're wired; tests use it now.
#[cfg_attr(not(test), allow(dead_code))]
pub fn push_network<R: Runner>(ctx: &Ctx<R>) -> Result<()> {
    let sandboxes = match sandbox::list(&ctx.vm) {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "warning: couldn't update running sandboxes ({e:#}); the change applies when they next start"
            );
            return Ok(());
        }
    };
    let policy = Policy::load(&ctx.paths)?;
    let secrets = SecretsFile::load(&ctx.paths)?;
    let mut updated = 0;
    for sb in sandboxes.iter().filter(|s| s.is_running()) {
        let network = compile::network(
            &policy,
            sb.name(),
            &credential_hosts(&secrets, &sb.meta.secrets),
        );
        match ctx.vm.update_network(&sb.machine, &network) {
            Ok(()) => updated += 1,
            Err(e) => eprintln!(
                "warning: {}: the change applies on its next start ({e:#})",
                sb.name()
            ),
        }
    }
    if updated > 0 {
        println!("Updated {updated} running sandbox(es)");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::testutil::*;
    use super::*;
    use crate::secrets::{SecretEntry, Source, scope_for};
    use crate::smolvm::NetworkSpec;

    fn save_secret(t: &TestEnv, service: &str, sandbox: Option<&str>, value: &str) {
        let mut f = SecretsFile::load(&t.ctx.paths).unwrap();
        let entry = SecretEntry {
            service: service.into(),
            scope: scope_for(sandbox),
            source: Source::Keychain,
        };
        t.ctx.store.set(&entry.account(), value).unwrap();
        f.set(entry);
        f.save(&t.ctx.paths).unwrap();
    }

    #[test]
    fn start_plan_resolves_bound_secrets_into_env() {
        let t = test_env(&[]);
        set_policy(&t, "mode = \"deny-all\"");
        save_secret(&t, "github", None, "gh-123");
        let plan = start_plan(&t.ctx, "s1", &["github".to_string()]).unwrap();
        assert_eq!(
            plan.env,
            vec![
                ("GH_TOKEN".to_string(), "gh-123".to_string()),
                ("GITHUB_TOKEN".to_string(), "gh-123".to_string())
            ]
        );
        let NetworkSpec::Restricted(list) = plan.network else {
            panic!("restricted")
        };
        assert!(list.hosts().contains(&"api.github.com".to_string()));
        assert_eq!(plan.uid, 501);
    }

    #[test]
    fn missing_secret_values_are_warnings() {
        let t = test_env(&[]);
        let plan = start_plan(&t.ctx, "s1", &["github".to_string()]).unwrap();
        assert!(plan.env.is_empty());
    }

    #[test]
    fn prepare_create_binds_configured_services_and_deny_network() {
        let t = test_env(&[]);
        set_policy(&t, "mode = \"balanced\"");
        save_secret(&t, "anthropic", None, "sk-1");
        let mut req = CreateRequest {
            name: "s1".into(),
            agent: "claude".into(),
            image: "img".into(),
            workspaces: vec![],
            cpus: 1,
            memory_mib: 1024,
            env: vec![],
            ports: vec![],
            docker: false,
            created: 1,
            network: NetworkSpec::Open,
            deny_cidrs: vec![],
            credentials: vec![],
            secrets: vec![],
        };
        prepare_create(&t.ctx, &mut req, true).unwrap();
        assert_eq!(req.secrets, vec!["anthropic"]);
        assert_eq!(req.credentials[0].env_var, "ANTHROPIC_API_KEY");
        let NetworkSpec::Restricted(list) = &req.network else {
            panic!("restricted")
        };
        assert!(list.hosts().contains(&"api.anthropic.com".to_string()));
        assert!(
            !list.hosts().contains(&"registry.npmjs.org".to_string()),
            "deny-network ignores balanced"
        );
        assert!(Policy::load(&t.ctx.paths).unwrap().sandboxes["s1"].deny_network);
    }

    #[test]
    fn no_policy_and_no_terminal_is_an_error() {
        let t = test_env(&[]);
        std::fs::remove_file(t.ctx.paths.policy_file()).unwrap();
        let err = ensure_policy(&t.ctx).unwrap_err().to_string();
        assert!(err.contains("sbt policy init"), "{err}");
    }

    #[test]
    fn push_updates_running_sandboxes_only() {
        let t = test_env(&[]);
        set_policy(&t, "mode = \"deny-all\"");
        let ls = format!(
            "[{},{}]",
            machine_json("sbx-a1", "running", &[("sbx.name", "a1")]),
            machine_json("sbx-b1", "stopped", &[("sbx.name", "b1")]),
        );
        t.ctx.vm.runner().ok(&["machine", "ls", "--json"], &ls);
        t.ctx.vm.runner().ok(
            &["machine", "status", "-n", "sbx-a1"],
            &machine_json("sbx-a1", "running", &[("sbx.name", "a1")]),
        );
        push_network(&t.ctx).unwrap();
        let updates: Vec<String> = t
            .ctx
            .vm
            .runner()
            .call_lines()
            .into_iter()
            .filter(|l| l.contains("update"))
            .collect();
        assert_eq!(
            updates,
            vec![
                "machine update -n sbx-a1 --reset-allow-list --allow-cidr 127.0.0.0/8 --allow-cidr ::1/128"
            ]
        );
    }
}
