//! Glue between sandboxes and the policy and secrets: what each start and create gets.

use std::io::{BufRead, Write};

use anyhow::{Context, Result, bail};

use super::Ctx;
use crate::policy::{Mode, Policy, compile};
use crate::sandbox::{self, CreateRequest, Meta, Sandbox, StartPlan};
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

/// Network and secret values for starting the sandbox `meta` describes: its credentials came from
/// `meta.secrets`, cover `meta.credential_hosts` and use `meta.credential_env` (all recorded at
/// create).
pub fn start_plan<R: Runner>(ctx: &Ctx<R>, meta: &Meta) -> Result<StartPlan> {
    let sandbox = meta.name.as_str();
    let bound = &meta.secrets;
    let hosts = &meta.credential_hosts;
    let mut policy = Policy::load(&ctx.paths)?;
    if policy.mode.is_none() {
        if ctx.stdin_tty {
            ensure_policy(ctx)?;
            policy = Policy::load(&ctx.paths)?;
        } else if policy.mode_for(sandbox) == Mode::AllowAll {
            // Not an error: scripts from before policies existed keep working.
            eprintln!(
                "warning: no network policy chosen; {sandbox} starts with an open network \
                 (choose one with `sbt policy init`)"
            );
        }
    }
    let secrets = SecretsFile::load(&ctx.paths)?;
    let network = compile::network(&policy, sandbox, hosts);
    let mut env = Vec::new();
    let mut remove = Vec::new();
    for name in bound {
        // Sandboxes created before `sbx.credential-env` existed rely on these.
        let vars = secrets
            .service(name)
            .map(|s| s.env_vars)
            .unwrap_or_default();
        let (Some(service), Some(entry)) =
            (secrets.service(name), secrets.entry_for(sandbox, name))
        else {
            eprintln!(
                "warning: {sandbox} was created with a {name} secret that's no longer set; requests using it will fail"
            );
            remove.extend(vars);
            continue;
        };
        match resolve(entry, ctx.store.as_ref()) {
            Ok(value) => env.extend(service.env_vars.iter().map(|v| (v.clone(), value.clone()))),
            Err(e) => {
                remove.extend(vars);
                eprintln!(
                    "warning: {name} secret for {sandbox}: {e:#}; requests using it will fail"
                );
            }
        }
    }
    // Recorded env vars cover services secrets.toml no longer defines.
    remove.extend(
        meta.credential_env
            .iter()
            .filter(|v| !env.iter().any(|(k, _)| k == *v))
            .cloned(),
    );
    remove.sort();
    remove.dedup();
    Ok(StartPlan {
        network,
        env,
        remove,
        uid: ctx.uid,
    })
}

/// `sandbox::ensure_running` with this context's plan.
pub fn ensure_running<R: Runner>(ctx: &Ctx<R>, sb: &mut Sandbox) -> Result<()> {
    let meta = sb.meta.clone();
    sandbox::ensure_running(&ctx.vm, sb, || start_plan(ctx, &meta))
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
    req.credential_hosts = credential_hosts(&secrets, &services);
    req.credential_env = req.credentials.iter().map(|c| c.env_var.clone()).collect();
    req.credential_env.sort();
    req.credential_env.dedup();
    req.network = compile::network(&policy, &req.name, &req.credential_hosts);
    req.deny_cidrs = compile::deny_cidrs(&policy, &req.name);
    req.secrets = services;
    Ok(())
}

/// Prepares, creates and starts a new sandbox. When that fails before smolvm has the machine, a
/// `--deny-network` flag recorded for it is dropped again, so a later create of the same name
/// isn't silently deny-all.
pub fn create<R: Runner>(
    ctx: &Ctx<R>,
    req: &mut CreateRequest,
    deny_network: bool,
) -> Result<Sandbox> {
    let result = (|| {
        prepare_create(ctx, req, deny_network)?;
        let plan = start_plan(ctx, &sandbox::create::meta(req))?;
        sandbox::create(&ctx.vm, req, &plan)
    })();
    if result.is_err() && deny_network && matches!(sandbox::find(&ctx.vm, &req.name), Ok(None)) {
        // Best effort: the create error is what matters.
        if let Ok(mut policy) = Policy::load(&ctx.paths)
            && let Some(s) = policy.sandboxes.get_mut(&req.name)
        {
            s.deny_network = false;
            if s.rules.is_empty() {
                policy.sandboxes.remove(&req.name);
            }
            let _ = policy.save(&ctx.paths);
        }
    }
    result
}

/// Pushes the current policy to running sandboxes. Failures are warnings: the policy applies on
/// each sandbox's next start anyway.
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
    let mut updated = 0;
    for sb in sandboxes.iter().filter(|s| s.is_running()) {
        let network = compile::network(&policy, sb.name(), &sb.meta.credential_hosts);
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
    use crate::sandbox::Meta;
    use crate::secrets::{SecretEntry, Source, scope_for};
    use crate::smolvm::NetworkSpec;

    /// A sandbox's labels as recorded at create; `credential_env` empty as before it existed.
    fn meta(name: &str, secrets: &[String], hosts: &[String]) -> Meta {
        Meta {
            name: name.into(),
            agent: "claude".into(),
            workspace: None,
            workspaces: vec![],
            created: 1,
            docker: false,
            secrets: secrets.to_vec(),
            credential_hosts: hosts.to_vec(),
            credential_env: vec![],
        }
    }

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
        let github = ["github".to_string()];
        let hosts = credential_hosts(&SecretsFile::load(&t.ctx.paths).unwrap(), &github);
        let plan = start_plan(&t.ctx, &meta("s1", &github, &hosts)).unwrap();
        assert!(plan.remove.is_empty());
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
        let plan = start_plan(&t.ctx, &meta("s1", &["github".to_string()], &[])).unwrap();
        assert!(plan.env.is_empty());
        assert_eq!(plan.remove, vec!["GH_TOKEN", "GITHUB_TOKEN"]);
    }

    #[test]
    fn unresolvable_secret_vars_are_removed_not_inherited() {
        let t = test_env(&[]);
        let mut f = SecretsFile::load(&t.ctx.paths).unwrap();
        // A keychain entry whose value isn't in the store.
        f.set(SecretEntry {
            service: "anthropic".into(),
            scope: scope_for(None),
            source: Source::Keychain,
        });
        f.save(&t.ctx.paths).unwrap();
        let plan = start_plan(&t.ctx, &meta("s1", &["anthropic".to_string()], &[])).unwrap();
        assert!(plan.env.is_empty());
        assert_eq!(plan.remove, vec!["ANTHROPIC_API_KEY"]);
    }

    #[test]
    fn start_keeps_recorded_credential_hosts_after_the_service_is_gone() {
        let t = test_env(&[]);
        set_policy(&t, "mode = \"deny-all\"");
        // `internal` was a custom service at create; secrets.toml no longer defines it.
        let plan = start_plan(
            &t.ctx,
            &meta(
                "s1",
                &["internal".to_string()],
                &["api.internal.example".to_string()],
            ),
        )
        .unwrap();
        let NetworkSpec::Restricted(list) = plan.network else {
            panic!("restricted")
        };
        assert!(list.hosts().contains(&"api.internal.example".to_string()));
        assert!(plan.env.is_empty());
    }

    #[test]
    fn recorded_env_vars_of_a_deleted_service_are_still_removed() {
        let t = test_env(&[]);
        // `internal` was a custom service with INTERNAL_TOKEN at create; it's gone now.
        let m = Meta {
            credential_env: vec!["INTERNAL_TOKEN".into()],
            ..meta(
                "s1",
                &["internal".to_string()],
                &["api.internal.example".to_string()],
            )
        };
        let plan = start_plan(&t.ctx, &m).unwrap();
        assert!(plan.env.is_empty());
        assert_eq!(plan.remove, vec!["INTERNAL_TOKEN"]);
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
            credential_hosts: vec![],
            credential_env: vec![],
        };
        prepare_create(&t.ctx, &mut req, true).unwrap();
        assert_eq!(req.secrets, vec!["anthropic"]);
        assert_eq!(req.credential_env, vec!["ANTHROPIC_API_KEY"]);
        assert_eq!(req.credentials[0].env_var, "ANTHROPIC_API_KEY");
        assert!(
            req.credential_hosts
                .contains(&"api.anthropic.com".to_string())
        );
        let NetworkSpec::Restricted(list) = &req.network else {
            panic!("restricted")
        };
        assert!(list.hosts().contains(&"api.anthropic.com".to_string()));
        assert!(
            !list.patterns().contains(&"registry.npmjs.org".to_string()),
            "deny-network ignores balanced"
        );
        assert!(Policy::load(&t.ctx.paths).unwrap().sandboxes["s1"].deny_network);
    }

    #[test]
    fn start_without_a_mode_and_without_a_terminal_stays_open() {
        let t = test_env(&[]);
        set_policy(&t, "[sandboxes.d1]\ndeny_network = true\n");
        let plan = start_plan(&t.ctx, &meta("s1", &[], &[])).unwrap();
        assert_eq!(plan.network, NetworkSpec::Open);
        assert_eq!(Policy::load(&t.ctx.paths).unwrap().mode, None);
        let plan = start_plan(&t.ctx, &meta("d1", &[], &[])).unwrap();
        assert!(matches!(plan.network, NetworkSpec::Restricted(_)));
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
            machine_json(
                "sbx-a1",
                "running",
                &[
                    ("sbx.name", "a1"),
                    ("sbx.credential-hosts", "api.x.example")
                ]
            ),
            machine_json("sbx-b1", "stopped", &[("sbx.name", "b1")]),
        );
        t.ctx.vm.runner().ok(&["machine", "ls", "--json"], &ls);
        t.ctx.vm.runner().ok(
            &["machine", "status", "-n", "sbx-a1"],
            &machine_json(
                "sbx-a1",
                "running",
                &[
                    ("sbx.name", "a1"),
                    ("sbx.credential-hosts", "api.x.example"),
                ],
            ),
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
                "machine update -n sbx-a1 --reset-allow-list --allow-host api.x.example \
                 --allow-cidr 127.0.0.0/8 --allow-cidr ::1/128"
            ]
        );
    }
}
