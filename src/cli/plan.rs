//! Glue between sandboxes and the policy and secrets: what each start and create gets.

use std::io::{BufRead, Write};
use std::path::Path;

use anyhow::{Context, Result, bail};

use super::Ctx;
use crate::kits::apply::apply;
use crate::kits::resolve::Plan;
use crate::policy::{Mode, Policy, compile};
use crate::sandbox::{self, CloneStep, CreateRequest, Meta, Sandbox, StartPlan, name};
use crate::secrets::{SecretsFile, resolve::resolve};
use crate::smolvm::{Credential, NetworkSpec, Runner};
use crate::workspace::clone;

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
        if s.hosts.is_empty() && !s.env_vars.is_empty() {
            bail!("secret service '{name}' has no hosts to send its value to");
        }
        for var in &s.env_vars {
            out.push(Credential {
                name: var.to_ascii_lowercase(),
                env_var: var.clone(),
                hosts: s.hosts.clone(),
                ..Default::default()
            });
        }
    }
    Ok(out)
}

/// Network and secret values for starting the sandbox `meta` describes: its credentials came from
/// `meta.secrets`, cover `meta.credential_hosts` and use `meta.credential_env` (all recorded at
/// create). Install-only credentials (`meta.credential_install`) are left out.
pub fn start_plan<R: Runner>(ctx: &Ctx<R>, meta: &Meta) -> Result<StartPlan> {
    plan_for(ctx, meta, None)
}

/// `start_plan` for a create's first start, which also passes the install-only credentials and
/// opens the install-phase rules with these ids (this create's kits').
pub fn first_start_plan<R: Runner>(
    ctx: &Ctx<R>,
    meta: &Meta,
    install_rules: &[String],
) -> Result<StartPlan> {
    plan_for(ctx, meta, Some(install_rules))
}

/// `install`: the first start's install-phase rule ids; `None` for any other start, which never
/// opens install-phase rules (one left by an interrupted create stays shut).
fn plan_for<R: Runner>(
    ctx: &Ctx<R>,
    meta: &Meta,
    install_rules: Option<&[String]>,
) -> Result<StartPlan> {
    let install = install_rules.is_some();
    let sandbox = meta.name.as_str();
    // Like create (and sbx after `policy reset`), a start needs a chosen policy.
    let policy = ensure_policy(ctx)?;
    let secrets = SecretsFile::load(&ctx.paths)?;
    let network = compile::network_with(
        &policy,
        sandbox,
        &meta.credential_hosts,
        install_rules.unwrap_or_default(),
    );
    let mut env = Vec::new();
    for name in &meta.secrets {
        let entry = secrets.entry_for(sandbox, meta.fork_of.as_deref(), name);
        let (Some(service), Some(entry)) = (secrets.service(name), entry) else {
            eprintln!(
                "warning: {sandbox} was created with a {name} secret that's no longer set; requests using it will fail"
            );
            continue;
        };
        // The service's own env vars, then kit ones bound to it (`sbx.credential-service.*`).
        let vars: Vec<&String> = service
            .env_vars
            .iter()
            .chain(
                meta.credential_services
                    .iter()
                    .filter(|(_, s)| *s == name)
                    .map(|(v, _)| v),
            )
            .filter(|v| install || !meta.credential_install.contains(v))
            .collect();
        if vars.is_empty() {
            continue;
        }
        match resolve(entry, ctx.store.as_ref()) {
            Ok(value) => env.extend(vars.into_iter().map(|v| {
                let value = match meta.credential_formats.get(v) {
                    Some(f) => f.apply(&value),
                    None => value.clone(),
                };
                (v.clone(), value)
            })),
            Err(e) => eprintln!(
                "warning: {name} secret for {sandbox}: {e:#}; requests using it will fail"
            ),
        }
    }
    // Recorded env vars without a value, even of services secrets.toml no longer defines, and
    // install-only and kit ones: none may come from the host shell's environment instead.
    let mut remove: Vec<String> = meta
        .credential_env
        .iter()
        .chain(&meta.credential_install)
        .chain(meta.credential_services.keys())
        .filter(|v| !env.iter().any(|(k, _)| k == *v))
        .cloned()
        .collect();
    remove.sort();
    remove.dedup();
    let clone = meta.clone_repo.as_ref().map(|dir| {
        let repo = Path::new(dir);
        let read =
            || -> Result<_> { Ok((clone::worktree_head(repo)?, clone::copied_remotes(repo)?)) };
        let (head, remotes) = read().unwrap_or_else(|e| {
            eprintln!(
                "warning: reading the host repo for {sandbox}: {e:#}; its remotes aren't copied"
            );
            (None, Vec::new())
        });
        CloneStep {
            dir: dir.clone(),
            head,
            remotes,
        }
    });
    Ok(StartPlan {
        network,
        env,
        remove,
        uid: ctx.uid,
        clone,
        branchable: meta.forkable() && ctx.settings.bool("fork.enabled")?,
        kit: None,
    })
}

/// `sandbox::ensure_running` with this context's plan.
pub fn ensure_running<R: Runner>(ctx: &Ctx<R>, sb: &mut Sandbox) -> Result<()> {
    let meta = sb.meta.clone();
    sandbox::ensure_running(&ctx.vm, sb, || start_plan(ctx, &meta))
}

/// The policy, asking for a network policy the first time one is needed (sbx behaviour).
pub fn ensure_policy<R: Runner>(ctx: &Ctx<R>) -> Result<Policy> {
    let mut policy = Policy::load(&ctx.paths)?;
    if policy.mode.is_some() {
        return Ok(policy);
    }
    if !ctx.stdin_tty {
        bail!(
            "no network policy chosen yet; run `sbt policy init allow-all|balanced|deny-all` first"
        );
    }
    let mut out = &ctx.out;
    writeln!(
        out,
        "Choose a network policy for your sandboxes (saved; change it with `sbt policy init`):"
    )?;
    writeln!(out, "  1) allow-all  open network")?;
    writeln!(
        out,
        "  2) balanced   AI APIs, package registries, code hosts and more (recommended)"
    )?;
    writeln!(out, "  3) deny-all   nothing unless you allow it")?;
    write!(out, "Choice [2]: ")?;
    out.flush()?;
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    policy.mode = Some(match line.trim() {
        "1" | "allow-all" => Mode::AllowAll,
        "" | "2" | "balanced" => Mode::Balanced,
        "3" | "deny-all" => Mode::DenyAll,
        other => bail!("'{other}' isn't 1, 2 or 3"),
    });
    policy.save(&ctx.paths)?;
    Ok(policy)
}

/// Fills a new sandbox's network, deny CIDRs and credentials from the policy and secrets, after
/// adding its `--deny-network` rules, and applies the resolved `kits` on top: their credentials
/// merge with the user's secrets and their rules join the policy. Returns the ids of the rules it
/// added (see `create`) and the kits' first-start steps.
pub fn prepare_create<R: Runner>(
    ctx: &Ctx<R>,
    req: &mut CreateRequest,
    deny_network: &[String],
    kits: Option<&Plan>,
) -> Result<(Vec<String>, Option<sandbox::KitFirstStart>)> {
    // Bad hosts fail before the policy prompt and before smolvm is asked for anything.
    let denies = super::policy::parse_create_denies(deny_network)?;
    let mut policy = ensure_policy(ctx)?;
    let secrets = SecretsFile::load(&ctx.paths)?;
    // Internal sandboxes run untrusted code (a kit's build steps): no credentials, not even as
    // placeholders.
    let services: Vec<String> = if name::is_internal(&req.name) {
        Vec::new()
    } else {
        secrets
            .services_for(&req.name)
            .into_iter()
            .filter(|s| secrets.service(s).is_some())
            .collect()
    };
    req.credentials = credentials(&secrets, &services)?;
    req.credential_hosts = credential_hosts(&secrets, &services);
    req.credential_env = req.credentials.iter().map(|c| c.env_var.clone()).collect();
    req.credential_env.sort();
    req.credential_env.dedup();
    req.secrets = services;
    let mut added = Vec::new();
    let mut first_start = None;
    if let Some(plan) = kits {
        // In memory until the save below, so an error before it leaves the policy file alone.
        let (steps, ids) = apply(
            plan,
            req,
            &mut policy,
            &secrets,
            &ctx.paths.kit_cache(),
            &|| host_git_identity(ctx),
        )?;
        added.extend(ids.iter().cloned());
        first_start = Some(sandbox::KitFirstStart {
            steps,
            restart_without: req.credential_install.clone(),
            rule_ids: ids,
        });
    }
    if !denies.is_empty() {
        added.extend(super::policy::add_create_denies(
            &mut policy,
            &req.name,
            &denies,
            &secrets,
            &req.secrets,
            &req.credential_hosts,
        )?);
    }
    if !added.is_empty() {
        // The last fallible step, so an error here leaves no rules for `create` to roll back.
        policy.save(&ctx.paths)?;
    }
    req.network = compile::network(&policy, &req.name, &req.credential_hosts);
    req.deny_cidrs = compile::deny_cidrs(&policy, &req.name);
    Ok((added, first_start))
}

/// The host's git `user.name` and `user.email`, for a kit's `git-identity@1`.
pub(crate) fn host_git_identity<R: Runner>(ctx: &Ctx<R>) -> Option<(String, String)> {
    let get = |key: &str| -> Option<String> {
        let out = std::process::Command::new("git")
            .args(["config", "--get", key])
            .current_dir(&ctx.cwd)
            .output()
            .ok()?;
        let v = String::from_utf8(out.stdout).ok()?.trim().to_string();
        (out.status.success() && !v.is_empty()).then_some(v)
    };
    Some((get("user.name")?, get("user.email")?))
}

/// Prepares, creates and starts a new sandbox, applying `kits` when given. When that fails and
/// smolvm doesn't have the machine (a failed kit first start removes it), the `--deny-network`
/// rules, the kits' rules and the `--clone` remote this create added are dropped again; rules the
/// sandbox name already had stay.
pub fn create<R: Runner>(
    ctx: &Ctx<R>,
    req: &mut CreateRequest,
    deny_network: &[String],
    kits: Option<&Plan>,
) -> Result<Sandbox> {
    create_with(ctx, req, deny_network, kits, None)
}

/// `create`, or with `prepared` steps whose rules are already in the policy (tests).
fn create_with<R: Runner>(
    ctx: &Ctx<R>,
    req: &mut CreateRequest,
    deny_network: &[String],
    kits: Option<&Plan>,
    prepared: Option<sandbox::KitFirstStart>,
) -> Result<Sandbox> {
    // Before prepare_create, which may prompt and adds the --deny-network and kit rules.
    if sandbox::find(&ctx.vm, &req.name)?.is_some() {
        bail!("sandbox '{}' already exists", req.name);
    }
    // The repo a `--clone` copies, at its top.
    let repo = req.clone.as_ref().map(|c| c.top.clone());
    if let Some(repo) = &repo {
        clone::check_remote_free(repo, &req.name)?;
        for remote in clone::userinfo_remotes(repo).unwrap_or_default() {
            eprintln!(
                "warning: remote '{remote}' has a user name or token in its URL; the sandbox can \
                 read it in {}/config",
                clone::SOURCE_MOUNT
            );
        }
    }
    // The name has no machine, so install-phase rules under it are an interrupted create's:
    // `rm` can't reach them, so they go before this create adds its own.
    if prepared.is_none() {
        drop_stale_install_rules(ctx, &req.name)?;
    }
    let mut added: Vec<String> = prepared
        .as_ref()
        .map(|k| k.rule_ids.clone())
        .unwrap_or_default();
    // Only a remote this create made: one left by an earlier sandbox of this name (`run --rm`)
    // keeps its fetched branches.
    let mut added_remote = None;
    let result = (|| {
        let (ids, kit) = prepare_create(ctx, req, deny_network, kits)?;
        added.extend(ids);
        let kit = kit.or(prepared);
        // The machine is created with this create's install-phase rules open: the first start's
        // setup and install hooks run under them, until `drop_install_rules`.
        if let Some(k) = &kit
            && !k.steps.install_rules.is_empty()
        {
            let policy = Policy::load(&ctx.paths)?;
            req.network = compile::network_with(
                &policy,
                &req.name,
                &req.credential_hosts,
                &k.steps.install_rules,
            );
            req.deny_cidrs = compile::deny_cidrs_with(&policy, &req.name, &k.steps.install_rules);
            for note in compile::install_deny_cidr_notes(&policy, &req.name, &k.steps.install_rules)
            {
                eprintln!("{note}");
            }
        }
        if let Some(repo) = &repo
            && clone::add_remote(repo, &req.name)?
        {
            added_remote = Some(repo);
        }
        let meta = sandbox::create::meta(req);
        let plan = match kit {
            Some(kit) => {
                let plan = first_start_plan(ctx, &meta, &kit.steps.install_rules)?;
                StartPlan {
                    kit: Some(kit),
                    ..plan
                }
            }
            None => start_plan(ctx, &meta)?,
        };
        let req: &CreateRequest = req;
        sandbox::create(&ctx.vm, req, &plan, |ids| drop_install_rules(ctx, req, ids))
    })();
    let rollback = result.is_err() && (!added.is_empty() || added_remote.is_some());
    let gone = rollback
        && match sandbox::find(&ctx.vm, &req.name) {
            Ok(found) => found.is_none(),
            Err(e) => {
                // Unknown whether the sandbox is gone: keep what it added (`rm` drops it).
                let name = &req.name;
                eprintln!(
                    "warning: couldn't check whether {name} still exists ({e:#}); what this create \
                     added was kept, and `sbt rm {name}` removes it if the sandbox exists"
                );
                if !added.is_empty() {
                    eprintln!(
                        "warning: if it doesn't, remove its rules with `sbt policy rm network \
                         --sandbox {name} --id <id>` (rule ids: {})",
                        added.join(", ")
                    );
                }
                false
            }
        };
    if gone {
        // Best effort: the create error is what matters.
        if !added.is_empty()
            && let Ok(mut policy) = Policy::load(&ctx.paths)
        {
            for id in &added {
                policy.remove_rules(Some(&req.name), Some(id), None);
            }
            let _ = policy.save(&ctx.paths);
        }
        if let Some(repo) = added_remote {
            let _ = clone::remove_remote(repo, &req.name);
        }
    }
    result
}

/// Removes the install-phase kit rules an interrupted create of `name` left in the policy.
fn drop_stale_install_rules<R: Runner>(ctx: &Ctx<R>, name: &str) -> Result<()> {
    let mut policy = Policy::load(&ctx.paths)?;
    let stale: Vec<String> = policy
        .rules_for(Some(name))
        .filter(|(r, s)| s.is_some() && r.is_kit_install())
        .map(|(r, _)| r.id.clone())
        .collect();
    if !stale.is_empty() {
        policy.remove_rules_by_ids(name, &stale);
        policy.save(&ctx.paths)?;
    }
    Ok(())
}

/// Removes a new sandbox's install-phase kit rules from the policy and returns its network
/// without them. Only this sandbox's rules change, so only its network needs pushing.
fn drop_install_rules<R: Runner>(
    ctx: &Ctx<R>,
    req: &CreateRequest,
    ids: &[String],
) -> Result<NetworkSpec> {
    let mut policy = Policy::load(&ctx.paths)?;
    policy.remove_rules_by_ids(&req.name, ids);
    policy.save(&ctx.paths)?;
    Ok(compile::network(&policy, &req.name, &req.credential_hosts))
}

/// Pushes the policy (as just saved) to running sandboxes. Failures are warnings: the policy
/// applies on each sandbox's next start anyway.
pub fn push_network<R: Runner>(ctx: &Ctx<R>, policy: &Policy) -> Result<()> {
    let sandboxes = match sandbox::list(&ctx.vm) {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "warning: couldn't update running sandboxes ({e:#}); the change applies when they next start"
            );
            return Ok(());
        }
    };
    let mut updated = 0;
    for sb in sandboxes.iter().filter(|s| s.is_running()) {
        let network = compile::network(policy, sb.name(), &sb.meta.credential_hosts);
        match ctx.vm.update_network(&sb.machine, &network) {
            Ok(()) => updated += 1,
            Err(e) => eprintln!(
                "warning: {}: the change applies on its next start ({e:#})",
                sb.name()
            ),
        }
    }
    if updated > 0 {
        writeln!(&ctx.out, "Updated {updated} running sandbox(es)")?;
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

    /// A sandbox's labels as recorded at create: `credential_env` holds the built-in services'
    /// env vars.
    fn meta(name: &str, secrets: &[String], hosts: &[String]) -> Meta {
        let mut credential_env: Vec<String> = secrets
            .iter()
            .filter_map(|s| crate::secrets::services::builtin(s))
            .flat_map(|s| s.env_vars)
            .collect();
        credential_env.sort();
        Meta {
            name: name.into(),
            agent: "claude".into(),
            created: 1,
            secrets: secrets.to_vec(),
            credential_hosts: hosts.to_vec(),
            credential_env,
            ..Default::default()
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
    fn fork_secrets_resolve_own_then_parent_then_global() {
        let t = test_env(&[]);
        set_policy(&t, "mode = \"deny-all\"");
        save_secret(&t, "github", None, "gh-global");
        save_secret(&t, "github", Some("a"), "gh-parent");
        let github = ["github".to_string()];
        let mut m = meta("a-fork-1", &github, &[]);
        m.fork_of = Some("a".into());
        let gh = |plan: StartPlan| plan.env[0].1.clone();
        assert_eq!(gh(start_plan(&t.ctx, &m).unwrap()), "gh-parent");
        save_secret(&t, "github", Some("a-fork-1"), "gh-fork");
        assert_eq!(gh(start_plan(&t.ctx, &m).unwrap()), "gh-fork");
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
    fn prepare_create_binds_configured_services() {
        let t = test_env(&[]);
        set_policy(&t, "mode = \"balanced\"");
        save_secret(&t, "anthropic", None, "sk-1");
        let mut req = CreateRequest {
            name: "s1".into(),
            ..Default::default()
        };
        let (added, _) = prepare_create(&t.ctx, &mut req, &["evil.com".to_string()], None).unwrap();
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
        assert!(list.patterns().contains(&"registry.npmjs.org".to_string()));
        let p = Policy::load(&t.ctx.paths).unwrap();
        assert_eq!(added, vec![p.sandboxes["s1"].rules[0].id.clone()]);
        assert!(!p.sandboxes["s1"].deny_network);
    }

    #[test]
    fn legacy_deny_network_still_compiles_to_deny_all() {
        // Written by v0.2.0's `--deny-network`.
        let t = test_env(&[]);
        set_policy(
            &t,
            "mode = \"balanced\"\n[sandboxes.s1]\ndeny_network = true\n",
        );
        save_secret(&t, "anthropic", None, "sk-1");
        let mut req = CreateRequest {
            name: "s1".into(),
            ..Default::default()
        };
        assert!(
            prepare_create(&t.ctx, &mut req, &[], None)
                .unwrap()
                .0
                .is_empty()
        );
        let NetworkSpec::Restricted(list) = &req.network else {
            panic!("restricted")
        };
        assert!(list.hosts().contains(&"api.anthropic.com".to_string()));
        assert!(
            !list.patterns().contains(&"registry.npmjs.org".to_string()),
            "deny-all ignores balanced"
        );
        let plan = start_plan(&t.ctx, &meta("s1", &[], &[])).unwrap();
        assert!(matches!(plan.network, NetworkSpec::Restricted(_)));
        let mut p = Policy::load(&t.ctx.paths).unwrap();
        assert!(p.sandboxes["s1"].deny_network, "still read");
        p.reset();
        assert!(p.sandboxes["s1"].deny_network, "reset keeps it");
    }

    #[test]
    fn start_without_a_mode_and_without_a_terminal_is_an_error() {
        let t = test_env(&[]);
        set_policy(&t, "[sandboxes.d1]\ndeny_network = true\n");
        for name in ["s1", "d1"] {
            let err = start_plan(&t.ctx, &meta(name, &[], &[]))
                .unwrap_err()
                .to_string();
            assert!(err.contains("sbt policy init"), "{err}");
        }
        assert_eq!(Policy::load(&t.ctx.paths).unwrap().mode, None);
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
        push_network(&t.ctx, &Policy::load(&t.ctx.paths).unwrap()).unwrap();
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

    /// A temp repo with an `origin` remote, as a path string.
    fn host_repo(origin: &str) -> (tempfile::TempDir, String) {
        let (dir, root) = temp_repo();
        git(&root, &["remote", "add", "origin", origin]);
        (dir, root.display().to_string())
    }

    #[test]
    fn start_plan_clones_with_the_host_repos_remotes() {
        let t = test_env(&[]);
        set_policy(&t, "mode = \"deny-all\"");
        let (_d, repo) = host_repo("https://x:y@github.com/o/r.git");
        let mut m = meta("s1", &[], &[]);
        m.clone_repo = Some(repo.clone());
        let plan = start_plan(&t.ctx, &m).unwrap();
        assert_eq!(
            plan.clone,
            Some(CloneStep {
                dir: repo,
                head: None,
                remotes: vec![("origin".into(), "https://github.com/o/r.git".into())],
            })
        );
        assert_eq!(
            start_plan(&t.ctx, &meta("s1", &[], &[])).unwrap().clone,
            None
        );
    }

    #[test]
    fn start_plan_is_branchable_only_for_forkable_sandboxes() {
        // Which sandboxes are forkable is `Meta::forkable`'s test; this checks the plan uses it.
        let branchable = |t: &TestEnv, m: &Meta| start_plan(&t.ctx, m).unwrap().branchable;
        let mountless = meta("s1", &[], &[]);
        let fork = Meta {
            fork_of: Some("s0".into()),
            ..mountless.clone()
        };
        let t = test_env(&[]);
        set_policy(&t, "mode = \"deny-all\"");
        assert!(branchable(&t, &mountless));
        assert!(!branchable(&t, &fork));

        let t = test_env(&[("SMOLBENTO_FORK", "false")]);
        set_policy(&t, "mode = \"deny-all\"");
        assert!(!branchable(&t, &mountless));
    }

    #[test]
    fn start_plan_for_a_linked_worktree_names_its_branch() {
        let t = test_env(&[]);
        set_policy(&t, "mode = \"deny-all\"");
        let (d, repo) = host_repo("https://github.com/o/r.git");
        let wt = d.path().canonicalize().unwrap().join("wt");
        git(
            Path::new(&repo),
            &["worktree", "add", "-q", "-b", "feat", wt.to_str().unwrap()],
        );
        let mut m = meta("s1", &[], &[]);
        m.clone_repo = Some(wt.display().to_string());
        let plan = start_plan(&t.ctx, &m).unwrap();
        assert_eq!(
            plan.clone.unwrap().head,
            Some(clone::WorktreeHead::Branch("feat".into()))
        );
    }

    #[test]
    fn start_plan_warns_when_the_host_repo_is_gone() {
        let t = test_env(&[]);
        set_policy(&t, "mode = \"deny-all\"");
        let mut m = meta("s1", &[], &[]);
        m.clone_repo = Some("/nonexistent/repo".into());
        let plan = start_plan(&t.ctx, &m).unwrap();
        assert_eq!(
            plan.clone,
            Some(CloneStep {
                dir: "/nonexistent/repo".into(),
                head: None,
                remotes: vec![],
            })
        );
    }

    #[test]
    fn install_only_credentials_are_left_out_of_later_starts() {
        let t = test_env(&[]);
        set_policy(&t, "mode = \"deny-all\"");
        save_secret(&t, "github", None, "gh-123");
        let m = Meta {
            credential_install: vec!["GH_TOKEN".into()],
            ..meta("s1", &["github".to_string()], &[])
        };
        let plan = start_plan(&t.ctx, &m).unwrap();
        assert_eq!(
            plan.env,
            vec![("GITHUB_TOKEN".to_string(), "gh-123".to_string())]
        );
        assert_eq!(plan.remove, vec!["GH_TOKEN"]);
        // The create's first start has them, for the install hooks.
        let first = first_start_plan(&t.ctx, &m, &[]).unwrap();
        assert!(
            first
                .env
                .iter()
                .any(|(k, v)| k == "GH_TOKEN" && v == "gh-123")
        );
        assert!(first.remove.is_empty());
    }

    #[test]
    fn kit_credential_vars_resolve_their_service_and_format() {
        use crate::sandbox::labels::CredFormat;
        let t = test_env(&[]);
        set_policy(&t, "mode = \"deny-all\"");
        save_secret(&t, "github", None, "gh-123");
        let mut m = meta("s1", &["github".to_string()], &[]);
        m.credential_env.push("SBX_KIT_GITHUB".into());
        m.credential_services = [("SBX_KIT_GITHUB".to_string(), "github".to_string())].into();
        m.credential_formats = [
            (
                "SBX_KIT_GITHUB".to_string(),
                CredFormat::Format("Bearer %s".into()),
            ),
            ("GH_TOKEN".to_string(), CredFormat::Basic("x".into())),
        ]
        .into();
        let plan = start_plan(&t.ctx, &m).unwrap();
        let env: std::collections::BTreeMap<_, _> = plan.env.into_iter().collect();
        assert_eq!(env["SBX_KIT_GITHUB"], "Bearer gh-123");
        assert_eq!(
            env["GH_TOKEN"],
            CredFormat::Basic("x".into()).apply("gh-123")
        );
        assert_eq!(env["GITHUB_TOKEN"], "gh-123");
        assert!(plan.remove.is_empty(), "{:?}", plan.remove);
    }

    /// `create` of `s1` with a kit that allows `registry.npmjs.org` for install only and
    /// `api.example.com` at runtime. Returns the env and the kit's two rule ids.
    fn kit_create(
        fail_install: bool,
        deny_network: &[String],
    ) -> (TestEnv, Result<Sandbox>, [String; 2]) {
        use crate::kits::apply::KitSteps;
        use crate::policy::Decision;
        use crate::sandbox::KitFirstStart;
        let t = test_env(&[]);
        set_policy(&t, "mode = \"deny-all\"");
        let mut policy = Policy::load(&t.ctx.paths).unwrap();
        let mut add = |host: &str, via: &str| {
            policy
                .add_rule(Some("s1"), Decision::Allow, host, via, None, None)
                .unwrap()
        };
        let ids = [
            add("registry.npmjs.org", "kit-install:k"),
            add("api.example.com", "kit:k"),
        ];
        policy.save(&t.ctx.paths).unwrap();
        let fake = t.ctx.vm.runner();
        fake.fail(&["machine", "status"], "NOT_FOUND", "vm not found");
        // A bad `--deny-network` host fails before the machine exists.
        if deny_network.is_empty() {
            fake.once_ok(
                &["machine", "status"],
                &machine_json("sbx-s1", "created", &[("sbx.name", "s1")]),
            );
        }
        // `create` checks the name is free first.
        fake.once_fail(&["machine", "status"], "NOT_FOUND", "vm not found");
        if fail_install {
            fake.fail(
                &[
                    "machine", "exec", "--name", "sbx-s1", "-u", "root", "--", "sh", "-c", "npm i",
                ],
                "EXEC_FAILED",
                "npm ERR! 404",
            );
        }
        let kit = KitFirstStart {
            steps: KitSteps {
                install_rules: vec![ids[0].clone()],
                install: vec![crate::kits::apply::InstallStep {
                    label: "kit k install hook 1".into(),
                    user: None,
                    script: "npm i".into(),
                }],
                ..Default::default()
            },
            rule_ids: ids.to_vec(),
            ..Default::default()
        };
        let mut req = CreateRequest {
            name: "s1".into(),
            ..Default::default()
        };
        let result = create_with(&t.ctx, &mut req, deny_network, None, Some(kit));
        (t, result, ids)
    }

    #[test]
    fn create_with_a_kit_drops_install_rules_after_the_hooks() {
        let (t, result, ids) = kit_create(false, &[]);
        result.unwrap();
        let p = Policy::load(&t.ctx.paths).unwrap();
        let left: Vec<&String> = p.sandboxes["s1"].rules.iter().map(|r| &r.id).collect();
        assert_eq!(left, vec![&ids[1]]);
        let lines = t.ctx.vm.runner().call_lines();
        let create = lines
            .iter()
            .position(|l| l.starts_with("machine create"))
            .unwrap();
        assert!(
            lines[create].contains("registry.npmjs.org"),
            "{}",
            lines[create]
        );
        let hook = lines
            .iter()
            .position(|l| l.ends_with("sh -c npm i"))
            .unwrap();
        let update = &lines[hook + 1];
        assert!(
            update.starts_with("machine update -n sbx-s1 --reset-allow-list")
                && update.contains("api.example.com")
                && !update.contains("registry.npmjs.org"),
            "{update}"
        );
    }

    #[test]
    fn the_first_start_opens_this_creates_install_rules() {
        let (t, result, _) = kit_create(false, &[]);
        result.unwrap();
        let lines = t.ctx.vm.runner().call_lines();
        let start = lines
            .iter()
            .position(|l| l.starts_with("machine start"))
            .unwrap_or_else(|| panic!("{lines:#?}"));
        let update = &lines[start - 1];
        assert!(
            update.starts_with("machine update -n sbx-s1") && update.contains("registry.npmjs.org"),
            "{lines:#?}"
        );
    }

    #[test]
    fn install_rules_left_by_an_interrupted_create_stay_shut() {
        use crate::policy::Decision;
        let t = test_env(&[]);
        set_policy(&t, "mode = \"deny-all\"");
        let mut policy = Policy::load(&t.ctx.paths).unwrap();
        let install = policy
            .add_rule(
                Some("s1"),
                Decision::Allow,
                "registry.npmjs.org",
                "kit-install:k",
                None,
                None,
            )
            .unwrap();
        policy
            .add_rule(
                Some("s1"),
                Decision::Allow,
                "api.example.com",
                "kit:k",
                None,
                None,
            )
            .unwrap();
        policy.save(&t.ctx.paths).unwrap();
        let m = meta("s1", &[], &[]);
        let later = format!("{:?}", start_plan(&t.ctx, &m).unwrap().network);
        assert!(
            later.contains("api.example.com") && !later.contains("registry.npmjs.org"),
            "{later}"
        );
        // Neither a first start without these ids nor a policy push opens them.
        let first = format!("{:?}", first_start_plan(&t.ctx, &m, &[]).unwrap().network);
        assert!(!first.contains("registry.npmjs.org"), "{first}");
        let pushed = format!("{:?}", compile::network(&policy, "s1", &[]));
        assert!(!pushed.contains("registry.npmjs.org"), "{pushed}");
        let first = format!(
            "{:?}",
            first_start_plan(&t.ctx, &m, &[install]).unwrap().network
        );
        assert!(first.contains("registry.npmjs.org"), "{first}");
    }

    #[test]
    fn a_re_create_after_an_interrupted_one_opens_then_drops_its_install_rules() {
        use crate::kits::args::ArgValues;
        use crate::kits::model::{
            Cap, CapBody, Content, Hook, HookCmd, Kind, Kit, Lifecycle, NetRule, Rules, Source,
        };
        use crate::policy::Decision;
        let t = test_env(&[]);
        set_policy(&t, "mode = \"deny-all\"");
        // An interrupted create of s1 left its install rule behind, and no machine.
        let mut policy = Policy::load(&t.ctx.paths).unwrap();
        policy
            .add_rule(
                Some("s1"),
                Decision::Allow,
                "registry.npmjs.org",
                "kit-install:k",
                None,
                None,
            )
            .unwrap();
        policy.save(&t.ctx.paths).unwrap();
        let fake = t.ctx.vm.runner();
        fake.fail(&["machine", "status"], "NOT_FOUND", "vm not found");
        fake.once_ok(
            &["machine", "status"],
            &machine_json("sbx-s1", "created", &[("sbx.name", "s1")]),
        );
        fake.once_fail(&["machine", "status"], "NOT_FOUND", "vm not found");
        let kit = |name: &str, kind| Kit {
            name: name.into(),
            source: Source::Registry(format!("acme/{name}:1")),
            digest: Some(format!("sha256:{}", "ab".repeat(32))),
            kind,
            provides: vec![],
            requires: vec![],
            integrates: vec![],
            conflicts: vec![],
            args: Default::default(),
            caps: vec![],
            env: vec![],
            content: Content::None,
            command: None,
            config: None,
        };
        let mut wl = kit("wl", Kind::Workload);
        wl.content = Content::Image("img:1".into());
        let mut k = kit("k", Kind::Mixin);
        let cap = |ty: &str, body| Cap {
            ty: format!("com.docker.sandbox/{ty}"),
            optional: false,
            body,
        };
        k.caps = vec![
            cap(
                "network-policy@2",
                CapBody::Network {
                    install: Rules {
                        allow: vec![NetRule {
                            host: "registry.npmjs.org".into(),
                            methods: vec![],
                            paths: vec![],
                        }],
                        deny: vec![],
                    },
                    runtime: Rules::default(),
                },
            ),
            cap(
                "lifecycle@1",
                CapBody::Lifecycle(Lifecycle {
                    install: vec![Hook {
                        command: HookCmd::Shell("npm i".into()),
                        user: None,
                        env: vec![],
                        background: false,
                        clean_env: true,
                    }],
                    ..Default::default()
                }),
            ),
        ];
        let plan = crate::kits::resolve::resolve(wl, vec![k], &ArgValues::default()).unwrap();
        let mut req = CreateRequest {
            name: "s1".into(),
            ..Default::default()
        };
        create_with(&t.ctx, &mut req, &[], Some(&plan), None).unwrap();
        let lines = t.ctx.vm.runner().call_lines();
        let create = lines
            .iter()
            .find(|l| l.starts_with("machine create"))
            .unwrap();
        assert!(create.contains("registry.npmjs.org"), "{create}");
        let p = Policy::load(&t.ctx.paths).unwrap();
        let left: Vec<&crate::policy::Rule> = p
            .sandboxes
            .get("s1")
            .map(|s| s.rules.iter().collect())
            .unwrap_or_default();
        assert!(left.iter().all(|r| !r.is_kit_install()), "{left:?}");
    }

    #[test]
    fn a_failed_kit_install_removes_the_sandbox_and_every_kit_rule() {
        let (t, result, _) = kit_create(true, &[]);
        let err = result.unwrap_err().to_string();
        assert_eq!(
            err,
            "kit install failed (the sandbox was removed): kit k install hook 1 failed:\nnpm ERR! 404"
        );
        assert!(
            t.ctx
                .vm
                .runner()
                .call_lines()
                .contains(&"machine delete -n sbx-s1 -f".to_string())
        );
        let p = Policy::load(&t.ctx.paths).unwrap();
        assert!(!p.sandboxes.contains_key("s1"), "{p:?}");
    }

    #[test]
    fn a_create_failing_before_the_machine_exists_drops_the_kit_rules() {
        let (t, result, _) = kit_create(false, &["not a host!".to_string()]);
        assert!(result.is_err());
        assert!(
            !t.ctx
                .vm
                .runner()
                .call_lines()
                .iter()
                .any(|l| l.starts_with("machine create")),
            "fails in prepare_create"
        );
        let p = Policy::load(&t.ctx.paths).unwrap();
        assert!(!p.sandboxes.contains_key("s1"), "{p:?}");
    }

    #[test]
    fn unrecorded_install_and_kit_vars_are_still_removed() {
        let t = test_env(&[]);
        set_policy(&t, "mode = \"deny-all\"");
        save_secret(&t, "github", None, "gh-123");
        // `credential_env` doesn't list either; the labels still name them.
        let m = Meta {
            credential_install: vec!["GH_TOKEN".into()],
            credential_services: [("SBX_KIT_GONE".to_string(), "gone".to_string())].into(),
            ..meta("s1", &["github".to_string()], &[])
        };
        let m = Meta {
            credential_env: vec!["GITHUB_TOKEN".into()],
            ..m
        };
        let plan = start_plan(&t.ctx, &m).unwrap();
        assert_eq!(plan.remove, vec!["GH_TOKEN", "SBX_KIT_GONE"]);
        assert_eq!(
            plan.env,
            vec![("GITHUB_TOKEN".to_string(), "gh-123".to_string())]
        );
    }
}
