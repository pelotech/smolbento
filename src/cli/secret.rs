//! `bento secret`: secret sources. Values go to the secret store, never to secrets.toml.

use std::io::{BufRead, Write};

use anyhow::{Context, Result, anyhow, bail};

use super::{
    Ctx, SecretCmd, SecretLsArgs, SecretRmArgs, SecretSetArgs, SecretSource, Unsupported, confirm,
    table,
};
use crate::policy::{Policy, compile};
use crate::provision;
use crate::sandbox::{self, labels, name};
use crate::secrets::resolve::{bound_vars, resolve, with_value};
use crate::secrets::services::Service;
use crate::secrets::{
    CustomService, RegistryEntry, SecretEntry, SecretsFile, Source, registry_account, scope_for,
    services,
};
use crate::smolvm::{NetworkSpec, Runner};

pub fn run<R: Runner>(ctx: &mut Ctx<R>, cmd: SecretCmd) -> Result<i32> {
    let mut cmd = cmd;
    // Asked before the lock, which every create and start of a hosted sandbox waits for.
    // `rm` refuses `--all` with these itself, unasked.
    if let SecretCmd::Rm(a) = &mut cmd
        && a.all
        && a.registry.is_none()
        && !a.all_sandboxes
    {
        confirm(ctx, "Remove every secret?", a.force)?;
        a.force = true;
    }
    // Each command that changes the file reloads it under the lock first (`locked`).
    let mut file = SecretsFile::load(&ctx.paths)?;
    match cmd {
        SecretCmd::Set(a) if a.registry.is_some() => {
            let _lock = locked(ctx, &mut file)?;
            registry_set(ctx, &mut file, a)?
        }
        SecretCmd::Set(mut a) => {
            if a.username.is_some() || a.password_stdin || a.registry_auth_endpoint.is_some() {
                bail!("--username, --password-stdin and --registry-auth-endpoint need --registry");
            }
            super::refuse(&[
                (a.oauth, "--oauth"),
                (a.refresh.is_some(), "--refresh"),
                (a.all_sandboxes, "--all-sandboxes"),
                (a.no_verify || a.show_error, "--no-verify/--show-error"),
            ])?;
            let service = a
                .service
                .context("specify a service, e.g. `bento secret set anthropic`")?;
            if service.starts_with("mcp:") {
                let _lock = ready(ctx, &mut file, &service, &mut a.source)?;
                set_mcp(ctx, &mut file, &service, a.source)?;
            } else {
                if file.service(&service).is_none() {
                    bail!(services::unknown(&service));
                }
                let _lock = ready(ctx, &mut file, &service, &mut a.source)?;
                set(ctx, &mut file, &service, a.source)?;
            }
        }
        SecretCmd::SetCustom(mut a) => {
            super::refuse(&[
                (a.refresh.is_some(), "--refresh"),
                (a.no_verify || a.show_error, "--no-verify/--show-error"),
            ])?;
            if a.placeholder.is_some() {
                return Err(Unsupported(
                    "--placeholder is not supported; smolvm chooses the placeholder".into(),
                )
                .into());
            }
            check_env_name(&a.env)?;
            if let Some(owner) = services::env_var_owner(&a.env) {
                bail!(
                    "{} belongs to the built-in {owner} service; use `bento secret set {owner}`",
                    a.env
                );
            }
            let hosts = custom_hosts(&a.hosts)?;
            if !cfg!(test) {
                warn_unresolved(&hosts);
            }
            let name = a.env.to_ascii_lowercase().replace('_', "-");
            let _lock = ready(ctx, &mut file, &name, &mut a.source)?;
            file.custom.retain(|c| c.name != name);
            file.custom.push(CustomService {
                name: name.clone(),
                env: a.env.clone(),
                hosts,
            });
            set(ctx, &mut file, &name, a.source)?;
        }
        SecretCmd::Ls(a) => ls(ctx, &file, &a)?,
        SecretCmd::Rm(a) => {
            let _lock = locked(ctx, &mut file)?;
            rm(ctx, &mut file, a)?
        }
        SecretCmd::Import(_) => {
            return Err(Unsupported("`bento secret import` is not implemented yet".into()).into());
        }
    }
    Ok(0)
}

fn ls<R: Runner>(ctx: &Ctx<R>, file: &SecretsFile, a: &SecretLsArgs) -> Result<()> {
    // A fork also uses its original's sandbox secrets (`SecretsFile::entry_for`). If smolvm can't
    // be asked, the listing stays a plain file read.
    let parent = a
        .sandbox
        .as_deref()
        .and_then(|s| sandbox::find(&ctx.vm, s).ok().flatten())
        .and_then(|sb| sb.meta.fork_of);
    let entries = listed(file, a, parent.as_deref());
    // Every registry login, or with `--sandbox` that sandbox's own (as sbx lists them); none when
    // filtering by `-g` or `--service`.
    let registries: Vec<&RegistryEntry> = file
        .registries
        .iter()
        .filter(|_| !a.global && a.service.is_none())
        .filter(|r| a.sandbox.is_none() || r.sandbox == a.sandbox)
        .collect();
    // -q wins over --json, as in `ls` and `settings ls`.
    let text = if a.quiet {
        entries.iter().map(|e| format!("{}\n", e.service)).collect()
    } else {
        match a.output.structured(&ls_doc(&entries, &registries))? {
            Some(doc) => doc,
            None => render_ls(&entries, &registries),
        }
    };
    write!(&ctx.out, "{text}")?;
    Ok(())
}

/// `--env` of `secret set-custom`: a name a shell (and smolvm's credential flag) accepts.
fn check_env_name(env: &str) -> Result<()> {
    if !crate::kits::guest::is_env_name(env) {
        bail!(
            "'{env}' isn't a valid env var name: use letters, digits and '_', not starting with \
             a digit (e.g. MY_API_KEY)"
        );
    }
    Ok(())
}

/// `--host`s of `secret set-custom`, trimmed, lowercased and deduped. smolvm takes them as
/// `--credential NAME=ENV@HOST,…` and `--allow-host`, so each must be a plain DNS host name.
fn custom_hosts(raw: &[String]) -> Result<Vec<String>> {
    let mut hosts: Vec<String> = Vec::new();
    for r in raw {
        let host = crate::secrets::check_credential_host(r)?;
        if !hosts.contains(&host) {
            hosts.push(host);
        }
    }
    Ok(hosts)
}

/// smolvm resolves credential hosts when it creates a sandbox, so one that doesn't resolve fails
/// that create. Only a warning here: the user may be offline.
fn warn_unresolved(hosts: &[String]) {
    use std::net::ToSocketAddrs;
    // `*.x` names no single host to look up.
    for host in hosts.iter().filter(|h| !h.starts_with("*.")) {
        if (host.as_str(), 443).to_socket_addrs().is_err() {
            crate::warning!(
                "{host} doesn't resolve right now; sandboxes created with this secret \
                 will fail to start until it does"
            );
        }
    }
}

fn set<R: Runner>(
    ctx: &Ctx<R>,
    file: &mut SecretsFile,
    service: &str,
    src: SecretSource,
) -> Result<()> {
    let scope = scope_for(src.sandbox.as_deref());
    let sandbox = src.sandbox.clone();
    let described = store(ctx, file, service, src)?;
    writeln!(&ctx.out, "Saved {service} secret ({described}; {scope})")?;
    explain_impact(ctx, file, service, sandbox.as_deref())
}

/// `secret set mcp:<server>:<name>`: the value of a registered MCP server's header placeholder
/// (`bento mcp add --header 'Name: ${name}'`). Global only, and never bound to a sandbox as an
/// ordinary secret: `--static-mcp` binds it to the server's host.
fn set_mcp<R: Runner>(
    ctx: &Ctx<R>,
    file: &mut SecretsFile,
    service: &str,
    src: SecretSource,
) -> Result<()> {
    let shape = service
        .strip_prefix("mcp:")
        .and_then(|rest| rest.split_once(':'))
        .filter(|(server, name)| {
            crate::mcp::check_name(server).is_ok()
                && crate::mcp::placeholder(&format!("${{{name}}}")).is_some()
        });
    if shape.is_none() {
        bail!("'{service}': an MCP secret is named mcp:<server>:<name>");
    }
    if src.sandbox.is_some() {
        bail!("MCP secrets are global: drop --sandbox");
    }
    let described = store(ctx, file, service, src)?;
    writeln!(&ctx.out, "Saved {service} secret ({described}; global)")?;
    Ok(())
}

/// `secret set` without its output: stores the value (if any) and saves the entry. Returns where
/// the value lives, as `secret set` describes it.
pub(crate) fn store<R: Runner>(
    ctx: &Ctx<R>,
    file: &mut SecretsFile,
    service: &str,
    src: SecretSource,
) -> Result<String> {
    if let Some(s) = &src.sandbox {
        name::validate(s)?;
    }
    let given = [
        src.token.is_some(),
        src.value_stdin,
        src.reference.is_some(),
        src.command.is_some(),
    ];
    if given.iter().filter(|g| **g).count() > 1 {
        bail!("pass only one of -t, --value-stdin, --ref and --command");
    }
    let scope = scope_for(src.sandbox.as_deref());
    let account = SecretEntry {
        service: service.into(),
        scope: scope.clone(),
        source: Source::Keychain,
    }
    .account();
    // The entry this replaces, if any. A stored value is deleted only once the new entry is saved.
    let old = file
        .secrets
        .iter()
        .find(|e| e.service == service && e.scope == scope)
        .cloned();
    let (source, value) = if let Some(r) = src.reference {
        crate::secrets::resolve::ref_command(&r)?;
        (Source::Ref { reference: r }, None)
    } else if let Some(c) = src.command {
        (Source::Command { command: c }, None)
    } else {
        let value = match src.token {
            Some(t) => t,
            None if src.value_stdin => stdin_value(ctx)?,
            None => read_value(ctx, service)?,
        };
        if value.is_empty() {
            bail!("empty value");
        }
        (Source::Keychain, Some(value))
    };
    // A stored value this replaces, kept in memory to put back if secrets.toml can't be saved.
    let mut previous = None;
    if let Some(v) = &value {
        if old.as_ref().is_some_and(|e| e.source == Source::Keychain) {
            previous = ctx.store.get(&account)?;
        }
        if let Err(e) = ctx.store.set(&account, v) {
            restore(ctx, &account, previous.as_deref());
            return Err(e);
        }
    }
    let described = match &source {
        Source::Keychain => format!("stored in {}", ctx.store.describe()),
        other => other.describe(),
    };
    file.set(SecretEntry {
        service: service.into(),
        scope: scope.clone(),
        source,
    });
    if let Err(e) = file.save(&ctx.paths) {
        if value.is_some() {
            restore(ctx, &account, previous.as_deref());
        }
        return Err(e);
    }
    // A new stored value replaced the old one in place; otherwise the old one goes.
    if value.is_none()
        && let Some(old) = old
    {
        forget(ctx, &[old])?;
    }
    Ok(described)
}

/// Hands the running `sb` service `name`'s new `value` (`machine credentials refresh`): false when
/// `sb` binds none of its variables, an error when smolvm can't (a machine that booted without
/// bindings can't take values live). The caller says what that means.
fn refresh<R: Runner>(
    ctx: &Ctx<R>,
    sb: &sandbox::Sandbox,
    service: &Service,
    name: &str,
    value: &str,
) -> Result<bool> {
    // Only the variables `sb` binds: smolvm refuses the whole refresh for one it doesn't, and a
    // kit can take a service's key without its variable (Claude's binds only SBX_KIT_ANTHROPIC).
    let vars: Vec<&String> = bound_vars(service, &sb.meta, name, false)
        .into_iter()
        .filter(|v| sb.meta.rec.credential_env.contains(v))
        .collect();
    if vars.is_empty() {
        return Ok(false);
    }
    ctx.vm
        .refresh_credentials(&sb.machine, &with_value(&sb.meta, vars, value))?;
    Ok(true)
}

/// Puts a stored value back as it was before a `set` whose store write or secrets.toml save then
/// failed: the earlier value, or none. Best effort; the first error is the one the caller reports.
fn restore<R: Runner>(ctx: &Ctx<R>, account: &str, previous: Option<&str>) {
    let _ = match previous {
        Some(v) => ctx.store.set(account, v),
        None => ctx.store.delete(account),
    };
}

/// Which sandboxes have the new value now and which get it on their next start. A running sandbox
/// bound to the service is handed the value at once; one in scope without it gets it bound.
fn explain_impact<R: Runner>(
    ctx: &Ctx<R>,
    file: &SecretsFile,
    service: &str,
    scope: Option<&str>,
) -> Result<()> {
    let Ok(sandboxes) = sandbox::list(&ctx.vm) else {
        return Ok(());
    };
    let svc = file.service(service);
    // The sandboxes that use this entry: a sandbox's own secret wins over its original's (for a
    // fork), which wins over the global one. Internal ones (`_builder`) never get a secret.
    let own = scope_for(scope);
    let (bound, unbound): (Vec<_>, Vec<_>) = sandboxes
        .iter()
        .filter(|s| !name::is_internal(s.name()))
        .filter(|s| {
            file.entry_for(s.name(), s.meta.fork_of.as_deref(), service)
                .is_some_and(|e| e.scope == own)
        })
        .partition(|s| is_bound(s, svc.as_ref(), service));
    // A hosted sandbox's values live in its egress process: smolvm refuses credential changes in
    // external mode. A restart applies a new value, or a new service bound to its label.
    let (hosted_bound, bound): (Vec<_>, Vec<_>) =
        bound.into_iter().partition(|s| s.meta.egress.is_some());
    // Read once for every sandbox: a --ref or --command source may prompt, or be slow. Binding a
    // new service to a hosted sandbox doesn't need it.
    let new = match (
        bound.iter().any(|s| s.is_running()) || unbound.iter().any(|s| s.meta.egress.is_none()),
        file.scoped_entry(scope, service),
    ) {
        (true, Some(entry)) => match (svc, resolve(entry, ctx.store.as_ref())) {
            (Some(svc), Ok(value)) => Some((svc, value)),
            (_, Err(e)) => {
                crate::warning!(
                    "couldn't read the new {service} secret to hand it over now: {e:#}"
                );
                None
            }
            (None, _) => None,
        },
        _ => None,
    };
    let (mut now, mut later) = (Vec::new(), Vec::new());
    let mut fresh_env = false;
    for s in hosted_bound {
        if s.is_running() && provision::restart_egress(ctx, s) {
            now.push(s);
        } else {
            later.push(s);
        }
    }
    for s in bound {
        let refreshed = s.is_running()
            && new
                .as_ref()
                // Not now (no live bindings yet): the sandbox gets it at its next start, as listed.
                .is_some_and(|(svc, value)| refresh(ctx, s, svc, service, value).unwrap_or(false));
        if refreshed {
            now.push(s);
        } else {
            later.push(s);
        }
    }
    let names = |v: &[&sandbox::Sandbox]| v.iter().map(|s| s.name()).collect::<Vec<_>>().join(", ");
    let value = new.as_ref().map(|(_, v)| v.as_str());
    // A sandbox that isn't hosted needs the value.
    let (unbound, unread): (Vec<_>, Vec<_>) = unbound
        .into_iter()
        .partition(|s| s.meta.egress.is_some() || value.is_some());
    if !unread.is_empty() {
        writeln!(
            &ctx.out,
            "{} don't have it yet; run `bento secret set {service}` again once it can be read",
            names(&unread)
        )?;
    }
    match (unbound.is_empty(), Policy::load(&ctx.paths)) {
        (true, _) => {}
        (false, Err(e)) => crate::warning!(
            "couldn't read the policy to give {} the secret: {e:#}",
            names(&unbound)
        ),
        (false, Ok(policy)) => {
            for s in unbound {
                match bind(ctx, file, &policy, s, service, value) {
                    Ok(true) => {
                        // A hosted sandbox's guest gets its placeholder as a new variable.
                        fresh_env |= s.meta.egress.is_some();
                        now.push(s);
                    }
                    Ok(false) => later.push(s),
                    Err(e) => crate::warning!(
                        "{}: couldn't give it the {service} secret: {e:#}",
                        s.name()
                    ),
                }
            }
        }
    }
    if !now.is_empty() {
        writeln!(&ctx.out, "Applied to {} now", names(&now))?;
    }
    if fresh_env {
        writeln!(
            &ctx.out,
            "Commands started from now see its variable; sessions already running keep their \
             environment until they restart"
        )?;
    }
    if !later.is_empty() {
        writeln!(&ctx.out, "Applies to {} on their next start", names(&later))?;
    }
    Ok(())
}

/// Whether `sb` has service `name`: created with it, or a kit binds one of its variables.
fn is_bound(sb: &sandbox::Sandbox, service: Option<&Service>, name: &str) -> bool {
    sb.meta.rec.secrets.iter().any(|x| x == name)
        || service.is_some_and(|svc| {
            bound_vars(svc, &sb.meta, name, true)
                .iter()
                .any(|v| sb.meta.rec.credential_env.contains(v))
        })
}

/// `old` and `new` together, sorted and deduped, as create records a list label.
fn merged(old: &[String], new: Vec<String>) -> Vec<String> {
    let mut all: Vec<String> = old.iter().cloned().chain(new).collect();
    all.sort();
    all.dedup();
    all
}

/// Binds service `name` to `sb`, which was created without it, as create would have: its network,
/// its labels, and its credentials. smolvm swaps `value` (in smolvm's env only); a hosted
/// sandbox's egress process swaps it, from a binding in its `sbx.egress` label, while the guest
/// gets the placeholder, so `value` is needed only when `sb` isn't hosted. True when a running `sb`
/// uses the value now; false when it waits for the next start.
fn bind<R: Runner>(
    ctx: &Ctx<R>,
    file: &SecretsFile,
    policy: &Policy,
    sb: &sandbox::Sandbox,
    name: &str,
    value: Option<&str>,
) -> Result<bool> {
    // Before anything changes.
    if sb.meta.egress.is_none() && value.is_none() {
        bail!("no value to hand to a sandbox that isn't hosted");
    }
    let services = [name.to_string()];
    let creds = provision::credentials(file, &services)?;
    let rec = &sb.meta.rec;
    let hosts = merged(
        &rec.credential_hosts,
        provision::credential_hosts(file, &services),
    );
    // First: smolvm refuses a credential whose host the machine's allow list (running or
    // stopped) doesn't reach. An open network (allow-all) has no allow list to change, and smolvm
    // can't add one live.
    let network = compile::network(
        policy,
        sb.name(),
        &hosts,
        rec.host_access,
        sb.meta.egress.is_some(),
    );
    if network != NetworkSpec::Open {
        ctx.vm.update_network(&sb.machine, &network)?;
    }
    let vars: Vec<String> = creds.iter().map(|c| c.env_var.clone()).collect();
    let mut labels = vec![
        (
            labels::SECRETS,
            merged(&rec.secrets, services.to_vec()).join(","),
        ),
        (
            labels::CREDENTIAL_ENV,
            merged(&rec.credential_env, vars).join(","),
        ),
        (labels::CREDENTIAL_HOSTS, hosts.join(",")),
    ];
    if let Some(label) = &sb.meta.egress {
        let mut label = label.clone();
        let had = label.bindings.len();
        crate::egress::add_bindings(&mut label, &creds);
        let placeholders: Vec<_> = (label.bindings[had..].iter())
            .map(|b| (b.env.clone(), b.placeholder.clone()))
            .collect();
        ctx.vm.set_env(&sb.machine, &placeholders)?;
        labels.push((labels::EGRESS, label.to_label()));
        ctx.vm.set_labels(&sb.machine, &labels)?;
        return Ok(sb.is_running() && provision::restart_egress(ctx, sb));
    }
    let env = with_value(
        &sb.meta,
        creds.iter().map(|c| &c.env_var).collect(),
        value.unwrap_or_default(),
    );
    if !creds.is_empty() {
        ctx.vm
            .add_credentials(&sb.machine, &creds, &env)
            .map_err(|e| anyhow!("{e:#}; its new hosts stay allowed until its next start"))?;
    }
    ctx.vm.set_labels(&sb.machine, &labels)?;
    // The probe: smolvm takes values live only on a machine that booted with bindings, and
    // refuses the refresh on one that didn't.
    Ok(sb.is_running() && !env.is_empty() && ctx.vm.refresh_credentials(&sb.machine, &env).is_ok())
}

/// Locks the secrets file and reads it again, so a change saved while holding the lock keeps
/// what other commands saved. Taken after any prompt: every create and start waits for it.
fn locked<R: Runner>(ctx: &Ctx<R>, file: &mut SecretsFile) -> Result<std::fs::File> {
    let lock = crate::config::lock(&ctx.paths.secrets_file())?;
    *file = SecretsFile::load(&ctx.paths)?;
    Ok(lock)
}

/// For `secret set`, once its arguments are checked: asks for the value when no source was
/// given, then `locked`.
fn ready<R: Runner>(
    ctx: &Ctx<R>,
    file: &mut SecretsFile,
    service: &str,
    src: &mut SecretSource,
) -> Result<std::fs::File> {
    if src.token.is_none() && !src.value_stdin && src.reference.is_none() && src.command.is_none() {
        src.token = Some(read_value(ctx, service)?);
    }
    locked(ctx, file)
}

fn read_value<R: Runner>(ctx: &Ctx<R>, service: &str) -> Result<String> {
    if !ctx.can_prompt() {
        bail!("no terminal to prompt on; pass -t, --ref or --command");
    }
    eprint!("Value for {service} (input hidden, empty line to cancel): ");
    std::io::stderr().flush()?;
    let fd = libc::STDIN_FILENO;
    // SAFETY: plain termios calls on stdin; the saved settings are restored below.
    let mut saved: libc::termios = unsafe { std::mem::zeroed() };
    let have_term = unsafe { libc::tcgetattr(fd, &mut saved) } == 0;
    if have_term {
        let mut quiet = saved;
        quiet.c_lflag &= !libc::ECHO;
        unsafe { libc::tcsetattr(fd, libc::TCSANOW, &quiet) };
    }
    let mut line = String::new();
    // Ctrl-C must not kill the process while echo is off.
    let _guard = crate::smolvm::IgnoreSignals::new(&[libc::SIGINT]);
    let read = std::io::stdin().lock().read_line(&mut line);
    if have_term {
        unsafe { libc::tcsetattr(fd, libc::TCSANOW, &saved) };
        eprintln!();
    }
    read?;
    Ok(line.trim_end_matches(['\n', '\r']).to_string())
}

/// The secrets `ls` shows for `a`'s filters; a fork (`fork_of` is its original) also shows its
/// original's.
fn listed<'a>(
    file: &'a SecretsFile,
    a: &SecretLsArgs,
    fork_of: Option<&str>,
) -> Vec<&'a SecretEntry> {
    let own = a.sandbox.as_deref().map(|s| scope_for(Some(s)));
    let parent = fork_of.map(|p| scope_for(Some(p)));
    file.secrets
        .iter()
        .filter(|e| !a.global || e.scope == "global")
        .filter(|e| {
            let shown_for_own = own
                .as_ref()
                .is_none_or(|o| e.scope == "global" || &e.scope == o);
            shown_for_own || inherited(file, e, own.as_deref(), parent.as_deref())
        })
        .filter(|e| a.service.as_deref().is_none_or(|s| e.service == s))
        .collect()
}

/// A registry login's scope as listed: its sandbox, or `(host only)`.
fn registry_scope(r: &RegistryEntry) -> String {
    r.sandbox.clone().unwrap_or_else(|| "(host only)".into())
}

/// sbx's `secret ls --json` shape. Values are never shown; `custom_secrets`, `shadowed_services`
/// and `env_only_count` are sbx's, always empty here (custom services are listed as secrets).
fn ls_doc(entries: &[&SecretEntry], registries: &[&RegistryEntry]) -> impl serde::Serialize {
    #[derive(serde::Serialize)]
    struct Row {
        scope: String,
        r#type: &'static str,
        name: String,
        secret: &'static str,
    }
    #[derive(serde::Serialize)]
    struct Doc {
        secrets: Vec<Row>,
        custom_secrets: [(); 0],
        shadowed_services: [(); 0],
        env_only_count: u32,
    }
    let services = entries.iter().map(|e| Row {
        scope: e
            .scope
            .strip_prefix("sandbox:")
            .unwrap_or(&e.scope)
            .to_string(),
        r#type: "service",
        name: e.service.clone(),
        secret: "(stored)",
    });
    let logins = registries.iter().map(|r| Row {
        scope: registry_scope(r),
        r#type: "registry",
        name: r.host.clone(),
        secret: "(stored)",
    });
    Doc {
        secrets: services.chain(logins).collect(),
        custom_secrets: [],
        shadowed_services: [],
        env_only_count: 0,
    }
}

/// The secrets table, then the registry logins in a table of their own.
fn render_ls(entries: &[&SecretEntry], registries: &[&RegistryEntry]) -> String {
    if entries.is_empty() && registries.is_empty() {
        return "No secrets found\n".into();
    }
    let mut tables = Vec::new();
    if !entries.is_empty() {
        let mut rows = Vec::new();
        for e in entries {
            rows.push(vec![
                e.service.clone(),
                e.scope.clone(),
                e.source.describe(),
            ]);
        }
        tables.push(table(&["SERVICE", "SCOPE", "SOURCE"], rows));
    }
    if !registries.is_empty() {
        let mut rows = Vec::new();
        for r in registries {
            rows.push(vec![
                registry_scope(r),
                "registry".into(),
                r.host.clone(),
                "(stored)".into(),
            ]);
        }
        tables.push(table(&["SCOPE", "TYPE", "NAME", "SECRET"], rows));
    }
    tables.join("\n")
}

/// Whether `e` is the fork's original's entry for a service the fork has no entry of its own for.
fn inherited(file: &SecretsFile, e: &SecretEntry, own: Option<&str>, parent: Option<&str>) -> bool {
    parent == Some(e.scope.as_str())
        && !file
            .secrets
            .iter()
            .any(|f| f.service == e.service && Some(f.scope.as_str()) == own)
}

fn forget<R: Runner>(ctx: &Ctx<R>, entries: &[SecretEntry]) -> Result<()> {
    for e in entries.iter().filter(|e| e.source == Source::Keychain) {
        ctx.store.delete(&e.account())?;
    }
    Ok(())
}

fn rm<R: Runner>(ctx: &Ctx<R>, file: &mut SecretsFile, a: SecretRmArgs) -> Result<()> {
    if a.registry.is_some() && (a.sandbox.is_some() || a.all_sandboxes) {
        return Err(Unsupported(REGISTRY_SANDBOX.into()).into());
    }
    if a.registry.is_some() && (a.all || a.service.is_some()) {
        bail!(
            "--registry removes one registry login; it can't be combined with --all or a service"
        );
    }
    if let Some(host) = &a.registry {
        let host = host.trim().to_ascii_lowercase();
        let i = file
            .registries
            .iter()
            .position(|r| r.host == host && r.sandbox.is_none())
            .with_context(|| format!("no {host} secret (host only)"))?;
        file.registries.remove(i);
        file.save(&ctx.paths)?;
        ctx.store.delete(&registry_account(&host))?;
        writeln!(&ctx.out, "Removed registry secret {host} ((host only))")?;
        return Ok(());
    }
    if a.all_sandboxes {
        return Err(Unsupported("--all-sandboxes removal is not implemented yet".into()).into());
    }
    // Before the removal: a custom service's definition can go with its last entry.
    let before = file.clone();
    let removed: Vec<String> = if a.all {
        confirm(ctx, "Remove every secret?", a.force)?;
        let all = std::mem::take(&mut file.secrets);
        let registries = std::mem::take(&mut file.registries);
        file.custom.clear();
        file.bindings.clear();
        // Saved first: a failed save must not leave entries pointing at deleted values. A delete
        // that fails afterwards orphans a value, which is the lesser harm.
        file.save(&ctx.paths)?;
        forget(ctx, &all)?;
        forget_registries(ctx, &registries)?;
        let mut services: Vec<String> = all.into_iter().map(|e| e.service).collect();
        services.sort();
        services.dedup();
        services
    } else {
        let service = a.service.context("specify a service, or --all")?;
        let scope = scope_for(a.sandbox.as_deref());
        let removed = file
            .remove(&service, &scope)
            .with_context(|| format!("no {service} secret ({scope})"))?;
        file.save(&ctx.paths)?;
        forget(ctx, &[removed])?;
        vec![service]
    };
    writeln!(&ctx.out, "Removed")?;
    let revoked = revoke(ctx, &before, file, &removed);
    if !revoked.is_empty() {
        writeln!(
            &ctx.out,
            "Running sandboxes {} no longer send it",
            revoked.join(", ")
        )?;
    }
    Ok(())
}

/// What a running sandbox is handed for a removed secret with no other entry to fall back on.
/// smolvm refuses an empty value, so a fixed one that isn't a secret replaces it.
const REMOVED_MARKER: &str = "smolbento-secret-removed";

/// Hands running sandboxes that used a removed entry of `services` the entry that applies now (a
/// global one under a removed sandbox one, or the original's for a fork), else the marker, so
/// their requests stop carrying the removed value at once. Returns the sandboxes it reached.
fn revoke<R: Runner>(
    ctx: &Ctx<R>,
    before: &SecretsFile,
    after: &SecretsFile,
    services: &[String],
) -> Vec<String> {
    let Ok(sandboxes) = sandbox::list(&ctx.vm) else {
        return Vec::new();
    };
    let services: Vec<(&String, Service)> = services
        .iter()
        .filter_map(|n| Some((n, before.service(n)?)))
        .collect();
    let mut reached = Vec::new();
    for sb in sandboxes
        .iter()
        .filter(|s| s.is_running() && !name::is_internal(s.name()))
    {
        let fork_of = sb.meta.fork_of.as_deref();
        let (mut any, mut restart) = (false, false);
        for (service, svc) in &services {
            let was = before.entry_for(sb.name(), fork_of, service);
            let now = after.entry_for(sb.name(), fork_of, service);
            if was.map(|e| &e.scope) == now.map(|e| &e.scope) || !is_bound(sb, Some(svc), service) {
                continue;
            }
            // A hosted sandbox's egress process reads its secrets itself, once for them all.
            if sb.meta.egress.is_some() {
                restart = true;
                continue;
            }
            let value = match now.map(|e| resolve(e, ctx.store.as_ref())) {
                Some(Ok(value)) => value,
                Some(Err(e)) => {
                    crate::warning!("{}: couldn't read its {service} secret: {e:#}", sb.name());
                    REMOVED_MARKER.to_string()
                }
                None => REMOVED_MARKER.to_string(),
            };
            match refresh(ctx, sb, svc, service, &value) {
                Ok(r) => any |= r,
                Err(e) => crate::warning!(
                    "{}: couldn't stop it sending the removed {service} secret now ({e:#}); it \
                     stops at its next start",
                    sb.name()
                ),
            }
        }
        if restart {
            any |= provision::restart_egress(ctx, sb);
        }
        if any {
            reached.push(sb.name().to_string());
        }
    }
    reached
}

/// `bento rm`: forget a sandbox's policy and, with `secrets`, its own secrets.
pub fn forget_sandbox<R: Runner>(ctx: &Ctx<R>, name: &str, secrets: bool) -> Result<()> {
    if secrets {
        let (gone, registries) = SecretsFile::update(&ctx.paths, |file| {
            Ok((
                file.remove_sandbox(name),
                file.remove_sandbox_registries(name),
            ))
        })?;
        forget(ctx, &gone)?;
        forget_registries(ctx, &registries)?;
    }
    Policy::update(&ctx.paths, |p| {
        p.forget_sandbox(name);
        Ok(())
    })
}

/// `bento reset` without --preserve-secrets.
pub fn forget_all<R: Runner>(ctx: &Ctx<R>) -> Result<()> {
    let file = SecretsFile::update(&ctx.paths, |f| Ok(std::mem::take(f)))?;
    forget(ctx, &file.secrets)?;
    forget_registries(ctx, &file.registries)
}

fn forget_registries<R: Runner>(ctx: &Ctx<R>, entries: &[RegistryEntry]) -> Result<()> {
    for r in entries {
        ctx.store.delete(&r.account())?;
    }
    Ok(())
}

const REGISTRY_SANDBOX: &str = "registry credentials for sandboxes (--sandbox, --all-sandboxes) \
     are not implemented yet; they're used for host pulls only";

/// `secret set --registry`: the password or token comes from stdin.
fn registry_set<R: Runner>(ctx: &Ctx<R>, file: &mut SecretsFile, a: SecretSetArgs) -> Result<()> {
    if a.source.sandbox.is_some() || a.all_sandboxes {
        return Err(Unsupported(REGISTRY_SANDBOX.into()).into());
    }
    if a.service.is_some()
        || a.source.token.is_some()
        || a.source.value_stdin
        || a.source.reference.is_some()
        || a.source.command.is_some()
    {
        bail!(
            "--registry takes its password or token from --password-stdin, not a service, -t, --ref or --command"
        );
    }
    for (flag, given) in [
        ("--oauth", a.oauth),
        ("--refresh", a.refresh.is_some()),
        ("--no-verify", a.no_verify),
        ("--show-error", a.show_error),
    ] {
        if given {
            bail!("{flag} has no effect with --registry; remove it");
        }
    }
    if !a.password_stdin {
        bail!(
            "--registry needs --password-stdin, e.g. `gh auth token | bento secret set --registry \
             ghcr.io --password-stdin`"
        );
    }
    let auth_endpoint = a.registry_auth_endpoint;
    let username = a.username.filter(|u| !u.is_empty());
    let host = a.registry.unwrap_or_default().trim().to_ascii_lowercase();
    crate::secrets::check_registry_host(&host, &format!("'{host}'"))?;
    // The login is only ever sent over https, or plain http to localhost (see `kits::registry::auth::trusted_realm`).
    if let Some(e) = &auth_endpoint
        && !e.starts_with("https://")
    {
        bail!("--registry-auth-endpoint must be an https:// URL: {e}");
    }
    let value = stdin_value(ctx)?;
    if value.is_empty() {
        bail!("empty password or token on stdin");
    }
    let who = username.clone().unwrap_or_else(|| "(token-only)".into());
    let entry = RegistryEntry {
        host: host.clone(),
        username,
        auth_endpoint,
        sandbox: None,
    };
    put_registry(ctx, file, entry, &value)?;
    writeln!(
        &ctx.out,
        "Saved registry secret {host} (host only, username {who})"
    )?;
    Ok(())
}

/// All of stdin, without its line ending: a value given with `--value-stdin` or `--password-stdin`.
fn stdin_value<R: Runner>(ctx: &Ctx<R>) -> Result<String> {
    let v = ctx.read_to_end()?;
    let v = v.strip_suffix('\n').unwrap_or(&v);
    Ok(v.strip_suffix('\r').unwrap_or(v).to_string())
}

/// Stores a registry login and its value, replacing the one for the same host and scope.
pub fn put_registry<R: Runner>(
    ctx: &Ctx<R>,
    file: &mut SecretsFile,
    entry: RegistryEntry,
    value: &str,
) -> Result<()> {
    let account = entry.account();
    // Kept in memory to put back if secrets.toml can't be saved.
    let previous = ctx.store.get(&account)?;
    let saved = ctx.store.set(&account, value).and_then(|()| {
        file.registries
            .retain(|r| !(r.host == entry.host && r.sandbox == entry.sandbox));
        file.registries.push(entry);
        file.save(&ctx.paths)
    });
    if saved.is_err() {
        restore(ctx, &account, previous.as_deref());
    }
    saved
}

#[cfg(test)]
#[path = "secret_tests.rs"]
mod tests;
