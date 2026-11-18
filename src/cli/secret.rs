//! `bento secret`: secret sources. Values go to the secret store, never to secrets.toml.

use std::io::{BufRead, Write};

use anyhow::{Context, Result, bail};

use super::{
    Ctx, SecretCmd, SecretLsArgs, SecretRmArgs, SecretSetArgs, SecretSource, Unsupported, confirm,
    table,
};
use crate::policy::Policy;
use crate::policy::rules::{SmolvmHost, check_host};
use crate::sandbox::{self, name};
use crate::secrets::resolve::start_env;
use crate::secrets::{
    CustomService, RegistryEntry, SecretEntry, SecretsFile, Source, registry_account, scope_for,
    services,
};
use crate::smolvm::{Credential, Runner};

pub fn run<R: Runner>(ctx: &mut Ctx<R>, cmd: SecretCmd) -> Result<i32> {
    let mut file = SecretsFile::load(&ctx.paths)?;
    match cmd {
        SecretCmd::Set(a) if a.registry.is_some() => registry_set(ctx, &mut file, a)?,
        SecretCmd::Set(a) => {
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
                set_mcp(ctx, &mut file, &service, a.source)?;
            } else {
                if file.service(&service).is_none() {
                    bail!(services::unknown(&service));
                }
                set(ctx, &mut file, &service, a.source)?;
            }
        }
        SecretCmd::SetCustom(a) => {
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
            file.custom.retain(|c| c.name != name);
            file.custom.push(CustomService {
                name: name.clone(),
                env: a.env.clone(),
                hosts,
            });
            set(ctx, &mut file, &name, a.source)?;
        }
        SecretCmd::Ls(a) => ls(ctx, &file, &a)?,
        SecretCmd::Rm(a) => rm(ctx, &mut file, a)?,
        SecretCmd::Import(_) => {
            return Err(Unsupported("`bento secret import` is not implemented yet".into()).into());
        }
    }
    Ok(0)
}

fn ls<R: Runner>(ctx: &Ctx<R>, file: &SecretsFile, a: &SecretLsArgs) -> Result<()> {
    // A fork also uses its original's sandbox secrets (see `plan::start_plan`). If smolvm can't be
    // asked, the listing stays a plain file read.
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
        let host = r.trim().to_ascii_lowercase();
        let unbracketed = host.trim_start_matches('[').trim_end_matches(']');
        if unbracketed.parse::<std::net::IpAddr>().is_ok() {
            bail!("'{r}': smolvm only substitutes secrets for host names, not IP addresses");
        }
        if host.contains("://") || host.contains([':', '/', '@', ',']) {
            bail!("'{r}': use a bare host name like api.x.com (no scheme, port or path)");
        }
        // smolvm takes `*.domain` (every subdomain, not the domain itself) and no other wildcard.
        let (prefix, name) = match SmolvmHost::parse(&host) {
            SmolvmHost::Subdomains(name) => ("*.", name),
            SmolvmHost::Exact(name) => ("", name),
        };
        if name.contains(['*', '?', '[', ']']) {
            bail!(
                "'{r}': the only wildcard a secret host takes is a leading `*.`, like *.x.com \
                 (every subdomain of x.com)"
            );
        }
        check_host(name, r)?;
        let name = name.strip_suffix('.').unwrap_or(name);
        if !prefix.is_empty() && !name.contains('.') {
            bail!("'{r}': a wildcard needs a domain below the top level, like *.x.com");
        }
        let host = format!("{prefix}{name}");
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
        ctx.store.set(&account, v)?;
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

/// Hands the running `sb` the service's current value (`machine credentials refresh`), resolved as
/// a start would; false when it can't, so the value waits for the next start. A sandbox created
/// before bindings were named after their variable can't, when a kit bound the service.
fn refresh<R: Runner>(
    ctx: &Ctx<R>,
    file: &SecretsFile,
    sb: &sandbox::Sandbox,
    service: &str,
) -> bool {
    let meta = sandbox::Meta {
        secrets: vec![service.to_string()],
        ..sb.meta.clone()
    };
    let (env, _) = start_env(file, &meta, ctx.store.as_ref(), false);
    if env.is_empty() {
        return false;
    }
    let bindings: Vec<String> = env.iter().map(|(v, _)| Credential::binding(v)).collect();
    match ctx.vm.refresh_credentials(&sb.machine, &bindings, &env) {
        Ok(()) => true,
        Err(e) => {
            crate::warning!("{}: couldn't hand it the new value now: {e:#}", sb.name());
            false
        }
    }
}

/// Puts a stored value back as it was before a `set` whose secrets.toml save then failed: the
/// earlier value, or none. Best effort; the save error is the one the caller reports.
fn restore<R: Runner>(ctx: &Ctx<R>, account: &str, previous: Option<&str>) {
    let _ = match previous {
        Some(v) => ctx.store.set(account, v),
        None => ctx.store.delete(account),
    };
}

/// Which sandboxes have the new value now, which get it on their next start, and which would need
/// recreating. A running sandbox bound to the service is handed the value at once.
fn explain_impact<R: Runner>(
    ctx: &Ctx<R>,
    file: &SecretsFile,
    service: &str,
    scope: Option<&str>,
) -> Result<()> {
    let Ok(sandboxes) = sandbox::list(&ctx.vm) else {
        return Ok(());
    };
    let (bound, unbound): (Vec<_>, Vec<_>) = sandboxes
        .iter()
        .filter(|s| scope.is_none_or(|n| n == s.name()))
        .partition(|s| s.meta.secrets.iter().any(|x| x == service));
    let (now, later): (Vec<_>, Vec<_>) = bound
        .into_iter()
        .partition(|s| s.is_running() && refresh(ctx, file, s, service));
    let names = |v: &[&sandbox::Sandbox]| v.iter().map(|s| s.name()).collect::<Vec<_>>().join(", ");
    if !now.is_empty() {
        writeln!(&ctx.out, "Applied to {} now", names(&now))?;
    }
    if !later.is_empty() {
        writeln!(&ctx.out, "Applies to {} on their next start", names(&later))?;
    }
    if !unbound.is_empty() {
        writeln!(
            &ctx.out,
            "{} were created without it; recreate them to use it (new sandboxes get it)",
            names(&unbound)
        )?;
    }
    Ok(())
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
    if a.all {
        confirm(ctx, "Remove every secret?", a.force)?;
        let all = std::mem::take(&mut file.secrets);
        let registries = std::mem::take(&mut file.registries);
        file.custom.clear();
        // Saved first: a failed save must not leave entries pointing at deleted values. A delete
        // that fails afterwards orphans a value, which is the lesser harm.
        file.save(&ctx.paths)?;
        forget(ctx, &all)?;
        forget_registries(ctx, &registries)?;
    } else {
        let service = a.service.context("specify a service, or --all")?;
        let scope = scope_for(a.sandbox.as_deref());
        let removed = file
            .remove(&service, &scope)
            .with_context(|| format!("no {service} secret ({scope})"))?;
        file.save(&ctx.paths)?;
        forget(ctx, &[removed])?;
    }
    writeln!(&ctx.out, "Removed")?;
    Ok(())
}

/// `bento rm`: forget a sandbox's policy and, with `secrets`, its own secrets.
pub fn forget_sandbox<R: Runner>(ctx: &Ctx<R>, name: &str, secrets: bool) -> Result<()> {
    if secrets {
        let mut file = SecretsFile::load(&ctx.paths)?;
        let gone = file.remove_sandbox(name);
        let registries = file.remove_sandbox_registries(name);
        file.save(&ctx.paths)?;
        forget(ctx, &gone)?;
        forget_registries(ctx, &registries)?;
    }
    let mut policy = Policy::load(&ctx.paths)?;
    policy.forget_sandbox(name);
    policy.save(&ctx.paths)
}

/// `bento reset` without --preserve-secrets.
pub fn forget_all<R: Runner>(ctx: &Ctx<R>) -> Result<()> {
    let file = SecretsFile::load(&ctx.paths)?;
    SecretsFile::default().save(&ctx.paths)?;
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
    if host.is_empty() || host.contains("://") || host.contains(['/', '@', ' ']) {
        bail!("'{host}': use a bare registry host like ghcr.io (no scheme or path)");
    }
    // The login is only ever sent over https, or plain http to localhost (see `kits::registry_auth::trusted_realm`).
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
    ctx.store.set(&account, value)?;
    file.registries
        .retain(|r| !(r.host == entry.host && r.sandbox == entry.sandbox));
    file.registries.push(entry);
    if let Err(e) = file.save(&ctx.paths) {
        restore(ctx, &account, previous.as_deref());
        return Err(e);
    }
    Ok(())
}

#[cfg(test)]
#[path = "secret_tests.rs"]
mod tests;
