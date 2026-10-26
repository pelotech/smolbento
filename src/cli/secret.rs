//! `sbt secret`: secret sources. Values go to the secret store, never to secrets.toml.

use std::io::{BufRead, Write};

use anyhow::{Context, Result, bail};

use super::{Ctx, SecretCmd, SecretRmArgs, SecretSource, Unsupported, confirm, table};
use crate::policy::Policy;
use crate::sandbox::{self, name};
use crate::secrets::{CustomService, SecretEntry, SecretsFile, Source, scope_for, services};
use crate::smolvm::Runner;

pub fn run<R: Runner>(ctx: &mut Ctx<R>, cmd: SecretCmd) -> Result<i32> {
    let mut file = SecretsFile::load(&ctx.paths)?;
    match cmd {
        SecretCmd::Set(a) => {
            let unsupported = [
                (a.oauth, "--oauth"),
                (
                    a.registry.is_some() || a.username.is_some() || a.password_stdin,
                    "registry credentials",
                ),
                (a.refresh.is_some(), "--refresh"),
                (a.all_sandboxes, "--all-sandboxes"),
                (a.no_verify || a.show_error, "--no-verify/--show-error"),
            ];
            if let Some((_, what)) = unsupported.iter().find(|(set, _)| *set) {
                return Err(Unsupported(format!("{what} is not implemented yet")).into());
            }
            let service = a
                .service
                .context("specify a service, e.g. `sbt secret set anthropic`")?;
            if file.service(&service).is_none() {
                bail!(
                    "unknown service '{service}' (built-in: {}; or use `sbt secret set-custom`)",
                    services::builtin_names().join(", ")
                );
            }
            set(ctx, &mut file, &service, a.source)?;
        }
        SecretCmd::SetCustom(a) => {
            if a.placeholder.is_some() {
                return Err(Unsupported(
                    "--placeholder is not supported; smolvm chooses the placeholder".into(),
                )
                .into());
            }
            check_env_name(&a.env)?;
            if let Some(owner) = services::env_var_owner(&a.env) {
                bail!(
                    "{} belongs to the built-in {owner} service; use `sbt secret set {owner}`",
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
        SecretCmd::Ls(a) => print!(
            "{}",
            render_ls(
                &file,
                a.sandbox.as_deref(),
                a.global,
                a.service.as_deref(),
                a.quiet
            )
        ),
        SecretCmd::Rm(a) => rm(ctx, &mut file, a)?,
        SecretCmd::Import(_) => {
            return Err(Unsupported("`sbt secret import` is not implemented yet".into()).into());
        }
    }
    Ok(0)
}

/// `--env` of `secret set-custom`: a name a shell (and smolvm's credential flag) accepts.
fn check_env_name(env: &str) -> Result<()> {
    let mut bytes = env.bytes();
    let valid = bytes
        .next()
        .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_');
    if !valid {
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
        let (prefix, name) = match host.strip_prefix("*.") {
            Some(name) => ("*.", name),
            None => ("", host.as_str()),
        };
        if name.contains(['*', '?', '[', ']']) {
            bail!(
                "'{r}': the only wildcard a secret host takes is a leading `*.`, like *.x.com \
                 (every subdomain of x.com)"
            );
        }
        crate::policy::rules::check_host(name, r)?;
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
            eprintln!(
                "warning: {host} doesn't resolve right now; sandboxes created with this secret \
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
    if let Some(s) = &src.sandbox {
        name::validate(s)?;
    }
    let given = [
        src.token.is_some(),
        src.reference.is_some(),
        src.command.is_some(),
    ];
    if given.iter().filter(|g| **g).count() > 1 {
        bail!("pass only one of -t, --ref and --command");
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
    let had_value = old.as_ref().is_some_and(|e| e.source == Source::Keychain);
    let mut wrote_value = false;
    let source = if let Some(r) = src.reference {
        if !(r.starts_with("op://") || r.starts_with("arn:aws:secretsmanager:")) {
            bail!("unsupported reference (use op://… or an AWS Secrets Manager ARN)");
        }
        Source::Ref { reference: r }
    } else if let Some(c) = src.command {
        Source::Command { command: c }
    } else {
        let value = match src.token {
            Some(t) => t,
            None => read_value(ctx, service)?,
        };
        if value.is_empty() {
            bail!("empty value");
        }
        ctx.store.set(&account, &value)?;
        wrote_value = true;
        Source::Keychain
    };
    let described = match &source {
        Source::Keychain => format!("stored in {}", ctx.store.describe()),
        other => other.describe(),
    };
    let keeps_value = source == Source::Keychain;
    file.set(SecretEntry {
        service: service.into(),
        scope: scope.clone(),
        source,
    });
    if let Err(e) = file.save(&ctx.paths) {
        // Don't leave a value no entry points to. One that replaced an earlier value can't be
        // put back (the old value is gone), so it stays: the unchanged entry still uses it.
        if wrote_value && !had_value {
            let _ = ctx.store.delete(&account);
        }
        return Err(e);
    }
    if !keeps_value && let Some(old) = old {
        forget(ctx, &[old])?;
    }
    println!("Saved {service} secret ({described}; {scope})");
    explain_impact(ctx, service, src.sandbox.as_deref());
    Ok(())
}

/// Which sandboxes pick the change up on their next start, and which would need recreating.
fn explain_impact<R: Runner>(ctx: &Ctx<R>, service: &str, scope: Option<&str>) {
    let Ok(sandboxes) = sandbox::list(&ctx.vm) else {
        return;
    };
    let (bound, unbound): (Vec<_>, Vec<_>) = sandboxes
        .iter()
        .filter(|s| scope.is_none_or(|n| n == s.name()))
        .partition(|s| s.meta.secrets.iter().any(|x| x == service));
    let names = |v: &[&sandbox::Sandbox]| v.iter().map(|s| s.name()).collect::<Vec<_>>().join(", ");
    if !bound.is_empty() {
        println!("Applies to {} on their next start", names(&bound));
    }
    if !unbound.is_empty() {
        println!(
            "{} were created without it; recreate them to use it (new sandboxes get it)",
            names(&unbound)
        );
    }
}

fn read_value<R: Runner>(ctx: &Ctx<R>, service: &str) -> Result<String> {
    if !ctx.stdin_tty {
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
    let _guard = crate::smolvm::IgnoreInterrupt::new();
    let read = std::io::stdin().lock().read_line(&mut line);
    if have_term {
        unsafe { libc::tcsetattr(fd, libc::TCSANOW, &saved) };
        eprintln!();
    }
    read?;
    Ok(line.trim_end_matches(['\n', '\r']).to_string())
}

pub fn render_ls(
    file: &SecretsFile,
    sandbox: Option<&str>,
    global_only: bool,
    service: Option<&str>,
    quiet: bool,
) -> String {
    let own = sandbox.map(|s| scope_for(Some(s)));
    let entries: Vec<&SecretEntry> = file
        .secrets
        .iter()
        .filter(|e| !global_only || e.scope == "global")
        .filter(|e| {
            own.as_ref()
                .is_none_or(|o| e.scope == "global" || &e.scope == o)
        })
        .filter(|e| service.is_none_or(|s| e.service == s))
        .collect();
    if quiet {
        return entries.iter().map(|e| format!("{}\n", e.service)).collect();
    }
    if entries.is_empty() {
        return "No secrets\n".into();
    }
    let mut lines = vec![["SERVICE", "SCOPE", "SOURCE"].map(String::from).to_vec()];
    for e in entries {
        let source = match &e.source {
            Source::Keychain => "stored value".into(),
            other => other.describe(),
        };
        lines.push(vec![e.service.clone(), e.scope.clone(), source]);
    }
    table(lines)
}

fn forget<R: Runner>(ctx: &Ctx<R>, entries: &[SecretEntry]) -> Result<()> {
    for e in entries.iter().filter(|e| e.source == Source::Keychain) {
        ctx.store.delete(&e.account())?;
    }
    Ok(())
}

fn rm<R: Runner>(ctx: &Ctx<R>, file: &mut SecretsFile, a: SecretRmArgs) -> Result<()> {
    if a.registry.is_some() || a.all_sandboxes {
        return Err(Unsupported(
            "registry and --all-sandboxes removal are not implemented yet".into(),
        )
        .into());
    }
    if a.all {
        confirm(ctx, "Remove every secret?", a.force)?;
        let all = std::mem::take(&mut file.secrets);
        forget(ctx, &all)?;
        file.custom.clear();
    } else {
        let service = a.service.context("specify a service, or --all")?;
        let scope = scope_for(a.sandbox.as_deref());
        let removed = file
            .remove(&service, &scope)
            .with_context(|| format!("no {service} secret ({scope})"))?;
        forget(ctx, &[removed])?;
    }
    file.save(&ctx.paths)?;
    println!("Removed");
    Ok(())
}

/// `sbt rm`: forget a sandbox's policy and, with `secrets`, its own secrets.
pub fn forget_sandbox<R: Runner>(ctx: &Ctx<R>, name: &str, secrets: bool) -> Result<()> {
    if secrets {
        let mut file = SecretsFile::load(&ctx.paths)?;
        let gone = file.remove_sandbox(name);
        forget(ctx, &gone)?;
        file.save(&ctx.paths)?;
    }
    let mut policy = Policy::load(&ctx.paths)?;
    policy.forget_sandbox(name);
    policy.save(&ctx.paths)
}

/// `sbt reset` without --preserve-secrets.
pub fn forget_all<R: Runner>(ctx: &Ctx<R>) -> Result<()> {
    let file = SecretsFile::load(&ctx.paths)?;
    forget(ctx, &file.secrets)?;
    SecretsFile::default().save(&ctx.paths)
}

#[cfg(test)]
mod tests {
    use super::super::testutil::*;
    use super::*;

    #[test]
    fn set_with_token_stores_the_value_in_the_store_only() {
        let mut t = test_env(&[]);
        sbt(&mut t.ctx, &["secret", "set", "anthropic", "-t", "sk-1"]).unwrap();
        let f = SecretsFile::load(&t.ctx.paths).unwrap();
        assert_eq!(f.secrets[0].source, Source::Keychain);
        assert_eq!(
            t.ctx.store.get("global/anthropic").unwrap().as_deref(),
            Some("sk-1")
        );
        let text = std::fs::read_to_string(t.ctx.paths.secrets_file()).unwrap();
        assert!(!text.contains("sk-1"), "{text}");
    }

    #[test]
    fn a_failed_save_doesnt_leave_the_value_behind() {
        use std::os::unix::fs::PermissionsExt;
        let mut t = test_env(&[]);
        sbt(&mut t.ctx, &["secret", "set", "github", "-t", "old"]).unwrap();
        let dir = t.ctx.paths.config.clone();
        let mode = |m| std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(m)).unwrap();
        mode(0o555);
        let new = sbt(&mut t.ctx, &["secret", "set", "anthropic", "-t", "sk-1"]);
        let replaced = sbt(
            &mut t.ctx,
            &["secret", "set", "github", "--command", "gh auth token"],
        );
        mode(0o755);
        assert!(new.is_err() && replaced.is_err());
        assert_eq!(t.ctx.store.get("global/anthropic").unwrap(), None);
        // The entry still says the value is stored, so it must still be there.
        assert_eq!(
            t.ctx.store.get("global/github").unwrap().as_deref(),
            Some("old")
        );
    }

    #[test]
    fn set_ref_command_and_sandbox_scope() {
        let mut t = test_env(&[]);
        sbt(
            &mut t.ctx,
            &[
                "secret",
                "set",
                "claude",
                "--ref",
                "op://P/c/credential",
                "--sandbox",
                "a1",
            ],
        )
        .unwrap();
        sbt(
            &mut t.ctx,
            &["secret", "set", "github", "--command", "gh auth token"],
        )
        .unwrap();
        let f = SecretsFile::load(&t.ctx.paths).unwrap();
        assert_eq!(f.entry_for("a1", "claude").unwrap().scope, "sandbox:a1");
        assert!(matches!(
            f.entry_for("x", "github").unwrap().source,
            Source::Command { .. }
        ));
    }

    #[test]
    fn set_errors() {
        let mut t = test_env(&[]);
        assert!(
            sbt(&mut t.ctx, &["secret", "set", "nope", "-t", "x"])
                .unwrap_err()
                .to_string()
                .contains("unknown service")
        );
        assert!(
            sbt(
                &mut t.ctx,
                &["secret", "set", "github", "-t", "x", "--command", "y"]
            )
            .is_err()
        );
        assert!(
            sbt(
                &mut t.ctx,
                &["secret", "set", "github", "--ref", "vault://x"]
            )
            .is_err()
        );
        assert!(
            sbt(&mut t.ctx, &["secret", "set", "github"])
                .unwrap_err()
                .to_string()
                .contains("no terminal")
        );
        assert!(
            sbt(&mut t.ctx, &["secret", "set", "github", "-t", ""])
                .unwrap_err()
                .to_string()
                .contains("empty value")
        );
        let err = sbt(&mut t.ctx, &["secret", "set", "github", "--oauth"]).unwrap_err();
        assert_eq!(super::super::exit_code(&err), 2);
    }

    #[test]
    fn replacing_a_stored_value_with_a_command_deletes_the_value() {
        let mut t = test_env(&[]);
        sbt(&mut t.ctx, &["secret", "set", "github", "-t", "v"]).unwrap();
        assert!(t.ctx.store.get("global/github").unwrap().is_some());
        sbt(&mut t.ctx, &["secret", "set", "github", "--command", "x"]).unwrap();
        assert_eq!(t.ctx.store.get("global/github").unwrap(), None);
    }

    #[test]
    fn set_custom_defines_a_service() {
        let mut t = test_env(&[]);
        sbt(
            &mut t.ctx,
            &[
                "secret",
                "set-custom",
                "--host",
                "httpbin.org",
                "--env",
                "TOK",
                "-t",
                "v",
            ],
        )
        .unwrap();
        let f = SecretsFile::load(&t.ctx.paths).unwrap();
        assert_eq!(f.service("tok").unwrap().hosts, vec!["httpbin.org"]);
        let err = sbt(
            &mut t.ctx,
            &[
                "secret",
                "set-custom",
                "--host",
                "x.com",
                "--env",
                "OPENAI_API_KEY",
                "-t",
                "v",
            ],
        )
        .unwrap_err();
        assert!(err.to_string().contains("openai"), "{err}");
    }

    #[test]
    fn set_custom_hosts_must_be_bare_host_names() {
        for (host, says) in [
            (
                "https://api.x.com/v1",
                "use a bare host name like api.x.com",
            ),
            ("api.x.com/v1", "use a bare host name like api.x.com"),
            ("api.x.com:443", "use a bare host name like api.x.com"),
            ("tok@api.x.com", "use a bare host name like api.x.com"),
            ("a.com,b.com", "use a bare host name like api.x.com"),
            ("*", "wildcard"),
            ("*.com", "wildcard"),
            ("**.x.com", "wildcard"),
            ("api.*.com", "wildcard"),
            ("api.?.com", "wildcard"),
            ("*.-x.com", "invalid host"),
            (
                "10.0.0.1",
                "smolvm only substitutes secrets for host names, not IP addresses",
            ),
            ("::1", "not IP addresses"),
            ("[::1]", "not IP addresses"),
            ("-bad.x.com", "invalid host"),
            ("a..com", "invalid host"),
            ("", "invalid host"),
        ] {
            let err = custom_hosts(&[host.to_string()]).unwrap_err().to_string();
            assert!(err.contains(says), "{host}: {err}");
        }
        let mut t = test_env(&[]);
        let err = sbt(
            &mut t.ctx,
            &[
                "secret",
                "set-custom",
                "--host",
                "https://api.x.com/v1",
                "--env",
                "TOK",
                "-t",
                "v",
            ],
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("use a bare host name like api.x.com (no scheme, port or path)"),
            "{err}"
        );
        let f = SecretsFile::load(&t.ctx.paths).unwrap();
        assert!(f.custom.is_empty() && f.secrets.is_empty());
        assert_eq!(t.ctx.store.get("global/tok").unwrap(), None);
    }

    #[test]
    fn set_custom_hosts_are_lowercased_and_deduped() {
        assert_eq!(
            custom_hosts(&[
                " API.X.com ".to_string(),
                "api.x.com.".to_string(),
                "b.x.com".to_string(),
                "api.x.com".to_string(),
                "*.Notion.com".to_string(),
                "*.notion.com".to_string(),
            ])
            .unwrap(),
            vec!["api.x.com", "b.x.com", "*.notion.com"]
        );
    }

    #[test]
    fn set_custom_env_must_be_a_variable_name() {
        let mut t = test_env(&[]);
        for env in ["1TOK", "MY-TOKEN", "TOK=1", "", "TÖK"] {
            let err = sbt(
                &mut t.ctx,
                &[
                    "secret",
                    "set-custom",
                    "--host",
                    "api.x.com",
                    "--env",
                    env,
                    "-t",
                    "v",
                ],
            )
            .unwrap_err()
            .to_string();
            assert!(err.contains("isn't a valid env var name"), "{env}: {err}");
        }
        assert!(SecretsFile::load(&t.ctx.paths).unwrap().custom.is_empty());
    }

    #[test]
    fn ls_and_rm() {
        let mut t = test_env(&[]);
        sbt(&mut t.ctx, &["secret", "set", "anthropic", "-t", "sk-1"]).unwrap();
        sbt(
            &mut t.ctx,
            &[
                "secret",
                "set",
                "github",
                "--command",
                "gh auth token",
                "--sandbox",
                "a1",
            ],
        )
        .unwrap();
        insta::assert_snapshot!(render_ls(
            &SecretsFile::load(&t.ctx.paths).unwrap(),
            None,
            false,
            None,
            false
        ));
        sbt(&mut t.ctx, &["secret", "rm", "anthropic"]).unwrap();
        assert_eq!(t.ctx.store.get("global/anthropic").unwrap(), None);
        assert!(
            sbt(&mut t.ctx, &["secret", "rm", "--all"])
                .unwrap_err()
                .to_string()
                .contains("pass -f")
        );
        sbt(&mut t.ctx, &["secret", "rm", "--all", "-f"]).unwrap();
        assert!(SecretsFile::load(&t.ctx.paths).unwrap().secrets.is_empty());
    }

    #[test]
    fn rm_of_the_last_custom_entry_drops_its_definition() {
        let mut t = test_env(&[]);
        for scope in [&[][..], &["--sandbox", "a1"][..]] {
            let mut args = vec![
                "secret",
                "set-custom",
                "--host",
                "httpbin.org",
                "--env",
                "TOK",
                "-t",
                "v",
            ];
            args.extend_from_slice(scope);
            sbt(&mut t.ctx, &args).unwrap();
        }
        sbt(&mut t.ctx, &["secret", "rm", "tok"]).unwrap();
        let f = SecretsFile::load(&t.ctx.paths).unwrap();
        assert!(f.service("tok").is_some(), "a1 still uses it");
        sbt(&mut t.ctx, &["secret", "rm", "tok", "--sandbox", "a1"]).unwrap();
        let f = SecretsFile::load(&t.ctx.paths).unwrap();
        assert!(f.custom.is_empty(), "{:?}", f.custom);
        assert!(f.service("tok").is_none());
    }

    #[test]
    fn rm_sandbox_forgets_its_secrets_and_policy() {
        let mut t = test_env(&[]);
        sbt(
            &mut t.ctx,
            &["secret", "set", "github", "-t", "g", "--sandbox", "a1"],
        )
        .unwrap();
        let mut p = crate::policy::Policy::load(&t.ctx.paths).unwrap();
        p.set_deny_network("a1", true);
        p.save(&t.ctx.paths).unwrap();
        t.ctx.vm.runner().ok(
            &["machine", "status"],
            &machine_json("sbx-a1", "stopped", &[("sbx.name", "a1")]),
        );
        sbt(&mut t.ctx, &["rm", "-f", "a1"]).unwrap();
        assert!(SecretsFile::load(&t.ctx.paths).unwrap().secrets.is_empty());
        assert_eq!(t.ctx.store.get("sandbox:a1/github").unwrap(), None);
        assert!(
            crate::policy::Policy::load(&t.ctx.paths)
                .unwrap()
                .sandboxes
                .is_empty()
        );
    }

    #[test]
    fn reset_preserves_secrets_only_when_asked() {
        let mut t = test_env(&[]);
        t.ctx.vm.runner().ok(&["machine", "ls", "--json"], "[]");
        sbt(&mut t.ctx, &["secret", "set", "anthropic", "-t", "sk-1"]).unwrap();
        sbt(&mut t.ctx, &["reset", "-f", "--preserve-secrets"]).unwrap();
        assert_eq!(SecretsFile::load(&t.ctx.paths).unwrap().secrets.len(), 1);
        sbt(&mut t.ctx, &["reset", "-f"]).unwrap();
        assert!(SecretsFile::load(&t.ctx.paths).unwrap().secrets.is_empty());
        assert_eq!(t.ctx.store.get("global/anthropic").unwrap(), None);
    }
}
