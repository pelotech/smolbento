//! `sbt secret`: secret sources. Values go to the secret store, never to secrets.toml.

use std::io::{BufRead, Write};

use anyhow::{Context, Result, bail};

use super::{
    Ctx, SecretCmd, SecretLsArgs, SecretRmArgs, SecretSource, Unsupported, confirm, table,
};
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
                bail!(unknown_service(&service));
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
        SecretCmd::Ls(a) => ls(ctx, &file, &a)?,
        SecretCmd::Rm(a) => rm(ctx, &mut file, a)?,
        SecretCmd::Import(_) => {
            return Err(Unsupported("`sbt secret import` is not implemented yet".into()).into());
        }
    }
    Ok(0)
}

/// `secret set`'s error for a service that is neither built in nor custom.
pub(crate) fn unknown_service(service: &str) -> String {
    format!(
        "unknown service '{service}' (built-in: {}; or use `sbt secret set-custom`)",
        services::builtin_names().join(", ")
    )
}

fn ls<R: Runner>(ctx: &Ctx<R>, file: &SecretsFile, a: &SecretLsArgs) -> Result<()> {
    // A fork also uses its original's sandbox secrets (see `plan::start_plan`). If smolvm can't be
    // asked, the listing stays a plain file read.
    let parent = a
        .sandbox
        .as_deref()
        .and_then(|s| sandbox::find(&ctx.vm, s).ok().flatten())
        .and_then(|sb| sb.meta.fork_of);
    write!(&ctx.out, "{}", render_ls(file, a, parent.as_deref()))?;
    Ok(())
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
    let (source, value) = if let Some(r) = src.reference {
        crate::secrets::resolve::ref_command(&r)?;
        (Source::Ref { reference: r }, None)
    } else if let Some(c) = src.command {
        (Source::Command { command: c }, None)
    } else {
        let value = match src.token {
            Some(t) => t,
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
        // Put the store back as the unchanged entry expects: the earlier value, or none. Best
        // effort; the save error is the one to report.
        if value.is_some() {
            let _ = match &previous {
                Some(v) => ctx.store.set(&account, v),
                None => ctx.store.delete(&account),
            };
        }
        return Err(e);
    }
    // A new stored value replaced the old one in place; otherwise the old one goes.
    if value.is_none()
        && let Some(old) = old
    {
        forget(ctx, &[old])?;
    }
    writeln!(&ctx.out, "Saved {service} secret ({described}; {scope})")?;
    explain_impact(ctx, service, src.sandbox.as_deref())
}

/// Which sandboxes pick the change up on their next start, and which would need recreating.
fn explain_impact<R: Runner>(ctx: &Ctx<R>, service: &str, scope: Option<&str>) -> Result<()> {
    let Ok(sandboxes) = sandbox::list(&ctx.vm) else {
        return Ok(());
    };
    let (bound, unbound): (Vec<_>, Vec<_>) = sandboxes
        .iter()
        .filter(|s| scope.is_none_or(|n| n == s.name()))
        .partition(|s| s.meta.secrets.iter().any(|x| x == service));
    let names = |v: &[&sandbox::Sandbox]| v.iter().map(|s| s.name()).collect::<Vec<_>>().join(", ");
    if !bound.is_empty() {
        writeln!(&ctx.out, "Applies to {} on their next start", names(&bound))?;
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

/// `secret ls` for `a`; `fork_of` is `a.sandbox`'s original when it's a fork.
fn render_ls(file: &SecretsFile, a: &SecretLsArgs, fork_of: Option<&str>) -> String {
    let own = a.sandbox.as_deref().map(|s| scope_for(Some(s)));
    let parent = fork_of.map(|p| scope_for(Some(p)));
    let entries: Vec<&SecretEntry> = file
        .secrets
        .iter()
        .filter(|e| !a.global || e.scope == "global")
        .filter(|e| {
            let shown_for_own = own
                .as_ref()
                .is_none_or(|o| e.scope == "global" || &e.scope == o);
            shown_for_own || inherited(file, e, own.as_deref(), parent.as_deref())
        })
        .filter(|e| a.service.as_deref().is_none_or(|s| e.service == s))
        .collect();
    if a.quiet {
        return entries.iter().map(|e| format!("{}\n", e.service)).collect();
    }
    if entries.is_empty() {
        return "No secrets\n".into();
    }
    let mut lines = vec![["SERVICE", "SCOPE", "SOURCE"].map(String::from).to_vec()];
    for e in entries {
        lines.push(vec![
            e.service.clone(),
            e.scope.clone(),
            e.source.describe(),
        ]);
    }
    table(lines)
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
    if a.registry.is_some() || a.all_sandboxes {
        return Err(Unsupported(
            "registry and --all-sandboxes removal are not implemented yet".into(),
        )
        .into());
    }
    if a.all {
        confirm(ctx, "Remove every secret?", a.force)?;
        let all = std::mem::take(&mut file.secrets);
        file.custom.clear();
        // Saved first: a failed save must not leave entries pointing at deleted values. A delete
        // that fails afterwards orphans a value, which is the lesser harm.
        file.save(&ctx.paths)?;
        forget(ctx, &all)?;
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

/// `sbt rm`: forget a sandbox's policy and, with `secrets`, its own secrets.
pub fn forget_sandbox<R: Runner>(ctx: &Ctx<R>, name: &str, secrets: bool) -> Result<()> {
    if secrets {
        let mut file = SecretsFile::load(&ctx.paths)?;
        let gone = file.remove_sandbox(name);
        file.save(&ctx.paths)?;
        forget(ctx, &gone)?;
    }
    let mut policy = Policy::load(&ctx.paths)?;
    policy.forget_sandbox(name);
    policy.save(&ctx.paths)
}

/// `sbt reset` without --preserve-secrets.
pub fn forget_all<R: Runner>(ctx: &Ctx<R>) -> Result<()> {
    let file = SecretsFile::load(&ctx.paths)?;
    SecretsFile::default().save(&ctx.paths)?;
    forget(ctx, &file.secrets)
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

    /// Runs `f` with the config dir read-only, so saving secrets.toml fails. Root ignores the
    /// mode, so these tests return early (pass vacuously) when run as root. The mode is restored
    /// even if `f` panics, so the tempdir can be cleaned up.
    #[cfg(unix)]
    fn with_read_only_config<T>(t: &mut TestEnv, f: impl FnOnce(&mut TestEnv) -> T) -> Option<T> {
        use std::os::unix::fs::PermissionsExt;
        struct Restore(std::path::PathBuf);
        impl Drop for Restore {
            fn drop(&mut self) {
                let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o755));
            }
        }
        // SAFETY: geteuid has no preconditions.
        if unsafe { libc::geteuid() } == 0 {
            return None;
        }
        let dir = t.ctx.paths.config.clone();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o555)).unwrap();
        let _restore = Restore(dir);
        Some(f(t))
    }

    #[cfg(unix)]
    #[test]
    fn a_failed_save_doesnt_leave_the_value_behind() {
        let mut t = test_env(&[]);
        sbt(&mut t.ctx, &["secret", "set", "github", "-t", "old"]).unwrap();
        let Some((new, replaced, overwritten)) = with_read_only_config(&mut t, |t| {
            (
                sbt(&mut t.ctx, &["secret", "set", "anthropic", "-t", "sk-1"]),
                sbt(
                    &mut t.ctx,
                    &["secret", "set", "github", "--command", "gh auth token"],
                ),
                sbt(&mut t.ctx, &["secret", "set", "github", "-t", "new"]),
            )
        }) else {
            return;
        };
        assert!(new.is_err() && replaced.is_err() && overwritten.is_err());
        assert_eq!(t.ctx.store.get("global/anthropic").unwrap(), None);
        // The entry still says the value is stored, so the old value must still be there.
        assert_eq!(
            t.ctx.store.get("global/github").unwrap().as_deref(),
            Some("old")
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_failed_save_keeps_removed_values() {
        let mut t = test_env(&[]);
        sbt(&mut t.ctx, &["secret", "set", "github", "-t", "g"]).unwrap();
        sbt(
            &mut t.ctx,
            &["secret", "set", "openai", "-t", "o", "--sandbox", "a1"],
        )
        .unwrap();
        let Some(results) = with_read_only_config(&mut t, |t| {
            [
                sbt(&mut t.ctx, &["secret", "rm", "github"]).map(drop),
                sbt(&mut t.ctx, &["secret", "rm", "--all", "-f"]).map(drop),
                forget_sandbox(&t.ctx, "a1", true),
                forget_all(&t.ctx),
            ]
        }) else {
            return;
        };
        assert!(results.iter().all(Result::is_err), "{results:?}");
        assert_eq!(
            t.ctx.store.get("global/github").unwrap().as_deref(),
            Some("g")
        );
        assert_eq!(
            t.ctx.store.get("sandbox:a1/openai").unwrap().as_deref(),
            Some("o")
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
        assert_eq!(
            f.entry_for("a1", None, "claude").unwrap().scope,
            "sandbox:a1"
        );
        assert!(matches!(
            f.entry_for("x", None, "github").unwrap().source,
            Source::Command { .. }
        ));
    }

    #[test]
    fn set_ref_accepts_any_aws_partition() {
        let mut t = test_env(&[]);
        let arn = "arn:aws-us-gov:secretsmanager:us-gov-west-1:123:secret:x";
        sbt(&mut t.ctx, &["secret", "set", "github", "--ref", arn]).unwrap();
        let f = SecretsFile::load(&t.ctx.paths).unwrap();
        assert_eq!(
            f.entry_for("x", None, "github").unwrap().source,
            Source::Ref {
                reference: arn.into()
            }
        );
        let err = sbt(
            &mut t.ctx,
            &["secret", "set", "github", "--ref", "arn:aws:s3:::bucket"],
        )
        .unwrap_err();
        assert!(err.to_string().contains("unsupported reference"), "{err}");
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
        t.stdout();
        sbt(&mut t.ctx, &["secret", "ls"]).unwrap();
        insta::assert_snapshot!(t.stdout());
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
    fn ls_of_a_fork_includes_its_originals_secrets() {
        let mut t = test_env(&[]);
        for args in [
            &["anthropic", "-t", "g"][..],
            &["github", "-t", "p", "--sandbox", "aa"][..],
            &["openai", "-t", "p", "--sandbox", "aa"][..],
            &["openai", "-t", "f", "--sandbox", "aa-fork-1"][..],
            &["claude", "-t", "o", "--sandbox", "other"][..],
        ] {
            let mut full = vec!["secret", "set"];
            full.extend_from_slice(args);
            sbt(&mut t.ctx, &full).unwrap();
        }
        let fake = t.ctx.vm.runner();
        fake.ok(
            &["machine", "status", "-n", "sbx-aa-fork-1"],
            &machine_json(
                "sbx-aa-fork-1",
                "running",
                &[("sbx.name", "aa-fork-1"), ("sbx.fork-of", "aa")],
            ),
        );
        t.stdout();
        let ls = |t: &mut TestEnv, args: &[&str]| {
            let mut full = vec!["secret", "ls"];
            full.extend_from_slice(args);
            sbt(&mut t.ctx, &full).unwrap();
            t.stdout()
        };
        // Own, the original's (but not where the fork has its own) and global; the original is
        // looked up from the fork's labels.
        assert_eq!(
            ls(&mut t, &["-q", "--sandbox", "aa-fork-1"]),
            "anthropic\ngithub\nopenai\n"
        );
        let table = ls(&mut t, &["--sandbox", "aa-fork-1"]);
        assert!(table.contains("sandbox:aa"), "{table}");
        assert!(!table.contains("sandbox:other"), "{table}");
        // A sandbox that isn't a fork sees only its own and the global ones.
        t.ctx.vm.runner().ok(
            &["machine", "status", "-n", "sbx-plain"],
            &machine_json("sbx-plain", "running", &[("sbx.name", "plain")]),
        );
        assert_eq!(ls(&mut t, &["-q", "--sandbox", "plain"]), "anthropic\n");
    }

    #[test]
    fn ls_for_a_sandbox_works_when_smolvm_cannot_be_asked() {
        let mut t = test_env(&[]);
        t.ctx
            .vm
            .runner()
            .fail(&["machine", "status"], "SMOLVM_ERROR", "boom");
        let mut f = SecretsFile::default();
        for scope in [None, Some("aa")] {
            f.set(SecretEntry {
                service: "github".into(),
                scope: scope_for(scope),
                source: Source::Keychain,
            });
        }
        f.save(&t.ctx.paths).unwrap();
        sbt(
            &mut t.ctx,
            &["secret", "ls", "-q", "--sandbox", "aa-fork-1"],
        )
        .unwrap();
        assert_eq!(t.stdout(), "github\n");
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
        let a1 = machine_json("sbx-a1", "stopped", &[("sbx.name", "a1")]);
        t.ctx.vm.runner().ok(&["machine", "status"], &a1);
        t.ctx
            .vm
            .runner()
            .ok(&["machine", "ls", "--json"], &format!("[{a1}]"));
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
