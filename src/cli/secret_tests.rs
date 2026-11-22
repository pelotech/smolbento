use super::*;
use crate::testutil::*;

fn set_registry_from(t: &mut TestEnv, host: &str, user: Option<&str>, input: &str) -> Result<()> {
    t.stdin(input);
    let mut args = vec!["secret", "set", "--registry", host, "--password-stdin"];
    if let Some(user) = user {
        args.extend(["--username", user]);
    }
    t.sbt(&args).map(|_| ())
}

#[test]
fn an_mcp_secret_is_stored_like_any_other() {
    let mut t = test_env(&[]);
    t.machine("sbx-s1", "running", &[("sbx.name", "s1")]);
    t.sbt(&["secret", "set", "mcp:linear:api-key", "-t", "tok"])
        .unwrap();
    // No "created without it" note: MCP secrets aren't offered to sandboxes as secrets.
    let out = t.stdout();
    assert!(
        out.starts_with("Saved mcp:linear:api-key secret ("),
        "{out}"
    );
    assert_eq!(out.lines().count(), 1, "{out}");
    let file = SecretsFile::load(&t.ctx.paths).unwrap();
    let entry = file
        .secrets
        .iter()
        .find(|e| e.service == "mcp:linear:api-key")
        .expect("an entry");
    assert_eq!(entry.scope, crate::secrets::scope_for(None));
    assert_eq!(
        t.ctx.store.get(&entry.account()).unwrap().as_deref(),
        Some("tok")
    );
    // Never bound to a sandbox as an ordinary secret.
    assert!(
        file.services_for("s1")
            .iter()
            .all(|s| !s.starts_with("mcp:") || file.service(s).is_none())
    );
    let err = t.sbt_err(&[
        "secret",
        "set",
        "mcp:linear:api-key",
        "--sandbox",
        "s1",
        "-t",
        "x",
    ]);
    assert!(err.contains("MCP secrets are global"), "{err}");
    for bad in ["mcp:linear", "mcp::k", "mcp:bad name:k", "mcp:linear:a b"] {
        let err = t.sbt_err(&["secret", "set", bad, "-t", "x"]);
        assert!(err.contains("mcp:<server>:<name>"), "{bad}: {err}");
    }
}

#[test]
fn registry_set_token_only_stores_value_and_entry() {
    let mut t = test_env(&[]);
    set_registry_from(&mut t, "Quay.IO", None, "tok\n").unwrap();
    assert_eq!(
        t.stdout(),
        "Saved registry secret quay.io (host only, username (token-only))\n"
    );
    let f = SecretsFile::load(&t.ctx.paths).unwrap();
    assert_eq!(f.registries.len(), 1);
    assert_eq!(f.registries[0].host, "quay.io");
    assert_eq!(f.registries[0].username, None);
    assert_eq!(
        crate::secrets::registry_secret(&*t.ctx.store, "quay.io")
            .unwrap()
            .as_deref(),
        Some("tok")
    );
    let text = std::fs::read_to_string(t.ctx.paths.secrets_file()).unwrap();
    assert!(
        !text.contains("tok\n") && !text.contains("\"tok\""),
        "{text}"
    );
}

#[test]
fn registry_set_with_username_and_replace() {
    let mut t = test_env(&[]);
    set_registry_from(&mut t, "ghcr.io", Some("me"), "one").unwrap();
    assert_eq!(
        t.stdout(),
        "Saved registry secret ghcr.io (host only, username me)\n"
    );
    set_registry_from(&mut t, "ghcr.io", Some("me"), "two").unwrap();
    let f = SecretsFile::load(&t.ctx.paths).unwrap();
    assert_eq!(f.registries.len(), 1);
    assert_eq!(f.registries[0].username.as_deref(), Some("me"));
    assert_eq!(
        t.ctx.store.get("registry:ghcr.io").unwrap().as_deref(),
        Some("two")
    );
}

#[test]
fn registry_set_refuses_empty_input_and_bad_hosts() {
    let mut t = test_env(&[]);
    assert!(set_registry_from(&mut t, "ghcr.io", None, "\n").is_err());
    assert!(set_registry_from(&mut t, "ghcr.io", None, "").is_err());
    assert!(set_registry_from(&mut t, "https://ghcr.io/x", None, "t").is_err());
    assert!(
        SecretsFile::load(&t.ctx.paths)
            .unwrap()
            .registries
            .is_empty()
    );
    assert_eq!(t.ctx.store.get("registry:ghcr.io").unwrap(), None);
}

#[test]
fn registry_auth_endpoint_must_be_https() {
    let mut t = test_env(&[]);
    let set = |t: &mut TestEnv, endpoint: &str| {
        t.stdin("tok");
        let registry = ["--registry", "quay.io", "--password-stdin"];
        let endpoint = ["--registry-auth-endpoint", endpoint];
        t.sbt(&[&["secret", "set"], &registry[..], &endpoint].concat())
    };
    let e = set(&mut t, "http://auth.example.com/token").unwrap_err();
    assert_eq!(
        e.to_string(),
        "--registry-auth-endpoint must be an https:// URL: http://auth.example.com/token"
    );
    assert!(set(&mut t, "auth.example.com/token").is_err());
    assert_eq!(t.ctx.store.get("registry:quay.io").unwrap(), None);
    set(&mut t, "https://auth.example.com/token").unwrap();
    let f = SecretsFile::load(&t.ctx.paths).unwrap();
    assert_eq!(
        f.registries[0].auth_endpoint.as_deref(),
        Some("https://auth.example.com/token")
    );
}

#[test]
fn registry_set_refuses_flags_it_would_ignore() {
    let mut t = test_env(&[]);
    for flag in [
        &["--oauth"][..],
        &["--refresh", "x"],
        &["--no-verify"],
        &["--show-error"],
    ] {
        let mut args = vec!["secret", "set", "--registry", "ghcr.io", "--password-stdin"];
        args.extend_from_slice(flag);
        let e = t.sbt(&args).unwrap_err();
        assert!(e.to_string().contains(flag[0]), "{e}");
    }
    assert_eq!(t.ctx.store.get("registry:ghcr.io").unwrap(), None);
}

#[test]
fn registry_rm_refuses_all_and_a_service() {
    let mut t = test_env(&[]);
    for extra in [&["--all"][..], &["github"]] {
        let mut args = vec!["secret", "rm", "--registry", "ghcr.io"];
        args.extend_from_slice(extra);
        let e = t.sbt(&args).unwrap_err();
        assert!(e.to_string().contains("--registry"), "{e}");
    }
}

#[test]
fn an_empty_username_is_token_only() {
    let mut t = test_env(&[]);
    set_registry_from(&mut t, "ghcr.io", Some(""), "tok").unwrap();
    assert_eq!(
        t.stdout(),
        "Saved registry secret ghcr.io (host only, username (token-only))\n"
    );
    let f = SecretsFile::load(&t.ctx.paths).unwrap();
    assert_eq!(f.registries[0].username, None);
}

#[test]
fn registry_set_refusals() {
    let mut t = test_env(&[]);
    for extra in [&["--sandbox", "a1"][..], &["--all-sandboxes"][..]] {
        let mut args = vec!["secret", "set", "--registry", "ghcr.io", "--password-stdin"];
        args.extend_from_slice(extra);
        let e = t.sbt(&args).unwrap_err();
        assert!(e.downcast_ref::<Unsupported>().is_some(), "{e}");
        assert!(e.to_string().contains("used for host pulls only"), "{e}");
    }
    let e = t
        .sbt(&["secret", "set", "--registry", "ghcr.io"])
        .unwrap_err();
    assert!(e.to_string().contains("--password-stdin"), "{e}");
    let e = t
        .sbt(&["secret", "set", "--username", "u", "--password-stdin"])
        .unwrap_err();
    assert!(e.to_string().contains("--registry"), "{e}");
}

#[test]
fn registry_ls_rows() {
    let mut t = test_env(&[]);
    t.sbt(&["secret", "ls"]).unwrap();
    assert_eq!(t.stdout(), "No secrets found\n");
    set_registry_from(&mut t, "ghcr.io", Some("me"), "abcdefgh").unwrap();
    t.stdout();
    t.sbt(&["secret", "ls"]).unwrap();
    let out = t.stdout();
    assert!(out.contains("SCOPE") && out.contains("TYPE"), "{out}");
    assert!(
        out.contains("(host only)   registry   ghcr.io   (stored)"),
        "{out}"
    );
    assert!(!out.contains("abcd"), "{out}");
}

#[test]
fn registry_rm_removes_value_and_entry() {
    let mut t = test_env(&[]);
    set_registry_from(&mut t, "ghcr.io", None, "v").unwrap();
    t.stdout();
    t.sbt(&["secret", "rm", "--registry", "GHCR.io"]).unwrap();
    assert_eq!(
        t.stdout(),
        "Removed registry secret ghcr.io ((host only))\n"
    );
    assert!(
        SecretsFile::load(&t.ctx.paths)
            .unwrap()
            .registries
            .is_empty()
    );
    assert_eq!(t.ctx.store.get("registry:ghcr.io").unwrap(), None);
    let e = t
        .sbt(&["secret", "rm", "--registry", "ghcr.io"])
        .unwrap_err();
    assert_eq!(e.to_string(), "no ghcr.io secret (host only)");
    let e = t
        .sbt(&["secret", "rm", "--registry", "ghcr.io", "--sandbox", "a"])
        .unwrap_err();
    assert!(e.downcast_ref::<Unsupported>().is_some(), "{e}");
    let e = t
        .sbt(&["secret", "rm", "--registry", "ghcr.io", "--all-sandboxes"])
        .unwrap_err();
    assert!(e.downcast_ref::<Unsupported>().is_some(), "{e}");
}

/// A login for `ghcr.io` scoped to sandbox `web`, as an environment file's `registries`.
fn scoped_login(t: &TestEnv) {
    let mut file = SecretsFile::load(&t.ctx.paths).unwrap();
    let entry = RegistryEntry {
        host: "ghcr.io".into(),
        username: None,
        auth_endpoint: None,
        sandbox: Some("web".into()),
    };
    put_registry(&t.ctx, &mut file, entry, "scoped").unwrap();
}

const SCOPED_KEY: &str = "sandbox-registry:web/ghcr.io";

#[test]
fn registry_set_and_rm_leave_a_sandboxs_login_alone() {
    let mut t = test_env(&[]);
    scoped_login(&t);
    set_registry_from(&mut t, "ghcr.io", None, "host-wide\n").unwrap();
    let hosts = |t: &TestEnv| -> Vec<Option<String>> {
        let f = SecretsFile::load(&t.ctx.paths).unwrap();
        f.registries.into_iter().map(|r| r.sandbox).collect()
    };
    assert_eq!(hosts(&t), [Some("web".to_string()), None]);
    t.sbt(&["secret", "rm", "--registry", "ghcr.io"]).unwrap();
    assert_eq!(hosts(&t), [Some("web".to_string())]);
    assert_eq!(
        t.ctx.store.get(SCOPED_KEY).unwrap().as_deref(),
        Some("scoped")
    );
    assert_eq!(t.ctx.store.get("registry:ghcr.io").unwrap(), None);
}

#[test]
fn forgetting_everything_takes_a_sandboxs_login_too() {
    let t = test_env(&[]);
    scoped_login(&t);
    forget_all(&t.ctx).unwrap();
    assert_eq!(t.ctx.store.get(SCOPED_KEY).unwrap(), None);
    assert!(
        SecretsFile::load(&t.ctx.paths)
            .unwrap()
            .registries
            .is_empty()
    );
}

#[test]
fn rm_all_clears_registries() {
    let mut t = test_env(&[]);
    set_registry_from(&mut t, "ghcr.io", None, "v").unwrap();
    t.sbt(&["secret", "rm", "--all", "-f"]).unwrap();
    assert!(
        SecretsFile::load(&t.ctx.paths)
            .unwrap()
            .registries
            .is_empty()
    );
    assert_eq!(t.ctx.store.get("registry:ghcr.io").unwrap(), None);
}

#[test]
fn set_with_token_stores_the_value_in_the_store_only() {
    let mut t = test_env(&[]);
    t.sbt(&["secret", "set", "anthropic", "-t", "sk-1"])
        .unwrap();
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

#[test]
fn a_failed_save_doesnt_leave_the_value_behind() {
    let mut t = test_env(&[]);
    t.sbt(&["secret", "set", "github", "-t", "old"]).unwrap();
    let Some((new, replaced, overwritten)) = with_read_only_config(&mut t, |t| {
        (
            t.sbt(&["secret", "set", "anthropic", "-t", "sk-1"]),
            t.sbt(&["secret", "set", "github", "--command", "gh auth token"]),
            t.sbt(&["secret", "set", "github", "-t", "new"]),
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

#[test]
fn a_failed_save_keeps_removed_values() {
    let mut t = test_env(&[]);
    t.sbt(&["secret", "set", "github", "-t", "g"]).unwrap();
    t.sbt(&["secret", "set", "openai", "-t", "o", "--sandbox", "a1"])
        .unwrap();
    let Some(results) = with_read_only_config(&mut t, |t| {
        [
            t.sbt(&["secret", "rm", "github"]).map(drop),
            t.sbt(&["secret", "rm", "--all", "-f"]).map(drop),
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
    t.sbt(&[
        "secret",
        "set",
        "claude",
        "--ref",
        "op://P/c/credential",
        "--sandbox",
        "a1",
    ])
    .unwrap();
    t.sbt(&["secret", "set", "github", "--command", "gh auth token"])
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
    t.sbt(&["secret", "set", "github", "--ref", arn]).unwrap();
    let f = SecretsFile::load(&t.ctx.paths).unwrap();
    assert_eq!(
        f.entry_for("x", None, "github").unwrap().source,
        Source::Ref {
            reference: arn.into()
        }
    );
    let err = t
        .sbt(&["secret", "set", "github", "--ref", "arn:aws:s3:::bucket"])
        .unwrap_err();
    assert!(err.to_string().contains("unsupported reference"), "{err}");
}

#[test]
fn set_errors() {
    let mut t = test_env(&[]);
    assert!(
        t.sbt_err(&["secret", "set", "nope", "-t", "x"])
            .contains("unknown service")
    );
    assert!(
        t.sbt(&["secret", "set", "github", "-t", "x", "--command", "y"])
            .is_err()
    );
    assert!(
        t.sbt(&["secret", "set", "github", "--ref", "vault://x"])
            .is_err()
    );
    assert!(
        t.sbt_err(&["secret", "set", "github"])
            .contains("no terminal")
    );
    assert!(
        t.sbt_err(&["secret", "set", "github", "-t", ""])
            .contains("empty value")
    );
    let err = t.sbt(&["secret", "set", "github", "--oauth"]).unwrap_err();
    assert_eq!(super::super::exit_code(&err), 2);
}

#[test]
fn value_stdin_reads_the_value_from_stdin() {
    let mut t = test_env(&[]);
    t.answer("s3cret\n");
    t.sbt(&["secret", "set", "github", "--value-stdin"])
        .unwrap();
    assert_eq!(
        t.ctx.store.get("global/github").unwrap().as_deref(),
        Some("s3cret"),
        "one trailing newline is dropped"
    );
    let err = t
        .sbt(&["secret", "set", "github", "--value-stdin", "-t", "x"])
        .unwrap_err();
    assert!(err.to_string().contains("pass only one"), "{err}");
}

#[test]
fn replacing_a_stored_value_with_a_command_deletes_the_value() {
    let mut t = test_env(&[]);
    t.sbt(&["secret", "set", "github", "-t", "v"]).unwrap();
    assert!(t.ctx.store.get("global/github").unwrap().is_some());
    t.sbt(&["secret", "set", "github", "--command", "x"])
        .unwrap();
    assert_eq!(t.ctx.store.get("global/github").unwrap(), None);
}

#[test]
fn set_custom_defines_a_service() {
    let mut t = test_env(&[]);
    t.sbt(&[
        "secret",
        "set-custom",
        "--host",
        "httpbin.org",
        "--env",
        "TOK",
        "-t",
        "v",
    ])
    .unwrap();
    let f = SecretsFile::load(&t.ctx.paths).unwrap();
    assert_eq!(f.service("tok").unwrap().hosts, vec!["httpbin.org"]);
    let err = t
        .sbt(&[
            "secret",
            "set-custom",
            "--host",
            "x.com",
            "--env",
            "OPENAI_API_KEY",
            "-t",
            "v",
        ])
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
    let err = t.sbt_err(&[
        "secret",
        "set-custom",
        "--host",
        "https://api.x.com/v1",
        "--env",
        "TOK",
        "-t",
        "v",
    ]);
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
        let err = t.sbt_err(&[
            "secret",
            "set-custom",
            "--host",
            "api.x.com",
            "--env",
            env,
            "-t",
            "v",
        ]);
        assert!(err.contains("isn't a valid env var name"), "{env}: {err}");
    }
    assert!(SecretsFile::load(&t.ctx.paths).unwrap().custom.is_empty());
}

#[test]
fn ls_and_rm() {
    let mut t = test_env(&[]);
    t.sbt(&["secret", "set", "anthropic", "-t", "sk-1"])
        .unwrap();
    t.sbt(&[
        "secret",
        "set",
        "github",
        "--command",
        "gh auth token",
        "--sandbox",
        "a1",
    ])
    .unwrap();
    t.stdout();
    t.sbt(&["secret", "ls"]).unwrap();
    insta::assert_snapshot!(t.stdout());
    t.sbt(&["secret", "rm", "anthropic"]).unwrap();
    assert_eq!(t.ctx.store.get("global/anthropic").unwrap(), None);
    assert!(t.sbt_err(&["secret", "rm", "--all"]).contains("pass -f"));
    t.sbt(&["secret", "rm", "--all", "-f"]).unwrap();
    assert!(SecretsFile::load(&t.ctx.paths).unwrap().secrets.is_empty());
}

#[test]
fn ls_as_json_has_sbxs_shape() {
    let json = |t: &TestEnv| -> serde_json::Value { serde_json::from_str(&t.stdout()).unwrap() };
    let mut t = test_env(&[]);
    t.sbt(&["secret", "ls", "--json"]).unwrap();
    let out = t.stdout();
    // sbx's key order.
    assert!(
        out.starts_with("{\n  \"secrets\": [],\n  \"custom_secrets\""),
        "{out}"
    );
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&out).unwrap(),
        serde_json::json!({
            "secrets": [], "custom_secrets": [], "shadowed_services": [], "env_only_count": 0
        })
    );
    // A service secret, then a registry login, in the one `secrets` list.
    t.sbt(&["secret", "set", "github", "--sandbox", "s1", "-t", "x"])
        .unwrap();
    set_registry_from(&mut t, "ghcr.io", Some("me"), "abcdefgh").unwrap();
    t.stdout();
    t.sbt(&["secret", "ls", "--json"]).unwrap();
    assert_eq!(
        json(&t)["secrets"],
        serde_json::json!([
            {"scope": "s1", "type": "service", "name": "github", "secret": "(stored)"},
            {"scope": "(host only)", "type": "registry", "name": "ghcr.io", "secret": "(stored)"},
        ])
    );
    // -q wins over --json.
    t.sbt(&["secret", "ls", "-q", "--json"]).unwrap();
    assert_eq!(t.stdout(), "github\n");
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
        t.sbt(&full).unwrap();
    }
    let fake = t.runner();
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
        t.sbt(&full).unwrap();
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
    t.runner().ok(
        &["machine", "status", "-n", "sbx-plain"],
        &machine_json("sbx-plain", "running", &[("sbx.name", "plain")]),
    );
    assert_eq!(ls(&mut t, &["-q", "--sandbox", "plain"]), "anthropic\n");
}

#[test]
fn ls_for_a_sandbox_works_when_smolvm_cannot_be_asked() {
    let mut t = test_env(&[]);
    t.runner()
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
    t.sbt(&["secret", "ls", "-q", "--sandbox", "aa-fork-1"])
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
        t.sbt(&args).unwrap();
    }
    t.sbt(&["secret", "rm", "tok"]).unwrap();
    let f = SecretsFile::load(&t.ctx.paths).unwrap();
    assert!(f.service("tok").is_some(), "a1 still uses it");
    t.sbt(&["secret", "rm", "tok", "--sandbox", "a1"]).unwrap();
    let f = SecretsFile::load(&t.ctx.paths).unwrap();
    assert!(f.custom.is_empty(), "{:?}", f.custom);
    assert!(f.service("tok").is_none());
}

#[test]
fn rm_sandbox_forgets_its_secrets_and_policy() {
    let mut t = test_env(&[]);
    t.sbt(&["secret", "set", "github", "-t", "g", "--sandbox", "a1"])
        .unwrap();
    let mut p = crate::policy::Policy::load(&t.ctx.paths).unwrap();
    p.add_rule(
        Some("a1"),
        crate::policy::Decision::Deny,
        "evil.com",
        "added",
        None,
        None,
    )
    .unwrap();
    p.save(&t.ctx.paths).unwrap();
    t.sandboxes(&[("a1", "stopped", &[])]);
    t.sbt(&["rm", "-f", "a1"]).unwrap();
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
    t.sandboxes(&[]);
    t.sbt(&["secret", "set", "anthropic", "-t", "sk-1"])
        .unwrap();
    t.sbt(&["reset", "-f", "--preserve-secrets"]).unwrap();
    assert_eq!(SecretsFile::load(&t.ctx.paths).unwrap().secrets.len(), 1);
    t.sbt(&["reset", "-f"]).unwrap();
    assert!(SecretsFile::load(&t.ctx.paths).unwrap().secrets.is_empty());
    assert_eq!(t.ctx.store.get("global/anthropic").unwrap(), None);
}

/// `a1` running and `b2` stopped, both created with the github secret; `c3` running without it.
fn github_sandboxes(t: &TestEnv) {
    // Both also have a `--static-mcp` header secret, which a github refresh leaves alone.
    let github = [
        ("sbx.secrets", "github"),
        ("sbx.credential-env", "GH_TOKEN,GITHUB_TOKEN"),
        ("sbx.mcp-secret.SBX_MCP_LINEAR_KEY", "mcp:linear:key"),
    ];
    t.sandboxes(&[
        ("a1", "running", &github),
        ("b2", "stopped", &github),
        ("c3", "running", &[]),
    ]);
}

/// smolvm 1.35.4's `machine credentials refresh`: the value reaches the smolvm process's
/// environment only, never its arguments.
#[test]
fn set_hands_a_running_sandbox_the_new_value_now() {
    let mut t = test_env(&[]);
    github_sandboxes(&t);
    t.sbt(&["secret", "set", "mcp:linear:key", "-t", "mcp-tok"])
        .unwrap();
    t.runner().ok(&["machine", "credentials", "refresh"], "");
    // c3 booted with no bindings: smolvm refuses its probe.
    t.runner().fail(
        &["machine", "credentials", "refresh", "-n", "sbx-c3"],
        "INVALID_STATE",
        "booted without credential bindings",
    );
    t.sbt(&["secret", "set", "github", "-t", "tok-2"]).unwrap();
    let out = t.stdout();
    assert!(out.contains("Applied to a1 now\n"), "{out}");
    assert!(
        out.contains("Applies to b2, c3 on their next start\n"),
        "{out}"
    );
    let calls = t.calls_of("machine credentials refresh");
    assert_eq!(
        calls,
        [
            "machine credentials refresh -n sbx-a1 gh_token github_token",
            "machine credentials refresh -n sbx-c3 gh_token github_token",
        ]
    );
    assert!(!calls.iter().any(|l| l.contains("tok-2")));
    let env = t.runner().envs().pop().unwrap();
    assert_eq!(
        env,
        [
            ("GH_TOKEN".to_string(), "tok-2".to_string()),
            ("GITHUB_TOKEN".to_string(), "tok-2".to_string())
        ]
    );
}

#[test]
fn a_failed_refresh_leaves_the_value_for_the_next_start() {
    let mut t = test_env(&[]);
    github_sandboxes(&t);
    t.runner().fail(
        &["machine", "credentials", "refresh"],
        "CONFIG_ERROR",
        "no credential binding 'gh_token'",
    );
    t.sbt(&["secret", "set", "github", "-t", "tok-2"]).unwrap();
    let out = t.stdout();
    assert!(
        out.contains("Applies to a1, b2, c3 on their next start\n"),
        "{out}"
    );
    assert!(!out.contains("now"), "{out}");
}

/// Running sandboxes, each bound to `service` through the variables `env` (`sbx.credential-env`).
fn running(t: &TestEnv, sandboxes: &[(&str, &[(&str, &str)])]) {
    let all: Vec<_> = sandboxes
        .iter()
        .map(|(name, labels)| (*name, "running", *labels))
        .collect();
    t.sandboxes(&all);
    t.runner().ok(&["machine", "credentials", "refresh"], "");
}

/// Claude's kit takes the anthropic key as SBX_KIT_ANTHROPIC alone, with no ANTHROPIC_API_KEY
/// binding: the refresh names only the bound variable, or smolvm refuses it all.
#[test]
fn a_refresh_names_only_the_variables_the_sandbox_binds() {
    let mut t = test_env(&[]);
    running(
        &t,
        &[(
            "cl",
            &[
                ("sbx.secrets", "anthropic"),
                ("sbx.credential-env", "SBX_KIT_ANTHROPIC"),
                ("sbx.credential-service.SBX_KIT_ANTHROPIC", "anthropic"),
            ],
        )],
    );
    t.sbt(&["secret", "set", "anthropic", "-t", "sk-2"])
        .unwrap();
    assert!(t.stdout().contains("Applied to cl now\n"));
    assert_eq!(
        t.calls_of("machine credentials refresh"),
        ["machine credentials refresh -n sbx-cl sbx_kit_anthropic"]
    );
    assert_eq!(
        t.runner().envs().pop().unwrap(),
        [("SBX_KIT_ANTHROPIC".to_string(), "sk-2".to_string())]
    );
}

/// A sandbox's own secret wins over its original's, which wins over the global one: a set
/// refreshes exactly the sandboxes that use the entry it changed.
#[test]
fn a_set_refreshes_the_sandboxes_that_use_that_entry() {
    let mut t = test_env(&[]);
    let gh: &[(&str, &str)] = &[
        ("sbx.secrets", "github"),
        ("sbx.credential-env", "GH_TOKEN"),
    ];
    let fork: &[(&str, &str)] = &[
        ("sbx.secrets", "github"),
        ("sbx.credential-env", "GH_TOKEN"),
        ("sbx.fork-of", "pa"),
    ];
    running(&t, &[("pa", gh), ("fo", fork), ("gl", gh)]);
    t.sbt(&["secret", "set", "github", "--sandbox", "pa", "-t", "pa-tok"])
        .unwrap();
    let out = t.stdout();
    assert!(out.contains("Applied to fo, pa now\n"), "{out}");
    t.sbt(&["secret", "set", "github", "-t", "global-tok"])
        .unwrap();
    let out = t.stdout();
    assert!(out.ends_with("Applied to gl now\n"), "{out}");
    assert_eq!(
        t.calls_of("machine credentials refresh"),
        [
            "machine credentials refresh -n sbx-fo gh_token",
            "machine credentials refresh -n sbx-pa gh_token",
            "machine credentials refresh -n sbx-gl gh_token",
        ]
    );
}

/// A --command (or --ref) source may prompt or be slow: one set reads it once, however many
/// running sandboxes get it.
#[test]
fn a_set_reads_the_new_value_once() {
    let mut t = test_env(&[]);
    let gh: &[(&str, &str)] = &[
        ("sbx.secrets", "github"),
        ("sbx.credential-env", "GH_TOKEN"),
    ];
    running(&t, &[("a", gh), ("b", gh)]);
    let runs = t.ctx.paths.config.join("runs");
    let command = format!("printf x >> '{}'; printf tok", runs.display());
    t.sbt(&["secret", "set", "github", "--command", &command])
        .unwrap();
    assert!(t.stdout().contains("Applied to a, b now\n"));
    assert_eq!(std::fs::read_to_string(runs).unwrap(), "x");
}

#[test]
fn rm_all_clears_bindings() {
    let mut t = test_env(&[]);
    let mut file = SecretsFile::default();
    file.bind("github", &["api.corp.example".into()], &[]);
    file.save(&t.ctx.paths).unwrap();
    t.sbt(&["secret", "rm", "--all", "-f"]).unwrap();
    assert!(SecretsFile::load(&t.ctx.paths).unwrap().bindings.is_empty());
}

/// A store whose writes can be made to fail after they've changed the value, as a keychain write
/// that lands garbled does.
#[derive(Clone, Default)]
struct FailingStore {
    values: std::rc::Rc<std::cell::RefCell<std::collections::BTreeMap<String, String>>>,
    fail: std::rc::Rc<std::cell::Cell<bool>>,
}

impl crate::secrets::store::SecretStore for FailingStore {
    fn get(&self, account: &str) -> Result<Option<String>> {
        Ok(self.values.borrow().get(account).cloned())
    }
    fn set(&self, account: &str, value: &str) -> Result<()> {
        self.values
            .borrow_mut()
            .insert(account.into(), value.into());
        if self.fail.get() {
            bail!("the store didn't keep the value intact");
        }
        Ok(())
    }
    fn delete(&self, account: &str) -> Result<()> {
        self.values.borrow_mut().remove(account);
        Ok(())
    }
    fn describe(&self) -> String {
        "failing".into()
    }
}

#[test]
fn a_failed_store_write_keeps_the_previous_secret() {
    let mut t = test_env(&[]);
    let store = FailingStore::default();
    t.ctx.store = Box::new(store.clone());
    t.sbt(&["secret", "set", "github", "-t", "old"]).unwrap();
    store.fail.set(true);
    assert!(t.sbt(&["secret", "set", "github", "-t", "new"]).is_err());
    let values = store.values.borrow();
    assert_eq!(values.values().collect::<Vec<_>>(), ["old"], "{values:?}");
}

#[test]
fn a_failed_store_write_keeps_the_previous_registry_login() {
    let mut t = test_env(&[]);
    let store = FailingStore::default();
    t.ctx.store = Box::new(store.clone());
    set_registry_from(&mut t, "ghcr.io", Some("me"), "old\n").unwrap();
    store.fail.set(true);
    assert!(set_registry_from(&mut t, "ghcr.io", Some("me"), "new\n").is_err());
    let values = store.values.borrow();
    assert_eq!(values.values().collect::<Vec<_>>(), ["old"], "{values:?}");
}

/// Bound to anthropic only: `credentials add` gives it a new service.
const ANTHROPIC: &[(&str, &str)] = &[
    ("sbx.secrets", "anthropic"),
    ("sbx.credential-env", "ANTHROPIC_API_KEY"),
    ("sbx.credential-hosts", "api.anthropic.com"),
];

/// Defines and sets the custom `xtok` service (XTOK, for x.example) to `x-secret`.
fn set_xtok(t: &mut TestEnv) -> Result<i32> {
    t.sbt(&[
        "secret",
        "set-custom",
        "--host",
        "x.example",
        "--env",
        "XTOK",
        "-t",
        "x-secret",
    ])
}

/// `sb` got xtok's binding (its value only in smolvm's env) and labels listing it.
fn assert_bound_xtok(t: &TestEnv, sb: &str, labels: [&str; 3]) {
    let m = format!("sbx-{sb}");
    assert_eq!(
        t.calls_of(&format!("machine credentials add -n {m} ")),
        [format!(
            "machine credentials add -n {m} --credential xtok=XTOK@x.example"
        )]
    );
    assert!(
        t.runner()
            .envs()
            .contains(&vec![("XTOK".to_string(), "x-secret".to_string())])
    );
    assert_eq!(
        t.calls_of(&format!("machine update -n {m} --label")),
        [format!(
            "machine update -n {m} --label {}",
            labels.join(" --label ")
        )]
    );
    assert!(!t.calls().iter().any(|l| l.contains("x-secret")));
}

/// A network update, not a label one, before the add: smolvm refuses a credential whose host the
/// machine's allow list doesn't reach, running or stopped.
fn assert_network_pushed_first(t: &TestEnv, sb: &str) {
    let calls = t.calls();
    let at = |p: &str| calls.iter().position(|l| l.starts_with(p));
    let network = calls.iter().position(|l| {
        l.starts_with(&format!("machine update -n sbx-{sb} ")) && !l.contains("--label")
    });
    let add = at(&format!("machine credentials add -n sbx-{sb} "));
    assert!(network.is_some() && network < add, "{calls:#?}");
}

const XTOK_ON_ANTHROPIC: [&str; 3] = [
    "sbx.secrets=anthropic,xtok",
    "sbx.credential-env=ANTHROPIC_API_KEY,XTOK",
    "sbx.credential-hosts=api.anthropic.com,x.example",
];

#[test]
fn set_binds_a_new_service_to_a_running_sandbox() {
    let mut t = test_env(&[]);
    t.sandboxes(&[("a", "running", ANTHROPIC)]);
    set_xtok(&mut t).unwrap();
    assert_bound_xtok(&t, "a", XTOK_ON_ANTHROPIC);
    assert_network_pushed_first(&t, "a");
    // The probe: a refresh succeeds only on a machine that takes bindings live.
    assert_eq!(
        t.calls_of("machine credentials refresh"),
        ["machine credentials refresh -n sbx-a xtok"]
    );
    let out = t.stdout();
    assert!(out.contains("Applied to a now\n"), "{out}");
    assert!(!out.contains("recreate"), "{out}");
}

#[test]
fn set_binds_a_new_service_to_a_stopped_sandbox() {
    let mut t = test_env(&[]);
    t.sandboxes(&[("a", "stopped", ANTHROPIC)]);
    set_xtok(&mut t).unwrap();
    assert_bound_xtok(&t, "a", XTOK_ON_ANTHROPIC);
    assert_network_pushed_first(&t, "a");
    assert!(!t.made("machine credentials refresh"));
    let out = t.stdout();
    assert!(out.contains("Applies to a on their next start\n"), "{out}");
}

/// smolvm records a binding on a machine that booted with none, but uses it from its next start.
#[test]
fn a_running_sandbox_booted_without_bindings_gets_it_next_start() {
    let mut t = test_env(&[]);
    t.sandboxes(&[("a", "running", &[])]);
    no_live_bindings(&t);
    set_xtok(&mut t).unwrap();
    assert_bound_xtok(
        &t,
        "a",
        [
            "sbx.secrets=xtok",
            "sbx.credential-env=XTOK",
            "sbx.credential-hosts=x.example",
        ],
    );
    let out = t.stdout();
    assert!(out.contains("Applies to a on their next start\n"), "{out}");
    assert!(!out.contains("now"), "{out}");
}

#[test]
fn internal_sandboxes_get_no_secret() {
    let mut t = test_env(&[]);
    t.sandboxes(&[("_builder", "running", &[])]);
    set_xtok(&mut t).unwrap();
    assert!(!t.made("machine credentials"));
    assert!(!t.made("machine update"));
    assert!(!t.stdout().contains("_builder"));
}

#[test]
fn a_failed_add_warns_and_binds_the_others() {
    let mut t = test_env(&[]);
    t.sandboxes(&[("a", "running", ANTHROPIC), ("b", "running", ANTHROPIC)]);
    t.runner().fail(
        &["machine", "credentials", "add", "-n", "sbx-a"],
        "INVALID_STATE",
        "boom",
    );
    set_xtok(&mut t).unwrap();
    assert!(!t.made("machine update -n sbx-a --label"));
    assert_bound_xtok(&t, "b", XTOK_ON_ANTHROPIC);
    let out = t.stdout();
    assert!(out.contains("Applied to b now\n"), "{out}");
    assert!(!out.contains("a now") && !out.contains("to a "), "{out}");
    let f = SecretsFile::load(&t.ctx.paths).unwrap();
    assert!(f.scoped_entry(None, "xtok").is_some());
}

/// A kit already binds one of the service's variables (`sbx.credential-service.*`): it's bound,
/// so a set refreshes it rather than binding it again.
#[test]
fn a_service_a_kit_already_binds_is_not_added_again() {
    let mut t = test_env(&[]);
    running(
        &t,
        &[(
            "cl",
            &[
                ("sbx.credential-env", "SBX_KIT_ANTHROPIC"),
                ("sbx.credential-service.SBX_KIT_ANTHROPIC", "anthropic"),
            ],
        )],
    );
    t.sbt(&["secret", "set", "anthropic", "-t", "sk-2"])
        .unwrap();
    assert!(!t.made("machine credentials add"));
    assert_eq!(
        t.calls_of("machine credentials refresh"),
        ["machine credentials refresh -n sbx-cl sbx_kit_anthropic"]
    );
    assert!(t.stdout().contains("Applied to cl now\n"));
}

const MARKER: &str = "smolbento-secret-removed";

/// The env of the last `run_with_env` call.
fn last_env(t: &TestEnv) -> Vec<(String, String)> {
    t.runner().envs().pop().unwrap()
}

fn pairs(vars: &[(&str, &str)]) -> Vec<(String, String)> {
    vars.iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

/// A removed secret's value can't be taken from a running machine (smolvm refuses an empty one):
/// it's replaced with a fixed marker, so requests stop carrying it at once.
#[test]
fn rm_hands_running_sandboxes_the_removed_marker() {
    let mut t = test_env(&[]);
    t.sbt(&["secret", "set", "github", "-t", "tok"]).unwrap();
    github_sandboxes(&t);
    t.runner().ok(&["machine", "credentials", "refresh"], "");
    t.sbt(&["secret", "rm", "github"]).unwrap();
    assert_eq!(
        t.calls_of("machine credentials refresh"),
        ["machine credentials refresh -n sbx-a1 gh_token github_token"]
    );
    assert_eq!(
        last_env(&t),
        pairs(&[("GH_TOKEN", MARKER), ("GITHUB_TOKEN", MARKER)])
    );
    assert!(!t.made("machine credentials remove"));
    assert!(!t.made("machine update"));
    assert!(
        t.stdout()
            .ends_with("Removed\nRunning sandboxes a1 no longer send it\n")
    );
}

/// A sandbox's own secret removed: it falls back to its original's (a fork), then the global one.
#[test]
fn rm_of_a_sandbox_secret_falls_back_to_the_global_value() {
    let mut t = test_env(&[]);
    t.sbt(&["secret", "set", "github", "-t", "global-tok"])
        .unwrap();
    for sb in ["pa", "fo"] {
        let tok = format!("{sb}-tok");
        t.sbt(&["secret", "set", "github", "--sandbox", sb, "-t", &tok])
            .unwrap();
    }
    let gh: &[(&str, &str)] = &[
        ("sbx.secrets", "github"),
        ("sbx.credential-env", "GH_TOKEN"),
    ];
    let fork: &[(&str, &str)] = &[
        ("sbx.secrets", "github"),
        ("sbx.credential-env", "GH_TOKEN"),
        ("sbx.fork-of", "pa"),
    ];
    running(&t, &[("pa", gh), ("fo", fork), ("gl", gh)]);
    t.sbt(&["secret", "rm", "github", "--sandbox", "fo"])
        .unwrap();
    assert_eq!(
        t.calls_of("machine credentials refresh"),
        ["machine credentials refresh -n sbx-fo gh_token"]
    );
    assert_eq!(last_env(&t), pairs(&[("GH_TOKEN", "pa-tok")]));
    assert!(
        t.stdout()
            .ends_with("Running sandboxes fo no longer send it\n")
    );
    t.sbt(&["secret", "rm", "github", "--sandbox", "pa"])
        .unwrap();
    let calls = t.calls_of("machine credentials refresh");
    assert_eq!(
        calls[1..],
        [
            "machine credentials refresh -n sbx-fo gh_token",
            "machine credentials refresh -n sbx-pa gh_token",
        ]
    );
    let envs = t.runner().envs();
    assert!(
        envs[envs.len() - 2..]
            .iter()
            .all(|e| *e == pairs(&[("GH_TOKEN", "global-tok")]))
    );
    assert!(
        t.stdout()
            .ends_with("Running sandboxes fo, pa no longer send it\n")
    );
}

#[test]
fn rm_leaves_stopped_sandboxes_alone() {
    let mut t = test_env(&[]);
    t.sbt(&["secret", "set", "github", "-t", "tok"]).unwrap();
    let gh: &[(&str, &str)] = &[
        ("sbx.secrets", "github"),
        ("sbx.credential-env", "GH_TOKEN"),
    ];
    t.sandboxes(&[("b", "stopped", gh)]);
    t.sbt(&["secret", "rm", "github"]).unwrap();
    assert!(!t.made("machine credentials"));
    assert!(t.stdout().ends_with("Removed\n"));
}

/// `rm --all` revokes every service, a custom one too (whose definition goes with it).
#[test]
fn rm_all_revokes_every_removed_service() {
    let mut t = test_env(&[]);
    t.sbt(&["secret", "set", "github", "-t", "tok"]).unwrap();
    set_xtok(&mut t).unwrap();
    running(
        &t,
        &[(
            "a",
            &[
                ("sbx.secrets", "github,xtok"),
                ("sbx.credential-env", "GH_TOKEN,GITHUB_TOKEN,XTOK"),
            ],
        )],
    );
    t.sbt(&["secret", "rm", "--all", "-f"]).unwrap();
    let mut calls = t.calls_of("machine credentials refresh");
    calls.sort();
    assert_eq!(
        calls,
        [
            "machine credentials refresh -n sbx-a gh_token github_token",
            "machine credentials refresh -n sbx-a xtok",
        ]
    );
    let envs = t.runner().envs();
    assert!(
        envs[envs.len() - 2..]
            .iter()
            .flatten()
            .all(|(_, v)| v == MARKER)
    );
    assert!(
        t.stdout()
            .ends_with("Running sandboxes a no longer send it\n")
    );
}

/// smolvm refuses a refresh on a machine that booted with no bindings: it has nothing to take
/// values live through until its next start.
fn no_live_bindings(t: &TestEnv) {
    t.runner().fail(
        &["machine", "credentials", "refresh"],
        "INVALID_STATE",
        "booted without credential bindings",
    );
}

/// Its labels list a binding added after it booted with none: a later set still waits for the
/// next start, which the refresh probe (not the labels) tells.
#[test]
fn a_second_set_on_a_sandbox_booted_without_bindings_waits_for_its_next_start() {
    let mut t = test_env(&[]);
    t.sbt(&["secret", "set", "github", "-t", "gh"]).unwrap();
    let later: &[(&str, &str)] = &[
        ("sbx.secrets", "github"),
        ("sbx.credential-env", "GH_TOKEN,GITHUB_TOKEN"),
    ];
    t.sandboxes(&[("a", "running", later)]);
    no_live_bindings(&t);
    set_xtok(&mut t).unwrap();
    assert!(t.made("machine credentials add -n sbx-a"));
    let out = t.stdout();
    assert!(out.contains("Applies to a on their next start\n"), "{out}");
    assert!(!out.contains("now"), "{out}");
}

/// A value that can't be read binds nothing, and says which sandboxes still lack it.
#[test]
fn an_unreadable_value_names_the_sandboxes_left_without_it() {
    let mut t = test_env(&[]);
    t.sandboxes(&[("a", "running", ANTHROPIC), ("b", "stopped", ANTHROPIC)]);
    t.sbt(&[
        "secret",
        "set-custom",
        "--host",
        "x.example",
        "--env",
        "XTOK",
        "--command",
        "exit 3",
    ])
    .unwrap();
    assert!(!t.made("machine credentials add"));
    let out = t.stdout();
    assert!(
        out.contains(
            "a, b don't have it yet; run `bento secret set xtok` again once it can be read\n"
        ),
        "{out}"
    );
}

/// The secret is saved before the binds: a policy that can't be read skips them, not the set.
#[test]
fn an_unreadable_policy_skips_the_binds() {
    let mut t = test_env(&[]);
    t.sandboxes(&[("a", "running", ANTHROPIC)]);
    std::fs::write(t.ctx.paths.policy_file(), "not = [toml").unwrap();
    set_xtok(&mut t).unwrap();
    assert!(!t.made("machine credentials add"));
    assert!(
        SecretsFile::load(&t.ctx.paths)
            .unwrap()
            .scoped_entry(None, "xtok")
            .is_some()
    );
}

/// A fork created without the service gets its original's value, not the global one.
#[test]
fn a_fork_is_bound_with_its_originals_value() {
    let mut t = test_env(&[]);
    t.sbt(&["secret", "set", "github", "-t", "global-tok"])
        .unwrap();
    let fork: &[(&str, &str)] = &[
        ("sbx.secrets", "anthropic"),
        ("sbx.credential-env", "ANTHROPIC_API_KEY"),
        ("sbx.fork-of", "pa"),
    ];
    t.sandboxes(&[("fo", "running", fork)]);
    t.sbt(&["secret", "set", "github", "--sandbox", "pa", "-t", "pa-tok"])
        .unwrap();
    assert!(t.made("machine credentials add -n sbx-fo"));
    let envs = t.runner().envs();
    assert!(
        envs.contains(&pairs(&[
            ("GH_TOKEN", "pa-tok"),
            ("GITHUB_TOKEN", "pa-tok")
        ])),
        "{envs:?}"
    );
    assert!(!envs.iter().flatten().any(|(_, v)| v == "global-tok"));
}
