use super::*;
use crate::secrets::{SecretEntry, Source};
use crate::testutil::*;

fn running(t: &TestEnv, labels: &[(&str, &str)]) {
    let m = machine_json("sbx-a1", "running", labels);
    t.runner()
        .ok(&["machine", "ls", "--json"], &format!("[{m}]"));
    t.runner().ok(&["machine", "status", "-n", "sbx-a1"], &m);
}

fn ls(p: &Policy, opts: LsOpts) -> String {
    render_ls(p, &ls_rows(p, &opts), &opts).unwrap()
}

fn ls_note_for(p: &Policy, sandbox: Option<&str>, decision: Option<Decision>) -> Option<String> {
    ls_note(&ls_rows(
        p,
        &LsOpts {
            sandbox,
            decision,
            ..Default::default()
        },
    ))
}

/// The `machine update` calls that set a whole allow list.
fn resets(t: &TestEnv) -> Vec<String> {
    updates(t)
        .into_iter()
        .filter(|l| l.contains("--reset-allow-list"))
        .collect()
}

fn updates(t: &TestEnv) -> Vec<String> {
    t.calls()
        .into_iter()
        .filter(|l| l.contains("machine update"))
        .collect()
}

#[test]
fn init_saves_and_pushes() {
    let mut t = test_env(&[]);
    running(&t, &[("sbx.name", "a1")]);
    t.sbt(&["policy", "init", "deny-all"]).unwrap();
    assert_eq!(
        Policy::load(&t.ctx.paths).unwrap().mode,
        Some(Mode::DenyAll)
    );
    // No hosts: smolvm's live-reset workaround takes a second call.
    let u = updates(&t);
    assert_eq!(u.len(), 2, "{u:?}");
    assert!(
        u[1].ends_with("--remove-allow-host smolbento.invalid"),
        "{u:?}"
    );
}

#[test]
fn allow_and_rm_push_live() {
    let mut t = test_env(&[]);
    set_policy(&t, "mode = \"deny-all\"");
    running(&t, &[("sbx.name", "a1")]);
    t.sbt(&["policy", "allow", "network", "api.x.com,*.npmjs.org"])
        .unwrap();
    let last = updates(&t).pop().unwrap();
    assert!(
        last.contains("--allow-host-pattern api.x.com")
            && last.contains("--allow-host-pattern *.npmjs.org"),
        "{last}"
    );
    t.sbt(&["policy", "rm", "network", "--resource", "api.x.com"])
        .unwrap();
    assert!(!updates(&t).pop().unwrap().contains("api.x.com"));
    let err = t
        .sbt(&["policy", "rm", "network", "--resource", "nope.com"])
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
        let err = t.sbt(&["policy", "deny", "network", deny]).unwrap_err();
        assert!(err.to_string().contains("github secret"), "{deny}: {err}");
    }
    // Never applied, so accepted (with a stderr note).
    for deny in ["api.github.com:8080", "foo.api.github.com:8080"] {
        t.sbt(&["policy", "deny", "network", deny]).unwrap();
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
        let err = t.sbt(&["policy", "deny", "network", deny]).unwrap_err();
        let msg = err.to_string();
        // No secrets.toml entry names the service, so the message falls back to "a secret".
        assert!(msg.contains("can't deny *.notion.com"), "{err}");
        assert!(msg.contains("has a secret bound to it"), "{err}");
    }
    t.sbt(&["policy", "deny", "network", "notion.com"]).unwrap();
}

#[test]
fn check_exit_codes() {
    let mut t = test_env(&[]);
    set_policy(&t, "mode = \"balanced\"");
    assert_eq!(
        t.sbt(&["policy", "check", "network", "pypi.org"]).unwrap(),
        0
    );
    assert_eq!(
        t.sbt(&["policy", "check", "network", "example.com"])
            .unwrap(),
        1
    );
    // --json keeps the exit code and prints sbx's keys.
    t.stdout();
    assert_eq!(
        t.sbt(&["policy", "check", "network", "--json", "example.com"])
            .unwrap(),
        1
    );
    let v: serde_json::Value = serde_json::from_str(&t.stdout()).unwrap();
    assert_eq!(v["allowed"], false);
    assert_eq!(v["target"], "example.com:443");
    assert_eq!(v["context"], "global");
    assert_eq!(v["type"], "network");
    assert_eq!(v["governance"]["active"], false);
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
        t.sbt(&["policy", "ls", "--decision", "deny", "-q"])
            .unwrap(),
        0
    );
    assert!(t.sbt(&["policy", "ls", "--decision", "maybe"]).is_err());
    for flag in [
        &["--created-via", "added"][..],
        &["--type", "network"],
        &["--protocol", "tcp"],
        &["--include-inactive"],
    ] {
        let args: Vec<&str> = ["policy", "ls"].iter().chain(flag).copied().collect();
        let err = t.sbt(&args).unwrap_err();
        assert_eq!(super::super::exit_code(&err), 2, "{flag:?}: {err}");
        assert!(err.to_string().contains("not implemented yet"), "{err}");
    }
}

#[test]
fn ls_source_accepts_mcp() {
    let mut t = test_env(&[]);
    set_policy(&t, "mode = \"deny-all\"");
    t.sbt(&["policy", "ls", "--source", "mcp"]).unwrap();
    let err = t.sbt_err(&["policy", "ls", "--source", "nope"]);
    assert!(err.contains("local, org, kit or mcp"), "{err}");
}

#[test]
fn ls_source_filters_kit_and_local_rules() {
    use crate::kits::model::{NetRule, Rules};
    let mut t = test_env(&[]);
    let mut p = Policy::default();
    p.add_rule(
        Some("my-sb"),
        Decision::Allow,
        "user.com",
        "added",
        None,
        None,
    )
    .unwrap();
    let rules = Rules {
        allow: vec![NetRule::host("kit.com")],
        deny: vec![],
    };
    p.add_kit_rules("my-sb", "gh", &rules, false).unwrap();
    let mut install = rules.clone();
    install.allow[0].host = "pkg.kit.com".into();
    p.add_kit_rules("my-sb", "gh", &install, true).unwrap();
    p.save(&t.ctx.paths).unwrap();
    let mut out = |args: &[&str]| {
        t.sbt(args).unwrap();
        t.stdout()
    };
    // One aggregated rule per sandbox, like sbx: runtime hosts only (install-phase hosts are
    // not listed).
    let kit = out(&["policy", "ls", "my-sb", "--source", "kit"]);
    let rows: Vec<_> = kit.lines().skip(2).collect();
    assert_eq!(rows.len(), 1, "{kit}");
    let id = crate::policy::kit_rule_id("my-sb");
    assert!(rows[0].starts_with(&id), "{kit}");
    assert!(rows[0].contains("sandbox:my-sb"), "{kit}");
    assert!(rows[0].contains("network: 1 allow"), "{kit}");
    assert!(
        !kit.contains("kit:gh") && !kit.contains("user.com"),
        "{kit}"
    );
    let wide = out(&["policy", "ls", "my-sb", "--source", "kit", "--wide"]);
    assert!(wide.contains("kit:my-sb"), "{wide}");
    assert!(
        wide.contains("kit.com") && !wide.contains("pkg.kit.com"),
        "{wide}"
    );
    let json = out(&["policy", "ls", "my-sb", "--source", "kit", "--json"]);
    let json: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(json.as_array().unwrap().len(), 1);
    assert_eq!(json[0]["id"], id.as_str());
    assert_eq!(json[0]["name"], "kit:my-sb");
    assert_eq!(json[0]["source"], "kit");
    assert_eq!(json[0]["applies_to"], "sandbox:my-sb");
    assert_eq!(json[0]["editable"], false);
    assert_eq!(json[0]["resources"].as_array().unwrap().len(), 1);
    let local = out(&["policy", "ls", "my-sb", "--source", "local"]);
    assert!(
        local.contains("user.com") && !local.contains("kit.com"),
        "{local}"
    );
    let org = out(&["policy", "ls", "my-sb", "--source", "org"]);
    assert!(
        !org.contains("user.com") && !org.contains("kit.com"),
        "{org}"
    );
    assert!(t.sbt(&["policy", "ls", "--source", "x"]).is_err());
}

#[test]
fn check_refuses_other_protocols_and_accepts_verbose() {
    let mut t = test_env(&[]);
    let err = t
        .sbt(&["policy", "check", "network", "x.com", "--protocol", "udp"])
        .unwrap_err();
    assert_eq!(super::super::exit_code(&err), 2);
    assert_eq!(
        t.sbt(&[
            "policy",
            "check",
            "network",
            "x.com",
            "--protocol",
            "tcp",
            "--verbose"
        ],)
            .unwrap(),
        0
    );
}

#[test]
fn reset_needs_force_and_refresh_is_unsupported() {
    let mut t = test_env(&[]);
    assert!(t.sbt_err(&["policy", "reset"]).contains("pass -f"));
    t.sbt(&["policy", "reset", "-f"]).unwrap();
    assert_eq!(Policy::load(&t.ctx.paths).unwrap(), Policy::default());
    set_policy(
        &t,
        "mode = \"allow-all\"\n[[rules]]\nid = \"r-1\"\ndecision = \"allow\"\n\
             resources = [\"a.com\"]\n",
    );
    t.sbt(&["policy", "reset", "-f"]).unwrap();
    assert_eq!(Policy::load(&t.ctx.paths).unwrap(), Policy::default());
    let err = t.sbt(&["policy", "refresh"]).unwrap_err();
    assert_eq!(super::super::exit_code(&err), 2);
}

#[test]
fn reset_stops_running_sandboxes() {
    let mut t = test_env(&[]);
    running(&t, &[("sbx.name", "a1")]);
    t.sbt(&["policy", "reset", "-f"]).unwrap();
    assert!(t.calls().contains(&"machine stop -n sbx-a1".to_string()));
    assert_eq!(Policy::load(&t.ctx.paths).unwrap().mode, None);
}

fn blocked(t: &TestEnv) {
    running(t, &[("sbx.name", "a1")]);
    t.runner().ok(
        &["machine", "egress-events"],
        r#"[{"timestamp":"2026-10-26T10:00:00Z","operation":"resolve","dest":"example.com"},
                {"timestamp":"2026-10-26T11:00:00Z","operation":"resolve","dest":"example.com"}]"#,
    );
}

#[test]
fn log_lists_blocked_hosts() {
    let mut t = test_env(&[]);
    blocked(&t);
    assert_eq!(t.sbt(&["policy", "log"]).unwrap(), 0);
    assert!(
        t.calls()
            .contains(&"machine egress-events --name sbx-a1 --json --limit 50".to_string())
    );
    let err = t
        .sbt(&["policy", "log", "--type", "filesystem"])
        .unwrap_err();
    assert_eq!(super::super::exit_code(&err), 2);
}

#[test]
fn approval_respond_adds_a_rule_and_pushes() {
    let mut t = test_env(&[]);
    set_policy(&t, "mode = \"deny-all\"");
    blocked(&t);
    t.sbt(&[
        "policy",
        "approval",
        "respond",
        "example.com",
        "allow",
        "--sandbox",
        "a1",
    ])
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
    let err = t
        .sbt(&["policy", "approval", "inspect", "nothing.com"])
        .unwrap_err();
    assert!(err.to_string().contains("no blocked request"), "{err}");
}

#[test]
fn approval_respond_refuses_to_deny_a_bound_secret_host() {
    let mut t = test_env(&[]);
    set_policy(&t, "mode = \"deny-all\"");
    blocked(&t);
    // Blocked earlier, and since bound to a secret of the same sandbox.
    running(
        &t,
        &[
            ("sbx.name", "a1"),
            ("sbx.secrets", "internal"),
            ("sbx.credential-hosts", "example.com"),
        ],
    );
    let err = t.sbt_err(&["policy", "approval", "respond", "example.com", "deny"]);
    assert!(err.contains("can't deny example.com"), "{err}");
    let p = Policy::load(&t.ctx.paths).unwrap();
    assert!(p.sandboxes.is_empty() && p.rules.is_empty());
    // Allowing it is still fine.
    t.sbt(&["policy", "approval", "respond", "example.com", "allow"])
        .unwrap();
}

#[test]
fn approval_respond_checks_the_sandbox_that_was_blocked() {
    let mut t = test_env(&[]);
    set_policy(&t, "mode = \"deny-all\"");
    blocked(&t);
    let err = t.sbt_err(&[
        "policy",
        "approval",
        "respond",
        "example.com",
        "allow",
        "--sandbox",
        "b2",
    ]);
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
        Some("note: 2 rule(s) aren't fully enforced; see `bento policy ls --wide`")
    );
    assert_eq!(
        ls_note_for(&p, None, Some(Decision::Allow)).as_deref(),
        Some("note: 1 rule(s) aren't fully enforced; see `bento policy ls --wide`")
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
    let code = t
        .sbt(&[
            "policy",
            "check",
            "network",
            "api.github.com",
            "--sandbox",
            "a1",
        ])
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
    assert_eq!(t.sbt(&["policy", "ls", "--json"]).unwrap(), 0);
    assert_eq!(t.sbt(&["policy", "ls", "--quiet"]).unwrap(), 0);
}

#[test]
fn log_empty_and_json() {
    assert_eq!(render_log(&[]), "No blocked requests\n");
    let mut t = test_env(&[]);
    running(&t, &[("sbx.name", "a1")]);
    t.runner().ok(&["machine", "egress-events"], "[]");
    assert_eq!(t.sbt(&["policy", "log"]).unwrap(), 0);
    assert_eq!(t.sbt(&["policy", "log", "--json"]).unwrap(), 0);
}

#[test]
fn warnings_dont_stop_a_rule_change() {
    // Listing sandboxes fails: the bound-secret check and the live push only warn.
    let mut t = test_env(&[]);
    set_policy(&t, "mode = \"deny-all\"");
    t.runner()
        .fail(&["machine", "ls"], "SMOLVM_ERROR", "db locked");
    t.sbt(&["policy", "deny", "network", "evil.com"]).unwrap();
    t.sbt(&["policy", "allow", "network", "ok.com"]).unwrap();
    assert_eq!(Policy::load(&t.ctx.paths).unwrap().rules.len(), 2);
    assert!(updates(&t).is_empty());
    // A reset still resets when the running sandboxes can't be stopped.
    t.sbt(&["policy", "reset", "-f"]).unwrap();
    assert_eq!(Policy::load(&t.ctx.paths).unwrap(), Policy::default());
}

#[test]
fn a_failed_live_update_only_warns() {
    let mut t = test_env(&[]);
    set_policy(&t, "mode = \"deny-all\"");
    blocked(&t);
    t.runner()
        .fail(&["machine", "update"], "SMOLVM_ERROR", "not running");
    t.sbt(&["policy", "approval", "respond", "example.com", "allow"])
        .unwrap();
    assert_eq!(Policy::load(&t.ctx.paths).unwrap().rules.len(), 1);
    assert_eq!(updates(&t).len(), 1);
    // And a stop that fails doesn't keep a reset from happening.
    t.runner()
        .fail(&["machine", "stop"], "SMOLVM_ERROR", "stuck");
    t.sbt(&["policy", "reset", "-f"]).unwrap();
    assert_eq!(Policy::load(&t.ctx.paths).unwrap().mode, None);
}

#[test]
fn approval_ls_and_inspect_list_pending_hosts() {
    let mut t = test_env(&[]);
    set_policy(&t, "mode = \"deny-all\"");
    blocked(&t);
    assert_eq!(t.sbt(&["policy", "approval", "ls"]).unwrap(), 0);
    assert_eq!(t.sbt(&["policy", "approval", "ls", "--json"]).unwrap(), 0);
    assert_eq!(
        t.sbt(&["policy", "approval", "inspect", "example.com"])
            .unwrap(),
        0
    );
}

#[test]
fn rm_by_id_finds_a_sandbox_rule_without_sandbox() {
    let mut t = test_env(&[]);
    set_policy(&t, "mode = \"deny-all\"");
    let mut p = Policy::load(&t.ctx.paths).unwrap();
    let id = p
        .add_rule(Some("a1"), Decision::Allow, "a.com", "added", None, None)
        .unwrap();
    p.save(&t.ctx.paths).unwrap();
    t.sbt(&["policy", "rm", "network", "--id", &id]).unwrap();
    assert!(Policy::load(&t.ctx.paths).unwrap().sandboxes.is_empty());
    let err = t
        .sbt(&["policy", "rm", "network", "--id", &id])
        .unwrap_err();
    assert!(err.to_string().contains("no matching rules"), "{err}");
}

#[test]
fn rm_refuses_kit_rules_by_id_aggregate_id_or_resource() {
    use crate::kits::model::{NetRule, Rules};
    let mut t = test_env(&[]);
    set_policy(&t, "mode = \"deny-all\"");
    let mut p = Policy::load(&t.ctx.paths).unwrap();
    let rules = Rules {
        allow: vec![NetRule::host("kit.com")],
        deny: vec![],
    };
    let (ids, _) = p.add_kit_rules("sb", "gh", &rules, false).unwrap();
    p.save(&t.ctx.paths).unwrap();
    let agg = crate::policy::kit_rule_id("sb");
    for args in [
        vec!["policy", "rm", "network", "--id", ids[0].as_str()],
        vec!["policy", "rm", "network", "--id", agg.as_str()],
        vec![
            "policy",
            "rm",
            "network",
            "--sandbox",
            "sb",
            "--resource",
            "kit.com",
        ],
    ] {
        let err = t.sbt(&args).unwrap_err().to_string();
        assert!(err.contains("kit rules can't be removed"), "{err}");
        assert!(err.contains("policy deny network --sandbox sb"), "{err}");
    }
    let p = Policy::load(&t.ctx.paths).unwrap();
    assert_eq!(p.rules_for(Some("sb")).count(), 1);
}

#[test]
fn rm_accepts_force_for_sbx_compatibility() {
    let mut t = test_env(&[]);
    set_policy(&t, "mode = \"deny-all\"");
    t.sbt(&["policy", "allow", "network", "a.com"]).unwrap();
    t.sbt(&["policy", "rm", "network", "--resource", "a.com", "-f"])
        .unwrap();
    // Nothing left to remove: the error is the missing rule, not an unknown flag.
    let err = t
        .sbt(&["policy", "rm", "network", "--resource", "a.com", "--force"])
        .unwrap_err();
    assert!(err.to_string().contains("no matching rules"), "{err}");
    assert!(Policy::load(&t.ctx.paths).unwrap().rules.is_empty());
}

#[test]
fn allow_and_deny_refuse_protocols_other_than_tcp() {
    let mut t = test_env(&[]);
    for kind in ["allow", "deny"] {
        let err = t
            .sbt(&["policy", kind, "network", "x.com", "--protocol", "udp"])
            .unwrap_err();
        assert_eq!(super::super::exit_code(&err), 2, "{kind}");
    }
    assert!(Policy::load(&t.ctx.paths).unwrap().rules.is_empty());
}

#[test]
fn localhost_rules_push_the_gateway_live_with_host_access_only() {
    for access in [true, false] {
        let mut t = test_env(&[]);
        set_policy(&t, "mode = \"deny-all\"");
        let mut labels = vec![("sbx.name", "a1")];
        if access {
            labels.push(("sbx.host-access", "true"));
        }
        running(&t, &labels);
        t.sbt(&[
            "policy",
            "allow",
            "network",
            "--sandbox",
            "a1",
            "LOCALHOST:11434",
        ])
        .unwrap();
        // No hosts: the list is the first of the two calls (see `NO_HOSTS_PLACEHOLDER`).
        let last = resets(&t).pop().unwrap();
        assert_eq!(
            last.contains("--allow-cidr 100.96.0.1/32"),
            access,
            "{access}: {last}"
        );
        assert!(!last.to_lowercase().contains("localhost"), "{last}");
        t.sbt(&[
            "policy",
            "rm",
            "network",
            "--sandbox",
            "a1",
            "--resource",
            "LOCALHOST:11434",
        ])
        .unwrap();
        let u = resets(&t);
        assert_eq!(u.len(), 2, "{u:?}");
        assert!(!u[1].contains("100.96.0.1"), "{u:?}");
    }
}

#[test]
fn localhost_warning_names_the_scope() {
    let res = |s: &str| parse_list(s).unwrap();
    assert_eq!(
        localhost_warning(None, &res("localhost:11434")).unwrap(),
        "warning: smolvm can't open a single host port yet; this opens every port on your \
             host's localhost to all sandboxes"
    );
    assert_eq!(
        localhost_warning(Some("a1"), &res("api.x.com, LOCALHOST:11434")).unwrap(),
        "warning: smolvm can't open a single host port yet; this opens every port on your \
             host's localhost to sandbox a1"
    );
    for other in ["127.0.0.1:80", "host.docker.internal:80", "api.x.com"] {
        assert!(localhost_warning(None, &res(other)).is_none(), "{other}");
    }
}

#[test]
fn without_access_note_lists_sandboxes_in_scope_without_the_label() {
    let sbs = [("a1", false), ("b2", true), ("c3", false)];
    assert_eq!(
        without_access_note(None, &sbs).unwrap(),
        "note: a1, c3 were created without host access; recreate them to use it"
    );
    assert_eq!(
        without_access_note(Some("c3"), &sbs).unwrap(),
        "note: c3 were created without host access; recreate them to use it"
    );
    assert!(without_access_note(Some("b2"), &sbs).is_none());
    assert!(without_access_note(Some("zz"), &sbs).is_none());
    assert!(without_access_note(None, &[("b2", true)]).is_none());
    assert!(without_access_note(None, &[(BUILDER, false)]).is_none());
}

#[test]
fn keeps_access_notes_name_open_sandboxes_with_host_access_that_lose_the_rule() {
    let mut before = Policy {
        mode: Some(Mode::AllowAll),
        ..Default::default()
    };
    before
        .add_rule(None, Decision::Allow, "localhost:80", "added", None, None)
        .unwrap();
    let mut after = before.clone();
    after.remove_rules(None, None, Some("localhost:80"));
    let sbs = [("a1", true), ("b2", false)];
    assert_eq!(
        keeps_access_notes(&before, &after, &sbs),
        ["note: a1 keeps host access until it's recreated"]
    );
    // No change: no note. A restricted sandbox loses it live: no note.
    assert!(keeps_access_notes(&before, &before, &sbs).is_empty());
    let mut before = before.clone();
    before.mode = Some(Mode::DenyAll);
    let mut after = after.clone();
    after.mode = Some(Mode::DenyAll);
    assert!(keeps_access_notes(&before, &after, &sbs).is_empty());
}
