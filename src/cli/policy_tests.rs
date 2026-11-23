use super::ls::{filtered, ls_note, ls_rules};
use super::*;
use crate::cli::PolicyLsArgs;
use crate::policy::Mode;
use crate::secrets::{SecretEntry, Source};
use crate::testutil::*;

/// The `machine update` calls that set a whole allow list.
fn resets(t: &TestEnv) -> Vec<String> {
    updates(t)
        .into_iter()
        .filter(|l| l.contains("--reset-allow-list"))
        .collect()
}

fn updates(t: &TestEnv) -> Vec<String> {
    t.calls_of("machine update")
}

#[test]
fn init_saves_and_pushes() {
    let mut t = test_env(&[]);
    t.sandboxes(&[("a1", "running", &[])]);
    t.sbt(&["policy", "init", "deny-all"]).unwrap();
    assert_eq!(
        Policy::load(&t.ctx.paths).unwrap().mode,
        Some(Mode::DenyAll)
    );
    let u = updates(&t);
    assert_eq!(u.len(), 1, "{u:?}");
    assert!(u[0].contains("--reset-allow-list"), "{u:?}");
    assert!(!u[0].contains("--allow-host"), "{u:?}");
}

#[test]
fn allow_and_rm_push_live() {
    let mut t = test_env(&[]);
    set_policy(&t, "mode = \"deny-all\"");
    t.sandboxes(&[("a1", "running", &[])]);
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
    assert!(
        err.to_string().contains("remove-resource: not found"),
        "{err}"
    );
}

#[test]
fn a_rule_change_lists_the_sandboxes_once() {
    let mut t = test_env(&[]);
    set_policy(&t, "mode = \"deny-all\"");
    t.sandboxes(&[("a1", "running", &[])]);
    for args in [
        &["policy", "deny", "network", "localhost"][..],
        &["policy", "allow", "network", "localhost"],
        &["policy", "rm", "network", "--resource", "localhost"],
    ] {
        let before = t
            .calls()
            .iter()
            .filter(|l| *l == "machine ls --json")
            .count();
        t.sbt(args).unwrap();
        let after = t
            .calls()
            .iter()
            .filter(|l| *l == "machine ls --json")
            .count();
        assert_eq!(after - before, 1, "{args:?}");
    }
}

#[test]
fn deny_refuses_a_bound_secret_host() {
    let mut t = test_env(&[]);
    t.sandboxes(&[(
        "a1",
        "running",
        &[
            ("sbx.secrets", "github"),
            ("sbx.credential-hosts", "api.github.com,github.com"),
        ],
    )]);
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
    t.sandboxes(&[(
        "a1",
        "running",
        &[
            ("sbx.secrets", "notion-token"),
            ("sbx.credential-hosts", "*.notion.com"),
        ],
    )]);
    for deny in ["api.notion.com", "**.notion.com", "*.notion.com"] {
        let err = t.sbt(&["policy", "deny", "network", deny]).unwrap_err();
        let msg = err.to_string();
        // No secrets.toml entry names the service, so the message falls back to "a secret".
        assert!(msg.contains("can't deny *.notion.com"), "{err}");
        assert!(msg.contains("has a secret bound to it"), "{err}");
    }
    t.sbt(&["policy", "deny", "network", "notion.com"]).unwrap();
    // A request deny leaves the host reachable, so the secret keeps working.
    t.sbt(&[
        "policy",
        "deny",
        "network",
        "api.notion.com",
        "--method",
        "POST",
    ])
    .unwrap();
}

#[test]
fn a_policy_change_before_smolvm_is_downloaded_asks_smolvm_nothing() {
    // A fresh install: no smolvm yet, so no sandbox to update (and nothing to warn about).
    let mut t = test_env(&[]);
    t.use_managed_smolvm();
    t.sbt(&["policy", "init", "balanced"]).unwrap();
    t.sbt(&["policy", "allow", "network", "example.com"])
        .unwrap();
    assert_eq!(t.calls(), Vec::<String>::new());
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
fn check_prints_sbxs_block_and_verbose_adds_the_action() {
    let mut t = test_env(&[]);
    set_policy(&t, "mode = \"deny-all\"");
    let code = t
        .sbt(&[
            "policy",
            "check",
            "network",
            "--protocol",
            "udp",
            "github.com:443",
        ])
        .unwrap();
    assert_eq!(code, 1);
    assert_eq!(
        t.stdout(),
        "  Denied:      github.com:443\n  Governance:  Local policy only\n  Context:     global\n  \
         Reason:      no matching allow rule (default deny)\n"
    );
    t.sbt(&[
        "policy",
        "check",
        "network",
        "--protocol",
        "udp",
        "-v",
        "github.com:123",
    ])
    .unwrap();
    assert_eq!(
        t.stdout(),
        "  Denied:      github.com:123\n  Governance:  Local policy only\n  Context:     global\n  \
         Reason:      no matching allow rule (default deny)\n  Action:      net:connect:udp\n  \
         Resource:    net:domain github.com:123\n  Deny kind:   implicit\n"
    );
    // An allowed target, tcp by default: a bare host is checked on port 443.
    t.sbt(&["policy", "allow", "network", "x.com"]).unwrap();
    t.stdout();
    let code = t
        .sbt(&[
            "policy",
            "check",
            "network",
            "x.com",
            "--protocol",
            "tcp",
            "--verbose",
        ])
        .unwrap();
    assert_eq!(code, 0);
    let out = t.stdout();
    assert!(
        out.starts_with(
            "  Allowed:     x.com:443\n  Governance:  Local policy only\n  Context:     global\n  \
             Reason:      allow rule "
        ),
        "{out}"
    );
    assert!(
        out.ends_with("  Action:      net:connect:tcp\n  Resource:    net:domain x.com:443\n"),
        "{out}"
    );
}

#[test]
fn check_udp_follows_the_rules_except_dns_and_json_has_sbxs_keys() {
    let mut t = test_env(&[]);
    set_policy(&t, "mode = \"deny-all\"");
    let code = t
        .sbt(&[
            "policy",
            "check",
            "network",
            "--protocol",
            "udp",
            "--json",
            "github.com:123",
        ])
        .unwrap();
    assert_eq!(code, 1);
    assert_eq!(
        t.stdout(),
        r#"{
  "action": "net:connect:udp",
  "allowed": false,
  "context": "global",
  "deny_kind": "implicit",
  "governance": {
    "active": false
  },
  "reason": "No matching allow rule (default deny)",
  "resource_type": "net:domain",
  "resource_value": "github.com:123",
  "target": "github.com:123",
  "type": "network"
}
"#
    );
    // smolvm's allow list admits UDP where it admits TCP, but answers DNS itself.
    t.sbt(&["policy", "allow", "network", "github.com"])
        .unwrap();
    t.stdout();
    let udp = ["policy", "check", "network", "--protocol", "udp", "--json"];
    assert_eq!(t.sbt(&[&udp[..], &["github.com:123"]].concat()).unwrap(), 0);
    let v: serde_json::Value = serde_json::from_str(&t.stdout()).unwrap();
    assert_eq!(v["allowed"], true);
    assert_eq!(v["action"], "net:connect:udp");
    assert!(v.get("deny_kind").is_none(), "{v}");
    let reason = v["reason"].as_str().unwrap();
    assert!(
        reason.ends_with("; not from hosted sandboxes, which send no UDP but DNS"),
        "{reason}"
    );
    assert_eq!(t.sbt(&[&udp[..], &["github.com:53"]].concat()).unwrap(), 1);
    let v: serde_json::Value = serde_json::from_str(&t.stdout()).unwrap();
    assert_eq!(
        v["reason"],
        "Smolvm answers DNS itself; UDP to port 53 never reaches the target"
    );
    // A deny rule's denial is explicit.
    t.sbt(&["policy", "deny", "network", "10.0.0.0/8"]).unwrap();
    t.stdout();
    assert_eq!(t.sbt(&[&udp[..], &["10.1.2.3:123"]].concat()).unwrap(), 1);
    let v: serde_json::Value = serde_json::from_str(&t.stdout()).unwrap();
    assert_eq!(v["deny_kind"], "explicit");
}

#[test]
fn check_refuses_an_unknown_protocol_as_sbx_does() {
    let mut t = test_env(&[]);
    let err = t
        .sbt(&[
            "policy",
            "check",
            "network",
            "--protocol",
            "bogus",
            "github.com",
        ])
        .unwrap_err();
    assert_eq!(super::super::exit_code(&err), 1);
    assert_eq!(
        err.to_string(),
        "invalid argument \"bogus\" for \"--protocol\" flag: invalid protocol \"bogus\": must be \
         tcp or udp\n  try: bento policy check network --help"
    );
}

#[test]
fn check_udp_to_port_53_reports_the_rules_denial_first() {
    let mut t = test_env(&[]);
    set_policy(&t, "mode = \"deny-all\"");
    let udp = ["policy", "check", "network", "--protocol", "udp"];
    // As measured in sbx: no allow rule is the reason, not DNS.
    assert_eq!(
        t.sbt(&[&udp[..], &["-v", "github.com:53"]].concat())
            .unwrap(),
        1
    );
    assert_eq!(
        t.stdout(),
        "  Denied:      github.com:53\n  Governance:  Local policy only\n  Context:     global\n  \
         Reason:      no matching allow rule (default deny)\n  Action:      net:connect:udp\n  \
         Resource:    net:domain github.com:53\n  Deny kind:   implicit\n"
    );
    // A deny rule's denial stays explicit on port 53.
    t.sbt(&["policy", "deny", "network", "10.0.0.0/8"]).unwrap();
    t.stdout();
    assert_eq!(
        t.sbt(&[&udp[..], &["--json", "10.1.2.3:53"]].concat())
            .unwrap(),
        1
    );
    let v: serde_json::Value = serde_json::from_str(&t.stdout()).unwrap();
    assert_eq!(v["deny_kind"], "explicit");
    assert!(
        v["reason"].as_str().unwrap().starts_with("Deny rule "),
        "{v}"
    );
}

#[test]
fn rm_refuses_an_empty_method_instead_of_matching_every_rule() {
    let mut t = test_env(&[]);
    set_policy(&t, "mode = \"deny-all\"");
    t.sbt(&["policy", "allow", "network", "a.com"]).unwrap();
    t.sbt(&[
        "policy", "allow", "network", "a.com", "--method", "GET", "--path", "/v1/**",
    ])
    .unwrap();
    let rm = ["policy", "rm", "network", "--resource", "a.com", "-f"];
    // Not measured in sbx: smolbento's own error.
    for method in ["", ",", " , "] {
        let err = t
            .sbt(&[&rm[..], &["--method", method]].concat())
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "--method names no HTTP method\n  try: bento policy rm network --help",
            "{method:?}"
        );
        assert_eq!(super::super::exit_code(&err), 1);
    }
    // An empty path is no rule's path.
    let err = t.sbt(&[&rm[..], &["--path", ""]].concat()).unwrap_err();
    assert!(
        err.to_string().contains("remove-resource: not found"),
        "{err}"
    );
    assert_eq!(Policy::load(&t.ctx.paths).unwrap().rules.len(), 2);
}

#[test]
fn rm_picks_a_rule_by_its_http_qualifiers() {
    let mut t = test_env(&[]);
    set_policy(&t, "mode = \"deny-all\"");
    t.sbt(&["policy", "allow", "network", "a.com"]).unwrap();
    t.sbt(&[
        "policy", "allow", "network", "a.com", "--method", "GET,POST", "--path", "/v1/**",
    ])
    .unwrap();
    const NOT_FOUND: &str = "remove network rule: remove-resource: not found; \
                             use \"bento policy ls --wide\" to find rule IDs";
    let rm = ["policy", "rm", "network", "--resource", "a.com", "-f"];
    for extra in [
        &["--method", "GET"][..],
        &["--path", "/v2"],
        &["--method", "GET,POST", "--path", "/v1/**", "--query", "a=1"],
    ] {
        let err = t.sbt(&[&rm[..], extra].concat()).unwrap_err();
        assert_eq!(err.to_string(), NOT_FOUND, "{extra:?}");
        assert_eq!(super::super::exit_code(&err), 1);
    }
    assert_eq!(Policy::load(&t.ctx.paths).unwrap().rules.len(), 2);
    t.stdout();
    t.sbt(&[&rm[..], &["--method", "post,get", "--path", "/v1/**"]].concat())
        .unwrap();
    assert_eq!(t.stdout(), "Removed\n");
    let p = Policy::load(&t.ctx.paths).unwrap();
    assert_eq!(p.rules.len(), 1);
    assert_eq!(p.rules[0].method, None);
    // Without --resource there is nothing for them to pick from. sbx's error was measured for
    // --method only; --path and --query are assumed to say the same.
    for flag in ["--method", "--path", "--query"] {
        let err = t
            .sbt(&["policy", "rm", "network", flag, "GET", "-f"])
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            format!("{flag} requires --resource\n  try: bento policy rm network --help")
        );
        assert_eq!(super::super::exit_code(&err), 1);
    }
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
    t.sandboxes(&[("a1", "running", &[])]);
    t.sbt(&["policy", "reset", "-f"]).unwrap();
    assert!(t.calls().contains(&"machine stop -n sbx-a1".to_string()));
    assert_eq!(Policy::load(&t.ctx.paths).unwrap().mode, None);
}

#[test]
fn policy_changes_reach_only_this_setups_sandboxes() {
    // Two bento setups can share one smolvm home; each policy is its own setup's.
    let mut t = test_env(&[]);
    let ours = crate::host_service::namespace(&t.ctx.paths);
    t.sandboxes(&[
        ("mine", "running", &[("sbx.setup", ours.as_str())]),
        ("legacy", "running", &[]),
        ("theirs", "running", &[("sbx.setup", "00000000")]),
    ]);
    t.sbt(&["policy", "allow", "network", "api.x.com"]).unwrap();
    let u = updates(&t);
    assert!(u.iter().any(|l| l.contains("-n sbx-mine")), "{u:?}");
    assert!(u.iter().any(|l| l.contains("-n sbx-legacy")), "{u:?}");
    assert!(!u.iter().any(|l| l.contains("-n sbx-theirs")), "{u:?}");
    t.sbt(&["policy", "reset", "-f"]).unwrap();
    let calls = t.calls();
    assert!(
        calls.contains(&"machine stop -n sbx-mine".to_string()),
        "{calls:?}"
    );
    assert!(
        !calls
            .iter()
            .any(|l| l.starts_with("machine stop -n sbx-theirs")),
        "{calls:?}"
    );
}

fn blocked(t: &TestEnv) {
    t.sandboxes(&[("a1", "running", &[])]);
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
        "--option",
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
fn approval_respond_checks_the_sandbox_that_was_blocked() {
    let mut t = test_env(&[]);
    set_policy(&t, "mode = \"deny-all\"");
    blocked(&t);
    let err = t.sbt_err(&[
        "policy",
        "approval",
        "respond",
        "example.com",
        "--option",
        "allow",
        "--sandbox",
        "b2",
    ]);
    assert!(err.contains("b2") && err.contains("blocked in a1"), "{err}");
    // sbx answers only with --option.
    let err = t.sbt_err(&["policy", "approval", "respond", "example.com", "allow"]);
    assert!(err.contains("unexpected argument 'allow'"), "{err}");
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
    p.allow(Some("s1"), "api.x.com:8080");
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
    p.deny(None, "crl*.digicert.com:80");
    assert!(!compile::check(&p, Some("s1"), &[], None, "crl3.digicert.com:80").allowed);
}

#[test]
fn log_rows_render() {
    let rows = vec![log::LogRow {
        sandbox: "a1".into(),
        host: "example.com".into(),
        count: 2,
        last_seen: "2026-10-26T11:00:00Z".into(),
        first_seen: "2026-10-26T10:00:00Z".into(),
    }];
    insta::assert_snapshot!(render_log(&rows));
}

#[test]
fn check_allows_a_bound_secret_host_under_deny_all() {
    let mut t = test_env(&[]);
    set_policy(&t, "mode = \"deny-all\"");
    t.sandboxes(&[(
        "a1",
        "running",
        &[("sbx.credential-hosts", "api.github.com")],
    )]);
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
fn log_empty_and_json() {
    assert_eq!(render_log(&[]), "No blocked requests\n");
    let mut t = test_env(&[]);
    t.sandboxes(&[("a1", "running", &[])]);
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
    t.sbt(&[
        "policy",
        "approval",
        "respond",
        "example.com",
        "--option",
        "allow",
    ])
    .unwrap();
    assert_eq!(sandbox_rules(&t, "a1").len(), 1);
    assert_eq!(updates(&t).len(), 1);
    // And a stop that fails doesn't keep a reset from happening.
    t.runner()
        .fail(&["machine", "stop"], "SMOLVM_ERROR", "stuck");
    t.sbt(&["policy", "reset", "-f"]).unwrap();
    assert_eq!(Policy::load(&t.ctx.paths).unwrap().mode, None);
}

#[test]
fn approval_ls_and_inspect_print_sbxs_layout() {
    let mut t = test_env(&[]);
    set_policy(&t, "mode = \"deny-all\"");
    assert_eq!(t.sbt(&["policy", "approval", "ls"]).unwrap(), 0);
    assert_eq!(t.stdout(), "No pending approvals.\n");
    t.sbt(&["policy", "approval", "ls", "--json"]).unwrap();
    assert_eq!(t.stdout(), "[]\n");
    blocked(&t);
    t.sbt(&["policy", "approval", "ls"]).unwrap();
    assert_eq!(
        t.stdout(),
        "APPROVAL      SANDBOX   TITLE         DETAIL                                                        OPTIONS\n\
         example.com   a1        example.com   Resource type: domain no matching allow rule (default deny)   allow (Allow), dismiss (Dismiss)\n"
    );
    t.sbt(&["policy", "approval", "ls", "-q"]).unwrap();
    assert_eq!(t.stdout(), "example.com\n");
    t.sbt(&["policy", "approval", "ls", "--json"]).unwrap();
    assert_eq!(
        t.stdout(),
        r#"[
  {
    "created_at": "2026-10-26T10:00:00Z",
    "detail": "Resource type: domain\nno matching allow rule (default deny)",
    "id": "example.com",
    "options": [
      {
        "id": "allow",
        "label": "Allow"
      },
      {
        "id": "dismiss",
        "label": "Dismiss"
      }
    ],
    "sandbox_name": "a1",
    "title": "example.com"
  }
]
"#
    );
    t.sbt(&["policy", "approval", "inspect", "example.com"])
        .unwrap();
    assert_eq!(
        t.stdout(),
        "  ○ APPROVAL example.com — sandbox a1\n      example.com\n      \
         Resource type: domain no matching allow rule (default deny)\n\n  \
         OPTION    LABEL\n  allow     Allow\n  dismiss   Dismiss\n"
    );
}

#[test]
fn approval_respond_option_allow_adds_the_sandboxs_rule() {
    let mut t = test_env(&[]);
    set_policy(&t, "mode = \"deny-all\"");
    blocked(&t);
    let respond = ["policy", "approval", "respond", "example.com"];
    // sbx's errors: no --option, an option the approval doesn't have.
    let err = t.sbt(&respond).unwrap_err();
    assert_eq!(
        err.to_string(),
        "required flag(s) \"option\" not set\n  try: bento policy approval respond --help"
    );
    assert_eq!(super::super::exit_code(&err), 1);
    let err = t
        .sbt(&[&respond[..], &["--option", "bogus"]].concat())
        .unwrap_err();
    assert_eq!(
        err.to_string(),
        "approval \"example.com\" has no option \"bogus\"\n  try: bento policy approval ls"
    );
    assert_eq!(super::super::exit_code(&err), 1);
    t.stdout();
    t.sbt(&[&respond[..], &["--option", "allow"]].concat())
        .unwrap();
    // (The second line is smolbento's: the rule was applied to the running sandbox.)
    assert_eq!(
        t.stdout(),
        "Recorded answer Allow\nUpdated 1 running sandbox(es)\n"
    );
    // As in sbx, the rule is the sandbox's own.
    let p = Policy::load(&t.ctx.paths).unwrap();
    assert!(p.rules.is_empty());
    let rule = &p.sandboxes["a1"].rules[0];
    assert_eq!(
        (
            rule.decision,
            rule.resources[0].as_str(),
            rule.created_via.as_str()
        ),
        (Decision::Allow, "example.com", "approval")
    );
    assert!(
        updates(&t)
            .pop()
            .unwrap()
            .contains("--allow-host-pattern example.com")
    );
    // Answered: no longer pending.
    let err = t
        .sbt(&[&respond[..], &["--option", "allow"]].concat())
        .unwrap_err();
    assert_eq!(
        err.to_string(),
        "approval \"example.com\" is not pending\n  try: bento policy approval ls"
    );
    t.sbt(&["policy", "approval", "ls"]).unwrap();
    assert_eq!(t.stdout(), "No pending approvals.\n");
    // The two forms don't mix.
    assert!(
        t.sbt(&[&respond[..], &["allow", "--option", "allow"]].concat())
            .is_err()
    );
}

#[test]
fn approval_respond_option_allow_gives_the_notes_policy_allow_gives() {
    let mut t = test_env(&[]);
    set_policy(&t, "mode = \"deny-all\"");
    t.sandboxes(&[("a1", "running", &[])]);
    t.runner().ok(
        &["machine", "egress-events"],
        r#"[{"timestamp":"2026-10-26T10:00:00Z","operation":"resolve","dest":"localhost"}]"#,
    );
    // The notes go to stderr, so they are checked as the handler computes them.
    let before = Policy::load(&t.ctx.paths).unwrap();
    let mut after = before.clone();
    after
        .add_rule(
            Some("a1"),
            Decision::Allow,
            "localhost",
            "approval",
            None,
            None,
        )
        .unwrap();
    let rows = blocked_rows(&t.ctx, None, APPROVAL_EVENTS).unwrap();
    // The same sandbox twice: each note once.
    let waiting = [&rows[0], &rows[0]];
    assert_eq!(
        approval_notes(
            &sandbox::Listing::new(&t.ctx.vm),
            &before,
            &after,
            &waiting,
            "localhost"
        )
        .unwrap(),
        [
            "warning: smolvm can't open a single host port yet; this opens every port on your \
             host's localhost to sandbox a1",
            "note: a1 were created without host access; recreate them to use it"
        ]
    );
    // Another host has none.
    assert!(
        approval_notes(
            &sandbox::Listing::new(&t.ctx.vm),
            &before,
            &before,
            &waiting,
            "example.com"
        )
        .unwrap()
        .is_empty()
    );
    t.sbt(&[
        "policy",
        "approval",
        "respond",
        "localhost",
        "--option",
        "allow",
    ])
    .unwrap();
    assert!(t.stdout().starts_with("Recorded answer Allow\n"));
    assert_eq!(Policy::load(&t.ctx.paths).unwrap(), after);
}

#[test]
fn approval_respond_option_dismiss_adds_no_rule_until_blocked_again() {
    let mut t = test_env(&[]);
    set_policy(&t, "mode = \"deny-all\"");
    blocked(&t);
    let dismiss = [
        "policy",
        "approval",
        "respond",
        "example.com",
        "--option",
        "dismiss",
    ];
    t.sbt(&dismiss).unwrap();
    assert_eq!(t.stdout(), "Recorded answer Dismiss\n");
    let p = Policy::load(&t.ctx.paths).unwrap();
    assert!(p.rules.is_empty() && p.sandboxes.is_empty());
    assert!(updates(&t).is_empty());
    t.sbt(&["policy", "approval", "ls", "--json"]).unwrap();
    assert_eq!(t.stdout(), "[]\n");
    assert!(t.sbt_err(&dismiss).contains("is not pending"));
    // Blocked again later: it asks again (smolbento's choice; not measured in sbx).
    t.runner().ok(
        &["machine", "egress-events"],
        r#"[{"timestamp":"2026-10-26T12:00:00Z","operation":"resolve","dest":"example.com"}]"#,
    );
    t.sbt(&["policy", "approval", "ls", "-q"]).unwrap();
    assert_eq!(t.stdout(), "example.com\n");
    // `policy reset` forgets dismissals with the rules.
    t.sbt(&dismiss).unwrap();
    t.sbt(&["policy", "reset", "-f"]).unwrap();
    assert_eq!(Policy::load(&t.ctx.paths).unwrap(), Policy::default());
}

#[test]
fn rm_by_id_finds_a_sandbox_rule_without_sandbox() {
    let mut t = test_env(&[]);
    set_policy(&t, "mode = \"deny-all\"");
    let mut p = Policy::load(&t.ctx.paths).unwrap();
    let id = p.allow(Some("a1"), "a.com");
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
    assert!(
        err.to_string()
            .starts_with("remove network rule: remove-resource: not found"),
        "{err}"
    );
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
        let labels: &[(&str, &str)] = if access {
            &[("sbx.host-access", "true")]
        } else {
            &[]
        };
        t.sandboxes(&[("a1", "running", labels)]);
        t.sbt(&[
            "policy",
            "allow",
            "network",
            "--sandbox",
            "a1",
            "LOCALHOST:11434",
        ])
        .unwrap();
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
    before.allow(None, "localhost:80");
    let mut after = before.clone();
    after.remove_rules(None, None, Some("localhost:80"), None, None, None);
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

/// An empty policy in `mode`.
fn policy(mode: Mode) -> Policy {
    Policy {
        mode: Some(mode),
        ..Default::default()
    }
}

/// Adds a rule without a method or a path to `p`, and returns its id.
fn add(
    p: &mut Policy,
    sandbox: Option<&str>,
    decision: Decision,
    hosts: &str,
    via: &str,
) -> String {
    p.add_rule(sandbox, decision, hosts, via, None, None)
        .unwrap()
}

/// `bento policy ls ARGS`'s stdout.
fn ls(t: &mut TestEnv, args: &[&str]) -> String {
    let args: Vec<&str> = ["policy", "ls"].iter().chain(args).copied().collect();
    t.sbt(&args).unwrap();
    t.stdout()
}

/// A `deny-all` policy with the rules sbx was measured with: a global allow, a global deny with
/// a port, and an allow for sandbox `chk-pol`, which exists. Returns the three rule ids.
fn checked_policy(t: &TestEnv) -> [String; 3] {
    let mut p = policy(Mode::DenyAll);
    let mut add = |sandbox, decision, host| add(&mut p, sandbox, decision, host, "added");
    let ids = [
        add(None, Decision::Allow, "chk-allow.example.invalid"),
        add(None, Decision::Deny, "chk-deny.example.invalid:8443"),
        add(
            Some("chk-pol"),
            Decision::Allow,
            "chk-scoped.example.invalid",
        ),
    ];
    p.save(&t.ctx.paths).unwrap();
    t.sandbox("chk-pol", "running", &[]);
    ids
}

/// A continuation line of the wide table: each `(column, text)` under its column of `head`.
fn under(head: &str, cells: &[(&str, &str)]) -> String {
    let mut line = String::new();
    for (column, text) in cells {
        let at = head.find(column).unwrap();
        line.push_str(&" ".repeat(at - line.chars().count()));
        line.push_str(text);
    }
    line
}

const NO_MATCH: &str = "No policies match the selected filters\n";

#[test]
fn ls_table_has_one_row_per_policy() {
    let mut t = test_env(&[]);
    checked_policy(&t);
    assert_eq!(
        ls(&mut t, &[]),
        "\
POLICY             SOURCE   APPLIES TO        SUMMARY
default-deny-all   local    all               network: deny when no rule decides
local-policy       local    all               network: 1 allow, 1 deny
sandbox:chk-pol    local    sandbox:chk-pol   network: 1 allow
"
    );
    set_policy(&t, "mode = \"balanced\"");
    assert_eq!(
        ls(&mut t, &[]),
        "\
POLICY             SOURCE   APPLIES TO   SUMMARY
default-deny-all   local    all          network: deny when no rule decides
local-policy       local    all          network: 199 allow
"
    );
}

#[test]
fn ls_shows_the_mode_as_the_fallback_policy() {
    let mut t = test_env(&[]);
    let open = "\
POLICY              SOURCE   APPLIES TO   SUMMARY
default-allow-all   local    all          network: allow when no rule decides
";
    assert_eq!(ls(&mut t, &[]), open, "no mode chosen: open");
    set_policy(&t, "mode = \"allow-all\"");
    assert_eq!(ls(&mut t, &[]), open);
    assert_eq!(ls(&mut t, &["-q"]), "default-allow-all\n");
    set_policy(&t, "mode = \"deny-all\"");
    assert_eq!(ls(&mut t, &["--quiet"]), "default-deny-all\n");
}

#[test]
fn ls_wide_is_sbx_s_fourteen_columns() {
    let mut t = test_env(&[]);
    set_policy(&t, "mode = \"deny-all\"");
    // sbx 0.53's `policy ls --decision deny --wide`, trailing spaces included.
    let head = "SOURCE   CREATED VIA   APPLIES TO   POLICY             POLICY_ID   RULE   RULE_ID            TYPE      METHOD   PATH   DECISION   PROTOCOLS   STATUS                       RESOURCES";
    assert_eq!(
        ls(&mut t, &["--wide"]),
        format!(
            "{head}\n\
local    -             all          default-deny-all   -           -      default-deny-all   network   -        -      deny       tcp,udp     active — Implicit fallback   **\n\
{}\n{}\n",
            under(
                head,
                &[("STATUS", "when no applicable policy"), ("RESOURCES", "")]
            ),
            under(
                head,
                &[("STATUS", "decides the request."), ("RESOURCES", "")]
            ),
        )
    );
}

#[test]
fn ls_wide_lists_each_resource_sorted_and_hides_a_plain_status() {
    let mut t = test_env(&[]);
    let mut p = policy(Mode::Balanced);
    let one = add(&mut p, None, Decision::Allow, "z.example.com", "approval");
    let hosts = "b.example.com,a.example.com";
    let two = add(&mut p, Some("a1"), Decision::Allow, hosts, "approval");
    p.save(&t.ctx.paths).unwrap();
    // As sbx's `--created-via approval --wide`: no row has more than `active` to say, so there
    // is no STATUS column.
    let wide = ls(&mut t, &["--created-via", "approval", "--wide"]);
    let lines: Vec<&str> = wide.lines().collect();
    let head = "SOURCE   CREATED VIA   APPLIES TO   POLICY   POLICY_ID      RULE   RULE_ID      TYPE      METHOD   PATH   DECISION   PROTOCOLS   RESOURCES";
    assert_eq!(
        lines,
        [
            head,
            &format!(
                "local    approval      all          -        local-policy   -      {one}   network   -        -      allow      tcp         z.example.com"
            ),
            &under(head, &[("RESOURCES", "")]),
            &format!(
                "local    approval      sandbox:a1   -        sandbox:a1     -      {two}   network   -        -      allow      tcp         a.example.com"
            ),
            &under(
                head,
                &[
                    ("METHOD", "-"),
                    ("PATH", "-"),
                    ("RESOURCES", "b.example.com")
                ]
            ),
        ],
        "{wide}"
    );
    // The whole listing: the preset's rows, each resource on its own line, the fallback last.
    let all = ls(&mut t, &["--wide"]);
    assert!(
        all.lines().next().unwrap().contains("   STATUS   "),
        "{all}"
    );
    assert!(
        all.contains(
            "local    default       all          -                  local-policy   -      default-ai-services "
        ),
        "{all}"
    );
    assert!(all.contains("   smolbento-nix   "), "{all}");
    assert!(all.trim_end().ends_with("decides the request."), "{all}");
}

#[test]
fn ls_json_and_yaml_are_sbx_s_rules_document() {
    let mut t = test_env(&[]);
    let mut p = policy(Mode::DenyAll);
    let scope = Some("chk-pol");
    let id = add(
        &mut p,
        scope,
        Decision::Allow,
        "example.org:443",
        "approval",
    );
    p.save(&t.ctx.paths).unwrap();
    // Keys in sbx's order.
    let json = format!(
        r#"{{
  "rules": [
    {{
      "id": "{id}",
      "name": "approval:{id}",
      "policy_id": "sandbox:chk-pol",
      "scope": "sandbox:chk-pol",
      "applies_to": "sandbox:chk-pol",
      "resource_type": "network",
      "decision": "allow",
      "resources": [
        "example.org:443"
      ],
      "origin": "scoped",
      "layer": "local",
      "status": "active",
      "reason": "example.org:443: port 443 not enforced by smolvm (all ports allowed; enforced for hosted sandboxes)",
      "editable": true,
      "sandbox_id": "chk-pol",
      "provenance": {{
        "created_via": "approval"
      }},
      "actions": [
        "net:connect:tcp"
      ]
    }},
    {{
      "id": "default-deny-all",
      "name": "default-deny-all",
      "policy_name": "default-deny-all",
      "scope": "global",
      "applies_to": "all",
      "resource_type": "network",
      "decision": "deny",
      "resources": [
        "**"
      ],
      "origin": "local",
      "layer": "local",
      "status": "active",
      "reason": "Implicit fallback when no applicable policy decides the request.",
      "editable": false,
      "actions": [
        "net:connect:tcp",
        "net:connect:udp"
      ]
    }}
  ]
}}
"#
    );
    assert_eq!(ls(&mut t, &["--json"]), json);
    assert_eq!(ls(&mut t, &["--format", "json"]), json);
    let yaml = ls(&mut t, &["--format", "yaml"]);
    // sbx's YAML for the fallback, byte for byte.
    assert!(
        yaml.ends_with(
            "\
- id: default-deny-all
  name: default-deny-all
  policy_name: default-deny-all
  scope: global
  applies_to: all
  resource_type: network
  decision: deny
  resources:
  - \"**\"
  origin: local
  layer: local
  status: active
  reason: Implicit fallback when no applicable policy decides the request.
  editable: false
  actions:
  - net:connect:tcp
  - net:connect:udp
"
        ),
        "{yaml}"
    );
    let doc: serde_json::Value = serde_saphyr::from_str(&yaml).unwrap();
    assert_eq!(
        doc,
        serde_json::from_str::<serde_json::Value>(&json).unwrap()
    );
    assert!(yaml.starts_with("rules:\n"), "{yaml}");
    // A filter that matches nothing leaves an empty list.
    assert_eq!(
        ls(&mut t, &["--json", "--source", "org"]),
        "{\n  \"rules\": []\n}\n"
    );
    // --quiet wins over the format: ids only.
    assert_eq!(
        ls(&mut t, &["--json", "-q"]),
        format!("{id}\ndefault-deny-all\n")
    );
}

#[test]
fn ls_for_a_sandbox_summarises_what_applies_to_it() {
    let mut t = test_env(&[]);
    let [allow, deny, scoped] = checked_policy(&t);
    let mut p = Policy::load(&t.ctx.paths).unwrap();
    add(&mut p, Some("other"), Decision::Allow, "x.com", "added");
    add(&mut p, None, Decision::Allow, "second.example", "added");
    p.save(&t.ctx.paths).unwrap();
    assert_eq!(
        ls(&mut t, &["chk-pol"]),
        "  Policy for sandbox:  chk-pol

NETWORK
  • allow 3 hosts from local-policy, sandbox:chk-pol
  • deny 1 host from local-policy
  • fallback: deny when no rule decides from default-deny-all

"
    );
    assert_eq!(
        ls(
            &mut t,
            &["chk-pol", "--decision", "deny", "--source", "local"]
        ),
        "  Policy for sandbox:  chk-pol

NETWORK
  • deny 1 host from local-policy
  • fallback: deny when no rule decides from default-deny-all

"
    );
    // --wide, --json and -q list the same rules as rows: the global ones and this sandbox's.
    let quiet = ls(&mut t, &["chk-pol", "-q"]);
    let ids: Vec<&str> = quiet.lines().collect();
    assert_eq!(ids.len(), 5, "{quiet}");
    assert_eq!(ids[..2], [allow.as_str(), deny.as_str()]);
    assert_eq!(ids[3..], [scoped.as_str(), "default-deny-all"]);
    let wide = ls(&mut t, &["chk-pol", "--wide"]);
    assert!(wide.starts_with("SOURCE   CREATED VIA   "), "{wide}");
    assert!(
        wide.contains("sandbox:chk-pol") && !wide.contains("other"),
        "{wide}"
    );
    let json = ls(&mut t, &["chk-pol", "--json"]);
    let json: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(json["rules"].as_array().unwrap().len(), 5);
}

#[test]
fn ls_for_an_unknown_sandbox_fails_as_sbx_does() {
    let mut t = test_env(&[]);
    t.runner()
        .fail(&["machine", "status"], "NOT_FOUND", "machine not found");
    assert_eq!(
        t.sbt_err(&["policy", "ls", "nosuch-sandbox"]),
        "sandbox 'nosuch-sandbox' not found\n  try: bento ls"
    );
    assert_eq!(t.stdout(), "");
}

#[test]
fn ls_filters() {
    let mut t = test_env(&[]);
    let [allow, deny, scoped] = checked_policy(&t);
    let (allow, deny, scoped) = (allow.as_str(), deny.as_str(), scoped.as_str());
    let mut ids = |args: &[&str]| -> Vec<String> {
        let args: Vec<&str> = args.iter().chain(&["-q"]).copied().collect();
        ls(&mut t, &args).lines().map(String::from).collect()
    };
    assert_eq!(ids(&[]), [allow, deny, scoped, "default-deny-all"]);
    assert_eq!(ids(&["--decision", "deny"]), [deny, "default-deny-all"]);
    assert_eq!(ids(&["--decision", "allow"]), [allow, scoped]);
    // The fallback wasn't created by anything.
    assert_eq!(ids(&["--created-via", "added"]), [allow, deny, scoped]);
    assert!(ids(&["--created-via", "default"]).is_empty());
    assert!(ids(&["--created-via", "provisioned"]).is_empty());
    assert!(ids(&["--created-via", "approval"]).is_empty());
    // As in sbx, a deny rule covers both protocols, an allow rule tcp.
    assert_eq!(ids(&["--protocol", "udp"]), [deny, "default-deny-all"]);
    assert_eq!(ids(&["--protocol", "tcp"]).len(), 4);
    assert_eq!(ids(&["--type", "all"]).len(), 4);
    assert_eq!(ids(&["--type", "network"]).len(), 4);
    assert!(ids(&["--type", "http"]).is_empty());
    assert!(ids(&["--type", "filesystem"]).is_empty());
    assert_eq!(ids(&["--source", "local"]).len(), 4);
    assert!(ids(&["--source", "org"]).is_empty());
    // smolbento has no inactive rules: the flag changes nothing.
    assert_eq!(ids(&["--include-inactive"]).len(), 4);

    // sbx's tables for these (its `--created-via added` and `--decision deny`).
    assert_eq!(
        ls(&mut t, &["--created-via", "added"]),
        "\
POLICY            SOURCE   APPLIES TO        SUMMARY
local-policy      local    all               network: 1 allow, 1 deny
sandbox:chk-pol   local    sandbox:chk-pol   network: 1 allow
"
    );
    assert_eq!(
        ls(&mut t, &["--decision", "deny"]),
        "\
POLICY             SOURCE   APPLIES TO   SUMMARY
default-deny-all   local    all          network: deny when no rule decides
local-policy       local    all          network: 1 deny
"
    );
    for args in [
        &["--type", "filesystem"][..],
        &["--source", "kit"],
        &["--source", "kit", "--wide"],
        &["--source", "org", "chk-pol"],
        &["--created-via", "default"],
    ] {
        assert_eq!(ls(&mut t, args), NO_MATCH, "{args:?}");
    }
}

#[test]
fn ls_refuses_bad_filter_values_in_sbx_s_words() {
    let mut t = test_env(&[]);
    for (flag, message) in [
        (
            "--type",
            "invalid type \"bogus\": must be one of: all, network, http, filesystem",
        ),
        (
            "--created-via",
            "invalid creation method \"bogus\": must be one of: default, added, provisioned, approval",
        ),
        (
            "--protocol",
            "invalid protocol \"bogus\": must be tcp or udp",
        ),
    ] {
        assert_eq!(
            t.sbt_err(&["policy", "ls", flag, "bogus"]),
            format!(
                "invalid argument \"bogus\" for \"{flag}\" flag: {message}\n  try: bento policy ls --help"
            )
        );
    }
    assert!(t.sbt(&["policy", "ls", "--decision", "maybe"]).is_err());
    let err = t.sbt_err(&["policy", "ls", "--source", "nope"]);
    assert!(err.contains("local, org, kit or mcp"), "{err}");
    // No governance profiles.
    let err = t.sbt(&["policy", "ls", "--profile", "strict"]).unwrap_err();
    assert_eq!(super::super::exit_code(&err), 2, "{err}");
    assert_eq!(t.stdout(), "");
}

#[test]
fn ls_shows_kit_rules_as_one_policy_per_sandbox() {
    use crate::kits::model::{NetRule, Rules};
    let mut t = test_env(&[]);
    let mut p = policy(Mode::DenyAll);
    add(&mut p, Some("my-sb"), Decision::Allow, "user.com", "added");
    let rules = |host: &str| Rules {
        allow: vec![NetRule::host(host)],
        deny: vec![],
    };
    p.add_kit_rules("my-sb", "gh", &rules("kit.com"), false)
        .unwrap();
    p.add_kit_rules("my-sb", "jq", &rules("jq.dev"), false)
        .unwrap();
    p.add_kit_rules("my-sb", "gh", &rules("pkg.kit.com"), true)
        .unwrap();
    let mcp = crate::policy::MCP_VIA;
    add(&mut p, Some("my-sb"), Decision::Allow, "mcp.dev", mcp);
    p.save(&t.ctx.paths).unwrap();
    t.sandbox("my-sb", "running", &[]);
    // One aggregated rule per sandbox, like sbx: runtime hosts only (install-phase hosts are
    // not listed).
    assert_eq!(
        ls(&mut t, &["--source", "kit"]),
        "\
POLICY      SOURCE   APPLIES TO      SUMMARY
kit:my-sb   kit      sandbox:my-sb   network: 2 allow
"
    );
    let id = crate::policy::kit_rule_id("my-sb");
    // sbx 0.49.2's row for a kit rule: the rule is named `kit:<sandbox>`.
    let head = "SOURCE   CREATED VIA   APPLIES TO      POLICY   POLICY_ID   RULE        RULE_ID      TYPE      METHOD   PATH   DECISION   PROTOCOLS   RESOURCES";
    assert_eq!(
        ls(&mut t, &["my-sb", "--source", "kit", "--wide"]),
        format!(
            "{head}\n\
kit      provisioned   sandbox:my-sb   -        kit:my-sb   kit:my-sb   {id}   network   -        -      allow      tcp         jq.dev\n\
{}\n",
            under(
                head,
                &[("METHOD", "-"), ("PATH", "-"), ("RESOURCES", "kit.com")]
            )
        )
    );
    let json = ls(&mut t, &["my-sb", "--source", "kit", "--json"]);
    let json: serde_json::Value = serde_json::from_str(&json).unwrap();
    let rows = json["rules"].as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["id"], id.as_str());
    assert_eq!(rows[0]["name"], "kit:my-sb");
    assert_eq!(rows[0]["policy_id"], "kit:my-sb");
    assert_eq!(rows[0]["layer"], "kit");
    assert_eq!(rows[0]["origin"], "scoped");
    assert_eq!(rows[0]["applies_to"], "sandbox:my-sb");
    assert_eq!(rows[0]["sandbox_id"], "my-sb");
    assert_eq!(rows[0]["editable"], false);
    assert_eq!(rows[0]["provenance"]["created_via"], "provisioned");
    assert_eq!(
        rows[0]["resources"],
        serde_json::json!(["kit.com", "jq.dev"])
    );
    assert_eq!(
        ls(&mut t, &["--source", "local"]),
        "\
POLICY             SOURCE   APPLIES TO      SUMMARY
default-deny-all   local    all             network: deny when no rule decides
sandbox:my-sb      local    sandbox:my-sb   network: 1 allow
"
    );
    // smolbento's own source for a `--static-mcp` server's host.
    assert_eq!(
        ls(&mut t, &["--source", "mcp"]),
        "\
POLICY      SOURCE   APPLIES TO      SUMMARY
mcp:my-sb   mcp      sandbox:my-sb   network: 1 allow
"
    );
    assert_eq!(
        ls(&mut t, &["--created-via", "provisioned", "-q"])
            .lines()
            .count(),
        2
    );
    assert_eq!(
        ls(&mut t, &["my-sb"]),
        "  Policy for sandbox:  my-sb

NETWORK
  • allow 4 hosts from kit:my-sb, mcp:my-sb, sandbox:my-sb
  • fallback: deny when no rule decides from default-deny-all

"
    );
}

/// A `balanced` policy with a plain allow, then the two rules smolvm enforces more loosely than
/// sbx would: a global deny with a port, and for sandbox `s1` an allow with a widened wildcard, a
/// method and a path. Returns that last rule's id.
fn loose_policy(p: &mut Policy) -> String {
    add(p, None, Decision::Deny, "b.com:8080", "added");
    p.add_rule(
        Some("s1"),
        Decision::Allow,
        "crl*.x.com",
        "added",
        Some("get".into()),
        Some("/v1/**".into()),
    )
    .unwrap()
}

#[test]
fn ls_note_counts_the_listed_rules_that_arent_fully_enforced() {
    let mut p = policy(Mode::Balanced);
    add(&mut p, None, Decision::Allow, "a.com", "added");
    let note = |p: &Policy, a: PolicyLsArgs| ls_note(&filtered(ls_rules(p, None), &a));
    assert_eq!(
        note(&p, PolicyLsArgs::default()),
        None,
        "the preset and the fallback have no notes"
    );
    loose_policy(&mut p);
    assert_eq!(
        note(&p, PolicyLsArgs::default()).as_deref(),
        Some("note: 2 rule(s) aren't fully enforced; see `bento policy ls --wide`")
    );
    let allows = || PolicyLsArgs {
        decision: Some(Decision::Allow),
        ..Default::default()
    };
    assert_eq!(
        note(&p, allows()).as_deref(),
        Some("note: 1 rule(s) aren't fully enforced; see `bento policy ls --wide`")
    );
    assert_eq!(
        note(
            &p,
            PolicyLsArgs {
                source: Some("kit".into()),
                ..allows()
            }
        ),
        None
    );
}

#[test]
fn ls_shows_what_isnt_enforced_as_the_status_reason() {
    let mut t = test_env(&[]);
    let mut p = policy(Mode::Balanced);
    add(&mut p, None, Decision::Allow, "a.com", "added");
    let http = loose_policy(&mut p);
    p.save(&t.ctx.paths).unwrap();
    // A rule with a method or a path is sbx's `http` type.
    assert_eq!(ls(&mut t, &["--type", "http", "-q"]), format!("{http}\n"));
    assert_eq!(
        ls(&mut t, &["--type", "http"]),
        "\
POLICY       SOURCE   APPLIES TO   SUMMARY
sandbox:s1   local    sandbox:s1   http: 1 allow
"
    );
    let head = "SOURCE   CREATED VIA   APPLIES TO   POLICY   POLICY_ID    RULE   RULE_ID      TYPE   METHOD   PATH     DECISION   PROTOCOLS   STATUS                       RESOURCES";
    let status = |text| under(head, &[("STATUS", text), ("RESOURCES", "")]);
    assert_eq!(
        ls(&mut t, &["--type", "http", "--wide"]),
        format!(
            "{head}\n\
local    added         sandbox:s1   -        sandbox:s1   -      {http}   http   GET      /v1/**   allow      tcp         active — crl*.x.com:         crl*.x.com\n\
{}\n{}\n{}\n",
            status("widened to *.x.com; method"),
            status("GET, path /v1/** enforced"),
            status("for hosted sandboxes"),
        )
    );
    let json = ls(&mut t, &["--decision", "deny", "--json"]);
    let json: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(json["rules"][0]["resources"][0], "b.com:8080");
    assert!(
        json["rules"][0]["reason"]
            .as_str()
            .unwrap()
            .starts_with("b.com:8080: port 8080 not enforced"),
        "{json}"
    );
    assert_eq!(
        json["rules"][0]["actions"],
        serde_json::json!(["net:connect:tcp", "net:connect:udp"])
    );
}

#[test]
fn ls_says_each_kit_rule_note_once() {
    use crate::kits::model::{NetRule, Rules};
    let mut t = test_env(&[]);
    let mut p = policy(Mode::DenyAll);
    // Two kits allow the same host and port, and one entry has two paths (a stored rule each).
    let rules = Rules {
        allow: vec![
            NetRule::host("kit.com:8080"),
            NetRule {
                host: "api.dev".into(),
                methods: vec!["GET".into()],
                paths: vec!["/a".into(), "/b".into()],
            },
        ],
        deny: vec![],
    };
    p.add_kit_rules("my-sb", "gh", &rules, false).unwrap();
    p.add_kit_rules("my-sb", "jq", &rules, false).unwrap();
    p.save(&t.ctx.paths).unwrap();
    let json = ls(&mut t, &["--source", "kit", "--json"]);
    let json: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(
        json["rules"][0]["resources"],
        serde_json::json!(["kit.com:8080", "api.dev"])
    );
    assert_eq!(
        json["rules"][0]["reason"],
        "kit.com:8080: port 8080 not enforced by smolvm (all ports allowed; enforced for hosted \
         sandboxes); method GET, path /a enforced for hosted sandboxes; \
         method GET, path /b enforced for hosted sandboxes"
    );
}

#[test]
fn ls_shows_a_sandbox_s_kit_deny_rules_as_a_second_kit_rule() {
    use crate::kits::model::{NetRule, Rules};
    let mut t = test_env(&[]);
    let mut p = policy(Mode::DenyAll);
    let rules = |allow: &str, deny: &str| Rules {
        allow: vec![NetRule::host(allow)],
        deny: vec![NetRule::host(deny)],
    };
    p.add_kit_rules("my-sb", "gh", &rules("kit.com", "ads.kit.com"), false)
        .unwrap();
    p.add_kit_rules("my-sb", "jq", &rules("jq.dev", "ads.jq.dev"), false)
        .unwrap();
    p.save(&t.ctx.paths).unwrap();
    let allow = crate::policy::kit_rule_id("my-sb");
    let deny = crate::policy::kit_rule_id("my-sb|deny");
    assert_ne!(allow, deny);
    assert_eq!(
        ls(&mut t, &["--source", "kit", "-q"]),
        format!("{allow}\n{deny}\n")
    );
    assert_eq!(
        ls(&mut t, &["--source", "kit", "--decision", "deny", "-q"]),
        format!("{deny}\n")
    );
    // Both rules are in the one `kit:<sandbox>` policy.
    assert_eq!(
        ls(&mut t, &["--source", "kit"]),
        "\
POLICY      SOURCE   APPLIES TO      SUMMARY
kit:my-sb   kit      sandbox:my-sb   network: 2 allow, 2 deny
"
    );
    let json = ls(&mut t, &["--source", "kit", "--decision", "deny", "--json"]);
    let json: serde_json::Value = serde_json::from_str(&json).unwrap();
    let rows = json["rules"].as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["id"], deny.as_str());
    assert_eq!(rows[0]["name"], "kit:my-sb");
    assert_eq!(rows[0]["policy_id"], "kit:my-sb");
    assert_eq!(rows[0]["decision"], "deny");
    assert_eq!(rows[0]["editable"], false);
    assert_eq!(
        rows[0]["resources"],
        serde_json::json!(["ads.kit.com", "ads.jq.dev"])
    );
    assert_eq!(
        rows[0]["actions"],
        serde_json::json!(["net:connect:tcp", "net:connect:udp"])
    );
}

/// `policy check network` target and resource, as sbx 0.54 prints them.
fn checked(t: &mut TestEnv, target: &str) -> serde_json::Value {
    t.sbt(&["policy", "check", "network", "--json", target])
        .ok();
    serde_json::from_str(&t.stdout()).unwrap()
}

#[test]
fn check_reads_urls_as_sbx_does() {
    let mut t = test_env(&[]);
    set_policy(&t, "mode = \"deny-all\"");
    for (given, target, resource) in [
        (
            "https://Example.COM/path",
            "example.com:443",
            "example.com:443",
        ),
        ("http://example.com", "example.com:80", "example.com:80"),
        (
            "http://example.com:8080/x",
            "example.com:8080",
            "example.com:8080",
        ),
        ("https://[::1]/", "[::1]:443", "::1:443"),
        ("[::1]:80", "[::1]:80", "::1:80"),
        ("host.docker.internal", "localhost:443", "localhost:443"),
    ] {
        let v = checked(&mut t, given);
        assert_eq!(
            (v["target"].as_str(), v["resource_value"].as_str()),
            (Some(target), Some(resource)),
            "{given}"
        );
    }
    for (given, want) in [
        (
            "ftp://example.com",
            "target URL scheme \"ftp\" must include an explicit port",
        ),
        (
            "example.com/path",
            "target must be a host, host:port, IP literal, or URL with a port",
        ),
    ] {
        let e = t.sbt(&["policy", "check", "network", given]).unwrap_err();
        assert_eq!(e.to_string(), want, "{given}");
    }
}

/// Every sandbox without host access is created with the host's loopback denied
/// (`compile::HOST_LOOPBACK`), whatever the mode; the check says so.
#[test]
fn check_denies_the_hosts_loopback_without_host_access() {
    let mut t = test_env(&[]);
    set_policy(&t, "mode = \"allow-all\"");
    for target in [
        "localhost",
        "127.0.0.1:8080",
        "[::1]:80",
        "100.96.0.1",
        "host.docker.internal",
    ] {
        let v = checked(&mut t, target);
        assert_eq!(v["allowed"], false, "{target}: {v}");
        assert_eq!(v["deny_kind"], "implicit", "{target}");
        assert_eq!(
            v["reason"],
            "The host's loopback is closed to sandboxes created without a localhost allow rule",
            "{target}"
        );
    }
    assert_eq!(checked(&mut t, "example.com")["allowed"], true);

    // A sandbox's own record decides: created with host access, it has it.
    t.sandboxes(&[
        ("open", "running", &[("sbx.host-access", "true")]),
        ("shut", "running", &[]),
    ]);
    let v = |t: &mut TestEnv, sb: &str| {
        t.sbt(&[
            "policy",
            "check",
            "network",
            "--json",
            "--sandbox",
            sb,
            "localhost",
        ])
        .ok();
        serde_json::from_str::<serde_json::Value>(&t.stdout()).unwrap()["allowed"].clone()
    };
    assert_eq!(v(&mut t, "open"), true);
    assert_eq!(v(&mut t, "shut"), false);
}

#[test]
fn policy_allow_takes_query() {
    let mut t = test_env(&[]);
    set_policy(&t, "mode = \"deny-all\"");
    t.sbt(&[
        "policy",
        "allow",
        "network",
        "a.com",
        "--method",
        "GET",
        "--query",
        "v=1.*",
        "--query",
        "tag=prod,x=*",
    ])
    .unwrap();
    let p = Policy::load(&t.ctx.paths).unwrap();
    let r = &p.rules[0];
    assert_eq!(r.query.as_deref(), Some("tag=prod,v=1.*,x=*"));
    assert_eq!(t.stdout(), format!("allow rule {}: a.com\n", r.id));
    // The query is part of the rule: another query is another rule.
    t.sbt(&[
        "policy", "allow", "network", "a.com", "--method", "GET", "--query", "y=*",
    ])
    .unwrap();
    assert_eq!(Policy::load(&t.ctx.paths).unwrap().rules.len(), 2);
    // `policy rm --query` matches the stored query.
    let rm = [
        "policy",
        "rm",
        "network",
        "--resource",
        "a.com",
        "-f",
        "--query",
    ];
    t.sbt(&[&rm[..], &["x=*,v=1.*,tag=prod"]].concat()).unwrap();
    let p = Policy::load(&t.ctx.paths).unwrap();
    assert_eq!(p.rules.len(), 1);
    assert_eq!(p.rules[0].query.as_deref(), Some("y=*"));

    for (args, want) in [
        (
            &["deny", "network", "**", "--method", "POST"][..],
            "request rules need a named host",
        ),
        (
            &["allow", "network", "10.0.0.1", "--path", "/a"],
            "request rules need a named host",
        ),
        (
            &["allow", "network", "crl*.x.com", "--method", "GET"],
            "host glob",
        ),
        (
            &["allow", "network", "a.com", "--query", "a*b"],
            "--query 'a*b'",
        ),
        (
            &["allow", "network", "a.com", "--path", "/a/../b"],
            "--path",
        ),
    ] {
        let err = t.sbt(&[&["policy"][..], args].concat()).unwrap_err();
        assert!(err.to_string().contains(want), "{args:?}: {err}");
    }
    // A glob deny widens rather than fails.
    t.sbt(&[
        "policy",
        "deny",
        "network",
        "crl*.x.com",
        "--method",
        "POST",
    ])
    .unwrap();
    assert_eq!(Policy::load(&t.ctx.paths).unwrap().rules.len(), 2);
}

#[test]
fn ls_says_where_request_rules_are_enforced() {
    let mut t = test_env(&[]);
    set_policy(&t, "mode = \"deny-all\"");
    t.sbt(&[
        "policy", "allow", "network", "api.dev", "--method", "GET", "--query", "v=1",
    ])
    .unwrap();
    t.stdout();
    let json = ls(&mut t, &["--type", "http", "--json"]);
    let json: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(
        json["rules"][0]["reason"],
        "method GET, query v=1 enforced for hosted sandboxes"
    );
}
