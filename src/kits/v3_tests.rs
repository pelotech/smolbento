use super::*;

fn fixture(name: &str) -> String {
    std::fs::read_to_string(format!("tests/fixtures/kits/v3/{name}")).unwrap()
}
fn local(name: &str) -> Source {
    Source::Local(name.into())
}

#[test]
fn parses_network_v2_phases() {
    let k = parse(&fixture("network-v2.yaml"), local("n")).unwrap();
    assert_eq!(k.kind, Kind::Mixin);
    assert_eq!(k.provides, ["net2@1.0.0"]);
    let CapBody::Network { install, runtime } = &k.caps[0].body else {
        panic!()
    };
    assert_eq!(install.allow[0].host, "registry.npmjs.org");
    assert_eq!(runtime.allow[0].methods, ["GET"]);
    assert_eq!(runtime.deny[0].host, "telemetry.example.com");
}

#[test]
fn unknown_types_parse_as_unsupported_keeping_optional() {
    let k = parse(&fixture("unknown-cap.yaml"), local("u")).unwrap();
    assert!(matches!(k.caps[0].body, CapBody::Unsupported));
    assert!(!k.caps[0].optional);
    assert!(k.caps[1].optional);
}

#[test]
fn unknown_config_keys_of_known_types_are_errors() {
    let e = parse(&fixture("bad-config-key.yaml"), local("b")).unwrap_err();
    assert!(format!("{e:#}").contains("sise"), "{e:#}");
}

#[test]
fn schema_version_must_be_3_and_set_is_refused_locally() {
    let e = parse("schemaVersion: \"2\"\nkind: mixin\n", local("x")).unwrap_err();
    assert!(format!("{e:#}").contains("schemaVersion"));
    let e = parse("schemaVersion: \"3\"\nkind: set\n", local("x")).unwrap_err();
    assert!(format!("{e:#}").contains("publish"), "{e:#}");
}

#[test]
fn an_unknown_kind_is_an_error() {
    let e = parse("schemaVersion: \"3\"\nkind: plugin\n", local("x")).unwrap_err();
    assert_eq!(format!("{e:#}"), "unknown kind 'plugin'");
}

#[test]
fn a_capability_without_a_type_is_an_error_naming_its_index() {
    for ty in [r#""#, r#""type":"","#] {
        let e = parse(
            &format!(
                r#"{{"schemaVersion":"3","kind":"mixin","capabilities":[
                        {{"type":"com.docker.sandbox/sbx@1"}},{{{ty}"optional":true}}]}}"#
            ),
            local("t"),
        )
        .unwrap_err();
        assert_eq!(format!("{e:#}"), "capabilities[1] has no type");
    }
}

#[test]
fn unquoted_numbers_and_bools_in_default_and_enum_become_strings() {
    let k = parse(
            "schemaVersion: \"3\"\nkind: mixin\nargs:\n  a:\n    default: 5\n    enum: [5, 6, true, 1.5, x]\n  b:\n    default: false\n",
            local("x"),
        )
        .unwrap();
    assert_eq!(k.args["a"].default.as_deref(), Some("5"));
    assert_eq!(k.args["a"].enum_values, ["5", "6", "true", "1.5", "x"]);
    assert_eq!(k.args["b"].default.as_deref(), Some("false"));
}

#[test]
fn an_empty_hook_command_is_an_error() {
    for (hook, want) in [
        (
            r#"{"command":[]}"#,
            "kit k: install hook 1 has an empty command",
        ),
        (
            r#"{"command":"  "}"#,
            "kit k: install hook 1 has an empty command",
        ),
    ] {
        let e = parse(
                &format!(
                    r#"{{"schemaVersion":"3","kind":"mixin","capabilities":[{{"type":"com.docker.sandbox/lifecycle@1","config":{{"install":[{hook}]}}}}]}}"#
                ),
                local("k"),
            )
            .unwrap_err();
        assert_eq!(format!("{e:#}"), want);
    }
    let e = parse(
            r#"{"schemaVersion":"3","kind":"mixin","capabilities":[{"type":"com.docker.sandbox/lifecycle@1","config":{"startup":[{"command":["a"]},{"command":""}]}}]}"#,
            local("k"),
        )
        .unwrap_err();
    assert_eq!(
        format!("{e:#}"),
        "kit k: startup hook 2 has an empty command"
    );
}

#[test]
fn unknown_arg_keys_are_ignored() {
    let k = parse(
        "schemaVersion: \"3\"\nkind: mixin\nargs:\n  a:\n    default: x\n    later: 1\n",
        local("x"),
    )
    .unwrap();
    assert_eq!(k.args["a"].default.as_deref(), Some("x"));
}

#[test]
fn a_port_of_zero_and_content_with_content_file_are_errors() {
    let e =
        one_cap(r#"{"type":"com.docker.sandbox/port@1","config":{"container":0}}"#).unwrap_err();
    assert!(
        format!("{e:#}").contains("container must be 1..65535"),
        "{e:#}"
    );
    let e = one_cap(
        r#"{"type":"com.docker.sandbox/agent-context@1",
                "config":{"content":"x","contentFile":"/k/x.md"}}"#,
    )
    .unwrap_err();
    assert!(
        format!("{e:#}").contains("content and contentFile are mutually exclusive"),
        "{e:#}"
    );
}

/// tck: agent-skills@1/off-default-honored (an omitted mode is `off`)
#[test]
fn agent_skills_caps() {
    use crate::skills::Mode;
    use serde_json::json;
    let b = |ty: &str, c: serde_json::Value| body(&format!("com.docker.sandbox/{ty}"), Some(c));
    assert_eq!(
        b(
            "agent-skills@1",
            json!({"path": "/home/agent/.claude/skills"})
        )
        .unwrap(),
        CapBody::AgentSkills {
            path: "/home/agent/.claude/skills".into(),
            mode: Mode::Off
        }
    );
    for (given, mode) in [
        ("off", Mode::Off),
        ("readonly", Mode::Readonly),
        ("readwrite", Mode::Readwrite),
    ] {
        assert_eq!(
            b("agent-skills@1", json!({"path": "/s", "mode": given})).unwrap(),
            CapBody::AgentSkills {
                path: "/s".into(),
                mode
            }
        );
    }
    for bad in [
        json!({"path": "s"}),
        json!({"path": "/s/"}),
        json!({"path": "/a/../s"}),
        json!({"path": "/"}),
        json!({"path": "/s", "mode": "rw"}),
        json!({}),
        json!({"path": "/run/sbx/skills-shared"}),
        json!({"path": "/run/sbx/skills-shared/x"}),
        json!({"path": "/home/a:b/skills"}),
    ] {
        assert!(b("agent-skills@1", bad.clone()).is_err(), "{bad}");
    }
    assert!(b("agent-skills@1", json!({"path": "/run/sbx/skills-shared2"})).is_ok());
    assert_eq!(
        b("agent-skill@1", json!({"path": "/usr/share/x/pr-review"})).unwrap(),
        CapBody::AgentSkill {
            source: "/usr/share/x/pr-review".into(),
            name: "pr-review".into()
        }
    );
    assert_eq!(
        b(
            "agent-skill@1",
            json!({"path": "/x/y", "name": "review-pr"})
        )
        .unwrap(),
        CapBody::AgentSkill {
            source: "/x/y".into(),
            name: "review-pr".into()
        }
    );
    for bad in [
        json!({"path": "/x/y", "name": ""}),
        json!({"path": "/x/y", "name": "a/b"}),
        json!({"path": "/x/${A}"}),
        json!({"path": "x"}),
        json!({"path": "/x/a:b", "name": "ab"}),
    ] {
        assert!(b("agent-skill@1", bad.clone()).is_err(), "{bad}");
    }
}

fn host_mount(config: &str) -> Result<CapBody> {
    let k = one_cap(&format!(
        r#"{{"type":"com.docker.sandbox/host-mount@1","config":{config}}}"#
    ))?;
    Ok(k.caps[0].body.clone())
}

#[test]
fn host_mount_parses_path_and_mode() {
    assert_eq!(
        host_mount(r#"{"path":"/home/agent/.cache/x"}"#).unwrap(),
        CapBody::HostMount {
            path: "/home/agent/.cache/x".into(),
            mode: None
        }
    );
    for mode in ["755", "0755", "1777"] {
        let body = host_mount(&format!(r#"{{"path":"/data","mode":"{mode}"}}"#)).unwrap();
        assert_eq!(
            body,
            CapBody::HostMount {
                path: "/data".into(),
                mode: Some(mode.into())
            }
        );
    }
}

#[test]
fn host_mount_refuses_paths_that_are_not_absolute_and_canonical() {
    for path in [
        "data",
        "",
        "/",
        "/data/",
        "/a//b",
        "/a/./b",
        "/a/../b",
        "/a/.",
        "/..",
        "/a\\u0000b",
    ] {
        let e = host_mount(&format!(r#"{{"path":"{path}"}}"#)).unwrap_err();
        let path = path.replace("\\u0000", "\0");
        assert_eq!(
            e.root_cause().to_string(),
            format!("host-mount@1 path {path:?} must be absolute and canonical")
        );
    }
}

#[test]
fn host_mount_refuses_a_mode_that_is_not_octal_and_unknown_keys() {
    for mode in ["", "75", "07555", "0789", "rwx", "+755"] {
        let e = host_mount(&format!(r#"{{"path":"/data","mode":"{mode}"}}"#)).unwrap_err();
        assert_eq!(
            e.root_cause().to_string(),
            format!("host-mount@1 mode {mode:?} must be octal")
        );
    }
    let e = host_mount(r#"{"path":"/data","size":"1G"}"#).unwrap_err();
    assert!(format!("{e:#}").contains("unknown field `size`"), "{e:#}");
}

#[test]
fn version_is_the_fallback_for_unversioned_provides_and_a_tag_beats_it() {
    let d = r#"{"schemaVersion":"3","kind":"mixin","version":"1.2.0","provides":["x","y@3"]}"#;
    let k = parse(d, local("k")).unwrap();
    assert_eq!(k.provides, ["x@1.2.0", "y@3"]);
    let k = parse(d, Source::Registry("docker.io/acme/k:v2.0.1".into())).unwrap();
    assert_eq!(k.provides, ["x@2.0.1", "y@3"]);
    // Not a version-shaped tag: the descriptor's version stays.
    let k = parse(d, Source::Registry("acme/k:latest@sha256:00".into())).unwrap();
    assert_eq!(k.provides[0], "x@1.2.0");
    // A kit without versions is still read (sbx's published `github-ssh` has one); it satisfies
    // only unconstrained requires.
    let k = parse(
        r#"{"schemaVersion":"3","kind":"mixin","provides":["x"]}"#,
        Source::Registry("acme/k".into()),
    )
    .unwrap();
    assert_eq!(k.provides, ["x"]);
}

#[test]
fn capability_entries_follow_the_spec_grammar() {
    let bad = |field: &str, entry: &str| {
        let d = format!(r#"{{"schemaVersion":"3","kind":"mixin","{field}":["{entry}"]}}"#);
        format!("{:#}", parse(&d, local("k")).unwrap_err())
    };
    assert_eq!(
        bad("provides", "Gh@1"),
        "provides[0]: provides entry \"Gh@1\": invalid capability name \"Gh\""
    );
    assert_eq!(
        bad("provides", "gh@v1"),
        "provides[0]: provides entry \"gh@v1\": invalid version \"v1\""
    );
    assert_eq!(
        bad("requires", "node >= 2, < 1"),
        "requires[0]: requires entry \"node >= 2, < 1\": unsatisfiable constraints: >= 2 and < 1"
    );
    assert_eq!(
        bad("requires", "x >= ${{ kit.args.v }}"),
        "requires[0]: requires entry \"x >= ${{ kit.args.v }}\": arg references are not \
             allowed in requires"
    );
    assert_eq!(
        bad("integrates", "x ~ 1"),
        "integrates[0]: requires entry \"x ~ 1\": invalid capability name \"x ~ 1\""
    );
    assert_eq!(
        bad("conflicts", "x@1"),
        "conflicts[0]: conflicts entry \"x@1\": invalid capability name \"x@1\""
    );
    assert_eq!(
        bad("provides", "example/x@1"),
        "provides[0]: provides entry \"example/x@1\": namespace \"example\" in \"example/x\" is a \
             single label, which this specification reserves; a namespace of your own is \
             reverse-DNS, as in com.example/x"
    );
    let e = parse(
        r#"{"schemaVersion":"3","kind":"mixin","version":"v1"}"#,
        local("k"),
    )
    .unwrap_err();
    assert_eq!(format!("{e:#}"), "version: invalid version \"v1\"");
}

#[test]
fn sandbox_is_the_old_spelling_of_workload() {
    let k = parse(
        r#"{"schemaVersion":"3","kind":"sandbox"}"#,
        Source::Registry("r/k:1".into()),
    )
    .unwrap();
    assert_eq!(k.kind, Kind::Workload);
}

#[test]
fn claude_mixin_capabilities_decode() {
    let k = parse(&fixture("claude-mixin.yaml"), local("c")).unwrap();
    assert_eq!(k.name, "c");
    assert_eq!(k.provides, ["claude@2.1.311"]);
    assert_eq!(k.args["version"].default.as_deref(), Some("2.1.311"));
    assert_eq!(k.args["reasoningEffort"].enum_values.len(), 7);
    assert_eq!(k.args["model"].env.as_deref(), Some("CLAUDE_MODEL"));

    let cred = k
        .caps
        .iter()
        .find_map(|c| match &c.body {
            CapBody::Credential(c) => Some(c.clone()),
            _ => None,
        })
        .unwrap();
    assert_eq!(cred.service, "anthropic");
    assert!(cred.runtime && !cred.install);
    assert_eq!(cred.env.as_deref(), Some("ANTHROPIC_API_KEY"));
    assert_eq!(cred.inject[0].header.as_deref(), Some("x-api-key"));
    let oauth = cred.oauth.unwrap();
    assert_eq!(oauth.token_host.as_deref(), Some("platform.claude.com"));
    assert!(!oauth.passthrough);

    let vols = k
        .caps
        .iter()
        .filter(|c| matches!(c.body, CapBody::Volume { .. }))
        .count();
    assert_eq!(vols, 5);

    let CapBody::Lifecycle(l) = &k
        .caps
        .iter()
        .find(|c| c.ty.ends_with("lifecycle@1"))
        .unwrap()
        .body
    else {
        panic!()
    };
    assert_eq!(l.install.len(), 4);
    assert_eq!(l.install[0].user.as_deref(), Some("0"));
    assert_eq!(l.install[0].env, ["WORKSPACE_DIR"]);
    assert!(matches!(l.install[0].command, HookCmd::Shell(_)));
    assert!(matches!(l.startup[0].command, HookCmd::Argv(_)));
    // Only install hooks get sbx's clean environment, set when they're merged.
    let p = crate::kits::resolve::resolve(
        Kit::new("w", Kind::Workload, Source::Local("w".into())),
        vec![k.clone()],
        &crate::kits::args::ArgValues::default(),
    )
    .unwrap();
    assert!(p.merged.install_hooks.iter().all(|(_, h)| h.clean_env));
    assert!(p.merged.startup_hooks.iter().all(|(_, h)| !h.clean_env));

    let skills = k
        .caps
        .iter()
        .find(|c| c.ty.ends_with("agent-skills@1"))
        .unwrap();
    assert!(matches!(skills.body, CapBody::AgentSkills { .. }) && skills.optional);

    let ctx: Vec<_> = k
        .caps
        .iter()
        .filter_map(|c| match &c.body {
            CapBody::AgentContext(a) => Some(a),
            _ => None,
        })
        .collect();
    // sbx publishes the guide as agent-context@1 and @2 alike. Both stay: the sandbox's kits
    // together settle which one is applied.
    assert_eq!(ctx.len(), 2);
    for version in ["agent-context@1", "agent-context@2"] {
        assert!(k.caps.iter().any(|c| c.ty.ends_with(version) && c.optional));
    }
    for c in ctx {
        assert_eq!(c.filename.as_deref(), Some("CLAUDE.md"));
        assert_eq!(c.directory.as_deref(), Some("/home/agent/.claude"));
        assert!(c.content.starts_with("Claude Code is installed"));
    }
}

#[test]
fn shell_workload_parses() {
    let k = parse(&fixture("shell-workload.yaml"), local("s")).unwrap();
    assert_eq!(k.kind, Kind::Workload);
    assert!(matches!(k.caps[0].body, CapBody::Sbx));
    let CapBody::Network { install, runtime } = &k.caps[1].body else {
        panic!()
    };
    assert!(install.allow.is_empty());
    assert_eq!(runtime.allow[1].host, "dhi.io");
}

#[test]
fn network_v1_entries_are_plain_hosts_and_may_carry_ports() {
    let k = parse(
        r#"{"schemaVersion":"3","kind":"mixin","capabilities":[
                {"type":"com.docker.sandbox/network-policy@1",
                 "config":{"runtime":{"allow":["a.com:443"],"deny":["b.com"]}}}]}"#,
        local("n"),
    )
    .unwrap();
    let CapBody::Network { runtime, .. } = &k.caps[0].body else {
        panic!()
    };
    assert_eq!(runtime.allow[0].host, "a.com:443");
    assert!(runtime.allow[0].methods.is_empty());
    assert_eq!(runtime.deny[0].host, "b.com");
}

#[test]
fn network_v2_entry_fans_out_per_host() {
    let k = parse(
        r#"{"schemaVersion":"3","kind":"mixin","capabilities":[
                {"type":"com.docker.sandbox/network-policy@2",
                 "config":{"runtime":{"allow":[{"hosts":["a","b"],"methods":["GET"]}]}}}]}"#,
        local("n"),
    )
    .unwrap();
    let CapBody::Network { runtime, .. } = &k.caps[0].body else {
        panic!()
    };
    assert_eq!(runtime.allow.len(), 2);
    assert_eq!(runtime.allow[1].host, "b");
    assert_eq!(runtime.allow[1].methods, ["GET"]);
}

#[test]
fn network_v2_takes_host_strings_and_star() {
    // SPEC network-policy@2: an entry is a host string or an object; `*` is everything, as `**`.
    let k = one_cap(
        r#"{"type":"com.docker.sandbox/network-policy@2","config":{
            "install":{"allow":["registry.npmjs.org"]},
            "runtime":{"allow":["github.com","*",{"hosts":["api.github.com"],"methods":["GET"],
                                                 "paths":["/repos/**"]}],
                       "deny":[{"hosts":["*.example.com"],"methods":["DELETE"]}]}}}"#,
    )
    .unwrap();
    let CapBody::Network { install, runtime } = &k.caps[0].body else {
        panic!()
    };
    assert_eq!(install.allow, [NetRule::host("registry.npmjs.org")]);
    let hosts: Vec<&str> = runtime.allow.iter().map(|r| r.host.as_str()).collect();
    assert_eq!(hosts, ["github.com", "**", "api.github.com"]);
    assert!(runtime.allow[0].methods.is_empty() && runtime.allow[0].paths.is_empty());
    assert_eq!(runtime.allow[2].paths, ["/repos/**"]);
    // A deny can name a pattern however it's bounded.
    assert_eq!(runtime.deny[0].host, "*.example.com");

    // network-policy@1 takes `*` too.
    let k = one_cap(
        r#"{"type":"com.docker.sandbox/network-policy@1","config":{"runtime":{"allow":["*"]}}}"#,
    )
    .unwrap();
    let CapBody::Network { runtime, .. } = &k.caps[0].body else {
        panic!()
    };
    assert_eq!(runtime.allow, [NetRule::host("**")]);
}

#[test]
fn network_v2_entries_are_checked_as_the_spec_says() {
    let entry = |e: &str| {
        let cap = format!(
            r#"{{"type":"com.docker.sandbox/network-policy@2","config":{{"runtime":{{"allow":[{e}]}}}}}}"#
        );
        format!("{:#}", one_cap(&cap).unwrap_err())
    };
    let at = "capability com.docker.sandbox/network-policy@2: runtime allow entry 0";
    for (e, why) in [
        // SPEC: an empty list would read as "every method".
        (
            r#"{"hosts":["a"],"methods":[]}"#,
            "an empty methods list grants nothing; omit it, or name the methods",
        ),
        (
            r#"{"hosts":["a"],"methods":["GET"],"paths":[]}"#,
            "an empty paths list grants nothing; omit it, or name the paths",
        ),
        (
            r#"{"hosts":["a"],"paths":["/x"]}"#,
            "paths need methods; name them, or use methods: [ANY]",
        ),
        (
            r#"{"hosts":[],"methods":["GET"]}"#,
            "hosts must name at least one host, none empty",
        ),
        (
            r#"{"methods":["GET"]}"#,
            "hosts must name at least one host, none empty",
        ),
        (
            r#"{"hosts":["a"],"methods":["get"]}"#,
            "method \"get\" is not an uppercase HTTP method or ANY",
        ),
        (
            r#"{"hosts":["a"],"methods":["GET","GET"]}"#,
            "method \"GET\" is listed twice",
        ),
        (
            r#"{"hosts":["a"],"methods":["ANY","GET"]}"#,
            "ANY covers every method; list it alone",
        ),
        (
            r#"{"hosts":["a"],"methods":["GET"],"paths":["x"]}"#,
            "path \"x\" must start with /",
        ),
        // SPEC network-policy@2/bounded-allow-hosts-literal.
        (
            r#"{"hosts":["*.a.com"],"methods":["GET"]}"#,
            "a bounded allow entry names its hosts exactly, not \"*.a.com\"",
        ),
        ("\"\"", "hosts must name at least one host, none empty"),
    ] {
        assert_eq!(entry(e), format!("{at}: {why}"), "{e}");
    }
    // An object keeps serde's own error, after the entry's name.
    let e = entry(r#"{"hosts":["a"],"verbs":["GET"]}"#);
    assert!(
        e.starts_with(at) && e.contains("unknown field `verbs`"),
        "{e}"
    );
    let e = entry("7");
    assert!(
        e.starts_with(at) && e.contains("invalid type: integer"),
        "{e}"
    );
    // `ANY` alone, and an unbounded object, are fine.
    for ok in [
        r#"{"hosts":["a"],"methods":["ANY"],"paths":["/v1/**"]}"#,
        r#"{"hosts":["*.a.com"]}"#,
    ] {
        let cap = format!(
            r#"{{"type":"com.docker.sandbox/network-policy@2","config":{{"runtime":{{"allow":[{ok}]}}}}}}"#
        );
        one_cap(&cap).unwrap();
    }
}

fn one_cap(json_cap: &str) -> Result<Kit> {
    parse(
        &format!(r#"{{"schemaVersion":"3","kind":"mixin","capabilities":[{json_cap}]}}"#),
        local("t"),
    )
}

/// SPEC-v3 §7.1: each declared version is its own request; none is dropped for a newer one.
#[test]
fn every_declared_version_of_a_capability_counts() {
    let caps = [
        r#"{"type":"com.docker.sandbox/agent-context@1","config":{"content":"old"}}"#,
        r#"{"type":"com.docker.sandbox/agent-context@2","config":{"content":"new"}}"#,
        r#"{"type":"com.docker.sandbox/agent-context@9","config":{"content":"future"}}"#,
        r#"{"type":"com.docker.sandbox/volume@1","config":{"path":"/a"}}"#,
        r#"{"type":"com.docker.sandbox/volume@1","config":{"path":"/b"}}"#,
    ]
    .join(",");
    let k = one_cap(&caps).unwrap();
    let types: Vec<&str> = k.caps.iter().map(|c| c.ty.as_str()).collect();
    assert_eq!(
        types,
        [
            "com.docker.sandbox/agent-context@1",
            "com.docker.sandbox/agent-context@2",
            "com.docker.sandbox/agent-context@9",
            "com.docker.sandbox/volume@1",
            "com.docker.sandbox/volume@1",
        ]
    );
    assert!(matches!(k.caps[2].body, CapBody::Unsupported));
}

/// SPEC-v3 §7.1: the two network-policy versions are exclusive; a descriptor states one, even
/// across a group.
#[test]
fn both_network_policy_versions_are_refused() {
    let np1 = r#"{"type":"com.docker.sandbox/network-policy@1","config":{}}"#;
    let np2 = r#"{"type":"com.docker.sandbox/network-policy@2","config":{}}"#;
    for caps in [
        format!("{np1},{np2}"),
        format!(r#"{np1},{{"group":{{"name":"g","capabilities":[{np2}]}}}}"#),
    ] {
        let e = one_cap(&caps).unwrap_err();
        assert!(
            format!("{e:#}").contains("network-policy@1 and network-policy@2 are exclusive"),
            "{e:#}"
        );
    }
}

/// tck: agent-context@2/delivery: `progressive` when omitted; `@1` bodies are progressive and
/// take no `delivery`. The accepted values: `resolve_tests`.
#[test]
fn agent_context_delivery() {
    use crate::kits::model::Delivery;
    let ctx = |ty: &str, extra: &str| {
        let c =
            format!(r#"{{"type":"com.docker.sandbox/{ty}","config":{{"content":"x"{extra}}}}}"#);
        one_cap(&c).map(|k| match &k.caps[0].body {
            CapBody::AgentContext(r) => r.delivery,
            b => panic!("{b:?}"),
        })
    };
    assert_eq!(ctx("agent-context@2", "").unwrap(), Delivery::Progressive);
    assert_eq!(ctx("agent-context@1", "").unwrap(), Delivery::Progressive);
    assert!(ctx("agent-context@1", r#","delivery":"inline""#).is_err());
}

/// agent-sessions@2 is a declaration, like @1, and exclusive with it.
#[test]
fn agent_sessions_2_is_a_declaration_exclusive_with_1() {
    let s1 = r#"{"type":"com.docker.sandbox/agent-sessions@1","config":{"prompt":["-p","{{.Prompt}}"]}}"#;
    let s2 = r#"{"type":"com.docker.sandbox/agent-sessions@2","config":{"prompt":["-p","{{.Prompt}}"]}}"#;
    let k = one_cap(s2).unwrap();
    assert_eq!(k.caps[0].body, CapBody::AgentSessions);
    let e = one_cap(&format!("{s1},{s2}")).unwrap_err();
    assert!(
        format!("{e:#}").contains("agent-sessions@1 and agent-sessions@2 are exclusive"),
        "{e:#}"
    );
}

#[test]
fn port_resources_and_agent_context_variants() {
    let k = one_cap(
        r#"{"type":"com.docker.sandbox/port@1","config":{"container":53,"transport":"udp"}}"#,
    )
    .unwrap();
    assert!(matches!(
        k.caps[0].body,
        CapBody::Port {
            container: 53,
            udp: true
        }
    ));

    let k =
        one_cap(r#"{"type":"com.docker.sandbox/resources@1","config":{"cpu":2.5,"memory":"4g"}}"#)
            .unwrap();
    assert_eq!(
        k.caps[0].body,
        CapBody::Resources {
            cpus: Some("2.5".into()),
            memory: Some("4g".into())
        }
    );

    let k = one_cap(
            r#"{"type":"com.docker.sandbox/agent-context@1","config":{"contentFile":"/usr/share/sandbox/kit/x/ctx.md"}}"#,
        )
        .unwrap();
    let CapBody::AgentContext(a) = &k.caps[0].body else {
        panic!()
    };
    assert_eq!(a.content, "");
    assert_eq!(
        a.content_file.as_deref(),
        Some("/usr/share/sandbox/kit/x/ctx.md")
    );

    let e =
        one_cap(r#"{"type":"com.docker.sandbox/agent-context@2","config":{"contentFile":"x"}}"#)
            .unwrap_err();
    assert!(format!("{e:#}").contains("contentFile"), "{e:#}");
}

#[test]
fn config_less_capabilities_reject_config_and_files_default_to_overwrite() {
    let e = one_cap(r#"{"type":"com.docker.sandbox/sbx@1","config":{"a":1}}"#).unwrap_err();
    assert!(format!("{e:#}").contains("no config"), "{e:#}");

    let k = one_cap(
        r#"{"type":"com.docker.sandbox/lifecycle@1","config":{"files":[{"path":"/a","content":"x"}],
                "startup":[{"command":"sleep 1","background":true}]}}"#,
    )
    .unwrap();
    let CapBody::Lifecycle(l) = &k.caps[0].body else {
        panic!()
    };
    assert!(l.files[0].overwrite);
    assert!(l.startup[0].background);
}

#[test]
fn credential_phase_list_and_validation() {
    let k = one_cap(
            r#"{"type":"com.docker.sandbox/credential@1","config":{"service":"github",
                "phase":["install","runtime"],
                "apiKey":{"name":"GH_TOKEN","inject":[{"domain":"github.com","scheme":"basic","username":"x-access-token"}]}}}"#,
        )
        .unwrap();
    let CapBody::Credential(c) = &k.caps[0].body else {
        panic!()
    };
    assert!(c.install && c.runtime);
    assert_eq!(c.inject[0].basic_user.as_deref(), Some("x-access-token"));

    let e = one_cap(
        r#"{"type":"com.docker.sandbox/credential@1","config":{"service":"s","phase":"runtime"}}"#,
    )
    .unwrap_err();
    assert!(format!("{e:#}").contains("apiKey"), "{e:#}");
}

/// The `apiKey.inject[]` rules of a v3 credential@1 with `inject` (a JSON list), and of the
/// same rules in a v2 kit's `credentials`.
fn v3_and_v2_injects(inject: &str) -> (Result<Vec<Inject>>, Result<Vec<Inject>>) {
    let v3 = one_cap(&format!(
        r#"{{"type":"com.docker.sandbox/credential@1","config":{{"service":"github",
            "phase":"runtime","apiKey":{{"name":"GH_TOKEN","inject":{inject}}}}}}}"#
    ))
    .map(|k| match &k.caps[0].body {
        CapBody::Credential(c) => c.inject.clone(),
        b => panic!("{b:?}"),
    });
    // JSON is YAML.
    let v2 = crate::kits::v2::parse(
        &format!(
            "schemaVersion: \"2\"\nkind: mixin\nname: m\ncredentials:\n  - service: github\n    \
             apiKey:\n      name: GH_TOKEN\n      inject: {inject}\n"
        ),
        std::path::Path::new("/nonexistent"),
    )
    .map(|k| match &k.caps[0].body {
        CapBody::Credential(c) => c.inject.clone(),
        b => panic!("{b:?}"),
    });
    (v3, v2)
}

/// SPEC credential@1, Config table row `apiKey.inject[].scheme` / `username` ("Non-header
/// presentation, e.g. `basic` with `username` (credential as password)"). The row has no `tck:`
/// id at the pinned SPEC_COMMIT. v3 presents a scheme as v2 does: `basic` is smolvm's basic-auth
/// format for the username, `bearer` an `Authorization: Bearer %s` header.
#[test]
fn credential_inject_scheme_is_presented_as_in_v2() {
    let (v3, v2) = v3_and_v2_injects(
        r#"[{"domain":"github.com","scheme":"basic","username":"x-access-token"}]"#,
    );
    let v3 = v3.unwrap();
    assert_eq!(
        v3,
        [Inject {
            domain: "github.com".into(),
            header: None,
            format: None,
            basic_user: Some("x-access-token".into()),
        }]
    );
    assert_eq!(v3, v2.unwrap());

    let (v3, v2) = v3_and_v2_injects(r#"[{"domain":"api.github.com","scheme":"bearer"}]"#);
    let v3 = v3.unwrap();
    assert_eq!(v3[0].header.as_deref(), Some("Authorization"));
    assert_eq!(v3[0].format.as_deref(), Some("Bearer %s"));
    assert_eq!(v3, v2.unwrap());
}

/// SPEC credential@1, row `apiKey.inject[].scheme` / `username` (no `tck:` id at the pinned
/// SPEC_COMMIT): smolvm presents only `bearer` and `basic`, so another scheme is refused at load
/// instead of sending the raw value, as is `basic` without a username or a scheme with a format.
#[test]
fn credential_inject_scheme_smolvm_cant_present_is_refused() {
    for (inject, want) in [
        (
            r#"[{"domain":"a.com","scheme":"digest"}]"#,
            r#"scheme must be bearer or basic (got "digest")"#,
        ),
        (
            r#"[{"domain":"a.com","scheme":"basic"}]"#,
            "scheme basic needs a username",
        ),
        (
            r#"[{"domain":"a.com","scheme":"bearer","format":"Token %s"}]"#,
            "inject sets both format and scheme",
        ),
    ] {
        let (v3, v2) = v3_and_v2_injects(inject);
        assert_eq!(
            format!("{:#}", v3.unwrap_err()),
            format!("capability com.docker.sandbox/credential@1: apiKey.inject[0]: {want}")
        );
        assert_eq!(
            format!("{:#}", v2.unwrap_err()),
            format!("credentials: github {want}")
        );
    }
}

fn ssh(config: &str) -> Result<CapBody> {
    one_cap(&format!(
        r#"{{"type":"com.docker.sandbox/ssh-agent@1","config":{config}}}"#
    ))
    .map(|k| k.caps[0].body.clone())
}

#[test]
fn ssh_agent_parses_phases_and_limits() {
    assert_eq!(
        ssh(r#"{"phase":"runtime"}"#).unwrap(),
        CapBody::SshAgent {
            phases: vec![SshPhase::Runtime],
            unrestricted: true,
            sign: vec![],
            authenticate: vec![],
        }
    );
    assert_eq!(
        ssh(
            r#"{"phase":["install","runtime"],"unrestricted":false,"sign":["git","file"],
                    "authenticate":["git@github.com","gitlab.example.org"]}"#
        )
        .unwrap(),
        CapBody::SshAgent {
            phases: vec![SshPhase::Install, SshPhase::Runtime],
            unrestricted: false,
            sign: vec!["git".into(), "file".into()],
            authenticate: vec!["git@github.com".into(), "gitlab.example.org".into()],
        }
    );
}

#[test]
fn ssh_agent_rejects_bad_configs() {
    let cases = [
        (r#"{}"#, "phase"),
        (r#"{"phase":"build"}"#, "phase must be install or runtime"),
        (
            r#"{"phase":[]}"#,
            "phase must name install, runtime or both",
        ),
        (
            r#"{"phase":["runtime","runtime"]}"#,
            "phase runtime is listed twice",
        ),
        (
            r#"{"phase":"runtime","sign":["git"]}"#,
            "an unrestricted entry can't state sign or authenticate",
        ),
        (
            r#"{"phase":"runtime","unrestricted":true,"authenticate":["a.com"]}"#,
            "an unrestricted entry can't state sign or authenticate",
        ),
        (
            r#"{"phase":"runtime","unrestricted":false}"#,
            "a bounded entry (unrestricted: false) needs sign or authenticate",
        ),
        (
            r#"{"phase":"runtime","unrestricted":false,"sign":[]}"#,
            "sign must not be empty",
        ),
        (
            r#"{"phase":"runtime","unrestricted":false,"sign":["git","git"]}"#,
            "sign lists \"git\" twice",
        ),
        (
            r#"{"phase":"runtime","unrestricted":false,"sign":["a b"]}"#,
            "sign namespace \"a b\" must be printable ASCII without spaces",
        ),
        (
            r#"{"phase":"runtime","unrestricted":false,"sign":[""]}"#,
            "sign namespace \"\" must be printable ASCII without spaces",
        ),
        (
            r#"{"phase":"runtime","unrestricted":false,"authenticate":[]}"#,
            "authenticate must not be empty",
        ),
        (
            r#"{"phase":"runtime","unrestricted":false,"authenticate":["a.com","a.com"]}"#,
            "authenticate lists \"a.com\" twice",
        ),
        (r#"{"phase":"runtime","bogus":1}"#, "bogus"),
    ];
    for (config, want) in cases {
        let e = ssh(config).unwrap_err();
        assert!(format!("{e:#}").contains(want), "{config}: {e:#}");
    }
    for host in [
        "*.github.com",
        "github.com:22",
        "1.2.3.4",
        "[::1]",
        "GitHub.com",
        "a..com",
        "-a.com",
        "a-.com",
        "a.com.",
        "@a.com",
        "a@b@c.com",
        "a b@c.com",
        "",
    ] {
        let e = ssh(&format!(
            r#"{{"phase":"runtime","unrestricted":false,"authenticate":["{host}"]}}"#
        ))
        .unwrap_err();
        assert!(
            format!("{e:#}").contains(&format!("authenticate entry {host:?} must be")),
            "{host}: {e:#}"
        );
    }
    for ok in [
        "github.com",
        "git@github.com",
        "localhost",
        "a-b.x1.example",
    ] {
        ssh(&format!(
            r#"{{"phase":"runtime","unrestricted":false,"authenticate":["{ok}"]}}"#
        ))
        .unwrap();
    }
}

#[test]
fn ssh_agent_entries_of_one_kit_must_not_overlap_in_phase() {
    let ty = "com.docker.sandbox/ssh-agent@1";
    let json = format!(
        r#"{{"schemaVersion":"3","kind":"mixin","capabilities":[
                {{"type":"{ty}","config":{{"phase":["install","runtime"]}}}},
                {{"type":"{ty}","config":{{"phase":"runtime","unrestricted":false,"sign":["git"]}}}}]}}"#
    );
    let e = parse(&json, local("t")).unwrap_err();
    assert_eq!(
        format!("{e:#}"),
        "kit t: ssh-agent@1 entries overlap in phase runtime"
    );
    let json = format!(
        r#"{{"schemaVersion":"3","kind":"mixin","capabilities":[
                {{"type":"{ty}","config":{{"phase":"install"}}}},
                {{"type":"{ty}","config":{{"phase":"runtime"}}}}]}}"#
    );
    assert_eq!(parse(&json, local("t")).unwrap().caps.len(), 2);
}

#[test]
fn kit_names_are_restricted() {
    assert_eq!(check_name("my-kit_1.0".into()).unwrap(), "my-kit_1.0");
    for bad in ["", "a\nb", "a\tb", "a\\b", "a b", "a;b"] {
        let e = check_name(bad.into()).unwrap_err();
        assert_eq!(
            e.to_string(),
            format!("kit name '{bad}' may only contain letters, digits, '.', '_' and '-'")
        );
    }
    let e = name_from_source(&Source::Local("/k/bad\nname".into())).unwrap_err();
    assert!(e.to_string().contains("may only contain"), "{e}");
}

#[test]
fn name_comes_from_the_source_not_display_name() {
    let json = r#"{"schemaVersion":"3","kind":"mixin","displayName":"Fancy Name"}"#;
    let name = |src| parse(json, src).unwrap().name;
    assert_eq!(
        name(Source::Registry(
            "docker.io/acme/sbx-kit-team:1.0@sha256:abc".into()
        )),
        "sbx-kit-team"
    );
    assert_eq!(
        name(Source::Registry("ghcr.io/acme/tool:1.2".into())),
        "tool"
    );
    assert_eq!(name(Source::Local("kits/dev.yaml".into())), "dev");
    let dir = tempfile::tempdir().unwrap();
    let kit_dir = dir.path().join("my-kit");
    std::fs::create_dir(&kit_dir).unwrap();
    assert_eq!(name(Source::Local(kit_dir)), "my-kit");
    assert_eq!(name(Source::Smolfile("proj/Smolfile".into())), "proj");
    assert_eq!(name(Source::Registry("localhost:5000/kit:1".into())), "kit");
    let digest = format!("acme/kit@sha256:{}", "ab".repeat(32));
    assert_eq!(name(Source::Registry(digest)), "kit");

    // Relative paths: the parent has no name of its own, so it is resolved on disk.
    let cwd = std::env::current_dir().unwrap();
    let cwd_name = cwd.file_name().unwrap().to_str().unwrap().to_string();
    assert_eq!(name(Source::Smolfile("Smolfile".into())), cwd_name);
    assert_eq!(name(Source::Smolfile("./Smolfile".into())), cwd_name);
    let root = dir.path().canonicalize().unwrap();
    std::fs::create_dir(root.join("sub")).unwrap();
    let via_dotdot = root.join("sub").join("..").join("Smolfile");
    let want = root.file_name().unwrap().to_str().unwrap();
    assert_eq!(name(Source::Smolfile(via_dotdot)), want);
    assert_eq!(name(Source::Smolfile("proj/dev.smolfile".into())), "dev");
}

#[test]
fn a_published_kits_build_arguments_are_not_required() {
    // As sbx 0.53 creates docker.io/sbx/antigravity with no --kit-arg: its required
    // `version` only fed the build, which is done.
    let d = r#"{"schemaVersion":"3","kind":"workload","name":"w",
            "args":{"version":{"required":true,"buildArg":"VERSION"},"run":{"required":true}}}"#;
    let k = parse(d, Source::Registry("acme/w:1".into())).unwrap();
    assert!(!k.args["version"].required);
    assert!(k.args["run"].required, "a runtime argument stays required");
}

const GROUPS: &str = r#"
schemaVersion: "3"
kind: mixin
capabilities:
  - type: com.docker.sandbox/lifecycle@1
    config: {startup: [{command: "printf base"}]}
  - group:
      name: Feature
      optional: true
      capabilities:
        - type: com.docker.sandbox/volume@1
          config: {path: /var/tmp/group-volume}
        - type: com.docker.sandbox/lifecycle@1
          config: {files: [{path: /var/tmp/group-feature, content: selected}]}
  - group:
      capabilities:
        - type: com.docker.sandbox/lifecycle@1
          config: {startup: [{command: "printf independent"}]}
"#;

/// tck: SPEC-v3 §7.1.1/group-grammar
#[test]
fn group_members_take_the_groups_place_and_optional() {
    let k = parse(GROUPS, local("g")).unwrap();
    let at: Vec<(String, bool)> = k
        .caps
        .iter()
        .map(|c| {
            let at = c.group.as_ref().map_or("top".into(), |g| g.member_path());
            (at, c.optional)
        })
        .collect();
    assert_eq!(
        at,
        [
            ("top".into(), false),
            ("capabilities[1].group.capabilities[0]".into(), true),
            ("capabilities[1].group.capabilities[1]".into(), true),
            // A group is required unless it says otherwise, and one member is enough.
            ("capabilities[2].group.capabilities[0]".into(), false),
        ]
    );
    assert_eq!(
        k.caps[1].group.as_ref().unwrap().name.as_deref(),
        Some("Feature")
    );
}

/// tck: SPEC-v3 §7.1.1/group-grammar
#[test]
fn the_group_grammar_refuses_mixed_empty_and_nested_groups_and_member_optional() {
    let lc = "{type: com.docker.sandbox/lifecycle@1}";
    for (item, want) in [
        (
            format!("{{type: com.docker.sandbox/sbx@1, group: {{capabilities: [{lc}]}}}}"),
            "capabilities[0]: a group can't also have type, config or optional",
        ),
        (
            format!("{{optional: true, group: {{capabilities: [{lc}]}}}}"),
            "capabilities[0]: a group can't also have type, config or optional",
        ),
        (
            "{group: {capabilities: []}}".into(),
            "capabilities[0]: the group has no capabilities",
        ),
        (
            "{group: {}}".into(),
            "capabilities[0]: the group has no capabilities",
        ),
        (
            format!("{{group: {{capabilities: [{{group: {{capabilities: [{lc}]}}}}]}}}}"),
            "capabilities[0].group.capabilities[0]: groups can't be nested",
        ),
        (
            "{group: {capabilities: [{type: com.docker.sandbox/sbx@1, optional: false}]}}".into(),
            "capabilities[0].group.capabilities[0]: a group member can't set optional; the group does",
        ),
        (
            "{group: {capabilities: [{type: com.docker.sandbox/sbx@1, declarationBlocks: [a]}]}}"
                .into(),
            "capabilities[0].group.capabilities[0]: a group member can't set declarationBlocks",
        ),
        (
            "{group: {capabilities: [{config: {}}]}}".into(),
            "capabilities[0].group.capabilities[0] has no type",
        ),
    ] {
        let doc = format!("schemaVersion: \"3\"\nkind: mixin\ncapabilities: [{item}]\n");
        let e = parse(&doc, local("g")).unwrap_err();
        assert_eq!(format!("{e:#}"), want, "{item}");
    }
}

/// tck: SPEC-v3 §7.1.1/validate-declarations
#[test]
fn every_member_is_validated_even_in_an_optional_group() {
    let doc = r#"
schemaVersion: "3"
kind: mixin
capabilities:
  - group:
      optional: true
      capabilities:
        - type: com.docker.sandbox/volume@1
          config: {path: /data, sise: 1}
"#;
    let e = parse(doc, local("g")).unwrap_err();
    assert!(format!("{e:#}").contains("sise"), "{e:#}");
}

#[test]
fn a_published_sets_groups_keep_their_attribution_fields() {
    let doc = r#"
schemaVersion: "3"
kind: mixin
capabilities:
  - group:
      capabilities:
        - type: com.docker.sandbox/lifecycle@1
          source: {kit: "registry.example/base:1.0.0", path: "capabilities[0]"}
    source: {kit: "registry.example/base:1.0.0", path: "capabilities[0]"}
    declarationBlocks: ["0:0"]
"#;
    let k = parse(doc, local("g")).unwrap();
    assert_eq!(k.caps.len(), 1);
}

#[test]
fn per_entry_checks_compare_a_groups_members_apart_from_other_entries() {
    let doc = r#"
schemaVersion: "3"
kind: mixin
capabilities:
  - type: com.docker.sandbox/ssh-agent@1
    config: {phase: install, unrestricted: true}
  - group:
      optional: true
      capabilities:
        - type: com.docker.sandbox/ssh-agent@1
          config: {phase: install, unrestricted: true}
"#;
    let k = parse(doc, local("g")).unwrap();
    assert_eq!(k.caps.len(), 2);
}

fn yaml_cap(cap: &str) -> Kit {
    let doc = format!("schemaVersion: \"3\"\nkind: mixin\ncapabilities:\n{cap}");
    parse(&doc, local("r")).unwrap()
}

#[test]
fn a_config_with_a_reference_is_kept_and_read_as_written_when_it_can_be() {
    let k = yaml_cap(
        r#"  - type: com.docker.sandbox/lifecycle@1
    config: {install: [{command: "echo ${{ kit.args.name }}"}]}
"#,
    );
    let CapBody::Lifecycle(l) = &k.caps[0].body else {
        panic!("{:?}", k.caps[0].body)
    };
    assert_eq!(
        l.install[0].command,
        HookCmd::Shell("echo ${{ kit.args.name }}".into())
    );
    assert!(k.caps[0].config.is_some());
}

#[test]
fn a_config_that_needs_its_references_to_be_read_is_pending() {
    for cap in [
        r#"  - type: com.docker.sandbox/port@1
    config: {container: "${{ kit.args.port }}"}"#,
        r#"  - type: com.docker.sandbox/host-mount@1
    config: {path: "${{ kit.args.dir }}"}"#,
    ] {
        let k = yaml_cap(cap);
        assert_eq!(k.caps[0].body, CapBody::Pending, "{cap}");
        assert!(k.caps[0].config.is_some(), "{cap}");
    }
}

#[test]
fn a_config_without_kit_references_is_read_once_and_not_kept() {
    for cap in [
        r#"  - type: com.docker.sandbox/lifecycle@1
    config: {install: [{command: "echo ${{ github.sha }}"}]}"#,
        // Nothing reads an unsupported type's config.
        r#"  - type: com.docker.sandbox/usb-device@1
    optional: true
    config: {class: "${{ kit.args.class }}"}"#,
    ] {
        assert_eq!(yaml_cap(cap).caps[0].config, None, "{cap}");
    }
}

#[test]
fn a_config_that_is_wrong_whatever_its_references_is_refused_at_load() {
    let doc = r#"schemaVersion: "3"
kind: mixin
capabilities:
  - type: com.docker.sandbox/port@1
    config: {container: 0}
"#;
    let e = parse(doc, local("r")).unwrap_err();
    assert!(
        format!("{e:#}").contains("container must be 1..65535"),
        "{e:#}"
    );
}

#[test]
fn a_lifecycle_file_path_must_be_absolute_once_expanded() {
    let doc = r#"schemaVersion: "3"
kind: mixin
capabilities:
  - type: com.docker.sandbox/lifecycle@1
    config: {files: [{path: notes/a.md, content: x}]}
"#;
    let e = parse(doc, local("r")).unwrap_err();
    assert!(
        format!("{e:#}").contains(r#"lifecycle@1 file path "notes/a.md" must be absolute"#),
        "{e:#}"
    );
    // With a reference, the path is checked once it expands.
    let k = yaml_cap(
        r#"  - type: com.docker.sandbox/lifecycle@1
    config: {files: [{path: "${{ kit.env.WORKSPACE }}/a.md", content: x}]}"#,
    );
    assert_eq!(k.caps[0].body, CapBody::Pending);
}

/// tck: dockerd@1 config section (no id): `autoStart` defaults true, no other field.
#[test]
fn dockerd_config_decodes_strictly() {
    use serde_json::json;
    let ty = "com.docker.sandbox/dockerd@1";
    let auto = |c| match body(ty, c).unwrap() {
        CapBody::Dockerd { auto_start } => auto_start,
        b => panic!("{b:?}"),
    };
    assert!(auto(None));
    assert!(auto(Some(json!({}))));
    assert!(!auto(Some(json!({"autoStart": false}))));
    assert!(body(ty, Some(json!({"other": 1}))).is_err());
}

fn volume_path(path: &str) -> Result<String> {
    let k = one_cap(&format!(
        r#"{{"type":"com.docker.sandbox/volume@1","config":{{"path":"{path}"}}}}"#
    ))?;
    match &k.caps[0].body {
        CapBody::Volume { path, .. } => Ok(path.clone()),
        other => panic!("{other:?}"),
    }
}

/// volume@1's path is REQUIRED and absolute; it's compared as the storage key cleans it (§7.1), so
/// it's cleaned here. smolvm reads `:` as host:guest, so a path can't hold one.
#[test]
fn volume_paths_are_cleaned_and_must_be_absolute() {
    assert_eq!(volume_path("/a/./b//c/").unwrap(), "/a/b/c");
    assert_eq!(volume_path("/a/../b").unwrap(), "/b");
    // So the engine-store check (dockerd@1/engine-store-owned) sees one spelling.
    assert_eq!(
        volume_path("/var/lib/x/../docker").unwrap(),
        "/var/lib/docker"
    );
    assert_eq!(
        volume_path("//var/lib//docker/./volumes").unwrap(),
        "/var/lib/docker/volumes"
    );
    for path in ["data", "", "/", "/..", "../x"] {
        let e = volume_path(path).unwrap_err();
        assert_eq!(
            e.root_cause().to_string(),
            format!("volume@1 path {path:?} must be an absolute path other than /"),
        );
    }
    let e = volume_path("/a:b").unwrap_err();
    assert_eq!(
        e.root_cause().to_string(),
        "volume@1 path \"/a:b\" can't contain ':' (smolvm reads it as host:guest)"
    );
}

fn volume_mode(mode: &str) -> Result<CapBody> {
    let k = one_cap(&format!(
        r#"{{"type":"com.docker.sandbox/volume@1","config":{{"path":"/v","mode":"{mode}"}}}}"#
    ))?;
    Ok(k.caps[0].body.clone())
}

/// volume@1's mode goes to the guest tmpfs `mode=` option, so it must be octal like host-mount@1's.
#[test]
fn volume_mode_must_be_octal() {
    for mode in ["0755,size=999G,suid", "999", "75", "07555"] {
        let e = volume_mode(mode).unwrap_err();
        let msg = e.root_cause().to_string();
        assert!(msg.contains("volume@1 mode"), "{msg}");
        assert!(msg.contains("must be octal"), "{msg}");
    }
    for mode in ["755", "0755", "1777"] {
        assert!(volume_mode(mode).is_ok(), "{mode}");
    }
}

#[test]
fn host_mount_refuses_a_colon() {
    let e = host_mount(r#"{"path":"/a:b"}"#).unwrap_err();
    assert_eq!(
        e.root_cause().to_string(),
        "host-mount@1 path \"/a:b\" can't contain ':' (smolvm reads it as host:guest)"
    );
}

/// resources@1 cpu: cores, non-negative (0 is valid).
#[test]
fn resources_cpu_must_be_a_non_negative_number() {
    let cpu = |v: &str| {
        one_cap(&format!(
            r#"{{"type":"com.docker.sandbox/resources@1","config":{{"cpu":{v}}}}}"#
        ))
    };
    assert!(cpu("0").is_ok());
    assert!(cpu("1.5").is_ok());
    assert_eq!(
        cpu("-1").unwrap_err().root_cause().to_string(),
        "resources@1 cpu must be a non-negative number of cores (got -1)"
    );
    // The descriptor's YAML reader refuses non-finite numbers first.
    for v in [".inf", ".nan"] {
        assert!(cpu(v).is_err(), "{v}");
    }
}

/// tck: SPEC-v3 §7.1.1/group-grammar (strict decoding, §1.2): a group's fields are name,
/// description, optional and capabilities.
#[test]
fn a_group_refuses_unknown_fields() {
    let group = |extra: &str| {
        one_cap(&format!(
            r#"{{"group":{{"name":"g","description":"d"{extra},"capabilities":[
                {{"type":"com.docker.sandbox/long-running@1"}}]}}}}"#
        ))
    };
    assert!(group("").is_ok());
    assert!(group(r#","optinal":true"#).is_err());
}

fn credential(config: &str) -> Result<Kit> {
    one_cap(&format!(
        r#"{{"type":"com.docker.sandbox/credential@1","config":{config}}}"#
    ))
}

/// credential@1: `service` is a lowercase-kebab name, `phase` lists distinct phases, and
/// `username` belongs with `scheme: basic`.
#[test]
fn credential_service_phases_and_username_are_checked() {
    let with = |service: &str, phase: &str, inject: &str| {
        credential(&format!(
            r#"{{"service":"{service}","phase":{phase},"apiKey":{{"name":"K","inject":[{inject}]}}}}"#
        ))
    };
    let plain = r#"{"domain":"a.com","header":"x"}"#;
    for ok in ["github", "my-api", "e2e-tok"] {
        assert!(with(ok, r#""runtime""#, plain).is_ok(), "{ok}");
    }
    for bad in ["", "GitHub", "git_hub", "-x", "x-"] {
        let e = with(bad, r#""runtime""#, plain).unwrap_err();
        assert_eq!(
            e.root_cause().to_string(),
            format!("credential@1 service {bad:?} must be a lowercase-kebab name"),
        );
    }
    assert!(with("gh", r#"["install","install"]"#, plain).is_err());
    let e = with(
        "gh",
        r#""runtime""#,
        r#"{"domain":"a.com","header":"x","format":"Bearer %s","username":"u"}"#,
    )
    .unwrap_err();
    assert!(
        format!("{e:#}").contains("username is only for scheme basic"),
        "{e:#}"
    );
}

/// SPEC-v3 §7: a type is `<namespace>/<name>@<version>`, as the spec's validator reads it.
#[test]
fn a_malformed_capability_type_is_refused() {
    for ty in [
        "network-policy@1",
        "com.docker.sandbox/network-policy",
        "com.docker.sandbox/network-policy@0",
        "com.docker.sandbox/network-policy@v1",
        "Com.Docker.Sandbox/network-policy@1",
        "com.docker.sandbox/network_policy@1",
        "com.docker.sandbox/-np@1",
    ] {
        let e = one_cap(&format!(r#"{{"type":"{ty}","optional":true}}"#)).unwrap_err();
        assert!(
            format!("{e:#}").contains(&format!(
                "capabilities[0]: type {ty:?} is not <namespace>/<name>@<version>"
            )),
            "{ty}: {e:#}"
        );
    }
    one_cap(r#"{"type":"com.example-1/x-y2@12","optional":true}"#).unwrap();
}

/// tck: clipboard@1/config-valid. smolbento doesn't provide the clipboard, but a kit asking for it
/// is still checked as the spec reads it.
#[test]
fn a_clipboard_config_is_checked_though_unsupported() {
    const CLIP: &str = "com.docker.sandbox/clipboard@1";
    let read = |v: Option<serde_json::Value>| body(CLIP, v);
    for ok in [
        None,
        Some(serde_json::json!({})),
        Some(serde_json::json!({"read": ["image/*"], "write": []})),
        Some(serde_json::json!({"read": ["*/*", "text/plain", "application/vnd.a+json"]})),
    ] {
        assert!(
            matches!(read(ok.clone()), Ok(CapBody::Unsupported)),
            "{ok:?}"
        );
    }
    for (bad, why) in [
        (serde_json::json!(null), "object"),
        (
            serde_json::json!({"read": [], "write": []}),
            "admit nothing",
        ),
        (serde_json::json!({"read": []}), ""),
        (serde_json::json!({"read": null}), "list"),
        (serde_json::json!({"read": ["Text/Plain"]}), "lowercase"),
        (
            serde_json::json!({"read": ["text/plain;charset=utf-8"]}),
            "lowercase",
        ),
        (serde_json::json!({"read": ["UTF8_STRING"]}), "lowercase"),
        (serde_json::json!({"read": ["image"]}), "lowercase"),
        (serde_json::json!({"read": ["*/png"]}), "lowercase"),
        (serde_json::json!({"read": ["image/x-png"]}), "alias"),
        (serde_json::json!({"write": ["text/*", "text/*"]}), "twice"),
        (serde_json::json!({"copy": ["text/*"]}), "copy"),
    ] {
        // `read: []` alone leaves write unfiltered, so it grants something.
        if why.is_empty() {
            assert!(read(Some(bad)).is_ok());
            continue;
        }
        let e = read(Some(bad.clone())).unwrap_err();
        assert!(format!("{e:#}").contains(why), "{bad}: {e:#}");
    }
}
