use super::*;
use crate::kits::model::SshPhase::{self, Install, Runtime};
use crate::sandbox::{Meta, Recorded};
use crate::secrets::{SecretEntry, Source, scope_for};
use crate::smolvm::NetworkSpec;
use crate::testutil::*;

#[test]
fn host_access_note_only_for_sandboxes_with_host_access() {
    assert_eq!(
        host_access_note("s1", true).as_deref(),
        Some("note: s1 is created with host access (every port on your host's localhost)")
    );
    assert_eq!(host_access_note("s1", false), None);
}

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
        rec: Recorded {
            secrets: secrets.to_vec(),
            credential_hosts: hosts.to_vec(),
            credential_env,
            ..Default::default()
        },
        name: name.into(),
        agent: "claude".into(),
        created: 1,
        ..Default::default()
    }
}

/// A test env whose policy is deny-all.
fn deny_all_env() -> TestEnv {
    let t = test_env(&[]);
    set_policy(&t, "mode = \"deny-all\"");
    t
}

#[test]
fn start_plan_resolves_bound_secrets_into_env() {
    let t = deny_all_env();
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
}

#[test]
fn fork_secrets_resolve_own_then_parent_then_global() {
    let t = deny_all_env();
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
    let t = deny_all_env();
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
    let mut m = meta(
        "s1",
        &["internal".to_string()],
        &["api.internal.example".to_string()],
    );
    m.rec.credential_env = vec!["INTERNAL_TOKEN".into()];
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
    assert_eq!(req.rec.secrets, vec!["anthropic"]);
    assert_eq!(req.rec.credential_env, vec!["ANTHROPIC_API_KEY"]);
    assert_eq!(req.credentials[0].env_var, "ANTHROPIC_API_KEY");
    assert!(
        req.rec
            .credential_hosts
            .contains(&"api.anthropic.com".to_string())
    );
    let NetworkSpec::Restricted(list) = &req.network else {
        panic!("restricted")
    };
    assert!(list.hosts().contains(&"api.anthropic.com".to_string()));
    assert!(list.patterns().contains(&"registry.npmjs.org".to_string()));
    let p = Policy::load(&t.ctx.paths).unwrap();
    assert_eq!(added, vec![p.sandboxes["s1"].rules[0].id.clone()]);
}

#[test]
fn a_0_2_0_policy_file_still_loads() {
    // v0.2.0's `--deny-network` wrote this; the field is ignored now.
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
    prepare_create(&t.ctx, &mut req, &[], None).unwrap();
    let NetworkSpec::Restricted(list) = &req.network else {
        panic!("restricted")
    };
    assert!(
        list.patterns().contains(&"registry.npmjs.org".to_string()),
        "balanced, like any sandbox without rules"
    );
}

#[test]
fn start_without_a_mode_and_without_a_terminal_is_an_error() {
    let t = test_env(&[]);
    set_policy(&t, "");
    let err = start_plan(&t.ctx, &meta("s1", &[], &[]))
        .unwrap_err()
        .to_string();
    assert!(err.contains("bento policy init"), "{err}");
    assert_eq!(Policy::load(&t.ctx.paths).unwrap().mode, None);
}

#[test]
fn start_without_a_mode_asks_on_a_terminal_and_saves_the_choice() {
    let mut t = test_env(&[]);
    set_policy(&t, "");
    t.answer("3\n");
    let _ = start_plan(&t.ctx, &meta("s1", &[], &[]));
    // A question, as in sbx: on stderr, so stdout stays clean for `--json` and pipes.
    assert_eq!(t.stdout(), "");
    assert!(super::POLICY_PROMPT.starts_with("  Choose the network policy for sandboxes\n"));
    assert!(super::POLICY_PROMPT.ends_with("\n  Choice [1-3, default 2]: "));
    assert_eq!(
        Policy::load(&t.ctx.paths).unwrap().mode,
        Some(Mode::DenyAll)
    );
    set_policy(&t, "");
    t.answer("9\n");
    let e = start_plan(&t.ctx, &meta("s1", &[], &[])).unwrap_err();
    assert_eq!(e.to_string(), "'9' isn't 1, 2 or 3");
    assert_eq!(Policy::load(&t.ctx.paths).unwrap().mode, None);
}

#[test]
fn no_policy_and_no_terminal_is_an_error() {
    let t = test_env(&[]);
    std::fs::remove_file(t.ctx.paths.policy_file()).unwrap();
    let err = ensure_policy(&t.ctx).unwrap_err().to_string();
    assert!(err.contains("bento policy init"), "{err}");
}

#[test]
fn push_updates_running_sandboxes_only() {
    let t = deny_all_env();
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
    t.runner().ok(&["machine", "ls", "--json"], &ls);
    t.runner().ok(
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
    let t = deny_all_env();
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
    let t = deny_all_env();
    assert!(branchable(&t, &mountless));
    assert!(!branchable(&t, &fork));

    let t = test_env(&[("SMOLBENTO_FORK", "false")]);
    set_policy(&t, "mode = \"deny-all\"");
    assert!(!branchable(&t, &mountless));
}

#[test]
fn start_plan_for_a_linked_worktree_names_its_branch() {
    let t = deny_all_env();
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
    let t = deny_all_env();
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
    let t = deny_all_env();
    save_secret(&t, "github", None, "gh-123");
    let mut m = meta("s1", &["github".to_string()], &[]);
    m.rec.credential_install = vec!["GH_TOKEN".into()];
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
    let t = deny_all_env();
    save_secret(&t, "github", None, "gh-123");
    let mut m = meta("s1", &["github".to_string()], &[]);
    m.rec.credential_env.push("SBX_KIT_GITHUB".into());
    m.rec.credential_services = [("SBX_KIT_GITHUB".to_string(), "github".to_string())].into();
    m.rec.credential_formats = [
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
    let t = deny_all_env();
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
    let fake = t.runner();
    fake.fail(&["machine", "status"], "NOT_FOUND", "vm not found");
    // A bad `--deny-network` host fails before the machine exists.
    if deny_network.is_empty() {
        fake.once_ok(
            &["machine", "status"],
            &machine_json("sbx-s1", "created", &[("sbx.name", "s1")]),
        );
    }
    fake.missing_until_created("sbx-s1");
    if fail_install {
        fake.fail(&root_sh("sbx-s1", "npm i"), "EXEC_FAILED", "npm ERR! 404");
    }
    let kit = KitFirstStart {
        steps: KitSteps {
            install_rules: vec![ids[0].clone()],
            install: vec![crate::kits::apply::InstallStep {
                label: "kit k install hook 1".into(),
                kit: Some("k".into()),
                user: None,
                script: "npm i".into(),
                relay_stderr: false,
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
    let result = check_free(&t.ctx, "s1")
        .and_then(|()| create_with(&t.ctx, &mut req, deny_network, None, Some(kit), &mut |_| {}));
    (t, result, ids)
}

#[test]
fn create_with_a_kit_drops_install_rules_after_the_hooks() {
    let (t, result, ids) = kit_create(false, &[]);
    result.unwrap();
    let p = Policy::load(&t.ctx.paths).unwrap();
    let left: Vec<&String> = p.sandboxes["s1"].rules.iter().map(|r| &r.id).collect();
    assert_eq!(left, vec![&ids[1]]);
    let lines = t.calls();
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
    let lines = t.calls();
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
    let t = deny_all_env();
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
    let pushed = format!("{:?}", compile::network(&policy, "s1", &[], false));
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
        Cap, CapBody, Content, Hook, HookCmd, Kind, Kit, Lifecycle, NetRule, Rules,
    };
    use crate::policy::Decision;
    let t = deny_all_env();
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
    let fake = t.runner();
    fake.fail(&["machine", "status"], "NOT_FOUND", "vm not found");
    fake.once_ok(
        &["machine", "status"],
        &machine_json("sbx-s1", "created", &[("sbx.name", "s1")]),
    );
    fake.missing_until_created("sbx-s1");
    let kit = Kit::test;
    let mut wl = kit("wl", Kind::Workload);
    wl.content = Content::Image("img:1".into());
    let mut k = kit("k", Kind::Mixin);
    let cap = |ty: &str, body| Cap::new(format!("com.docker.sandbox/{ty}"), false, body);
    k.caps = vec![
        cap(
            "network-policy@2",
            CapBody::Network {
                install: Rules {
                    allow: vec![NetRule::host("registry.npmjs.org")],
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
    check_free(&t.ctx, "s1").unwrap();
    create_with(&t.ctx, &mut req, &[], Some(&plan), None, &mut |_| {}).unwrap();
    let lines = t.calls();
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
    let err = format!("{:#}", result.unwrap_err());
    assert_eq!(
        err,
        "the first start failed (the sandbox was removed): kit k install hook 1 failed:\nnpm ERR! 404"
    );
    assert!(
        t.calls()
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
        !t.calls().iter().any(|l| l.starts_with("machine create")),
        "fails in prepare_create"
    );
    let p = Policy::load(&t.ctx.paths).unwrap();
    assert!(!p.sandboxes.contains_key("s1"), "{p:?}");
}

#[test]
fn unrecorded_install_and_kit_vars_are_still_removed() {
    let t = deny_all_env();
    save_secret(&t, "github", None, "gh-123");
    // `credential_env` doesn't list either; the labels still name them.
    let mut m = meta("s1", &["github".to_string()], &[]);
    m.rec.credential_install = vec!["GH_TOKEN".into()];
    m.rec.credential_services = [("SBX_KIT_GONE".to_string(), "gone".to_string())].into();
    m.rec.credential_env = vec!["GITHUB_TOKEN".into()];
    let plan = start_plan(&t.ctx, &m).unwrap();
    assert_eq!(plan.remove, vec!["GH_TOKEN", "SBX_KIT_GONE"]);
    assert_eq!(
        plan.env,
        vec![("GITHUB_TOKEN".to_string(), "gh-123".to_string())]
    );
}

/// An `ssh-agent@1` entry of mixin `k`.
fn ssh_agent(phases: &[SshPhase], sign: &[&str], optional: bool) -> crate::kits::model::Cap {
    crate::kits::model::Cap::new(
        "com.docker.sandbox/ssh-agent@1",
        optional,
        crate::kits::model::CapBody::ssh_agent(phases, sign, &[]),
    )
}

/// The `shell` preset (`preset`) or a v3 image workload, plus a mixin `k` with an install hook
/// and `caps`, resolved.
fn agent_plan(preset: bool, caps: Vec<crate::kits::model::Cap>) -> Plan {
    use crate::kits::args::ArgValues;
    use crate::kits::model::{Cap, CapBody, Content, Hook, HookCmd, Kind, Kit, Lifecycle};
    let kit = |name: &str, kind, content| Kit {
        content,
        ..Kit::test(name, kind)
    };
    let wl = if preset {
        Kit::agent_test("shell")
    } else {
        kit("wl", Kind::Workload, Content::Image("img:1".into()))
    };
    let mut k = kit("k", Kind::Mixin, Content::None);
    k.caps = caps;
    k.caps.push(Cap::new(
        "com.docker.sandbox/lifecycle@1",
        false,
        CapBody::Lifecycle(Lifecycle {
            install: vec![Hook {
                command: HookCmd::Shell("ssh-add -l".into()),
                user: None,
                env: vec!["SSH_AUTH_SOCK".into()],
                background: false,
                clean_env: true,
            }],
            ..Default::default()
        }),
    ));
    crate::kits::resolve::resolve(wl, vec![k], &ArgValues::default()).unwrap()
}

fn agent_request(preset: bool) -> CreateRequest {
    CreateRequest {
        name: "s1".into(),
        agent: if preset { "shell" } else { "wl" }.into(),
        ..Default::default()
    }
}

/// Creates `name` from `plan` (`None`: a bare `create`), with `env` as bento's environment.
/// Returns the env, the result and the smolvm calls.
fn agent_create(
    env: &[(&str, &str)],
    name: &str,
    preset: bool,
    plan: Option<Plan>,
) -> (TestEnv, Result<Sandbox>, Vec<String>) {
    let t = test_env(env);
    let fake = t.runner();
    fake.fail(&["machine", "status"], "NOT_FOUND", "vm not found");
    fake.once_ok(
        &["machine", "status"],
        &machine_json(
            &sandbox::name::machine_name(name),
            "created",
            &[("sbx.name", name)],
        ),
    );
    fake.missing_until_created(&sandbox::name::machine_name(name));
    let mut req = agent_request(preset);
    req.name = name.into();
    let result = check_free(&t.ctx, name)
        .and_then(|()| create_with(&t.ctx, &mut req, &[], plan.as_ref(), None, &mut |_| {}));
    let lines = t.calls();
    (t, result, lines)
}

/// `agent_create` of `s1` from `agent_plan`.
fn kit_agent_create(
    env: &[(&str, &str)],
    preset: bool,
    caps: Vec<crate::kits::model::Cap>,
) -> (TestEnv, Result<Sandbox>, Vec<String>) {
    agent_create(env, "s1", preset, Some(agent_plan(preset, caps)))
}

/// The `machine create` line, and the install hook's.
fn create_and_hook(t: &TestEnv) -> (String, String) {
    let lines = t.calls();
    let hook = lines.iter().find(|l| l.contains("ssh-add -l"));
    let hook = hook.unwrap_or_else(|| panic!("{lines:#?}")).clone();
    (t.create_line(), hook)
}

const AGENT_ENV: &str = "-e SSH_AUTH_SOCK=/run/ssh-agent.sock";

/// A host agent socket (only its existence is checked at create), and its path.
fn host_agent() -> (tempfile::TempDir, String) {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("agent.sock");
    std::fs::write(&sock, "").unwrap();
    (dir, sock.display().to_string())
}

#[test]
fn a_built_in_agent_gets_the_agent_socket_and_ssh_auth_sock() {
    let (_agent, sock) = host_agent();
    let (t, result, _) = kit_agent_create(&[("SSH_AUTH_SOCK", &sock)], true, vec![]);
    result.unwrap();
    let (create, hook) = create_and_hook(&t);
    let mount = format!(
        "--mount-socket {}:/run/ssh-agent.sock",
        crate::bridge::agent_socket("s1").display()
    );
    assert!(create.contains(&mount), "{create}");
    assert!(create.contains(AGENT_ENV), "{create}");
    assert!(
        create.contains(r#"sbx.ssh-agent={"runtime":{"sign":null}}"#),
        "{create}"
    );
    // A runtime grant isn't the install phase's: its hooks don't see it.
    assert!(hook.contains("unset SSH_AUTH_SOCK && "), "{hook}");
}

/// `create shell` with no kits has no plan, and still gets the built-in agent's grant.
#[test]
fn a_bare_built_in_agent_gets_the_agent_too() {
    let (_agent, sock) = host_agent();
    let (t, result, _) = agent_create(&[("SSH_AUTH_SOCK", &sock)], "s1", true, None);
    result.unwrap();
    let create = t.create_line();
    assert!(create.contains(":/run/ssh-agent.sock"), "{create}");
    assert!(create.contains(AGENT_ENV), "{create}");
    assert!(
        create.contains(r#"sbx.ssh-agent={"runtime":{"sign":null}}"#),
        "{create}"
    );
}

/// With no agent available a bare preset is created without a socket, and without an error.
#[test]
fn a_bare_built_in_agent_without_an_agent_gets_none() {
    let env = [("SMOLBENTO_SSH_AGENT_FORWARDING", "false")];
    let (t, result, _) = agent_create(&env, "s1", true, None);
    result.unwrap();
    let create = t.create_line();
    assert!(!create.contains("ssh-agent"), "{create}");
    assert!(!create.contains("SSH_AUTH_SOCK"), "{create}");
}

/// An internal sandbox (`_builder`) never gets the agent, even with one available.
#[test]
fn an_internal_name_gets_no_agent() {
    let (_agent, sock) = host_agent();
    let (t, result, _) = agent_create(&[("SSH_AUTH_SOCK", &sock)], "_builder", true, None);
    result.unwrap();
    let create = t.create_line();
    assert!(!create.contains("ssh-agent"), "{create}");
    assert!(!create.contains("SSH_AUTH_SOCK"), "{create}");
}

/// A plan's Debug output never carries the process env beyond what the agent lookup reads.
#[test]
fn a_kit_first_start_debug_output_has_no_secrets() {
    let t = test_env(&[
        ("SSH_AUTH_SOCK", "/a.sock"),
        ("MY_SECRET_TOKEN", "hunter2-secret-value"),
    ]);
    let first = sandbox::KitFirstStart {
        steps: Default::default(),
        restart_without: Default::default(),
        rule_ids: vec![],
        agent_backing: Some(crate::ssh_agent::filter::Backing::new(
            &t.ctx.paths,
            &t.ctx.env,
        )),
        agent_socket: None,
    };
    let shown = format!("{first:?}");
    assert!(shown.contains("/a.sock"), "{shown}");
    assert!(!shown.contains("hunter2-secret-value"), "{shown}");
    assert!(!shown.contains("MY_SECRET_TOKEN"), "{shown}");
}

#[test]
fn a_kit_grant_for_both_phases_reaches_the_install_hooks_too() {
    let (_agent, sock) = host_agent();
    let caps = vec![ssh_agent(&[Install, Runtime], &["git"], false)];
    let (t, result, _) = kit_agent_create(&[("SSH_AUTH_SOCK", &sock)], false, caps);
    result.unwrap();
    let (create, hook) = create_and_hook(&t);
    assert!(create.contains(":/run/ssh-agent.sock"), "{create}");
    assert!(create.contains(AGENT_ENV), "{create}");
    assert!(
        create.contains(r#"sbx.ssh-agent={"runtime":{"sign":["git"]},"install":{"sign":["git"]}}"#),
        "{create}"
    );
    assert!(
        hook.contains("export SSH_AUTH_SOCK=/run/ssh-agent.sock && "),
        "{hook}"
    );
}

#[test]
fn an_install_only_grant_sets_ssh_auth_sock_only_for_install_hooks() {
    let (_agent, sock) = host_agent();
    let caps = vec![ssh_agent(&[Install], &[], false)];
    let (t, result, _) = kit_agent_create(&[("SSH_AUTH_SOCK", &sock)], false, caps);
    result.unwrap();
    let (create, hook) = create_and_hook(&t);
    assert!(create.contains(":/run/ssh-agent.sock"), "{create}");
    assert!(!create.contains("SSH_AUTH_SOCK"), "{create}");
    assert!(
        create.contains(r#"sbx.ssh-agent={"install":{"sign":null}}"#),
        "{create}"
    );
    assert!(
        hook.contains("export SSH_AUTH_SOCK=/run/ssh-agent.sock && "),
        "{hook}"
    );
}

#[test]
fn a_v3_workload_without_a_grant_gets_no_agent() {
    let (_agent, sock) = host_agent();
    let (t, result, _) = kit_agent_create(&[("SSH_AUTH_SOCK", &sock)], false, vec![]);
    result.unwrap();
    let (create, hook) = create_and_hook(&t);
    assert!(!create.contains("ssh-agent"), "{create}");
    assert!(!create.contains("SSH_AUTH_SOCK"), "{create}");
    assert!(!hook.contains("SSH_AUTH_SOCK &&"), "{hook}");
}

#[test]
fn a_required_grant_without_an_agent_refuses_before_creating() {
    for (env, why) in [
        (vec![], "SSH_AUTH_SOCK is unset".to_string()),
        (
            vec![("SSH_AUTH_SOCK", "/nonexistent/agent.sock")],
            "/nonexistent/agent.sock doesn't exist".to_string(),
        ),
    ] {
        let caps = vec![ssh_agent(&[Runtime], &[], false)];
        let (_t, result, lines) = kit_agent_create(&env, false, caps);
        assert_eq!(
            format!("{:#}", result.unwrap_err()),
            format!("kit k: com.docker.sandbox/ssh-agent@1 needs an SSH agent, but {why}")
        );
        assert!(
            !lines.iter().any(|l| l.starts_with("machine create")),
            "{lines:#?}"
        );
    }
    let (_agent, sock) = host_agent();
    let caps = vec![ssh_agent(&[Runtime], &[], false)];
    let env = [
        ("SSH_AUTH_SOCK", sock.as_str()),
        ("SMOLBENTO_SSH_AGENT_FORWARDING", "false"),
    ];
    let (_t, result, _) = kit_agent_create(&env, false, caps);
    assert_eq!(
        format!("{:#}", result.unwrap_err()),
        "kit k: com.docker.sandbox/ssh-agent@1 needs an SSH agent, but ssh.agentForwardingEnabled is false"
    );
}

#[test]
fn an_optional_grant_without_an_agent_is_dropped() {
    for preset in [true, false] {
        let caps = if preset {
            vec![]
        } else {
            vec![ssh_agent(&[Install, Runtime], &[], true)]
        };
        let (t, result, _) = kit_agent_create(&[], preset, caps);
        result.unwrap();
        let (create, hook) = create_and_hook(&t);
        assert!(!create.contains("ssh-agent"), "{create}");
        assert!(!create.contains("SSH_AUTH_SOCK"), "{create}");
        assert!(!hook.contains("SSH_AUTH_SOCK &&"), "{hook}");
    }
}

/// What `prepare_create` prints: a note for a kit's dropped grant, none for the implicit one.
#[test]
fn only_a_kit_grant_dropped_for_want_of_an_agent_leaves_a_note() {
    let t = test_env(&[]);
    let plan = agent_plan(false, vec![ssh_agent(&[Runtime], &[], true)]);
    let mut req = agent_request(false);
    let notes = settle_agent(&t.ctx, &mut req, Some(&plan), |_| panic!("checked")).unwrap();
    assert_eq!(
        notes,
        [
            "kit k: no SSH agent for the runtime phase (SSH_AUTH_SOCK is unset); continuing \
              without one"
        ]
    );
    assert_eq!(req.ssh_agent, None);
    let plan = agent_plan(true, vec![]);
    let mut req = agent_request(true);
    let notes = settle_agent(&t.ctx, &mut req, Some(&plan), |_| panic!("checked")).unwrap();
    assert!(notes.is_empty(), "{notes:?}");
    assert_eq!(req.ssh_agent, None);
}

/// An unsafe socket directory refuses a required grant and drops an optional or implicit one.
#[test]
fn an_unsafe_socket_dir_refuses_a_required_grant_and_drops_the_rest() {
    let (_agent, sock) = host_agent();
    let t = test_env(&[("SSH_AUTH_SOCK", &sock)]);
    let dir = crate::bridge::socket_dir();
    let plan = agent_plan(false, vec![ssh_agent(&[Runtime], &[], false)]);
    let mut req = agent_request(false);
    let e = settle_agent(&t.ctx, &mut req, Some(&plan), |_| false).unwrap_err();
    assert_eq!(
        e.to_string(),
        format!(
            "kit k: com.docker.sandbox/ssh-agent@1 needs an SSH agent, but {} isn't a private directory owned \
                 by you",
            dir.display()
        )
    );
    let unsafe_dir = |phase: &str| {
        format!(
            "no SSH agent for the {phase} phase ({} isn't a private directory owned by you); \
                 continuing without one",
            dir.display()
        )
    };
    for (preset, caps, want) in [
        (
            false,
            vec![ssh_agent(&[Install, Runtime], &[], true)],
            vec![
                format!("kit k: {}", unsafe_dir("install")),
                format!("kit k: {}", unsafe_dir("runtime")),
            ],
        ),
        (
            true,
            vec![],
            vec![format!("warning: s1: {}", unsafe_dir("runtime"))],
        ),
    ] {
        let plan = agent_plan(preset, caps);
        let mut req = agent_request(preset);
        let mut checked = None;
        let notes = settle_agent(&t.ctx, &mut req, Some(&plan), |d| {
            checked = Some(d.to_path_buf());
            false
        })
        .unwrap();
        assert_eq!(checked.as_deref(), Some(dir.as_path()));
        assert_eq!(notes, want);
        assert_eq!(req.ssh_agent, None);
    }
    // A private one keeps an optional grant, and the required one; no grant checks nothing.
    let plan = agent_plan(false, vec![ssh_agent(&[Runtime], &[], true)]);
    let mut req = agent_request(false);
    assert!(
        settle_agent(&t.ctx, &mut req, Some(&plan), |_| true)
            .unwrap()
            .is_empty()
    );
    assert!(req.ssh_agent.is_some());
    let plan = agent_plan(false, vec![]);
    let mut req = agent_request(false);
    let notes = settle_agent(&t.ctx, &mut req, Some(&plan), |_| panic!("checked")).unwrap();
    assert!(notes.is_empty(), "{notes:?}");
    assert_eq!(req.ssh_agent, None);
    let mut req = agent_request(false);
    let plan = agent_plan(false, vec![ssh_agent(&[Runtime], &[], false)]);
    assert!(
        settle_agent(&t.ctx, &mut req, Some(&plan), |_| true)
            .unwrap()
            .is_empty()
    );
    assert!(req.ssh_agent.is_some());
}

/// When the host-service socket path exceeds macOS's limit (`plan()` returns `None` and create
/// falls back to `bridge::socket_dir()`), `settle_agent` must check that fallback directory.
#[test]
fn settle_agent_checks_fallback_socket_dir_when_service_socket_path_is_too_long() {
    let (_agent, sock) = host_agent();
    let mut t = test_env(&[("SSH_AUTH_SOCK", &sock)]);
    let long = tempfile::tempdir_in("/tmp").unwrap();
    let deep = long.path().join("a".repeat(80));
    std::fs::create_dir_all(&deep).unwrap();
    let (svc, _ctl) =
        crate::host_service::fake::services(&deep, crate::host_service::Flavor::Launchd, "ns1");
    assert!(svc.usable());
    assert!(
        svc.plan("s1").is_none(),
        "service path must exceed socket limit"
    );
    let svc_dir = svc.sock_dir().to_path_buf();
    t.ctx.services = svc;

    let fallback = crate::bridge::socket_dir();
    let plan = agent_plan(false, vec![ssh_agent(&[Runtime], &[], false)]);
    let mut req = agent_request(false);
    let mut checked = None;
    let err = settle_agent(&t.ctx, &mut req, Some(&plan), |d| {
        checked = Some(d.to_path_buf());
        // The service dir is private, but the fallback dir we'll actually mount is NOT.
        d == svc_dir
    })
    .unwrap_err();
    assert_eq!(checked.as_deref(), Some(fallback.as_path()));
    assert!(
        err.to_string().contains(&fallback.display().to_string()),
        "{err}"
    );
}

/// An env where `s1` (with the github secret bound) can be created under
/// `network.egress=<egress>`, plus `env`; returns it and its fake service manager.
fn egress_env(
    egress: &str,
    env: &[(&str, &str)],
) -> (TestEnv, crate::host_service::fake::FakeControl) {
    let mut env = env.to_vec();
    env.push(("SMOLBENTO_NETWORK_EGRESS", egress));
    let (t, ctl) = service_env(&env);
    save_secret(&t, "github", None, "gh-123");
    (t, ctl)
}

/// An env with a fake service manager where `s1` can be created with no secret, under `env`.
fn service_env(env: &[(&str, &str)]) -> (TestEnv, crate::host_service::fake::FakeControl) {
    let mut t = test_env(env);
    // A hosted sandbox needs its egress unit: a fake service manager under a short temp dir.
    let tmp = tempfile::Builder::new()
        .prefix("sbe")
        .tempdir_in("/tmp")
        .unwrap();
    let (services, ctl) = crate::host_service::fake::services(
        tmp.path(),
        crate::host_service::Flavor::Launchd,
        "ns1",
    );
    t.ctx.services = services;
    std::mem::forget(tmp);
    set_policy(&t, "mode = \"deny-all\"");
    let fake = t.runner();
    fake.fail(&["machine", "status"], "NOT_FOUND", "vm not found");
    fake.once_ok(
        &["machine", "status"],
        &machine_json("sbx-s1", "created", &[("sbx.name", "s1")]),
    );
    fake.missing_until_created("sbx-s1");
    (t, ctl)
}

/// Creates `s1` in `egress_env`; returns the env, the request as prepared and the result.
fn egress_create(
    egress: &str,
    tweak: impl FnOnce(&mut CreateRequest),
) -> (TestEnv, CreateRequest, Result<Sandbox>) {
    let (t, _) = egress_env(egress, &[]);
    let mut req = CreateRequest {
        name: "s1".into(),
        ..Default::default()
    };
    tweak(&mut req);
    let result = create_with(&t.ctx, &mut req, &[], None, None, &mut |_| {});
    (t, req, result)
}

#[test]
fn a_hosted_create_passes_no_credential_and_mounts_the_ca() {
    let (t, req, result) = egress_create("hosted", |_| {});
    result.unwrap();
    let label = req.egress.as_ref().expect("prepared").label.clone();
    let placeholder = &label
        .bindings
        .iter()
        .find(|b| b.env == "GH_TOKEN")
        .unwrap()
        .placeholder;
    let create = t.create_line();
    assert!(!create.contains("--credential"), "{create}");
    let ca = t.ctx.paths.egress("s1").join("ca/guest");
    assert!(
        create.contains(&format!("-v {}:/run/smol/credentials:ro", ca.display())),
        "{create}"
    );
    assert!(
        create.contains(&format!("-e GH_TOKEN={placeholder}")),
        "{create}"
    );
    for var in [
        "SSL_CERT_FILE",
        "NODE_EXTRA_CA_CERTS",
        "REQUESTS_CA_BUNDLE",
        "CURL_CA_BUNDLE",
        "GIT_SSL_CAINFO",
    ] {
        assert!(
            create.contains(&format!("-e {var}=/run/smolvm/ca-bundle.pem")),
            "{create}"
        );
    }
    assert!(create.contains("sbx.egress="), "{create}");
    assert!(!create.contains("gh-123"), "{create}");
}

#[test]
fn an_install_agent_grant_doesnt_hold_back_the_egress_unit() {
    // The other units wait for the install hooks; their port-443 flows need the egress process.
    let (_agent, sock) = host_agent();
    let (t, ctl) = egress_env("hosted", &[("SSH_AUTH_SOCK", &sock)]);
    let plan = agent_plan(false, vec![ssh_agent(&[Install], &[], false)]);
    let mut req = agent_request(false);
    let mut at_created = Vec::new();
    create_with(&t.ctx, &mut req, &[], Some(&plan), None, &mut |e| {
        if e == sandbox::Event::Created {
            at_created = ctl.calls();
        }
    })
    .unwrap();
    assert!(req.egress.is_some());
    assert_eq!(at_created, ["refresh", "load dev.smolbento.ns1.s1.egress"]);
}

#[test]
fn no_service_manager_falls_back_to_smolvm() {
    // The default (hosted), and a test context with no service manager.
    let t = test_env(&[]);
    set_policy(&t, "mode = \"deny-all\"");
    save_secret(&t, "github", None, "gh-123");
    let mut req = CreateRequest {
        name: "s1".into(),
        ..Default::default()
    };
    prepare_create(&t.ctx, &mut req, &[], None).unwrap();
    assert!(req.egress.is_none());
    assert!(!t.ctx.paths.egress("s1").exists());
    let spec = sandbox::create::spec(&req);
    assert!(!spec.labels.contains_key("sbx.egress"));
    // smolvm swaps the credential, as with network.egress=smolvm.
    assert!(!spec.credentials.is_empty());
}

#[test]
fn a_sandbox_without_credentials_is_hosted() {
    // The default setting, with a service manager and no secret.
    let (t, _) = service_env(&[]);
    let mut req = CreateRequest {
        name: "s1".into(),
        ..Default::default()
    };
    create_with(&t.ctx, &mut req, &[], None, None, &mut |_| {}).unwrap();
    let label = &req.egress.as_ref().expect("hosted").label;
    assert!(label.bindings.is_empty());
    let starts = t.calls_of("machine start");
    assert!(
        starts[0].contains(&format!("--egress-interceptor 127.0.0.1:{}", label.port)),
        "{starts:?}"
    );
    let token = crate::egress::token(&t.ctx.paths, "s1").unwrap();
    assert_eq!(
        t.runner().envs().last().unwrap(),
        &vec![("SMOLVM_INTERCEPTOR_TOKEN".to_string(), token)]
    );
    // Nothing is terminated, so the guest gets no CA and no trust variables.
    let create = t.create_line();
    assert!(!create.contains("/run/smol/credentials"), "{create}");
    assert!(!create.contains("SSL_CERT_FILE"), "{create}");
    assert!(create.contains("sbx.egress="), "{create}");
}

#[test]
fn a_hosted_create_keeps_the_users_ca_env() {
    let (t, _, result) = egress_create("hosted", |r| {
        r.env.push(("SSL_CERT_FILE".into(), "/mine.pem".into()));
    });
    result.unwrap();
    let create = t.create_line();
    assert!(create.contains("-e SSL_CERT_FILE=/mine.pem"), "{create}");
    assert!(!create.contains("SSL_CERT_FILE=/run/smolvm"), "{create}");
}

#[test]
fn a_hosted_create_gives_a_bound_variable_only_its_placeholder() {
    let (t, req, result) = egress_create("hosted", |r| {
        r.env.push(("GH_TOKEN".into(), "mine".into()));
        r.env.push(("OTHER".into(), "kept".into()));
    });
    result.unwrap();
    let label = &req.egress.as_ref().unwrap().label;
    let placeholder = &label
        .bindings
        .iter()
        .find(|b| b.env == "GH_TOKEN")
        .unwrap()
        .placeholder;
    let create = t.create_line();
    assert_eq!(create.matches("-e GH_TOKEN=").count(), 1, "{create}");
    assert!(
        create.contains(&format!("-e GH_TOKEN={placeholder}")),
        "{create}"
    );
    // Only bound variables give way: a user's own variable stays.
    assert!(create.contains("-e OTHER=kept"), "{create}");
}

#[test]
fn network_egress_smolvm_creates_as_before() {
    let (t, req, result) = egress_create("smolvm", |_| {});
    result.unwrap();
    assert!(req.egress.is_none());
    assert!(!t.ctx.paths.egress("s1").exists());
    let create = t.create_line();
    assert!(create.contains("--credential"), "{create}");
    assert!(!create.contains("/run/smol/credentials"), "{create}");
    assert!(!create.contains("SSL_CERT_FILE"), "{create}");
    assert!(!create.contains("sbx.egress"), "{create}");
    assert!(
        t.calls_of("machine start")
            .iter()
            .all(|l| !l.contains("--egress-interceptor"))
    );
}

#[test]
fn install_only_credentials_fall_back_to_smolvm() {
    let (t, req, result) = egress_create("hosted", |r| {
        r.rec.credential_install = vec!["GH_TOKEN".into()];
    });
    result.unwrap();
    assert!(req.egress.is_none());
    assert!(!t.ctx.paths.egress("s1").exists());
    let create = t.create_line();
    assert!(create.contains("--credential"), "{create}");
    assert!(!create.contains("sbx.egress"), "{create}");
    assert!(
        t.calls_of("machine start")
            .iter()
            .all(|l| !l.contains("--egress-interceptor"))
    );
}

#[test]
fn a_hosted_start_passes_the_interceptor_and_token_not_values() {
    let (t, req, result) = egress_create("hosted", |_| {});
    result.unwrap();
    let starts = t.calls_of("machine start");
    let port = req.egress.as_ref().unwrap().label.port;
    assert!(
        starts[0].contains(&format!("--egress-interceptor 127.0.0.1:{port}")),
        "{starts:?}"
    );
    let token = crate::egress::token(&t.ctx.paths, "s1").unwrap();
    let envs = t.runner().envs();
    let start_env = envs.last().unwrap();
    assert_eq!(
        start_env,
        &vec![("SMOLVM_INTERCEPTOR_TOKEN".to_string(), token)]
    );
    // A later start is the same.
    let mut m = meta("s1", &["github".to_string()], &[]);
    m.egress = req.egress.map(|p| p.label);
    let plan = start_plan(&t.ctx, &m).unwrap();
    assert_eq!(
        plan.egress,
        Some(std::net::SocketAddr::from(([127, 0, 0, 1], port)))
    );
    assert_eq!(plan.env.len(), 1);
    assert!(plan.env.iter().all(|(_, v)| v != "gh-123"));
}

#[test]
fn a_start_fails_closed_when_the_egress_label_is_unreadable() {
    let t = deny_all_env();
    save_secret(&t, "github", None, "gh-123");
    let mut m = meta("s1", &["github".to_string()], &[]);
    m.rec.egress_unreadable = true;
    let e = start_plan(&t.ctx, &m).unwrap_err().to_string();
    assert!(e.contains("sbx.egress label is unreadable"), "{e}");
}

#[test]
fn rm_forgets_the_egress_state() {
    let mut t = test_env(&[]);
    let cred = crate::smolvm::Credential {
        env_var: "GH_TOKEN".into(),
        hosts: vec!["api.github.com".into()],
        ..Default::default()
    };
    crate::egress::prepare(&t.ctx.paths, "box", &[cred]).unwrap();
    assert!(t.ctx.paths.egress("box").exists());
    t.sandbox("box", "stopped", &[]);
    t.runner().ok(
        &["machine", "ls", "--json"],
        &format!("[{}]", sandbox_json("box", "stopped", &[])),
    );
    t.sbt(&["rm", "-f", "box"]).unwrap();
    assert!(!t.ctx.paths.egress("box").exists());
}

#[test]
fn a_start_fails_closed_when_a_hosted_sandbox_lost_its_label() {
    let t = deny_all_env();
    save_secret(&t, "github", None, "gh-123");
    let labels =
        r#"{"sbx.name":"s1","sbx.secrets":"github","sbx.credential-env":"GH_TOKEN,GITHUB_TOKEN"}"#;
    let machine = |creds: &str| -> crate::smolvm::Machine {
        serde_json::from_str(&format!(
            r#"{{"name":"sbx-s1","state":"stopped","labels":{labels}{creds}}}"#
        ))
        .unwrap()
    };
    let sb = Sandbox::from_machine(&machine(r#","credentials":[]"#)).unwrap();
    let e = start_plan(&t.ctx, &sb.meta).unwrap_err().to_string();
    assert!(e.contains("has no sbx.egress label"), "{e}");
    assert!(t.runner().envs().is_empty());
    // Bindings listed, or a smolvm that doesn't say: a smolvm-mode start as before.
    for creds in [
        r#","credentials":[{"name":"gh_token","variable":"GH_TOKEN","hosts":["api.github.com"]}]"#,
        "",
    ] {
        let sb = Sandbox::from_machine(&machine(creds)).unwrap();
        let plan = start_plan(&t.ctx, &sb.meta).unwrap();
        assert!(plan.egress.is_none());
        assert!(plan.env.iter().any(|(_, v)| v == "gh-123"));
    }
}
