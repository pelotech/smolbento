use crate::sandbox::session;
use crate::testutil::*;

#[test]
fn agent_args_rule() {
    let base = &["claude", "--dangerously-skip-permissions"];
    let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
    assert_eq!(super::command_with_args(base, &[]), s(base));
    assert_eq!(
        super::command_with_args(base, &s(&["-c"])),
        s(&["claude", "--dangerously-skip-permissions", "-c"])
    );
    assert_eq!(
        super::command_with_args(base, &s(&["mcp", "list"])),
        s(&["claude", "mcp", "list"])
    );
}
#[test]
fn clone_is_ignored_when_run_attaches_to_an_existing_sandbox() {
    let mut t = test_env(&[]);
    t.project("running");
    t.runner().interactive_exit(0);
    // cwd is not a git repo, yet --clone must not matter for an existing sandbox.
    t.sbt(&["run", "claude", "--clone"]).unwrap();
    assert!(!t.made("machine create"));
}

#[test]
fn workdir_starts_the_session_in_a_directory_of_the_workspace() {
    for (given, want) in [("src/app", "/src/app"), ("/tmp/x", "")] {
        let mut t = test_env(&[]);
        t.project_creatable();
        t.runner().interactive_exit(0);
        t.sbt(&["run", "claude", "--cpus", "1", "-m", "1g", "-w", given])
            .unwrap();
        let ws = t.ctx.cwd.display().to_string();
        let dir = if want.is_empty() {
            given.to_string()
        } else {
            format!("{ws}{want}")
        };
        let call = t.runner().interactive_calls()[0].join(" ");
        assert!(call.contains(&format!(" -w {dir} -i ")), "{call}");
    }
}

/// The labels of a sandbox running `claude` with the `sbx.workspaces` label `ws`.
fn claude_in(ws: &str) -> [(&str, &str); 3] {
    [
        ("sbx.agent", "claude"),
        ("sbx.command", r#"["claude"]"#),
        ("sbx.workspaces", ws),
    ]
}

/// Two folders with the same name (sbx 0.53): a plain `run` attaches to this folder's sandbox,
/// whatever it's called, and never to the other folder's.
#[test]
fn run_reuses_this_folders_sandbox_under_another_name() {
    let mut t = test_env(&[]);
    let ws = t.ctx.cwd.display().to_string();
    t.sandboxes(&[
        (
            "claude-proj-2",
            "running",
            &claude_in(&workspaces_label(&[&ws])),
        ),
        ("claude-proj", "running", &claude_in(r#"["/other/proj"]"#)),
    ]);
    t.runner().interactive_exit(0);
    t.sbt(&["run", "claude"]).unwrap();
    let call = t.runner().interactive_calls()[0].join(" ");
    assert!(
        call.starts_with("machine exec --name sbx-claude-proj-2 "),
        "{call}"
    );
    assert!(!t.made("machine create"));
}

#[test]
fn run_refuses_a_default_name_another_folder_uses_and_suggests_one() {
    let mut t = test_env(&[]);
    t.sandboxes(&[("claude-proj", "running", &claude_in(r#"["/other/proj"]"#))]);
    let err = t.sbt_err(&["run", "claude"]);
    assert!(
        err.starts_with(
            "sandbox name \"claude-proj\" is already used by workspace \"/other/proj\"; pass \
                 --name to choose a different name, such as --name claude-"
        ) && err.ends_with("-proj"),
        "{err}"
    );
    assert!(t.runner().interactive_calls().is_empty());
    assert!(!t.made("machine create"));
    // `--name` is taken as given: it attaches to that sandbox.
    t.runner().interactive_exit(0);
    t.sbt(&["run", "--name", "claude-proj"]).unwrap();
    let call = t.runner().interactive_calls()[0].join(" ");
    assert!(
        call.starts_with("machine exec --name sbx-claude-proj "),
        "{call}"
    );
}

#[test]
fn creates_attaches_and_stops_after_the_last_session() {
    let mut t = test_env(&[]);
    t.project_creatable();
    t.runner().interactive_exit(0);
    assert_eq!(
        t.sbt(&["run", "claude", "--cpus", "1", "-m", "1g", "--", "-c"])
            .unwrap(),
        0
    );

    let ws = t.ctx.cwd.display().to_string();
    assert_eq!(
        t.runner().interactive_calls()[0].join(" "),
        format!(
            "machine exec --name sbx-claude-proj -u agent -w {ws} -i -- claude --dangerously-skip-permissions -c"
        )
    );
    let lines = t.calls();
    assert!(
        lines
            .iter()
            .any(|l| l.starts_with("machine create -n sbx-claude-proj"))
    );
    assert!(
            lines
                .iter()
                .any(|l| l.starts_with("machine create ")
                    && l.ends_with(" -u agent -- sleep infinity")),
            "the workload user is the session user: {lines:?}"
        );
    assert_eq!(lines.last().unwrap(), "machine stop -n sbx-claude-proj");
    assert_eq!(
        session::live_sessions(&t.ctx.paths.sessions(), "claude-proj"),
        0
    );
}

/// `run -d claude` of a new sandbox, with `extra` args; returns stdout.
fn run_new(extra: &[&str]) -> String {
    let mut t = test_env(&[]);
    t.project_creatable();
    let args: Vec<&str> = ["run", "-d", "claude", "--cpus", "1", "-m", "1g"]
        .into_iter()
        .chain(extra.iter().copied())
        .collect();
    t.sbt(&args).unwrap();
    t.stdout()
}

#[test]
fn run_of_a_new_sandbox_reports_the_create_without_a_hint() {
    let out = run_new(&[]);
    assert!(
        out.starts_with("\nSANDBOX\n  Name:       claude-proj\n"),
        "{out}"
    );
    assert!(
        out.ends_with("  ✓ docker — installed\n\n  ✓ Created sandbox claude-proj\nclaude-proj\n"),
        "{out}"
    );
    assert!(!out.contains("try:"), "{out}");
}

#[test]
fn no_progress_leaves_only_the_detached_name() {
    assert_eq!(run_new(&["--no-progress"]), "claude-proj\n");
}

#[test]
fn run_of_an_existing_sandbox_reports_no_progress() {
    let mut t = test_env(&[]);
    t.project("stopped");
    t.sbt(&["run", "-d", "--name", "claude-proj"]).unwrap();
    assert_eq!(t.stdout(), "claude-proj\n");
}

#[test]
fn a_failed_create_does_not_leave_deny_rules_behind() {
    let mut t = test_env(&[]);
    let fake = t.runner();
    fake.fail(&["machine", "status"], "NOT_FOUND", "vm not found");
    fake.fail(&["machine", "create"], "CREATE_FAILED", "no space left");
    assert!(
        t.sbt(&["run", "claude", "--deny-network", "evil.com"])
            .is_err()
    );
    let p = crate::policy::Policy::load(&t.ctx.paths).unwrap();
    assert!(p.sandboxes.is_empty(), "{p:?}");
}

#[test]
fn deny_network_adds_sandbox_deny_rules_at_create() {
    let mut t = test_env(&[]);
    t.project_creatable();
    t.runner().interactive_exit(0);
    t.sbt(&[
        "run",
        "claude",
        "--deny-network",
        "a.example,b.example",
        "--deny-network",
        "c.example",
    ])
    .unwrap();
    let p = crate::policy::Policy::load(&t.ctx.paths).unwrap();
    let rules: Vec<Vec<String>> = p.sandboxes["claude-proj"]
        .rules
        .iter()
        .map(|r| {
            assert_eq!(r.decision, crate::policy::Decision::Deny);
            r.resources.clone()
        })
        .collect();
    assert_eq!(
        rules,
        vec![
            vec!["a.example".to_string()],
            vec!["b.example".to_string()],
            vec!["c.example".to_string()]
        ]
    );
    assert!(p.rules.is_empty());
}

#[test]
fn running_an_existing_sandbox_records_nothing_and_starting_it_needs_a_policy() {
    let mut t = test_env(&[]);
    std::fs::remove_file(t.ctx.paths.policy_file()).unwrap();
    t.project("running");
    t.runner().interactive_exit(0);
    assert_eq!(
        t.sbt(&["run", "claude", "--deny-network", "evil.com"])
            .unwrap(),
        0
    );
    assert!(!t.ctx.paths.policy_file().exists());
    let lines = t.calls();
    assert!(!lines.iter().any(|l| l.contains("create")), "{lines:?}");

    // A stopped one has to start, and every start needs a policy.
    let mut t = test_env(&[]);
    std::fs::remove_file(t.ctx.paths.policy_file()).unwrap();
    t.project("stopped");
    let err = t.sbt_err(&["run", "claude", "--deny-network", "evil.com"]);
    assert!(err.contains("bento policy init"), "{err}");
    assert!(!t.ctx.paths.policy_file().exists());
    let lines = t.calls();
    assert!(
        !lines
            .iter()
            .any(|l| l.contains("create") || l.contains("start")),
        "{lines:?}"
    );
}

#[test]
fn reattaches_by_name_and_returns_the_agent_status() {
    let mut t = test_env(&[]);
    t.project("running");
    t.runner().interactive_exit(42);
    assert_eq!(t.sbt(&["run", "--name", "claude-proj"]).unwrap(), 42);
    assert!(!t.calls().iter().any(|l| l.contains("create")));
}

#[test]
fn detach_leaves_it_running_and_later_runs_keep_it() {
    let mut t = test_env(&[]);
    t.project("running");
    t.sbt(&["run", "-d", "--name", "claude-proj"]).unwrap();
    assert!(t.runner().interactive_calls().is_empty());
    t.sbt(&["run", "--name", "claude-proj"]).unwrap();
    assert!(!t.calls().iter().any(|l| l.contains("stop")));
}

#[test]
fn rm_deletes_after_exit() {
    let mut t = test_env(&[]);
    t.project("running");
    t.sbt(&["run", "--rm", "--name", "claude-proj"]).unwrap();
    assert_eq!(
        t.calls().last().unwrap(),
        "machine delete -n sbx-claude-proj -f"
    );
}

#[test]
fn create_options_on_an_existing_sandbox_get_a_warning() {
    use clap::Parser;
    let parse = |args: &[&str]| match super::super::Cli::try_parse_from(args).unwrap().command {
        Some(super::super::Cmd::Run(a)) => a,
        _ => unreachable!(),
    };
    assert_eq!(
        super::ignored_options_warning(
            &parse(&["sbt", "run", "--name", "s1", "--cpus", "8"]),
            "s1"
        )
        .as_deref(),
        Some("warning: --cpus only applies when a sandbox is created; s1 already exists")
    );
    assert_eq!(
        super::ignored_options_warning(
            &parse(&[
                "sbt", "run", "--name", "s1", "-m", "4g", "-e", "A=1", "--clone"
            ]),
            "s1"
        )
        .as_deref(),
        Some(
            "warning: --memory, --env, --clone only apply when a sandbox is created; s1 \
                 already exists"
        )
    );
    assert_eq!(
        super::ignored_options_warning(
            &parse(&["sbt", "run", "--name", "s1", "--static-mcp", "linear"]),
            "s1"
        )
        .as_deref(),
        Some("warning: --static-mcp only applies when a sandbox is created; s1 already exists")
    );
    assert_eq!(
        super::ignored_options_warning(&parse(&["sbt", "run", "--name", "s1"]), "s1"),
        None
    );
}

#[test]
fn a_session_that_cant_be_registered_still_stops_the_sandbox() {
    let mut t = test_env(&[]);
    t.project("stopped");
    // The sessions directory can't be created: a file is in its place.
    let sessions = t.ctx.paths.sessions();
    std::fs::create_dir_all(sessions.parent().unwrap()).unwrap();
    std::fs::write(&sessions, b"").unwrap();
    let err = t.sbt(&["run", "--name", "claude-proj"]).unwrap_err();
    assert!(!format!("{err:#}").is_empty());
    assert!(t.made("machine start"), "{:#?}", t.calls());
    assert_eq!(
        t.calls().last().unwrap(),
        "machine stop -n sbx-claude-proj",
        "{:#?}",
        t.calls()
    );
}

#[test]
fn rm_keeps_a_sandbox_another_session_is_using() {
    let mut t = test_env(&[]);
    t.project("running");
    // A live session of another process (this test's parent).
    let dir = t.ctx.paths.sessions().join("claude-proj");
    std::fs::create_dir_all(&dir).unwrap();
    let pid = std::os::unix::process::parent_id();
    std::fs::write(dir.join(pid.to_string()), b"").unwrap();
    t.sbt(&["run", "--rm", "--name", "claude-proj"]).unwrap();
    assert!(!t.made("machine delete"), "{:#?}", t.calls());
    assert!(!t.made("machine stop"), "{:#?}", t.calls());
}

#[test]
fn a_failed_attach_still_stops_or_removes_the_sandbox() {
    for (flags, cleanup) in [
        (vec![], "machine stop -n sbx-claude-proj"),
        (vec!["--rm"], "machine delete -n sbx-claude-proj -f"),
    ] {
        let mut t = test_env(&[]);
        t.project("running");
        t.runner().interactive_fail("can't run smolvm");
        let mut args = vec!["run"];
        args.extend(flags);
        args.extend(["--name", "claude-proj"]);
        let err = t.sbt_err(&args);
        assert!(err.contains("can't run smolvm"), "{err}");
        assert_eq!(t.calls().last().unwrap(), cleanup);
        // No session of ours is left behind either.
        assert!(session::idle(&t.ctx.paths.sessions(), "claude-proj"));
    }
}

#[test]
fn rm_forgets_the_sandbox_policy_and_scoped_secrets_like_sbt_rm() {
    use crate::policy::{Decision, Policy};
    use crate::secrets::{SecretEntry, SecretsFile, Source, scope_for};
    let mut t = test_env(&[]);
    t.project("running");
    let mut p = Policy::load(&t.ctx.paths).unwrap();
    p.add_rule(
        Some("claude-proj"),
        Decision::Allow,
        "a.com",
        "added",
        None,
        None,
    )
    .unwrap();
    p.save(&t.ctx.paths).unwrap();
    let mut f = SecretsFile::default();
    for scope in [Some("claude-proj"), None] {
        let entry = SecretEntry {
            service: "github".into(),
            scope: scope_for(scope),
            source: Source::Keychain,
        };
        t.ctx.store.set(&entry.account(), "tok").unwrap();
        f.set(entry);
    }
    f.save(&t.ctx.paths).unwrap();

    t.sbt(&["run", "--rm", "--name", "claude-proj"]).unwrap();

    let p = Policy::load(&t.ctx.paths).unwrap();
    assert!(!p.sandboxes.contains_key("claude-proj"), "{p:?}");
    let f = SecretsFile::load(&t.ctx.paths).unwrap();
    let scopes: Vec<_> = f.secrets.iter().map(|e| e.scope.as_str()).collect();
    assert_eq!(scopes, [scope_for(None)]);
}

#[test]
fn cleanup_failures_warn_and_keep_the_agent_status() {
    let mut t = test_env(&[]);
    t.project("running");
    t.runner().interactive_exit(7);
    t.runner()
        .fail(&["machine", "stop"], "SMOLVM_ERROR", "boom");
    assert_eq!(t.sbt(&["run", "--name", "claude-proj"]).unwrap(), 7);
    t.runner()
        .fail(&["machine", "delete"], "SMOLVM_ERROR", "boom");
    assert_eq!(t.sbt(&["run", "--rm", "--name", "claude-proj"]).unwrap(), 7);
}

#[test]
fn unsupported_flags_exit_2_even_without_a_usable_smolvm() {
    let mut t = test_env(&[]);
    t.runner().ok(&["--version"], "smolvm 1.0.0\n");
    for args in [
        &["run", "claude", "--ttl", "1h"][..],
        &["create", "claude", "--ttl", "1h"][..],
        &["run", "claude", "--new"][..],
    ] {
        let err = t.sbt(args).unwrap_err();
        assert_eq!(super::super::exit_code(&err), 2, "{args:?}: {err}");
    }
    assert!(t.runner().calls().is_empty());
}

#[test]
fn argument_errors() {
    let mut t = test_env(&[]);
    assert!(t.sbt_err(&["run"]).contains("specify an agent"));
    assert!(t.sbt_err(&["run", "-d", "--rm", "claude"]).contains("--rm"));
}

fn clone_sandbox(t: &TestEnv, ws: &std::path::Path) {
    t.machine(
        "sbx-claude-proj",
        "running",
        &[
            ("sbx.name", "claude-proj"),
            ("sbx.agent", "claude"),
            ("sbx.command", r#"["claude"]"#),
            (
                "sbx.workspaces",
                &workspaces_label(&[&ws.display().to_string()]),
            ),
            ("sbx.clone", &ws.display().to_string()),
        ],
    );
}

#[test]
fn a_failed_fetch_warns_and_keeps_the_agent_status_and_the_stop() {
    let mut t = test_env(&[]);
    // The remote's upload-pack records that the fetch ran, then fails it.
    let (_keep, repo) = temp_repo();
    let marker = repo.parent().unwrap().join("fetch-ran");
    git(
        &repo,
        &[
            "remote",
            "add",
            "sandbox-claude-proj",
            "file:///sbt/claude-proj",
        ],
    );
    git(
        &repo,
        &[
            "config",
            "remote.sandbox-claude-proj.uploadpack",
            &format!("touch '{}'; exit 1 #", marker.display()),
        ],
    );
    clone_sandbox(&t, &repo);
    t.runner().interactive_exit(5);
    assert_eq!(t.sbt(&["run", "--name", "claude-proj"]).unwrap(), 5);
    assert!(marker.exists(), "the fetch was never attempted");
    assert_eq!(t.calls().last().unwrap(), "machine stop -n sbx-claude-proj");
}

#[test]
fn fetch_on_exit_needs_a_clone_and_the_setting() {
    let (_keep, repo) = temp_repo();
    for (env, clone, want) in [
        (&[][..], true, true),
        (
            &[("SMOLBENTO_CLONE_FETCH_ON_EXIT", "false")][..],
            true,
            false,
        ),
        (&[][..], false, false),
    ] {
        let t = test_env(env);
        if clone {
            clone_sandbox(&t, &repo);
        } else {
            t.project("running");
        }
        let sb = crate::sandbox::find(&t.ctx.vm, "claude-proj")
            .unwrap()
            .unwrap();
        assert_eq!(super::fetch_on_exit(&t.ctx, &sb), want);
    }
}

fn kit_sandbox(t: &TestEnv, long_running: bool) {
    let ws = workspaces_label(&[&t.ctx.cwd.display().to_string()]);
    let mut labels = vec![
        ("sbx.name", "toolbox-proj"),
        ("sbx.agent", "toolbox"),
        ("sbx.workspaces", ws.as_str()),
        ("sbx.command", r#"["/bin/agent","--x"]"#),
    ];
    if long_running {
        labels.push(("sbx.long-running", "true"));
    }
    t.machine("sbx-toolbox-proj", "running", &labels);
    t.runner().interactive_exit(0);
}

#[test]
fn run_launches_a_kit_sandboxs_command() {
    let mut t = test_env(&[]);
    kit_sandbox(&t, false);
    t.sbt(&["run", "--name", "toolbox-proj", "--", "--y", "z"])
        .unwrap();
    let ws = t.ctx.cwd.display().to_string();
    assert_eq!(
        t.runner().interactive_calls()[0].join(" "),
        format!("machine exec --name sbx-toolbox-proj -u agent -w {ws} -i -- /bin/agent --x --y z")
    );
    assert_eq!(
        t.calls().last().unwrap(),
        "machine stop -n sbx-toolbox-proj"
    );
}

/// A v3 workload kit's sandbox: its image user is recorded.
fn image_user_sandbox(t: &TestEnv) {
    let ws = t.ctx.cwd.display().to_string();
    t.machine(
        "sbx-toolbox-proj",
        "running",
        &[
            ("sbx.name", "toolbox-proj"),
            ("sbx.agent", "toolbox"),
            ("sbx.workspaces", &workspaces_label(&[&ws])),
            ("sbx.command", r#"["/bin/agent","--x"]"#),
            ("sbx.user", "somebody"),
        ],
    );
    t.runner().interactive_exit(0);
}

#[test]
fn run_launches_a_v3_workload_as_its_image_user_under_bash() {
    let mut t = test_env(&[]);
    image_user_sandbox(&t);
    t.sbt(&["run", "--name", "toolbox-proj", "--", "--y", "z"])
        .unwrap();
    let ws = t.ctx.cwd.display().to_string();
    assert_eq!(
        t.runner().interactive_calls()[0].join(" "),
        format!(
            "machine exec --name sbx-toolbox-proj -u somebody -w {ws} -i -- \
                 /bin/bash -c exec -- \"$@\" bash /bin/agent --x --y z"
        )
    );
    assert!(
        t.calls()
            .contains(&"machine exec --name sbx-toolbox-proj -- /bin/bash -c :".into())
    );
}

#[test]
fn run_launches_a_numeric_image_user_as_given() {
    let mut t = test_env(&[]);
    let ws = t.ctx.cwd.display().to_string();
    t.machine(
        "sbx-toolbox-proj",
        "running",
        &[
            ("sbx.name", "toolbox-proj"),
            ("sbx.agent", "toolbox"),
            ("sbx.workspaces", &workspaces_label(&[&ws])),
            ("sbx.command", r#"["/bin/agent"]"#),
            ("sbx.user", "1000"),
        ],
    );
    t.runner().interactive_exit(0);
    t.sbt(&["run", "--name", "toolbox-proj"]).unwrap();
    assert_eq!(
        t.runner().interactive_calls()[0].join(" "),
        format!(
            "machine exec --name sbx-toolbox-proj -u 1000 -w {ws} -i -- \
                 /bin/bash -c exec -- \"$@\" bash /bin/agent"
        )
    );
}

#[test]
fn run_without_bash_in_the_image_fails_like_sbx() {
    let mut t = test_env(&[]);
    image_user_sandbox(&t);
    t.runner().on(
        &[
            "machine",
            "exec",
            "--name",
            "sbx-toolbox-proj",
            "--",
            "/bin/bash",
        ],
        crate::smolvm::Output {
            code: 1,
            ..Default::default()
        },
    );
    let code = t.sbt(&["run", "--name", "toolbox-proj"]).unwrap();
    assert_eq!(code, 127);
    assert!(t.runner().interactive_calls().is_empty());
    assert_eq!(
        t.calls().last().unwrap(),
        "machine stop -n sbx-toolbox-proj"
    );
}

#[test]
fn a_smolvm_error_from_the_bash_probe_is_not_a_missing_bash() {
    let mut t = test_env(&[]);
    image_user_sandbox(&t);
    t.runner().fail(
        &[
            "machine",
            "exec",
            "--name",
            "sbx-toolbox-proj",
            "--",
            "/bin/bash",
        ],
        "AGENT_ERROR",
        "the guest agent is not responding",
    );
    let err = t.sbt(&["run", "--name", "toolbox-proj"]).unwrap_err();
    assert!(
        format!("{err:#}").contains("the guest agent is not responding"),
        "{err:#}"
    );
    assert!(t.runner().interactive_calls().is_empty());
}

#[test]
fn gemini_is_refused_for_a_new_sandbox() {
    let mut t = test_env(&[]);
    t.no_machine();
    let err = t.sbt_err(&["run", "gemini", "."]);
    assert!(err.starts_with("\"gemini\" is retired"), "{err}");
    assert!(!t.made("machine create"));
}

#[test]
fn attaching_to_an_existing_sandbox_loads_no_kits() {
    let mut t = kit_env();
    t.project("running");
    t.runner().interactive_exit(0);
    // Loading either would fail: the path doesn't exist.
    t.sbt(&[
        "run",
        "claude",
        "--kit",
        "./no-such-kit",
        "--kit-arg",
        "a=1",
    ])
    .unwrap();
    assert_eq!(t.runner().interactive_calls().len(), 1);
    assert!(
        !t.calls()
            .iter()
            .any(|l| l.contains("_builder") || l.starts_with("machine create"))
    );
}

#[test]
fn attaching_with_a_workload_kit_target_loads_nothing() {
    for (kit, sandbox) in [
        ("./kit", "kit-proj"),
        ("localhost:1/acme/my-kit:1", "my-kit-proj"),
    ] {
        let mut t = test_env(&[
            ("SMOLBENTO_KIT_ALLOW_LOCAL_KITS", "true"),
            ("SMOLBENTO_KIT_ALLOWED_SOURCES", r#"["localhost:1/"]"#),
        ]);
        let dir = t.ctx.cwd.join("kit");
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(
            dir.join("k.yaml"),
            "# syntax=docker/sandbox-kit:3\nschemaVersion: \"3\"\nkind: workload\n",
        )
        .unwrap();
        let ws = t.ctx.cwd.display().to_string();
        t.machine(
            &format!("sbx-{sandbox}"),
            "running",
            &[
                ("sbx.name", sandbox),
                ("sbx.agent", "kit"),
                ("sbx.workspaces", &workspaces_label(&[&ws])),
                ("sbx.command", r#"["/bin/agent"]"#),
            ],
        );
        t.runner().interactive_exit(0);
        // A build would ask smolvm for `_builder`; a pull of localhost:1 would fail.
        t.sbt(&["run", kit, "."]).unwrap();
        let lines = t.calls();
        assert!(
            !lines
                .iter()
                .any(|l| l.contains("_builder") || l.starts_with("machine create")),
            "{lines:?}"
        );
        assert_eq!(t.runner().interactive_calls().len(), 1, "{kit}");
    }
}

#[test]
fn mount_on_an_existing_sandbox_is_warned_about_and_attaches() {
    use clap::Parser;
    let warning = |args: &[&str]| {
        let cli =
            super::super::Cli::try_parse_from(std::iter::once("sbt").chain(args.iter().copied()))
                .unwrap();
        let Some(super::super::Cmd::Run(a)) = cli.command else {
            panic!("run");
        };
        super::ignored_mount_warning(&a, "s1")
    };
    assert_eq!(
        warning(&["run", "--name", "s1", "--mount", ".:/home/agent/x"]).as_deref(),
        Some("warning: --mount only applies when a sandbox is created; s1 already exists")
    );
    assert_eq!(warning(&["run", "--name", "s1"]), None);

    let mut t = test_env(&[]);
    t.project("running");
    t.runner().interactive_exit(0);
    t.sbt(&["run", "claude", "--mount", ".:/home/agent/x"])
        .unwrap();
    assert!(!t.made("machine create"));
}

#[test]
fn kit_flags_on_an_existing_sandbox_are_warned_about() {
    use clap::Parser;
    let warning = |args: &[&str]| {
        let cli =
            super::super::Cli::try_parse_from(std::iter::once("sbt").chain(args.iter().copied()))
                .unwrap();
        let Some(super::super::Cmd::Run(a)) = cli.command else {
            panic!("run");
        };
        super::ignored_kits_warning(&a, "s1")
    };
    let want =
        Some("warning: kits only apply when a sandbox is created; s1 already exists".to_string());
    assert_eq!(warning(&["run", "--name", "s1", "--kit", "./k"]), want);
    assert_eq!(
        warning(&["run", "--name", "s1", "--kit", "./k", "--kit-arg", "a=1"]),
        want
    );
    assert_eq!(warning(&["run", "./k", "."]), want);
    assert_eq!(warning(&["run", "--name", "s1"]), None);
    assert_eq!(warning(&["run", "claude", "."]), None);
}

#[test]
fn kit_args_without_a_kit_always_fail() {
    let want = "kit arguments were supplied but no kits were referenced";
    let mut t = test_env(&[]);
    t.project("running");
    t.runner().interactive_exit(0);
    // `run claude` names a kit now (sbx 0.53), so only a bare --name has none.
    for args in [
        vec!["run", "--name", "claude-proj", "--kit-arg", "a=1"],
        vec!["run", "--name", "claude-proj", "--kit-args-file", "f"],
    ] {
        let err = t.sbt(&args).unwrap_err();
        assert_eq!(format!("{err:#}"), want, "{args:?}");
    }
    assert!(t.runner().interactive_calls().is_empty());

    // A new sandbox: the agent's kit declares no such argument.
    let mut t = test_env(&[]);
    t.no_machine();
    let err = t.sbt(&["run", "claude", "--kit-arg", "a=1"]).unwrap_err();
    assert!(
        format!("{err:#}").contains("unknown kit argument a"),
        "{err:#}"
    );
    assert!(!t.made("machine create"));
}

#[test]
fn existing_name_with_kit_flags_attaches_without_loading() {
    let mut t = kit_env();
    t.project("running");
    t.runner().interactive_exit(0);
    t.sbt(&["run", "--name", "claude-proj", "--kit", "./no-such-kit"])
        .unwrap();
    assert_eq!(t.runner().interactive_calls().len(), 1);
}

#[test]
fn a_long_running_sandbox_keeps_running_after_the_last_session() {
    let mut t = test_env(&[]);
    kit_sandbox(&t, true);
    t.sbt(&["run", "--name", "toolbox-proj"]).unwrap();
    assert!(!t.made("machine stop"));
}

#[test]
fn a_bad_fetch_setting_skips_the_fetch_but_not_the_rm() {
    let mut t = test_env(&[("SMOLBENTO_CLONE_FETCH_ON_EXIT", "yes")]);
    let (_keep, repo) = temp_repo();
    clone_sandbox(&t, &repo);
    t.runner().interactive_exit(3);
    assert_eq!(t.sbt(&["run", "--rm", "--name", "claude-proj"]).unwrap(), 3);
    assert_eq!(
        t.calls().last().unwrap(),
        "machine delete -n sbx-claude-proj -f"
    );
}

#[test]
fn serves_the_bridge_while_attached() {
    let mut t = test_env(&[]);
    let (name, seen) = bridge_probe(&t, "run", true);
    t.sbt(&["run", "--name", &name]).unwrap();
    assert_eq!(*seen.borrow(), vec![true]);
    // Stopped with the session.
    assert!(!crate::bridge::host_socket(&name).exists());
}

#[test]
fn serves_a_runtime_ssh_agent_grant_while_attached() {
    let mut t = test_env(&[]);
    let (name, seen) = agent_probe(&t, "run", Some(r#"{"runtime":{"sign":["git"]}}"#));
    t.sbt(&["run", "--name", &name]).unwrap();
    assert_eq!(*seen.borrow(), vec![true]);
    assert!(!crate::bridge::agent_socket(&name).exists());
}

#[test]
fn serves_no_ssh_agent_without_a_runtime_grant() {
    for (tag, grant) in [
        ("run-none", None),
        ("run-install", Some(r#"{"install":{"sign":null}}"#)),
    ] {
        let mut t = test_env(&[]);
        let (name, seen) = agent_probe(&t, tag, grant);
        t.sbt(&["run", "--name", &name]).unwrap();
        assert_eq!(*seen.borrow(), vec![false], "{tag}");
    }
}

#[test]
fn serves_no_bridge_for_an_unlabelled_sandbox() {
    let mut t = test_env(&[]);
    let (name, seen) = bridge_probe(&t, "run", false);
    t.sbt(&["run", "--name", &name]).unwrap();
    assert_eq!(*seen.borrow(), vec![false]);
}

#[test]
fn serves_no_bridge_over_ssh_without_a_display() {
    let mut t = test_env(&[("SSH_CONNECTION", "10.0.0.1 50000 10.0.0.2 22")]);
    let (name, seen) = bridge_probe(&t, "run", true);
    t.sbt(&["run", "--name", &name]).unwrap();
    assert_eq!(*seen.borrow(), vec![false]);
}
