use super::*;

#[test]
fn starts_install_the_bridge_shims_or_remove_ours() {
    for bridged in [true, false] {
        let fake = FakeRunner::new();
        let status = stopped();
        let status = if bridged {
            status.replace(
                "\"sbx.docker\"",
                "\"sbx.bridge\": \"true\",\n    \"sbx.docker\"",
            )
        } else {
            status
        };
        fake.ok(&["machine", "status"], &status);
        let vm = Smolvm::new(fake);
        let sb = get(&vm, "claude-myrepo").unwrap();
        assert_eq!(sb.meta.bridge, bridged);
        start_checked(&vm, &sb, &plan(), &mut |_| {}, &|_| true).unwrap();
        let install = format!(
            "machine exec --name sbx-claude-myrepo -u root -- sh -c {}",
            bridge::install_cmd()
        );
        let remove = format!(
            "machine exec --name sbx-claude-myrepo -u root -- sh -c {}",
            bridge::remove_cmd()
        );
        let lines = vm.runner().call_lines();
        // Right after the hosts step: the install, or without the bridge the removal.
        let hosts = lines
            .iter()
            .position(|l| l.ends_with(&hosts_cmd()))
            .unwrap();
        let expected = if bridged { &install } else { &remove };
        assert_eq!(&lines[hosts + 1], expected, "{lines:#?}");
        assert_eq!(lines.contains(&install), bridged, "{lines:#?}");
    }
}

#[test]
fn clone_commands_quote_and_copy_remotes() {
    let step = CloneStep {
        dir: "/w/my repo".into(),
        head: Some(WorktreeHead::Branch("feat".into())),
        remotes: vec![("origin".into(), "https://github.com/o/r.git".into())],
    };
    assert_eq!(
        clone_prep_cmd(&step),
        "[ -d '/w/my repo/.git' ] && exit 0; rmdir '/w/my repo/lost+found' 2>/dev/null; chown agent '/w/my repo'"
    );
    assert_eq!(
        clone_cmd(&step),
        "set -e; [ -d '/w/my repo/.git' ] || \
         git -c safe.directory=/run/sandbox/source clone -q --branch 'feat' /run/sandbox/source '/w/my repo'; \
         cd '/w/my repo'; \
         git remote set-url -- 'origin' 'https://github.com/o/r.git' 2>/dev/null || git remote add -- 'origin' 'https://github.com/o/r.git'"
    );
    assert_eq!(sh_quote("it's"), r"'it'\''s'");
}

#[test]
fn a_detached_worktree_clone_checks_out_its_commit_or_falls_back() {
    let detached = CloneStep {
        head: Some(WorktreeHead::Detached(
            "0123456789abcdef0123456789abcdef01234567".into(),
        )),
        ..step("/w/r")
    };
    assert_eq!(
        clone_cmd(&detached),
        "set -e; [ -d '/w/r/.git' ] || \
         { git -c safe.directory=/run/sandbox/source clone -q --no-checkout /run/sandbox/source '/w/r' || exit 1; \
         git -C '/w/r' checkout -q --detach '0123456789abcdef0123456789abcdef01234567' -- 2>/dev/null || { \
         git -C '/w/r' reset -q --hard || { rm -rf '/w/r/.git'; exit 1; }; \
         echo \"warning: commit 0123456789ab isn't in the clone; the agent starts \
         from $(git -C '/w/r' symbolic-ref -q --short HEAD || echo HEAD) instead\" >&2; }; }; \
         cd '/w/r'"
    );
    // Anything but a hex id is cloned plainly rather than echoed.
    let odd = CloneStep {
        head: Some(WorktreeHead::Detached("\"$(x)".into())),
        ..step("/w/r")
    };
    assert_eq!(clone_cmd(&odd), clone_cmd(&step("/w/r")));
}

#[test]
fn run_clone_returns_the_guests_warning_lines() {
    let fake = FakeRunner::new();
    fake.ok(&["machine"], "");
    fake.ok_with_stderr(
        &["machine", "exec", "--name", "sbx-r", "-u", "agent"],
        "",
        "Cloning...\nwarning: commit abc isn't in the clone; the agent starts from main instead\n",
    );
    let vm = Smolvm::new(fake);
    let (sb, plan) = clone_sandbox();
    assert_eq!(
        run_clone(&vm, &sb, plan.clone.as_ref().unwrap()).unwrap(),
        vec!["warning: commit abc isn't in the clone; the agent starts from main instead"]
    );
}

#[test]
fn start_runs_the_clone_step_after_setup() {
    let fake = FakeRunner::new();
    fake.ok(&["machine"], "");
    let vm = Smolvm::new(fake);
    let (sb, plan) = clone_sandbox();
    start(&vm, &sb, &plan).unwrap();
    let lines = vm.runner().call_lines();
    // The startup hooks follow the clone.
    assert!(
        lines.last().unwrap().ends_with(&startup_cmd(None)),
        "{lines:?}"
    );
    let last2 = &lines[lines.len() - 3..lines.len() - 1];
    assert!(
        last2[0].contains("-u root") && last2[0].contains("chown agent"),
        "{last2:?}"
    );
    assert!(
        last2[1].contains("-u agent") && last2[1].contains("clone -q /run/sandbox/source '/w/r'"),
        "{last2:?}"
    );
}

#[test]
fn a_failed_clone_stops_the_machine_and_reports_gits_first_line() {
    let fake = FakeRunner::new();
    fake.fail(
        &["machine", "exec", "--name", "sbx-r", "-u", "agent"],
        "EXEC_FAILED",
        "fatal: repository not found\nhint: more",
    );
    let vm = Smolvm::new(fake);
    let (sb, p) = clone_sandbox();
    let err = start(&vm, &sb, &p).unwrap_err();
    assert_eq!(
        err.to_string(),
        "cloning the repo in the sandbox: fatal: repository not found"
    );
    let lines = vm.runner().call_lines();
    assert!(
        lines.last().unwrap().starts_with("machine stop"),
        "{lines:?}"
    );
}

#[test]
fn a_failed_clone_prep_reports_the_first_line_and_stops() {
    let prep = clone_prep_cmd(&step("/w/r"));
    let fake = FakeRunner::new();
    fake.spawn_fail(
        &root_sh("sbx-r", &prep),
        "could not run smolvm\nsecond line",
    );
    let vm = Smolvm::new(fake);
    let (sb, p) = clone_sandbox();
    let err = start(&vm, &sb, &p).unwrap_err();
    assert_eq!(
        err.to_string(),
        "cloning the repo in the sandbox: could not run smolvm"
    );
    let lines = vm.runner().call_lines();
    assert!(
        lines.last().unwrap().starts_with("machine stop"),
        "{lines:?}"
    );
    assert!(
        !lines.iter().any(|l| l.contains("-u agent -- sh")),
        "{lines:?}"
    );
}

#[test]
fn create_tells_what_it_is_doing() {
    let vm = created_vm();
    vm.runner().progress(
        &["machine", "start"],
        &[
            "Pulling image img... [==>      ] 10%",
            "Pulling image img... [=========] 100% — syncing...",
        ],
    );
    let mut plan = kit_plan(&[]);
    let kit = plan.kit.as_mut().unwrap();
    // The docker kit, without install hooks, comes after the kit whose hooks run.
    kit.steps.kits_record = "docker\tbuiltin:docker\tdocker\nk\tref@sha256:00\tnpm\n".into();
    kit.steps.install.insert(
        0,
        InstallStep {
            kit: None,
            ..hook(0, None, "echo git-identity")
        },
    );
    // A hook of another kit between k's: k still gets one step.
    kit.steps.install.insert(
        2,
        InstallStep {
            kit: Some("j".into()),
            ..hook(0, None, "echo j")
        },
    );
    let mut events = Vec::new();
    create(&vm, &request(), &plan, |_| Ok(restricted(&[])), &mut |e| {
        events.push(format!("{e:?}"))
    })
    .unwrap();
    assert_eq!(
        events,
        [
            "Boot",
            "Pull(Percent(10))",
            "Pull(Syncing)",
            "Setup",
            "Install(\"k\")",
            "Install(\"j\")",
            "Install(\"docker\")"
        ]
    );
}

#[test]
fn only_the_bundled_skills_step_relays_its_stderr() {
    let fake = FakeRunner::new();
    fake.ok(&["machine", "status"], STATUS);
    fake.ok_with_stderr(
        &["machine", "exec"],
        "",
        "warning: skipping skill review: /x/review already exists\n",
    );
    let vm = Smolvm::new(fake);
    let sb = get(&vm, "claude-myrepo").unwrap();
    let mut run = Steps {
        vm: &vm,
        sb: &sb,
        n: 0,
    };
    let own = InstallStep {
        label: "bundled agent skills".into(),
        kit: None,
        user: None,
        script: "true".into(),
        relay_stderr: true,
    };
    assert_eq!(
        run.install(&own).unwrap(),
        ["warning: skipping skill review: /x/review already exists"]
    );
    assert!(run.install(&hook(1, None, "true")).unwrap().is_empty());
    let git_identity = InstallStep {
        label: "the git identity step".into(),
        kit: None,
        user: None,
        script: "true".into(),
        relay_stderr: false,
    };
    assert!(run.install(&git_identity).unwrap().is_empty());
}

#[test]
fn a_large_script_is_copied_in_rather_than_passed_in_argv() {
    let vm = created_vm();
    let big = format!("echo {}", "x".repeat(70 * 1024));
    let mut plan = kit_plan(&[]);
    let kit = plan.kit.as_mut().unwrap();
    kit.steps.install = vec![hook(1, Some("agent"), &big)];
    create(
        &vm,
        &request(),
        &plan,
        |_| Ok(restricted(&["api.example.com"])),
        &mut |_| {},
    )
    .unwrap();
    let lines = vm.runner().call_lines();
    assert!(!lines.iter().any(|l| l.contains(&big)), "inline");
    let run = position(&lines, "step exec", |l| {
        *l == format!("machine exec --name {MACHINE} -u agent -- sh /run/smolbento/step-1.sh")
    });
    let cp = position(&lines, "step cp", |l| {
        l.starts_with("machine cp ") && l.ends_with(&format!("{MACHINE}:/run/smolbento/step-1.sh"))
    });
    assert!(cp < run, "{lines:#?}");
    let rm = position(&lines, "step rm", |l| {
        *l == format!("machine exec --name {MACHINE} -u root -- rm -f /run/smolbento/step-1.sh")
    });
    assert!(run < rm, "{lines:#?}");
    let uploads = vm.runner().uploads();
    assert!(
        uploads
            .iter()
            .any(|(p, c)| p.ends_with(":/run/smolbento/step-1.sh") && *c == big)
    );
}

#[test]
fn a_plain_start_runs_the_startup_hooks_in_one_blocking_exec() {
    let fake = FakeRunner::new();
    fake.ok(&["machine"], "");
    let vm = Smolvm::new(fake);
    let (mut sb, plan) = clone_sandbox();
    sb.meta.clone_repo = None;
    start(
        &vm,
        &sb,
        &StartPlan {
            clone: None,
            ..plan
        },
    )
    .unwrap();
    let lines = vm.runner().call_lines();
    assert_eq!(lines.len(), 6, "{lines:#?}");
    assert!(lines[2].ends_with("usermod -o -u 501 agent"), "{lines:#?}");
    assert!(lines[3].ends_with(&hosts_cmd()), "{lines:#?}");
    assert!(lines[4].ends_with(&bridge::remove_cmd()), "{lines:#?}");
    // A no-op without kits (no runner).
    assert_eq!(
        lines[5],
        "machine exec --name sbx-r -u root -- sh -c \
         [ -x /etc/smolbento/startup ] || exit 0; exec /etc/smolbento/startup"
    );
}

#[test]
fn a_failing_startup_hook_fails_the_start_and_stops_the_machine() {
    let fake = FakeRunner::new();
    fake.ok(&["machine"], "");
    failing_startup(&fake, "sbx-r", 3);
    let vm = Smolvm::new(fake);
    let (mut sb, plan) = clone_sandbox();
    sb.meta.clone_repo = None;
    let err = start(
        &vm,
        &sb,
        &StartPlan {
            clone: None,
            ..plan
        },
    )
    .unwrap_err();
    assert_eq!(format!("{err:#}"), "kit startup exited with code 3");
    let lines = vm.runner().call_lines();
    assert_eq!(lines.last().unwrap(), "machine stop -n sbx-r", "{lines:#?}");
}

#[test]
fn one_kits_startup_hooks_run_by_script() {
    let fake = FakeRunner::new();
    fake.ok(&["machine"], "");
    let vm = Smolvm::new(fake);
    let (sb, _) = clone_sandbox();
    let script = "/etc/smolbento/startup.d/02-net.sh";
    run_startup(&vm, &sb, Some(script)).unwrap();
    assert_eq!(
        vm.runner().call_lines(),
        vec![
            "machine exec --name sbx-r -u root -- sh -c [ -x /etc/smolbento/startup ] || \
             exit 0; exec /etc/smolbento/startup '/etc/smolbento/startup.d/02-net.sh'",
        ]
    );
}

#[test]
fn a_smolvm_error_running_the_startup_hooks_is_named() {
    let fake = FakeRunner::new();
    fake.ok(&["machine"], "");
    fake.fail(
        &["machine", "exec", "--name", "sbx-r", "-u", "root", "--"],
        "EXEC_FAILED",
        "agent gone",
    );
    let vm = Smolvm::new(fake);
    let (sb, _) = clone_sandbox();
    let err = run_startup(&vm, &sb, None).unwrap_err();
    assert_eq!(
        format!("{err:#}"),
        "running the kits' startup hooks: agent gone"
    );
}

/// Guest stderr (here the shell's, before the runner's redirect) isn't smolvm's error.
#[test]
fn startup_stderr_without_a_smolvm_error_gets_sbxs_text() {
    let fake = FakeRunner::new();
    fake.ok(&["machine"], "");
    fake.on(
        &["machine", "exec", "--name", "sbx-r", "-u", "root", "--"],
        crate::smolvm::Output {
            code: 2,
            stderr: "sh: can't create /var/log/sbx-kit-startup.log: Read-only file system\n".into(),
            ..Default::default()
        },
    );
    let vm = Smolvm::new(fake);
    let (sb, _) = clone_sandbox();
    let err = run_startup(&vm, &sb, None).unwrap_err();
    assert_eq!(format!("{err:#}"), "kit startup exited with code 2");
}
