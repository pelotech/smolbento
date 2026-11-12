use super::*;

/// The fixture is a pre-4a docker sandbox: `sbx.docker=true` and no `sbx.kits`, so `setup`
/// starts dockerd itself.
#[test]
fn start_applies_network_then_starts_with_env_then_setup() {
    let vm = vm_with(&stopped());
    let mut sb = get(&vm, "claude-myrepo").unwrap();
    ensure_running(&vm, &mut sb, || Ok(plan())).unwrap();
    assert!(sb.is_running());
    let lines = vm.runner().call_lines();
    assert_eq!(
        lines[1],
        "machine update -n sbx-claude-myrepo --net --reset-allow-list"
    );
    assert_eq!(lines[2], "machine start -n sbx-claude-myrepo --branchable");
    assert!(
        lines[3].ends_with("usermod -o -u 501 agent"),
        "{}",
        lines[3]
    );
    assert!(lines[4].ends_with(&hosts_cmd()), "{lines:#?}");
    assert!(lines[5].ends_with(&bridge::remove_cmd()), "{lines:#?}");
    assert_eq!(
        lines[6],
        format!("machine exec --name sbx-claude-myrepo -u root -d -- sh -c {DOCKER_START}")
    );
    assert_eq!(
        lines[7],
        format!(
            "machine exec --name sbx-claude-myrepo -u root -- sh -c {}",
            startup_cmd(None)
        )
    );
    assert_eq!(lines.len(), 8, "{lines:#?}");
    assert_eq!(
        vm.runner().envs(),
        vec![vec![("TOK".to_string(), "secret".to_string())]]
    );
    assert_eq!(vm.runner().removed(), vec![vec!["GONE".to_string()]]);
}

#[test]
fn a_read_only_etc_hosts_warns_and_the_start_goes_on() {
    let fake = FakeRunner::new();
    fake.ok(&["machine", "status"], &stopped());
    fake.fail(
        &root_sh("sbx-claude-myrepo", &hosts_cmd()),
        "EXEC_FAILED",
        "Read-only file system",
    );
    let vm = Smolvm::new(fake);
    let mut sb = get(&vm, "claude-myrepo").unwrap();
    ensure_running(&vm, &mut sb, || Ok(plan())).unwrap();
    assert!(sb.is_running());
    let lines = vm.runner().call_lines();
    assert!(
        lines.iter().any(|l| l.ends_with(&startup_cmd(None))),
        "{lines:#?}"
    );
    assert!(
        !lines.iter().any(|l| l.starts_with("machine stop")),
        "{lines:#?}"
    );
}

#[test]
fn a_docker_kit_sandbox_leaves_dockerd_to_its_startup_runner() {
    let vm = vm_with(&stopped().replace(
        "\"sbx.docker\": \"true\",",
        "\"sbx.docker\": \"true\", \"sbx.kits\": \"[\\\"builtin:docker\\\"]\",",
    ));
    let mut sb = get(&vm, "claude-myrepo").unwrap();
    assert_eq!(sb.meta.kits, ["builtin:docker"]);
    ensure_running(&vm, &mut sb, || Ok(plan())).unwrap();
    let lines = vm.runner().call_lines();
    assert!(
        !lines.iter().any(|l| l.ends_with(DOCKER_START)),
        "no second dockerd start: {lines:#?}"
    );
    assert!(
        lines.last().unwrap().ends_with(&startup_cmd(None)),
        "{lines:#?}"
    );
}

#[test]
fn create_creates_and_starts() {
    let req = create::CreateRequest {
        name: "claude-myrepo".into(),
        agent: "claude".into(),
        image: "img".into(),
        cpus: 1,
        memory_mib: 1024,
        created: 1,
        ..Default::default()
    };
    let fake = FakeRunner::new();
    let created = STATUS
        .replace("\"state\": \"running\"", "\"state\": \"created\"")
        .replace("\"true\"", "\"false\"");
    fake.ok(&["machine", "status"], &created);
    let vm = Smolvm::new(fake);
    let sb = create(&vm, &req, &plan(), |_| unreachable!(), &mut |_| {}).unwrap();
    assert!(sb.is_running());
    let lines = vm.runner().call_lines();
    assert!(
        lines[0].starts_with("machine create -n sbx-claude-myrepo --image img"),
        "{}",
        lines[0]
    );
    assert_eq!(
        lines[2],
        "machine update -n sbx-claude-myrepo --net --reset-allow-list"
    );
    assert_eq!(lines[3], "machine start -n sbx-claude-myrepo --branchable");
    assert_eq!(
        lines.len(),
        8,
        "no dockerd for a non-docker sandbox: {lines:?}"
    );
    assert!(lines[7].ends_with(&startup_cmd(None)), "{lines:?}");
}

#[test]
fn an_install_grant_is_served_only_while_the_install_hooks_run() {
    let both = r#"{"install":{"sign":["git"]},"runtime":{"sign":null}}"#;
    let runtime = r#"{"runtime":{"sign":null}}"#;
    for (tag, grant, want) in [
        ("both", both, [true, true, false, false]),
        ("runtime", runtime, [false; 4]),
    ] {
        let name = format!("agent-{}-first-{tag}", std::process::id());
        let label = serde_json::to_string(grant).unwrap();
        let status = STATUS
            .replace("\"state\": \"running\"", "\"state\": \"created\"")
            .replace("\"true\"", "\"false\"")
            .replace(
                "\"sbx.name\": \"claude-myrepo\"",
                &format!("\"sbx.name\": \"{name}\", \"sbx.ssh-agent\": {label}"),
            );
        let fake = FakeRunner::new();
        fake.ok(&["machine", "status"], &status);
        let (seen, probe) = crate::testutil::socket_probe(bridge::agent_socket(&name));
        fake.during(&["machine", "exec"], move |args| {
            let script = args.last().unwrap();
            if ["install-1", "install-2", "files-1", "context-1"]
                .iter()
                .any(|w| script == &format!("echo {w}"))
            {
                probe();
            }
        });
        let vm = Smolvm::new(fake);
        let (_dir, paths) = crate::config::test_paths();
        let mut plan = kit_plan(&[]);
        plan.kit.as_mut().unwrap().agent_backing = Some(crate::ssh_agent::filter::Backing::new(
            &paths,
            &Default::default(),
        ));
        let sb = create(
            &vm,
            &request(),
            &plan,
            |_| Ok(plan.network.clone()),
            &mut |_| {},
        )
        .unwrap();
        assert!(sb.meta.ssh_agent.is_some());
        assert_eq!(*seen.borrow(), want, "{tag}");
        assert!(!bridge::agent_socket(&name).exists(), "{tag}");
    }
}

#[test]
fn create_runs_kit_steps_in_lifecycle_order() {
    let vm = created_vm();
    let dropped = std::cell::RefCell::new(Vec::new());
    create(
        &vm,
        &request(),
        &kit_plan(&[]),
        |ids| {
            dropped.borrow_mut().extend_from_slice(ids);
            Ok(restricted(&["api.example.com"]))
        },
        &mut |_| {},
    )
    .unwrap();
    assert_eq!(*dropped.borrow(), vec!["r-npm".to_string()]);
    let lines = vm.runner().call_lines();
    let start = position(&lines, "start", |l| l.starts_with("machine start"));
    let uid = position(&lines, "usermod", |l| {
        l.ends_with("usermod -o -u 501 agent")
    });
    let install1 = position(&lines, "install 1", |l| {
        *l == exec_line("root", false, "echo install-1")
    });
    let install2 = position(&lines, "install 2", |l| {
        *l == exec_line("agent", false, "echo install-2")
    });
    let update = position(&lines, "post-install update", |l| {
        l.starts_with("machine update")
            && l.contains("--allow-host api.example.com")
            && !l.contains("registry.npmjs.org")
    });
    let files = position(&lines, "files", |l| {
        *l == exec_line("root", false, "echo files-1")
    });
    let context = position(&lines, "context", |l| {
        *l == exec_line("root", false, "echo context-1")
    });
    let startup_d = position(&lines, "startup.d cp", |l| {
        l.starts_with("machine cp ")
            && l.ends_with(&format!("{MACHINE}:/etc/smolbento/startup.d/01-k.sh"))
    });
    let runner = exec_line("root", false, &startup_cmd(None));
    assert!(
        start < uid
            && uid < install1
            && install1 < install2
            && install2 < update
            && update < files
            && files < context
            && context < startup_d,
        "{lines:#?}"
    );
    assert_eq!(lines.last().unwrap(), &runner, "{lines:#?}");
    assert_eq!(
        lines.iter().filter(|l| **l == runner).count(),
        1,
        "only after the kit files: {lines:#?}"
    );
    // R11: the post-install update replaces the whole list, so the CIDRs smolvm resolved
    // for the install host go with it.
    assert!(
        lines[update].contains("--reset-allow-list"),
        "{}",
        lines[update]
    );
    assert!(
        !lines.iter().any(|l| l.contains("machine stop")),
        "{lines:#?}"
    );
    let uploads: std::collections::BTreeMap<String, String> =
        vm.runner().uploads().into_iter().collect();
    let at = |p: &str| uploads.get(&format!("{MACHINE}:{p}")).cloned();
    assert_eq!(
        at("/etc/smolbento/startup.d/01-k.sh").as_deref(),
        Some("echo startup")
    );
    assert_eq!(
        at(guest::STARTUP_PATH).as_deref(),
        Some(guest::STARTUP_RUNNER)
    );
    assert_eq!(
        at(guest::KITS_FILE).as_deref(),
        Some("k\tref@sha256:00\tnpm\n")
    );
    assert!(
        lines[startup_d..]
            .iter()
            .any(|l| l.contains("chmod 755 '/etc/smolbento/startup'")),
        "{lines:#?}"
    );
}

#[test]
fn install_only_credentials_restart_the_machine_without_them() {
    let vm = created_vm();
    create(
        &vm,
        &request(),
        &kit_plan(&["TOK"]),
        |_| Ok(restricted(&["api.example.com"])),
        &mut |_| {},
    )
    .unwrap();
    let lines = vm.runner().call_lines();
    let install2 = position(&lines, "install 2", |l| {
        *l == exec_line("agent", false, "echo install-2")
    });
    let stop = position(&lines, "stop", |l| l.starts_with("machine stop"));
    let restart = lines
        .iter()
        .rposition(|l| l.starts_with("machine start"))
        .unwrap();
    let files = position(&lines, "files", |l| {
        *l == exec_line("root", false, "echo files-1")
    });
    assert!(
        install2 < stop && stop < restart && restart < files,
        "{lines:#?}"
    );
    // The network without the install rules goes once, to the stopped machine, by `start`.
    let updates: Vec<usize> = (install2..restart)
        .filter(|&i| lines[i].starts_with("machine update"))
        .collect();
    assert!(
        updates.len() == 1 && stop < updates[0] && lines[updates[0]].contains("api.example.com"),
        "{lines:#?}"
    );
    assert!(
        lines[restart..files]
            .iter()
            .any(|l| l.ends_with("usermod -o -u 501 agent")),
        "setup runs again: {lines:#?}"
    );
    assert_eq!(
        lines
            .iter()
            .filter(|l| l.ends_with(&startup_cmd(None)))
            .count(),
        1,
        "not on the restart either: {lines:#?}"
    );
    let envs = vm.runner().envs();
    let removed = vm.runner().removed();
    assert_eq!(envs.len(), 2);
    assert!(
        envs[0].iter().any(|(k, _)| k == "TOK"),
        "the first start has it"
    );
    assert!(!envs[1].iter().any(|(k, _)| k == "TOK"), "{:?}", envs[1]);
    assert!(envs[1].iter().any(|(k, _)| k == "KEEP"));
    assert!(removed[1].contains(&"TOK".to_string()), "{:?}", removed[1]);
}

#[test]
fn a_failed_install_hook_removes_the_sandbox() {
    let vm = created_vm();
    let stderr: Vec<String> = (1..=25).map(|i| format!("line {i}")).collect();
    vm.runner().fail(
        &root_sh(MACHINE, "echo install-1"),
        "EXEC_FAILED",
        &stderr.join("\n"),
    );
    let err = create(
        &vm,
        &request(),
        &kit_plan(&[]),
        |_| panic!("install rules stay until the hooks succeed"),
        &mut |_| {},
    )
    .unwrap_err()
    .to_string();
    assert_eq!(
        err,
        format!(
            "kit install failed (the sandbox was removed): kit k install hook 1 failed:\n{}",
            stderr[5..].join("\n")
        )
    );
    let lines = vm.runner().call_lines();
    assert_eq!(
        lines.last().unwrap(),
        &format!("machine delete -n {MACHINE} -f")
    );
    assert!(!lines.iter().any(|l| l.contains("install-2")), "{lines:#?}");
}

#[test]
fn failing_to_drop_the_install_rules_or_write_files_removes_the_sandbox() {
    let vm = created_vm();
    let err = create(
        &vm,
        &request(),
        &kit_plan(&[]),
        |_| anyhow::bail!("policy.toml: permission denied"),
        &mut |_| {},
    )
    .unwrap_err();
    assert!(
        err.to_string()
            .starts_with("kit install failed (the sandbox was removed): "),
        "{err}"
    );
    assert!(format!("{err:#}").contains("permission denied"), "{err:#}");
    assert_eq!(
        vm.runner().call_lines().last().unwrap(),
        &format!("machine delete -n {MACHINE} -f")
    );

    let vm = created_vm();
    vm.runner()
        .fail(&["machine", "cp"], "CP_FAILED", "no space left");
    let err = create(
        &vm,
        &request(),
        &kit_plan(&[]),
        |_| Ok(restricted(&["api.example.com"])),
        &mut |_| {},
    )
    .unwrap_err();
    assert!(
        err.to_string().starts_with("kit install failed")
            && format!("{err:#}").contains("no space left"),
        "{err:#}"
    );
    assert_eq!(
        vm.runner().call_lines().last().unwrap(),
        &format!("machine delete -n {MACHINE} -f")
    );
}

#[test]
fn a_failed_first_start_without_install_hooks_says_so_neutrally() {
    // Like a default Docker sandbox: the docker kit has no install hooks.
    let vm = created_vm();
    vm.runner()
        .fail(&["machine", "cp"], "CP_FAILED", "no space left");
    let mut plan = kit_plan(&[]);
    let kit = plan.kit.as_mut().unwrap();
    kit.steps.install.clear();
    kit.steps.install_rules.clear();
    let err = create(&vm, &request(), &plan, |_| unreachable!(), &mut |_| {}).unwrap_err();
    assert!(
        err.to_string()
            .starts_with("the first start failed (the sandbox was removed): ")
            && format!("{err:#}").contains("no space left"),
        "{err:#}"
    );
}

#[test]
fn a_failing_startup_hook_at_create_warns_and_keeps_the_sandbox_stopped() {
    let vm = created_vm();
    failing_startup(vm.runner(), MACHINE, 1);
    let sb = create(
        &vm,
        &request(),
        &kit_plan(&[]),
        |_| Ok(restricted(&["api.example.com"])),
        &mut |_| {},
    )
    .unwrap();
    // Stopped, so the next run starts it and runs the hooks again (and fails like sbx).
    assert_eq!(sb.state, MachineState::Stopped);
    let lines = vm.runner().call_lines();
    assert_eq!(
        lines.last().unwrap(),
        &format!("machine stop -n {MACHINE}"),
        "{lines:#?}"
    );
    assert!(
        !lines.iter().any(|l| l.starts_with("machine delete")),
        "{lines:#?}"
    );
    assert_eq!(
        create_warning(&anyhow!("kit startup exited with code 1")),
        "warning: StartRuntime after create failed; kit commands.startup will fire on first \
         run: kit startup exited with code 1"
    );
}

#[test]
fn a_failed_hook_with_no_stderr_reports_its_stdout() {
    let vm = created_vm();
    vm.runner().on(
        &root_sh(MACHINE, "echo install-1"),
        crate::smolvm::Output {
            code: 2,
            stdout: "resolving\nE: package not found\n".into(),
            stderr: String::new(),
        },
    );
    let err = create(
        &vm,
        &request(),
        &kit_plan(&[]),
        |_| unreachable!(),
        &mut |_| {},
    )
    .unwrap_err()
    .to_string();
    assert_eq!(
        err,
        "kit install failed (the sandbox was removed): kit k install hook 1 failed:\n\
         resolving\nE: package not found"
    );
}

#[test]
fn a_failed_first_start_of_a_kit_sandbox_removes_it() {
    let vm = created_vm();
    vm.runner().fail(
        &root_sh(MACHINE, &identity_cmd(501, 20)),
        "EXEC_FAILED",
        "usermod: busy",
    );
    let err = create(
        &vm,
        &request(),
        &kit_plan(&[]),
        |_| unreachable!(),
        &mut |_| {},
    )
    .unwrap_err();
    assert!(
        err.to_string()
            .starts_with("kit install failed (the sandbox was removed): "),
        "{err:#}"
    );
    assert!(format!("{err:#}").contains("usermod: busy"), "{err:#}");
    let lines = vm.runner().call_lines();
    assert_eq!(
        lines.last().unwrap(),
        &format!("machine delete -n {MACHINE} -f")
    );
    assert!(!lines.iter().any(|l| l.contains("install-1")), "{lines:#?}");
}
