use super::*;

#[test]
fn find_maps_name_and_reads_labels() {
    let fake = FakeRunner::new();
    fake.ok(&["machine", "status", "-n", "sbx-claude-myrepo"], STATUS);
    let vm = Smolvm::new(fake);
    let sb = find(&vm, "claude-myrepo").unwrap().unwrap();
    assert_eq!(sb.meta.agent, "claude");
    assert!(sb.is_running());
    assert_eq!(sb.workdir(), "/Users/dev/myrepo");
    assert_eq!(sb.ports[0].host, 18080);
}

#[test]
fn get_missing_is_a_clear_error() {
    let fake = FakeRunner::new();
    fake.fail(&["machine", "status"], "NOT_FOUND", "vm not found");
    let err = get(&Smolvm::new(fake), "nope").unwrap_err().to_string();
    assert!(err.contains("sandbox 'nope' not found"), "{err}");
}

#[test]
fn list_skips_foreign_machines_and_adds_ports() {
    let fake = FakeRunner::new();
    fake.ok(
        &["machine", "ls", "--json"],
        include_str!("../../../tests/fixtures/smolvm/ls.json"),
    );
    fake.ok(&["machine", "status", "-n", "sbx-claude-myrepo"], STATUS);
    let list = list(&Smolvm::new(fake)).unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].name(), "claude-myrepo");
    assert_eq!(list[0].ports.len(), 1);
}

#[test]
fn a_start_checks_the_socket_dir_and_installs_the_shims_when_it_is_private() {
    let vm = vm_with(&bridged_status());
    let sb = get(&vm, "claude-myrepo").unwrap();
    let checked = std::cell::RefCell::new(Vec::new());
    start_checked(&vm, &sb, &plan(), &mut |_| {}, &|d| {
        checked.borrow_mut().push(d.to_path_buf());
        true
    })
    .unwrap();
    assert_eq!(*checked.borrow(), vec![bridge::socket_dir()]);
    let install = format!(
        "machine exec --name sbx-claude-myrepo -u root -- sh -c {}",
        bridge::install_cmd()
    );
    assert!(vm.runner().call_lines().contains(&install));
}

/// A sandbox with an SSH agent: the directory is checked even without the bridge, and an
/// unsafe one warns that this start gets no agent.
#[test]
fn a_start_checks_the_socket_dir_for_the_ssh_agent_too() {
    let fake = FakeRunner::new();
    let status = stopped().replace(
        "\"sbx.docker\"",
        "\"sbx.ssh-agent\": \"{\\\"runtime\\\":{\\\"sign\\\":null}}\",\n    \"sbx.docker\"",
    );
    fake.ok(&["machine", "status"], &status);
    let vm = Smolvm::new(fake);
    let sb = get(&vm, "claude-myrepo").unwrap();
    assert!(sb.meta.ssh_agent.is_some() && !sb.meta.bridge);
    let checked = std::cell::RefCell::new(Vec::new());
    start_checked(&vm, &sb, &plan(), &mut |_| {}, &|d| {
        checked.borrow_mut().push(d.to_path_buf());
        false
    })
    .unwrap();
    let dir = bridge::socket_dir();
    assert_eq!(*checked.borrow(), vec![dir.clone()]);
    let unsafe_dir = |what: &str| {
        format!(
            "warning: {} isn't a private directory owned by you; claude-myrepo gets no {what} \
             unless it can be made private",
            dir.display()
        )
    };
    // What `setup` prints: an agent-only sandbox's warning, and no shims, private or not.
    assert_eq!(
        unsafe_dir_warnings(&sb, &dir),
        vec![unsafe_dir("SSH agent")]
    );
    let shims =
        |cmd: String| format!("machine exec --name sbx-claude-myrepo -u root -- sh -c {cmd}");
    let lines = vm.runner().call_lines();
    assert!(lines.contains(&shims(bridge::remove_cmd())), "{lines:#?}");
    let vm = vm_with(&status);
    start_checked(&vm, &sb, &plan(), &mut |_| {}, &|_| true).unwrap();
    let lines = vm.runner().call_lines();
    assert!(lines.contains(&shims(bridge::remove_cmd())), "{lines:#?}");
    assert!(!lines.contains(&shims(bridge::install_cmd())), "{lines:#?}");
    let mut both = sb.clone();
    both.meta.bridge = true;
    assert_eq!(
        unsafe_dir_warnings(&both, &dir),
        vec![
            unsafe_dir("browser or clipboard bridge"),
            unsafe_dir("SSH agent")
        ]
    );
    // Neither: nothing to check.
    let mut neither = sb.clone();
    neither.meta.ssh_agent = None;
    let vm = vm_with(&stopped());
    start_checked(&vm, &neither, &plan(), &mut |_| {}, &|_| panic!("checked")).unwrap();
}

#[test]
fn a_start_with_an_unsafe_socket_dir_removes_the_shims() {
    let vm = vm_with(&bridged_status());
    let sb = get(&vm, "claude-myrepo").unwrap();
    start_checked(&vm, &sb, &plan(), &mut |_| {}, &|_| false).unwrap();
    let lines = vm.runner().call_lines();
    let exec =
        |cmd: String| format!("machine exec --name sbx-claude-myrepo -u root -- sh -c {cmd}");
    assert!(lines.contains(&exec(bridge::remove_cmd())), "{lines:#?}");
    assert!(!lines.contains(&exec(bridge::install_cmd())), "{lines:#?}");
}

#[test]
fn failing_to_install_the_shims_warns_and_the_start_goes_on() {
    let fake = FakeRunner::new();
    fake.ok(
        &["machine", "status"],
        &stopped().replace(
            "\"sbx.docker\"",
            "\"sbx.bridge\": \"true\",\n    \"sbx.docker\"",
        ),
    );
    fake.fail(
        &root_sh("sbx-claude-myrepo", &bridge::install_cmd()),
        "EXEC_FAILED",
        "Read-only file system",
    );
    let vm = Smolvm::new(fake);
    let mut sb = get(&vm, "claude-myrepo").unwrap();
    ensure_running(&vm, &mut sb, || Ok(plan())).unwrap();
    assert!(sb.is_running());
}

#[test]
fn every_start_names_the_host_after_the_agent_user() {
    let vm = vm_with(&stopped());
    let mut sb = get(&vm, "claude-myrepo").unwrap();
    ensure_running(&vm, &mut sb, || Ok(plan())).unwrap();
    let lines = vm.runner().call_lines();
    assert!(lines[3].ends_with("usermod -o -u 501 agent"), "{lines:#?}");
    assert_eq!(
        lines[4],
        "machine exec --name sbx-claude-myrepo -u root -- sh -c grep -q ' host.docker.internal$' \
         /etc/hosts || printf '\\n%s\\n' '100.96.0.1 host.docker.internal' >> /etc/hosts"
    );
}

#[test]
fn a_failed_skills_link_only_warns() {
    let fake = FakeRunner::new();
    fake.ok(&["machine", "status"], &skills_status(RO_LABEL));
    let script = crate::skills::link_script(&[crate::skills::Dir {
        path: "/home/agent/.claude/skills".into(),
        access: crate::skills::Access::Link,
    }])
    .unwrap();
    fake.fail(
        &root_sh("sbx-claude-myrepo", &script),
        "EXEC_FAILED",
        "boom",
    );
    let vm = Smolvm::new(fake);
    let mut sb = get(&vm, "claude-myrepo").unwrap();
    ensure_running(&vm, &mut sb, || Ok(plan())).unwrap();
    assert!(sb.is_running());
}

#[test]
fn a_sandbox_without_a_skills_label_gets_no_link_exec() {
    let vm = vm_with(&stopped());
    let mut sb = get(&vm, "claude-myrepo").unwrap();
    ensure_running(&vm, &mut sb, || Ok(plan())).unwrap();
    let lines = vm.runner().call_lines();
    assert!(
        !lines.iter().any(|l| l.contains("skills-shared")),
        "{lines:#?}"
    );
}

#[test]
fn running_sandboxes_skip_the_plan() {
    let vm = vm_with(STATUS);
    let mut sb = get(&vm, "claude-myrepo").unwrap();
    ensure_running(&vm, &mut sb, || panic!("plan must not be computed")).unwrap();
}

#[test]
fn a_failed_setup_step_stops_the_machine() {
    let fake = FakeRunner::new();
    fake.ok(&["machine", "status"], &stopped());
    fake.fail(
        &[
            "machine",
            "exec",
            "--name",
            "sbx-claude-myrepo",
            "-u",
            "root",
            "-d",
        ],
        "EXEC_FAILED",
        "dockerd: not found",
    );
    let vm = Smolvm::new(fake);
    let mut sb = get(&vm, "claude-myrepo").unwrap();
    assert!(sb.meta.docker);
    let err = ensure_running(&vm, &mut sb, || Ok(plan())).unwrap_err();
    assert!(format!("{err:#}").contains("starting dockerd"), "{err:#}");
    assert!(!sb.is_running());
    assert_eq!(
        vm.runner().call_lines().last().unwrap(),
        "machine stop -n sbx-claude-myrepo"
    );
}
