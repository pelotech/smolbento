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
fn list_skips_foreign_machines() {
    let fake = FakeRunner::new();
    fake.ok(
        &["machine", "ls", "--json"],
        include_str!("../../../tests/fixtures/smolvm/ls.json"),
    );
    let list = list(&Smolvm::new(fake)).unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].name(), "claude-myrepo");
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
fn every_start_names_the_host() {
    let vm = vm_with(&stopped());
    let mut sb = get(&vm, "claude-myrepo").unwrap();
    ensure_running(&vm, &mut sb, || Ok(plan())).unwrap();
    let lines = vm.runner().call_lines();
    assert_eq!(
        lines[3],
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
fn a_failed_startup_step_warns_and_the_start_goes_on() {
    // sbx 0.51: a warning with the log's tail, and the agent still starts.
    let fake = FakeRunner::new();
    fake.ok(&["machine", "status"], &stopped());
    failing_startup(&fake, "sbx-claude-myrepo", 7);
    let vm = Smolvm::new(fake);
    let mut sb = get(&vm, "claude-myrepo").unwrap();
    ensure_running(&vm, &mut sb, || Ok(plan())).unwrap();
    assert!(sb.is_running());
    let lines = vm.runner().call_lines();
    assert!(
        !lines.iter().any(|l| l.starts_with("machine stop")),
        "{lines:#?}"
    );
    assert!(
        lines.last().unwrap().ends_with(&startup_log_tail_cmd()),
        "the warning shows the log's tail: {lines:#?}"
    );
}

#[test]
fn a_create_whose_first_start_fails_removes_the_sandbox() {
    // Without kits too, as sbx does: the same command can simply be run again.
    let vm = created_vm();
    vm.runner()
        .fail(&["machine", "start"], "SMOLVM_ERROR", "image pull failed");
    let err = create(&vm, &request(), &plan(), |_| unreachable!(), &mut |_| {}).unwrap_err();
    assert_eq!(
        format!("{err:#}"),
        "the first start failed (the sandbox was removed): smolvm: image pull failed"
    );
    assert_eq!(
        vm.runner().call_lines().last().unwrap(),
        &format!("machine delete -n {MACHINE} -f")
    );
    // The smolvm error stays reachable, for its hint.
    assert!(err.chain().any(|e| e.is::<crate::smolvm::SmolvmError>()));
}

const LAUNCH: &str = "exec dockerd >/var/log/dockerd.log 2>&1";
const PROBE: &str = "curl -sf --unix-socket /var/run/docker.sock http://localhost/_ping >/dev/null \
                     2>&1 || docker version >/dev/null 2>&1";
const UNANSWERED: &str =
    "dockerd didn't answer within 60s; see /var/log/dockerd.log in the sandbox";

/// A probe's argv: bounded by smolvm, so a hung engine can't outlast `ENGINE_BOUND`.
fn probe_argv(machine: &str) -> [&str; 12] {
    [
        "machine",
        "exec",
        "--name",
        machine,
        "-u",
        "root",
        "--timeout",
        "2s",
        "--",
        "sh",
        "-c",
        PROBE,
    ]
}

fn socket_step(user: &str) -> String {
    socket_step_to(&format!("\"$(id -gn -- {})\"", sh_quote(user)))
}

/// The socket step handing the socket to `group`, a shell word.
fn socket_step_to(group: &str) -> String {
    exec_line(
        "root",
        &format!("chgrp {group} /var/run/docker.sock && chmod g+rw /var/run/docker.sock"),
    )
}

/// The fixture with `sbx.user` set to `user`.
fn as_user(user: &str) -> String {
    stopped().replace(
        "\"sbx.docker\"",
        &format!("\"sbx.user\": \"{user}\",\n    \"sbx.docker\""),
    )
}

/// The fixture with `sbx.docker` set to `value`.
fn docker_status(value: &str) -> String {
    stopped().replace(
        "\"sbx.docker\": \"true\"",
        &format!("\"sbx.docker\": \"{value}\""),
    )
}

fn restarted(status: &str) -> Vec<String> {
    let vm = vm_with(status);
    let mut sb = get(&vm, "claude-myrepo").unwrap();
    ensure_running(&vm, &mut sb, || Ok(plan())).unwrap();
    vm.runner().call_lines()
}

fn launches(lines: &[String]) -> usize {
    lines.iter().filter(|l| l.contains(LAUNCH)).count()
}

/// tck: dockerd@1/engine-before-startup
#[test]
fn the_engine_answers_before_startup_hooks() {
    let runner = exec_line("root", &startup_cmd(None));
    let order = |lines: &[String]| {
        let launch = position(lines, "launch", |l| l.contains(LAUNCH));
        let probe = position(lines, "probe", |l| *l == probe_argv(MACHINE).join(" "));
        let socket = position(lines, "socket step", |l| *l == socket_step("agent"));
        let hooks = position(lines, "startup hooks", |l| *l == runner);
        assert!(
            launch < probe && probe < socket && socket < hooks,
            "{lines:#?}"
        );
    };
    order(&restarted(&stopped()));

    // The first start of a kit sandbox: after its startup scripts are written.
    let fake = FakeRunner::new();
    fake.ok(
        &["machine", "status"],
        &STATUS.replace("\"state\": \"running\"", "\"state\": \"created\""),
    );
    let vm = Smolvm::new(fake);
    create(
        &vm,
        &request(),
        &kit_plan(&[]),
        |_| Ok(NetworkSpec::Open),
        &mut |_| {},
    )
    .unwrap();
    let lines = vm.runner().call_lines();
    order(&lines);
    let startup_d = position(&lines, "startup.d cp", |l| l.contains("startup.d/01-k.sh"));
    assert!(startup_d < position(&lines, "launch", |l| l.contains(LAUNCH)));
    assert_eq!(launches(&lines), 1, "{lines:#?}");
}

/// tck: dockerd@1/fails-when-engine-unanswered
/// tck: dockerd@1/unanswered-bound-named
#[test]
fn an_unanswered_engine_fails_the_start() {
    let fake = FakeRunner::new();
    fake.ok(&["machine", "status"], &stopped());
    fake.fail(&probe_argv(MACHINE), "COMMAND_FAILED", "no engine");
    let vm = Smolvm::new(fake);
    let mut sb = get(&vm, "claude-myrepo").unwrap();
    let err = ensure_running(&vm, &mut sb, || Ok(plan())).unwrap_err();
    assert_eq!(err.to_string(), UNANSWERED);
    let lines = vm.runner().call_lines();
    assert!(
        !lines.iter().any(|l| l.ends_with(&startup_cmd(None))),
        "{lines:#?}"
    );
    assert!(!lines.contains(&socket_step("agent")), "{lines:#?}");
    assert_eq!(lines.last().unwrap(), &format!("machine stop -n {MACHINE}"));
}

/// tck: dockerd@1/manual-engine-not-started
#[test]
fn manual_engine_is_never_started() {
    let lines = restarted(&docker_status("manual"));
    assert_eq!(launches(&lines), 0, "{lines:#?}");
    assert!(
        lines.last().unwrap().ends_with(&startup_cmd(None)),
        "{lines:#?}"
    );
}

/// tck: dockerd@1/absent-without-grant
#[test]
fn no_engine_without_a_grant() {
    let lines = restarted(&docker_status("false"));
    assert_eq!(launches(&lines), 0, "{lines:#?}");
    assert!(
        !lines.contains(&probe_argv(MACHINE).join(" ")),
        "{lines:#?}"
    );
}

/// tck: dockerd@1/socket-usable-by-image-user
#[test]
fn the_socket_is_handed_to_the_image_user() {
    let lines = restarted(&stopped());
    assert!(lines.contains(&socket_step("agent")), "{lines:#?}");
    for root in ["root", "0", "0:0", "root:root"] {
        let lines = restarted(&as_user(root));
        assert_eq!(launches(&lines), 1, "{root}: {lines:#?}");
        assert!(
            !lines.iter().any(|l| l.contains("chgrp")),
            "{root}: {lines:#?}"
        );
    }
}

/// A `user:group` image user names its group: no `id` lookup, which would fail on the pair.
#[test]
fn a_user_with_a_group_gets_the_socket_by_that_group() {
    let lines = restarted(&as_user("somebody:1001"));
    assert!(lines.contains(&socket_step_to("'1001'")), "{lines:#?}");
    assert!(!lines.iter().any(|l| l.contains("id -gn")), "{lines:#?}");
}

/// `somebody:` names no group: its own is looked up, not `chgrp ''`.
#[test]
fn a_user_with_an_empty_group_gets_the_socket_by_its_own_group() {
    let lines = restarted(&as_user("somebody:"));
    assert!(lines.contains(&socket_step("somebody")), "{lines:#?}");
}

/// tck: dockerd@1/daemon-json-honored
#[test]
fn dockerd_gets_no_flags() {
    let lines = restarted(&stopped());
    let launch = &lines[position(&lines, "launch", |l| l.contains(LAUNCH))];
    assert!(
        launch.starts_with(&exec_line("root", "")),
        "as root: {launch}"
    );
    assert!(!launch.contains("dockerd --"), "{launch}");
}

#[test]
fn the_probe_works_without_curl() {
    let lines = restarted(&stopped());
    let probe = &lines[position(&lines, "probe", |l| l.contains("_ping"))];
    assert!(
        probe.contains("curl -sf --unix-socket /var/run/docker.sock http://localhost/_ping"),
        "{probe}"
    );
    assert!(probe.contains("|| docker version"), "{probe}");
}

/// A hung engine can block `curl` or `docker version`; smolvm kills each probe after 2s, so the
/// bound holds whatever the image has.
#[test]
fn each_probe_is_bounded() {
    let lines = restarted(&stopped());
    let probes: Vec<_> = lines.iter().filter(|l| l.contains("_ping")).collect();
    assert_eq!(probes, [&probe_argv(MACHINE).join(" ")], "{lines:#?}");
}

/// tck: dockerd@1/fails-when-engine-unanswered
#[test]
fn an_unanswered_engine_on_a_kit_create_removes_the_sandbox() {
    let fake = FakeRunner::new();
    fake.ok(
        &["machine", "status"],
        &STATUS.replace("\"state\": \"running\"", "\"state\": \"created\""),
    );
    fake.fail(&probe_argv(MACHINE), "COMMAND_FAILED", "no engine");
    let vm = Smolvm::new(fake);
    let err = create(
        &vm,
        &request(),
        &kit_plan(&[]),
        |_| Ok(NetworkSpec::Open),
        &mut |_| {},
    )
    .unwrap_err();
    assert!(err.chain().any(|e| e.to_string() == UNANSWERED), "{err:#}");
    assert_eq!(
        vm.runner().call_lines().last().unwrap(),
        &format!("machine delete -n {MACHINE} -f")
    );
}

/// smolvm mounts the agent socket at every start: a later start of a sandbox whose grant was for
/// the install phase only closes it again (`tck: ssh-agent@1/phase-scoped`).
#[test]
fn a_later_start_closes_an_install_only_agent_socket() {
    let close = "machine exec --name sbx-claude-myrepo -u root -- sh -c umount -l \
                 /run/ssh-agent.sock; rm -f /run/ssh-agent.sock";
    for (grant, closed) in [("install", true), ("runtime", false)] {
        let status = stopped().replace(
            "\"sbx.docker\"",
            &format!(
                "\"sbx.ssh-agent\": \"{{\\\"{grant}\\\":{{\\\"sign\\\":null}}}}\",\n    \"sbx.docker\""
            ),
        );
        let vm = vm_with(&status);
        let sb = get(&vm, "claude-myrepo").unwrap();
        assert!(sb.meta.ssh_agent.is_some(), "{grant}");
        start_checked(&vm, &sb, &plan(), &mut |_| {}, &|_| true).unwrap();
        let lines = vm.runner().call_lines();
        assert_eq!(
            lines.iter().any(|l| l == close),
            closed,
            "{grant}: {lines:#?}"
        );
    }
}
