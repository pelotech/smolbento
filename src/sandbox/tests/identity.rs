use super::*;

#[test]
fn hosts_line_stays_apart_and_is_added_once() {
    let d = tempfile::tempdir().unwrap();
    let f = d.path().join("hosts");
    std::fs::write(&f, "127.0.0.1 localhost").unwrap(); // no trailing newline
    let cmd = hosts_script(f.to_str().unwrap());
    for _ in 0..2 {
        let st = std::process::Command::new("sh")
            .args(["-c", &cmd])
            .status()
            .unwrap();
        assert!(st.success());
    }
    let got = std::fs::read_to_string(&f).unwrap();
    let lines: Vec<&str> = got.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(
        lines,
        ["127.0.0.1 localhost", "100.96.0.1 host.docker.internal"]
    );
}

#[test]
fn a_linking_skills_sandbox_links_the_store_as_root_at_start() {
    let vm = vm_with(&skills_status(RO_LABEL));
    let mut sb = get(&vm, "claude-myrepo").unwrap();
    ensure_running(&vm, &mut sb, || Ok(plan())).unwrap();
    let script = crate::skills::link_script(&sb.meta.skills.as_ref().unwrap().dirs).unwrap();
    let lines = vm.runner().call_lines();
    let want = format!("machine exec --name sbx-claude-myrepo -u root -- sh -c {script}");
    assert_eq!(
        lines.iter().filter(|l| **l == want).count(),
        1,
        "{lines:#?}"
    );
    assert!(script.contains("/home/agent/.claude/skills"));
    let at = |f: &dyn Fn(&String) -> bool| lines.iter().position(f).unwrap();
    let hosts = at(&|l| l.ends_with(&hosts_cmd()));
    let link = at(&|l| *l == want);
    assert!(hosts < link, "{lines:#?}");
}

#[test]
fn a_v3_workloads_image_user_is_resolved_before_agent_moves() {
    let vm = vm_with(&stopped());
    let mut sb = get(&vm, "claude-myrepo").unwrap();
    sb.meta.user = Some("1000".into());
    ensure_running(&vm, &mut sb, || Ok(plan())).unwrap();
    let lines = vm.runner().call_lines();
    // Before `identity_cmd`: uid 1000 is still `agent` the first time.
    assert_eq!(
        lines[3],
        format!(
            "machine exec --name sbx-claude-myrepo -u root -- sh -c {}",
            image_user_cmd("1000", 501, 20)
        )
    );
    assert!(lines[4].ends_with("usermod -o -u 501 agent"), "{lines:#?}");
    assert_eq!(lines.len(), 9, "{lines:#?}");
}

#[test]
fn a_numeric_image_user_is_resolved_once_and_kept_after_agent_moves() {
    let d = tempfile::tempdir().unwrap();
    let etc = d.path();
    let passwd = |agent_uid: u32| {
        std::fs::write(
            etc.join("passwd"),
            format!("root:x:0:0::/root:/bin/sh\nagent:x:{agent_uid}:1000::/home/agent:/bin/sh\n"),
        )
        .unwrap()
    };
    std::fs::write(etc.join("group"), "root:x:0:\nagent:x:1000:\n").unwrap();
    // First start: uid 1000 is `agent` (sandbox-templates); it's recorded and mapped.
    passwd(1000);
    assert_eq!(run_image_user_script(etc, "1000"), 0);
    let name = std::fs::read_to_string(etc.join("smolbento/image-user")).unwrap();
    assert_eq!(name, "agent\n");
    let log = std::fs::read_to_string(etc.join("usermod.log")).unwrap();
    assert_eq!(log, "-o -u 501 agent\n");
    // Its group takes the host gid too: Linux virtiofs creates files as the caller's gid.
    let groups = std::fs::read_to_string(etc.join("groupmod.log")).unwrap();
    assert_eq!(groups, "-o -g 20 agent\n");
    // Later starts: `agent` is 501 now and uid 1000 is nobody, yet the record still names it.
    passwd(501);
    assert_eq!(run_image_user_script(etc, "1000"), 0);
    assert_eq!(
        std::fs::read_to_string(etc.join("usermod.log")).unwrap(),
        log
    );
    // A uid without a passwd entry can't be mapped; root needs no mapping.
    let d = tempfile::tempdir().unwrap();
    std::fs::write(d.path().join("passwd"), "root:x:0:0::/root:/bin/sh\n").unwrap();
    assert_eq!(run_image_user_script(d.path(), "1001"), 3);
    assert_eq!(run_image_user_script(d.path(), "0"), 0);
}

#[test]
fn a_failing_usermod_names_its_error() {
    let fake = FakeRunner::new();
    fake.ok(&["machine", "status"], STATUS);
    fake.on(
        &[
            "machine",
            "exec",
            "--name",
            "sbx-claude-myrepo",
            "-u",
            "root",
        ],
        crate::smolvm::Output {
            code: 8,
            stderr: "usermod: user somebody is currently used by process 7\n".into(),
            ..Default::default()
        },
    );
    let vm = Smolvm::new(fake);
    let sb = get(&vm, "claude-myrepo").unwrap();
    let e = format!(
        "{:#}",
        map_image_user(&vm, &sb, "somebody", 501, 20).unwrap_err()
    );
    assert!(
        e.contains("usermod: user somebody is currently used by process 7"),
        "{e}"
    );
}

#[test]
fn launch_user_ignores_a_hostile_record() {
    let long = "a".repeat(33);
    for record in ["-x", "a:b", "a b", long.as_str(), "a\u{7}b", ""] {
        let fake = FakeRunner::new();
        fake.ok(&["machine", "status"], STATUS);
        fake.download(format!("{record}\n").as_bytes());
        let vm = Smolvm::new(fake);
        let mut sb = get(&vm, "claude-myrepo").unwrap();
        sb.meta.user = Some("1001:staff".into());
        assert_eq!(
            launch_user(&vm, &sb).as_deref(),
            Some("1001:staff"),
            "{record:?}"
        );
    }
    // The longest name allowed, and a trailing `$` (machine accounts).
    for ok in ["a".repeat(32), "_svc.x-1$".to_string()] {
        let fake = FakeRunner::new();
        fake.ok(&["machine", "status"], STATUS);
        fake.download(format!("{ok}\n").as_bytes());
        let vm = Smolvm::new(fake);
        let mut sb = get(&vm, "claude-myrepo").unwrap();
        sb.meta.user = Some("1001".into());
        assert_eq!(launch_user(&vm, &sb).as_deref(), Some(ok.as_str()));
    }
}

#[test]
fn launch_user_names_a_numeric_image_users_account() {
    let vm = vm_with(STATUS);
    let mut sb = get(&vm, "claude-myrepo").unwrap();
    assert_eq!(launch_user(&vm, &sb), None);
    sb.meta.user = Some("somebody".into());
    assert_eq!(launch_user(&vm, &sb).as_deref(), Some("somebody"));
    sb.meta.user = Some("0".into());
    assert_eq!(launch_user(&vm, &sb).as_deref(), Some("0"));
    assert!(
        vm.runner()
            .call_lines()
            .iter()
            .all(|l| !l.contains("machine cp"))
    );
    vm.runner().download(b"agent\n");
    sb.meta.user = Some("1000:staff".into());
    assert_eq!(launch_user(&vm, &sb).as_deref(), Some("agent:staff"));
    assert!(
        vm.runner()
            .call_lines()
            .last()
            .unwrap()
            .starts_with(&format!("machine cp sbx-claude-myrepo:{IMAGE_USER_FILE} ")),
    );
    // No record (no passwd entry): the raw uid.
    let fake = FakeRunner::new();
    fake.ok(&["machine", "status"], STATUS);
    fake.fail(&["machine", "cp"], "NOT_FOUND", "no such file");
    let vm = Smolvm::new(fake);
    let mut sb = get(&vm, "claude-myrepo").unwrap();
    sb.meta.user = Some("1001".into());
    assert_eq!(launch_user(&vm, &sb).as_deref(), Some("1001"));
}

#[test]
fn an_unmappable_image_user_is_a_warning() {
    let vm = vm_with(STATUS);
    let sb = get(&vm, "claude-myrepo").unwrap();
    assert_eq!(map_image_user(&vm, &sb, "somebody", 501, 20).unwrap(), None);
    vm.runner().on(
        &[
            "machine",
            "exec",
            "--name",
            "sbx-claude-myrepo",
            "-u",
            "root",
        ],
        crate::smolvm::Output {
            code: 3,
            ..Default::default()
        },
    );
    assert_eq!(
        map_image_user(&vm, &sb, "1001", 501, 20)
            .unwrap()
            .as_deref(),
        Some(
            "warning: claude-myrepo: couldn't map the image user 1001 to your uid; the \
             workspace may not be writable"
        )
    );
}

#[test]
fn identity_cmd_targets_the_host_uid_and_gid() {
    assert_eq!(
        identity_cmd(501, 20),
        "id -u agent >/dev/null 2>&1 || exit 0; g=$(id -g agent); [ \"$g\" = 0 ] || \
         [ \"$g\" = 20 ] || ! command -v groupmod >/dev/null 2>&1 || \
         groupmod -o -g 20 \"$(id -gn agent)\" || exit; \
         [ \"$(id -u agent)\" = 501 ] || usermod -o -u 501 agent"
    );
}
