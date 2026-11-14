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
fn a_start_takes_fuse_away_and_keeps_env_files_read_only_when_asked() {
    let vm = vm_with(&stopped());
    let mut sb = get(&vm, "claude-myrepo").unwrap();
    sb.meta.no_fuse = true;
    sb.meta.read_only_files = vec!["/w/sbxenv.yaml".into()];
    ensure_running(&vm, &mut sb, || Ok(plan())).unwrap();
    let lines = vm.runner().call_lines();
    let script = crate::sandbox::lockdown_cmd(true, &sb.meta.read_only_files).unwrap();
    assert!(script.contains("rm -f /dev/fuse"), "{script}");
    assert!(
        script.contains("mount --bind '/w/sbxenv.yaml' '/w/sbxenv.yaml'"),
        "{script}"
    );
    let want = format!("machine exec --name sbx-claude-myrepo -u root -- sh -c {script}");
    assert_eq!(
        lines.iter().filter(|l| **l == want).count(),
        1,
        "{lines:#?}"
    );

    // Nothing to do without either.
    let vm = vm_with(&stopped());
    let mut sb = get(&vm, "claude-myrepo").unwrap();
    ensure_running(&vm, &mut sb, || Ok(plan())).unwrap();
    assert!(crate::sandbox::lockdown_cmd(false, &[]).is_none());
    assert!(
        !vm.runner()
            .call_lines()
            .iter()
            .any(|l| l.contains("/dev/fuse"))
    );
}
