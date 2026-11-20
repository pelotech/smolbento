use super::*;

#[test]
#[ignore = "boots real VMs and needs httpbin.org; run with `just e2e`"]
pub(crate) fn fork_round_trip() {
    let e = E2e::new("fork");
    let ws = e.workspace();
    let ws = ws.to_str().unwrap();
    e.git_repo();
    e.ok(&["policy", "init", "balanced"]);
    e.httpbin_secret("TOK");

    e.create_clone();

    guest_root(&e.name, "echo before > /root/before");
    e.guest_commit(&e.name, "before-fork");

    // Guard the predicted names first: a partial failure still cleans up the copy it made.
    let forks = Machines(vec![
        format!("{}-fork-1", e.name),
        format!("{}-fork-2", e.name),
    ]);
    let names: Vec<String> = e
        .ok(&["fork", &e.name, "--count", "2"])
        .lines()
        .map(str::to_string)
        .collect();
    assert_eq!(names, forks.0);
    let (f1, f2) = (&forks.0[0], &forks.0[1]);

    let ls: serde_json::Value = serde_json::from_str(&e.ok(&["ls", "--json"])).unwrap();
    let row = |n: &str| {
        ls.as_array()
            .unwrap()
            .iter()
            .find(|r| r["name"] == n)
            .unwrap_or_else(|| panic!("{n} listed: {ls}"))
            .clone()
    };
    let (parent_row, f1_row) = (row(&e.name), row(f1));
    assert_eq!(f1_row["fork_of"], e.name.as_str());
    assert!(
        f1_row["created_at"].as_str() > parent_row["created_at"].as_str(),
        "a fork's created time is its own: {f1_row} vs {parent_row}"
    );

    let root_test = |sb: &str, path: &str| root_sh(sb, &format!("test -e {path}")).status.success();
    for f in [f1, f2] {
        assert!(root_test(f, "/root/before"), "{f} sees the parent's files");
        let log = e.ok(&["exec", f, "git", "-C", ws, "log", "--format=%s", "-1"]);
        assert_eq!(log, "before-fork\n", "{f} has the parent's commit");
    }
    guest_root(f1, "touch /root/only-1");
    assert!(root_test(f1, "/root/only-1"));
    // Positive controls: the exec works in these machines, so a missing file means missing.
    assert!(root_test(f2, "/root/before"), "{f2} is reachable");
    assert!(!root_test(f2, "/root/only-1"), "forks don't share writes");
    assert!(
        root_test(&e.name, "/root/before"),
        "the parent is reachable"
    );
    assert!(
        !root_test(&e.name, "/root/only-1"),
        "the parent doesn't see fork writes"
    );

    assert!(
        basic_auth_ok(&e, f1, "TOK", "real-secret-xyz"),
        "the fork's secret"
    );
    e.ok(&["stop", f1]);
    e.ok(&["start", f1]);
    assert!(
        basic_auth_ok(&e, f1, "TOK", "real-secret-xyz"),
        "the fork's secret after a restart"
    );

    e.guest_commit(f1, "in-fork-1");
    e.git_ok(&["fetch", "-q", &format!("sandbox-{f1}")]);
    let log = e.git_ok(&["log", "--format=%s", "-1", &format!("sandbox-{f1}/main")]);
    assert_eq!(log, "in-fork-1\n");
    let parent_remote = format!("sandbox-{}", e.name);
    e.git_ok(&["fetch", "-q", &parent_remote]);
    let log = e.git_ok(&["log", "--format=%s", &format!("{parent_remote}/main")]);
    assert_eq!(
        log, "before-fork\nhost commit\n",
        "the parent doesn't have the fork's commit"
    );

    let out = e.sbt(&["rm", "-f", &e.name]);
    let err = err_text(&out);
    assert!(!out.status.success(), "rm of a parent with forks fails");
    assert!(err.contains("remove its forks first"), "{err}");
    e.ok(&["rm", "-f", f1, f2]);
    e.ok(&["rm", "-f", &e.name]);
    let remotes = e.git_ok(&["remote"]);
    for n in [f1, f2, &e.name] {
        let remote = format!("sandbox-{n}");
        assert!(!remotes.lines().any(|r| r == remote), "{remote} removed");
    }
}

#[test]
#[ignore = "boots real VMs; run with `just e2e`"]
pub(crate) fn template_round_trip() {
    let e = E2e::new("tpl");
    e.create_alpine_offline();
    guest_root(&e.name, "echo kept > /etc/marker && rm /etc/motd");
    // Running: refused without a terminal.
    let out = e.sbt(&["template", "save", &e.name, "e2e-tpl:v1"]);
    assert!(!out.status.success());
    assert!(err_text(&out).contains("cannot save a running sandbox"));
    e.ok(&["stop", &e.name]);
    let out = e.ok(&["template", "save", &e.name, "e2e-tpl:v1", "-o", "tpl.tar"]);
    assert!(
        out.contains("Saved template docker.io/library/e2e-tpl:v1"),
        "{out}"
    );
    assert!(
        e.ok(&["template", "ls", "-q"])
            .contains("docker.io/library/e2e-tpl:v1")
    );

    // A second sandbox from it has the file and the deletion.
    let copy = format!("{}-copy", e.name);
    let _guard = Machines(vec![copy.clone()]);
    let ws = e.workspace();
    e.create(&copy, &["-t", "e2e-tpl:v1", "--pull", "never", "shell"]);
    let got = e.sh_ok(
        &copy,
        "cat /etc/marker; [ -e /etc/motd ] && echo present || echo gone; pwd",
    );
    assert!(got.contains("kept"), "{got}");
    assert!(got.contains("gone") && !got.contains("present"), "{got}");
    assert!(
        got.contains(ws.to_str().unwrap()),
        "exec runs in the workspace: {got}"
    );

    // Nested saves are refused (smolvm can't pack them: see development-status.md).
    e.ok(&["stop", &copy]);
    let out = e.sbt(&["template", "save", &copy, "e2e-tpl:v2"]);
    assert!(!out.status.success());
    assert!(err_text(&out).contains("created from template"));

    // rm then load restores it; the copy keeps working without the pack.
    e.ok(&["template", "rm", "-f", "e2e-tpl:v1"]);
    assert!(
        !e.ok(&["template", "ls", "-q"])
            .contains("docker.io/library/e2e-tpl:v1")
    );
    e.ok(&["start", &copy]);
    let again = e.ok(&["exec", &copy, "cat", "/etc/marker"]);
    assert!(again.contains("kept"), "{again}");
    e.ok(&["template", "load", "tpl.tar"]);
    assert!(
        e.ok(&["template", "ls", "-q"])
            .contains("docker.io/library/e2e-tpl:v1")
    );
}
