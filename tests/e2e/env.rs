use super::*;

/// A shell loop printing `NAME=value` for each sbx sandbox variable, run in the guest by `exec`
/// and `run`.
pub(crate) const SBX_VARS: &str = "for v in SANDBOX_NAME SANDBOX_VM_ID SANDBOX_ID WORKSPACE_DIR SBX_AGENT \
                        SBX_CRED_ANTHROPIC_MODE; do eval \"echo $v=\\$$v\"; done";

pub(crate) fn sbx_vars(out: &str) -> std::collections::BTreeMap<String, String> {
    out.lines()
        .filter_map(|l| l.trim_end_matches('\r').split_once('='))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

/// `8-4-4-4-12` lowercase hex.
pub(crate) fn is_uuid(s: &str) -> bool {
    let parts: Vec<&str> = s.split('-').collect();
    parts.iter().map(|p| p.len()).eq([8, 4, 4, 4, 12])
        && parts.iter().all(|p| {
            p.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        })
}

/// sbx's sandbox variables reach the agent and `exec`; a fork gets its own name and id
/// (`machine branch -e` wins over what the fork inherits from its parent).
#[test]
#[ignore = "boots real VMs; run with `just e2e`"]
pub(crate) fn sbx_sandbox_variables_reach_the_agent_exec_and_forks() {
    let e = E2e::new("env");
    e.create_alpine();
    let ws = e.workspace();
    let exec = sbx_vars(&e.ok(&["exec", &e.name, "sh", "-c", SBX_VARS]));
    assert_eq!(exec["SANDBOX_NAME"], e.name, "{exec:?}");
    assert_eq!(exec["SANDBOX_VM_ID"], e.name, "{exec:?}");
    assert!(is_uuid(&exec["SANDBOX_ID"]), "{exec:?}");
    assert_eq!(exec["WORKSPACE_DIR"], ws.to_str().unwrap(), "{exec:?}");
    assert_eq!(exec["SBX_AGENT"], "shell", "{exec:?}");
    assert_eq!(exec["SBX_CRED_ANTHROPIC_MODE"], "none", "{exec:?}");

    // The agent (the shell preset's shell) sees the same values.
    let agent = sbx_vars(&e.ok(&["run", "--name", &e.name, "--", "-c", SBX_VARS]));
    assert_eq!(agent, exec, "the agent's variables match exec's");

    // A mountless sandbox can be forked. Set up as `create_alpine` does, plus the guest workdir
    // (sbx images have it; Alpine doesn't).
    let m = E2e::new("envm");
    m.ok(&[
        "create",
        "shell",
        "--name",
        &m.name,
        "-t",
        Image::alpine_agent_archive().to_str().unwrap(),
        "--cpus",
        "1",
        "-m",
        "1g",
    ]);
    guest_root(
        &m.name,
        "apk add -q bash && install -d -o agent /home/agent/workspace",
    );
    let fork = format!("{}-fork-1", m.name);
    let forks = Forks(vec![fork.clone()]);
    assert_eq!(m.ok(&["fork", &m.name]).trim(), fork);
    let parent = sbx_vars(&m.ok(&["exec", &m.name, "sh", "-c", SBX_VARS]));
    let child = sbx_vars(&m.ok(&["exec", &fork, "sh", "-c", SBX_VARS]));
    assert_eq!(parent["SANDBOX_NAME"], m.name, "{parent:?}");
    assert_eq!(
        child["SANDBOX_NAME"], fork,
        "the fork's own name: {child:?}"
    );
    assert_eq!(child["SANDBOX_VM_ID"], fork, "{child:?}");
    assert!(is_uuid(&child["SANDBOX_ID"]), "{child:?}");
    assert_ne!(
        child["SANDBOX_ID"], parent["SANDBOX_ID"],
        "the fork's own id"
    );
    assert_ne!(
        exec["SANDBOX_ID"], parent["SANDBOX_ID"],
        "an id per sandbox"
    );
    assert_eq!(child["WORKSPACE_DIR"], parent["WORKSPACE_DIR"], "{child:?}");
    assert!(!parent["WORKSPACE_DIR"].is_empty(), "{parent:?}");
    m.ok(&["rm", "-f", &fork]);
    drop(forks);
}

#[test]
#[ignore = "boots real VMs; run with `just e2e`"]
pub(crate) fn env_files_create_exec_and_remove() {
    let e = E2e::new("envf");
    let dir = e.dir.path().join("envs");
    std::fs::create_dir_all(dir.join("ws")).unwrap();
    let base = dir.join("base.yaml");
    let local = dir.join("local.yaml");
    std::fs::write(
        &base,
        format!(
            "schemaVersion: \"1\"\nagent: shell\nname: {}\nworkspace: ./ws\n\
             args:\n  greeting:\n    required: true\n\
             env:\n  GREETING: ${{{{ env.args.greeting }}}}\n\
             secrets:\n  github:\n    value: dummy-token\n\
             sandboxOptions:\n  template: {}\n  cpus: 1\n  memory: 1g\n",
            e.name,
            Image::alpine_agent_archive().display()
        ),
    )
    .unwrap();
    std::fs::write(&local, "env:\n  EXTRA: \"1\"\n").unwrap();
    let (base, local) = (base.to_str().unwrap(), local.to_str().unwrap());

    // The secret lives in the real keychain on macOS: remove it on every exit path.
    struct EnvCleanup<'a>(&'a E2e, [&'a str; 2]);
    impl Drop for EnvCleanup<'_> {
        fn drop(&mut self) {
            let [base, local] = self.1;
            let _ = self.0.sbt(&[
                "env",
                "rm",
                "--force",
                "--env-arg",
                "greeting=hi",
                base,
                local,
            ]);
        }
    }
    let _cleanup = EnvCleanup(&e, [base, local]);

    e.ok(&[
        "env",
        "create",
        "--force",
        base,
        local,
        "--env-arg",
        "greeting=hi",
    ]);
    assert_ne!(e.state(), "absent");
    // Alpine has no bash; add it as `create_alpine` does.
    guest_root(&e.name, "apk add -q bash");

    let out = e.ok(&[
        "env",
        "exec",
        "--env-arg",
        "greeting=hi",
        base,
        local,
        "--",
        "sh",
        "-c",
        "echo $GREETING $EXTRA; pwd",
    ]);
    let ws = dir.join("ws").canonicalize().unwrap();
    assert_eq!(out, format!("hi 1\n{}\n", ws.display()));

    let secrets = e.ok(&["secret", "ls"]);
    assert!(
        secrets.contains("github") && secrets.contains(&e.name),
        "{secrets}"
    );

    e.ok(&[
        "env",
        "rm",
        "--force",
        "--env-arg",
        "greeting=hi",
        base,
        local,
    ]);
    assert_eq!(e.state(), "absent");
    let secrets = e.ok(&["secret", "ls"]);
    assert!(!secrets.contains(&e.name), "{secrets}");
}
