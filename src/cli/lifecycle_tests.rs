
use clap::Parser;

use super::super::{Cli, Cmd, DiskSizes, SandboxOpts};
use crate::testutil::*;

#[test]
fn create_clone_mounts_the_repo_and_adds_the_remote() {
    let mut t = test_env(&[]);
    let (_d, root) = temp_repo();
    t.ctx.cwd = root.clone();
    creatable_as(&t, "claude-repo");
    t.sbt(&["create", "--clone", "claude", "."]).unwrap();
    let create = t
        .ctx
        .vm
        .runner()
        .call_lines()
        .into_iter()
        .find(|l| l.contains("machine create"))
        .unwrap();
    assert!(
        create.contains(&format!(
            "-v {}/.git:/run/sandbox/source:ro",
            root.display()
        )),
        "{create}"
    );
    assert!(create.contains("--label sbx.clone=true"), "{create}");
    assert_eq!(
        git_config(&root, "remote.sandbox-claude-repo.uploadpack"),
        "smolbento _upload-pack claude-repo"
    );
    assert_eq!(
        git_config(&root, "remote.sandbox-claude-repo.tagOpt"),
        "--no-tags"
    );
}

#[test]
fn clone_needs_a_repo_before_smolvm_is_called() {
    let mut t = test_env(&[]);
    let err = t.sbt_err(&["create", "--clone", "claude", "."]);
    assert!(err.contains("--clone needs a git repository"), "{err}");
    assert!(!t.made("machine create"));
}

#[test]
fn clone_needs_a_workspace_path_before_smolvm_is_called() {
    let mut t = test_env(&[]);
    let err = t.sbt_err(&["create", "--clone", "claude"]);
    assert!(err.contains("--clone needs a workspace path"), "{err}");
    assert!(!t.made("machine create"));
}

#[test]
fn clone_needs_a_free_remote_before_smolvm_is_called() {
    let mut t = test_env(&[]);
    let (_d, root) = temp_repo();
    git(
        &root,
        &[
            "remote",
            "add",
            "sandbox-claude-repo",
            "https://example.com/x",
        ],
    );
    t.ctx.cwd = root;
    t.no_machine();
    let err = t.sbt_err(&["create", "--clone", "claude", "."]);
    assert!(
        err.contains("already has a remote 'sandbox-claude-repo'"),
        "{err}"
    );
    assert!(!t.made("machine create"));
}

#[test]
fn clone_create_still_works_when_a_remote_url_has_a_token() {
    // The credential warning goes to stderr (see clone::userinfo_remotes' own test); it must
    // not stop the create.
    let mut t = test_env(&[]);
    let (_d, root) = temp_repo();
    git(
        &root,
        &[
            "remote",
            "add",
            "origin",
            "https://u:tok@github.com/o/r.git",
        ],
    );
    t.ctx.cwd = root;
    creatable_as(&t, "claude-repo");
    t.sbt(&["create", "--clone", "claude", "."]).unwrap();
    assert!(t.made("machine create"));
}

#[test]
fn a_failed_clone_create_removes_the_remote_only_when_no_machine_exists() {
    // machine create fails: no machine, so the remote is removed again.
    let mut t = test_env(&[]);
    let (_d, root) = temp_repo();
    t.ctx.cwd = root.clone();
    let fake = t.runner();
    fake.fail(&["machine", "status"], "NOT_FOUND", "vm not found");
    fake.fail(&["machine", "create"], "CREATE_FAILED", "no space left");
    assert!(t.sbt(&["create", "--clone", "claude", "."]).is_err());
    assert_eq!(git_config(&root, "remote.sandbox-claude-repo.url"), "");

    // Created but the start failed (e.g. the clone step): the machine exists, so the remote
    // stays for the next start's retry.
    let mut t = test_env(&[]);
    t.ctx.cwd = root.clone();
    let fake = t.runner();
    creatable_as(&t, "claude-repo");
    fake.fail(&["machine", "start"], "START_FAILED", "boot failed");
    assert!(t.sbt(&["create", "--clone", "claude", "."]).is_err());
    assert_eq!(
        git_config(&root, "remote.sandbox-claude-repo.url"),
        "file:///sbt/claude-repo"
    );
}

#[test]
fn a_failed_clone_create_keeps_a_remote_it_didnt_add() {
    // Left by an earlier `run --rm` of the same name, with the agent's fetched commits.
    let mut t = test_env(&[]);
    let (_d, root) = temp_repo();
    crate::workspace::clone::add_remote(&root, "claude-repo").unwrap();
    t.ctx.cwd = root.clone();
    let fake = t.runner();
    fake.fail(&["machine", "status"], "NOT_FOUND", "vm not found");
    fake.fail(&["machine", "create"], "CREATE_FAILED", "no space left");
    assert!(t.sbt(&["create", "--clone", "claude", "."]).is_err());
    assert_eq!(
        git_config(&root, "remote.sandbox-claude-repo.url"),
        "file:///sbt/claude-repo"
    );
}

#[test]
fn create_builds_the_machine_from_the_preset() {
    let mut t = test_env(&[]);
    creatable_as(&t, "claude-proj");
    t.sbt(&[
        "create", "claude", ".", "--cpus", "2", "-m", "4g", "-e", "A=1", "-p", "8080:80",
    ])
    .unwrap();

    let ws = t.ctx.cwd.display().to_string();
    let create = t
        .ctx
        .vm
        .runner()
        .calls()
        .into_iter()
        .find(|c| c.get(1).is_some_and(|a| a == "create"))
        .unwrap();
    let pair = |flag: &str| -> Vec<String> {
        create
            .windows(2)
            .filter(|w| w[0] == flag)
            .map(|w| w[1].clone())
            .collect()
    };
    assert_eq!(pair("-n"), vec!["sbx-claude-proj"]);
    // The agent kit's image, archived in the kit cache.
    let image = pair("--image");
    assert!(
        image[0].starts_with(&t.ctx.paths.kit_cache().join("images").display().to_string()),
        "{image:?}"
    );
    assert_eq!(
        pair("-v"),
        vec![
            format!("{ws}:{ws}"),
            // Skills default to readonly: the store, shared read-only.
            format!(
                "{}:/run/sbx/skills-shared:ro",
                t.ctx.paths.skills_store().display()
            ),
            "/var/lib/docker".into(),
            "/var/lib/containerd".into()
        ]
    );
    assert_eq!(pair("--cpus"), vec!["2"]);
    assert_eq!(pair("--mem"), vec!["4096"]);
    // The user's -e first, then sbx's sandbox variables (SANDBOX_ID is a fresh UUID).
    let mut env = pair("-e");
    let id = env.remove(3);
    assert!(
        id.starts_with("SANDBOX_ID=") && id.len() == "SANDBOX_ID=".len() + 36,
        "{id}"
    );
    assert_eq!(
        env,
        vec![
            "A=1".to_string(),
            "SANDBOX_NAME=claude-proj".into(),
            "SANDBOX_VM_ID=claude-proj".into(),
            format!("WORKSPACE_DIR={ws}"),
            // The default stand-in declares no credential, so no mode; IS_SANDBOX is the
            // image's own.
            "SBX_AGENT=claude".into(),
        ]
    );
    assert_eq!(pair("-p"), vec!["8080:80"]);
    assert!(pair("--label").contains(&"sbx.created=1000000".to_string()));
    assert!(pair("--label").contains(&"sbx.docker=true".to_string()));
    // Docker-in-sandbox is the shipped `docker` kit: its volumes above, its startup hook here.
    // The agent's kit, then the shipped docker kit.
    let kits = pair("--label");
    let kits = kits.iter().find(|l| l.starts_with("sbx.kits=")).unwrap();
    assert!(
        kits.ends_with(&format!(
            ",{}]",
            r#"{"name":"docker","ref":"builtin:docker","provides":["docker@1.0.0"]}"#
        )),
        "{kits}"
    );
    let uploads = t.runner().uploads();
    let (_, script) = uploads
        .iter()
        .find(|(to, _)| to == "sbx-claude-proj:/etc/smolbento/startup.d/01-docker.sh")
        .expect("the docker kit's startup script");
    assert!(script.contains("exec dockerd"), "{script}");
    assert!(
        script.contains("$d sh -c ") && script.contains("fi' &\n"),
        "dockerd runs in the background: {script}"
    );
    // A host-mounted sandbox can't be forked, so it isn't started branchable.
    assert!(
        t.calls()
            .contains(&"machine start -n sbx-claude-proj".to_string())
    );
}

#[test]
fn create_on_an_existing_name_fails_before_touching_the_policy() {
    let mut t = test_env(&[]);
    t.runner().ok(
        &["machine", "status"],
        &json("sbx-claude-proj", "stopped", "claude-proj"),
    );
    let before = std::fs::read_to_string(t.ctx.paths.policy_file()).unwrap();
    let err = t.sbt_err(&["create", "claude", ".", "--deny-network", "evil.com"]);
    assert!(
        err.contains("sandbox 'claude-proj' already exists"),
        "{err}"
    );
    assert_eq!(
        std::fs::read_to_string(t.ctx.paths.policy_file()).unwrap(),
        before
    );
    assert!(
        !t.calls()
            .iter()
            .any(|l| l.contains("create") || l.contains("start"))
    );
}

/// The request `create AGENT` makes once its kits are planned (no machine touched).
fn planned(
    t: &TestEnv,
    agent: &str,
    opts: &SandboxOpts,
) -> anyhow::Result<crate::sandbox::CreateRequest> {
    let (mut req, w) = super::kit_target(&t.ctx, &[agent.to_string()], opts, false)?;
    let quiet = crate::cli::progress::Progress::new(t.ctx.out.clone(), false, false, true);
    super::kit_plan(&t.ctx, &mut req, w, opts, &quiet)?;
    Ok(req)
}

fn creatable(t: &TestEnv) {
    creatable_as(t, "claude-proj");
}

#[test]
fn t_replaces_a_kit_image() {
    let mut t = test_env(&[]);
    creatable_as(&t, "shell-proj");
    t.sbt(&["create", "shell", "-t", "alpine:3"]).unwrap();
    let create = t.calls_of("machine create").remove(0);
    assert!(create.contains("--image alpine:3 "), "{create}");
    // The kit stays, with its command; an image whose name isn't Docker-enabled gets no dockerd.
    assert!(create.contains(r#"sbx.kits=[{"name":"shell""#), "{create}");
    assert!(create.contains(r#"sbx.command=["bash","-l"]"#), "{create}");
    assert!(create.contains("sbx.docker=false"), "{create}");
    // Any workload kit, not only an agent.
    let mut t = test_env(&[("SMOLBENTO_KIT_ALLOW_LOCAL_KITS", "true")]);
    creatable_as(&t, "toolbox-proj");
    let kit = format!(
        "{}/tests/fixtures/kits/v2/tool-workload",
        env!("CARGO_MANIFEST_DIR")
    );
    t.sbt(&["create", &kit, "-t", "img:2"]).unwrap();
    let create = t.calls_of("machine create").remove(0);
    assert!(create.contains("--image img:2 "), "{create}");
}

#[test]
fn claude_without_a_key_installs_with_mode_none() {
    let mut t = test_env(&[]);
    agent_stand_in(&t, "claude", CLAUDE_STAND_IN);
    creatable(&t);
    t.sbt(&["create", "claude", "."]).unwrap();
    let create = t.calls_of("machine create").remove(0);
    assert!(
        create.contains("-e SBX_CRED_ANTHROPIC_MODE=none "),
        "{create}"
    );
    assert!(!create.contains("--credential"), "{create}");
    assert!(
        t.calls_of("machine exec")
            .iter()
            .any(|l| l.contains("echo mode=")),
        "the install step runs"
    );
}

#[test]
fn an_oauth_credential_binds_its_api_key() {
    let mut t = test_env(&[]);
    agent_stand_in(&t, "claude", CLAUDE_STAND_IN);
    global_secret(&t, "anthropic", "sk-ant-test");
    creatable(&t);
    t.sbt(&["create", "claude", "."]).unwrap();
    let create = t.calls_of("machine create").remove(0);
    assert!(
        create.contains("-e SBX_CRED_ANTHROPIC_MODE=apikey "),
        "{create}"
    );
    assert!(create.contains("api.anthropic.com"), "{create}");
    assert!(!create.contains("sk-ant-test"), "never in argv: {create}");
}

/// Creates `claude-proj` with `create_args` (the full claude stand-in), then saves it,
/// stopped, as template `t:v1`.
fn kit_template(create_args: &[&str]) -> TestEnv {
    let mut t = test_env(&[]);
    agent_stand_in(&t, "claude", CLAUDE_STAND_IN);
    creatable(&t);
    t.sbt(create_args).unwrap();
    // The create's labels, as smolvm reports them for the stopped sandbox (later replies win).
    let calls = t.ctx.vm.runner().calls();
    let create = calls
        .iter()
        .find(|c| c.get(1).is_some_and(|a| a == "create"))
        .unwrap();
    let labels: Vec<(String, String)> = create
        .windows(2)
        .filter(|w| w[0] == "--label")
        .filter_map(|w| w[1].split_once('=').map(|(k, v)| (k.into(), v.into())))
        .collect();
    let labels: Vec<(&str, &str)> = labels
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    t.sandbox("claude-proj", "stopped", &labels);
    let r = t.runner();
    r.ok(&["pack", "create"], "");
    r.during(&["pack", "create"], |args| {
        let out = args.last().unwrap();
        std::fs::write(out, "stub").unwrap();
        std::fs::write(format!("{out}.smolmachine"), "packed").unwrap();
    });
    t.sbt(&["template", "save", "claude-proj", "t:v1"]).unwrap();
    t
}

#[test]
fn save_records_the_kits_and_args() {
    let t = kit_template(&["create", "claude", ".", "--kit-arg", "model=x"]);
    let e = crate::templates::Store::new(&t.ctx.paths)
        .find_ref("t:v1")
        .unwrap()
        .unwrap();
    assert_eq!(e.agent, "claude");
    let kits = &t.ctx.env["SMOLBENTO_AGENT_KITS_DIR"];
    assert!(
        e.kits[0]
            .reference
            .starts_with(&format!("{kits}/claude@sha256:"))
    );
    assert_eq!(e.kits[0].args.get("model").map(String::as_str), Some("x"));
    assert!(e.kits.iter().any(|k| k.reference == "builtin:docker"));
}

#[test]
fn a_kit_template_reruns_install_steps_from_the_cache() {
    let mut t = kit_template(&["create", "claude", "."]);
    let fake = t.runner();
    fake.ok(&["machine", "status"], &json("sbx-bb", "created", "bb"));
    fake.missing_until_created("sbx-bb");
    t.sbt(&[
        "create", "claude", "-t", "t:v1", "--pull", "never", "--name", "bb",
    ])
    .unwrap();
    let create = t
        .calls_of("machine create")
        .into_iter()
        .find(|l| l.contains("-n sbx-bb "))
        .unwrap();
    assert!(create.contains(" --from "), "{create}");
    assert!(!create.contains("--image"), "{create}");
    assert!(
        create.contains("-e SBX_CRED_ANTHROPIC_MODE=none "),
        "{create}"
    );
    let execs = t.calls_of("machine exec");
    assert!(
        execs
            .iter()
            .any(|l| l.contains("sbx-bb") && l.contains("echo mode=")),
        "the install step runs again: {execs:#?}"
    );
}

/// A current template of the `shell` stand-in plus `extra` records, saved as `x:v1`.
fn template_with(t: &TestEnv, extra: Vec<crate::sandbox::labels::KitRecord>, docker: bool) {
    let mut kits = saved_template_kits(t, "shell");
    kits.extend(extra);
    let src = t.ctx.cwd.join("x.smolmachine");
    std::fs::write(&src, "packed").unwrap();
    crate::templates::Store::new(&t.ctx.paths)
        .add(
            crate::templates::Entry {
                repository: "docker.io/library/x".into(),
                tag: "v1".into(),
                agent: "shell".into(),
                image: "img:1".into(),
                docker,
                created_at: "1970-01-12T13:46:30Z".into(),
                kits,
                ..Default::default()
            },
            &src,
        )
        .unwrap();
}

fn record(reference: &str) -> crate::sandbox::labels::KitRecord {
    crate::sandbox::labels::KitRecord {
        name: "k".into(),
        reference: reference.into(),
        provides: vec![],
        format: None,
        args: Default::default(),
    }
}

#[test]
fn a_template_never_reads_a_layout_outside_the_stand_ins() {
    // A prebuilt layout anywhere else (a planted directory) isn't a kit to load as-is.
    let t = test_env(&[]);
    let planted = t.ctx.cwd.join("planted");
    std::fs::create_dir_all(&planted).unwrap();
    crate::kits::registry::fixtures::oci_layout(
        &planted,
        Some(r#"{"schemaVersion":"3","kind":"mixin"}"#),
        &[],
        "{}",
    );
    let r = crate::kits::load::pinned(
        &t.ctx,
        &planted.display().to_string(),
        true,
        None,
        None,
        &mut |_| {},
    );
    assert!(r.is_err(), "loaded a planted layout");
}

#[test]
fn a_template_drops_its_docker_kit_when_docker_is_disabled() {
    let mut t = test_env(&[("SMOLBENTO_DOCKER", "false")]);
    let mut docker = record("builtin:docker");
    docker.name = "docker".into();
    template_with(&t, vec![docker], true);
    let fake = t.runner();
    fake.ok(&["machine", "status"], &json("sbx-bb", "created", "bb"));
    fake.missing_until_created("sbx-bb");
    t.sbt(&["create", "shell", "-t", "x:v1", "--name", "bb"])
        .unwrap();
    let create = t.calls_of("machine create").remove(0);
    assert!(!create.contains("builtin:docker"), "{create}");
    assert!(create.contains("--label sbx.docker=false"), "{create}");
}

#[test]
fn pull_never_names_itself_for_a_template_kit_that_needs_a_build() {
    let mut t = test_env(&[]);
    let kit = t.ctx.cwd.join("src-kit");
    std::fs::create_dir_all(&kit).unwrap();
    std::fs::write(
        kit.join("kit.yaml"),
        "# syntax=docker/sandbox-kit:3\nschemaVersion: \"3\"\nkind: mixin\n",
    )
    .unwrap();
    template_with(&t, vec![record(&kit.display().to_string())], false);
    creatable_as(&t, "bb");
    let err = t.sbt_err(&[
        "create", "shell", "-t", "x:v1", "--pull", "never", "--name", "bb",
    ]);
    assert!(err.contains("--pull never"), "{err}");
    assert!(!err.contains("--offline"), "{err}");
}

#[test]
fn template_kits_follow_kit_policy() {
    let tool = format!(
        "{}/tests/fixtures/kits/v2/tool-mixin",
        env!("CARGO_MANIFEST_DIR")
    );
    // A local kit, under --pull never, still needs kit.allowLocalKits.
    let mut t = test_env(&[("SMOLBENTO_KIT_ALLOW_LOCAL_KITS", "false")]);
    template_with(&t, vec![record(&tool)], false);
    creatable_as(&t, "bb");
    let err = t.sbt_err(&[
        "create", "shell", "-t", "x:v1", "--pull", "never", "--name", "bb",
    ]);
    assert!(err.contains("local"), "{err}");
    // kit.requireSignature: a local kit is refused, and a registry kit can't be verified
    // without the registry.
    for (kit, want) in [
        (tool.as_str(), "not signed"),
        ("acme/k:1@sha256:ab", "requireSignature"),
    ] {
        let mut t = test_env(&[
            ("SMOLBENTO_KIT_ALLOW_LOCAL_KITS", "true"),
            ("SMOLBENTO_KIT_REQUIRE_SIGNATURE", "true"),
            ("SMOLBENTO_KIT_ALLOWED_SOURCES", r#"["docker.io/acme/"]"#),
        ]);
        template_with(&t, vec![record(kit)], false);
        creatable_as(&t, "bb");
        let err = t.sbt_err(&[
            "create", "shell", "-t", "x:v1", "--pull", "never", "--name", "bb",
        ]);
        assert!(err.contains(want), "{kit}: {err}");
    }
}

#[test]
fn an_old_template_is_refused_on_create() {
    let mut t = test_env(&[]);
    legacy_template(&t, "old:v1", "shell");
    let err = t.sbt_err(&["create", "shell", "-t", "old:v1"]);
    assert_eq!(
        err,
        "template docker.io/library/old:v1 was saved by an older smolbento; save it again \
             from a new sandbox"
    );
}

#[test]
fn a_built_in_name_loads_its_kit() {
    let mut t = test_env(&[]);
    creatable(&t);
    t.sbt(&["create", "claude", "."]).unwrap();
    let calls = t.calls();
    let create = calls
        .iter()
        .find(|l| l.starts_with("machine create"))
        .unwrap();
    let kits = t.ctx.env["SMOLBENTO_AGENT_KITS_DIR"].clone();
    assert!(
        create.contains(&format!("{kits}/claude@sha256:")),
        "{create}"
    );
    assert!(create.contains("--label sbx.agent=claude "), "{create}");
    assert!(create.contains("sbx.command="), "{create}");
    assert!(
        create.contains("sbx.agent-file=/home/agent/.claude/CLAUDE.md"),
        "{create}"
    );
}

#[test]
fn built_in_agents_skip_the_kit_trust_checks() {
    let mut t = test_env(&[]);
    t.sbt(&["settings", "set", "kit.allowedSources", r#"["ghcr.io/x/"]"#])
        .unwrap();
    t.sbt(&["settings", "set", "kit.requireSignature", "true"])
        .unwrap();
    creatable(&t);
    t.sbt(&["create", "claude", "."]).unwrap();
    assert!(t.made("machine create"));
}

#[test]
fn a_missing_agent_kit_names_its_ref() {
    let empty = tempfile::tempdir().unwrap();
    let dir = empty.path().display().to_string();
    let mut t = test_env(&[("SMOLBENTO_AGENT_KITS_DIR", &dir)]);
    t.sbt(&["settings", "set", "kit.requireSignature", "true"])
        .unwrap();
    creatable(&t);
    let err = t.sbt_err(&["create", "claude", "."]);
    assert!(err.contains(&format!("{dir}/claude")), "{err}");
    assert!(
        !err.contains("allowedSources") && !err.contains("signature"),
        "{err}"
    );
}

#[test]
fn create_deny_network_adds_sandbox_deny_rules() {
    let mut t = test_env(&[]);
    set_policy(&t, "mode = \"balanced\"\n");
    global_github_secret(&t);
    creatable(&t);
    t.sbt(&[
        "create",
        "claude",
        ".",
        "--deny-network",
        "evil.com,10.0.0.0/8",
        "--deny-network",
        "tracker.example",
    ])
    .unwrap();

    // One sandbox-scoped rule per value, as `policy deny network --sandbox` adds them.
    assert_eq!(
        sandbox_rules(&t, "claude-proj"),
        vec![
            deny(&["evil.com"]),
            deny(&["10.0.0.0/8"]),
            deny(&["tracker.example"])
        ]
    );
    let p = crate::policy::Policy::load(&t.ctx.paths).unwrap();
    assert!(p.rules.is_empty(), "nothing global: {p:?}");

    let lines = t.calls();
    let create = lines
        .iter()
        .find(|l| l.starts_with("machine create"))
        .unwrap();
    assert!(create.contains(" --deny-cidr 10.0.0.0/8 "), "{create}");
    // The sandbox keeps its mode and secrets.
    assert!(
        create.contains(" --credential gh_token=GH_TOKEN@api.github.com,github.com,"),
        "{create}"
    );
    assert!(create.contains("registry.npmjs.org"), "{create}");
    assert!(!create.contains("gh-123"));
}

#[test]
fn create_denies_host_loopback_unless_a_localhost_rule_applies() {
    let rule = "[[rules]]\nid = \"r-1\"\ndecision = \"allow\"\nresources = [\"LOCALHOST:11434\"]\n";
    for mode in ["allow-all", "balanced", "deny-all"] {
        for localhost in [false, true] {
            let mut t = test_env(&[]);
            let extra = if localhost { rule } else { "" };
            set_policy(&t, &format!("mode = \"{mode}\"\n{extra}"));
            creatable(&t);
            t.sbt(&["create", "claude", "."]).unwrap();
            let lines = t.calls();
            let create = lines
                .iter()
                .find(|l| l.starts_with("machine create"))
                .unwrap();
            for cidr in ["127.0.0.0/8", "::1/128"] {
                assert_eq!(
                    create.contains(&format!(" --deny-cidr {cidr} ")),
                    !localhost,
                    "{mode}: {create}"
                );
            }
            assert_eq!(
                create.contains("--label sbx.host-access=true"),
                localhost,
                "{mode}: {create}"
            );
            // A restricted sandbox with host access gets the gateway from the start.
            if mode != "allow-all" {
                assert_eq!(
                    create.contains("--allow-cidr 100.96.0.1/32"),
                    localhost,
                    "{mode}: {create}"
                );
            }
            if !localhost {
                // Not a rule: `policy ls` doesn't show it.
                let p = crate::policy::Policy::load(&t.ctx.paths).unwrap();
                assert!(p.rules.is_empty(), "{mode}: {p:?}");
                assert!(sandbox_rules(&t, "claude-proj").is_empty(), "{mode}");
            }
        }
    }
}

#[test]
fn deny_network_is_checked_before_the_machine_is_created() {
    // A bad host: nothing is created and the policy is untouched.
    let mut t = test_env(&[]);
    let fake = t.runner();
    fake.fail(&["machine", "status"], "NOT_FOUND", "vm not found");
    let before = std::fs::read_to_string(t.ctx.paths.policy_file()).unwrap();
    let err = t
        .sbt(&[
            "create",
            "claude",
            ".",
            "--deny-network",
            "ok.com,10.0.0.0/33",
        ])
        .unwrap_err();
    assert!(format!("{err:#}").contains("--deny-network"), "{err:#}");
    assert_eq!(
        std::fs::read_to_string(t.ctx.paths.policy_file()).unwrap(),
        before
    );
    let lines = t.calls();
    assert!(!lines.iter().any(|l| l.contains("create")), "{lines:?}");

    // A host a secret bound at create uses: smolvm would keep it reachable.
    let mut t = test_env(&[]);
    global_github_secret(&t);
    let fake = t.runner();
    fake.fail(&["machine", "status"], "NOT_FOUND", "vm not found");
    let err = t.sbt_err(&["create", "claude", ".", "--deny-network", "github.com"]);
    assert!(
        err.contains(
            "can't deny github.com: sandbox claude-proj would be created with a github secret"
        ),
        "{err}"
    );
    assert!(sandbox_rules(&t, "claude-proj").is_empty());
    let lines = t.calls();
    assert!(!lines.iter().any(|l| l.contains("create")), "{lines:?}");
}

#[test]
fn a_failed_create_removes_only_its_own_deny_rules() {
    let earlier = "mode = \"allow-all\"\n[[sandboxes.claude-proj.rules]]\nid = \"r-old\"\n\
                       decision = \"deny\"\nresources = [\"old.example\"]\n";
    let mut t = test_env(&[]);
    set_policy(&t, earlier);
    let fake = t.runner();
    fake.fail(&["machine", "status"], "NOT_FOUND", "vm not found");
    fake.fail(&["machine", "create"], "CREATE_FAILED", "no space left");
    let err = t
        .sbt(&["create", "claude", ".", "--deny-network", "evil.com"])
        .unwrap_err();
    assert!(err.to_string().contains("no space left"), "{err:#}");
    assert_eq!(
        sandbox_rules(&t, "claude-proj"),
        vec![deny(&["old.example"])]
    );

    // Nothing earlier: the sandbox's entry goes away.
    let mut t = test_env(&[]);
    let fake = t.runner();
    fake.fail(&["machine", "status"], "NOT_FOUND", "vm not found");
    fake.fail(&["machine", "create"], "CREATE_FAILED", "no space left");
    assert!(
        t.sbt(&["create", "claude", ".", "--deny-network", "evil.com"])
            .is_err()
    );
    assert!(
        crate::policy::Policy::load(&t.ctx.paths)
            .unwrap()
            .sandboxes
            .is_empty()
    );

    // Created but failed to start: the machine exists, so its rules stay.
    let mut t = test_env(&[]);
    creatable(&t);
    t.runner()
        .fail(&["machine", "start"], "START_FAILED", "boot failed");
    assert!(
        t.sbt(&["create", "claude", ".", "--deny-network", "evil.com"])
            .is_err()
    );
    assert_eq!(sandbox_rules(&t, "claude-proj"), vec![deny(&["evil.com"])]);

    // No policy chosen and no terminal: create stops before adding rules, and the rollback
    // doesn't write a policy.toml either.
    let mut t = test_env(&[]);
    std::fs::remove_file(t.ctx.paths.policy_file()).unwrap();
    let fake = t.runner();
    fake.fail(&["machine", "status"], "NOT_FOUND", "vm not found");
    assert!(
        t.sbt(&["create", "claude", ".", "--deny-network", "evil.com"])
            .is_err()
    );
    assert!(!t.ctx.paths.policy_file().exists());
}

#[test]
fn create_without_path_is_mountless_and_docker_can_be_disabled() {
    let mut t = test_env(&[("SMOLBENTO_DOCKER", "false")]);
    creatable_as(&t, "shell-proj");
    t.sbt(&["create", "shell", "--cpus", "1", "-m", "1g"])
        .unwrap();
    let line = t
        .ctx
        .vm
        .runner()
        .call_lines()
        .into_iter()
        .find(|l| l.starts_with("machine create"))
        .unwrap();
    assert!(line.contains("/kits/images/"), "{line}");
    assert!(!line.contains(" -v "), "{line}");
    assert!(line.contains("--label sbx.docker=false"), "{line}");
    assert!(!line.contains("builtin:docker"), "no docker kit: {line}");
    assert!(
        t.calls()
            .contains(&"machine start -n sbx-shell-proj --branchable".to_string())
    );
}

#[test]
fn explicit_template_is_kept_when_docker_is_disabled() {
    let t = test_env(&[("SMOLBENTO_DOCKER", "false")]);
    let Some(Cmd::Create(a)) = Cli::try_parse_from([
        "sbt",
        "create",
        "shell",
        "-t",
        "docker/sandbox-templates:shell-docker-0.10.0",
        "--cpus",
        "1",
        "-m",
        "1g",
    ])
    .unwrap()
    .command
    else {
        panic!("expected create");
    };
    let req = planned(&t, "shell", &a.opts).unwrap();
    assert_eq!(req.image, "docker/sandbox-templates:shell-docker-0.10.0");
    assert!(!req.docker, "docker.enabled=false still skips dockerd");
}

#[test]
fn a_saved_template_is_created_from_its_pack() {
    let t = test_env(&[]);
    let e = saved_template(&t, "chk-tpl:v1", "shell");
    let opts = SandboxOpts {
        template: Some("chk-tpl:v1".into()),
        pull: Some("never".into()),
        ..Default::default()
    };
    let req = planned(&t, "shell", &opts).unwrap();
    let pack = crate::templates::Store::new(&t.ctx.paths).pack(&e);
    assert_eq!(req.template_pack, Some(pack));
    assert_eq!(
        req.template.as_deref(),
        Some("docker.io/library/chk-tpl:v1")
    );
    assert_eq!(req.image, e.image);
    assert!(!req.docker, "the template's docker flag, not the image's");
}

#[test]
fn disk_sizes_come_from_the_options_and_the_docker_volume_setting() {
    let t = test_env(&[]);
    let req = planned(&t, "shell", &SandboxOpts::default()).unwrap();
    assert_eq!(
        (req.storage_gib, req.overlay_gib),
        (None, None),
        "smolvm's own sizes"
    );

    let t = test_env(&[("SMOLBENTO_SANDBOX_DISK_DOCKER_VOLUME", "40g")]);
    let req = planned(&t, "shell", &SandboxOpts::default()).unwrap();
    assert_eq!(req.storage_gib, Some(40));

    // An environment file's sizes: the larger storage size wins, and sizes round up to GiB.
    let opts = SandboxOpts {
        disk: DiskSizes {
            root: Some("24g".into()),
            docker: Some("30g".into()),
            cloned_workspace: Some("35500m".into()),
        },
        ..Default::default()
    };
    let req = planned(&t, "shell", &opts).unwrap();
    assert_eq!((req.storage_gib, req.overlay_gib), (Some(35), Some(24)));
    let opts = SandboxOpts {
        disk: DiskSizes {
            root: Some("512m".into()),
            ..Default::default()
        },
        ..Default::default()
    };
    let req = planned(&t, "shell", &opts).unwrap();
    assert_eq!(req.overlay_gib, Some(1));
    let opts = SandboxOpts {
        disk: DiskSizes {
            root: Some("lots".into()),
            ..Default::default()
        },
        ..Default::default()
    };
    let err = planned(&t, "shell", &opts).unwrap_err();
    assert!(err.to_string().contains("rootSize"), "{err}");
}

#[test]
fn a_template_saved_from_another_agent_is_refused() {
    let t = test_env(&[]);
    saved_template(&t, "t:v1", "shell");
    let opts = SandboxOpts {
        template: Some("t:v1".into()),
        ..Default::default()
    };
    let err = planned(&t, "claude", &opts).unwrap_err().to_string();
    assert_eq!(
        err,
        "template docker.io/library/t:v1 was saved from a shell sandbox; run it with shell"
    );
}

#[test]
fn pull_never_needs_a_saved_template() {
    let t = test_env(&[]);
    let opts = SandboxOpts {
        template: Some("alpine".into()),
        pull: Some("never".into()),
        ..Default::default()
    };
    let err = planned(&t, "shell", &opts).unwrap_err();
    assert_eq!(
        err.to_string(),
        "--pull never works only with a saved template (see `bento template ls`); smolvm pulls missing images"
    );
    assert_eq!(crate::cli::exit_code(&err), 2);
}

#[test]
fn an_unsaved_template_is_still_an_image() {
    let t = test_env(&[]);
    let opts = SandboxOpts {
        template: Some("alpine".into()),
        ..Default::default()
    };
    let req = planned(&t, "shell", &opts).unwrap();
    assert_eq!(
        (req.image.as_str(), req.template_pack.is_none()),
        ("alpine", true)
    );
}

#[test]
fn create_from_a_saved_template_passes_from_and_the_label() {
    let mut t = test_env(&[]);
    let e = saved_template(&t, "chk-tpl:v1", "shell");
    let fake = t.runner();
    fake.ok(&["machine", "status"], &json("sbx-bb", "created", "bb"));
    fake.missing_until_created("sbx-bb");
    t.sbt(&["create", "shell", "-t", "chk-tpl:v1", "--name", "bb"])
        .unwrap();
    let create = t
        .ctx
        .vm
        .runner()
        .call_lines()
        .into_iter()
        .find(|l| l.contains("machine create"))
        .unwrap();
    let pack = crate::templates::Store::new(&t.ctx.paths).pack(&e);
    assert!(
        create.contains(&format!("--from {}", pack.display())),
        "{create}"
    );
    assert!(
        create.contains("--label sbx.template=docker.io/library/chk-tpl:v1"),
        "{create}"
    );
    assert!(!create.contains("--image"), "{create}");
}

#[test]
fn a_templates_docker_flag_follows_docker_enabled() {
    for (enabled, want) in [("false", false), ("true", true)] {
        let t = test_env(&[("SMOLBENTO_DOCKER", enabled)]);
        let kits = saved_template(&t, "s:v1", "shell").kits;
        let src = t.ctx.cwd.join("p.smolmachine");
        std::fs::write(&src, "packed").unwrap();
        let r = crate::templates::TemplateRef::parse("d:v1").unwrap();
        crate::templates::Store::new(&t.ctx.paths)
            .add(
                crate::templates::Entry {
                    repository: r.repository,
                    tag: r.tag,
                    agent: "shell".into(),
                    image: "img:1".into(),
                    docker: true,
                    created_at: "1970-01-12T13:46:30Z".into(),
                    kits,
                    ..Default::default()
                },
                &src,
            )
            .unwrap();
        let opts = SandboxOpts {
            template: Some("d:v1".into()),
            ..Default::default()
        };
        let req = planned(&t, "shell", &opts).unwrap();
        assert_eq!(req.docker, want, "docker.enabled={enabled}");
    }
}

#[test]
fn create_rejects_unknown_agents_and_bad_names() {
    let mut t = test_env(&[]);
    assert!(
        t.sbt_err(&["create", "nope"])
            .contains("unknown agent \"nope\"")
    );
    // Exact sbx text; a bare word with a tag is still an agent name.
    // A dotted bare word is a name too; only `.`, `..` and paths are kit refs.
    for w in ["alpine", "alpine:3", ".hidden", "...", ".kit.yaml"] {
        assert_eq!(t.sbt_err(&["create", w]), format!("unknown agent \"{w}\""));
    }
    assert!(
        t.sbt_err(&["create", "claude", "--name", "a_b"])
            .contains("'_'")
    );
}

#[test]
fn create_with_only_a_cached_agent_kit_prints_no_kits_section() {
    let mut t = test_env(&[("SMOLBENTO_DOCKER", "false")]);
    creatable_as(&t, "shell-proj");
    t.sbt(&[
        "create",
        "--name",
        "shell-proj",
        "shell",
        "--cpus",
        "3",
        "-m",
        "1536m",
    ])
    .unwrap();
    let kits = t.ctx.env["SMOLBENTO_AGENT_KITS_DIR"].clone();
    assert_eq!(
        t.stdout().replace(&kits, "KITS"),
        "
SANDBOX
  Name:       shell-proj
  Agent:      shell
  Workspace:  -
  Image:      from KITS/shell
  CPU:        3
  Memory:     1536 MiB

IMAGE
  ○ image — preparing…
  ✓ image — ready

SETUP
  ○ sandbox — starting…
  ✓ sandbox — started
  ○ shell — installing…
  ✓ shell — installed

  ✓ Created sandbox shell-proj
        try: bento run --name shell-proj
"
    );
}

#[test]
fn create_shows_clone_and_read_only_workspaces() {
    let mut t = test_env(&[]);
    creatable_as(&t, "claude-proj");
    let docs = t.ctx.cwd.join("docs");
    std::fs::create_dir(&docs).unwrap();
    t.sbt(&["create", "claude", ".", "docs:ro"]).unwrap();
    let ws = t.ctx.cwd.display().to_string();
    let out = t.stdout();
    assert!(
        out.contains(&format!("  Workspace:  {ws} (rw), {ws}/docs (ro)\n")),
        "{out}"
    );
}

#[test]
fn create_no_progress_prints_nothing() {
    let mut t = test_env(&[]);
    creatable(&t);
    t.sbt(&["create", "claude", ".", "--no-progress"]).unwrap();
    assert_eq!(t.stdout(), "");
}

#[test]
fn a_failed_image_pull_fails_its_step() {
    let mut t = test_env(&[]);
    creatable(&t);
    t.runner()
        .fail(&["machine", "start"], "PULL_FAILED", "no such image");
    t.sbt(&["create", "claude", "."]).unwrap_err();
    let out = t.stdout();
    assert!(
        out.ends_with("\nIMAGE\n  ○ image — preparing…\n  ✗ image — failed\n"),
        "{out}"
    );
}

#[test]
fn stop_and_start() {
    let mut t = test_env(&[]);
    t.runner().ok(
        &["machine", "status"],
        &json("sbx-claude-proj", "running", "claude-proj"),
    );
    t.sbt(&["stop", "claude-proj"]).unwrap();
    assert!(
        t.calls()
            .contains(&"machine stop -n sbx-claude-proj".to_string())
    );

    let mut t = test_env(&[]);
    t.runner().ok(
        &["machine", "status"],
        &json("sbx-claude-proj", "stopped", "claude-proj"),
    );
    t.stdout();
    t.sbt(&["start", "claude-proj"]).unwrap();
    assert!(
        t.calls()
            .contains(&"machine start -n sbx-claude-proj --branchable".to_string())
    );
    assert_eq!(
        t.stdout(),
        "  ○ claude-proj — starting…\n  ✓ Started claude-proj\n"
    );
}

#[test]
fn a_failed_start_fails_its_step() {
    let mut t = test_env(&[]);
    let fake = t.runner();
    fake.ok(
        &["machine", "status"],
        &json("sbx-claude-proj", "stopped", "claude-proj"),
    );
    fake.fail(&["machine", "start"], "BOOT_FAILED", "no hypervisor");
    let err = t.sbt(&["start", "claude-proj"]).unwrap_err();
    assert!(format!("{err:#}").contains("no hypervisor"), "{err:#}");
    assert_eq!(
        t.stdout(),
        "  ○ claude-proj — starting…\n  ✗ claude-proj — failed\n"
    );
}

#[test]
fn start_needs_a_policy() {
    let mut t = test_env(&[]);
    set_policy(&t, "");
    t.runner().ok(
        &["machine", "status"],
        &json("sbx-claude-proj", "stopped", "claude-proj"),
    );
    let err = t.sbt_err(&["start", "claude-proj"]);
    assert!(
        err.contains("no network policy chosen yet; run `bento policy init"),
        "{err}"
    );
    let started = |t: &TestEnv| {
        t.calls()
            .into_iter()
            .any(|l| l.starts_with("machine update") || l.starts_with("machine start"))
    };
    assert!(!started(&t));
    t.sbt(&["policy", "init", "balanced"]).unwrap();
    t.sbt(&["start", "claude-proj"]).unwrap();
    assert!(started(&t));
}

fn clone_json(name: &str, state: &str, repo: &std::path::Path) -> String {
    machine_json(
        &format!("sbx-{name}"),
        state,
        &[
            ("sbx.name", name),
            ("sbx.created", "999000"),
            ("sbx.clone", "true"),
            ("sbx.workspace", &repo.display().to_string()),
        ],
    )
}

/// Fakes `machine ls --json` for the one sandbox a test `rm`s by name.
fn ls_one(t: &TestEnv, json: &str) {
    t.runner()
        .ok(&["machine", "ls", "--json"], &format!("[{json}]"));
}

fn remote(repo: &std::path::Path, name: &str) -> String {
    git_config(repo, &format!("remote.sandbox-{name}.url"))
}

#[test]
fn rm_prune_and_reset_remove_our_remote_but_keep_foreign_ones() {
    for cmd in [
        vec!["rm", "-f", "box"],
        vec!["prune", "-f"],
        vec!["reset", "-f"],
    ] {
        let mut t = test_env(&[]);
        let (_d, repo) = temp_repo();
        crate::workspace::clone::add_remote(&repo, "box").unwrap();
        git(
            &repo,
            &[
                "remote",
                "add",
                "sandbox-other",
                "https://example.com/x.git",
            ],
        );
        let fake = t.runner();
        fake.ok(&["machine", "status"], &clone_json("box", "stopped", &repo));
        fake.ok(
            &["machine", "ls", "--json"],
            &format!("[{}]", clone_json("box", "stopped", &repo)),
        );
        assert!(!remote(&repo, "box").is_empty());
        t.sbt(&cmd).unwrap();
        assert_eq!(remote(&repo, "box"), "", "{cmd:?}");
        assert!(!remote(&repo, "other").is_empty(), "{cmd:?}");
    }
}

#[test]
fn rm_keeps_a_foreign_remote_of_the_same_name() {
    let mut t = test_env(&[]);
    let (_d, repo) = temp_repo();
    git(
        &repo,
        &["remote", "add", "sandbox-box", "https://example.com/x.git"],
    );
    t.runner()
        .ok(&["machine", "status"], &clone_json("box", "stopped", &repo));
    ls_one(&t, &clone_json("box", "stopped", &repo));
    t.sbt(&["rm", "-f", "box"]).unwrap();
    assert!(!remote(&repo, "box").is_empty());
}

#[test]
fn rm_succeeds_when_the_clone_workspace_is_gone() {
    let mut t = test_env(&[]);
    let gone = t.ctx.cwd.join("deleted");
    t.runner()
        .ok(&["machine", "status"], &clone_json("box", "stopped", &gone));
    ls_one(&t, &clone_json("box", "stopped", &gone));
    t.sbt(&["rm", "-f", "box"]).unwrap();
    assert!(t.made("machine delete -n sbx-box"), "{:?}", t.calls());
}

#[test]
fn rm_removes_the_remote_from_the_repo_top_when_the_subdirectory_is_gone() {
    let mut t = test_env(&[]);
    let (_d, repo) = temp_repo();
    crate::workspace::clone::add_remote(&repo, "box").unwrap();
    let sub = repo.join("deleted").display().to_string();
    let box_json = machine_json(
        "sbx-box",
        "stopped",
        &[
            ("sbx.name", "box"),
            ("sbx.clone", "true"),
            ("sbx.workspace", &sub),
            ("sbx.clone-top", &repo.display().to_string()),
        ],
    );
    t.runner().ok(&["machine", "status"], &box_json);
    ls_one(&t, &box_json);
    t.sbt(&["rm", "-f", "box"]).unwrap();
    assert_eq!(remote(&repo, "box"), "");
}

#[test]
fn rm_needs_force_without_a_terminal() {
    let mut t = test_env(&[]);
    t.runner().ok(
        &["machine", "status"],
        &json("sbx-claude-proj", "running", "claude-proj"),
    );
    ls_one(&t, &json("sbx-claude-proj", "running", "claude-proj"));
    assert!(t.sbt_err(&["rm", "claude-proj"]).contains("pass -f"));
    t.sbt(&["rm", "-f", "claude-proj"]).unwrap();
    assert!(
        t.calls()
            .contains(&"machine delete -n sbx-claude-proj -f".to_string())
    );
}

#[test]
fn rm_asks_on_a_terminal_and_removes_only_on_yes() {
    let mut t = test_env(&[]);
    t.ctx.vm.runner().ok(
        &["machine", "status"],
        &json("sbx-claude-proj", "running", "claude-proj"),
    );
    ls_one(&t, &json("sbx-claude-proj", "running", "claude-proj"));
    let deleted = |t: &TestEnv| {
        t.ctx
            .vm
            .runner()
            .call_lines()
            .iter()
            .any(|l| l.starts_with("machine delete"))
    };
    t.answer("n\n");
    let e = sbt(&mut t.ctx, &["rm", "claude-proj"]).unwrap_err();
    assert_eq!(e.to_string(), "aborted");
    assert_eq!(t.stdout(), "Remove claude-proj? [y/N] ");
    assert!(!deleted(&t));
    t.answer("y\n");
    sbt(&mut t.ctx, &["rm", "claude-proj"]).unwrap();
    assert!(deleted(&t));
}

#[test]
fn prune_removes_only_old_stopped_sandboxes() {
    let mut t = test_env(&[]);
    let ls = format!(
        "[{},{},{}]",
        json("sbx-old", "stopped", "old"),
        json("sbx-live", "running", "live"),
        machine_json(
            "sbx-new",
            "stopped",
            &[("sbx.name", "new"), ("sbx.created", "999990")]
        )
    );
    t.runner().ok(&["machine", "ls", "--json"], &ls);
    t.runner().ok(
        &["machine", "status", "-n", "sbx-live"],
        &json("sbx-live", "running", "live"),
    );
    t.sbt(&["prune", "-f", "--filter", "until=1m"]).unwrap();
    let deletes: Vec<String> = t
        .ctx
        .vm
        .runner()
        .call_lines()
        .into_iter()
        .filter(|l| l.contains("delete"))
        .collect();
    assert_eq!(deletes, vec!["machine delete -n sbx-old -f"]);
}

#[test]
fn create_refuses_a_default_name_another_folder_uses() {
    let t = test_env(&[]);
    let theirs = machine_json(
        "sbx-claude-proj",
        "stopped",
        &[
            ("sbx.name", "claude-proj"),
            ("sbx.agent", "claude"),
            ("sbx.workspace", "/other/proj"),
        ],
    );
    t.runner()
        .ok(&["machine", "ls", "--json"], &format!("[{theirs}]"));
    t.runner()
        .ok(&["machine", "status", "-n", "sbx-claude-proj"], &theirs);
    let mut t = t;
    let err = t.sbt_err(&["create", "claude", "."]);
    assert!(
        err.contains("is already used by workspace \"/other/proj\""),
        "{err}"
    );
    assert!(err.contains("such as --name claude-"), "{err}");
    assert!(!t.made("machine create"));
}

#[test]
fn auto_name_creates_under_the_suggested_name() {
    let t = test_env(&[("SMOLBENTO_SANDBOX_AUTO_NAME", "true")]);
    let suggested =
        crate::sandbox::name::suggest_name("claude", &t.ctx.cwd, |n| n == "claude-proj");
    creatable_as(&t, &suggested);
    let theirs = machine_json(
        "sbx-claude-proj",
        "stopped",
        &[
            ("sbx.name", "claude-proj"),
            ("sbx.agent", "claude"),
            ("sbx.workspace", "/other/proj"),
        ],
    );
    t.runner()
        .ok(&["machine", "ls", "--json"], &format!("[{theirs}]"));
    t.runner()
        .ok(&["machine", "status", "-n", "sbx-claude-proj"], &theirs);
    let mut t = t;
    t.sbt(&["create", "claude", "."]).unwrap();
    let machine = crate::sandbox::name::machine_name(&suggested);
    assert!(
        t.made(&format!("machine create -n {machine} ")),
        "{:?}",
        t.calls()
    );
}

#[test]
fn no_input_never_prompts() {
    let mut t = test_env(&[]);
    t.answer("y\n");
    let err = t.sbt(&["--no-input", "reset"]).unwrap_err();
    assert!(err.to_string().contains("pass -f"), "{err}");
}

#[test]
fn reset_deletes_everything() {
    let mut t = test_env(&[]);
    let ls = format!(
        "[{},{}]",
        json("sbx-a1", "stopped", "a1"),
        json("sbx-b1", "stopped", "b1")
    );
    t.runner().ok(&["machine", "ls", "--json"], "[]");
    // The first list is smolbento's own state; the second, smolvm's old default.
    t.runner().once_ok(&["machine", "ls", "--json"], &ls);
    t.sbt(&["reset", "-f"]).unwrap();
    let deletes = t
        .ctx
        .vm
        .runner()
        .call_lines()
        .into_iter()
        .filter(|l| l.contains("delete"))
        .count();
    assert_eq!(deletes, 2);
}

#[test]
fn reset_preserve_secrets_keeps_sandbox_scoped_secrets() {
    use crate::policy::Policy;
    use crate::secrets::{SecretEntry, SecretsFile, Source, scope_for};

    let mut t = test_env(&[]);
    let entry = SecretEntry {
        service: "github".into(),
        scope: scope_for(Some("a1")),
        source: Source::Keychain,
    };
    t.ctx.store.set(&entry.account(), "gh-123").unwrap();
    let mut f = SecretsFile::default();
    f.set(entry.clone());
    f.save(&t.ctx.paths).unwrap();
    set_policy(
        &t,
        "mode = \"balanced\"\n[[sandboxes.a1.rules]]\nid = \"r-1\"\ndecision = \"allow\"\n\
             resources = [\"a.com\"]\n",
    );
    t.runner().ok(
        &["machine", "ls", "--json"],
        &format!("[{}]", json("sbx-a1", "stopped", "a1")),
    );
    t.sbt(&["reset", "-f", "--preserve-secrets"]).unwrap();
    let f = SecretsFile::load(&t.ctx.paths).unwrap();
    assert_eq!(f.secrets, vec![entry.clone()]);
    assert_eq!(
        t.ctx.store.get(&entry.account()).unwrap().as_deref(),
        Some("gh-123")
    );
    assert!(Policy::load(&t.ctx.paths).unwrap().sandboxes.is_empty());
}

#[test]
fn reset_removes_old_location_sandboxes_but_not_others() {
    let mut t = test_env(&[]);
    let old = format!(
        "[{},{}]",
        json("sbx-old", "stopped", "old"),
        machine_json("mine", "stopped", &[])
    );
    // smolbento's own state is empty; smolvm's default has one of ours and one of yours.
    t.runner().ok(&["machine", "ls", "--json"], &old);
    t.runner().once_ok(&["machine", "ls", "--json"], "[]");
    t.sbt(&["reset", "-f"]).unwrap();
    let calls = t.calls();
    assert!(
        calls.contains(&"machine delete -n sbx-old -f".to_string()),
        "{calls:?}"
    );
    assert!(!calls.iter().any(|l| l.contains("-n mine")), "{calls:?}");
    // The old-location calls run without smolbento's SMOLVM_DATA_DIR.
    let removed = t.runner().removed();
    assert!(
        removed
            .iter()
            .filter(|r| r.contains(&"SMOLVM_DATA_DIR".to_string()))
            .count()
            >= 2,
        "{removed:?}"
    );
}

#[test]
fn reset_removes_smolbentos_dirs_and_its_home() {
    let mut t = test_env(&[]);
    t.runner().ok(&["machine", "ls", "--json"], "[]");
    let home = std::path::PathBuf::from(&t.ctx.env["HOME"]).join(".smolbento");
    for d in [
        &t.ctx.paths.config,
        &t.ctx.paths.cache,
        &t.ctx.paths.data,
        &home.join("engine/1.0.0"),
    ] {
        std::fs::create_dir_all(d).unwrap();
        std::fs::write(d.join("x"), "x").unwrap();
    }
    t.sbt(&["reset", "-f"]).unwrap();
    for d in [
        &t.ctx.paths.config,
        &t.ctx.paths.cache,
        &t.ctx.paths.data,
        &home,
    ] {
        assert!(!d.exists(), "{} is left", d.display());
    }
}

#[test]
fn reset_goes_on_when_an_old_location_sandbox_wont_go_and_removes_forks_first() {
    let mut t = test_env(&[]);
    let old = format!(
        "[{},{}]",
        machine_json("sbx-a", "stopped", &[("sbx.name", "a")]),
        machine_json(
            "sbx-b",
            "stopped",
            &[("sbx.name", "b"), ("sbx.fork-of", "a")]
        )
    );
    t.runner().ok(&["machine", "ls", "--json"], &old);
    t.runner().once_ok(&["machine", "ls", "--json"], "[]");
    t.runner().fail(
        &["machine", "delete", "-n", "sbx-b"],
        "SMOLVM_ERROR",
        "busy",
    );
    std::fs::create_dir_all(&t.ctx.paths.config).unwrap();
    t.sbt(&["reset", "-f"]).unwrap();
    let deletes: Vec<String> = t
        .calls()
        .into_iter()
        .filter(|l| l.starts_with("machine delete"))
        .collect();
    assert_eq!(
        deletes,
        ["machine delete -n sbx-b -f", "machine delete -n sbx-a -f"]
    );
    assert!(!t.ctx.paths.config.exists(), "the reset went on");
}

#[test]
fn reset_keeps_a_smolvm_home_you_chose_but_removes_its_smolvm() {
    // Short, for the macOS socket check.
    let home = tempfile::tempdir_in("/tmp").unwrap();
    std::fs::create_dir_all(home.path().join("engine/1.0.0")).unwrap();
    std::fs::write(home.path().join("notes.txt"), "mine").unwrap();
    let mut t = test_env(&[("SMOLBENTO_SMOLVM_HOME", home.path().to_str().unwrap())]);
    t.runner().ok(&["machine", "ls", "--json"], "[]");
    t.sbt(&["reset", "-f"]).unwrap();
    assert!(!home.path().join("engine").exists());
    assert!(home.path().join("notes.txt").exists());
}

#[test]
fn reset_removes_the_ssh_block() {
    let mut t = test_env(&[]);
    t.runner().ok(&["machine", "ls", "--json"], "[]");
    let ssh = std::path::PathBuf::from(&t.ctx.env["HOME"]).join(".ssh");
    std::fs::create_dir_all(&ssh).unwrap();
    let user = "Host gh\n  User git\n";
    let block = crate::ssh::block::render("/bin/sbt", &[]);
    std::fs::write(ssh.join("config"), format!("{block}{user}")).unwrap();
    t.sbt(&["reset", "-f"]).unwrap();
    assert_eq!(std::fs::read_to_string(ssh.join("config")).unwrap(), user);
}

fn fork_json(name: &str, state: &str, parent: Option<&str>) -> String {
    let mut l = labels(name);
    if let Some(p) = parent {
        l.push(("sbx.fork-of", p.to_string()));
    }
    let pairs: Vec<(&str, &str)> = l.iter().map(|(k, v)| (*k, v.as_str())).collect();
    machine_json(&format!("sbx-{name}"), state, &pairs)
}

/// `a` with forks `a-fork-1` and `a-fork-2`, in the given states.
fn with_forks(t: &TestEnv, a: &str, f1: &str, f2: &str) {
    let (ja, j1, j2) = (
        fork_json("a", a, None),
        fork_json("a-fork-1", f1, Some("a")),
        fork_json("a-fork-2", f2, Some("a")),
    );
    let fake = t.runner();
    fake.ok(&["machine", "ls", "--json"], &format!("[{ja},{j1},{j2}]"));
    fake.ok(&["machine", "status", "-n", "sbx-a"], &ja);
    fake.ok(&["machine", "status", "-n", "sbx-a-fork-1"], &j1);
    fake.ok(&["machine", "status", "-n", "sbx-a-fork-2"], &j2);
}

fn deletes(t: &TestEnv) -> Vec<String> {
    t.calls()
        .into_iter()
        .filter(|l| l.contains("machine delete"))
        .map(|l| l.replace("machine delete -n sbx-", "").replace(" -f", ""))
        .collect()
}

#[test]
fn rm_refuses_a_parent_that_still_has_forks() {
    let mut t = test_env(&[]);
    with_forks(&t, "stopped", "stopped", "stopped");
    let err = t.sbt_err(&["rm", "-f", "a"]);
    assert!(
        err.contains("remove its forks first: a-fork-1, a-fork-2"),
        "{err}"
    );
    assert!(deletes(&t).is_empty());
}

#[test]
fn rm_deletes_forks_named_in_the_same_call_before_the_parent() {
    let mut t = test_env(&[]);
    with_forks(&t, "stopped", "stopped", "stopped");
    t.sbt(&["rm", "-f", "a", "a-fork-1", "a-fork-2"]).unwrap();
    assert_eq!(deletes(&t), vec!["a-fork-1", "a-fork-2", "a"]);
    // Named targets come from the one list, not a status call each.
    let calls = t.calls();
    assert!(
        calls.iter().all(|c| !c.starts_with("machine status")),
        "{calls:?}"
    );
}

#[test]
fn rm_of_a_missing_sandbox_deletes_nothing() {
    let mut t = test_env(&[]);
    with_forks(&t, "stopped", "stopped", "stopped");
    let err = t.sbt(&["rm", "-f", "a-fork-1", "nope"]).unwrap_err();
    assert_eq!(err.to_string(), "sandbox 'nope' not found (see `bento ls`)");
    assert!(deletes(&t).is_empty());
}

#[test]
fn rm_all_deletes_forks_before_parents_and_lists_once() {
    let mut t = test_env(&[]);
    with_forks(&t, "stopped", "stopped", "stopped");
    t.sbt(&["rm", "-f", "--all"]).unwrap();
    assert_eq!(deletes(&t), vec!["a-fork-1", "a-fork-2", "a"]);
    let lists = t
        .ctx
        .vm
        .runner()
        .call_lines()
        .iter()
        .filter(|c| c.starts_with("machine ls"))
        .count();
    assert_eq!(lists, 1);
}

#[test]
fn prune_skips_a_parent_whose_fork_is_running() {
    let mut t = test_env(&[]);
    with_forks(&t, "stopped", "running", "stopped");
    t.sbt(&["prune", "-f"]).unwrap();
    assert_eq!(deletes(&t), vec!["a-fork-2"]);

    let mut t = test_env(&[]);
    with_forks(&t, "stopped", "stopped", "stopped");
    t.sbt(&["prune", "-f"]).unwrap();
    assert_eq!(deletes(&t), vec!["a-fork-1", "a-fork-2", "a"]);
}

#[test]
fn prune_says_which_parents_it_skipped() {
    let mut t = test_env(&[]);
    with_forks(&t, "stopped", "running", "stopped");
    t.sbt(&["prune", "-f"]).unwrap();
    // remove() reports through the same sink, after the skips.
    assert_eq!(t.stdout(), "a has forks; skipped\nRemoved a-fork-2\n");
}

#[test]
fn prune_until_keeps_a_new_fork_of_an_old_parent() {
    let mut t = test_env(&[]);
    let parent = fork_json("a", "stopped", None);
    // `fork` labels the copy with its own creation time (now), not the parent's.
    let fork = machine_json(
        "sbx-a-fork-1",
        "stopped",
        &[
            ("sbx.name", "a-fork-1"),
            ("sbx.created", "1000000"),
            ("sbx.fork-of", "a"),
        ],
    );
    let fake = t.runner();
    fake.ok(&["machine", "ls", "--json"], &format!("[{parent},{fork}]"));
    fake.ok(&["machine", "status", "-n", "sbx-a"], &parent);
    fake.ok(&["machine", "status", "-n", "sbx-a-fork-1"], &fork);
    t.sbt(&["prune", "-f", "--filter", "until=1m"]).unwrap();
    assert!(deletes(&t).is_empty(), "{:?}", deletes(&t));
}

#[test]
fn reset_deletes_forks_before_parents() {
    let mut t = test_env(&[]);
    with_forks(&t, "stopped", "stopped", "stopped");
    t.sbt(&["reset", "-f"]).unwrap();
    // The fake answers smolvm's default location with the same machines, deleted after.
    assert_eq!(deletes(&t)[..3], ["a-fork-1", "a-fork-2", "a"]);
}

#[test]
fn reset_removes_the_skills_store() {
    let mut t = test_env(&[]);
    t.runner().ok(&["machine", "ls", "--json"], "[]");
    let store = t.ctx.paths.skills_store();
    std::fs::create_dir_all(store.join("a")).unwrap();
    std::fs::create_dir_all(t.ctx.paths.skills_metadata()).unwrap();
    t.sbt(&["reset", "-f"]).unwrap();
    assert!(!store.exists() && !t.ctx.paths.skills_metadata().exists());
}
