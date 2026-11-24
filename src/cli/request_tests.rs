use clap::Parser;

use super::super::{Cli, Cmd, SandboxOpts};
use super::*;
use crate::testutil::*;

/// No machine touched: only the lookup that checks the name is free.
fn no_machine_calls(t: &TestEnv) -> bool {
    !t.calls()
        .iter()
        .any(|l| l.starts_with("machine ") && !l.starts_with("machine status"))
}

/// A kit env whose sandbox names are all free.
fn kit_env_free() -> TestEnv {
    let t = kit_env();
    t.no_machine();
    t
}

#[test]
fn kit_pins_apply_beneath_kit_args() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
            dir.path().join("spec.yaml"),
            "schemaVersion: \"2\"\nkind: mixin\nname: pinme\nargs:\n  mode:\n    default: plain\nsetup:\n  install:\n    - command: echo mode=${{ kit.args.mode }}\n",
        )
        .unwrap();
    let kit = dir.path().display().to_string();
    for (flags, want) in [(vec![], "mode=pinned"), (vec!["mode=flag"], "mode=flag")] {
        let mut t = kit_env();
        creatable_as(&t, "shell-proj");
        let a = super::super::CreateArgs {
            // A v2 mixin needs a v2 workload.
            targets: vec![v2_fixture("shell-workload"), ".".into()],
            opts: SandboxOpts {
                kit: vec![kit.clone()],
                kit_args: super::super::args::KitArgOpts {
                    kit_arg: flags.iter().map(|s| s.to_string()).collect(),
                    ..Default::default()
                },
                kit_pins: vec![(kit.clone(), vec!["mode=pinned".into()])],
                ..Default::default()
            },
            no_progress: false,
        };
        super::super::lifecycle::create(&mut t.ctx, &a).unwrap();
        let lines = t.calls();
        assert!(
            lines
                .iter()
                .any(|l| l.contains("machine exec") && l.contains(want)),
            "{want}: {lines:?}"
        );
    }
}

#[test]
fn kit_pins_apply_to_a_workload_kit() {
    let dir = tempfile::tempdir().unwrap();
    let kit = dir.path().join("wl");
    std::fs::create_dir(&kit).unwrap();
    std::fs::write(
            kit.join("spec.yaml"),
            "schemaVersion: \"2\"\nkind: sandbox\nname: wl\nargs:\n  mode:\n    default: plain\nsandbox:\n  image: img:1\n  entrypoint: [/bin/agent]\nsetup:\n  install:\n    - command: echo mode=${{ kit.args.mode }}\n",
        )
        .unwrap();
    let kit = kit.display().to_string();
    let mut t = kit_env();
    creatable_as(&t, "wl-proj");
    let a = super::super::CreateArgs {
        targets: vec![kit.clone(), ".".into()],
        opts: SandboxOpts {
            kit_pins: vec![(kit.clone(), vec!["mode=pinned".into()])],
            ..Default::default()
        },
        no_progress: false,
    };
    super::super::lifecycle::create(&mut t.ctx, &a).unwrap();
    let lines = t.calls();
    assert!(
        lines
            .iter()
            .any(|l| l.contains("machine exec") && l.contains("mode=pinned")),
        "{lines:?}"
    );
    // The image comes from the kit, which loads after SANDBOX is printed.
    let out = t.stdout();
    assert!(
        out.contains(&format!("  Image:      from {kit}\n")),
        "{out}"
    );
    assert!(!out.contains("KITS"), "nothing pulled or built: {out}");
    assert!(
        out.contains("  ○ wl — installing…\n  ✓ wl — installed\n"),
        "{out}"
    );
}

#[test]
fn create_with_a_mixin_kit_applies_it() {
    let mut t = kit_env();
    // allow-all would leave the kit's allow rule out of the argv.
    set_policy(&t, "mode = \"deny-all\"");
    creatable_as(&t, "shell-proj");
    let kit = v2_fixture("tool-mixin");
    // A v2 mixin needs a v2 workload.
    let shell = v2_fixture("shell-workload");
    t.sbt(&[
        "create",
        &shell,
        ".",
        "--kit",
        &kit,
        "--kit-arg",
        "mode=slow",
        "--cpus",
        "1",
        "-m",
        "1g",
    ])
    .unwrap();
    let create = t.create_line();
    assert!(create.contains("-e TOOL_MODE=fast"), "{create}");
    assert!(create.contains(":8080 "), "{create}");
    // The workload's image is Docker-enabled, so the docker kit comes too.
    assert!(
            create.contains(&format!(
                "--label sbx.kits=[{{\"name\":\"shell\",\"ref\":\"{shell}\",\"format\":\"v2\"}},{{\"name\":\"tool\",\"ref\":\"{kit}\",\"format\":\"v2\",\"args\":{{\"mode\":\"slow\"}}}},{}]",
                r#"{"name":"docker","ref":"builtin:docker"}"#
            )),
            "{create}"
        );
    assert!(create.contains("api.tool.example"), "{create}");
    let lines = t.calls();
    let start = lines
        .iter()
        .position(|l| l == "machine start -n sbx-shell-proj")
        .unwrap();
    let install = lines
        .iter()
        .position(|l| l.contains("machine exec") && l.contains("echo installed"))
        .expect("the install hook runs");
    assert!(start < install, "{lines:?}");
    // The progress, as sbx prints it without a terminal: no KITS (a v2 directory needs no
    // pull or build), and the install hooks' kit before the docker kit, which has none.
    let ws = t.ctx.cwd.display().to_string();
    assert_eq!(
        t.stdout()
            .replace(&ws, "WS")
            .replace(&kit, "KIT")
            .replace(&shell, "SHELL"),
        "
SANDBOX
  Name:       shell-proj
  Agent:      shell
  Workspace:  WS (rw)
  Image:      from SHELL
  CPU:        1
  Memory:     1 GiB

IMAGE
  ○ image — preparing…
  ✓ image — ready

SETUP
  ○ sandbox — starting…
  ✓ sandbox — started
  ○ tool — installing…
  ✓ tool — installed
  ○ shell — installing…
  ✓ shell — installed
  ○ docker — installing…
  ✓ docker — installed

  ✓ Created sandbox shell-proj
        try: bento run --name shell-proj
"
    );
}

#[test]
fn create_writes_v2_workspace_files_into_the_workspace() {
    let mut t = kit_env();
    creatable_as(&t, "shell-proj");
    let kit = v2_fixture("workspace-files");
    // A v2 mixin needs a v2 workload.
    let shell = v2_fixture("shell-workload");
    t.sbt(&["create", &shell, ".", "--kit", &kit]).unwrap();
    let ws = t.ctx.cwd.canonicalize().unwrap().display().to_string();
    let lines = t.calls();
    let wrote = |needle: &str| {
        lines
            .iter()
            .any(|l| l.starts_with("machine exec") && l.contains(needle))
    };
    assert!(wrote(&format!("{ws}/docs/NOTES.md")), "{lines:#?}");
    assert!(wrote(&format!("workdir={ws}")), "{lines:#?}");
}

#[test]
fn create_with_a_workload_kit_names_the_sandbox_after_it() {
    let mut t = kit_env();
    creatable_as(&t, "toolbox-proj");
    t.sbt(&["create", &v2_fixture("tool-workload"), "."])
        .unwrap();
    let create = t.create_line();
    assert!(create.contains("-n sbx-toolbox-proj"), "{create}");
    assert!(
        create.contains("--image ghcr.io/example/toolbox:1"),
        "{create}"
    );
    assert!(
        create.contains(r#"--label sbx.command=["/bin/agent","--x"]"#),
        "{create}"
    );
    assert!(create.contains("--label sbx.agent=toolbox"), "{create}");
}

#[test]
fn a_workload_kit_named_claude_gets_no_preset_variables() {
    let mut t = kit_env();
    let dir = tempfile::tempdir().unwrap();
    let kit = dir.path().join("claude");
    std::fs::create_dir(&kit).unwrap();
    std::fs::write(
        kit.join("spec.yaml"),
        "schemaVersion: \"2\"\nkind: sandbox\nname: claude\nsandbox:\n  image: img:1\n  \
             entrypoint: [/bin/agent]\n",
    )
    .unwrap();
    creatable_as(&t, "claude-proj");
    t.sbt(&["create", &kit.display().to_string(), "."]).unwrap();
    let create = t.create_line();
    assert!(create.contains("-e SBX_AGENT=claude"), "{create}");
    assert!(!create.contains("SBX_CRED_"), "{create}");
    assert!(!create.contains("IS_SANDBOX"), "{create}");
}

#[test]
fn a_workload_kit_without_a_command_is_refused() {
    let mut t = kit_env();
    let dir = tempfile::tempdir().unwrap();
    let kit = dir.path().join("bare");
    std::fs::create_dir(&kit).unwrap();
    std::fs::write(
        kit.join("spec.yaml"),
        "schemaVersion: \"2\"\nkind: sandbox\nname: bare\nsandbox:\n  image: img:1\n",
    )
    .unwrap();
    // The image declares no command either.
    crate::kits::registry::fixtures::cached_image(
        &t.ctx.paths.kit_cache(),
        "img:1",
        r#"{"config":{"Env":["A=1"]}}"#,
    );
    let fake = t.runner();
    fake.fail(&["machine", "status"], "NOT_FOUND", "vm not found");
    let err = t
        .sbt(&["create", &kit.display().to_string(), "."])
        .unwrap_err();
    assert_eq!(
        format!("{err:#}"),
        "workload kit image declares no ENTRYPOINT or CMD; the image config is the runtime \
             contract"
    );
    assert!(!t.made("machine create"));
}

#[test]
fn a_v2_workload_without_a_command_launches_its_images() {
    let mut t = kit_env();
    let dir = tempfile::tempdir().unwrap();
    let kit = dir.path().join("bare");
    std::fs::create_dir(&kit).unwrap();
    std::fs::write(
        kit.join("spec.yaml"),
        "schemaVersion: \"2\"\nkind: sandbox\nname: bare\nsandbox:\n  image: img:1\n",
    )
    .unwrap();
    crate::kits::registry::fixtures::cached_image(
        &t.ctx.paths.kit_cache(),
        "img:1",
        r#"{"config":{"Entrypoint":["/bin/agent"],"Cmd":["--x"]}}"#,
    );
    creatable_as(&t, "bare-proj");
    t.sbt(&["create", &kit.display().to_string(), "."]).unwrap();
    let create = t.create_line();
    assert!(
        create.contains(r#"--label sbx.command=["/bin/agent","--x"]"#),
        "{create}"
    );
    // v2 still launches as `agent`.
    assert!(!create.contains("sbx.user"), "{create}");
}

#[test]
fn a_local_kit_named_like_a_preset_is_still_a_kit() {
    let mut t = kit_env();
    let dir = tempfile::tempdir().unwrap();
    let kit = dir.path().join("mine");
    std::fs::create_dir(&kit).unwrap();
    std::fs::write(
        kit.join("spec.yaml"),
        "schemaVersion: \"2\"\nkind: sandbox\nname: shell\nsandbox:\n  image: img:1\n  \
             entrypoint: [/bin/agent]\n",
    )
    .unwrap();
    creatable_as(&t, "shell-proj");
    t.sbt(&["create", &kit.display().to_string(), "."]).unwrap();
    let create = t.create_line();
    let path = kit.canonicalize().unwrap().display().to_string();
    assert!(
        create.contains(&format!(
            "--label sbx.kits=[{{\"name\":\"shell\",\"ref\":\"{path}\",\"format\":\"v2\"}}]"
        )),
        "{create}"
    );
    assert!(
        create.contains(r#"--label sbx.command=["/bin/agent"]"#),
        "{create}"
    );
}

#[test]
fn a_mixin_as_the_target_fails_before_smolvm() {
    let mut t = kit_env_free();
    let kit = v2_fixture("tool-mixin");
    let err = t.sbt_err(&["create", &kit]);
    assert_eq!(
        err,
        format!(
            "resolve: the kit set is not coherent:\n  - no workload kit in the set; every \
                 composition needs exactly one kind: workload base\n{kit} is a mixin; add it with \
                 --kit to an agent, e.g. bento run shell --kit {kit}"
        )
    );
    assert!(no_machine_calls(&t));
}

#[test]
fn bad_kit_flags_fail_before_smolvm() {
    let kit = v2_fixture("tool-mixin");
    let workload = v2_fixture("tool-workload");
    for (args, want) in [
        (
            vec!["create", &workload, "--kit", &kit, "--kit-arg", "nope=1"],
            "unknown kit argument nope",
        ),
        (
            // `shell` is a kit now, as in sbx 0.53 ("no kit declares this argument").
            vec!["create", "shell", "--kit-arg", "mode=1"],
            "unknown kit argument mode",
        ),
        (
            vec!["create", "shell", "--kit", "git+https://github.com/o/r.git"],
            "git kit sources are not supported",
        ),
        (
            vec!["create", "shell", "--kit", "./k.zip"],
            "ZIP kits are not supported",
        ),
    ] {
        let mut t = kit_env_free();
        let err = format!("{:#}", t.sbt(&args).unwrap_err());
        assert!(err.contains(want), "{args:?}: {err}");
        assert!(no_machine_calls(&t), "{args:?}");
        assert!(
            crate::policy::Policy::load(&t.ctx.paths)
                .unwrap()
                .sandboxes
                .is_empty()
        );
    }
}

#[test]
fn a_kit_create_on_an_existing_name_adds_no_rules() {
    let mut t = kit_env();
    t.runner().ok(
        &["machine", "status"],
        &json("sbx-shell-proj", "stopped", "shell-proj"),
    );
    let err = t.sbt_err(&["create", "shell", ".", "--kit", &v2_fixture("tool-mixin")]);
    assert!(err.contains("already exists"), "{err}");
    assert!(sandbox_rules(&t, "shell-proj").is_empty());
}

#[test]
fn a_kit_binding_merges_with_a_global_secret_of_the_same_variable() {
    let t = kit_env();
    global_github_secret(&t);
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("spec.yaml"),
        "schemaVersion: \"2\"\nkind: mixin\nname: gh\ncredentials:\n  - service: github\n    \
             apiKey:\n      name: GH_TOKEN\n      inject:\n        - domain: gist.github.com\n",
    )
    .unwrap();
    let (mut req, plan) = kit_request(&t, &["create", "shell", "--kit"], dir.path());
    crate::provision::prepare_create(&t.ctx, &mut req, &[], plan.as_ref()).unwrap();
    let gh: Vec<_> = req
        .credentials
        .iter()
        .filter(|c| c.env_var == "GH_TOKEN")
        .collect();
    assert_eq!(gh.len(), 1, "{:?}", req.credentials);
    assert!(gh[0].hosts.contains(&"gist.github.com".to_string()));
    assert!(gh[0].hosts.contains(&"api.github.com".to_string()));
    assert_eq!(req.rec.secrets, vec!["github"]);
}

/// A mixin `gh` binding `service`'s secret to GH_TOKEN for `domain`.
fn inject_kit(service: &str, domain: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
            dir.path().join("spec.yaml"),
            format!(
                "schemaVersion: \"2\"\nkind: mixin\nname: gh\ncredentials:\n  - service: {service}\n    \
                 apiKey:\n      name: GH_TOKEN\n      inject:\n        - domain: {domain}\n"
            ),
        )
        .unwrap();
    dir
}

#[test]
fn a_kit_cant_send_a_builtin_secret_outside_its_hosts() {
    let t = kit_env();
    global_github_secret(&t);
    let dir = inject_kit("github", "evil.example.com");
    let (mut req, plan) = kit_request(&t, &["create", "shell", "--kit"], dir.path());
    let err = crate::provision::prepare_create(&t.ctx, &mut req, &[], plan.as_ref())
        .unwrap_err()
        .to_string();
    assert_eq!(
        err,
        "kit gh wants to send your github secret to evil.example.com, which github doesn't \
             use; refusing"
    );
    assert!(sandbox_rules(&t, "shell-proj").is_empty());
}

#[test]
fn a_kit_may_send_a_custom_secret_anywhere() {
    let mut t = kit_env();
    t.sbt(&[
        "secret",
        "set-custom",
        "--env",
        "CORP",
        "--host",
        "api.corp.example",
        "-t",
        "c-1",
    ])
    .unwrap();
    let dir = inject_kit("corp", "ghe.corp.example");
    let (mut req, plan) = kit_request(&t, &["create", "shell", "--kit"], dir.path());
    crate::provision::prepare_create(&t.ctx, &mut req, &[], plan.as_ref()).unwrap();
    let c = req
        .credentials
        .iter()
        .find(|c| c.env_var == "GH_TOKEN")
        .unwrap_or_else(|| panic!("{:?}", req.credentials));
    assert_eq!(c.hosts, vec!["ghe.corp.example"]);
}

#[test]
fn a_kit_injecting_a_global_secrets_variable_differently_fails() {
    let t = kit_env();
    global_github_secret(&t);
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
            dir.path().join("spec.yaml"),
            "schemaVersion: \"2\"\nkind: mixin\nname: gh\ncredentials:\n  - service: github\n    \
             apiKey:\n      name: GH_TOKEN\n      inject:\n        - domain: api.github.com\n          \
             header: x-token\n",
        )
        .unwrap();
    let (mut req, plan) = kit_request(&t, &["create", "shell", "--kit"], dir.path());
    let err = crate::provision::prepare_create(&t.ctx, &mut req, &[], plan.as_ref())
        .unwrap_err()
        .to_string();
    assert!(err.contains("GH_TOKEN"), "{err}");
    assert!(sandbox_rules(&t, "shell-proj").is_empty());
}

/// A mixin binding the github secret to `env` for api.github.com with `inject`.
fn gh_kit(env: &str, inject: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
            dir.path().join("spec.yaml"),
            format!(
                "schemaVersion: \"2\"\nkind: mixin\nname: gh\ncredentials:\n  - service: github\n    \
                 apiKey:\n      name: {env}\n      inject:\n        - domain: api.github.com\n{inject}"
            ),
        )
        .unwrap();
    dir
}

#[test]
fn a_kit_format_must_match_the_user_secret_of_its_variable() {
    // The user's github secret records no format and no header for GH_TOKEN.
    for (inject, ok) in [
        ("", true),
        ("          scheme: bearer\n", false),
        (
            "          scheme: basic\n          username: x-access-token\n",
            false,
        ),
    ] {
        let t = kit_env();
        global_github_secret(&t);
        let dir = gh_kit("GH_TOKEN", inject);
        let (mut req, plan) = kit_request(&t, &["create", "shell", "--kit"], dir.path());
        let r = crate::provision::prepare_create(&t.ctx, &mut req, &[], plan.as_ref());
        match ok {
            true => {
                r.unwrap();
                assert!(req.rec.credential_formats.is_empty());
            }
            false => {
                let err = r.unwrap_err().to_string();
                assert_eq!(
                    err,
                    "kit gh: the github credential (GH_TOKEN) is injected differently by your \
                         github secret"
                );
            }
        }
    }
}

#[test]
fn two_kits_with_the_same_format_merge_and_differing_ones_fail() {
    // KIT_TOKEN isn't one of the github secret's own variables, so only the kits bind it.
    let bearer = "          scheme: bearer\n";
    let basic = "          scheme: basic\n          username: u\n";
    for (second, ok) in [(bearer, true), (basic, false)] {
        let t = kit_env();
        global_github_secret(&t);
        let dir = gh_kit("KIT_TOKEN", bearer);
        let other = gh_kit("KIT_TOKEN", second);
        let spec = other.path().join("spec.yaml");
        let text = std::fs::read_to_string(&spec)
            .unwrap()
            .replace("name: gh", "name: gh2");
        std::fs::write(&spec, text).unwrap();
        let other = other.path().display().to_string();
        let (mut req, plan) = kit_request(
            &t,
            &["create", "shell", "--kit", other.as_str(), "--kit"],
            dir.path(),
        );
        let r = crate::provision::prepare_create(&t.ctx, &mut req, &[], plan.as_ref());
        assert_eq!(r.is_ok(), ok, "{second}: {r:?}");
        if ok {
            let kit: Vec<_> = req
                .credentials
                .iter()
                .filter(|c| c.env_var == "KIT_TOKEN")
                .collect();
            assert_eq!(kit.len(), 1, "{:?}", req.credentials);
            assert_eq!(kit[0].set_header.as_deref(), Some("authorization"));
        }
    }
}

#[test]
fn docker_image_detection() {
    assert!(is_docker_image("docker/sandbox-templates:shell-docker"));
    assert!(is_docker_image(
        "docker/sandbox-templates:docker-agent-docker-0.11.0"
    ));
    assert!(!is_docker_image(
        "docker/sandbox-templates:docker-agent-0.11.0"
    ));
    assert!(!is_docker_image("alpine"));
    assert!(!is_docker_image("localhost:5000/x"));
}

#[test]
fn a_start_docker_workload_gets_the_docker_kit() {
    use crate::kits::model::{Content, Kind, Kit, Source};
    let mut w = Kit::new("wl", Kind::Workload, Source::Registry("acme/wl:1".into()));
    w.content = Content::Oci("/layout".into());
    assert!(!wants_docker(&w, true));
    w.starts_docker = true;
    assert!(wants_docker(&w, true));
    // docker.enabled=false: no docker kit.
    assert!(!wants_docker(&w, false));
    // A plain image is still judged by its name.
    w.content = Content::Image("docker/sandbox-templates:shell-docker".into());
    w.starts_docker = false;
    assert!(wants_docker(&w, true));
}

/// A Docker image gets the shipped kit once; a kit providing `docker` doesn't stand in for it.
#[test]
fn a_docker_image_gets_the_shipped_kit_once() {
    use crate::kits::load;
    use crate::kits::model::{Kind, Kit, Source};
    let mut dind = Kit::new("dind", Kind::Mixin, Source::Registry("acme/dind:1".into()));
    dind.provides = vec!["docker".into()];
    let names = |ks: Vec<Kit>| ks.into_iter().map(|k| k.name).collect::<Vec<_>>();
    let docker = load::builtin("docker").unwrap().unwrap();
    // docker.enabled=false (or a plain image): not added.
    assert_eq!(
        names(with_docker_kit(false, vec![dind.clone()]).unwrap()),
        ["dind"]
    );
    assert_eq!(
        names(with_docker_kit(true, vec![dind.clone()]).unwrap()),
        ["dind", "docker"]
    );
    // `--kit docker`: not added twice.
    assert_eq!(
        names(with_docker_kit(true, vec![docker, dind]).unwrap()),
        ["docker", "dind"]
    );
}

/// With `docker.enabled=false`, a required `dockerd@1` refuses the create; an optional one is
/// skipped like any other optional capability smolbento can't grant.
#[test]
fn docker_disabled_refuses_a_required_dockerd_and_skips_an_optional_one() {
    let env = |optional: bool| {
        let t = test_env(&[
            ("SMOLBENTO_KIT_ALLOW_LOCAL_KITS", "true"),
            ("SMOLBENTO_DOCKER", "false"),
        ]);
        creatable_as(&t, "shell-proj");
        let descriptor = format!(
            r#"{{"schemaVersion":"3","kind":"mixin","name":"dind","capabilities":[
                {{"type":"com.docker.sandbox/dockerd@1","optional":{optional}}}]}}"#
        );
        v3_kit(&t, "dind", &descriptor, &[]);
        t
    };
    let args = ["create", "shell", ".", "--kit", "./dind"];

    let mut t = env(false);
    let e = t.sbt(&args).unwrap_err();
    assert!(
        format!("{e:#}").ends_with(
            "kit dind: dockerd@1: Docker is disabled (docker.enabled=false); turn it on with \
             `bento settings set docker.enabled true`"
        ),
        "{e:#}"
    );
    assert!(!t.made("machine create"));

    let t = env(true);
    let argv: Vec<&str> = std::iter::once("sbt").chain(args).collect();
    let Some(Cmd::Create(a)) = Cli::try_parse_from(argv).unwrap().command else {
        panic!("expected create");
    };
    let (mut req, workload) = super::kit_target(&t.ctx, &a.targets, &a.opts, true).unwrap();
    let quiet = super::Progress::new(t.ctx.out.clone(), false, false, true);
    let plan = super::kit_plan(&t.ctx, &mut req, workload, &a.opts, &quiet).unwrap();
    assert_eq!(plan.merged.dockerd, crate::sandbox::Engine::Off);
    assert_eq!(plan.skipped, ["dind: com.docker.sandbox/dockerd@1"]);
    assert_eq!(
        plan.skipped_warnings(),
        [
            "kit dind: skipping com.docker.sandbox/dockerd@1 (Docker is disabled: \
          docker.enabled=false)"
        ]
    );

    let mut t = env(true);
    t.sbt(&args).unwrap();
    let line = t.create_line();
    assert!(line.contains("--label sbx.docker=false"), "{line}");
}

/// The shipped kit only starts dockerd (the image has Docker), so it provides nothing and composes
/// with a workload that lists `docker` among its tools, as sbx's shell kit does.
/// tck: SPEC-v3 §5.3/one-provider-per-name
#[test]
fn a_workload_providing_docker_composes_with_the_shipped_kit() {
    use crate::kits::{args::ArgValues, load, model::Kit, model::Source, resolve::resolve};
    let shipped = load::builtin("docker").unwrap().unwrap();
    assert!(shipped.provides.is_empty(), "{:?}", shipped.provides);
    let mut wl = Kit::agent_test("shell");
    wl.provides = vec!["docker@29.10.0".into()];
    let mixins = with_docker_kit(true, vec![]).unwrap();
    assert_eq!(mixins[0].source, Source::Builtin("docker"));
    resolve(wl, mixins, &ArgValues::default()).unwrap();
}

/// `kit_target` and a quiet `kit_plan` for `args` followed by `kit`.
fn kit_request(
    t: &TestEnv,
    args: &[&str],
    kit: &std::path::Path,
) -> (
    crate::sandbox::CreateRequest,
    Option<crate::kits::resolve::Plan>,
) {
    let kit = kit.display().to_string();
    // These tests add v2 mixins, which the v3 `shell` agent refuses: a v2 `shell` instead.
    let v2_shell = v2_fixture("shell-workload");
    let argv: Vec<&str> = std::iter::once("sbt")
        .chain(
            args.iter()
                .map(|a| if *a == "shell" { v2_shell.as_str() } else { a }),
        )
        .chain([kit.as_str(), "--cpus", "1", "-m", "1g"])
        .collect();
    let Some(Cmd::Create(a)) = Cli::try_parse_from(argv).unwrap().command else {
        panic!("expected create");
    };
    let (mut req, workload) = super::kit_target(&t.ctx, &a.targets, &a.opts, true).unwrap();
    let quiet = super::Progress::new(t.ctx.out.clone(), false, false, true);
    let plan = super::kit_plan(&t.ctx, &mut req, workload, &a.opts, &quiet).unwrap();
    (req, Some(plan))
}

const SHARED: &str = "/home/agent/.chk-shared";

/// A `shell-proj` create with a v3 mixin `./hm` declaring host-mount@1 at `path`, mode 0750.
fn host_mount_env(path: &str) -> TestEnv {
    let t = kit_env();
    creatable_as(&t, "shell-proj");
    let descriptor = format!(
        r#"{{"schemaVersion":"3","kind":"mixin","name":"hm","capabilities":[
                {{"type":"com.docker.sandbox/host-mount@1","config":{{"path":"{path}",
                "mode":"0750"}}}}]}}"#
    );
    v3_kit(&t, "hm", &descriptor, &[]);
    std::fs::create_dir(t.ctx.cwd.join("data")).unwrap();
    t
}

/// `./hm`'s managed directory for `path`.
fn managed(t: &TestEnv, path: &str) -> std::path::PathBuf {
    let kit = t.ctx.cwd.join("hm").display().to_string();
    crate::kits::host_mount::managed_dir(&t.ctx.paths.kit_host_mounts(), &kit, path)
}

/// The `-v` values and the `sbx.host-mounts` label of the machine create.
fn create_mounts(t: &TestEnv) -> (Vec<String>, Option<String>) {
    let call = t
        .ctx
        .vm
        .runner()
        .calls()
        .into_iter()
        .find(|c| c.starts_with(&["machine".to_string(), "create".to_string()]))
        .expect("a machine create");
    let value = |flag: &str| -> Vec<String> {
        call.windows(2)
            .filter(|w| w[0] == flag)
            .map(|w| w[1].clone())
            .collect()
    };
    let label = value("--label")
        .into_iter()
        .find_map(|l| l.strip_prefix("sbx.host-mounts=").map(String::from));
    (value("-v"), label)
}

fn mode(path: &std::path::Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).unwrap().permissions().mode() & 0o7777
}

/// Creates `args` (a `claude-proj` or `shell-proj` sandbox) with `env`; returns the env, the
/// skills `-v` values and the `sbx.skills` label.
fn skills_create(
    env: &[(&str, &str)],
    args: &[&str],
) -> (TestEnv, anyhow::Result<i32>, Vec<String>, Option<String>) {
    let mut all = vec![("SMOLBENTO_DOCKER", "false")];
    all.extend_from_slice(env);
    let mut t = test_env(&all);
    let agent = args[1];
    let fake = t.runner();
    fake.ok(
        &["machine", "status"],
        &json(
            &format!("sbx-{agent}-proj"),
            "created",
            &format!("{agent}-proj"),
        ),
    );
    fake.missing_until_created(&format!("sbx-{agent}-proj"));
    let r = t.sbt(args);
    if r.is_err() {
        return (t, r, vec![], None);
    }
    let store = t.ctx.paths.skills_store().display().to_string();
    let call = t
        .ctx
        .vm
        .runner()
        .calls()
        .into_iter()
        .find(|c| c.starts_with(&["machine".to_string(), "create".to_string()]))
        .expect("a machine create");
    let value = |flag: &str| -> Vec<String> {
        call.windows(2)
            .filter(|w| w[0] == flag)
            .map(|w| w[1].clone())
            .collect()
    };
    let mounts = value("-v")
        .into_iter()
        .filter(|v| v.starts_with(&format!("{store}:")))
        .collect();
    let label = value("--label")
        .into_iter()
        .find_map(|l| l.strip_prefix("sbx.skills=").map(String::from));
    (t, r, mounts, label)
}

#[test]
fn create_shares_skills_by_mode() {
    use crate::skills::{Access, Label, Mode, Shared};
    let claude = "/home/agent/.claude/skills";
    // (env, args, the store's mount point, the label's mode and access)
    type Case<'a> = (
        &'a [(&'a str, &'a str)],
        &'a [&'a str],
        Option<&'a str>,
        Mode,
        Shared,
        Access,
    );
    let cases: [Case; 5] = [
        (
            &[],
            &["create", "claude", "."],
            Some("/run/sbx/skills-shared:ro"),
            Mode::Readonly,
            Shared::Ro,
            Access::Link,
        ),
        (
            &[],
            &["create", "claude", ".", "--skills", "readwrite"],
            Some("/run/sbx/skills-shared"),
            Mode::Readwrite,
            Shared::Rw,
            Access::Rw,
        ),
        (
            &[],
            &["create", "claude", ".", "--skills", "off"],
            None,
            Mode::Off,
            Shared::None,
            Access::None,
        ),
        (
            &[("SMOLBENTO_SKILLS_DEFAULT_MODE", "off")],
            &["create", "claude", "."],
            None,
            Mode::Off,
            Shared::None,
            Access::None,
        ),
        (
            &[("SMOLBENTO_SKILLS_DEFAULT_MODE", "off")],
            &["create", "claude", ".", "--skills", "readonly"],
            Some("/run/sbx/skills-shared:ro"),
            Mode::Readonly,
            Shared::Ro,
            Access::Link,
        ),
    ];
    for (env, args, mount, want_mode, shared, access) in cases {
        let (t, r, mounts, label) = skills_create(env, args);
        r.unwrap();
        let store = t.ctx.paths.skills_store();
        let want: Vec<String> = mount
            .map(|m| format!("{}:{m}", store.display()))
            .into_iter()
            .collect();
        assert_eq!(mounts, want, "{args:?}");
        let label = Label::from_label(&label.expect("an sbx.skills label")).unwrap();
        assert_eq!(label.mode, want_mode, "{args:?}");
        assert_eq!(label.shared, shared, "{args:?}");
        assert_eq!(label.dirs.len(), 1, "{args:?}");
        assert_eq!(label.dirs[0].path, claude);
        assert_eq!(label.dirs[0].access, access, "{args:?}");
        if access == Access::None {
            assert!(!store.exists(), "{args:?}");
        } else {
            assert_eq!(mode(&store), 0o700, "{args:?}");
        }
    }

    let (t, r, mounts, label) = skills_create(&[], &["create", "shell", "."]);
    r.unwrap();
    assert!(mounts.is_empty() && label.is_none(), "{mounts:?} {label:?}");
    assert!(!t.ctx.paths.skills_store().exists());

    let (_, r, _, _) = skills_create(&[], &["create", "claude", ".", "--skills", "bogus"]);
    assert_eq!(
        r.unwrap_err().to_string(),
        "invalid skills mode \"bogus\": use off, readonly or readwrite"
    );
}

const AS: &str = "com.docker.sandbox/agent-skills@1";
const AK: &str = "com.docker.sandbox/agent-skill@1";

/// An `<agent>-proj` create env with a v3 mixin `./k` (named `k`) whose capabilities are
/// `caps` (a JSON list body).
fn skills_kit_env(agent: &str, caps: &str) -> TestEnv {
    let t = kit_env();
    let fake = t.runner();
    fake.ok(
        &["machine", "status"],
        &json(
            &format!("sbx-{agent}-proj"),
            "created",
            &format!("{agent}-proj"),
        ),
    );
    fake.missing_until_created(&format!("sbx-{agent}-proj"));
    let descriptor =
        format!(r#"{{"schemaVersion":"3","kind":"mixin","name":"k","capabilities":[{caps}]}}"#);
    v3_kit(&t, "k", &descriptor, &[]);
    t
}

/// The `sbx.skills` label of the machine create.
fn skills_label(t: &TestEnv) -> crate::skills::Label {
    let call = t
        .ctx
        .vm
        .runner()
        .calls()
        .into_iter()
        .find(|c| c.starts_with(&["machine".to_string(), "create".to_string()]))
        .unwrap();
    let label = call
        .windows(2)
        .filter(|w| w[0] == "--label")
        .find_map(|w| w[1].strip_prefix("sbx.skills=").map(String::from))
        .expect("an sbx.skills label");
    crate::skills::Label::from_label(&label).unwrap()
}

#[test]
fn a_kit_s_bundled_skill_caps_its_directory_and_links_before_install_hooks() {
    use crate::skills::Access;
    let caps = format!(
        r#"{{"type":"{AS}","config":{{"path":"/home/agent/.k/skills"}}}},
               {{"type":"{AK}","config":{{"path":"/opt/k/review"}}}},
               {{"type":"com.docker.sandbox/lifecycle@1",
                 "config":{{"install":[{{"command":"echo hook-ran"}}]}}}}"#
    );
    let mut t = skills_kit_env("shell", &caps);
    t.sbt(&[
        "create",
        "shell",
        ".",
        "--kit",
        "./k",
        "--skills",
        "readwrite",
    ])
    .unwrap();
    let label = skills_label(&t);
    assert_eq!(label.dirs.len(), 1, "{label:?}");
    assert_eq!(label.dirs[0].path, "/home/agent/.k/skills");
    assert_eq!(label.dirs[0].access, Access::Link);
    // The kit asks for readonly: the shared mount stays read-only under `readwrite`.
    assert_eq!(label.shared, crate::skills::Shared::Ro);
    let (mounts, _) = create_mounts(&t);
    let store = t.ctx.paths.skills_store().display().to_string();
    assert!(
        mounts.contains(&format!("{store}:/run/sbx/skills-shared:ro")),
        "{mounts:?}"
    );
    let lines = t.calls();
    let bundled = lines
        .iter()
        .position(|l| l.starts_with("machine exec") && l.contains("ln -sn '/opt/k/review'"))
        .expect("the bundled skills step");
    assert!(
        lines[bundled].contains(" -u root ") && lines[bundled].contains(" -- sh -c "),
        "{}",
        lines[bundled]
    );
    let hook = lines
        .iter()
        .position(|l| l.starts_with("machine exec") && l.contains("echo hook-ran"))
        .expect("the install hook");
    assert!(bundled < hook, "{lines:#?}");
}

/// A mountless kit sandbox's workdir is made before its install hooks: a kit workload's image
/// may not have it, and exec starts there (`tck: dockerd@1/elevation-granted` execs in it).
#[test]
fn a_mountless_kit_sandbox_gets_its_workdir_before_install_hooks() {
    let caps = r#"{"type":"com.docker.sandbox/lifecycle@1",
                   "config":{"install":[{"command":"echo hook-ran"}]}}"#;
    let mkdir = "mkdir -p '/home/agent/workspace'";
    let mut t = skills_kit_env("shell", caps);
    t.sbt(&["create", "--name", "shell-proj", "shell", "--kit", "./k"])
        .unwrap();
    let lines = t.calls();
    let dir = lines
        .iter()
        .position(|l| l.starts_with("machine exec") && l.contains(mkdir))
        .expect("the workdir step");
    assert!(lines[dir].contains(" -u root "), "{}", lines[dir]);
    assert!(lines[dir].contains("chown 'agent': "), "{}", lines[dir]);
    let hook = lines
        .iter()
        .position(|l| l.starts_with("machine exec") && l.contains("echo hook-ran"))
        .expect("the install hook");
    assert!(dir < hook, "{lines:#?}");

    let mut t = skills_kit_env("shell", caps);
    t.sbt(&["create", "shell", ".", "--kit", "./k"]).unwrap();
    assert!(
        !t.calls().iter().any(|l| l.contains(mkdir)),
        "a workspace has its own directory"
    );
}

/// The store's `-v` targets (`guest[:ro]`) of a `shell-proj` create with kit `k` and `caps`.
fn kit_skills_mounts(caps: &str, mode: &str) -> (Vec<String>, crate::skills::Label) {
    let mut t = skills_kit_env("shell", caps);
    t.sbt(&["create", "shell", ".", "--kit", "./k", "--skills", mode])
        .unwrap();
    let store = format!("{}:", t.ctx.paths.skills_store().display());
    let (mounts, _) = create_mounts(&t);
    let mounts = mounts
        .iter()
        .filter_map(|m| m.strip_prefix(&store).map(String::from))
        .collect();
    (mounts, skills_label(&t))
}

/// sbx's kit table: without a bundled skill the store is bound over each kit directory (no
/// links); with one, every directory links. Either way smolvm mounts the store once
/// (agent-skills@1/same-store-at-every-path), with the widest access.
#[test]
fn kit_skills_directories_follow_sbx_s_table() {
    use crate::skills::{Access, Shared};
    let dirs = format!(
        r#"{{"type":"{AS}","config":{{"path":"/r"}}}},
               {{"type":"{AS}","config":{{"path":"/w","mode":"readwrite"}}}}"#
    );
    let bundled = format!(r#"{dirs},{{"type":"{AK}","config":{{"path":"/opt/k/review"}}}}"#);
    let access =
        |l: &crate::skills::Label| -> Vec<Access> { l.dirs.iter().map(|d| d.access).collect() };
    let (m, l) = kit_skills_mounts(&dirs, "readwrite");
    assert_eq!(m, ["/run/sbx/skills-shared"]);
    assert_eq!(
        (l.shared, access(&l)),
        (Shared::Rw, vec![Access::Ro, Access::Rw])
    );
    let (m, l) = kit_skills_mounts(&dirs, "readonly");
    assert_eq!(m, ["/run/sbx/skills-shared:ro"]);
    assert_eq!(access(&l), [Access::Ro, Access::Ro]);
    let (m, l) = kit_skills_mounts(&dirs, "off");
    assert!(m.is_empty(), "{m:?}");
    assert_eq!(access(&l), [Access::None, Access::None]);
    let (m, l) = kit_skills_mounts(&bundled, "readwrite");
    assert_eq!(m, ["/run/sbx/skills-shared"]);
    assert_eq!(
        (l.shared, access(&l)),
        (Shared::Rw, vec![Access::Link, Access::Link])
    );
    let (m, l) = kit_skills_mounts(&bundled, "readonly");
    assert_eq!(m, ["/run/sbx/skills-shared:ro"]);
    assert_eq!(
        (l.shared, access(&l)),
        (Shared::Ro, vec![Access::Link, Access::Link])
    );
    let (m, l) = kit_skills_mounts(&bundled, "off");
    assert!(m.is_empty(), "{m:?}");
    assert_eq!(
        (l.shared, access(&l)),
        (Shared::None, vec![Access::None, Access::None])
    );
}

#[test]
fn a_bundled_skill_without_a_skills_directory_fails_or_is_skipped() {
    let required = format!(r#"{{"type":"{AK}","config":{{"path":"/opt/k/review"}}}}"#);
    let mut t = skills_kit_env("shell", &required);
    let e = t
        .sbt(&["create", "shell", ".", "--kit", "./k"])
        .unwrap_err();
    assert_eq!(
        format!("{e:#}"),
        "kit k: skill review needs a skills directory: no agent-skills@1 in this sandbox"
    );
    let lines = t.calls();
    assert!(!t.made("machine create"), "{lines:#?}");

    let optional =
        format!(r#"{{"type":"{AK}","optional":true,"config":{{"path":"/opt/k/review"}}}}"#);
    let mut t = skills_kit_env("shell", &optional);
    // Prints `note: kit k: skipping skill review: no skills directory in this sandbox`.
    t.sbt(&["create", "shell", ".", "--kit", "./k"]).unwrap();
    let lines = t.calls();
    assert!(t.made("machine create"));
    assert!(!lines.iter().any(|l| l.contains("ln -sn ")), "{lines:#?}");
}

/// agent-skill@1/host-conflict: a stored skill of a required bundled skill's name is refused
/// before anything is made; under `off` the store isn't shared, so there's no conflict.
#[test]
fn a_bundled_skill_named_like_a_stored_one_is_refused_before_create() {
    let caps = format!(
        r#"{{"type":"{AS}","config":{{"path":"/s"}}}},
           {{"type":"{AK}","config":{{"path":"/opt/k/review"}}}}"#
    );
    let mut t = skills_kit_env("shell", &caps);
    std::fs::create_dir_all(t.ctx.paths.skills_store().join("review")).unwrap();
    let e = t
        .sbt(&["create", "shell", ".", "--kit", "./k"])
        .unwrap_err();
    assert_eq!(
        format!("{e:#}"),
        "failed to compose shared skills into the sandbox: bundled skills review cannot be \
         exposed in /s: another skill already uses the name"
    );
    let lines = t.calls();
    assert!(!t.made("machine create"), "{lines:#?}");

    let mut t = skills_kit_env("shell", &caps);
    std::fs::create_dir_all(t.ctx.paths.skills_store().join("review")).unwrap();
    t.sbt(&["create", "shell", ".", "--kit", "./k", "--skills", "off"])
        .unwrap();
    assert!(t.made("machine create"));
}

#[test]
fn a_kit_s_readonly_request_does_not_cap_the_built_in_readwrite_one() {
    use crate::skills::Access;
    let caps = format!(
        r#"{{"type":"{AS}","config":{{"path":"/home/agent/.claude/skills","mode":"readonly"}}}}"#
    );
    let mut t = skills_kit_env("claude", &caps);
    t.sbt(&[
        "create",
        "claude",
        ".",
        "--kit",
        "./k",
        "--skills",
        "readwrite",
    ])
    .unwrap();
    let label = skills_label(&t);
    assert_eq!(label.dirs.len(), 1, "{label:?}");
    assert_eq!(label.dirs[0].path, "/home/agent/.claude/skills");
    assert_eq!(label.dirs[0].access, Access::Rw);
}

#[test]
fn create_mounts_a_kit_s_managed_host_directory() {
    let mut t = host_mount_env(SHARED);
    t.sbt(&["create", "shell", ".", "--kit", "./hm"]).unwrap();
    let out = t.stdout();
    assert!(
        out.contains("\n  ○ ./hm — building…\n  ✓ ./hm — ready\n\nIMAGE\n"),
        "{out}"
    );
    let dir = managed(&t, SHARED);
    let (mounts, label) = create_mounts(&t);
    assert!(
        mounts.contains(&format!("{}:{SHARED}", dir.display())),
        "{mounts:?}"
    );
    let want = serde_json::json!({ SHARED: dir }).to_string();
    assert_eq!(label.as_deref(), Some(want.as_str()));
    assert_eq!(mode(&dir), 0o750);
    assert_eq!(mode(dir.parent().unwrap()), 0o700);
    assert_eq!(mode(&t.ctx.paths.kit_host_mounts()), 0o700);
}

#[test]
fn an_existing_managed_directory_is_reused_unchanged() {
    use std::os::unix::fs::PermissionsExt;
    let mut t = host_mount_env(SHARED);
    let dir = managed(&t, SHARED);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o711)).unwrap();
    std::fs::write(dir.join("keep"), "x").unwrap();
    t.sbt(&["create", "shell", ".", "--kit", "./hm"]).unwrap();
    assert_eq!(mode(&dir), 0o711);
    assert_eq!(std::fs::read_to_string(dir.join("keep")).unwrap(), "x");
}

#[test]
fn mount_binds_a_host_directory_instead_of_the_managed_one() {
    let mut t = host_mount_env(SHARED);
    let bind = format!("data:{SHARED}");
    t.sbt(&["create", "shell", ".", "--kit", "./hm", "--mount", &bind])
        .unwrap();
    let data = t.ctx.cwd.join("data");
    let (mounts, label) = create_mounts(&t);
    assert!(
        mounts.contains(&format!("{}:{SHARED}", data.display())),
        "{mounts:?}"
    );
    let want = serde_json::json!({ SHARED: data }).to_string();
    assert_eq!(label.as_deref(), Some(want.as_str()));
    assert!(!t.ctx.paths.kit_host_mounts().exists());
}

#[test]
fn refused_mounts_create_nothing() {
    let shared = format!("data:{SHARED}");
    let other = "data:/home/agent/other";
    let undeclared = "no kit declares host-mount@1 at \"/home/agent/other\"";
    let cases: Vec<(Vec<&str>, String)> = vec![
        (
            vec!["--kit", "./hm", "--mount", "data"],
            "--mount \"data\" requires HOST:SANDBOX_PATH\n  try: bento create --help".into(),
        ),
        (
            vec!["--kit", "./hm", "--mount", "missing:/x"],
            "HOST \"{cwd}/missing\" does not exist on the host".into(),
        ),
        (
            vec!["--kit", "./hm", "--mount", &shared, "--mount", &shared],
            format!("--mount {SHARED} given twice"),
        ),
        (vec!["--kit", "./hm", "--mount", other], undeclared.into()),
        // No kits at all.
        (vec!["-t", "alpine", "--mount", other], undeclared.into()),
    ];
    for (flags, want) in cases {
        let mut t = host_mount_env(SHARED);
        let cwd = t.ctx.cwd.display().to_string();
        let mut args = vec!["create", "shell", "."];
        args.extend(&flags);
        let e = t.sbt(&args).unwrap_err();
        assert_eq!(format!("{e:#}"), want.replace("{cwd}", &cwd), "{flags:?}");
        assert!(!t.made("machine create"), "{flags:?}");
        assert!(!t.ctx.paths.kit_host_mounts().exists(), "{flags:?}");
    }
}

#[test]
fn a_host_mount_at_a_workspace_path_is_refused() {
    let ws = tempfile::tempdir().unwrap();
    let ws = ws.path().canonicalize().unwrap().display().to_string();
    let mut t = host_mount_env(&ws);
    t.creatable("ws", &[]);
    let e = t
        .sbt(&["create", "shell", &ws, "--kit", "./hm", "--name", "ws"])
        .unwrap_err();
    assert_eq!(
        format!("{e:#}"),
        format!("host-mount@1 path {ws} is already a workspace mount")
    );
    assert!(!t.made("machine create"));
    assert!(!t.ctx.paths.kit_host_mounts().exists());
}

#[test]
fn kit_docker_adds_dockerd_to_any_template() {
    let mut t = test_env(&[]);
    creatable_as(&t, "shell-proj");
    t.sbt(&["create", "-t", "alpine", "--kit", "docker", "shell", "."])
        .unwrap();
    let line = t.create_line();
    assert!(line.contains("--image alpine "), "{line}");
    assert!(
        line.contains("-v /var/lib/docker -v /var/lib/containerd"),
        "{line}"
    );
    assert!(line.contains("--label sbx.docker=true"), "{line}");
    // The agent's kit, then the docker kit.
    assert!(
        line.contains(&format!(
            ",{}]",
            r#"{"name":"docker","ref":"builtin:docker"}"#
        )),
        "{line}"
    );
}

#[test]
fn a_template_refuses_kits_that_add_image_layers() {
    let mut t = kit_env_free();
    saved_template(&t, "chk-tpl:v1", "shell");
    v3_kit(
        &t,
        "layered",
        r#"{"schemaVersion":"3","kind":"mixin","name":"layered"}"#,
        &[b"layer"],
    );
    let err = t
        .sbt(&[
            "create",
            "shell",
            "-t",
            "chk-tpl:v1",
            "--name",
            "bb",
            "--kit",
            "./layered",
        ])
        .unwrap_err();
    assert_eq!(
        err.to_string(),
        "-t docker.io/library/chk-tpl:v1 can't be combined with kits that add image layers \
             (layered): a template's filesystem is saved whole"
    );
    let lines = t.calls();
    assert!(!t.made("machine create"), "{lines:?}");
}

#[test]
fn create_of_a_taken_name_fails_before_printing_or_fetching_kits() {
    let mut t = kit_env();
    t.runner().ok(
        &["machine", "status"],
        &json("sbx-shell-proj", "stopped", "shell-proj"),
    );
    v3_kit(
        &t,
        "kit",
        r#"{"schemaVersion":"3","kind":"mixin","name":"m"}"#,
        &[],
    );
    let err = t
        .sbt(&["create", "shell", ".", "--kit", "./kit"])
        .unwrap_err();
    assert_eq!(err.to_string(), "sandbox 'shell-proj' already exists");
    assert_eq!(t.stdout(), "");
    assert_eq!(
        t.calls(),
        [
            "machine ls --json",
            "machine status -n sbx-shell-proj --json"
        ]
    );
}

#[test]
fn kits_without_a_fetch_wait_for_the_kits_section() {
    let mut t = host_mount_env(SHARED);
    t.sbt(&["create", "shell", ".", "--kit", "docker", "--kit", "./hm"])
        .unwrap();
    let out = t.stdout();
    assert!(
        out.contains(
            "— cached\n  ✓ docker — cached\n  ○ ./hm — building…\n  ✓ ./hm — ready\n\nIMAGE\n"
        ),
        "{out}"
    );
}

#[test]
fn create_refuses_v2_and_v3_kits_together() {
    let mut t = host_mount_env(SHARED);
    let v2 = v2_fixture("tool-mixin");
    let err = t.sbt_err(&["create", "shell", ".", "--kit", &v2, "--kit", "./hm"]);
    assert!(
        err.starts_with("cannot mix v3 kits with v1/v2 kits in one sandbox"),
        "{err}"
    );
    assert!(!t.made("machine create"));
}
