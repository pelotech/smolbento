use super::*;
use crate::kits::args::ArgValues;
use crate::kits::model::{
    AgentContextReq, Cap, CapBody, Content, CredReq, FileReq, Format, Hook, HookCmd, Inject, Kind,
    Kit, Lifecycle, NetRule, OAuthReq, Rules, Source,
};
use crate::kits::resolve::resolve;
use crate::sandbox::{Engine, create};
use crate::secrets::{SecretEntry, Source as SecretSource};

fn kit(name: &str, kind: Kind) -> Kit {
    Kit::test(name, kind)
}
/// A published v2 workload: a v2 spec names its image.
fn workload() -> Kit {
    let mut w = kit("wl", Kind::Workload);
    w.v2 = true;
    w.content = Content::Image("img:1".into());
    w.command = Some(vec!["wl".into(), "--go".into()]);
    w
}
fn with(mut k: Kit, ty: &str, optional: bool, body: CapBody) -> Kit {
    k.caps
        .push(Cap::new(format!("com.docker.sandbox/{ty}"), optional, body));
    k
}
fn rules(hosts: &[&str]) -> Rules {
    Rules {
        allow: hosts.iter().map(|h| NetRule::host(*h)).collect(),
        deny: vec![],
    }
}
fn plan(mixins: Vec<Kit>) -> Plan {
    resolve(workload(), mixins, &ArgValues::default()).unwrap()
}
fn secrets(services: &[&str]) -> SecretsFile {
    SecretsFile {
        secrets: services
            .iter()
            .map(|s| SecretEntry {
                service: s.to_string(),
                scope: "global".into(),
                source: SecretSource::Keychain,
            })
            .collect(),
        custom: vec![],
        registries: vec![],
        bindings: Default::default(),
    }
}
/// The user's `anthropic` secret, bound as `create` binds it before the kits.
fn user_anthropic() -> (SecretsFile, CreateRequest) {
    let s = secrets(&["anthropic"]);
    let mut req = request();
    req.credentials = crate::provision::credentials(&s, &["anthropic".into()]).unwrap();
    req.rec.credential_env = vec!["ANTHROPIC_API_KEY".into()];
    req.rec.secrets = vec!["anthropic".into()];
    (s, req)
}
fn request() -> CreateRequest {
    CreateRequest {
        name: "sb".into(),
        agent: "claude".into(),
        image: "preset:1".into(),
        cpus: 2,
        memory_mib: 4096,
        created: 1,
        ..Default::default()
    }
}
fn no_git() -> Option<(String, String)> {
    None
}
fn run(p: &Plan, req: &mut CreateRequest, policy: &mut Policy) -> Result<(KitSteps, Vec<String>)> {
    run_with(p, req, policy, &secrets(&[]))
}
fn run_with(
    p: &Plan,
    req: &mut CreateRequest,
    policy: &mut Policy,
    s: &SecretsFile,
) -> Result<(KitSteps, Vec<String>)> {
    let store = crate::secrets::store::MemoryStore::default();
    apply(
        p,
        req,
        policy,
        s,
        &store,
        Path::new("/nonexistent"),
        &no_git,
    )
}
fn credential_args(req: &CreateRequest) -> Vec<String> {
    create::spec(req)
        .to_args()
        .windows(2)
        .filter(|w| w[0] == "--credential")
        .map(|w| w[1].clone())
        .collect()
}
fn rule_hosts(policy: &Policy, ids: &[String]) -> Vec<String> {
    ids.iter()
        .map(|id| policy.find(id).unwrap().0.resources.join(","))
        .collect()
}
fn cred(service: &str, env: Option<&str>, inject: Vec<Inject>) -> CapBody {
    CapBody::Credential(CredReq {
        service: service.into(),
        install: false,
        runtime: true,
        env: env.map(String::from),
        inject,
        oauth: None,
    })
}
fn inject(domain: &str, header: Option<&str>) -> Inject {
    Inject {
        domain: domain.into(),
        header: header.map(String::from),
        format: None,
        basic_user: None,
    }
}

#[test]
fn network_rules_are_added_and_install_ones_listed_for_removal() {
    let net = CapBody::Network {
        install: rules(&["pkg.example.com", "both.example.com"]),
        runtime: rules(&["api.example.com", "both.example.com"]),
    };
    let p = plan(vec![with(
        kit("net", Kind::Mixin),
        "network-policy@1",
        false,
        net,
    )]);
    let mut policy = Policy::default();
    let mut req = request();
    let (steps, added) = run(&p, &mut req, &mut policy).unwrap();
    assert_eq!(
        rule_hosts(&policy, &added),
        ["api.example.com", "both.example.com", "pkg.example.com"]
    );
    // `both` is also a runtime rule, so it stays after install.
    assert_eq!(
        rule_hosts(&policy, &steps.install_rules),
        ["pkg.example.com"]
    );
    for id in &added {
        let via = &policy.find(id).unwrap().0.created_via;
        if steps.install_rules.contains(id) {
            assert_eq!(via, "kit-install:net");
        } else {
            assert_eq!(via, "kit:net");
        }
    }
    // Applying again adds nothing new, so a rollback can't remove what was there; the install
    // rules already in place (an interrupted create's) still open for the first start.
    let mut again = request();
    let (steps, added) = run(&p, &mut again, &mut policy).unwrap();
    assert!(added.is_empty(), "{added:?}");
    assert_eq!(
        rule_hosts(&policy, &steps.install_rules),
        ["pkg.example.com"]
    );
}

#[test]
fn a_missing_custom_secret_names_the_command_that_defines_it() {
    assert_eq!(
        missing_secret("k", "my-api", "api.x.com"),
        "kit k needs the my-api secret; set it with \
             bento secret set-custom --env MY_API --host api.x.com \
             and recreate the sandbox"
    );
    // `set-custom --env MY_API` names its service my-api, never my_api or 1tok.
    for service in ["my_api", "1tok", "My-Api"] {
        let m = missing_secret("k", service, "api.x.com");
        assert!(
            m.starts_with(&format!(
                "kit k needs a custom secret service named {service}, which"
            )) && m.contains("can't define"),
            "{m}"
        );
    }
}

#[test]
fn a_kit_cant_use_an_mcp_servers_secret() {
    let p = |optional| {
        plan(vec![with(
            kit("k", Kind::Mixin),
            "credential@1",
            optional,
            cred(
                "mcp:linear:api-key",
                Some("TOK"),
                vec![inject("evil.example", None)],
            ),
        )])
    };
    let has_it = secrets(&["mcp:linear:api-key"]);
    let err = run_with(&p(false), &mut request(), &mut Policy::default(), &has_it)
        .unwrap_err()
        .to_string();
    assert_eq!(
        err,
        "kit k asks for mcp:linear:api-key, an MCP server's secret, which kits can't use"
    );
    // Optional: skipped, and nothing is bound.
    let mut req = request();
    run_with(&p(true), &mut req, &mut Policy::default(), &has_it).unwrap();
    assert!(req.credentials.is_empty(), "{:?}", req.credentials);
    assert!(req.rec.credential_services.is_empty());
}

#[test]
fn a_custom_service_binding_notes_where_the_secret_goes() {
    let hosts = vec!["api.x.com".to_string(), "up.x.com".to_string()];
    assert_eq!(
        custom_service_note("k", "my-api", &hosts),
        "note: kit k sends your my-api secret to api.x.com, up.x.com"
    );
}

#[test]
fn an_api_key_credential_becomes_a_smolvm_credential() {
    let c = cred(
        "anthropic",
        Some("ANTHROPIC_API_KEY"),
        vec![inject("api.anthropic.com", None)],
    );
    let p = plan(vec![with(kit("a", Kind::Mixin), "credential@1", false, c)]);
    let mut req = request();
    run_with(
        &p,
        &mut req,
        &mut Policy::default(),
        &secrets(&["anthropic"]),
    )
    .unwrap();
    assert_eq!(
        credential_args(&req),
        ["anthropic_api_key=ANTHROPIC_API_KEY@api.anthropic.com"]
    );
    assert_eq!(req.rec.secrets, ["anthropic"]);
    assert_eq!(req.rec.credential_env, ["ANTHROPIC_API_KEY"]);
    assert_eq!(req.rec.credential_hosts, ["api.anthropic.com"]);
    assert!(req.rec.credential_services.is_empty());
}

#[test]
fn a_builtin_secret_goes_only_to_its_own_hosts() {
    assert!(super::host_within(
        "API.github.com",
        &["api.github.com".into()]
    ));
    assert!(!super::host_within(
        "x.api.github.com",
        &["api.github.com".into()]
    ));
    let pat = ["*.example.com".to_string()];
    assert!(super::host_within("a.example.com", &pat));
    assert!(super::host_within("*.a.example.com", &pat));
    assert!(super::host_within("*.example.com", &pat));
    assert!(!super::host_within("example.com", &pat));

    let c = cred(
        "github",
        None,
        vec![
            inject("api.github.com", None),
            inject("ghe.corp.example", None),
        ],
    );
    let p = plan(vec![with(
        kit("g", Kind::Mixin),
        "credential@1",
        false,
        c.clone(),
    )]);
    let mut req = request();
    let e = run_with(&p, &mut req, &mut Policy::default(), &secrets(&["github"]))
        .unwrap_err()
        .to_string();
    assert_eq!(
        e,
        "kit g wants to send your github secret to ghe.corp.example, which github doesn't use; \
             refusing"
    );
    // Checked before the secret: setting it wouldn't help.
    let e = run_with(&p, &mut request(), &mut Policy::default(), &secrets(&[]))
        .unwrap_err()
        .to_string();
    assert!(e.contains("refusing"), "{e}");
    // An optional one is skipped.
    let p = plan(vec![with(kit("g", Kind::Mixin), "credential@1", true, c)]);
    let mut req = request();
    run_with(&p, &mut req, &mut Policy::default(), &secrets(&["github"])).unwrap();
    assert!(req.credentials.is_empty(), "{:?}", req.credentials);
}

#[test]
fn a_kit_key_that_isnt_bound_leaves_the_service_variable() {
    // Optional, and aimed at a host the service doesn't use: refused, so the user's own
    // variable is the only way the key reaches the sandbox.
    let c = cred(
        "anthropic",
        None,
        vec![inject("api.example.com", Some("x-api-key"))],
    );
    let p = plan(vec![with(kit("k", Kind::Mixin), "credential@1", true, c)]);
    let (s, mut req) = user_anthropic();
    run_with(&p, &mut req, &mut Policy::default(), &s).unwrap();
    assert_eq!(req.rec.credential_env, ["ANTHROPIC_API_KEY"]);
}

#[test]
fn a_kit_that_takes_a_key_without_a_variable_gets_no_service_variable() {
    // Claude's kit: the key reaches the agent through its apiKeyHelper, never a variable.
    // `ANTHROPIC_API_KEY` from the user's secret would make Claude ask whether to use it.
    let c = cred(
        "anthropic",
        None,
        vec![inject("api.anthropic.com", Some("x-api-key"))],
    );
    let p = plan(vec![with(
        kit("claude", Kind::Mixin),
        "credential@1",
        true,
        c,
    )]);
    let (s, mut req) = user_anthropic();
    run_with(&p, &mut req, &mut Policy::default(), &s).unwrap();
    assert_eq!(
        credential_args(&req),
        ["sbx_kit_anthropic=SBX_KIT_ANTHROPIC@api.anthropic.com:set-header=x-api-key"]
    );
    assert_eq!(req.rec.credential_env, ["SBX_KIT_ANTHROPIC"]);
    assert_eq!(req.rec.secrets, ["anthropic"]);

    // Another kit that names the variable keeps it.
    let named = cred(
        "anthropic",
        Some("ANTHROPIC_API_KEY"),
        vec![inject("api.anthropic.com", None)],
    );
    let p = plan(vec![
        with(
            kit("claude", Kind::Mixin),
            "credential@1",
            true,
            cred(
                "anthropic",
                None,
                vec![inject("api.anthropic.com", Some("x-api-key"))],
            ),
        ),
        with(kit("other", Kind::Mixin), "credential@1", false, named),
    ]);
    let (_, mut req) = user_anthropic();
    run_with(&p, &mut req, &mut Policy::default(), &s).unwrap();
    assert!(
        req.rec
            .credential_env
            .contains(&"ANTHROPIC_API_KEY".to_string()),
        "{req:?}"
    );
}

#[test]
fn an_inject_only_credential_sets_its_header() {
    let mut i = inject("api.x.com", Some("authorization"));
    i.format = Some("Bearer %s".into());
    let c = cred("xsvc", None, vec![i]);
    let p = plan(vec![with(kit("x", Kind::Mixin), "credential@1", false, c)]);
    let mut req = request();
    run_with(&p, &mut req, &mut Policy::default(), &secrets(&["xsvc"])).unwrap();
    assert_eq!(
        credential_args(&req),
        ["sbx_kit_xsvc=SBX_KIT_XSVC@api.x.com:set-header=authorization"]
    );
    assert_eq!(
        req.rec.credential_formats["SBX_KIT_XSVC"],
        crate::sandbox::labels::CredFormat::Format("Bearer %s".into())
    );
    assert_eq!(req.rec.credential_services["SBX_KIT_XSVC"], "xsvc");
}

#[test]
fn a_missing_required_credential_warns_like_sbx_and_an_optional_one_is_skipped() {
    let c = || cred("github", Some("GH_TOKEN"), vec![inject("github.com", None)]);
    for optional in [false, true] {
        let p = plan(vec![with(
            kit("gh", Kind::Mixin),
            "credential@1",
            optional,
            c(),
        )]);
        let mut policy = Policy::default();
        let mut req = request();
        run(&p, &mut req, &mut policy).unwrap();
        assert!(req.credentials.is_empty(), "{:?}", req.credentials);
        assert!(credential_args(&req).is_empty());
    }
    assert_eq!(
        unbound_required("gh", "github", "github.com"),
        "WARN: required credential not found for service github\n\
             kit gh needs the github secret; set it with bento secret set github \
             and recreate the sandbox"
    );
}

#[test]
fn install_only_credentials_are_recorded() {
    let mut c = CredReq {
        service: "github".into(),
        install: true,
        runtime: false,
        env: Some("GH_TOKEN".into()),
        inject: vec![inject("github.com", None)],
        oauth: None,
    };
    let p = plan(vec![with(
        kit("gh", Kind::Mixin),
        "credential@1",
        false,
        CapBody::Credential(c.clone()),
    )]);
    let mut req = request();
    run_with(&p, &mut req, &mut Policy::default(), &secrets(&["github"])).unwrap();
    assert_eq!(req.rec.credential_install, ["GH_TOKEN"]);
    c.runtime = true;
    let p = plan(vec![with(
        kit("gh", Kind::Mixin),
        "credential@1",
        false,
        CapBody::Credential(c),
    )]);
    let mut req = request();
    run_with(&p, &mut req, &mut Policy::default(), &secrets(&["github"])).unwrap();
    assert!(req.rec.credential_install.is_empty());
}

#[test]
fn a_workload_declaring_sbx_is_launched_by_the_host() {
    // Any workload kit, not only a built-in agent's: sbx@1 says the host launches it.
    let w = with(workload(), "sbx@1", false, CapBody::Sbx);
    let p = resolve(w, vec![], &ArgValues::default()).unwrap();
    let mut req = request();
    run(&p, &mut req, &mut Policy::default()).unwrap();
    assert!(req.launched_by_host);
    // Without it, the image's entrypoint is the workload, started at boot.
    let mut req = request();
    run(&plan(vec![]), &mut req, &mut Policy::default()).unwrap();
    assert!(!req.launched_by_host);
}

#[test]
fn the_login_note_is_only_for_a_service_without_its_key() {
    let kc = |passthrough| KitCred {
        kit: "claude".into(),
        optional: true,
        req: CredReq {
            service: "anthropic".into(),
            install: false,
            runtime: true,
            env: None,
            inject: vec![],
            oauth: Some(OAuthReq {
                passthrough,
                token_host: None,
                resource_hosts: vec![],
            }),
        },
    };
    let note = oauth_note(&kc(false), false).unwrap();
    assert!(
        note.contains("asks you to log in inside the sandbox"),
        "{note}"
    );
    // Its API key is bound: nothing to say.
    assert_eq!(oauth_note(&kc(false), true), None);
    // Passthrough tokens always live in the sandbox.
    assert!(oauth_note(&kc(true), true).unwrap().contains("passthrough"));
}

#[test]
fn oauth_only_allows_its_hosts() {
    let o = |passthrough| {
        CapBody::Credential(CredReq {
            service: "xsvc".into(),
            install: true,
            runtime: true,
            env: None,
            inject: vec![],
            oauth: Some(OAuthReq {
                passthrough,
                token_host: Some("auth.x.com".into()),
                resource_hosts: vec!["api.x.com".into()],
            }),
        })
    };
    let p = plan(vec![with(
        kit("o", Kind::Mixin),
        "credential@1",
        false,
        o(true),
    )]);
    let mut policy = Policy::default();
    let mut req = request();
    let (steps, added) = run(&p, &mut req, &mut policy).unwrap();
    assert_eq!(rule_hosts(&policy, &added), ["auth.x.com", "api.x.com"]);
    assert!(steps.install_rules.is_empty(), "same hosts as runtime");
    assert!(credential_args(&req).is_empty());
    assert!(req.rec.secrets.is_empty());

    // Without passthrough (sbx's sentinels) the hosts are allowed too: the login happens in
    // the sandbox.
    let p = plan(vec![with(
        kit("o", Kind::Mixin),
        "credential@1",
        false,
        o(false),
    )]);
    let mut policy = Policy::default();
    let mut req = request();
    let (_, added) = run(&p, &mut req, &mut policy).unwrap();
    assert_eq!(rule_hosts(&policy, &added), ["auth.x.com", "api.x.com"]);
}

#[test]
fn resources_ports_volumes_and_env() {
    let k = kit("m", Kind::Mixin);
    let k = with(
        k,
        "resources@1",
        false,
        CapBody::Resources {
            cpus: Some("4".into()),
            memory: Some("8g".into()),
        },
    );
    let k = with(
        k,
        "port@1",
        false,
        CapBody::Port {
            container: 3000,
            udp: false,
        },
    );
    let k = with(
        k,
        "volume@1",
        false,
        CapBody::Volume {
            path: "/data".into(),
            tmpfs: false,
            mode: None,
        },
    );
    let k = with(
        k,
        "volume@1",
        false,
        CapBody::Volume {
            path: "/scratch".into(),
            tmpfs: true,
            mode: Some("1777".into()),
        },
    );
    let mut k = k;
    k.env = vec![("A".into(), "kit".into()), ("B".into(), "kit".into())];
    let p = plan(vec![k]);

    let mut req = request();
    req.env = vec![("A".into(), "user".into())];
    let (steps, _) = run(&p, &mut req, &mut Policy::default()).unwrap();
    assert_eq!((req.cpus, req.memory_mib), (4, 8192));
    assert_eq!(req.ports.len(), 1);
    assert_eq!((req.ports[0].guest, req.ports[0].udp), (3000, false));
    assert_ne!(req.ports[0].host, 0);
    assert_eq!(req.volumes, ["/data"]);
    assert_eq!(req.tmpfs, ["/scratch"]);
    assert_eq!(
        req.env,
        [
            ("A".to_string(), "user".to_string()),
            ("B".into(), "kit".into())
        ]
    );
    let (name, body) = &steps.startup_d[0];
    assert_eq!(name, "00-volumes.sh");
    assert!(
        body.contains("mount -t tmpfs -o mode='1777' tmpfs '/scratch'"),
        "{body}"
    );
    let mounts: Vec<String> = create::spec(&req)
        .to_args()
        .windows(2)
        .filter(|w| w[0] == "-v")
        .map(|w| w[1].clone())
        .collect();
    assert_eq!(mounts, ["/data"]);

    let mut req = request();
    req.cpus_set = true;
    req.memory_set = true;
    run(&p, &mut req, &mut Policy::default()).unwrap();
    assert_eq!((req.cpus, req.memory_mib), (2, 4096));
}

#[test]
fn image_command_kits_and_long_running() {
    let mut m = with(
        kit("m", Kind::Mixin),
        "long-running@1",
        false,
        CapBody::LongRunning,
    );
    m.provides = vec!["a".into(), "b".into()];
    let p = plan(vec![m]);
    let mut req = request();
    let (steps, _) = run(&p, &mut req, &mut Policy::default()).unwrap();
    assert_eq!(req.image, "img:1");
    assert_eq!(req.rec.command, Some(vec!["wl".to_string(), "--go".into()]));
    let pinned = |n: &str| format!("acme/{n}:1@sha256:{}", "ab".repeat(32));
    let record = |name: &str, provides: &[&str], format| KitRecord {
        name: name.into(),
        reference: pinned(name),
        provides: provides.iter().map(|p| p.to_string()).collect(),
        format: Some(format),
        args: Default::default(),
    };
    assert_eq!(
        req.rec.kits,
        [
            record("wl", &[], Format::V2),
            record("m", &["a", "b"], Format::V3)
        ]
    );
    assert!(req.rec.long_running);
    // The fixture workload is a published kit that names an image: a v2 one.
    assert_eq!(steps.kit_names, ["wl", "m"]);
    let labels = create::spec(&req).labels;
    assert_eq!(labels["sbx.long-running"], "true");
    assert_eq!(labels["sbx.command"], r#"["wl","--go"]"#);
}

#[test]
fn a_v3_workload_records_its_image_user_and_installs_in_its_workdir() {
    let hook = Hook {
        command: HookCmd::Shell("make".into()),
        user: None,
        env: vec![],
        background: false,
        clean_env: true,
    };
    let m = with(
        kit("m", Kind::Mixin),
        "lifecycle@1",
        false,
        CapBody::Lifecycle(Lifecycle {
            install: vec![hook],
            ..Default::default()
        }),
    );
    let mut w = workload();
    w.config = Some(crate::kits::model::ImageConfig {
        user: "somebody".into(),
        workdir: "/x".into(),
        ..Default::default()
    });
    let p = resolve(w, vec![m.clone()], &ArgValues::default()).unwrap();
    let mut req = request();
    let (steps, _) = run(&p, &mut req, &mut Policy::default()).unwrap();
    assert_eq!(req.rec.user.as_deref(), Some("somebody"));
    assert_eq!(create::spec(&req).labels["sbx.user"], "somebody");
    assert_eq!(create::spec(&req).labels["sbx.workdir"], "/x");
    assert_eq!(steps.install[0].user, None);
    assert!(
        steps.install[0].script.starts_with("cd '/x' && env -i "),
        "{}",
        steps.install[0].script
    );

    // No USER is root; no WORKDIR is `/`.
    let mut w = workload();
    w.config = Some(Default::default());
    let p = resolve(w, vec![m], &ArgValues::default()).unwrap();
    let mut req = request();
    let (steps, _) = run(&p, &mut req, &mut Policy::default()).unwrap();
    assert_eq!(req.rec.user.as_deref(), Some("0"));
    assert_eq!(req.rec.image_workdir, None);
    assert!(steps.install[0].script.starts_with("cd / && env -i "));
}

#[test]
fn a_workload_without_an_image_config_records_no_user() {
    let p = plan(vec![]);
    let mut req = request();
    run(&p, &mut req, &mut Policy::default()).unwrap();
    assert_eq!(req.rec.user, None);
    assert!(!create::spec(&req).labels.contains_key("sbx.user"));
}

#[test]
fn a_smolfile_workload_is_passed_with_smolfile() {
    let mut w = kit("sf", Kind::Workload);
    w.source = Source::Smolfile("/k/Smolfile".into());
    w.content = Content::Smolfile("/k/Smolfile".into());
    let p = resolve(w, vec![], &ArgValues::default()).unwrap();
    let mut req = request();
    run(&p, &mut req, &mut Policy::default()).unwrap();
    let args = create::spec(&req).to_args();
    assert!(!args.contains(&"--image".to_string()), "{args:?}");
    let i = args.iter().position(|a| a == "--smolfile").unwrap();
    assert_eq!(args[i + 1], "/k/Smolfile");
}

#[test]
fn hooks_and_files_become_steps() {
    let hook = |cmd: &str, user: Option<&str>, background| Hook {
        command: HookCmd::Shell(cmd.into()),
        user: user.map(String::from),
        env: vec![],
        background,
        clean_env: true,
    };
    let file = |path: &str, content: &str| FileReq {
        path: path.into(),
        content: content.into(),
        mode: None,
        overwrite: true,
    };
    let a = with(
        kit("a", Kind::Mixin),
        "lifecycle@1",
        false,
        CapBody::Lifecycle(Lifecycle {
            install: vec![hook("apt-get install x", None, false)],
            startup: vec![hook("serve", Some("agent"), true)],
            files: vec![file("/etc/x", "from a")],
            interactive: false,
        }),
    );
    let b = with(
        kit("b", Kind::Mixin),
        "lifecycle@1",
        false,
        CapBody::Lifecycle(Lifecycle {
            install: vec![hook("npm i -g y", Some("agent"), false)],
            startup: vec![],
            files: vec![file("/etc/y", "from b")],
            interactive: false,
        }),
    );
    let p = plan(vec![a, b]);
    let mut req = request();
    let (steps, _) = run(&p, &mut req, &mut Policy::default()).unwrap();
    let labels: Vec<&str> = steps.install.iter().map(|i| i.label.as_str()).collect();
    assert_eq!(labels, ["kit a install hook 1", "kit b install hook 1"]);
    let install: Vec<(Option<String>, String)> = steps
        .install
        .into_iter()
        .map(|i| (i.user, i.script))
        .collect();
    // guest's tests pin the hook text; here it only has to run from WORKDIR (`/` here).
    let script = |cmd: &str| {
        format!(
            "cd / && {}",
            crate::kits::guest::hook_script(&hook(cmd, None, false))
        )
    };
    assert!(script("x").contains("env -i "));
    assert_eq!(
        install,
        [
            (None, script("apt-get install x")),
            (Some("agent".into()), script("npm i -g y")),
        ]
    );
    // `resolve` refuses two kits writing one path; each kit's file is written, in order.
    assert_eq!(steps.files.len(), 2);
    assert!(steps.files[0].contains("'from a'") && steps.files[1].contains("'from b'"));
    let names: Vec<&str> = steps.startup_d.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(names, ["01-a.sh"]);
    assert!(
        // A background hook, so quoted once more for its detached `sh -c`.
        steps.startup_d[0].1.contains(r"runuser -u '\''agent'\''"),
        "{}",
        steps.startup_d[0].1
    );
}

/// The workload user's global defaults, which outrank an image's own `~/.gitconfig` (`tck:
/// git-identity@1/global-defaults`), set before any install hook (`tck: git-identity@1/before-hooks`).
#[test]
fn git_identity_comes_from_the_host() {
    let p = plan(vec![with(
        kit("g", Kind::Mixin),
        "git-identity@1",
        false,
        CapBody::GitIdentity,
    )]);
    let git = || Some(("Ada L".to_string(), "ada@x.org".to_string()));
    let mut req = request();
    let (steps, _) = apply(
        &p,
        &mut req,
        &mut Policy::default(),
        &secrets(&[]),
        &crate::secrets::store::MemoryStore::default(),
        Path::new("/nonexistent"),
        &git,
    )
    .unwrap();
    assert_eq!(
            steps.install,
            [InstallStep {
                label: "the git identity step".into(),
                kit: None,
                user: Some("agent".into()),
                script: "git config --global user.name 'Ada L' && git config --global user.email 'ada@x.org'"
                    .to_string(),
                relay_stderr: false,
            }]
        );
    let e = run(&p, &mut request(), &mut Policy::default()).unwrap_err();
    assert!(format!("{e:#}").contains("git config"), "{e:#}");
    let p = plan(vec![with(
        kit("g", Kind::Mixin),
        "git-identity@1",
        true,
        CapBody::GitIdentity,
    )]);
    let (steps, _) = run(&p, &mut request(), &mut Policy::default()).unwrap();
    assert!(steps.install.is_empty());
}

#[test]
fn a_bad_host_part_way_leaves_the_policy_unchanged() {
    let ok = CapBody::Network {
        install: Rules::default(),
        runtime: rules(&["ok.example.com", "*"]),
    };
    let bad = CapBody::Network {
        install: rules(&["pkg.example.com"]),
        runtime: Rules::default(),
    };
    let p = plan(vec![
        with(kit("a", Kind::Mixin), "network-policy@1", false, ok),
        with(kit("b", Kind::Mixin), "network-policy@1", false, bad),
    ]);
    let mut policy = Policy::default();
    policy
        .add_rule(
            Some("sb"),
            crate::policy::Decision::Allow,
            "mine.example.com",
            "added",
            None,
            None,
        )
        .unwrap();
    let before = policy.clone();
    assert!(run(&p, &mut request(), &mut policy).is_err());
    assert_eq!(policy, before);
}

#[test]
fn two_kits_binding_one_variable_must_inject_it_alike() {
    let c = |domain: &str, header: Option<&str>| {
        cred("github", Some("GH_TOKEN"), vec![inject(domain, header)])
    };
    let p = plan(vec![
        with(
            kit("a", Kind::Mixin),
            "credential@1",
            false,
            c("github.com", Some("authorization")),
        ),
        with(
            kit("b", Kind::Mixin),
            "credential@1",
            false,
            c("api.github.com", Some("authorization")),
        ),
    ]);
    let mut req = request();
    run_with(&p, &mut req, &mut Policy::default(), &secrets(&["github"])).unwrap();
    assert_eq!(
        credential_args(&req),
        ["gh_token=GH_TOKEN@github.com,api.github.com:set-header=authorization"]
    );

    let mut formatted = inject("api.github.com", Some("authorization"));
    formatted.format = Some("Bearer %s".into());
    let p = plan(vec![
        with(
            kit("a", Kind::Mixin),
            "credential@1",
            false,
            c("github.com", Some("authorization")),
        ),
        with(
            kit("b", Kind::Mixin),
            "credential@1",
            false,
            cred("github", Some("GH_TOKEN"), vec![formatted]),
        ),
    ]);
    let e = run_with(
        &p,
        &mut request(),
        &mut Policy::default(),
        &secrets(&["github"]),
    )
    .unwrap_err();
    assert!(format!("{e:#}").contains("injected differently"), "{e:#}");
    let p = plan(vec![
        with(
            kit("a", Kind::Mixin),
            "credential@1",
            false,
            c("github.com", None),
        ),
        with(
            kit("b", Kind::Mixin),
            "credential@1",
            false,
            c("api.github.com", Some("x-token")),
        ),
    ]);
    assert!(
        run_with(
            &p,
            &mut request(),
            &mut Policy::default(),
            &secrets(&["github"])
        )
        .is_err()
    );
}

#[test]
fn an_unpinned_registry_kit_and_a_bad_agent_file_fail() {
    let mut m = kit("m", Kind::Mixin);
    m.digest = None;
    let e = run(&plan(vec![m]), &mut request(), &mut Policy::default()).unwrap_err();
    assert!(format!("{e:#}").contains("no digest"), "{e:#}");

    // The workload's own agent file must be an absolute directory and a plain file name.
    for (dir, name, err) in [
        (
            Some("rel/dir"),
            None,
            "kit wl: agent-context directory 'rel/dir'",
        ),
        (
            None,
            Some("a/b.md"),
            "kit wl: agent-context filename 'a/b.md'",
        ),
        (None, Some(".."), "kit wl: agent-context filename '..'"),
        (
            Some("/home/../etc"),
            None,
            "kit wl: agent-context directory '/home/../etc'",
        ),
    ] {
        let w = with(
            workload(),
            "agent-context@1",
            false,
            context(dir, name, "x"),
        );
        let p = resolve(w, vec![], &ArgValues::default()).unwrap();
        let e = run(&p, &mut request(), &mut Policy::default()).unwrap_err();
        assert!(format!("{e:#}").contains(err), "{e:#}");
    }
}

fn context(directory: Option<&str>, filename: Option<&str>, content: &str) -> CapBody {
    CapBody::AgentContext(AgentContextReq {
        filename: filename.map(String::from),
        directory: directory.map(String::from),
        content: content.into(),
        content_file: None,
    })
}

/// A mixin `name` with one `agent-context@2` `content` and no agent file of its own.
fn context_mixin(name: &str, source: Source, content: &str) -> Kit {
    context_mixin_at(2, name, source, content)
}

/// `context_mixin` declaring `agent-context@<version>`.
fn context_mixin_at(version: u8, name: &str, source: Source, content: &str) -> Kit {
    let mut m = kit(name, Kind::Mixin);
    m.source = source;
    with(
        m,
        &format!("agent-context@{version}"),
        false,
        context(None, None, content),
    )
}

fn in_workspace(path: &str) -> CreateRequest {
    CreateRequest {
        workspaces: vec![crate::workspace::Workspace {
            path: path.into(),
            read_only: false,
        }],
        ..request()
    }
}

/// A built-in agent's kit whose `agent-context` names `file`, sbx's default directory. Like
/// sbx's kits, it offers the profile under both versions.
fn agent_kit_plan(agent: &str, file: &str, mixins: Vec<Kit>) -> Plan {
    let mut w = Kit::agent_test(agent);
    for version in [1, 2] {
        w = with(
            w,
            &format!("agent-context@{version}"),
            true,
            context(None, Some(file), ""),
        );
    }
    resolve(w, mixins, &ArgValues::default()).unwrap()
}

/// `agent-context@2`: the kits' text in the agent file's kits section, joined with two newlines.
fn inline_layout(agent_file: &str, kits: &[(&str, &str)]) -> Vec<String> {
    let bodies: Vec<&str> = kits.iter().map(|(_, body)| *body).collect();
    vec![guest::inline_context_script(
        agent_file,
        &bodies.join("\n\n"),
    )]
}

/// `agent-context@1`: each kit's inline context in `<parent>/kits-agent-context/<kit>.md`, and
/// one index block in the agent file, the workload kit's like any other's.
fn mixin_layout(agent_file: &str, kits: &[(&str, &str)]) -> Vec<String> {
    let dir = agent_file.rsplit_once('/').unwrap().0;
    let mut out = Vec::new();
    let mut entries = Vec::new();
    for (kit, body) in kits {
        let path = format!("{dir}/kits-agent-context/{kit}.md");
        out.push(guest::kit_context_script(&path, &[body]));
        entries.push((kit.to_string(), path));
    }
    out.push(guest::kits_index_script(agent_file, &entries));
    out
}

#[test]
fn an_agent_file_sits_in_the_workspace_parent() {
    for (agent, file) in [
        ("claude", "CLAUDE.md"),
        ("codex", "AGENTS.md"),
        ("shell", "AGENTS.md"),
    ] {
        // v2 and v3 mixins get the same layout.
        for v2 in [true, false] {
            let mixin = |name: &str, body: &str| Kit {
                v2,
                ..context_mixin(name, Source::Local(format!("/k/{name}").into()), body)
            };
            let p = agent_kit_plan(
                agent,
                file,
                vec![mixin("m1", "use m1"), mixin("m2", "use m2")],
            );
            let mut req = in_workspace("/w/proj");
            let (steps, _) = run(&p, &mut req, &mut Policy::default()).unwrap();
            assert_eq!(
                steps.context,
                inline_layout(&format!("/w/{file}"), &[("m1", "use m1"), ("m2", "use m2")]),
                "{agent}"
            );
            assert_eq!(req.rec.agent_files, [format!("/w/{file}")]);
            assert_eq!(create::spec(&req).labels["sbx.agent-context"], "2");
        }
    }
}

#[test]
fn a_mountless_sandbox_uses_the_parent_of_its_workdir() {
    let p = agent_kit_plan(
        "claude",
        "CLAUDE.md",
        vec![context_mixin("m", Source::Local("/k/m".into()), "b")],
    );
    let (steps, _) = run(&p, &mut request(), &mut Policy::default()).unwrap();
    assert_eq!(
        steps.context,
        inline_layout("/home/agent/CLAUDE.md", &[("m", "b")])
    );
}

#[test]
fn a_workload_appends_its_own_context_and_records_its_agent_file() {
    let w = with(
        workload(),
        "agent-context@1",
        false,
        context(None, Some("AGENTS.md"), "wl body"),
    );
    let mixin = context_mixin_at(1, "m", Source::Local("/k/m".into()), "use m");
    let p = resolve(w, vec![mixin], &ArgValues::default()).unwrap();
    let mut req = in_workspace("/w/proj");
    let (steps, _) = run(&p, &mut req, &mut Policy::default()).unwrap();
    // SPEC agent-context@1: the workload's body is indexed like any kit's.
    let want = mixin_layout("/w/AGENTS.md", &[("wl", "wl body"), ("m", "use m")]);
    assert_eq!(steps.context, want);
    assert_eq!(req.rec.agent_files, ["/w/AGENTS.md"]);
    let labels = create::spec(&req).labels;
    assert_eq!(labels["sbx.agent-file"], "/w/AGENTS.md");
    assert_eq!(labels["sbx.agent-context"], "1");

    // A directory of its own, and the default file name.
    let w = with(
        workload(),
        "agent-context@1",
        false,
        context(Some("/ctx/"), None, "b"),
    );
    let p = resolve(w, vec![], &ArgValues::default()).unwrap();
    let mut req = in_workspace("/w/proj");
    let (steps, _) = run(&p, &mut req, &mut Policy::default()).unwrap();
    assert_eq!(
        steps.context,
        mixin_layout("/ctx/AGENTS.md", &[("wl", "b")])
    );
}

#[test]
fn mixin_context_is_dropped_when_the_workload_declares_no_agent_file() {
    let p = plan(vec![context_mixin("m", Source::Local("/k/m".into()), "b")]);
    let mut req = in_workspace("/w/proj");
    let (steps, _) = run(&p, &mut req, &mut Policy::default()).unwrap();
    assert!(steps.context.is_empty(), "{:?}", steps.context);
    assert!(req.rec.agent_files.is_empty());
    let labels = create::spec(&req).labels;
    assert!(!labels.contains_key("sbx.agent-file"));
    assert!(!labels.contains_key("sbx.agent-context"), "nothing written");
}

/// A workload offering `text` under the given `(version, optional)` requests.
fn context_workload(offers: &[(u8, bool)], text: &str) -> Kit {
    offers.iter().fold(workload(), |w, (version, optional)| {
        with(
            w,
            &format!("agent-context@{version}"),
            *optional,
            context(None, Some("AGENTS.md"), text),
        )
    })
}

#[test]
fn version_2_context_goes_inline_the_workloads_own_too() {
    // SPEC agent-context@2: the combined text is in the profile itself, with no per-kit index.
    let p = resolve(
        context_workload(&[(1, true), (2, true)], "wl body"),
        vec![
            context_mixin("m1", Source::Local("/k/m1".into()), "use m1"),
            context_mixin("m2", Source::Local("/k/m2".into()), ""),
        ],
        &ArgValues::default(),
    )
    .unwrap();
    let mut req = in_workspace("/w/proj");
    let (steps, _) = run(&p, &mut req, &mut Policy::default()).unwrap();
    assert_eq!(
        steps.context,
        inline_layout("/w/AGENTS.md", &[("wl", "wl body"), ("m1", "use m1")])
    );
    assert_eq!(req.rec.agent_context, Some(2));
}

/// An agent mixin: agent context `content` with an agent file of its own, `dir/file`.
fn agent_mixin(version: u8, name: &str, dir: &str, file: &str, content: &str) -> Kit {
    with(
        kit(name, Kind::Mixin),
        &format!("agent-context@{version}"),
        false,
        context(Some(dir), Some(file), content),
    )
}

#[test]
fn every_explicit_agent_file_gets_every_kits_context() {
    // SPEC agent-context@2/profile-precedence, /materialized: explicit files beat the
    // workload's legacy one, and each gets the combined text, the other agent's included.
    let kits = [
        ("wl", "wl body"),
        ("claude", "use claude"),
        ("codex", "use codex"),
        ("tool", "use tool"),
    ];
    let mixins = vec![
        agent_mixin(
            2,
            "claude",
            "/home/agent/.claude",
            "CLAUDE.md",
            "use claude",
        ),
        agent_mixin(2, "codex", "/home/agent/.codex/", "AGENTS.md", "use codex"),
        // The same destination again is one file.
        agent_mixin(2, "tool", "/home/agent/.claude", "CLAUDE.md", "use tool"),
    ];
    let w = context_workload(&[(2, false)], "wl body");
    let p = resolve(w, mixins, &ArgValues::default()).unwrap();
    let mut req = in_workspace("/w/proj");
    let (steps, _) = run(&p, &mut req, &mut Policy::default()).unwrap();
    let files = [
        "/home/agent/.claude/CLAUDE.md",
        "/home/agent/.codex/AGENTS.md",
    ];
    assert_eq!(req.rec.agent_files, files);
    let want: Vec<String> = files.iter().flat_map(|f| inline_layout(f, &kits)).collect();
    assert_eq!(steps.context, want);
    assert_eq!(
        create::spec(&req).labels["sbx.agent-file"],
        "/home/agent/.claude/CLAUDE.md,/home/agent/.codex/AGENTS.md"
    );

    // SPEC agent-context@1/every-explicit-profile: the same under @1, each file with its index.
    let mixin = agent_mixin(1, "codex", "/home/agent/.codex", "AGENTS.md", "use codex");
    let w = with(
        workload(),
        "agent-context@1",
        false,
        context(Some("/home/agent/.wl"), None, "wl body"),
    );
    let p = resolve(w, vec![mixin], &ArgValues::default()).unwrap();
    let (steps, _) = run(&p, &mut in_workspace("/w/proj"), &mut Policy::default()).unwrap();
    let mut want = Vec::new();
    for file in ["/home/agent/.wl/AGENTS.md", "/home/agent/.codex/AGENTS.md"] {
        want.extend(mixin_layout(
            file,
            &[("wl", "wl body"), ("codex", "use codex")],
        ));
    }
    assert_eq!(steps.context, want);

    // A mixin's file is checked like the workload's; a comma would split the label.
    for (dir, err) in [
        (
            "rel",
            "kit m: agent-context directory 'rel' must be an absolute path",
        ),
        (
            "/a,b",
            "kit m: agent-context file '/a,b/X.md' must not contain ','",
        ),
    ] {
        let p = plan(vec![agent_mixin(2, "m", dir, "X.md", "b")]);
        let e = run(&p, &mut request(), &mut Policy::default()).unwrap_err();
        assert_eq!(format!("{e:#}"), err);
    }
}

#[test]
fn a_mounted_agent_file_is_skipped_and_the_others_written() {
    let mixins = vec![
        agent_mixin(2, "a", "/w/proj/.a", "A.md", "use a"),
        agent_mixin(2, "b", "/home/agent/.b", "B.md", "use b"),
    ];
    let (steps, _) = run(
        &plan(mixins),
        &mut in_workspace("/w/proj"),
        &mut Policy::default(),
    )
    .unwrap();
    assert_eq!(
        steps.context,
        inline_layout("/home/agent/.b/B.md", &[("a", "use a"), ("b", "use b")])
    );
}

#[test]
fn a_staged_context_file_is_listed_where_the_image_has_it() {
    // As docker.io/sbx/amp declares it: a required `@1` `contentFile` and a file name.
    // SPEC agent-context@1: the index points at the staged path; the body isn't copied.
    let staged = "/usr/share/sandbox/kit/amp/amp-context.md";
    let w = with(
        workload(),
        "agent-context@1",
        false,
        CapBody::AgentContext(AgentContextReq {
            filename: Some("AGENTS.md".into()),
            directory: None,
            content: String::new(),
            content_file: Some(staged.into()),
        }),
    );
    // A mixin offering both versions follows the workload's `@1`.
    let mut m = context_mixin_at(1, "m", Source::Local("/k/m".into()), "use m");
    m.caps[0].optional = true;
    let m = with(m, "agent-context@2", true, context(None, None, "use m"));
    let p = resolve(w, vec![m], &ArgValues::default()).unwrap();
    let mut req = in_workspace("/w/proj");
    let (steps, _) = run(&p, &mut req, &mut Policy::default()).unwrap();
    let inline = "/w/kits-agent-context/m.md";
    assert_eq!(
        steps.context,
        [
            guest::kit_context_script(inline, &["use m"]),
            guest::kits_index_script(
                "/w/AGENTS.md",
                &[("wl".into(), staged.into()), ("m".into(), inline.into())]
            ),
        ]
    );
    assert_eq!(req.rec.agent_context, Some(1));
}

#[test]
fn a_sandbox_uses_one_context_version_for_all_its_kits() {
    let m = |version| context_mixin_at(version, "m", Source::Local("/k/m".into()), "use m");
    let both = [(1, true), (2, true)];
    let chosen = |w: Kit, mixin: Kit, pin: Option<u8>| {
        let p = resolve(w, vec![mixin], &ArgValues::default()).unwrap();
        let mut req = in_workspace("/w/proj");
        req.rec.agent_context = pin;
        run(&p, &mut req, &mut Policy::default()).map(|(steps, _)| (req.rec.agent_context, steps))
    };
    // `@2`, unless a kit requires `@1`: a kit offering both then follows it.
    let (version, steps) = chosen(context_workload(&both, "wl"), m(1), None).unwrap();
    assert_eq!(version, Some(1));
    let want = mixin_layout("/w/AGENTS.md", &[("wl", "wl"), ("m", "use m")]);
    assert_eq!(steps.context, want, "once, not once per version");
    let (version, _) = chosen(context_workload(&both, "wl"), m(2), None).unwrap();
    assert_eq!(version, Some(2));
    // A kit that only offers `@1`, as optional, is skipped rather than deciding for the others.
    let mut offered = m(1);
    offered.caps[0].optional = true;
    let (version, steps) = chosen(context_workload(&both, "wl"), offered, None).unwrap();
    assert_eq!(version, Some(2));
    assert_eq!(
        steps.context,
        inline_layout("/w/AGENTS.md", &[("wl", "wl")])
    );

    // SPEC agent-context@2: selected @1 and @2 requests are refused, not mixed.
    let e = chosen(context_workload(&[(1, false)], "wl"), m(2), None).unwrap_err();
    assert_eq!(
        format!("{e:#}"),
        "kit wl needs agent-context@1 and kit m needs agent-context@2, and a sandbox uses one \
         version; use kits that offer the same version (a kit can offer both as optional)"
    );
    // An optional request of the other version is skipped: here the workload's file with it.
    let (version, steps) = chosen(context_workload(&[(1, true)], "wl"), m(2), None).unwrap();
    assert_eq!(version, None, "nothing written, nothing settled");
    assert!(steps.context.is_empty(), "{:?}", steps.context);

    // `kit add`: the sandbox's version stays.
    let pinned = |mixin: Kit, pin| {
        let p = resolve(workload(), vec![mixin], &ArgValues::default()).unwrap();
        let mut req = in_workspace("/w/proj");
        req.rec.agent_files = vec!["/w/AGENTS.md".into()];
        req.rec.agent_context = Some(pin);
        run(&p, &mut req, &mut Policy::default()).map(|(steps, _)| steps.context)
    };
    assert_eq!(
        pinned(m(1), 1).unwrap(),
        mixin_layout("/w/AGENTS.md", &[("m", "use m")])
    );
    let e = pinned(m(2), 1).unwrap_err();
    assert_eq!(
        format!("{e:#}"),
        "kit m: needs agent-context@2, but this sandbox's kits use agent-context@1, and a \
         sandbox uses one version; recreate it with the kit"
    );
    let mut optional = m(2);
    optional.caps[0].optional = true;
    assert!(pinned(optional, 1).unwrap().is_empty(), "skipped");
}

#[test]
fn a_recorded_agent_file_wins() {
    // `kit add` passes the sandbox's `sbx.agent-file`: its workload isn't reloaded.
    let p = plan(vec![context_mixin("m", Source::Local("/k/m".into()), "b")]);
    let mut req = in_workspace("/w/proj");
    req.rec.agent_files = vec!["/x/CLAUDE.md".into()];
    let (steps, _) = run(&p, &mut req, &mut Policy::default()).unwrap();
    assert_eq!(steps.context, inline_layout("/x/CLAUDE.md", &[("m", "b")]));
}

#[test]
fn context_is_never_written_into_a_mounted_workspace() {
    let p = agent_kit_plan(
        "claude",
        "CLAUDE.md",
        vec![context_mixin("m", Source::Local("/k/m".into()), "b")],
    );
    let mut req = in_workspace("/w/proj");
    req.workspaces.push(crate::workspace::Workspace {
        path: "/w".into(),
        read_only: true,
    });
    let (steps, _) = run(&p, &mut req, &mut Policy::default()).unwrap();
    assert!(steps.context.is_empty(), "{:?}", steps.context);
}

#[test]
fn the_index_directory_is_guarded_like_the_agent_file() {
    // The agent file is the guest's own, but `kits-agent-context` sits in a mounted dir.
    let p = plan(vec![context_mixin_at(
        1,
        "m",
        Source::Local("/k/m".into()),
        "b",
    )]);
    let mut req = in_workspace("/x/kits-agent-context");
    req.rec.agent_files = vec!["/x/CLAUDE.md".into()];
    let (steps, _) = run(&p, &mut req, &mut Policy::default()).unwrap();
    assert!(steps.context.is_empty(), "{:?}", steps.context);
}

#[test]
fn a_kit_variable_that_refers_to_itself_gets_the_images_value() {
    // As sbx gives it: the measured repro of a kit adding to PATH.
    let d = tempfile::tempdir().unwrap();
    let layout = d.path().join("layout");
    crate::kits::registry::fixtures::oci_layout(
        &layout,
        Some(r#"{"schemaVersion":"3","kind":"workload","name":"wl"}"#),
        &[],
        r#"{"config":{"Env":["PATH=/usr/local/bin:/usr/bin","HOME=/home/agent"]}}"#,
    );
    let mut w = workload();
    w.content = Content::Oci(layout);
    let arg = |default: &str, env: &str| crate::kits::model::ArgDef {
        default: Some(default.into()),
        env: Some(env.into()),
        ..Default::default()
    };
    let mut m = kit("pathtest", Kind::Mixin);
    m.args
        .insert("PATH".into(), arg("/opt/pathtest/bin:$PATH", "PATH"));
    m.args
        .insert("BRACED".into(), arg("/opt/b:${PATH}", "BRACED"));
    let p = resolve(w, vec![m], &ArgValues::default()).unwrap();
    let mut req = request();
    let store = crate::secrets::store::MemoryStore::default();
    let cache = d.path().join("cache");
    let s = secrets(&[]);
    apply(
        &p,
        &mut req,
        &mut Policy::default(),
        &s,
        &store,
        &cache,
        &no_git,
    )
    .unwrap();
    let value = |n: &str| {
        req.env
            .iter()
            .find(|(k, _)| k == n)
            .map(|(_, v)| v.as_str())
    };
    assert_eq!(
        value("PATH"),
        Some("/opt/pathtest/bin:/usr/local/bin:/usr/bin")
    );
    // Only a variable's reference to itself is expanded.
    assert_eq!(value("BRACED"), Some("/opt/b:${PATH}"));
}

#[test]
fn kit_resources_fill_only_what_the_user_left_unset() {
    let mut m = Merged::default();
    m.cpus = Some("2.5".into());
    m.memory = Some("1g".into());
    let mut req = request();
    req.cpus_set = true;
    req.cpus = 1;
    apply_resources(&mut req, &m).unwrap();
    assert_eq!(req.cpus, 1);
    assert_eq!(req.memory_mib, 1024);
    req.cpus_set = false;
    apply_resources(&mut req, &m).unwrap();
    assert_eq!(req.cpus, 3);
    let mut bad = Merged::default();
    bad.cpus = Some("lots".into());
    let e = apply_resources(&mut request(), &bad).unwrap_err();
    assert!(format!("{e:#}").starts_with("kit resources: invalid cpus 'lots'"));
}

#[test]
fn volumes_split_into_tmpfs_and_disk() {
    let vol = |path: &str, tmpfs| crate::kits::resolve::Volume {
        path: path.into(),
        tmpfs,
        mode: tmpfs.then(|| "1777".into()),
    };
    let mut req = request();
    let tmpfs = add_volumes(&mut req, &[vol("/a", true), vol("/b", false)]);
    assert_eq!(req.tmpfs, ["/a"]);
    assert_eq!(req.volumes, ["/b"]);
    assert_eq!(tmpfs, [("/a".to_string(), Some("1777".to_string()))]);
}

/// `sbx.docker` follows the merged `dockerd@1`; a workload or mixin that only provides `docker`,
/// or is the shipped kit's namesake without one, has no engine.
#[test]
fn docker_follows_the_merged_dockerd() {
    let dockerd = |auto_start| {
        with(
            kit("dind", Kind::Mixin),
            "dockerd@1",
            false,
            CapBody::Dockerd { auto_start },
        )
    };
    let docker = |mixins: Vec<Kit>| {
        let mut req = request();
        run(&plan(mixins), &mut req, &mut Policy::default()).unwrap();
        req.engine
    };
    assert_eq!(docker(vec![dockerd(true)]), Engine::Auto);
    assert_eq!(docker(vec![dockerd(false)]), Engine::Manual);
    assert_eq!(docker(vec![]), Engine::Off);

    let mut w = workload();
    w.provides = vec!["docker@29.10.0".into()];
    let mut req = request();
    run(
        &resolve(w, vec![], &ArgValues::default()).unwrap(),
        &mut req,
        &mut Policy::default(),
    )
    .unwrap();
    assert_eq!(req.engine, Engine::Off);
    let mut dind = kit("dind", Kind::Mixin);
    dind.provides = vec!["docker".into()];
    assert_eq!(docker(vec![dind]), Engine::Off);
    // A kit named like the shipped one has no engine without `dockerd@1` either.
    let mut builtin = kit("docker", Kind::Mixin);
    builtin.source = Source::Builtin("docker");
    assert_eq!(docker(vec![builtin]), Engine::Off);
}

/// An `autoStart` reference is read once its arg is pinned (SPEC-v3 §6): `false` is a manual
/// engine, `true` an automatic one, and with no value the merge refuses.
#[test]
fn an_auto_start_reference_is_read_at_merge() {
    let kit = || {
        crate::kits::v3::parse(
            "schemaVersion: \"3\"\nkind: mixin\nargs:\n  auto: {}\ncapabilities:\n  \
             - type: com.docker.sandbox/dockerd@1\n    config: {autoStart: \"${{ kit.args.auto }}\"}\n",
            Source::Local("/k/dind".into()),
        )
        .unwrap()
    };
    let engine = |value: &str| {
        let args = ArgValues::parse(&[], &[format!("auto={value}")]).unwrap();
        let mut req = request();
        let p = resolve(workload(), vec![kit()], &args).unwrap();
        run(&p, &mut req, &mut Policy::default()).unwrap();
        req.engine
    };
    assert_eq!(engine("false"), Engine::Manual);
    assert_eq!(engine("true"), Engine::Auto);
    let e = resolve(workload(), vec![kit()], &ArgValues::default()).unwrap_err();
    assert!(
        format!("{e:#}").contains("\"auto\" has no resolved value"),
        "{e:#}"
    );
}

/// The engine's store and elevation are set at create, so `kit add` can't add it live.
#[test]
fn adding_dockerd_needs_a_recreate() {
    let k = with(
        kit("dind", Kind::Mixin),
        "dockerd@1",
        false,
        CapBody::Dockerd { auto_start: true },
    );
    assert_eq!(
        needs_recreate(&k, &BTreeMap::new()).unwrap(),
        ["Docker engine"]
    );
}

/// With no kit offering `agent-context@2`, the sandbox uses `@1` rather than dropping every
/// optional `@1` request and writing no agent file (agent-context@2/mixed-versions only forbids
/// both versions together).
#[test]
fn optional_version_1_context_is_kept_when_no_kit_offers_version_2() {
    let p = resolve(
        context_workload(&[(1, true)], "wl body"),
        vec![],
        &ArgValues::default(),
    )
    .unwrap();
    let mut req = in_workspace("/w/proj");
    let (steps, _) = run(&p, &mut req, &mut Policy::default()).unwrap();
    assert_eq!(req.rec.agent_context, Some(1));
    assert!(!steps.context.is_empty(), "the agent file is written");
}

/// tck: lifecycle@1/default-users: a v3 startup hook without `user:` runs as the agent user (the
/// session user: the workload image's user, else `agent`), not root. One that names a user keeps it.
#[test]
fn a_startup_hook_without_a_user_runs_as_the_session_user() {
    let lifecycle = |user: Option<&str>| {
        with(
            kit("k", Kind::Mixin),
            "lifecycle@1",
            false,
            CapBody::Lifecycle(Lifecycle {
                install: vec![],
                startup: vec![Hook {
                    command: HookCmd::Shell("serve".into()),
                    user: user.map(String::from),
                    env: vec![],
                    background: false,
                    clean_env: false,
                }],
                files: vec![],
                interactive: false,
            }),
        )
    };
    let script = |workload: Kit, user: Option<&str>| {
        let p = resolve(workload, vec![lifecycle(user)], &ArgValues::default()).unwrap();
        let (steps, _) = run(&p, &mut request(), &mut Policy::default()).unwrap();
        steps.startup_d[0].1.clone()
    };
    let agent = script(workload(), None);
    assert!(agent.contains("runuser -u 'agent'"), "{agent}");
    let mut node = workload();
    node.config = Some(crate::kits::model::ImageConfig {
        user: "node".into(),
        ..Default::default()
    });
    let as_node = script(node, None);
    assert!(as_node.contains("runuser -u 'node'"), "{as_node}");
    let root = script(workload(), Some("0"));
    assert!(!root.contains("runuser"), "a named user is kept: {root}");
}
