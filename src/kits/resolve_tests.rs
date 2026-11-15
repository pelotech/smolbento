
use super::*;
use crate::kits::model::{ArgDef, Cap, Lifecycle, NetRule, OAuthReq, Source, SshPhase};
use crate::ssh_agent::PhaseGrant;

fn base(name: &str, kind: Kind) -> Kit {
    Kit::new(name, kind, Source::Registry(name.into()))
}
fn mixin(name: &str) -> Kit {
    base(name, Kind::Mixin)
}
fn workload(name: &str) -> Kit {
    base(name, Kind::Workload)
}

trait KitExt {
    fn requires(self, r: &[&str]) -> Self;
    fn provides(self, p: &[&str]) -> Self;
    fn cap(self, ty: &str, optional: bool, body: CapBody) -> Self;
}
impl KitExt for Kit {
    fn requires(mut self, r: &[&str]) -> Self {
        self.requires = r.iter().map(|s| s.to_string()).collect();
        self
    }
    fn provides(mut self, p: &[&str]) -> Self {
        self.provides = p.iter().map(|s| s.to_string()).collect();
        self
    }
    fn cap(mut self, ty: &str, optional: bool, body: CapBody) -> Self {
        self.caps.push(Cap {
            ty: ty.into(),
            optional,
            body,
        });
        self
    }
}

/// Every kit's runtime network rules, in kit order.
fn runtime(p: &Plan) -> Rules {
    let mut all = Rules::default();
    for k in &p.merged.network {
        all.allow.extend(k.runtime.allow.iter().cloned());
        all.deny.extend(k.runtime.deny.iter().cloned());
    }
    all
}

/// A kit the user named by `reference`.
fn typed(mut k: Kit, reference: &str) -> Kit {
    k.reference = Some(reference.into());
    k
}
/// One problem in sbx's coherence block.
fn incoherent(problem: &str) -> String {
    format!("resolve: the kit set is not coherent:\n  - {problem}")
}

fn run(w: Kit, m: Vec<Kit>) -> Result<Plan> {
    resolve(w, m, &ArgValues::default())
}
fn names(p: &Plan) -> Vec<&str> {
    p.mixins.iter().map(|k| k.name.as_str()).collect()
}
fn rule(host: &str) -> NetRule {
    NetRule::host(host)
}
fn vol(path: &str, tmpfs: bool) -> CapBody {
    CapBody::Volume {
        path: path.into(),
        tmpfs,
        mode: None,
    }
}
fn shell_hook(s: &str) -> Hook {
    Hook {
        command: HookCmd::Shell(s.into()),
        user: None,
        env: vec![],
        background: false,
        clean_env: true,
    }
}

#[test]
fn mixins_follow_requires_not_flag_order() {
    let a = mixin("a").requires(&["b"]);
    let b = mixin("b").provides(&["b"]);
    let p = run(workload("w"), vec![a, b]).unwrap();
    assert_eq!(names(&p), ["b", "a"]);
}

#[test]
fn independent_mixins_keep_given_order() {
    let p = run(workload("w"), vec![mixin("z"), mixin("a")]).unwrap();
    assert_eq!(names(&p), ["z", "a"]);
}

#[test]
fn a_mixin_may_require_what_the_workload_provides() {
    let w = workload("w").provides(&["node"]);
    let p = run(w, vec![mixin("a").requires(&["node"])]).unwrap();
    assert_eq!(names(&p), ["a"]);
}

#[test]
fn a_provide_naming_a_kit_arg_expands_before_ordering() {
    let mut c = mixin("c").provides(&["claude@${{ kit.args.version }}"]);
    c.args.insert(
        "version".into(),
        ArgDef {
            default: Some("2.1.0".into()),
            ..Default::default()
        },
    );
    let u = mixin("u").requires(&["claude >= 2.0"]);
    let p = run(workload("w"), vec![u.clone(), c.clone()]).unwrap();
    assert_eq!(names(&p), ["c", "u"]);
    assert_eq!(p.mixins[0].provides, ["claude@2.1.0"]);
    let v = ArgValues::parse(&[], &["version=1.9.0".into()]).unwrap();
    let e = resolve(workload("w"), vec![u, c.clone()], &v).unwrap_err();
    assert!(format!("{e:#}").contains("only offers"), "{e:#}");
    c.args.get_mut("version").unwrap().default = None;
    let e = run(workload("w"), vec![c]).unwrap_err();
    assert_eq!(
        format!("{e:#}"),
        "kit c: create-phase kit arg \"version\" has no resolved value"
    );
}

#[test]
fn duplicate_provides_fail_like_sbx_at_any_versions() {
    let a = typed(mixin("a").provides(&["x@1.0.0"]), "./chkdupa");
    let b = mixin("b").provides(&["com.docker.kit/x@2.0"]);
    let e = run(workload("w"), vec![a, b]).unwrap_err();
    assert_eq!(
        format!("{e:#}"),
        "resolve: the kit set is not coherent:\n  - capability \"com.docker.kit/x\" is \
             provided by more than one kit: ./chkdupa (1.0.0), b (2.0); one name has one owner, so \
             drop the redundant kit"
    );
    let a = mixin("a").provides(&["x"]);
    let b = mixin("b").provides(&["x@1"]);
    let e = run(workload("w"), vec![a, b]).unwrap_err();
    assert!(
        format!("{e:#}").contains(": a (unversioned), b (1);"),
        "{e:#}"
    );
}

#[test]
fn unmet_requires_fails_like_sbx() {
    let a = typed(mixin("a").requires(&["nothing >= 1.0.0"]), "./chkreq");
    let e = run(workload("w"), vec![a]).unwrap_err();
    assert_eq!(
        format!("{e:#}"),
        "resolve: the kit set is not coherent:\n  - ./chkreq requires \"nothing >= 1.0.0\" but \
             nothing in the set provides it; add a kit that provides com.docker.kit/nothing"
    );
}

#[test]
fn a_require_is_met_only_by_a_version_in_its_constraints() {
    let w = workload("w").provides(&["node@20.11.1"]);
    let ok = mixin("a").requires(&["node >= 20.0.0, < 21.0.0"]);
    assert_eq!(names(&run(w.clone(), vec![ok]).unwrap()), ["a"]);
    let qualified = mixin("a").requires(&["com.docker.kit/node = 20.11.1"]);
    assert_eq!(names(&run(w.clone(), vec![qualified]).unwrap()), ["a"]);

    let too_new = mixin("a").requires(&["node >= 21"]);
    let e = run(w, vec![too_new]).unwrap_err();
    assert_eq!(
        format!("{e:#}"),
        incoherent("a requires \"node >= 21\" but the set only offers node@20.11.1 (from w)")
    );
    // An unversioned provide satisfies only an unconstrained require.
    let w = workload("w").provides(&["node"]);
    assert!(run(w.clone(), vec![mixin("a").requires(&["node"])]).is_ok());
    let e = run(w, vec![mixin("a").requires(&["node > 0"])]).unwrap_err();
    assert_eq!(
        format!("{e:#}"),
        incoherent("a requires \"node > 0\" but the set only offers node (unversioned, from w)")
    );
    // Another namespace's name never matches the default one.
    let w = workload("w").provides(&["com.example/node@20"]);
    assert!(run(w, vec![mixin("a").requires(&["node"])]).is_err());
}

#[test]
fn a_kit_cannot_meet_its_own_require() {
    let a = mixin("a").provides(&["x@1"]).requires(&["x"]);
    let e = run(workload("w"), vec![a]).unwrap_err();
    assert_eq!(
        format!("{e:#}"),
        incoherent("a requires \"x\" but the set only offers x@1 (from a)")
    );
}

#[test]
fn every_problem_is_reported_and_bad_entries_name_their_kit() {
    let a = typed(mixin("a").requires(&["x", "Y"]), "./a");
    let e = run(workload("w"), vec![a]).unwrap_err();
    assert_eq!(
        format!("{e:#}"),
        "resolve: the kit set is not coherent:\n  - ./a requires \"x\" but nothing in the set \
             provides it; add a kit that provides com.docker.kit/x\n  - ./a: requires entry \"Y\": \
             invalid capability name \"Y\""
    );
}

#[test]
fn a_present_provider_must_meet_integrates_and_conflicts_must_be_absent() {
    let w = workload("w").provides(&["docker-engine@24.0.7"]);
    let mut a = mixin("a");
    a.integrates = vec!["docker-engine >= 25.0.0".into()];
    assert!(run(workload("bare"), vec![a.clone()]).is_ok());
    let e = run(w, vec![a]).unwrap_err();
    assert_eq!(
        format!("{e:#}"),
        incoherent(
            "a integrates with \"docker-engine >= 25.0.0\" but the set only offers \
                 docker-engine@24.0.7 (from w); upgrade the provider or drop it from the set"
        )
    );

    let w = workload("w").provides(&["podman@5"]);
    let mut a = mixin("a");
    a.conflicts = vec!["podman".into()];
    let e = run(w, vec![a]).unwrap_err();
    assert_eq!(
        format!("{e:#}"),
        incoherent("a conflicts with \"podman\", which w provides; the two cannot compose")
    );
}

#[test]
fn a_met_integrates_orders_like_requires() {
    let mut a = mixin("a");
    a.integrates = vec!["b >= 1".into()];
    let b = mixin("b").provides(&["b@1.2"]);
    assert_eq!(names(&run(workload("w"), vec![a, b]).unwrap()), ["b", "a"]);
}

#[test]
fn circular_requires_fail_like_sbx() {
    let a = typed(mixin("a").requires(&["b"]).provides(&["a@1"]), "./chkcyca");
    let b = typed(mixin("b").requires(&["a"]).provides(&["b@1"]), "./chkcycb");
    let e = run(workload("w"), vec![a, b]).unwrap_err();
    assert_eq!(
        format!("{e:#}"),
        "resolve: dependency cycle among ./chkcyca, ./chkcycb"
    );
}

#[test]
fn a_kit_listed_twice_fails_like_sbx() {
    let a = || typed(mixin("a"), "./chkallow");
    let e = run(workload("w"), vec![a(), a()]).unwrap_err();
    assert_eq!(format!("{e:#}"), "kit ./chkallow is listed more than once");
    // The same kit by another spelling is still listed twice; sbx names the later one.
    let e = run(workload("w"), vec![a(), typed(mixin("a"), "./chkallow/")]).unwrap_err();
    assert_eq!(format!("{e:#}"), "kit ./chkallow/ is listed more than once");
    let docker = || crate::kits::load::builtin("docker").unwrap().unwrap();
    let e = run(workload("w"), vec![docker(), docker()]).unwrap_err();
    assert_eq!(format!("{e:#}"), "kit docker is listed more than once");
}

#[test]
fn a_mixin_as_the_workload_and_two_kits_of_one_name_are_rejected() {
    let e = run(mixin("m"), vec![]).unwrap_err();
    assert_eq!(
        format!("{e:#}"),
        "resolve: the kit set is not coherent:\n  - no workload kit in the set; every \
             composition needs exactly one kind: workload base"
    );
    let mut other = mixin("a");
    other.source = Source::Registry("other/a".into());
    let e = run(workload("w"), vec![mixin("a"), other.clone()]).unwrap_err();
    assert_eq!(format!("{e:#}"), "two kits are named a");
    let e = run(workload("a"), vec![other]).unwrap_err();
    assert_eq!(format!("{e:#}"), "two kits are named a");
    let shipped = crate::kits::load::builtin("docker").unwrap().unwrap();
    let e = run(workload("w"), vec![mixin("docker"), shipped]).unwrap_err();
    assert_eq!(
        format!("{e:#}"),
        "two kits are named docker: yours and the shipped one a Docker-enabled image gets; \
             rename your kit, or have it provide docker (`provides: [docker@<version>]`) to \
             replace the shipped one"
    );
    // A built-in agent is a kit like any other: its name is taken.
    let e = run(Kit::agent_test("claude"), vec![mixin("claude")]).unwrap_err();
    assert_eq!(format!("{e:#}"), "two kits are named claude");
}

#[test]
fn a_second_workload_is_rejected() {
    let e = run(workload("w"), vec![workload("other")]).unwrap_err();
    assert_eq!(
        format!("{e:#}"),
        "two workloads: w and other; pass a workload kit as the agent argument"
    );
}

#[test]
fn a_required_unsupported_capability_fails_closed() {
    let k = mixin("m").cap(
        "com.docker.sandbox/usb-device@1",
        false,
        CapBody::Unsupported,
    );
    let e = run(workload("w"), vec![k]).unwrap_err();
    assert_eq!(
        format!("{e:#}"),
        "kit m: com.docker.sandbox/usb-device@1 is not supported by smolbento"
    );
}

#[test]
fn an_optional_unsupported_capability_is_skipped() {
    let k = mixin("m").cap(
        "com.docker.sandbox/usb-device@1",
        true,
        CapBody::Unsupported,
    );
    let p = run(workload("w"), vec![k]).unwrap();
    assert_eq!(p.skipped, ["m: com.docker.sandbox/usb-device@1"]);
}

const SSH: &str = "com.docker.sandbox/ssh-agent@1";

fn grant(sign: Option<&[&str]>, required: bool, kit: Option<&str>) -> Option<PhaseGrant> {
    Some(PhaseGrant::new(sign, required, kit))
}
fn preset() -> Kit {
    let mut w = workload("shell");
    w.source = Source::Agent("docker.io/sbx/shell:latest".into());
    w
}

#[test]
fn a_built_in_agent_gets_an_implicit_optional_runtime_grant() {
    let p = run(preset(), vec![]).unwrap();
    assert_eq!(
        p.merged.ssh_agent,
        AgentGrant {
            runtime: grant(None, false, None),
            install: None,
        }
    );
    // The same grant a create with no plan uses.
    assert_eq!(built_in_ssh_agent(), p.merged.ssh_agent);
    // A built-in agent's published kit gets it too; a kit merely named like one doesn't.
    let mut agent = workload("claude");
    agent.source = Source::Agent("docker.io/sbx/claude:latest".into());
    assert_eq!(
        run(agent, vec![]).unwrap().merged.ssh_agent,
        built_in_ssh_agent()
    );
    assert!(
        run(workload("claude"), vec![])
            .unwrap()
            .merged
            .ssh_agent
            .is_empty()
    );
    // A workload kit gets nothing unless it asks.
    assert!(
        run(workload("w"), vec![])
            .unwrap()
            .merged
            .ssh_agent
            .is_empty()
    );
}

#[test]
fn ssh_agent_grants_merge_per_phase() {
    use SshPhase::{Install, Runtime};
    // Bounded entries union their namespaces; required wins and names its kit.
    let a = mixin("a").cap(SSH, true, CapBody::ssh_agent(&[Runtime], &["git"], &[]));
    let b = mixin("b").cap(
        SSH,
        false,
        CapBody::ssh_agent(&[Install, Runtime], &["file", "git"], &[]),
    );
    let p = run(workload("w"), vec![a, b]).unwrap();
    assert_eq!(
        p.merged.ssh_agent,
        AgentGrant {
            install: grant(Some(&["file", "git"]), true, Some("b")),
            runtime: grant(Some(&["git", "file"]), true, Some("b")),
        }
    );

    // Unrestricted wins over bounded; optional entries name the first kit.
    let a = mixin("a").cap(SSH, true, CapBody::ssh_agent(&[Runtime], &["git"], &[]));
    let b = mixin("b").cap(SSH, true, CapBody::ssh_agent(&[Runtime], &[], &[]));
    let p = run(workload("w"), vec![a, b]).unwrap();
    assert_eq!(p.merged.ssh_agent.runtime, grant(None, false, Some("a")));
    assert_eq!(p.merged.ssh_agent.install, None);

    // A built-in agent's implicit grant is unrestricted; a kit's bounded entry joins it.
    let m = mixin("m").cap(SSH, false, CapBody::ssh_agent(&[Runtime], &["git"], &[]));
    let p = run(preset(), vec![m]).unwrap();
    assert_eq!(p.merged.ssh_agent.runtime, grant(None, true, Some("m")));
}

#[test]
fn authenticate_entries_union_like_sign_and_unrestricted_drops_them() {
    use SshPhase::{Install, Runtime};
    let a = mixin("a").cap(
        SSH,
        false,
        CapBody::ssh_agent(&[Install, Runtime], &["git"], &["git@github.com", "a.com"]),
    );
    let b = mixin("b").cap(
        SSH,
        true,
        CapBody::ssh_agent(&[Runtime], &[], &["a.com", "b.org"]),
    );
    let p = run(workload("w"), vec![a.clone(), b]).unwrap();
    assert_eq!(
        p.merged.ssh_agent,
        AgentGrant {
            install: Some(
                PhaseGrant::new(Some(&["git"]), true, Some("a"))
                    .authenticating(&["git@github.com", "a.com"])
            ),
            runtime: Some(
                PhaseGrant::new(Some(&["git"]), true, Some("a")).authenticating(&[
                    "git@github.com",
                    "a.com",
                    "b.org"
                ])
            ),
        }
    );
    assert!(p.skipped.is_empty());

    // An authenticate-only entry is bounded with no namespaces.
    let only = mixin("o").cap(SSH, true, CapBody::ssh_agent(&[Runtime], &[], &["a.com"]));
    let p = run(workload("w"), vec![only]).unwrap();
    assert_eq!(
        p.merged.ssh_agent.runtime,
        Some(PhaseGrant::new(Some(&[]), false, Some("o")).authenticating(&["a.com"]))
    );

    // Under an unrestricted grant for the phase, the limits don't matter.
    let p = run(preset(), vec![a]).unwrap();
    assert_eq!(p.merged.ssh_agent.runtime, grant(None, true, Some("a")));
}

fn cred(oauth: Option<OAuthReq>) -> CapBody {
    CapBody::Credential(CredReq {
        service: "svc".into(),
        install: false,
        runtime: true,
        env: None,
        inject: vec![],
        oauth,
    })
}
fn oauth(passthrough: bool) -> Option<OAuthReq> {
    Some(OAuthReq {
        passthrough,
        token_host: None,
        resource_hosts: vec![],
    })
}

#[test]
fn oauth_passthrough_hosts_join_the_kit_s_network_rules() {
    let ty = "com.docker.sandbox/credential@1";
    let body = cred(Some(OAuthReq {
        passthrough: true,
        token_host: Some("auth.x.com".into()),
        resource_hosts: vec!["api.x.com".into()],
    }));
    let p = run(workload("w"), vec![mixin("m").cap(ty, false, body)]).unwrap();
    let hosts = |l: &[NetRule]| l.iter().map(|n| n.host.clone()).collect::<Vec<_>>();
    assert_eq!(p.merged.network.len(), 1);
    assert_eq!(p.merged.network[0].kit, "m");
    assert_eq!(
        hosts(&p.merged.network[0].runtime.allow),
        ["auth.x.com", "api.x.com"]
    );
    // Not used during install: no install rules.
    assert!(p.merged.network[0].install.allow.is_empty());
}

#[test]
fn oauth_without_passthrough_is_kept() {
    let ty = "com.docker.sandbox/credential@1";
    let body = || {
        cred(Some(OAuthReq {
            passthrough: false,
            token_host: Some("auth.x.com".into()),
            resource_hosts: vec![],
        }))
    };
    // Required or optional, it binds its API key part; the login happens in the sandbox.
    for optional in [false, true] {
        let p = run(workload("w"), vec![mixin("m").cap(ty, optional, body())]).unwrap();
        assert_eq!(p.merged.credentials.len(), 1, "{optional}");
        assert!(p.skipped.is_empty(), "{:?}", p.skipped);
        let hosts: Vec<_> = p.merged.network[0]
            .runtime
            .allow
            .iter()
            .map(|n| n.host.clone())
            .collect();
        assert_eq!(hosts, ["auth.x.com"]);
    }
    // Passthrough still works as before.
    let ok = mixin("m").cap(ty, false, cred(oauth(true)));
    assert_eq!(
        run(workload("w"), vec![ok])
            .unwrap()
            .merged
            .credentials
            .len(),
        1
    );
}

#[test]
fn network_rules_union_and_deny_is_kept() {
    let n = |allow: &str, deny: &str| CapBody::Network {
        install: Rules::default(),
        runtime: Rules {
            allow: vec![rule(allow)],
            deny: vec![rule(deny)],
        },
    };
    let w = workload("w").cap("n@1", false, n("a.com", "bad.com"));
    let m = mixin("m").cap("n@1", false, n("b.com", "worse.com"));
    let p = run(w, vec![m]).unwrap();
    let hosts = |r: &[NetRule]| r.iter().map(|x| x.host.clone()).collect::<Vec<_>>();
    assert_eq!(hosts(&runtime(&p).allow), ["a.com", "b.com"]);
    assert_eq!(hosts(&runtime(&p).deny), ["bad.com", "worse.com"]);
    let per_kit: Vec<(&str, Vec<String>)> = p
        .merged
        .network
        .iter()
        .map(|k| (k.kit.as_str(), hosts(&k.runtime.allow)))
        .collect();
    assert_eq!(
        per_kit,
        [
            ("w", vec!["a.com".to_string()]),
            ("m", vec!["b.com".into()])
        ]
    );
}

#[test]
fn network_policy_2_method_and_path_rules_need_to_be_optional() {
    let n = |host: &str, methods: &[&str]| CapBody::Network {
        install: Rules::default(),
        runtime: Rules {
            allow: vec![NetRule {
                host: host.into(),
                methods: methods.iter().map(|s| s.to_string()).collect(),
                paths: vec![],
            }],
            deny: vec![],
        },
    };
    let ty = "com.docker.sandbox/network-policy@2";
    let req = mixin("m").cap(ty, false, n("a.com", &["GET"]));
    let e = run(workload("w"), vec![req]).unwrap_err();
    assert_eq!(
        format!("{e:#}"),
        "kit m: network-policy@2 method/path rules are not enforced by smolbento"
    );
    let opt = mixin("m").cap(ty, true, n("a.com", &["GET"]));
    let p = run(workload("w"), vec![opt]).unwrap();
    assert_eq!(p.skipped, ["m: network-policy@2 method/path (host-only)"]);
    assert!(runtime(&p).allow[0].methods.is_empty());
    // Host-only entries and @1 are unaffected.
    let plain = mixin("m").cap(ty, false, n("a.com", &[]));
    assert!(run(workload("w"), vec![plain]).unwrap().skipped.is_empty());
}

#[test]
fn host_only_downgrade_drops_qualified_denies_instead_of_widening_them() {
    let rule = |host: &str, methods: &[&str], paths: &[&str]| NetRule {
        host: host.into(),
        methods: methods.iter().map(|s| s.to_string()).collect(),
        paths: paths.iter().map(|s| s.to_string()).collect(),
    };
    let body = CapBody::Network {
        install: Rules::default(),
        runtime: Rules {
            allow: vec![rule("registry.npmjs.org", &["GET", "HEAD"], &[])],
            deny: vec![
                rule("registry.npmjs.org", &["POST", "PUT"], &[]),
                rule("github.com", &["POST"], &["/**/git-receive-pack"]),
                rule("evil.com", &[], &[]),
            ],
        },
    };
    let ty = "com.docker.sandbox/network-policy@2";
    let p = run(workload("w"), vec![mixin("m").cap(ty, true, body)]).unwrap();
    assert_eq!(
        p.skipped,
        ["m: network-policy@2 method/path (host-only; 2 qualified deny rules dropped)"]
    );
    let hosts = |l: &[NetRule]| l.iter().map(|n| n.host.clone()).collect::<Vec<_>>();
    // The allow survives, widened to its host; only the host-only deny is kept.
    assert_eq!(hosts(&runtime(&p).allow), ["registry.npmjs.org"]);
    assert_eq!(hosts(&runtime(&p).deny), ["evil.com"]);
    assert_eq!(hosts(&p.merged.network[0].runtime.deny), ["evil.com"]);
}

#[test]
fn conflicting_volume_configs_fail_and_identical_ones_merge() {
    let a = mixin("a").cap("v@1", false, vol("/data", false));
    let b = mixin("b").cap("v@1", false, vol("/data", true));
    assert!(run(workload("w"), vec![a.clone(), b]).is_err());
    let c = mixin("c").cap("v@1", false, vol("/data", false));
    let p = run(workload("w"), vec![a, c]).unwrap();
    assert_eq!(
        p.merged.volumes,
        [Volume {
            path: "/data".into(),
            tmpfs: false,
            mode: None
        }]
    );
}

fn host(path: &str, mode: Option<&str>) -> CapBody {
    CapBody::HostMount {
        path: path.into(),
        mode: mode.map(Into::into),
    }
}

#[test]
fn host_mounts_are_collected_in_kit_order_with_their_kit_s_identity() {
    const HM: &str = "com.docker.sandbox/host-mount@1";
    let mut a = mixin("a")
        .requires(&["b"])
        .cap(HM, false, host("/home/agent/.a", None));
    a.source = Source::LocalV3("/kits/a".into());
    let b = mixin("b")
        .provides(&["b@1.0.0"])
        .cap(HM, false, host("/home/agent/.b", Some("0700")));
    let w = workload("w").cap(HM, false, host("/w", None));
    let p = run(w, vec![a, b]).unwrap();
    let got: Vec<_> = p
        .merged
        .host_mounts
        .iter()
        .map(|m| (&*m.kit, &*m.identity, &*m.path, m.mode.as_deref()))
        .collect();
    assert_eq!(
        got,
        [
            ("w", "docker.io/library/w", "/w", None),
            ("b", "docker.io/library/b", "/home/agent/.b", Some("0700")),
            ("a", "/kits/a", "/home/agent/.a", None),
        ]
    );
}

#[test]
fn a_host_mount_path_has_one_owner() {
    const HM: &str = "com.docker.sandbox/host-mount@1";
    let msg = "kits a and b both declare storage at /data; a host mount has one owner";
    let cases = [
        // Two host mounts, even identical ones.
        (host("/data", None), host("/data", Some("0700"))),
        (host("/data", None), host("/data", None)),
        // A host mount and a volume, either order.
        (host("/data", None), vol("/data", false)),
        (vol("/data", false), host("/data", None)),
    ];
    for (first, second) in cases {
        let a = mixin("a").cap(HM, false, first);
        let b = mixin("b").cap(HM, false, second);
        let e = run(workload("w"), vec![a, b]).unwrap_err();
        assert_eq!(format!("{e:#}"), msg);
    }
}

fn skills_dir(path: &str, rw: bool) -> CapBody {
    CapBody::AgentSkills {
        path: path.into(),
        readwrite: rw,
    }
}
fn skill(source: &str, name: &str) -> CapBody {
    CapBody::AgentSkill {
        source: source.into(),
        name: name.into(),
    }
}

#[test]
fn skill_dirs_merge_to_the_widest_mode_and_one_kit_names_a_path_once() {
    const AS: &str = "com.docker.sandbox/agent-skills@1";
    let a = mixin("a").cap(AS, false, skills_dir("/s", false));
    let b = mixin("b").cap(AS, false, skills_dir("/s", true));
    let p = run(workload("w"), vec![a, b]).unwrap();
    assert_eq!(
        p.merged.skill_dirs,
        [SkillDir {
            path: "/s".into(),
            readwrite: true
        }]
    );
    let k =
        mixin("k")
            .cap(AS, false, skills_dir("/s", false))
            .cap(AS, false, skills_dir("/s", true));
    let e = run(workload("w"), vec![k]).unwrap_err();
    assert_eq!(format!("{e:#}"), "kit k: agent-skills@1 names /s twice");
}

#[test]
fn bundled_skills_merge_by_name_and_conflict_on_different_sources() {
    const AK: &str = "com.docker.sandbox/agent-skill@1";
    let k = mixin("k")
        .cap(AK, false, skill("/a/x", "x"))
        .cap(AK, false, skill("/b/y", "x"));
    let e = run(workload("w"), vec![k]).unwrap_err();
    assert_eq!(
        format!("{e:#}"),
        "kit k: two agent-skill@1 entries are named x"
    );

    let a = mixin("a").cap(AK, true, skill("/s/x", "x"));
    let b = mixin("b").cap(AK, false, skill("/s/x", "x"));
    let p = run(workload("w"), vec![a, b]).unwrap();
    assert_eq!(p.merged.bundled.len(), 1);
    assert_eq!(p.merged.bundled[0].name, "x");
    assert!(!p.merged.bundled[0].optional);

    let a = mixin("a").cap(AK, false, skill("/s/x", "x"));
    let b = mixin("b").cap(AK, false, skill("/t/x", "x"));
    let e = run(workload("w"), vec![a, b]).unwrap_err();
    assert_eq!(
        format!("{e:#}"),
        "kits a and b both bundle a skill named \"x\" from different paths"
    );
}

#[test]
fn resources_last_wins_and_flags_are_set() {
    let res = |c: Option<&str>, m: Option<&str>| CapBody::Resources {
        cpus: c.map(String::from),
        memory: m.map(String::from),
    };
    let w = workload("w").cap("r@1", false, res(Some("2"), Some("1g")));
    let m = mixin("m")
        .cap("r@1", false, res(Some("4"), None))
        .cap("g@1", false, CapBody::GitIdentity)
        .cap("l@1", false, CapBody::LongRunning)
        .cap("p@1", false, CapBody::Privileged);
    let p = run(w, vec![m]).unwrap();
    assert_eq!(p.merged.cpus.as_deref(), Some("4"));
    assert_eq!(p.merged.memory.as_deref(), Some("1g"));
    assert!(p.merged.git_identity && p.merged.long_running && p.merged.privileged);
}

#[test]
fn an_arg_with_env_is_exported_into_the_sandbox() {
    // As Docker's claude mixin does with `model` -> CLAUDE_MODEL.
    let arg = |env: Option<&str>, default: Option<&str>| ArgDef {
        env: env.map(String::from),
        default: default.map(String::from),
        ..Default::default()
    };
    let mut w = workload("w");
    w.env = vec![("CLAUDE_MODEL".into(), "from-env".into())];
    // Given on the command line: replaces the kit's own variable of that name.
    w.args
        .insert("model".into(), arg(Some("CLAUDE_MODEL"), Some("")));
    // A default counts as a value, an empty one included.
    w.args.insert("empty".into(), arg(Some("EMPTY"), Some("")));
    // Overridden by the later kit below.
    w.args
        .insert("region".into(), arg(Some("REGION"), Some("eu")));
    // No value, and no `env:`: neither is exported.
    w.args.insert("effort".into(), arg(Some("EFFORT"), None));
    w.args.insert("plain".into(), arg(None, Some("p")));
    let mut m = mixin("m");
    m.args
        .insert("region".into(), arg(Some("REGION"), Some("us")));
    let v = ArgValues::parse(&[], &["model=opus".into()]).unwrap();
    let p = resolve(w, vec![m], &v).unwrap();
    assert_eq!(
        p.merged.env,
        [
            ("CLAUDE_MODEL".into(), "opus".into()),
            ("EMPTY".into(), String::new()),
            ("REGION".into(), "us".into())
        ]
    );
}

#[test]
fn the_claude_mixin_exports_its_model_arg() {
    let text = std::fs::read_to_string(format!(
        "{}/tests/fixtures/kits/v3/claude-mixin.yaml",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    let mixin = crate::kits::v3::parse(
        &text,
        Source::LocalV3(std::path::PathBuf::from("/k/claude-mixin")),
    )
    .unwrap();
    let v = ArgValues::parse(&[], &["model=x".into()]).unwrap();
    let mut w = workload("w");
    // Whatever the mixin requires of its base.
    w.provides = mixin.requires.clone();
    let p = resolve(w, vec![mixin], &v).unwrap();
    assert!(
        p.merged
            .env
            .contains(&("CLAUDE_MODEL".to_string(), "x".to_string())),
        "{:?}",
        p.merged.env
    );
}

#[test]
fn env_merges_with_later_winning() {
    let mut w = workload("w");
    w.env = vec![("A".into(), "1".into()), ("B".into(), "1".into())];
    let mut m = mixin("m");
    m.env = vec![("B".into(), "2".into())];
    let p = run(w, vec![m]).unwrap();
    assert_eq!(
        p.merged.env,
        [("A".into(), "1".into()), ("B".into(), "2".into())]
    );
}

#[test]
fn hooks_files_and_contexts_expand_args_and_env() {
    let mut m = mixin("m");
    m.args.insert(
        "name".into(),
        ArgDef {
            default: Some("bob".into()),
            ..Default::default()
        },
    );
    m.args.insert("opt".into(), ArgDef::default());
    m.env = vec![("TOOL".into(), "x".into())];
    // `opt` is declared with no value but never used: not an error.
    let m = m
        .cap(
            "l@1",
            false,
            CapBody::Lifecycle(Lifecycle {
                install: vec![shell_hook("hi ${{ kit.args.name }}")],
                startup: vec![Hook {
                    command: HookCmd::Argv(vec!["echo".into(), "${{ kit.env.HOME }}".into()]),
                    ..shell_hook("")
                }],
                files: vec![FileReq {
                    path: "/f/${{ kit.args.name }}".into(),
                    content: "${{ kit.env.TOOL }}".into(),
                    mode: None,
                    overwrite: true,
                }],
            }),
        )
        .cap(
            "c@1",
            false,
            CapBody::AgentContext(AgentContextReq {
                filename: None,
                directory: None,
                content: "for ${{ kit.args.name }}".into(),
            }),
        );
    let v = ArgValues::parse(&[], &["name=alice".into()]).unwrap();
    let p = resolve(workload("w"), vec![m], &v).unwrap();
    assert_eq!(
        p.merged.install_hooks[0].1.command,
        HookCmd::Shell("hi alice".into())
    );
    assert_eq!(
        p.merged.startup_hooks[0].1.command,
        HookCmd::Argv(vec!["echo".into(), "/home/agent".into()])
    );
    assert_eq!(p.merged.files[0].path, "/f/alice");
    assert_eq!(p.merged.files[0].content, b"x");
    assert_eq!(p.merged.contexts[0].1.content, "for alice");
    assert!(!p.args["m"].contains_key("opt"));
}

fn opt_hook_kit() -> Kit {
    let mut m = mixin("m");
    m.args.insert("opt".into(), ArgDef::default());
    m.cap(
        "l@1",
        false,
        CapBody::Lifecycle(Lifecycle {
            install: vec![shell_hook("x${{ kit.args.opt }}y")],
            startup: vec![],
            files: vec![],
        }),
    )
}

#[test]
fn a_used_optional_arg_with_no_value_is_an_error_but_empty_is_a_value() {
    let e = resolve(workload("w"), vec![opt_hook_kit()], &ArgValues::default()).unwrap_err();
    assert_eq!(
        format!("{e:#}"),
        "kit m: create-phase kit arg \"opt\" has no resolved value"
    );
    let v = ArgValues::parse(&[], &["opt=".into()]).unwrap();
    let p = resolve(workload("w"), vec![opt_hook_kit()], &v).unwrap();
    assert_eq!(
        p.merged.install_hooks[0].1.command,
        HookCmd::Shell("xy".into())
    );
}

#[test]
fn unknown_args_and_undeclared_placeholders_fail() {
    let v = ArgValues::parse(&[], &["nope=1".into()]).unwrap();
    assert!(resolve(workload("w"), vec![], &v).is_err());
    let m = mixin("m").cap(
        "c@1",
        false,
        CapBody::AgentContext(AgentContextReq {
            filename: None,
            directory: None,
            content: "${{ kit.args.zzz }}".into(),
        }),
    );
    assert!(run(workload("w"), vec![m]).is_err());
}

#[test]
fn v2_workspace_files_and_workdir_expand_to_the_workdir() {
    let dir = std::path::Path::new("tests/fixtures/kits/v2/workspace-files");
    let yaml = std::fs::read_to_string(dir.join("spec.yaml")).unwrap();
    let kit = crate::kits::v2::parse(&yaml, dir).unwrap();
    let v2_workload = || Kit::new("w", Kind::Workload, Source::LocalV2("w".into()));
    let files = |p: &Plan| -> Vec<(String, Vec<u8>)> {
        p.merged
            .files
            .iter()
            .map(|f| (f.path.clone(), f.content.clone()))
            .collect()
    };
    let p = resolve_for(
        v2_workload(),
        vec![kit.clone()],
        &ArgValues::default(),
        "/w/repo",
    )
    .unwrap();
    assert_eq!(
        files(&p),
        [
            ("/home/agent/.wsrc".into(), "workdir=/w/repo\n".into()),
            (
                "/w/repo/docs/NOTES.md".into(),
                "Notes for the workspace.\n".into()
            ),
        ]
    );
    // Without a sandbox (`kit validate`): the mountless directory.
    let p = resolve(v2_workload(), vec![kit], &ArgValues::default()).unwrap();
    assert_eq!(files(&p)[1].0, "/home/agent/workspace/docs/NOTES.md");
}

#[test]
fn v2_and_v3_kits_are_not_mixed() {
    let v2_workload = || Kit::new("w2", Kind::Workload, Source::LocalV2("w2".into()));
    let v2 = |name: &str| Kit::new(name, Kind::Mixin, Source::LocalV2(name.into()));
    let docker = || Kit::new("docker", Kind::Mixin, Source::Builtin("docker"));
    // sbx's wording.
    let err = check_formats(&v2_workload(), &[v2("old"), mixin("new")]).unwrap_err();
    assert_eq!(
        err.to_string(),
        "cannot mix v3 kits with v1/v2 kits in one sandbox; compositions are single-format \
             (v3: new; v1/v2: w2, old). Use a v3 version of the v1/v2 kit"
    );
    // A built-in agent's kit is v3, as in sbx.
    let agent = Kit::agent_test("shell");
    assert!(check_formats(&agent, &[v2("old")]).is_err());
    let err = check_formats(&workload("w"), &[v2("old")]).unwrap_err();
    assert!(err.to_string().contains("(v3: w; v1/v2: old)"), "{err}");
    // The shipped docker kit has no format of its own.
    check_formats(&v2_workload(), &[docker(), v2("old"), v2("older")]).unwrap();
    check_formats(&agent, &[docker(), mixin("new")]).unwrap();
}
