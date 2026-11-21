use super::*;
use crate::kits::model::{ArgDef, Cap, HookCmd, NetRule, OAuthReq, Source, SshPhase};
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
        self.caps.push(Cap::new(ty, optional, body));
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
    a.source = Source::Local("/kits/a".into());
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
        Source::Local(std::path::PathBuf::from("/k/claude-mixin")),
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

/// A v3 mixin `m` from a descriptor: `args` and `caps` are its YAML blocks.
fn v3_m(args: &str, caps: &str) -> Kit {
    let doc = format!("schemaVersion: \"3\"\nkind: mixin\nargs:\n{args}capabilities:\n{caps}");
    crate::kits::v3::parse(&doc, Source::Registry("m".into())).unwrap()
}

#[test]
fn hooks_files_and_contexts_expand_args_and_env() {
    // `opt` is declared with no value but never used: not an error.
    let m = v3_m(
        "  name: {default: bob}\n  opt: {}\n  tool: {default: x, env: TOOL}\n",
        r#"  - type: com.docker.sandbox/lifecycle@1
    config:
      install: [{command: "hi ${{ kit.args.name }}"}]
      startup: [{command: [echo, "${{ kit.env.HOME }}"]}]
      files: [{path: "/f/${{ kit.args.name }}", content: "${{ kit.env.TOOL }}"}]
  - type: com.docker.sandbox/agent-context@2
    config:
      filename: "${{ kit.args.name }}.md"
      directory: "/home/${{ kit.args.name }}"
      content: "for ${{ kit.args.name }}"
"#,
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
    // SPEC §6: the file's name and directory expand too.
    let context = &p.merged.contexts[0].req;
    assert_eq!(context.content, "for alice");
    assert_eq!(context.directory.as_deref(), Some("/home/alice"));
    assert_eq!(context.filename.as_deref(), Some("alice.md"));
    assert!(!p.args["m"].contains_key("opt"));
}

fn opt_hook_kit() -> Kit {
    v3_m(
        "  opt: {}\n",
        "  - type: com.docker.sandbox/lifecycle@1\n    config: {install: [{command: \"x${{ kit.args.opt }}y\"}]}\n",
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
    let m = v3_m(
        "  a: {}\n",
        "  - type: com.docker.sandbox/agent-context@2\n    config: {content: \"${{ kit.args.zzz }}\"}\n",
    );
    let e = run(workload("w"), vec![m]).unwrap_err();
    assert!(
        format!("{e:#}").contains("undeclared kit argument \"zzz\""),
        "{e:#}"
    );
}

#[test]
fn v2_workspace_files_and_workdir_expand_to_the_workdir() {
    let dir = std::path::Path::new("tests/fixtures/kits/v2/workspace-files");
    let yaml = std::fs::read_to_string(dir.join("spec.yaml")).unwrap();
    let kit = crate::kits::v2::parse(&yaml, dir).unwrap();
    let v2_workload = || Kit {
        v2: true,
        ..Kit::new("w", Kind::Workload, Source::Local("w".into()))
    };
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
    let v2_workload = || Kit {
        v2: true,
        ..Kit::new("w2", Kind::Workload, Source::Local("w2".into()))
    };
    let v2 = |name: &str| Kit {
        v2: true,
        ..Kit::new(name, Kind::Mixin, Source::Local(name.into()))
    };
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

/// A mixin `g` from a v3 descriptor whose `capabilities` are `caps`. It declares the arguments
/// `port`, `dir`, `host`, `mode` and `method`, without values.
fn v3_mixin(caps: &str) -> Kit {
    let doc = format!(
        "schemaVersion: \"3\"\nkind: mixin\nargs:\n  port: {{}}\n  dir: {{}}\n  host: {{}}\n  \
         mode: {{}}\n  method: {{}}\ncapabilities:\n{caps}"
    );
    crate::kits::v3::parse(&doc, Source::Registry("g".into())).unwrap()
}

/// A volume plus a lifecycle file, and `extra` as a third member.
fn feature_group(optional: bool, extra: &str) -> Kit {
    v3_mixin(&format!(
        "  - group:
      name: Feature
      optional: {optional}
      capabilities:
        - type: com.docker.sandbox/volume@1
          config: {{path: /var/tmp/group-volume}}
        - type: com.docker.sandbox/lifecycle@1
          config: {{files: [{{path: /var/tmp/group-feature, content: selected}}]}}
{extra}"
    ))
}

const USB: &str = "        - type: com.docker.sandbox/usb-device@1\n";

/// tck: SPEC-v3 §7.1.1/atomic-selection
#[test]
fn an_optional_group_with_an_unsupported_member_is_skipped_whole() {
    let p = run(workload("w"), vec![feature_group(true, USB)]).unwrap();
    assert!(p.merged.volumes.is_empty(), "{:?}", p.merged.volumes);
    assert!(p.merged.files.is_empty(), "{:?}", p.merged.files);
    assert_eq!(
        p.skipped,
        ["g: optional group capabilities[0] (Feature), for its \
          capabilities[0].group.capabilities[2] com.docker.sandbox/usb-device@1"]
    );
    assert_eq!(
        p.skipped_warnings(),
        [
            "kit g: skipping optional group capabilities[0] (Feature), for its \
          capabilities[0].group.capabilities[2] com.docker.sandbox/usb-device@1 (not supported)"
        ]
    );
}

/// tck: SPEC-v3 §7.1.1/selection-before-application
#[test]
fn a_skipped_groups_members_are_gone_from_the_plans_kits() {
    let p = run(workload("w"), vec![feature_group(true, USB)]).unwrap();
    assert!(p.mixins[0].caps.is_empty(), "{:?}", p.mixins[0].caps);
}

/// tck: SPEC-v3 §7.1.1/atomic-selection
#[test]
fn a_required_group_with_an_unsupported_member_refuses_the_kit_naming_the_member() {
    let e = run(workload("w"), vec![feature_group(false, USB)]).unwrap_err();
    assert_eq!(
        format!("{e:#}"),
        "kit g: required group capabilities[0] (Feature): capabilities[0].group.capabilities[2] \
         com.docker.sandbox/usb-device@1 is not supported by smolbento"
    );
}

/// tck: SPEC-v3 §7.1.1/atomic-selection
#[test]
fn a_group_whose_members_are_all_supported_is_applied() {
    let p = run(workload("w"), vec![feature_group(true, "")]).unwrap();
    assert_eq!(p.merged.volumes.len(), 1);
    assert_eq!(p.merged.files[0].path, "/var/tmp/group-feature");
    assert!(p.skipped.is_empty(), "{:?}", p.skipped);
}

/// A group member is taken whole or not at all, never widened to its hosts as an optional
/// ordinary `network-policy@2` entry is.
#[test]
fn a_group_with_method_or_path_rules_is_skipped_not_widened() {
    let k = feature_group(
        true,
        "        - type: com.docker.sandbox/network-policy@2
          config: {runtime: {allow: [{hosts: [api.example.com], methods: [GET]}]}}
",
    );
    let p = run(workload("w"), vec![k]).unwrap();
    assert!(runtime(&p).allow.is_empty(), "{:?}", runtime(&p));
    assert!(p.merged.volumes.is_empty());
    assert!(
        p.skipped[0].what.contains("network-policy@2"),
        "{:?}",
        p.skipped
    );
}

/// tck: SPEC-v3 §7.1.1/order
#[test]
fn selected_group_members_apply_in_declaration_order() {
    let k = v3_mixin(
        r#"  - type: com.docker.sandbox/lifecycle@1
    config: {startup: [{command: "printf base"}]}
  - group:
      optional: true
      capabilities:
        - type: com.docker.sandbox/lifecycle@1
          config: {startup: [{command: "printf feature"}]}
  - group:
      name: Feature
      capabilities:
        - type: com.docker.sandbox/lifecycle@1
          config: {startup: [{command: "printf independent"}]}
"#,
    );
    let p = run(workload("w"), vec![k]).unwrap();
    let hooks: Vec<String> = p
        .merged
        .startup_hooks
        .iter()
        .map(|(_, h)| format!("{:?}", h.command))
        .collect();
    assert_eq!(
        hooks,
        [
            r#"Shell("printf base")"#,
            r#"Shell("printf feature")"#,
            r#"Shell("printf independent")"#,
        ]
    );
}

#[test]
fn one_groups_rejection_leaves_another_group_alone() {
    let k = v3_mixin(&format!(
        "  - group:
      optional: true
      capabilities:
{USB}  - group:
      optional: true
      capabilities:
        - type: com.docker.sandbox/volume@1
          config: {{path: /data}}
"
    ));
    let p = run(workload("w"), vec![k]).unwrap();
    assert_eq!(p.merged.volumes.len(), 1);
    assert_eq!(p.skipped.len(), 1);
}

fn with_args(values: &[&str]) -> ArgValues {
    let flags: Vec<String> = values.iter().map(|v| v.to_string()).collect();
    ArgValues::parse(&[], &flags).unwrap()
}

/// SPEC-v3 §6: references expand inside a capability's config before it's read, so a numeric
/// argument reaches a numeric field and a path argument a checked path.
#[test]
fn config_references_expand_before_the_config_is_read() {
    let k = v3_mixin(
        r#"  - type: com.docker.sandbox/port@1
    config: {container: "${{ kit.args.port }}"}
  - type: com.docker.sandbox/host-mount@1
    config: {path: "${{ kit.args.dir }}"}
  - type: com.docker.sandbox/volume@1
    config: {path: /cache, mode: "${{ kit.args.mode }}"}
  - type: com.docker.sandbox/network-policy@1
    config: {runtime: {allow: ["${{ kit.args.host }}"]}}
"#,
    );
    let args = with_args(&[
        "port=8080",
        "dir=/srv/data",
        "mode=0755",
        "host=api.example.com",
        "method=GET",
    ]);
    let p = resolve(workload("w"), vec![k], &args).unwrap();
    assert_eq!(p.merged.ports, [(8080, false)]);
    assert_eq!(p.merged.host_mounts[0].path, "/srv/data");
    // `volume@1`'s mode stays text, though `0755` would otherwise read as text anyway.
    assert_eq!(p.merged.volumes[0].mode.as_deref(), Some("0755"));
    assert_eq!(runtime(&p).allow[0].host, "api.example.com");
    // The plan's kits hold what was read, not the references.
    assert!(p.mixins[0].caps.iter().all(|c| c.config.is_none()));
}

#[test]
fn an_expanded_config_is_read_strictly() {
    let k = v3_mixin(
        r#"  - type: com.docker.sandbox/port@1
    config: {container: "${{ kit.args.port }}"}
"#,
    );
    let e = resolve(workload("w"), vec![k], &with_args(&["port=web"])).unwrap_err();
    let e = format!("{e:#}");
    assert!(
        e.starts_with("kit g: capability com.docker.sandbox/port@1: "),
        "{e}"
    );
}

/// tck: SPEC-v3 §7.1.1/validate-expanded-declarations
#[test]
fn groups_are_selected_from_their_expanded_members() {
    let k = v3_mixin(
        r#"  - group:
      optional: true
      capabilities:
        - type: com.docker.sandbox/network-policy@2
          config:
            runtime: {allow: [{hosts: [api.example.com], methods: ["${{ kit.args.method }}"]}]}
"#,
    );
    let p = resolve(workload("w"), vec![k], &with_args(&["method=GET"])).unwrap();
    assert!(runtime(&p).allow.is_empty(), "{:?}", runtime(&p));
    assert_eq!(p.skipped.len(), 1, "{:?}", p.skipped);
}

#[test]
fn a_reference_with_no_value_fails_even_in_an_optional_capability() {
    let k = v3_mixin(
        r#"  - type: com.docker.sandbox/port@1
    optional: true
    config: {container: "${{ kit.args.port }}"}
"#,
    );
    let e = resolve(workload("w"), vec![k], &ArgValues::default()).unwrap_err();
    assert!(
        format!("{e:#}").contains("\"port\" has no resolved value"),
        "{e:#}"
    );
}

const DD: &str = "com.docker.sandbox/dockerd@1";
const VOL: &str = "com.docker.sandbox/volume@1";
fn dockerd(auto_start: bool) -> CapBody {
    CapBody::Dockerd { auto_start }
}

#[test]
fn dockerd_merges_auto_start_true_wins() {
    let two = |a, b| {
        let p = run(
            workload("w").cap(DD, false, dockerd(a)),
            vec![mixin("m").cap(DD, false, dockerd(b))],
        );
        p.unwrap().merged.dockerd
    };
    assert_eq!(two(false, false), Some(false));
    assert_eq!(two(true, false), Some(true));
    assert_eq!(two(false, true), Some(true));
}

/// tck: dockerd@1/elevation-granted
/// tck: dockerd@1/storage-private-and-persistent
/// tck: dockerd@1/manual-elevation-granted
/// tck: dockerd@1/manual-storage-private-and-persistent
/// tck: dockerd@1/storage-removed-with-sandbox
/// tck: dockerd@1/removed-store-not-reused
#[test]
fn dockerd_brings_elevation_and_the_engine_store() {
    for auto_start in [true, false] {
        let p = run(workload("w").cap(DD, false, dockerd(auto_start)), vec![]).unwrap();
        assert!(p.merged.privileged);
        let got: Vec<_> = (p.merged.volumes.iter())
            .map(|v| (&*v.path, v.tmpfs, v.mode.as_deref()))
            .collect();
        assert_eq!(
            got,
            [
                ("/var/lib/docker", false, None),
                ("/var/lib/containerd", false, None)
            ]
        );
    }
}

/// tck: dockerd@1/engine-store-owned
#[test]
fn dockerd_owns_the_engine_store() {
    let others: [(&str, CapBody); 3] = [
        (VOL, vol("/var/lib/docker/", false)),
        (VOL, vol("/var/lib/docker/volumes", false)),
        (
            "com.docker.sandbox/host-mount@1",
            host("/var/lib/docker", None),
        ),
    ];
    for (ty, body) in others {
        // Whichever side is added first.
        let d = || workload("w").cap(DD, false, dockerd(true));
        let o = || mixin("m").cap(ty, false, body.clone());
        assert!(run(d(), vec![o()]).is_err(), "{body:?}");
        let w = workload("w").cap(ty, false, body.clone());
        let m = mixin("m").cap(DD, false, dockerd(true));
        assert!(run(w, vec![m]).is_err(), "{body:?}");
    }
    for ok in ["/var/lib/docker2", "/var/lib/docker-cache"] {
        let m = mixin("m").cap(VOL, false, vol(ok, false));
        run(workload("w").cap(DD, false, dockerd(true)), vec![m]).unwrap();
    }
}

/// tck: dockerd@1/absent-without-grant
#[test]
fn dockerd_absent_without_a_declaration() {
    let p = run(workload("w"), vec![]).unwrap();
    assert_eq!(p.merged.dockerd, None);
    assert!(!p.merged.privileged);
}

/// tck: dockerd@1/engine-store-owned (the cleaned path decides, not its spelling)
#[test]
fn dockerd_engine_store_is_compared_on_the_cleaned_path() {
    for bad in [
        "/var/lib/x/../docker",
        "/var/lib/docker/./volumes",
        "//var/lib//docker",
    ] {
        let d = || workload("w").cap(DD, false, dockerd(true));
        let m = || mixin("m").cap(VOL, false, vol(bad, false));
        assert!(run(d(), vec![m()]).is_err(), "{bad}");
        let w = workload("w").cap(VOL, false, vol(bad, false));
        let m = mixin("m").cap(DD, false, dockerd(true));
        assert!(run(w, vec![m]).is_err(), "{bad}");
    }
    let m = mixin("m").cap(VOL, false, vol("/var/lib/docker2/../docker2", false));
    run(workload("w").cap(DD, false, dockerd(true)), vec![m]).unwrap();
}
