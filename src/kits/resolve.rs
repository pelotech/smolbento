//! Resolves one workload plus mixins into an ordered, merged `Plan` ready to apply.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, bail};

use crate::kits::args::{ArgValues, expand};
use crate::kits::model::{
    AgentContextReq, CapBody, CredReq, FileReq, Hook, HookCmd, Kind, Kit, NetRule, Rules,
};

/// The agent user's home in the platform floor; the host can't see the guest's real env.
const AGENT_HOME: &str = "/home/agent";

#[derive(Debug)]
pub struct Plan {
    /// The agent preset as a synthetic workload kit, or a workload kit.
    pub workload: Kit,
    /// Dependency order.
    pub mixins: Vec<Kit>,
    /// Kit name to effective args.
    pub args: BTreeMap<String, BTreeMap<String, String>>,
    pub merged: Merged,
    /// `kit: type@n` of skipped optional capabilities.
    pub skipped: Vec<String>,
}

impl Plan {
    /// One stderr line per skipped optional capability.
    pub fn warn_skipped(&self) {
        for s in &self.skipped {
            let (kit, what) = s.split_once(": ").unwrap_or(("?", s));
            eprintln!("warning: kit {kit}: skipping {what} (not supported)");
        }
    }
}

#[derive(Debug, Default)]
pub struct Merged {
    pub install: Rules,
    pub runtime: Rules,
    /// The same network rules per kit (each kit's rules are tagged with it in the policy).
    pub network: Vec<KitRules>,
    pub credentials: Vec<KitCred>,
    pub ports: Vec<(u16, bool)>,
    pub volumes: Vec<(String, bool, Option<String>)>,
    pub cpus: Option<String>,
    pub memory: Option<String>,
    pub env: Vec<(String, String)>,
    /// `(kit name, hook)` in dependency order.
    pub install_hooks: Vec<(String, Hook)>,
    pub startup_hooks: Vec<(String, Hook)>,
    pub files: Vec<FileReq>,
    pub contexts: Vec<(String, AgentContextReq)>,
    pub git_identity: bool,
    pub long_running: bool,
    pub privileged: bool,
}

#[derive(Debug)]
pub struct KitRules {
    pub kit: String,
    pub install: Rules,
    pub runtime: Rules,
}

#[derive(Debug)]
pub struct KitCred {
    pub kit: String,
    pub optional: bool,
    pub req: CredReq,
}

/// `${{ kit.env.WORKSPACE }}` when there's no sandbox (`kit validate`, tests): the mountless
/// working directory, so a kit validates the same way it applies to a mountless sandbox.
pub const NO_SANDBOX_WORKDIR: &str = crate::workspace::MOUNTLESS_WORKDIR;

/// `resolve_for` without a sandbox, for checking kits: `WORKSPACE` is `NO_SANDBOX_WORKDIR`.
pub fn resolve(workload: Kit, mixins: Vec<Kit>, args: &ArgValues) -> Result<Plan> {
    resolve_for(workload, mixins, args, NO_SANDBOX_WORKDIR)
}

/// Resolves the kits for a sandbox whose working directory in the guest is `workdir`: v2's
/// `files/workspace` and `${WORKDIR}` expand to it as `${{ kit.env.WORKSPACE }}`.
pub fn resolve_for(
    workload: Kit,
    mixins: Vec<Kit>,
    args: &ArgValues,
    workdir: &str,
) -> Result<Plan> {
    if workload.kind != Kind::Workload {
        bail!(
            "{} is a mixin, not a workload; pass it with --kit",
            workload.name
        );
    }
    // Names scope `--kit-arg`s and tag policy rules. An agent preset isn't a kit, so a kit may
    // share its name.
    use crate::kits::model::Source;
    let named = std::iter::once(&workload)
        .filter(|w| !matches!(w.source, Source::Preset(_)))
        .chain(&mixins);
    let mut seen = BTreeSet::new();
    for k in named {
        if !seen.insert(k.name.as_str()) {
            // Most likely a user's own docker kit beside the shipped one a Docker image gets.
            let shipped = std::iter::once(&workload)
                .chain(&mixins)
                .any(|k| k.source == Source::Builtin("docker"));
            if k.name == "docker" && shipped {
                bail!(
                    "two kits are named docker: yours and the shipped one a Docker-enabled image \
                     gets; rename your kit, or have it provide docker (`provides: [docker]`) to \
                     replace the shipped one"
                );
            }
            bail!("two kits are named {}", k.name);
        }
    }
    if let Some(m) = mixins.iter().find(|m| m.kind == Kind::Workload) {
        bail!(
            "two workloads: {} and {}; pass a workload kit as the agent argument",
            workload.name,
            m.name
        );
    }
    let mixins = order(&workload, mixins)?;

    let all: Vec<Kit> = std::iter::once(workload.clone())
        .chain(mixins.iter().cloned())
        .collect();
    args.check_unknown(&all)?;

    let mut kit_args = BTreeMap::new();
    for k in &all {
        let mut effective = args.for_kit(k)?;
        // An optional arg with no value and no default expands to "".
        for name in k.args.keys() {
            effective.entry(name.clone()).or_default();
        }
        kit_args.insert(k.name.clone(), effective);
    }

    let mut merged = Merged::default();
    for k in &all {
        for (name, value) in &k.env {
            match merged.env.iter_mut().find(|(n, _)| n == name) {
                Some(e) => e.1 = value.clone(),
                None => merged.env.push((name.clone(), value.clone())),
            }
        }
    }
    let mut env_map: BTreeMap<String, String> = merged.env.iter().cloned().collect();
    env_map.insert("HOME".into(), AGENT_HOME.into());
    env_map.insert("WORKSPACE".into(), workdir.into());

    let mut skipped = Vec::new();
    for k in &all {
        let a = &kit_args[&k.name];
        let ex = |s: &str| -> Result<String> {
            expand(s, a, &env_map).with_context(|| format!("kit {}", k.name))
        };
        for cap in &k.caps {
            match &cap.body {
                CapBody::Unsupported => {
                    if cap.optional {
                        skipped.push(format!("{}: {}", k.name, cap.ty));
                        continue;
                    }
                    bail!("kit {}: {} is not supported by smolbento", k.name, cap.ty);
                }
                CapBody::Credential(c) => {
                    if c.oauth.as_ref().is_some_and(|o| !o.passthrough) {
                        if cap.optional {
                            skipped.push(format!("{}: {}", k.name, cap.ty));
                            continue;
                        }
                        bail!(
                            "kit {}: {} oauth without passthrough is not supported by smolbento",
                            k.name,
                            cap.ty
                        );
                    }
                    merged.credentials.push(KitCred {
                        kit: k.name.clone(),
                        optional: cap.optional,
                        req: c.clone(),
                    });
                }
                CapBody::Network { install, runtime } => {
                    // Method and path qualifiers can't be enforced, only hosts can.
                    let qualified = [install, runtime]
                        .iter()
                        .flat_map(|r| r.allow.iter().chain(&r.deny))
                        .any(|n| !n.methods.is_empty() || !n.paths.is_empty());
                    let host_only = |r: &Rules| {
                        let strip = |l: &[NetRule]| -> Vec<NetRule> {
                            l.iter()
                                .map(|n| NetRule {
                                    host: n.host.clone(),
                                    methods: vec![],
                                    paths: vec![],
                                })
                                .collect()
                        };
                        Rules {
                            allow: strip(&r.allow),
                            deny: strip(&r.deny),
                        }
                    };
                    let (install, runtime) = if qualified && cap.ty.ends_with("network-policy@2") {
                        if !cap.optional {
                            bail!(
                                "kit {}: network-policy@2 method/path rules are not enforced by \
                                 smolbento",
                                k.name
                            );
                        }
                        skipped.push(format!(
                            "{}: network-policy@2 method/path (host-only)",
                            k.name
                        ));
                        (host_only(install), host_only(runtime))
                    } else {
                        (install.clone(), runtime.clone())
                    };
                    merged.network.push(KitRules {
                        kit: k.name.clone(),
                        install: install.clone(),
                        runtime: runtime.clone(),
                    });
                    merged.install.allow.extend(install.allow);
                    merged.install.deny.extend(install.deny);
                    merged.runtime.allow.extend(runtime.allow);
                    merged.runtime.deny.extend(runtime.deny);
                }
                CapBody::Port { container, udp } => {
                    if !merged.ports.contains(&(*container, *udp)) {
                        merged.ports.push((*container, *udp));
                    }
                }
                CapBody::Volume { path, tmpfs, mode } => {
                    match merged.volumes.iter().find(|v| &v.0 == path) {
                        Some(v) if v.1 != *tmpfs || v.2 != *mode => bail!(
                            "kit {}: volume {path} conflicts with another kit's request",
                            k.name
                        ),
                        Some(_) => {}
                        None => merged.volumes.push((path.clone(), *tmpfs, mode.clone())),
                    }
                }
                CapBody::Resources { cpus, memory } => {
                    if cpus.is_some() {
                        merged.cpus = cpus.clone();
                    }
                    if memory.is_some() {
                        merged.memory = memory.clone();
                    }
                }
                CapBody::Lifecycle(l) => {
                    for h in &l.install {
                        merged
                            .install_hooks
                            .push((k.name.clone(), expand_hook(h, &ex)?));
                    }
                    for h in &l.startup {
                        merged
                            .startup_hooks
                            .push((k.name.clone(), expand_hook(h, &ex)?));
                    }
                    for f in &l.files {
                        merged.files.push(FileReq {
                            path: ex(&f.path)?,
                            content: ex(&f.content)?,
                            ..f.clone()
                        });
                    }
                }
                CapBody::AgentContext(c) => {
                    merged.contexts.push((
                        k.name.clone(),
                        AgentContextReq {
                            content: ex(&c.content)?,
                            ..c.clone()
                        },
                    ));
                }
                CapBody::GitIdentity => merged.git_identity = true,
                CapBody::LongRunning => merged.long_running = true,
                CapBody::Privileged => merged.privileged = true,
                CapBody::Sbx | CapBody::AgentSessions => {}
            }
        }
    }

    let mut it = all.into_iter();
    let workload = it.next().expect("workload is first");
    Ok(Plan {
        workload,
        mixins: it.collect(),
        args: kit_args,
        merged,
        skipped,
    })
}

fn expand_hook(h: &Hook, ex: &dyn Fn(&str) -> Result<String>) -> Result<Hook> {
    let command = match &h.command {
        HookCmd::Shell(s) => HookCmd::Shell(ex(s)?),
        HookCmd::Argv(v) => HookCmd::Argv(v.iter().map(|s| ex(s)).collect::<Result<_>>()?),
    };
    Ok(Hook {
        command,
        ..h.clone()
    })
}

/// Stable topological sort: repeatedly take the first mixin whose requirements are provided.
fn order(workload: &Kit, mixins: Vec<Kit>) -> Result<Vec<Kit>> {
    let mut providers: BTreeMap<&str, &str> = BTreeMap::new();
    for k in std::iter::once(workload).chain(mixins.iter()) {
        for p in &k.provides {
            if let Some(other) = providers.insert(p, &k.name) {
                bail!("'{p}' is provided by both {other} and {}", k.name);
            }
        }
    }
    for k in std::iter::once(workload).chain(mixins.iter()) {
        for r in &k.requires {
            if !providers.contains_key(r.as_str()) {
                bail!("{} requires '{r}', which no kit provides", k.name);
            }
        }
    }

    let mut have: BTreeSet<String> = workload.provides.iter().cloned().collect();
    let mut rest = mixins;
    let mut out = Vec::with_capacity(rest.len());
    while !rest.is_empty() {
        let Some(i) = rest
            .iter()
            .position(|k| k.requires.iter().all(|r| have.contains(r)))
        else {
            let names: Vec<_> = rest.iter().map(|k| k.name.as_str()).collect();
            bail!("kits have circular requirements: {}", names.join(", "));
        };
        let k = rest.remove(i);
        have.extend(k.provides.iter().cloned());
        out.push(k);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kits::model::{ArgDef, Cap, Content, Lifecycle, NetRule, OAuthReq, Source};

    fn base(name: &str, kind: Kind) -> Kit {
        Kit {
            name: name.into(),
            source: Source::Registry(name.into()),
            digest: None,
            kind,
            provides: vec![],
            requires: vec![],
            args: BTreeMap::new(),
            caps: vec![],
            env: vec![],
            content: Content::None,
            command: None,
        }
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

    fn run(w: Kit, m: Vec<Kit>) -> Result<Plan> {
        resolve(w, m, &ArgValues::default())
    }
    fn names(p: &Plan) -> Vec<&str> {
        p.mixins.iter().map(|k| k.name.as_str()).collect()
    }
    fn rule(host: &str) -> NetRule {
        NetRule {
            host: host.into(),
            methods: vec![],
            paths: vec![],
        }
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
    fn duplicate_provides_fail() {
        let a = mixin("a").provides(&["x"]);
        let b = mixin("b").provides(&["x"]);
        let e = run(workload("w"), vec![a, b]).unwrap_err();
        assert!(format!("{e:#}").contains("'x'"), "{e:#}");
    }

    #[test]
    fn unmet_requires_fails_naming_both() {
        let e = run(workload("w"), vec![mixin("a").requires(&["x"])]).unwrap_err();
        assert_eq!(format!("{e:#}"), "a requires 'x', which no kit provides");
    }

    #[test]
    fn circular_requires_fail() {
        let a = mixin("a").requires(&["b"]).provides(&["a"]);
        let b = mixin("b").requires(&["a"]).provides(&["b"]);
        assert!(run(workload("w"), vec![a, b]).is_err());
    }

    #[test]
    fn a_mixin_as_the_workload_and_two_kits_of_one_name_are_rejected() {
        let e = run(mixin("m"), vec![]).unwrap_err();
        assert_eq!(
            format!("{e:#}"),
            "m is a mixin, not a workload; pass it with --kit"
        );
        let e = run(workload("w"), vec![mixin("a"), mixin("a")]).unwrap_err();
        assert_eq!(format!("{e:#}"), "two kits are named a");
        let e = run(workload("a"), vec![mixin("a")]).unwrap_err();
        assert_eq!(format!("{e:#}"), "two kits are named a");
        let shipped = crate::kits::load::builtin("docker").unwrap().unwrap();
        let e = run(workload("w"), vec![mixin("docker"), shipped]).unwrap_err();
        assert_eq!(
            format!("{e:#}"),
            "two kits are named docker: yours and the shipped one a Docker-enabled image gets; \
             rename your kit, or have it provide docker (`provides: [docker]`) to replace the \
             shipped one"
        );
        // A preset agent's name is free for a kit.
        let mut preset = workload("claude");
        preset.source = Source::Preset("img:1".into());
        run(preset, vec![mixin("claude")]).unwrap();
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
            "com.docker.sandbox/host-mount@1",
            false,
            CapBody::Unsupported,
        );
        let e = run(workload("w"), vec![k]).unwrap_err();
        assert_eq!(
            format!("{e:#}"),
            "kit m: com.docker.sandbox/host-mount@1 is not supported by smolbento"
        );
    }

    #[test]
    fn an_optional_unsupported_capability_is_skipped() {
        let k = mixin("m").cap(
            "com.docker.sandbox/host-mount@1",
            true,
            CapBody::Unsupported,
        );
        let p = run(workload("w"), vec![k]).unwrap();
        assert_eq!(p.skipped, ["m: com.docker.sandbox/host-mount@1"]);
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
    fn oauth_passthrough_is_accepted_and_without_is_not() {
        let ty = "com.docker.sandbox/credential@1";
        let ok = mixin("m").cap(ty, false, cred(oauth(true)));
        assert_eq!(
            run(workload("w"), vec![ok])
                .unwrap()
                .merged
                .credentials
                .len(),
            1
        );

        let bad = mixin("m").cap(ty, false, cred(oauth(false)));
        let e = run(workload("w"), vec![bad]).unwrap_err();
        assert!(
            format!("{e:#}").contains("kit m: com.docker.sandbox/credential@1 oauth without passthrough is not supported by smolbento"),
            "{e:#}"
        );

        let opt = mixin("m").cap(ty, true, cred(oauth(false)));
        let p = run(workload("w"), vec![opt]).unwrap();
        assert_eq!(p.skipped, ["m: com.docker.sandbox/credential@1"]);
        assert!(p.merged.credentials.is_empty());
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
        assert_eq!(hosts(&p.merged.runtime.allow), ["a.com", "b.com"]);
        assert_eq!(hosts(&p.merged.runtime.deny), ["bad.com", "worse.com"]);
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
        assert!(p.merged.runtime.allow[0].methods.is_empty());
        // Host-only entries and @1 are unaffected.
        let plain = mixin("m").cap(ty, false, n("a.com", &[]));
        assert!(run(workload("w"), vec![plain]).unwrap().skipped.is_empty());
    }

    #[test]
    fn conflicting_volume_configs_fail_and_identical_ones_merge() {
        let a = mixin("a").cap("v@1", false, vol("/data", false));
        let b = mixin("b").cap("v@1", false, vol("/data", true));
        assert!(run(workload("w"), vec![a.clone(), b]).is_err());
        let c = mixin("c").cap("v@1", false, vol("/data", false));
        let p = run(workload("w"), vec![a, c]).unwrap();
        assert_eq!(p.merged.volumes, [("/data".to_string(), false, None)]);
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
        let m = m
            .cap(
                "l@1",
                false,
                CapBody::Lifecycle(Lifecycle {
                    install: vec![shell_hook("hi ${{ kit.args.name }}${{ kit.args.opt }}")],
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
        assert_eq!(p.merged.files[0].content, "x");
        assert_eq!(p.merged.contexts[0].1.content, "for alice");
        assert_eq!(p.args["m"]["opt"], "");
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
        let files = |p: &Plan| -> Vec<(String, String)> {
            p.merged
                .files
                .iter()
                .map(|f| (f.path.clone(), f.content.clone()))
                .collect()
        };
        let p = resolve_for(
            workload("w"),
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
        let p = resolve(workload("w"), vec![kit], &ArgValues::default()).unwrap();
        assert_eq!(files(&p)[1].0, "/home/agent/workspace/docs/NOTES.md");
    }
}
