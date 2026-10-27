//! Applies a resolved kit plan to a new sandbox: `CreateRequest` fields, the kits' policy rules,
//! and the guest steps the first start runs.

use std::path::Path;

use anyhow::{Context, Result, bail};

use crate::agents;
use crate::kits::compose;
use crate::kits::guest;
use crate::kits::model::{CapBody, Content, CredReq, FileReq, Hook, Kit, NetRule, Rules, Source};
use crate::kits::resolve::{KitCred, Plan};
use crate::policy::Policy;
use crate::sandbox::CreateRequest;
use crate::sandbox::labels::CredFormat;
use crate::sandbox::options::{free_port, parse_memory};
use crate::secrets::{SecretsFile, services};
use crate::smolvm::{Credential, PortMap};

/// Guest steps for a sandbox's first start (and `kit add`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KitSteps {
    /// Policy rule ids to remove once the install hooks have run.
    pub install_rules: Vec<String>,
    /// `(exec user, script)` run with `sh -c` in order; `None` is root.
    pub install: Vec<(Option<String>, String)>,
    /// Scripts writing kit files (as root, then owned by `agent`).
    pub files: Vec<String>,
    /// Scripts writing agent context sections.
    pub context: Vec<String>,
    /// `(file name "NN-<kit>.sh", body)` for `/etc/smolbento/startup.d`, in run order.
    pub startup_d: Vec<(String, String)>,
    /// `/etc/smolbento/kits`: `name<TAB>ref<TAB>provides` per kit.
    pub kits_record: String,
}

/// Fills `req` from the plan and writes the kits' policy rules (install-phase ones too: they must
/// be in place while install hooks run). Returns the steps for the first start and the ids of
/// every rule this call added, for rollback. Nothing is written to `policy` on error.
pub fn apply(
    plan: &Plan,
    req: &mut CreateRequest,
    policy: &mut Policy,
    secrets: &SecretsFile,
    cache: &Path,
    host_git: &dyn Fn() -> Option<(String, String)>,
) -> Result<(KitSteps, Vec<String>)> {
    let m = &plan.merged;
    let kits: Vec<&Kit> = std::iter::once(&plan.workload)
        .chain(&plan.mixins)
        .collect();
    let mut steps = KitSteps::default();

    match &plan.workload.content {
        Content::Smolfile(path) => {
            if compose::has_mixin_layers(plan)? {
                bail!("mixins with image layers can't be added to a Smolfile kit");
            }
            req.image.clear();
            req.smolfile = Some(path.clone());
        }
        _ => req.image = compose::image_for(plan, cache)?,
    }

    if let Some(c) = m.cpus.as_deref().filter(|_| !req.cpus_set) {
        let n: f64 = c
            .trim()
            .parse()
            .with_context(|| format!("kit resources: invalid cpus '{c}'"))?;
        req.cpus = (n.ceil() as u32).max(1);
    }
    if let Some(mem) = m.memory.as_deref().filter(|_| !req.memory_set) {
        req.memory_mib = parse_memory(mem).context("kit resources")?;
    }
    // The user's -e wins over a kit's variable.
    for (k, v) in &m.env {
        if !req.env.iter().any(|(n, _)| n == k) {
            req.env.push((k.clone(), v.clone()));
        }
    }
    for &(guest, udp) in &m.ports {
        if !req.ports.iter().any(|p| p.guest == guest && p.udp == udp) {
            let host = free_port()?;
            req.ports.push(PortMap { host, guest, udp });
        }
    }
    let mut tmpfs = Vec::new();
    for (path, is_tmpfs, mode) in &m.volumes {
        if *is_tmpfs {
            req.tmpfs.push(path.clone());
            tmpfs.push((path.clone(), mode.clone()));
        } else {
            req.volumes.push(path.clone());
        }
    }

    let mut kit_rules: Vec<(String, Rules, Rules)> = m
        .network
        .iter()
        .map(|k| (k.kit.clone(), k.install.clone(), k.runtime.clone()))
        .collect();
    let mut notes = Vec::new();
    for kc in &m.credentials {
        if let Some(o) = kc.req.oauth.as_ref().filter(|o| o.passthrough) {
            let hosts: Vec<NetRule> = o
                .token_host
                .iter()
                .chain(&o.resource_hosts)
                .map(|h| NetRule {
                    host: h.clone(),
                    methods: vec![],
                    paths: vec![],
                })
                .collect();
            let i = match kit_rules.iter().position(|r| r.0 == kc.kit) {
                Some(i) => i,
                None => {
                    kit_rules.push((kc.kit.clone(), Rules::default(), Rules::default()));
                    kit_rules.len() - 1
                }
            };
            kit_rules[i].2.allow.extend(hosts.iter().cloned());
            if kc.req.install {
                kit_rules[i].1.allow.extend(hosts);
            }
            let note = format!(
                "note: kit {}: {} OAuth tokens live in the sandbox (passthrough)",
                kc.kit, kc.req.service
            );
            if !notes.contains(&note) {
                notes.push(note);
            }
        }
        if kc.req.env.is_some() || !kc.req.inject.is_empty() {
            bind_credential(kc, req, secrets)?;
        }
    }

    if m.git_identity {
        let required = kits.iter().find(|k| {
            k.caps
                .iter()
                .any(|c| matches!(c.body, CapBody::GitIdentity) && !c.optional)
        });
        match (host_git(), required) {
            (Some((name, email)), _) => steps
                .install
                .push((None, guest::git_identity_script(&name, &email))),
            (None, Some(k)) => bail!(
                "kit {} needs your git identity; set it with `git config --global user.name …` \
                 and `git config --global user.email …`",
                k.name
            ),
            (None, None) => {
                eprintln!("warning: no git user.name/user.email on the host; skipping git-identity")
            }
        }
    }
    for (kit, h) in m.install_hooks.iter().chain(&m.startup_hooks) {
        if let Some(v) = h.env.iter().find(|v| !guest::is_env_name(v)) {
            bail!("kit {kit}: hook env '{v}' is not a valid variable name");
        }
    }
    for (_, h) in &m.install_hooks {
        let script = format!("cd / && {}", guest::hook_script(h));
        steps.install.push((h.user.clone(), script));
    }
    // The later kit (in dependency order) wins a path.
    let mut files: Vec<&FileReq> = Vec::new();
    for f in &m.files {
        files.retain(|x| x.path != f.path);
        files.push(f);
    }
    steps.files = files.into_iter().map(guest::file_script).collect();
    steps.context = context_scripts(plan)?;
    if !tmpfs.is_empty() {
        steps
            .startup_d
            .push(("00-volumes.sh".into(), guest::tmpfs_script(&tmpfs)));
    }
    let mut n = 0;
    for k in &kits {
        let hooks: Vec<&Hook> = m
            .startup_hooks
            .iter()
            .filter(|(kit, _)| *kit == k.name)
            .map(|(_, h)| h)
            .collect();
        if !hooks.is_empty() {
            n += 1;
            steps.startup_d.push((
                format!("{n:02}-{}.sh", k.name),
                guest::startup_script(&k.name, &hooks),
            ));
        }
    }

    // A preset agent isn't a kit: nothing to record, and its command is the agent's own.
    let preset = is_preset(&plan.workload);
    if !preset {
        req.command = plan.workload.command.clone();
    }
    for k in kits.iter().skip(usize::from(preset)) {
        let pinned = pinned_ref(k)?;
        steps
            .kits_record
            .push_str(&format!("{}\t{pinned}\t{}\n", k.name, k.provides.join(",")));
        req.kits.push(pinned);
    }
    req.long_running = m.long_running;

    // Last, so an error above leaves the policy untouched; a failure part-way through (a bad
    // host) restores the snapshot. Runtime rules go first: an install rule that is also a runtime
    // rule must outlive the install phase.
    let snapshot = policy.clone();
    let mut added = Vec::new();
    let mut add = |policy: &mut Policy| -> Result<()> {
        for (kit, _, runtime) in &kit_rules {
            added.extend(policy.add_kit_rules(&req.name, kit, runtime)?.1);
        }
        for (kit, install, _) in &kit_rules {
            let new = policy.add_kit_rules(&req.name, kit, install)?.1;
            steps.install_rules.extend(new.iter().cloned());
            added.extend(new);
        }
        Ok(())
    };
    if let Err(e) = add(policy) {
        *policy = snapshot;
        return Err(e);
    }
    for s in &plan.skipped {
        eprintln!("warning: skipping optional capability {s}");
    }
    for note in notes {
        eprintln!("{note}");
    }
    Ok((steps, added))
}

/// Binds a kit credential through the user's secrets: a smolvm credential whose value
/// `start` resolves from the service's secret.
fn bind_credential(kc: &KitCred, req: &mut CreateRequest, secrets: &SecretsFile) -> Result<()> {
    let c: &CredReq = &kc.req;
    let service = secrets.service(&c.service);
    if secrets.entry_for(&req.name, None, &c.service).is_none() {
        if kc.optional {
            eprintln!(
                "warning: kit {}: no {} secret is set; skipping its optional credential",
                kc.kit, c.service
            );
            return Ok(());
        }
        let how = if services::builtin(&c.service).is_some() {
            format!("sbt secret set {}", c.service)
        } else {
            format!(
                "sbt secret set-custom --env {} --host {}",
                upper_env(&c.service),
                c.inject.first().map_or("HOST", |i| i.domain.as_str())
            )
        };
        bail!(
            "kit {} needs the {} secret; set it with {how}",
            kc.kit,
            c.service
        );
    }
    let env = c
        .env
        .clone()
        .unwrap_or_else(|| format!("SBX_KIT_{}", upper_env(&c.service)));
    if !guest::is_env_name(&env) {
        bail!("kit {}: '{env}' is not a valid variable name", kc.kit);
    }
    let mut hosts: Vec<String> = Vec::new();
    for i in &c.inject {
        if !hosts.contains(&i.domain) {
            hosts.push(i.domain.clone());
        }
    }
    if hosts.is_empty() {
        hosts = service
            .as_ref()
            .map(|s| s.hosts.clone())
            .unwrap_or_default();
    }
    if hosts.is_empty() {
        bail!(
            "kit {}: the {} credential names no host to send it to",
            kc.kit,
            c.service
        );
    }
    // smolvm takes one header and format per credential.
    let shape =
        |i: &crate::kits::model::Inject| (i.header.clone(), i.format.clone(), i.basic_user.clone());
    if c.inject.windows(2).any(|w| shape(&w[0]) != shape(&w[1])) {
        bail!(
            "kit {}: the {} credential injects differently per domain, which smolbento can't do",
            kc.kit,
            c.service
        );
    }
    let (header, format, basic) = c.inject.first().map(shape).unwrap_or_default();
    let fmt = basic
        .map(CredFormat::Basic)
        .or(format.map(CredFormat::Format));
    let set_header = header
        .or_else(|| fmt.as_ref().map(|_| "authorization".to_string()))
        .map(|h| h.to_ascii_lowercase());

    let mut name = c.service.clone();
    if req
        .credentials
        .iter()
        .any(|x| x.name == name && x.env_var != env)
    {
        name = env.to_ascii_lowercase();
    }
    match req
        .credentials
        .iter_mut()
        .find(|x| x.name == name && x.env_var == env)
    {
        Some(x) => {
            // Two kits binding the same variable must agree on how smolvm injects it.
            if x.set_header != set_header || req.credential_formats.get(&env) != fmt.as_ref() {
                bail!(
                    "kit {}: the {} credential ({env}) is injected differently by another kit",
                    kc.kit,
                    c.service
                );
            }
            for h in &hosts {
                if !x.hosts.contains(h) {
                    x.hosts.push(h.clone());
                }
            }
        }
        None => req.credentials.push(Credential {
            name,
            env_var: env.clone(),
            hosts: hosts.clone(),
            set_header,
        }),
    }
    if let Some(f) = fmt {
        req.credential_formats.insert(env.clone(), f);
    }
    if !service.is_some_and(|s| s.env_vars.contains(&env)) {
        req.credential_services
            .insert(env.clone(), c.service.clone());
    }
    if c.install && !c.runtime && !req.credential_install.contains(&env) {
        req.credential_install.push(env.clone());
    }
    let sorted_push = |v: &mut Vec<String>, items: &[String]| {
        v.extend(items.iter().cloned());
        v.sort();
        v.dedup();
    };
    sorted_push(&mut req.secrets, std::slice::from_ref(&c.service));
    sorted_push(&mut req.credential_env, std::slice::from_ref(&env));
    sorted_push(&mut req.credential_hosts, &hosts);
    Ok(())
}

/// `my-svc` → `MY_SVC`.
fn upper_env(service: &str) -> String {
    service
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect()
}

/// One script per profile file and kit, in plan order.
fn context_scripts(plan: &Plan) -> Result<Vec<String>> {
    let profile =
        agents::find(&plan.workload.name).map_or(agents::DEFAULT_CONTEXT_FILE, |a| a.context_file);
    let (profile_dir, profile_name) = profile.rsplit_once('/').expect("an absolute path");
    let mut sections: Vec<((String, String), Vec<&str>)> = Vec::new();
    for (kit, c) in &plan.merged.contexts {
        let dir = c.directory.as_deref().unwrap_or(profile_dir);
        if !dir.starts_with('/') {
            bail!("kit {kit}: agent-context directory '{dir}' must be an absolute path");
        }
        let name = c.filename.as_deref().unwrap_or(profile_name);
        let key = (format!("{}/{name}", dir.trim_end_matches('/')), kit.clone());
        match sections.iter_mut().find(|(k, _)| *k == key) {
            Some((_, bodies)) => bodies.push(&c.content),
            None => sections.push((key, vec![&c.content])),
        }
    }
    Ok(sections
        .iter()
        .map(|((file, kit), bodies)| guest::context_script_parts(file, kit, bodies))
        .collect())
}

/// The agent preset as a synthetic workload (`load::preset_kit`), not a kit the user chose.
fn is_preset(w: &Kit) -> bool {
    agents::find(&w.name).is_some_and(|a| {
        w.digest.is_none()
            && w.caps.is_empty()
            && matches!(w.content, Content::Image(_))
            && w.command.as_ref().is_some_and(|c| {
                c.len() == a.command.len() && c.iter().zip(a.command).all(|(x, y)| x == y)
            })
    })
}

/// A registry kit pinned to its digest, or a local kit's canonical path.
fn pinned_ref(k: &Kit) -> Result<String> {
    Ok(match &k.source {
        Source::Registry(r) if r.contains('@') => r.clone(),
        Source::Registry(r) => match &k.digest {
            Some(d) => format!("{r}@{d}"),
            None => bail!("kit {}: {r} has no digest to pin it to", k.name),
        },
        Source::LocalV3(p) | Source::LocalV2(p) | Source::Smolfile(p) => p
            .canonicalize()
            .unwrap_or_else(|_| p.clone())
            .display()
            .to_string(),
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::kits::args::ArgValues;
    use crate::kits::model::{
        AgentContextReq, Cap, CapBody, Content, CredReq, FileReq, Hook, HookCmd, Inject, Kind, Kit,
        Lifecycle, NetRule, OAuthReq, Rules, Source,
    };
    use crate::kits::resolve::resolve;
    use crate::sandbox::create;
    use crate::secrets::{SecretEntry, Source as SecretSource};

    fn kit(name: &str, kind: Kind) -> Kit {
        Kit {
            name: name.into(),
            source: Source::Registry(format!("acme/{name}:1")),
            digest: Some(format!("sha256:{}", "ab".repeat(32))),
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
    fn workload() -> Kit {
        let mut w = kit("wl", Kind::Workload);
        w.content = Content::Image("img:1".into());
        w.command = Some(vec!["wl".into(), "--go".into()]);
        w
    }
    fn with(mut k: Kit, ty: &str, optional: bool, body: CapBody) -> Kit {
        k.caps.push(Cap {
            ty: format!("com.docker.sandbox/{ty}"),
            optional,
            body,
        });
        k
    }
    fn rules(hosts: &[&str]) -> Rules {
        Rules {
            allow: hosts
                .iter()
                .map(|h| NetRule {
                    host: h.to_string(),
                    methods: vec![],
                    paths: vec![],
                })
                .collect(),
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
        }
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
    fn run(
        p: &Plan,
        req: &mut CreateRequest,
        policy: &mut Policy,
    ) -> Result<(KitSteps, Vec<String>)> {
        run_with(p, req, policy, &secrets(&[]))
    }
    fn run_with(
        p: &Plan,
        req: &mut CreateRequest,
        policy: &mut Policy,
        s: &SecretsFile,
    ) -> Result<(KitSteps, Vec<String>)> {
        apply(p, req, policy, s, Path::new("/nonexistent"), &no_git)
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
            assert_eq!(policy.find(id).unwrap().0.created_via, "kit:net");
        }
        // Applying again adds nothing new, so a rollback can't remove what was there.
        let mut again = request();
        let (steps, added) = run(&p, &mut again, &mut policy).unwrap();
        assert!(added.is_empty() && steps.install_rules.is_empty());
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
            ["anthropic=ANTHROPIC_API_KEY@api.anthropic.com"]
        );
        assert_eq!(req.secrets, ["anthropic"]);
        assert_eq!(req.credential_env, ["ANTHROPIC_API_KEY"]);
        assert_eq!(req.credential_hosts, ["api.anthropic.com"]);
        assert!(req.credential_services.is_empty());
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
            ["xsvc=SBX_KIT_XSVC@api.x.com:set-header=authorization"]
        );
        assert_eq!(
            req.credential_formats["SBX_KIT_XSVC"],
            crate::sandbox::labels::CredFormat::Format("Bearer %s".into())
        );
        assert_eq!(req.credential_services["SBX_KIT_XSVC"], "xsvc");
    }

    #[test]
    fn a_missing_required_credential_fails_and_an_optional_one_is_skipped() {
        let c = || cred("github", Some("GH_TOKEN"), vec![inject("github.com", None)]);
        let p = plan(vec![with(
            kit("gh", Kind::Mixin),
            "credential@1",
            false,
            c(),
        )]);
        let mut policy = Policy::default();
        let e = run(&p, &mut request(), &mut policy).unwrap_err();
        assert_eq!(
            format!("{e:#}"),
            "kit gh needs the github secret; set it with sbt secret set github"
        );
        assert_eq!(policy, Policy::default());

        let p = plan(vec![with(
            kit("gh", Kind::Mixin),
            "credential@1",
            true,
            c(),
        )]);
        let mut req = request();
        run(&p, &mut req, &mut policy).unwrap();
        assert!(req.credentials.is_empty());
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
        assert_eq!(req.credential_install, ["GH_TOKEN"]);
        c.runtime = true;
        let p = plan(vec![with(
            kit("gh", Kind::Mixin),
            "credential@1",
            false,
            CapBody::Credential(c),
        )]);
        let mut req = request();
        run_with(&p, &mut req, &mut Policy::default(), &secrets(&["github"])).unwrap();
        assert!(req.credential_install.is_empty());
    }

    #[test]
    fn passthrough_oauth_only_allows_its_hosts() {
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
        assert!(req.secrets.is_empty());

        let e = resolve(
            workload(),
            vec![with(kit("o", Kind::Mixin), "credential@1", false, o(false))],
            &ArgValues::default(),
        )
        .unwrap_err();
        assert!(format!("{e:#}").contains("without passthrough"), "{e:#}");
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
        assert_eq!(req.command, Some(vec!["wl".to_string(), "--go".into()]));
        let pinned = |n: &str| format!("acme/{n}:1@sha256:{}", "ab".repeat(32));
        assert_eq!(req.kits, [pinned("wl"), pinned("m")]);
        assert!(req.long_running);
        assert_eq!(
            steps.kits_record,
            format!("wl\t{}\t\nm\t{}\ta,b\n", pinned("wl"), pinned("m"))
        );
        let labels = create::spec(&req).labels;
        assert_eq!(labels["sbx.long-running"], "true");
        assert_eq!(labels["sbx.command"], r#"["wl","--go"]"#);
    }

    #[test]
    fn a_preset_workload_records_no_command_or_kit() {
        let agent = crate::agents::find("claude").unwrap();
        let w = crate::kits::load::preset_kit(agent, "preset:1");
        let p = resolve(w, vec![], &ArgValues::default()).unwrap();
        let mut req = request();
        let (steps, _) = run(&p, &mut req, &mut Policy::default()).unwrap();
        assert_eq!(req.command, None);
        assert!(req.kits.is_empty() && steps.kits_record.is_empty());
        assert_eq!(
            create::spec(&req).labels,
            create::meta(&request()).to_labels()
        );
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
    fn hooks_files_and_contexts_become_steps() {
        let hook = |cmd: &str, user: Option<&str>, background| Hook {
            command: HookCmd::Shell(cmd.into()),
            user: user.map(String::from),
            env: vec![],
            background,
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
            }),
        );
        let a = with(
            a,
            "agent-context@1",
            false,
            CapBody::AgentContext(AgentContextReq {
                filename: None,
                directory: None,
                content: "use x".into(),
            }),
        );
        let b = with(
            kit("b", Kind::Mixin),
            "lifecycle@1",
            false,
            CapBody::Lifecycle(Lifecycle {
                install: vec![hook("npm i -g y", Some("agent"), false)],
                startup: vec![],
                files: vec![file("/etc/x", "from b")],
            }),
        );
        let b = with(
            b,
            "agent-context@2",
            false,
            CapBody::AgentContext(AgentContextReq {
                filename: Some("NOTES.md".into()),
                directory: Some("/work".into()),
                content: "use y".into(),
            }),
        );
        let p = plan(vec![a, b]);
        let mut req = request();
        let (steps, _) = run(&p, &mut req, &mut Policy::default()).unwrap();
        assert_eq!(
            steps.install,
            [
                (
                    None,
                    r#"cd / && env -i PATH="$PATH" HOME="$HOME" sh -c 'apt-get install x'"#
                        .to_string()
                ),
                (
                    Some("agent".into()),
                    r#"cd / && env -i PATH="$PATH" HOME="$HOME" sh -c 'npm i -g y'"#.into()
                ),
            ]
        );
        assert_eq!(steps.files.len(), 1, "the later kit wins one path");
        assert!(steps.files[0].contains("'from b'"));
        assert_eq!(steps.context.len(), 2);
        // The workload `wl` isn't a preset: the generic profile file.
        assert!(
            steps.context[0].contains("'/home/agent/AGENTS.md'"),
            "{}",
            steps.context[0]
        );
        assert!(
            steps.context[1].contains("'/work/NOTES.md'"),
            "{}",
            steps.context[1]
        );
        let names: Vec<&str> = steps.startup_d.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, ["01-a.sh"]);
        assert!(
            steps.startup_d[0].1.contains("runuser -u 'agent'"),
            "{}",
            steps.startup_d[0].1
        );
    }

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
            Path::new("/nonexistent"),
            &git,
        )
        .unwrap();
        assert_eq!(
            steps.install,
            [(
                None,
                "git config --system user.name 'Ada L' && git config --system user.email 'ada@x.org'"
                    .to_string()
            )]
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
            ["github=GH_TOKEN@github.com,api.github.com:set-header=authorization"]
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
    fn an_unpinned_registry_kit_and_a_relative_context_directory_fail() {
        let mut m = kit("m", Kind::Mixin);
        m.digest = None;
        let e = run(&plan(vec![m]), &mut request(), &mut Policy::default()).unwrap_err();
        assert!(format!("{e:#}").contains("no digest"), "{e:#}");

        let ctx = CapBody::AgentContext(AgentContextReq {
            filename: None,
            directory: Some("rel/dir".into()),
            content: "x".into(),
        });
        let p = plan(vec![with(
            kit("c", Kind::Mixin),
            "agent-context@1",
            false,
            ctx,
        )]);
        let e = run(&p, &mut request(), &mut Policy::default()).unwrap_err();
        assert!(
            format!("{e:#}").contains("kit c: agent-context directory 'rel/dir'"),
            "{e:#}"
        );
    }
}
