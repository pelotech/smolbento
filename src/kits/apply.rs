//! Applies a resolved kit plan to a new sandbox: `CreateRequest` fields, the kits' policy rules,
//! and the guest steps the first start runs.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result, bail};

use crate::kits::compose;
use crate::kits::env_ref;
use crate::kits::guest;
use crate::kits::model::{CapBody, Content, CredReq, Delivery, Hook, Kit, Source};
use crate::kits::registry::auth::Logins;
use crate::kits::resolve::{KitContext, KitCred, Merged, Plan};
use crate::policy::Policy;
use crate::policy::rules::is_under;
use crate::sandbox::CreateRequest;
use crate::sandbox::labels::CredFormat;
use crate::sandbox::labels::KitRecord;
use crate::sandbox::options::{free_port, parse_memory};
use crate::secrets::store::SecretStore;
use crate::secrets::{SecretsFile, services};
use crate::smolvm::{Credential, PortMap};
use crate::ssh_agent as agent;
use crate::util::union;

/// Guest steps for a sandbox's first start (and `kit add`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KitSteps {
    /// Policy rule ids to remove once the install hooks have run.
    pub install_rules: Vec<String>,
    /// Run with `sh -c` in order.
    pub install: Vec<InstallStep>,
    /// Scripts writing kit files (as root, then owned by `agent`).
    pub files: Vec<String>,
    /// Scripts writing agent context: the agent file, kit context files and their index.
    pub context: Vec<String>,
    /// `(file name "NN-<kit>.sh", body)` for `/etc/smolbento/startup.d`, in run order.
    pub startup_d: Vec<(String, String)>,
    /// Every kit's name, in order: each gets an install progress event.
    pub kit_names: Vec<String>,
    /// A v3 workload's non-root image user, given back what root left in their home after the
    /// last root write (`guest::home_to_user`).
    pub home_owner: Option<String>,
}

/// One install-time guest script.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InstallStep {
    /// Names the step in errors, e.g. `kit a install hook 2`.
    pub label: String,
    /// The kit whose hook this is; `None` for smolbento's own steps (git identity, bundled skills).
    pub kit: Option<String>,
    /// The exec user; `None` is root.
    pub user: Option<String>,
    pub script: String,
    /// Relay a successful run's stderr as warnings (the bundled skills step's skipped skills).
    pub relay_stderr: bool,
}

/// The kits' variables, with a variable's reference to itself (`PATH: /x:$PATH`) replaced by the
/// image's value (`env_ref`). The image's environment is read only when one does.
fn expand_self_references(
    plan: &Plan,
    env: &[(String, String)],
    image_env: impl FnOnce() -> Result<Option<Vec<String>>>,
) -> Result<Vec<(String, String)>> {
    let Some((first, _)) = env.iter().find(|(k, v)| env_ref::refers_to_itself(k, v)) else {
        return Ok(env.to_vec());
    };
    let image = image_env()
        .with_context(|| format!("reading the image's environment for the kits' {first}"))?
        .with_context(|| {
            format!(
                "a kit's {first} refers to the image's {first}, which smolbento can't read for \
                 {}'s image",
                plan.workload.name
            )
        })?;
    Ok(env
        .iter()
        .map(|(k, v)| {
            (
                k.clone(),
                env_ref::expand(k, v, env_ref::image_value(&image, k)),
            )
        })
        .collect())
}

/// Fills `req` from the plan and writes the kits' policy rules (install-phase ones too: they must
/// be in place while install hooks run). Returns the steps for the first start and the ids of
/// every rule this call added, for rollback. Nothing is written to `policy` on error.
pub fn apply(
    plan: &Plan,
    req: &mut CreateRequest,
    policy: &mut Policy,
    secrets: &SecretsFile,
    store: &dyn SecretStore,
    cache: &Path,
    host_git: &dyn Fn() -> Option<(String, String)>,
) -> Result<(KitSteps, Vec<String>)> {
    let m = &plan.merged;
    let kits: Vec<&Kit> = std::iter::once(&plan.workload)
        .chain(&plan.mixins)
        .collect();
    let mut steps = KitSteps::default();
    let registries = secrets.registries_for(&req.name);
    let logins = Logins::new(&registries, store);

    match &plan.workload.content {
        Content::Smolfile(path) => {
            if !compose::layered_names(plan)?.is_empty() {
                bail!("mixins with image layers can't be added to a Smolfile kit");
            }
            req.image.clear();
            req.smolfile = Some(path.clone());
        }
        _ => req.image = compose::image_for(plan, cache, logins)?,
    }
    let kit_env = expand_self_references(plan, &m.env, || compose::image_env(plan, cache, logins))?;

    apply_resources(req, m)?;
    // The user's -e wins over a kit's variable.
    for (k, v) in &kit_env {
        crate::util::env_default(&mut req.env, k, v.clone());
    }
    for &(guest, udp) in &m.ports {
        if !req.ports.iter().any(|p| p.guest == guest && p.udp == udp) {
            let p = PortMap {
                host: free_port()?,
                guest,
                udp,
            };
            // Picked again at each start, as sbx.
            req.rec.auto_ports.push(p.arg());
            req.ports.push(p);
        }
    }
    let tmpfs = add_volumes(req, &m.volumes);

    // The user's own secrets' credentials, already in `req`: kit bindings merge with them.
    let user_creds = user_credentials(req, secrets);
    let mut notes = Vec::new();
    for kc in &m.credentials {
        // `resolve` added its hosts to the kit's network rules.
        if let Some(note) = oauth_note(kc, req.rec.secrets.contains(&kc.req.service))
            && !notes.contains(&note)
        {
            notes.push(note);
        }
        if kc.req.env.is_some() || !kc.req.inject.is_empty() {
            bind_credential(kc, req, secrets, &user_creds, &mut notes)?;
        }
    }
    drop_service_variables(req, &m.credentials);

    for (kit, h) in m.install_hooks.iter().chain(&m.startup_hooks) {
        if let Some(v) = h.env.iter().find(|v| !guest::is_env_name(v)) {
            bail!("kit {kit}: hook env '{v}' is not a valid variable name");
        }
    }
    // Before `req.workdir()`: a mountless sandbox works there (SPEC sbx@1/workspace-at-workdir).
    req.rec.image_workdir = image_workdir(&plan.workload).map(String::from);
    let runtime_only = runtime_only_vars(&m.credentials, &user_creds);
    steps
        .install
        .extend(kit_install_steps(plan, req, &runtime_only));
    steps.home_owner = image_user(plan).map(String::from);
    // `resolve` refuses two kits writing one path.
    steps.files = m.files.iter().map(guest::file_script).collect();
    let (context_version, contexts) = select_contexts(&m.contexts, req.rec.agent_context)?;
    let agent_files = if req.rec.agent_files.is_empty() {
        agent_files(&plan.workload.name, &contexts, &req.workdir())?
    } else {
        req.rec.agent_files.clone()
    };
    let mounts: Vec<&Path> = req.workspaces.iter().map(|w| w.path.as_path()).collect();
    steps.context = context_scripts(
        &plan.workload.name,
        context_version,
        &contexts,
        &agent_files,
        &mounts,
    )?;
    // Settled by the first text written: until then a later kit is free to choose.
    if !steps.context.is_empty() {
        req.rec.agent_context = context_version;
    }
    req.launched_by_host = plan
        .workload
        .caps
        .iter()
        .any(|c| matches!(c.body, CapBody::Sbx));
    set_workload_fields(req, &plan.workload, agent_files);
    // After the workload's fields: a startup hook without `user:` runs as the workload user (the
    // session user, root for `_builder`).
    let user = req.rec.workload_user(&req.name);
    steps.startup_d = startup_d(&kits, m, &tmpfs, user);
    if m.git_identity
        && let Some(step) = git_identity_step(&kits, host_git(), user)?
    {
        steps.install.insert(0, step);
    }
    record_kits(&kits, &plan.args, req)?;
    steps.kit_names = req.rec.kits.iter().map(|k| k.name.clone()).collect();
    req.rec.long_running = m.long_running;
    // `sbx.docker` records a `dockerd@1` grant; the engine start reads it on every boot. A
    // workload's `provides` lists its tools, not an engine.
    req.engine = m.dockerd;

    // Last, so an error above leaves the policy untouched.
    let added = add_policy(policy, &req.name, m, &mut steps.install_rules)?;
    for note in notes {
        eprintln!("{note}");
    }
    Ok((steps, added))
}

/// What to say about an OAuth credential: passthrough tokens live in the sandbox; otherwise its
/// subscription login happens there, unless the service's API key is `bound` (then nothing).
fn oauth_note(kc: &KitCred, bound: bool) -> Option<String> {
    let o = kc.req.oauth.as_ref()?;
    let (kit, svc) = (&kc.kit, &kc.req.service);
    if o.passthrough {
        return Some(format!(
            "note: kit {kit}: {svc} OAuth tokens live in the sandbox (passthrough)"
        ));
    }
    (!bound).then(|| {
        format!(
            "note: no {svc} API key is set, so {kit} asks you to log in inside the sandbox (its \
             tokens stay there). To use a key kept on the host: `bento secret set {svc}`, then \
             recreate the sandbox"
        )
    })
}

/// Kit `resources@1` fill the cpus and memory the user didn't set.
fn apply_resources(req: &mut CreateRequest, m: &Merged) -> Result<()> {
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
    Ok(())
}

/// Adds the kits' volumes to `req`; returns the tmpfs ones with their modes.
fn add_volumes(
    req: &mut CreateRequest,
    volumes: &[crate::kits::resolve::Volume],
) -> Vec<(String, Option<String>)> {
    let mut tmpfs = Vec::new();
    for v in volumes {
        if v.tmpfs {
            req.tmpfs.push(v.path.clone());
            tmpfs.push((v.path.clone(), v.mode.clone()));
        } else {
            req.volumes.push(v.path.clone());
        }
    }
    tmpfs
}

/// A kit that takes a built-in service's key without naming a variable (Claude's, whose
/// apiKeyHelper reads it) gets it only that way, as in sbx: the service's own variable from the
/// user's secret (`ANTHROPIC_API_KEY`) would make the agent ask whether to use a key it doesn't
/// know. Other sandboxes keep the variable.
fn drop_service_variables(req: &mut CreateRequest, kit_creds: &[KitCred]) {
    // A variable another kit names stays: that kit asked for it.
    let named: Vec<&str> = kit_creds
        .iter()
        .filter_map(|kc| kc.req.env.as_deref())
        .collect();
    let vars: Vec<String> = kit_creds
        .iter()
        // Bound: a kit credential that was skipped leaves the user's variable the only way in.
        .filter(|kc| kc.req.env.is_none() && req.rec.credential_env.contains(&kit_env(&kc.req)))
        .filter_map(|kc| services::builtin(&kc.req.service))
        .flat_map(|s| s.env_vars)
        .filter(|v| !named.contains(&v.as_str()))
        .collect();
    req.credentials.retain(|c| !vars.contains(&c.env_var));
    req.rec.credential_env.retain(|e| !vars.contains(e));
}

/// The variables of runtime-only kit credentials, which install hooks don't get even when they
/// declare them (`tck: credential@1/sentinel-phase-scoped`). Not one an install-phase credential
/// or the user's own secret also binds.
fn runtime_only_vars(creds: &[KitCred], user_creds: &[(String, String)]) -> Vec<String> {
    let install: Vec<String> = creds
        .iter()
        .filter(|kc| kc.req.install)
        .map(|kc| kit_env(&kc.req))
        .collect();
    creds
        .iter()
        .filter(|kc| !kc.req.install)
        .map(|kc| kit_env(&kc.req))
        // Only valid names reach a v2 hook's `unset`: an unbound credential's is never checked.
        .filter(|v| guest::is_env_name(v))
        .filter(|v| !install.contains(v) && !user_creds.iter().any(|(e, _)| e == v))
        .collect()
}

/// The variable a kit credential binds: the one it names, else `SBX_KIT_<SERVICE>`.
fn kit_env(c: &CredReq) -> String {
    c.env
        .clone()
        .unwrap_or_else(|| format!("SBX_KIT_{}", upper_env(&c.service)))
}

/// `(env var, service)` for each credential already in `req`; the service is empty when the
/// credential isn't one of the user's own secrets.
fn user_credentials(req: &CreateRequest, secrets: &SecretsFile) -> Vec<(String, String)> {
    req.credentials
        .iter()
        .map(|c| {
            let service = secret_owning(&req.rec.secrets, secrets, &c.env_var)
                .cloned()
                .unwrap_or_default();
            (c.env_var.clone(), service)
        })
        .collect()
}

/// The one of the user's `services` whose secret sets `env`.
fn secret_owning<'a>(
    services: &'a [String],
    secrets: &SecretsFile,
    env: &str,
) -> Option<&'a String> {
    services.iter().find(|s| {
        secrets
            .service(s)
            .is_some_and(|sv| sv.env_vars.iter().any(|e| e == env))
    })
}

/// The first install step, setting the session user's global git identity from the host's `git`.
/// Without one on the host it's an error when a kit requires it, else a warning.
fn git_identity_step(
    kits: &[&Kit],
    host: Option<(String, String)>,
    session: &str,
) -> Result<Option<InstallStep>> {
    let required = kits.iter().find(|k| {
        k.caps
            .iter()
            .any(|c| matches!(c.body, CapBody::GitIdentity) && !c.optional)
    });
    match (host, required) {
        (Some((name, email)), _) => Ok(Some(InstallStep {
            label: "the git identity step".into(),
            kit: None,
            user: Some(session.to_string()),
            script: guest::git_identity_script(&name, &email),
            relay_stderr: false,
        })),
        (None, Some(k)) => bail!(
            "kit {} needs your git identity; set it with `git config --global user.name …` \
             and `git config --global user.email …`",
            k.name
        ),
        (None, None) => {
            crate::warning!("no git user.name/user.email on the host; skipping git-identity");
            Ok(None)
        }
    }
}

/// The request fields the workload kit sets. A v3 workload's agent runs as its image's user, root
/// when the image names none.
fn set_workload_fields(req: &mut CreateRequest, workload: &Kit, agent_files: Vec<String>) {
    req.rec.command = workload.command.clone();
    // `kit add` can't reload the workload: it reads this back from `sbx.agent-file`.
    req.rec.agent_files = agent_files;
    req.rec.user = workload.config.as_ref().map(|c| match c.user.as_str() {
        "" => "0".to_string(),
        u => u.to_string(),
    });
}

/// Each kit's record, with the args it resolved with, pushed on `req.kits` (the `sbx.kits` label).
fn record_kits(
    kits: &[&Kit],
    args: &BTreeMap<String, BTreeMap<String, String>>,
    req: &mut CreateRequest,
) -> Result<()> {
    for k in kits {
        let mut r = kit_record(k)?;
        r.args = args.get(&k.name).cloned().unwrap_or_default();
        req.rec.kits.push(r);
    }
    Ok(())
}

/// The `sbx.kits` record of an applied kit.
pub fn kit_record(k: &Kit) -> Result<KitRecord> {
    Ok(KitRecord {
        name: k.name.clone(),
        reference: pinned_ref(k)?,
        provides: k.provides.clone(),
        // None for a kit that mixes with either.
        format: crate::kits::resolve::mixing_format(k),
        args: BTreeMap::new(),
    })
}

/// The workload image's WORKDIR, unless it's unset, `/` or relative.
pub fn image_workdir(workload: &Kit) -> Option<&str> {
    workload
        .config
        .as_ref()
        .map(|c| c.workdir.as_str())
        .filter(|d| d.starts_with('/') && *d != "/")
}

/// A v3 workload's image user, unless that's root.
fn image_user(plan: &Plan) -> Option<&str> {
    (plan.workload.config.as_ref())
        .map(|c| c.user.as_str())
        .filter(|u| !crate::sandbox::labels::is_root_user(u))
}

/// The kits' install hooks as steps, numbered per kit. They run in the workload image's WORKDIR,
/// as sbx runs them (`/` without one), and see `SSH_AUTH_SOCK` only with an install grant (a
/// clean-env hook only when it declares it); a runtime grant's create-time variable is unset for
/// them. One run as root has the image user's `HOME` (SPEC sbx@1/honors-image-user).
fn kit_install_steps(
    plan: &Plan,
    req: &CreateRequest,
    runtime_only: &[String],
) -> Vec<InstallStep> {
    let install_dir =
        image_workdir(&plan.workload).map_or_else(|| "/".to_string(), crate::util::sh_quote);
    let image_home = image_user(plan).map(guest::image_home).unwrap_or_default();
    let granted = req.ssh_agent.as_ref();
    let agent_env = if granted.is_some_and(|a| a.install.is_some()) {
        format!("export SSH_AUTH_SOCK={} && ", agent::GUEST_SOCKET)
    } else if granted.is_some_and(|a| a.runtime.is_some()) {
        "unset SSH_AUTH_SOCK && ".to_string()
    } else {
        String::new()
    };
    let mut steps = Vec::new();
    let mut per_kit: BTreeMap<&str, usize> = BTreeMap::new();
    for (kit, h) in &plan.merged.install_hooks {
        let n = *per_kit.entry(kit).and_modify(|n| *n += 1).or_insert(1);
        let mut h = h.clone();
        h.env.retain(|v| !runtime_only.contains(v));
        // A hook that inherits the sandbox's environment (v2's) would still see them.
        let unset = if h.clean_env || runtime_only.is_empty() {
            String::new()
        } else {
            format!("unset {} && ", runtime_only.join(" "))
        };
        steps.push(InstallStep {
            label: format!("kit {kit} install hook {n}"),
            kit: Some(kit.to_string()),
            user: h.user.clone(),
            script: format!(
                "{}cd {install_dir} && {agent_env}{unset}{}",
                if h.user.is_none() { &image_home } else { "" },
                guest::hook_script(&h)
            ),
            relay_stderr: false,
        });
    }
    steps
}

/// The `startup.d` scripts: tmpfs volumes first, then each kit's startup hooks, in kit order.
/// `session`: the user a hook without `user:` runs as (SPEC lifecycle@1/default-users: the agent
/// user for startup, as sessions run; v2 kits already name `agent`).
fn startup_d(
    kits: &[&Kit],
    m: &Merged,
    tmpfs: &[(String, Option<String>)],
    session: &str,
) -> Vec<(String, String)> {
    let mut out = Vec::new();
    if !tmpfs.is_empty() {
        out.push(("00-volumes.sh".into(), guest::tmpfs_script(tmpfs)));
    }
    let mut n = 0;
    for k in kits {
        let hooks: Vec<Hook> = m
            .startup_hooks
            .iter()
            .filter(|(kit, _)| *kit == k.name)
            .map(|(_, h)| Hook {
                user: h.user.clone().or_else(|| Some(session.to_string())),
                ..h.clone()
            })
            .collect();
        if !hooks.is_empty() {
            n += 1;
            let hooks: Vec<&Hook> = hooks.iter().collect();
            out.push((
                format!("{n:02}-{}.sh", k.name),
                guest::startup_script(&k.name, &hooks),
            ));
        }
    }
    out
}

/// Writes the kits' rules for sandbox `sandbox` and returns the ids it added, for rollback. Runtime
/// rules go first: an install rule that is also a runtime rule must outlive the install phase.
/// Every install rule in place goes into `install_rules`, to be removed after the install hooks
/// (one an interrupted `kit add` left too); only new ones are returned. A failure part-way through (a bad
/// host) restores the policy as it was.
fn add_policy(
    policy: &mut Policy,
    sandbox: &str,
    m: &Merged,
    install_rules: &mut Vec<String>,
) -> Result<Vec<String>> {
    let snapshot = policy.clone();
    let mut added = Vec::new();
    let mut add = |policy: &mut Policy| -> Result<()> {
        for k in &m.network {
            added.extend(policy.add_kit_rules(sandbox, &k.kit, &k.runtime, false)?.1);
        }
        for k in &m.network {
            let (all, new) = policy.add_kit_rules(sandbox, &k.kit, &k.install, true)?;
            for id in all {
                let is_install = policy
                    .rules_for(Some(sandbox))
                    .any(|(r, s)| s.is_some() && r.id == id && r.is_kit_install());
                if is_install && !install_rules.contains(&id) {
                    install_rules.push(id);
                }
            }
            added.extend(new);
        }
        Ok(())
    };
    if let Err(e) = add(policy) {
        *policy = snapshot;
        return Err(e);
    }
    Ok(added)
}

/// Whether a kit's inject `host` is one of a service's own `hosts`: the same host, or one its
/// `*.x` pattern covers.
fn host_within(host: &str, hosts: &[String]) -> bool {
    let host = host.to_ascii_lowercase();
    hosts.iter().any(|s| {
        let s = s.to_ascii_lowercase();
        match s.strip_prefix("*.") {
            None => host == s,
            Some(d) => {
                let h = host.strip_prefix("*.").unwrap_or(&host);
                (h == d && host.starts_with("*.")) || is_under(h, d)
            }
        }
    })
}

/// Skips an optional credential with a warning saying `why`; a required one fails with `why` and
/// `refusing`.
fn optional_or_bail(kc: &KitCred, why: String, refusing: &str) -> Result<()> {
    if kc.optional {
        crate::kit_warning!("{why}; skipping its optional credential");
        return Ok(());
    }
    bail!("{why}{refusing}");
}

/// Binds a kit credential through the user's secrets: a smolvm credential whose value
/// `start` resolves from the service's secret. `user_creds`: (env var, service) of the
/// credentials `req` already had from the user's secrets. A built-in service's secret only goes
/// to that service's own hosts (R24); a custom service's goes where the kit says, with a note.
fn bind_credential(
    kc: &KitCred,
    req: &mut CreateRequest,
    secrets: &SecretsFile,
    user_creds: &[(String, String)],
    notes: &mut Vec<String>,
) -> Result<()> {
    let c: &CredReq = &kc.req;
    // An MCP server's secret goes to that server's host only (`--static-mcp`), never to a host a
    // kit names.
    if c.service.starts_with("mcp:") {
        let why = format!(
            "kit {} asks for {}, an MCP server's secret, which kits can't use",
            kc.kit, c.service
        );
        return optional_or_bail(kc, why, "");
    }
    let service = secrets.service(&c.service);
    // Checked before asking for the secret: setting it wouldn't help.
    if let Some(builtin) = services::builtin(&c.service) {
        let outside =
            union((c.inject.iter().map(|i| &i.domain)).filter(|d| !host_within(d, &builtin.hosts)));
        if !outside.is_empty() {
            let why = format!(
                "kit {} wants to send your {} secret to {}, which {} doesn't use",
                kc.kit,
                c.service,
                outside.join(", "),
                c.service
            );
            return optional_or_bail(kc, why, "; refusing");
        }
    }
    if secrets.entry_for(&req.name, None, &c.service).is_none() {
        // A required one fails, as the kit spec says (sbx warns and the requests go out without it).
        let host = c.inject.first().map_or("HOST", |i| i.domain.as_str());
        return optional_or_bail(kc, missing_secret(&kc.kit, &c.service, host), "");
    }
    let env = kit_env(c);
    if !guest::is_env_name(&env) {
        bail!("kit {}: '{env}' is not a valid variable name", kc.kit);
    }
    let mut hosts = union(c.inject.iter().map(|i| &i.domain));
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
    if services::builtin(&c.service).is_none() {
        let note = custom_service_note(&kc.kit, &c.service, &hosts);
        if !notes.contains(&note) {
            notes.push(note);
        }
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

    // One variable holds one value: a binding of it merges with the existing one.
    match req.credentials.iter_mut().find(|x| x.env_var == env) {
        Some(x) => {
            let user = user_creds.iter().find(|(e, _)| *e == env);
            let owner = match user {
                Some((_, s)) => Some(s),
                None => (req.rec.credential_services.get(&env))
                    .or_else(|| secret_owning(&req.rec.secrets, secrets, &env)),
            };
            if owner.is_some_and(|s| *s != c.service) {
                bail!(
                    "kit {}: {env} is already bound to the {} secret, not {}",
                    kc.kit,
                    owner.map_or("", |s| s.as_str()),
                    c.service
                );
            }
            // Two bindings of the same variable must agree on how smolvm injects it.
            if x.set_header != set_header || req.rec.credential_formats.get(&env) != fmt.as_ref() {
                let other = match user {
                    Some(_) => format!("your {} secret", c.service),
                    None => "another kit".to_string(),
                };
                bail!(
                    "kit {}: the {} credential ({env}) is injected differently by {other}",
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
            env_var: env.clone(),
            hosts: hosts.clone(),
            set_header,
        }),
    }
    if let Some(f) = fmt {
        req.rec.credential_formats.insert(env.clone(), f);
    }
    if !service.is_some_and(|s| s.env_vars.contains(&env)) {
        req.rec
            .credential_services
            .insert(env.clone(), c.service.clone());
    }
    // The user's own secret stays set at runtime.
    let user = user_creds.iter().any(|(e, _)| *e == env);
    if c.inject_only() && !user && !req.host_only_env.contains(&env) {
        req.host_only_env.push(env.clone());
    }
    if c.install && !c.runtime && !user && !req.rec.credential_install.contains(&env) {
        req.rec.credential_install.push(env.clone());
    }
    let sorted_push = |v: &mut Vec<String>, items: &[String]| {
        v.extend(items.iter().cloned());
        v.sort();
        v.dedup();
    };
    sorted_push(&mut req.rec.secrets, std::slice::from_ref(&c.service));
    sorted_push(&mut req.rec.credential_env, std::slice::from_ref(&env));
    sorted_push(&mut req.rec.credential_hosts, &hosts);
    Ok(())
}

/// What a kit credential whose secret isn't set needs, with the command that sets it. A custom
/// service is named after `set-custom`'s `--env` (lowercased, `_` as `-`), so the hint names the
/// variable that gives `service`, or says no variable does.
fn missing_secret(kit: &str, service: &str, host: &str) -> String {
    if services::builtin(service).is_some() {
        return format!(
            "kit {kit} needs the {service} secret; set it with bento secret set {service}"
        );
    }
    let env = upper_env(service);
    if guest::is_env_name(&env) && env.to_ascii_lowercase().replace('_', "-") == service {
        format!(
            "kit {kit} needs the {service} secret; set it with \
             bento secret set-custom --env {env} --host {host}"
        )
    } else {
        format!(
            "kit {kit} needs a custom secret service named {service}, which \
             `bento secret set-custom` can't define: it names a service after its --env variable, \
             lowercased with '_' as '-'"
        )
    }
}

/// What create and `kit add` print when a kit binds a custom service's secret (R24).
fn custom_service_note(kit: &str, service: &str, hosts: &[String]) -> String {
    format!(
        "note: kit {kit} sends your {service} secret to {}",
        hosts.join(", ")
    )
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

/// SPEC agent-context@2/size-budget: warn above 64 KiB, refuse above 512 KiB.
const CONTEXT_WARN_BYTES: usize = 64 * 1024;
const CONTEXT_MAX_BYTES: usize = 512 * 1024;

/// The agent file's name for a workload kit's `agent-context` without a `filename`.
const DEFAULT_CONTEXT_FILE: &str = "AGENTS.md";

/// The `agent-context` requests a sandbox applies, and their version. A sandbox uses one version
/// for all its kits (SPEC agent-context@2/mixed-versions refuses `@1` and `@2` together): `pin`
/// when it already has one (`kit add`), else `@2`, unless a kit requires `@1` or none offers `@2`.
/// Requests of the
/// other version are skipped when optional (a kit left with none gets a warning) and an error
/// when required.
pub fn select_contexts(
    all: &[KitContext],
    pin: Option<u8>,
) -> Result<(Option<u8>, Vec<&KitContext>)> {
    if all.is_empty() {
        return Ok((pin, Vec::new()));
    }
    let required = |v: u8| all.iter().find(|c| c.version == v && !c.optional);
    let offers_2 = all.iter().any(|c| c.version == 2);
    let version = pin.unwrap_or(if required(1).is_some() || !offers_2 {
        1
    } else {
        2
    });
    let other = if version == 1 { 2 } else { 1 };
    if let Some(c) = required(other) {
        match (pin, required(version)) {
            (None, Some(mine)) => bail!(
                "kit {} needs agent-context@{version} and kit {} needs agent-context@{other}, \
                 and a sandbox uses one version; use kits that offer the same version (a kit \
                 can offer both as optional)",
                mine.kit,
                c.kit
            ),
            _ => bail!(
                "kit {}: needs agent-context@{other}, but this sandbox's kits use \
                 agent-context@{version}, and a sandbox uses one version; recreate it with the \
                 kit",
                c.kit
            ),
        }
    }
    let dropped = all.iter().map(|c| &*c.kit);
    warn_once(
        dropped.filter(|k| !all.iter().any(|o| o.kit == *k && o.version == version)),
        |kit| {
            format!(
                "kit {kit}: agent-context@{other} skipped (this sandbox's kits use \
                 agent-context@{version})"
            )
        },
    );
    let kept = all.iter().filter(|c| c.version == version).collect();
    Ok((Some(version), kept))
}

/// Warns once for each kit in KITS, in order, with WARNING's text for it.
fn warn_once<'a>(kits: impl Iterator<Item = &'a str>, warning: impl Fn(&str) -> String) {
    let mut told: Vec<&str> = Vec::new();
    for kit in kits {
        if !told.contains(&kit) {
            told.push(kit);
            crate::kit_warning!("{}", warning(kit));
        }
    }
}

/// The agent files in the guest, each of which gets every kit's agent context. They are the
/// explicit profiles (`directory` and `filename`) any kit declares, each once, in kit order
/// (SPEC agent-context `every-explicit-profile`, `profile-precedence`). With none, it is the
/// workload kit's own file in the parent of `workdir` (sbx #15), the legacy profile; a mixin
/// can't name that one. Empty when no kit declares a file.
pub fn agent_files(workload: &str, contexts: &[&KitContext], workdir: &str) -> Result<Vec<String>> {
    let mut explicit = Vec::new();
    for c in contexts {
        if let Some(dir) = &c.req.directory {
            let file = profile_path(&c.kit, dir, c.req.filename.as_deref())?;
            if !explicit.contains(&file) {
                explicit.push(file);
            }
        }
    }
    if !explicit.is_empty() {
        return Ok(explicit);
    }
    let Some(own) = contexts.iter().find(|c| c.kit == workload) else {
        return Ok(Vec::new());
    };
    let parent = Path::new(workdir)
        .parent()
        .map_or_else(|| "/".to_string(), |p| p.display().to_string());
    let file = profile_path(workload, &parent, own.req.filename.as_deref())?;
    Ok(vec![file])
}

/// `dir/name` for kit `kit`'s agent file, checked: an absolute directory and a plain file name.
fn profile_path(kit: &str, dir: &str, name: Option<&str>) -> Result<String> {
    if !dir.starts_with('/') {
        bail!("kit {kit}: agent-context directory '{dir}' must be an absolute path");
    }
    // A lexical check only: symlinks inside the guest are out of scope.
    if dir.split('/').any(|c| c == "..") {
        bail!("kit {kit}: agent-context directory '{dir}' must not contain '..'");
    }
    let name = name.unwrap_or(DEFAULT_CONTEXT_FILE);
    if name.is_empty() || name.contains('/') || name == "." || name == ".." {
        bail!("kit {kit}: agent-context filename '{name}' must be a file name");
    }
    let file = format!("{}/{name}", dir.trim_end_matches('/'));
    // The `sbx.agent-file` label lists the files, comma-separated.
    if file.contains(',') {
        bail!("kit {kit}: agent-context file '{file}' must not contain ','");
    }
    Ok(file)
}

/// Writes the kits' agent context to each agent file, which is the guest's own: nothing is
/// written into a mounted workspace.
///
/// Inline text goes in the file itself, in its kits section, joined with two newlines and not
/// trimmed: under `agent-context@2`, the workload kit's text and a mixin's `delivery: inline` text
/// (SPEC agent-context@2/complete-content). The rest is progressive: the section's index lists
/// where each kit's text is, for the agent to read when it needs it (SPEC
/// agent-context@1/progressive-surfacing, @2/delivery). A `contentFile` (`@1`) is listed where the
/// kit image has it; other text is written to `<dir>/kits-agent-context/<kit>.md` first.
/// A profile is written whenever a kit asks for one, with the runtime's guidance even if no kit has
/// text (SPEC agent-context@1/workload-filename-is-profile).
fn context_scripts(
    workload: &str,
    version: Option<u8>,
    contexts: &[&KitContext],
    agent_files: &[String],
    mounts: &[&Path],
) -> Result<Vec<String>> {
    let asks = contexts;
    let has_body =
        |c: &&&KitContext| !c.req.content.trim().is_empty() || c.req.content_file.is_some();
    let contexts: Vec<&&KitContext> = asks.iter().filter(has_body).collect();
    // SPEC agent-context@2/size-budget. shortcut: the bodies' bytes stand for the serialized
    // descriptor, which smolbento never builds; upgrade if the descriptor's own overhead matters.
    let size: usize = contexts.iter().map(|c| c.req.content.len()).sum();
    if size > CONTEXT_MAX_BYTES {
        bail!("agent context is {size} bytes, over the {CONTEXT_MAX_BYTES} byte budget");
    }
    if size > CONTEXT_WARN_BYTES {
        crate::kit_warning!(
            "agent context is {size} bytes; the advisory budget is {CONTEXT_WARN_BYTES}"
        );
    }
    if agent_files.is_empty() {
        let mixins = contexts.iter().map(|c| &*c.kit).filter(|k| *k != workload);
        warn_once(mixins, |kit| {
            format!("kit {kit}: agent context dropped (no kit declares an agent file)")
        });
        return Ok(Vec::new());
    }
    // No kit asks for a profile (a `kit add` of a kit without agent context): nothing to write.
    if asks.is_empty() {
        return Ok(Vec::new());
    }
    // SPEC agent-context@2/profile-precedence: a profile is required when an ask naming it is, and
    // an undirected ask counts toward the first.
    let required = |i: usize, file: &str| {
        asks.iter().any(|c| {
            !c.optional
                && match &c.req.directory {
                    Some(d) => {
                        profile_path(&c.kit, d, c.req.filename.as_deref()).is_ok_and(|p| p == file)
                    }
                    None => i == 0,
                }
        })
    };
    let inline = |c: &KitContext| {
        version == Some(2) && (c.kit == workload || c.req.delivery == Delivery::Inline)
    };
    let text: Vec<&str> = (contexts.iter().filter(|c| inline(c)))
        .map(|c| c.req.content.as_str())
        .collect();
    let text = text.join("\n\n");
    let indexed: Vec<&&&KitContext> = contexts.iter().filter(|c| !inline(c)).collect();
    let mut scripts = Vec::new();
    for (i, file) in agent_files.iter().enumerate() {
        let dir = file.rsplit_once('/').map_or("", |(d, _)| d);
        let index_dir = format!("{dir}/{}", guest::KITS_CONTEXT_DIR);
        if mounts.iter().any(|m| Path::new(file).starts_with(m)) {
            if required(i, file) {
                bail!(
                    "required agent context can't be written: {file} is in a mounted workspace, \
                     outside the sandbox"
                );
            }
            crate::warning!(
                "agent context not written: {file} is in a mounted workspace, outside the \
                 sandbox"
            );
            continue;
        }
        // SPEC agent-context@2/delivery: refused rather than loaded inline.
        if !indexed.is_empty() && mounts.iter().any(|m| Path::new(&index_dir).starts_with(m)) {
            bail!(
                "agent context can't be written for {file}: {index_dir} is in a mounted \
                 workspace, outside the sandbox"
            );
        }
        // In kit order: one entry per staged file, and one per kit's own file.
        let mut entries: Vec<(String, String)> = Vec::new();
        for c in &indexed {
            if let Some(staged) = &c.req.content_file {
                entries.push((c.kit.clone(), staged.clone()));
                continue;
            }
            let path = format!("{index_dir}/{}.md", c.kit);
            if entries.iter().any(|(_, p)| *p == path) {
                continue;
            }
            let bodies: Vec<&str> = (indexed.iter())
                .filter(|o| o.kit == c.kit && o.req.content_file.is_none())
                .map(|o| o.req.content.as_str())
                .collect();
            scripts.push(guest::kit_context_script(&path, &bodies));
            entries.push((c.kit.clone(), path));
        }
        scripts.push(guest::kits_section_script(file, &text, &entries));
    }
    Ok(scripts)
}

/// A registry kit pinned to its digest, a shipped kit as `builtin:<name>`, or a local kit's
/// canonical path.
fn pinned_ref(k: &Kit) -> Result<String> {
    Ok(match &k.source {
        Source::Registry(r) | Source::Agent(r) if r.contains('@') => r.clone(),
        Source::Registry(r) | Source::Agent(r) => match &k.digest {
            Some(d) => format!("{r}@{d}"),
            None => bail!("kit {}: {r} has no digest to pin it to", k.name),
        },
        Source::Builtin(n) => format!("builtin:{n}"),
        Source::Local(p) | Source::Smolfile(p) => p
            .canonicalize()
            .unwrap_or_else(|_| p.clone())
            .display()
            .to_string(),
    })
}

/// What in `kit` only a create can apply (spec "Data flow", `kit add`), in a fixed order. `args`
/// are the kit's argument values: one that the kit exports (`env:`) is a variable to set.
pub fn needs_recreate(kit: &Kit, args: &BTreeMap<String, String>) -> Result<Vec<&'static str>> {
    let mut what = Vec::new();
    if compose::has_layers(kit)? {
        what.push("image layers");
    }
    for c in &kit.caps {
        // By type, so a config read only at create (a port from an argument, say) counts too.
        let ty = c.ty.strip_prefix(super::CAP_NS).unwrap_or_default();
        let need = match (ty, &c.body) {
            // A passthrough OAuth credential only adds network rules.
            ("credential@1", CapBody::Credential(r)) if r.env.is_none() && r.inject.is_empty() => {
                continue;
            }
            ("credential@1", _) => "credentials",
            ("port@1", _) => "ports",
            ("volume@1", _) => "volumes",
            ("host-mount@1", _) => "host mounts",
            // Its store and elevation are set at create.
            ("dockerd@1", _) => "Docker engine",
            ("agent-skills@1" | "agent-skill@1", _) => "agent skills",
            // A new agent file needs every kit's context, and `add` has only this kit's.
            ("agent-context@1" | "agent-context@2", CapBody::AgentContext(r))
                if r.directory.is_none() =>
            {
                continue;
            }
            ("agent-context@1" | "agent-context@2", _) => "agent file",
            // The agent socket is mounted at create.
            ("ssh-agent@1", _) => "SSH agent",
            ("resources@1", _) => "resources",
            ("long-running@1", _) => "long-running",
            _ => continue,
        };
        what.push(need);
    }
    let exports = kit
        .args
        .iter()
        .any(|(name, def)| def.env.is_some() && args.contains_key(name));
    if !kit.env.is_empty() || exports {
        what.push("environment variables");
    }
    let order = [
        "agent file",
        "image layers",
        "credentials",
        "ports",
        "volumes",
        "host mounts",
        "Docker engine",
        "agent skills",
        "SSH agent",
        "resources",
        "environment variables",
        "long-running",
    ];
    what.sort_by_key(|w| order.iter().position(|o| o == w));
    what.dedup();
    Ok(what)
}

#[cfg(test)]
#[path = "apply_tests.rs"]
mod tests;
