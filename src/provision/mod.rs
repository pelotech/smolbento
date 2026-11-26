//! Glue between sandboxes and the policy and secrets: what each start and create gets.

pub mod builder;

use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result, bail};

use crate::bridge;
use crate::ctx::Ctx;
use crate::host_service::Kind;
use crate::kits::apply::apply;
use crate::kits::host_mount;
use crate::kits::resolve::Plan;
use crate::policy::{Mode, Policy, compile};
use crate::sandbox::{self, CloneStep, CreateRequest, Meta, Sandbox, StartPlan, name};
use crate::secrets::{SecretsFile, resolve::start_env};
use crate::smolvm::{Credential, NetworkSpec, Runner};
use crate::ssh_agent as agent;
use crate::workspace::clone;

/// Hosts of the given services' credentials.
pub fn credential_hosts(secrets: &SecretsFile, services: &[String]) -> Vec<String> {
    let mut hosts: Vec<String> = services
        .iter()
        .filter_map(|s| secrets.service(s))
        .flat_map(|s| s.hosts)
        .collect();
    hosts.sort();
    hosts.dedup();
    hosts
}

/// One smolvm credential per env var of each service.
pub fn credentials(secrets: &SecretsFile, services: &[String]) -> Result<Vec<Credential>> {
    let mut out = Vec::new();
    for name in services {
        let s = secrets
            .service(name)
            .with_context(|| format!("unknown secret service '{name}'"))?;
        if s.hosts.is_empty() && !s.env_vars.is_empty() {
            bail!("secret service '{name}' has no hosts to send its value to");
        }
        for var in &s.env_vars {
            out.push(Credential {
                env_var: var.clone(),
                hosts: s.hosts.clone(),
                ..Default::default()
            });
        }
    }
    Ok(out)
}

/// Network and secret values for starting the sandbox `meta` describes: its credentials came from
/// `meta.secrets`, cover `meta.credential_hosts` and use `meta.credential_env` (all recorded at
/// create). Install-only credentials (`meta.credential_install`) are left out, and install-phase
/// kit rules an interrupted create or `kit add` left are removed first.
pub fn start_plan<R: Runner>(ctx: &Ctx<R>, meta: &Meta) -> Result<StartPlan> {
    plan_for(ctx, meta, false)
}

/// `start_plan` for a create's first start, which also passes the install-only credentials and
/// keeps the install-phase rules (this create's kits') for its install hooks.
pub fn first_start_plan<R: Runner>(ctx: &Ctx<R>, meta: &Meta) -> Result<StartPlan> {
    plan_for(ctx, meta, true)
}

#[tracing::instrument(name = "start_plan", skip_all, fields(sandbox = %meta.name, install))]
fn plan_for<R: Runner>(ctx: &Ctx<R>, meta: &Meta, install: bool) -> Result<StartPlan> {
    let sandbox = meta.name.as_str();
    // Before the network is compiled, and before the guest runs: the egress process reads the
    // policy on its next connection.
    if !install {
        drop_stale_install_rules(ctx, sandbox)?;
    }
    // Like create (and sbx after `policy reset`), a start needs a chosen policy.
    let policy = ensure_policy(ctx)?;
    let secrets = SecretsFile::load(&ctx.paths)?;
    let network = compile::network_of(&policy, meta);
    let (env, remove, egress) = match &meta.egress {
        // Secret values stay with bento's interceptor; smolvm gets only its token.
        Some(label) => (
            vec![(
                "SMOLVM_INTERCEPTOR_TOKEN".to_string(),
                crate::egress::token(&ctx.paths, sandbox)?,
            )],
            Vec::new(),
            Some(std::net::SocketAddr::from(([127, 0, 0, 1], label.port))),
        ),
        None if meta.rec.egress_unreadable => bail!(
            "{sandbox}: its sbx.egress label is unreadable; recreate it (bento rm {sandbox}, then bento create …)"
        ),
        // A hosted sandbox whose label was removed: smolvm holds no bindings for its credentials.
        None if !meta.rec.credential_env.is_empty() && meta.rec.no_credential_bindings => bail!(
            "{sandbox} has no sbx.egress label but was created for hosted egress (smolvm holds no credential bindings); recreate it"
        ),
        None => {
            let (env, remove) = start_env(&secrets, meta, ctx.store.as_ref(), install);
            (env, remove, None)
        }
    };
    let clone = meta.clone_repo.as_ref().map(|dir| {
        let repo = Path::new(dir);
        let read =
            || -> Result<_> { Ok((clone::worktree_head(repo)?, clone::copied_remotes(repo)?)) };
        let (head, remotes) = read().unwrap_or_else(|e| {
            crate::warning!(
                "reading the host repo for {sandbox}: {e:#}; its remotes aren't copied"
            );
            (None, Vec::new())
        });
        CloneStep {
            dir: dir.clone(),
            head,
            remotes,
        }
    });
    Ok(StartPlan {
        network,
        env,
        remove,
        egress,
        clone,
        branchable: meta.forkable() && ctx.settings.bool("fork.enabled")?,
        kit: None,
    })
}

/// `sandbox::ensure_running` with this context's plan; also brings the sandbox's host service
/// units up to date and sweeps the leftovers of removed sandboxes.
pub fn ensure_running<R: Runner>(ctx: &Ctx<R>, sb: &mut Sandbox) -> Result<()> {
    sweep_orphans(ctx);
    refresh_services(ctx, sb);
    let meta = sb.meta.clone();
    if sb.is_running() {
        return sandbox::ensure_running(&ctx.vm, sb, || start_plan(ctx, &meta));
    }
    before_start(ctx, sb);
    sandbox::ensure_running(&ctx.vm, sb, || start_plan(ctx, &meta))?;
    for w in egress_warnings(ctx, sb.name()) {
        crate::warning!("{w}");
    }
    Ok(())
}

/// What a stopped sandbox needs before its start: the stale unresolved-secrets list removed
/// (the restarted process writes a new one) and its egress process restarted.
pub(crate) fn before_start<R: Runner>(ctx: &Ctx<R>, sb: &Sandbox) {
    let _ = std::fs::remove_file(crate::egress::unresolved_file(&ctx.paths, sb.name()));
    restart_egress(ctx, sb);
}

/// What the egress process of `sandbox` reported it couldn't resolve, as warnings. Read without
/// waiting: nothing when it hasn't started or got that far yet.
pub(crate) fn egress_warnings<R: Runner>(ctx: &Ctx<R>, sandbox: &str) -> Vec<String> {
    let file = crate::egress::unresolved_file(&ctx.paths, sandbox);
    let text = std::fs::read_to_string(file).unwrap_or_default();
    text.lines()
        .filter(|l| !l.is_empty())
        .map(|name| {
            format!(
                "the {name} secret resolved to nothing in {sandbox}'s egress process, which \
                 doesn't get your shell's environment; requests using it will fail. Use a source \
                 that doesn't need it, or create the sandbox with network.egress=smolvm"
            )
        })
        .collect()
}

/// The units a sandbox needs: the bridge, the agent when a runtime phase is granted, and the
/// egress process when it is hosted. A fork's is the egress process only: the others would serve
/// its parent's sockets (`cli::fork`).
pub(crate) fn service_kinds(meta: &Meta) -> Vec<Kind> {
    let mut kinds = Vec::new();
    if meta.fork_of.is_some() {
        kinds.extend(meta.egress.as_ref().map(|_| Kind::Egress));
        return kinds;
    }
    if meta.ssh_agent.as_ref().is_some_and(|a| a.runtime.is_some()) {
        kinds.push(Kind::Agent);
    }
    if meta.bridge {
        kinds.push(Kind::Bridge);
    }
    if meta.egress.is_some() {
        kinds.push(Kind::Egress);
    }
    kinds
}

/// Writes (and loads) the `kinds` units of the sandbox `name`, or removes the other kinds'.
/// Failures only warn: without a unit the sockets are served while a session is attached only, if
/// at all.
#[tracing::instrument(name = "host_services", skip_all, fields(sandbox = %name, kinds = ?kinds))]
fn sync_services<R: Runner>(ctx: &Ctx<R>, name: &str, kinds: &[Kind], meta: &Meta) {
    let port = meta.egress.as_ref().map(|e| e.port);
    if let Err(e) = ctx.services.sync(name, kinds, port, &ctx.paths, &ctx.env) {
        let what = match (kinds.contains(&Kind::Egress), kinds.len()) {
            (true, 1) => "its egress unit",
            (true, _) => {
                "host services (the egress unit, and the browser, clipboard and SSH agent units)"
            }
            _ => "host services for the browser, clipboard and SSH agent",
        };
        crate::warning!("{name}: {what}: {e:#}");
    }
}

/// Restarts a hosted sandbox's egress process, which resolves its secrets once, as it starts: so
/// a new value applies, before a start or at once. Open connections drop. Returns false when `sb`
/// isn't hosted or the restart failed, which only warns.
#[tracing::instrument(name = "restart_egress", skip_all, fields(sandbox = %sb.name()))]
pub fn restart_egress<R: Runner>(ctx: &Ctx<R>, sb: &Sandbox) -> bool {
    if sb.meta.egress.is_none() {
        return false;
    }
    let result = ctx.services.restart_egress(sb.name());
    if let Err(e) = &result {
        crate::warning!("{}: restarting its egress process: {e:#}", sb.name());
    }
    result.is_ok()
}

/// Rewrites the units of a sandbox served by them if they differ (a new binary path, a new
/// `SSH_AUTH_SOCK`), so a stale unit mends itself on next use.
pub fn refresh_services<R: Runner>(ctx: &Ctx<R>, sb: &Sandbox) {
    // A fork is `sbx.service=false` for its socket units, but a hosted one has an egress unit.
    if sb.meta.service || sb.meta.fork_of.is_some() {
        sync_services(ctx, sb.name(), &service_kinds(&sb.meta), &sb.meta);
    }
}

/// Removes the units of sandboxes smolvm no longer has (deleted with `smolvm machine delete`,
/// which gives no hook). Called by commands that change state; names are returned.
pub fn sweep_orphans<R: Runner>(ctx: &Ctx<R>) -> Vec<String> {
    let gone = orphan_services(ctx);
    remove_services(ctx, &gone);
    gone
}

/// `sweep_orphans` for a caller that just listed the sandboxes: no second `machine ls`.
pub fn sweep_orphans_among<R: Runner>(ctx: &Ctx<R>, all: &[Sandbox]) -> Vec<String> {
    let gone = orphans_among(ctx, all);
    remove_services(ctx, &gone);
    gone
}

fn remove_services<R: Runner>(ctx: &Ctx<R>, names: &[String]) {
    for name in names {
        if let Err(e) = ctx.services.remove(name) {
            crate::warning!("removing the leftover host services of {name}: {e:#}");
        }
    }
}

/// `orphan_services`, given the sandboxes smolvm has.
pub fn orphans_among<R: Runner>(ctx: &Ctx<R>, all: &[Sandbox]) -> Vec<String> {
    let live: Vec<String> = all.iter().map(|sb| sb.name().to_string()).collect();
    ctx.services.orphans(&live)
}

/// Sandbox names with units here and no machine in smolvm: `sweep_orphans` without removing.
pub fn orphan_services<R: Runner>(ctx: &Ctx<R>) -> Vec<String> {
    if ctx.services.units().is_empty() || (ctx.smolvm.managed && !ctx.smolvm.bin.is_file()) {
        return Vec::new();
    }
    live_sandboxes(ctx).map_or_else(Vec::new, |live| ctx.services.orphans(&live))
}

/// The names of smolvm's sandboxes; `None` when it can't say (nothing is then removed).
fn live_sandboxes<R: Runner>(ctx: &Ctx<R>) -> Option<Vec<String>> {
    let machines = ctx.vm.list().ok()?;
    Some(
        machines
            .iter()
            .filter_map(Sandbox::from_machine)
            .map(|sb| sb.meta.name)
            .collect(),
    )
}

/// sbx 0.54's question when no network policy is chosen yet, word for word.
pub(crate) const POLICY_PROMPT: &str = "  Choose the network policy for sandboxes
    1. Open   all network traffic allowed, no restrictions
    2. Balanced   default deny, with common dev sites allowed
    3. Locked Down   all network traffic blocked unless you allow it
  Choice [1-3, default 2]: ";

/// Whether `name` may get hosted egress, as known before its kits are resolved: the setting, and a
/// service manager for its egress unit. Its kits can still make it fall back (see `prepare_create`).
pub fn may_host<R: Runner>(ctx: &Ctx<R>, name: &str) -> Result<bool> {
    Ok(crate::egress::hosted(&ctx.settings, name)? && ctx.services.plan(name).is_some())
}

/// The policy, asking for a network policy the first time one is needed (sbx behaviour).
pub fn ensure_policy<R: Runner>(ctx: &Ctx<R>) -> Result<Policy> {
    let mut policy = Policy::load(&ctx.paths)?;
    if policy.mode.is_some() {
        return Ok(policy);
    }
    if !ctx.can_prompt() {
        bail!(
            "no network policy chosen yet; run `bento policy init allow-all|balanced|deny-all` first"
        );
    }
    // A question, not command output: stderr, as sbx asks it, so stdout stays clean.
    let mut err = std::io::stderr().lock();
    write!(err, "{POLICY_PROMPT}")?;
    err.flush()?;
    drop(err);
    let line = ctx.read_line()?;
    policy.mode = Some(match line.trim() {
        "1" | "allow-all" => Mode::AllowAll,
        "" | "2" | "balanced" => Mode::Balanced,
        "3" | "deny-all" => Mode::DenyAll,
        other => bail!("'{other}' isn't 1, 2 or 3"),
    });
    policy.save(&ctx.paths)?;
    Ok(policy)
}

/// What `req`'s `--static-mcp` attaches, if given; `builtin` says the agent is a built-in one,
/// not a workload kit. An error is the selection's: an unknown or invalid server, an agent without
/// MCP support, a secret that isn't set. The CLI also calls this before it loads any kit.
pub fn mcp_attachment<R: Runner>(
    ctx: &Ctx<R>,
    req: &CreateRequest,
    builtin: bool,
) -> Result<Option<crate::mcp::Attachment>> {
    let Some(selection) = &req.mcp else {
        return Ok(None);
    };
    let secrets = SecretsFile::load(&ctx.paths)?;
    crate::mcp::attach(
        &crate::mcp::McpFile::load(&ctx.paths)?,
        selection,
        builtin.then_some(req.agent.as_str()),
        &|secret| secrets.global_entry(secret).is_some(),
    )
    .map(Some)
}

/// Fills a new sandbox's network, deny CIDRs and credentials from the policy and secrets, after
/// adding its `--deny-network` rules, and applies the resolved `kits` on top: their credentials
/// merge with the user's secrets and their rules join the policy, and their host mounts get a
/// `--mount` binding or a managed directory (made here). Returns the ids of the rules it added
/// (see `create`) and the kits' first-start steps.
#[tracing::instrument(name = "prepare_create", skip_all)]
pub fn prepare_create<R: Runner>(
    ctx: &Ctx<R>,
    req: &mut CreateRequest,
    deny_network: &[String],
    kits: Option<&Plan>,
) -> Result<(Vec<String>, Option<sandbox::KitFirstStart>)> {
    // Bad hosts fail before the policy prompt and before smolvm is asked for anything.
    let denies = crate::policy::notes::parse_create_denies(deny_network)?;
    // So do `--mount` paths no kit declares. The managed directories are made last.
    let workspaces: Vec<String> = req
        .workspaces
        .iter()
        .map(|w| &w.path)
        .chain(req.clone.as_ref().map(|c| &c.top))
        .map(|p| p.display().to_string())
        .collect();
    let host_dirs = host_mount::host_dirs(
        kits.map_or(&[], |p| &p.merged.host_mounts),
        &req.host_mounts,
        &workspaces,
        &ctx.paths.kit_host_mounts(),
    )?;
    req.host_mounts = host_dirs
        .iter()
        .map(|d| (d.host.clone(), d.guest.clone()))
        .collect();
    // So does a required SSH agent the host can't back. Before `apply`, whose install hooks
    // need to know whether they get the agent.
    for note in settle_agent(ctx, req, kits, bridge::ensure_private_dir)? {
        eprintln!("{note}");
    }
    let mut policy = ensure_policy(ctx)?;
    let secrets = SecretsFile::load(&ctx.paths)?;
    bind_user_secrets(req, &secrets)?;
    if !name::is_internal(&req.name) {
        // The services the kits declare a credential for get a mode, unless it's inject-only.
        let mut services: Vec<String> = kits
            .map(|p| {
                p.merged
                    .credentials
                    .iter()
                    .filter(|c| !c.req.inject_only())
                    .map(|c| c.req.service.clone())
                    .collect()
            })
            .unwrap_or_default();
        services.sort();
        services.dedup();
        sandbox::env::apply(req, &services);
    }
    // Before the policy is saved or smolvm creates anything. A workload kit named like a built-in
    // agent isn't that agent.
    let attachment = mcp_attachment(ctx, req, kits.is_none_or(|p| p.workload.is_builtin_agent()))?;
    let mut added = Vec::new();
    let mut first_start = None;
    if let Some(plan) = kits {
        // In memory until the save below, so an error before it leaves the policy file alone.
        let (steps, ids) = apply(
            plan,
            req,
            &mut policy,
            &secrets,
            &*ctx.store,
            &ctx.paths.kit_cache(),
            &|| host_git_identity(ctx),
        )?;
        added.extend(ids.iter().cloned());
        first_start = Some(sandbox::KitFirstStart {
            steps,
            restart_without: req.rec.credential_install.clone(),
            rule_ids: ids,
            agent_backing: Some(crate::ssh_agent::filter::Backing::new(&ctx.paths, &ctx.env)),
            agent_socket: None,
        });
    }
    if let Some(mcp) = attachment {
        added.extend(attach_mcp(req, &mut policy, mcp, &mut first_start)?);
    }
    let hosted = egress_choice(ctx, req, kits)?;
    if !denies.is_empty() {
        added.extend(crate::policy::notes::add_create_denies(
            &mut policy,
            &req.name,
            &denies,
            &secrets,
            &req.rec.secrets,
            &req.rec.credential_hosts,
        )?);
    }
    let (label, skills_step) = plan_skills(ctx, req, kits)?;
    // Bundled skills come from kits, and kits always make a first start.
    debug_assert!(skills_step.is_none() || first_start.is_some());
    // The bundled skills step runs before every install hook and after the start's setup linked
    // the store (a store entry of the same name is then taken).
    if let Some(step) = skills_step
        && let Some(first) = first_start.as_mut()
    {
        first.steps.install.insert(0, step);
    }
    // The mountless directory, where exec starts: a kit workload's image may not have it. First,
    // ahead of the bundled skills step.
    if req.workspaces.is_empty()
        && let Some(first) = first_start.as_mut()
    {
        let dir = crate::util::sh_quote(&req.workdir());
        let (user, group) = crate::sandbox::labels::split_user(req.rec.session_user());
        let owner = crate::util::sh_quote(&format!("{user}:{}", group.unwrap_or("")));
        first.steps.install.insert(
            0,
            crate::kits::apply::InstallStep {
                label: "the workspace directory".into(),
                kit: None,
                user: None,
                script: format!("mkdir -p {dir} && chown {owner} {dir}"),
                relay_stderr: false,
            },
        );
    }
    req.skills = (!label.dirs.is_empty()).then(|| crate::skills::Setup {
        store: crate::skills::store::Store::new(&ctx.paths).dir,
        label,
    });
    // After every check, so a refused create makes no directories.
    host_mount::create_managed(&host_dirs)?;
    // Created empty so it can be mounted; `off` mounts nothing.
    if req
        .skills
        .as_ref()
        .is_some_and(|s| s.label.shared != crate::skills::Shared::None)
    {
        crate::skills::store::Store::new(&ctx.paths).ensure()?;
    }
    if !added.is_empty() {
        // The last fallible step, so an error here leaves no rules for `create` to roll back.
        policy.save(&ctx.paths)?;
    }
    req.rec.host_access = compile::host_access(&policy, &req.name);
    req.network = compile::network(
        &policy,
        &req.name,
        &req.rec.credential_hosts,
        req.rec.host_access,
        hosted,
    );
    req.deny_cidrs = compile::deny_cidrs(&policy, &req.name, req.rec.host_access);
    for note in compile::install_deny_cidr_notes(&policy, &req.name, req.rec.host_access) {
        eprintln!("{note}");
    }
    if let Some(note) = host_access_note(&req.name, req.rec.host_access) {
        eprintln!("{note}");
    }
    if hosted {
        req.egress = Some(crate::egress::prepare(
            &ctx.paths,
            &req.name,
            &req.credentials,
        )?);
    }
    Ok((added, first_start))
}

/// Binds the user's secrets for `req.name` as its credentials, with the builder's registry
/// logins (`req.rec.registries`).
fn bind_user_secrets(req: &mut CreateRequest, secrets: &SecretsFile) -> Result<()> {
    // Internal sandboxes run untrusted code (a kit's build steps): no secrets, not even as
    // placeholders. The builder only binds stored registry hosts (`req.registries`) below.
    let services: Vec<String> = if name::is_internal(&req.name) {
        Vec::new()
    } else {
        secrets
            .services_for(&req.name)
            .into_iter()
            .filter(|s| secrets.service(s).is_some())
            .collect()
    };
    req.credentials = credentials(secrets, &services)?;
    req.rec.credential_hosts = credential_hosts(secrets, &services);
    for (i, host) in req.rec.registries.iter().enumerate() {
        req.credentials.push(builder::registry_credential(i, host));
        req.rec.credential_hosts.push(host.clone());
    }
    req.rec.credential_hosts.sort();
    req.rec.credential_hosts.dedup();
    req.rec.credential_env = req.credentials.iter().map(|c| c.env_var.clone()).collect();
    req.rec.credential_env.sort();
    req.rec.credential_env.dedup();
    req.rec.secrets = services;
    Ok(())
}

/// Adds the `--static-mcp` attachment: its hosts' allow rules, its credentials and its
/// first-start steps. Returns the ids of the rules it added.
fn attach_mcp(
    req: &mut CreateRequest,
    policy: &mut Policy,
    mcp: crate::mcp::Attachment,
    first_start: &mut Option<sandbox::KitFirstStart>,
) -> Result<Vec<String>> {
    let mut added = Vec::new();
    // A rule that was already there isn't this create's: a failed create leaves it.
    for host in &mcp.hosts {
        let (id, new) = policy.insert_rule(
            Some(&req.name),
            crate::policy::Decision::Allow,
            host,
            crate::policy::MCP_VIA,
            None,
            None,
            None,
        )?;
        if new {
            added.push(id);
        }
    }
    for c in &mcp.credentials {
        req.rec.credential_hosts.extend(c.hosts.iter().cloned());
        req.rec.credential_env.push(c.env_var.clone());
    }
    req.rec.credential_hosts.sort();
    req.rec.credential_hosts.dedup();
    req.rec.credential_env.sort();
    req.rec.credential_env.dedup();
    req.credentials.extend(mcp.credentials);
    req.rec.mcp_secrets = mcp.secrets;
    req.mcp_servers = Some(mcp.names);
    if !mcp.steps.is_empty() {
        // After the kits' install hooks. A sandbox without kits gets a first start for these
        // steps alone.
        first_start
            .get_or_insert_default()
            .steps
            .install
            .extend(mcp.steps);
    }
    Ok(added)
}

/// Whether `req` gets hosted egress. Refuses kits' request rules that a fallback to smolvm egress
/// would leave unenforced.
fn egress_choice<R: Runner>(
    ctx: &Ctx<R>,
    req: &CreateRequest,
    kits: Option<&Plan>,
) -> Result<bool> {
    // A sandbox that can't be hosted falls back to smolvm egress, with the first reason why.
    let setting = crate::egress::hosted(&ctx.settings, &req.name)?;
    let smolvm_because = if !setting {
        None
    } else if !req.rec.credential_install.is_empty() {
        // Hosted egress swaps values in bento, where an install-only credential (restarted
        // away after the install hooks) has no way to be withdrawn yet.
        Some("install-only credentials need network.egress=smolvm")
    } else if ctx.services.plan(&req.name).is_none() {
        // Without its unit nothing would own the interceptor port, so every connection fails.
        Some("no service manager for its egress unit")
    } else {
        None
    };
    let hosted = setting && smolvm_because.is_none();
    tracing::info!(hosted, fallback = smolvm_because, "egress");
    // Kits are resolved for hosted egress when it may be used (`may_host`); a fallback found
    // since leaves their request rules unenforced, so refuse them before anything is made.
    if !hosted && let Some(kit) = kits.and_then(Plan::request_rules_kit) {
        bail!(
            "kit {kit}: network-policy@2 method/path rules need hosted egress, but {} uses smolvm \
             egress: {}",
            req.name,
            smolvm_because.unwrap_or("network.egress is smolvm")
        );
    }
    if let Some(why) = smolvm_because {
        crate::warning!("{why}; creating {} with smolvm egress", req.name);
    }
    Ok(hosted)
}

/// The skills label for `req`, after checking the kits' bundled skills can be linked, and the
/// install step that links them, if there are any.
fn plan_skills<R: Runner>(
    ctx: &Ctx<R>,
    req: &CreateRequest,
    kits: Option<&Plan>,
) -> Result<(
    crate::skills::Label,
    Option<crate::kits::apply::InstallStep>,
)> {
    let wants = skill_wants(kits);
    let mut bundled: Vec<&crate::kits::resolve::Bundled> =
        kits.map_or(Vec::new(), |p| p.merged.bundled.iter().collect());
    if wants.is_empty() {
        if let Some(b) = bundled.iter().find(|b| !b.optional) {
            bail!(
                "kit {}: skill {} needs a skills directory: no agent-skills@1 in this sandbox",
                b.kit,
                b.name
            );
        }
        for b in &bundled {
            eprintln!(
                "note: kit {}: skipping skill {}: no skills directory in this sandbox",
                b.kit, b.name
            );
        }
        bundled.clear();
    }
    let label = crate::skills::plan(req.skills_mode, &wants, !bundled.is_empty());
    // A stored skill takes its name in every linking directory before bundled skills are linked
    // (agent-skill@1/host-conflict), so a required one's clash is known now: refuse it before
    // anything is made. Image content can clash too, which only the first start sees.
    if let Some(d) = label
        .dirs
        .iter()
        .find(|d| d.access == crate::skills::Access::Link)
    {
        let store = ctx.paths.skills_store();
        if let Some(b) = bundled
            .iter()
            .find(|b| !b.optional && store.join(&b.name).symlink_metadata().is_ok())
        {
            bail!(
                "failed to compose shared skills into the sandbox: bundled skills {} cannot be \
                 exposed in {}: another skill already uses the name",
                b.name,
                d.path
            );
        }
    }
    // As root, like the store's links; the script hands the links to the agent.
    let step = (!bundled.is_empty()).then(|| {
        let skills: Vec<(String, String, bool)> = bundled
            .iter()
            .map(|b| (b.name.clone(), b.source.clone(), b.optional))
            .collect();
        crate::kits::apply::InstallStep {
            label: "bundled agent skills".into(),
            kit: None,
            user: None,
            script: crate::skills::bundled_script(&label.dirs, &skills),
            relay_stderr: true,
        }
    });
    Ok((label, step))
}

/// A built-in agent's own `agent-skills@1` directories as read-write requests whatever its kit
/// says (the user's mode decides, as in sbx; a recorded difference from the spec's `off` default),
/// then every kit's.
fn skill_wants(kits: Option<&Plan>) -> Vec<crate::skills::Want> {
    let mut wants = Vec::new();
    if let Some(p) = kits {
        // A built-in agent's own skills directories are the agent's.
        if p.workload.is_builtin_agent() {
            wants.extend(p.workload.caps.iter().filter_map(|c| match &c.body {
                crate::kits::model::CapBody::AgentSkills { path, .. } => {
                    Some(crate::skills::Want {
                        path: path.clone(),
                        mode: crate::skills::Mode::Readwrite,
                        builtin: true,
                    })
                }
                _ => None,
            }));
        }
        wants.extend(p.merged.skill_dirs.iter().map(|d| crate::skills::Want {
            path: d.path.clone(),
            mode: d.mode,
            builtin: false,
        }));
    }
    wants
}

/// Sets `req.ssh_agent` from the kits' `ssh-agent@1` grant: refused when a required phase has no
/// host agent to back it or the socket directory isn't `private`; dropped when an optional one
/// hasn't or it isn't. Returns the notes and warnings for stderr. Internal sandboxes never get one.
fn settle_agent<R: Runner>(
    ctx: &Ctx<R>,
    req: &mut CreateRequest,
    kits: Option<&Plan>,
    private: impl FnOnce(&Path) -> bool,
) -> Result<Vec<String>> {
    req.ssh_agent = None;
    // No plan: a built-in agent's own grant.
    let built_in = crate::kits::resolve::built_in_ssh_agent();
    let grant = kits.map_or(&built_in, |p| &p.merged.ssh_agent);
    if grant.is_empty() || name::is_internal(&req.name) {
        return Ok(vec![]);
    }
    // The agent's socket goes where the bridge's does, checked only when there's an agent: in
    // the units' directory only when host services are usable AND the socket paths fit the OS
    // limit (matching `HostServices::plan()`).
    let dir = if ctx.services.fits(&req.name) {
        ctx.services.sock_dir().to_path_buf()
    } else {
        bridge::socket_dir()
    };
    let backing = match agent::host_agent(&ctx.settings, &ctx.env)? {
        Ok(_) if !private(&dir) => Err(agent::Unavailable::UnsafeDir(dir)),
        b => b,
    };
    let (label, notes) = agent::settle(&req.name, grant, &backing)?;
    req.ssh_agent = label;
    Ok(notes)
}

/// What a create says when the sandbox gets host access: the localhost rule opens every host port.
fn host_access_note(name: &str, host_access: bool) -> Option<String> {
    host_access.then(|| {
        format!("note: {name} is created with host access (every port on your host's localhost)")
    })
}

/// The host's git `user.name` and `user.email`, for a kit's `git-identity@1`.
pub(crate) fn host_git_identity<R: Runner>(ctx: &Ctx<R>) -> Option<(String, String)> {
    let get = |key: &str| -> Option<String> {
        let v = crate::workspace::clone::config_get(&ctx.cwd, key).ok()??;
        let v = v.trim();
        (!v.is_empty()).then(|| v.to_string())
    };
    Some((get("user.name")?, get("user.email")?))
}

/// Prepares, creates and starts a new sandbox, applying `kits` when given. When that fails and
/// smolvm doesn't have the machine (a failed kit first start removes it), the `--deny-network`
/// rules, the kits' rules and the `--clone` remote this create added are dropped again; rules the
/// sandbox name already had stay.
pub fn create<R: Runner>(
    ctx: &Ctx<R>,
    req: &mut CreateRequest,
    deny_network: &[String],
    kits: Option<&Plan>,
) -> Result<Sandbox> {
    // Before prepare_create, which may prompt and adds the --deny-network and kit rules.
    check_free(ctx, &req.name)?;
    create_with(ctx, req, deny_network, kits, None, &mut |_| {})
}

/// Fails when a sandbox named `name` exists.
pub fn check_free<R: Runner>(ctx: &Ctx<R>, name: &str) -> Result<()> {
    if sandbox::find(&ctx.vm, name)?.is_some() {
        bail!("sandbox '{name}' already exists");
    }
    Ok(())
}

/// `create` once the name is known to be free, or with `prepared` steps whose rules are already
/// in the policy (tests); `on` hears what the start and the kit steps are doing.
#[tracing::instrument(name = "provision", skip_all, fields(sandbox = %req.name))]
pub fn create_with<R: Runner>(
    ctx: &Ctx<R>,
    req: &mut CreateRequest,
    deny_network: &[String],
    kits: Option<&Plan>,
    prepared: Option<sandbox::KitFirstStart>,
    on: &mut dyn FnMut(sandbox::Event),
) -> Result<Sandbox> {
    sweep_orphans(ctx);
    // The repo a `--clone` copies, at its top.
    let repo = req.clone.as_ref().map(|c| c.top.clone());
    if let Some(repo) = &repo {
        clone::check_remote_free(repo, &req.name)?;
        for remote in clone::userinfo_remotes(repo).unwrap_or_default() {
            crate::warning!(
                "remote '{remote}' has a user name or token in its URL; the sandbox can \
                 read it in {}/config",
                clone::SOURCE_MOUNT
            );
        }
    }
    // The name has no machine, so install-phase rules under it are an interrupted create's:
    // `rm` can't reach them, so they go before this create adds its own.
    if prepared.is_none() {
        drop_stale_install_rules(ctx, &req.name)?;
    }
    let mut added: Vec<String> = prepared
        .as_ref()
        .map(|k| k.rule_ids.clone())
        .unwrap_or_default();
    // Only a remote this create made: one left by an earlier sandbox of this name (`run --rm`)
    // keeps its fetched branches.
    let mut added_remote = None;
    let result = (|| {
        let (ids, kit) = prepare_create(ctx, req, deny_network, kits)?;
        added.extend(ids);
        let mut kit = kit.or(prepared);
        // Units serve the sockets when the host has a service manager, for the bridge and a
        // runtime agent grant (known now that the agent was settled).
        req.host_services = plan_services(ctx, req);
        if let Some(k) = &mut kit {
            k.agent_socket = req.host_services.as_ref().map(|s| s.agent.clone());
        }
        if let Some(repo) = &repo
            && clone::add_remote(repo, &req.name)?
        {
            added_remote = Some(repo);
        }
        let meta = sandbox::create::meta(req);
        let plan = match kit {
            Some(kit) => {
                let plan = first_start_plan(ctx, &meta)?;
                StartPlan {
                    kit: Some(kit),
                    ..plan
                }
            }
            None => start_plan(ctx, &meta)?,
        };
        let req: &CreateRequest = req;
        // The units go in once the machine exists (the orphan sweep would remove them before)
        // and before its first start, so a boot-time workload reaches the agent and the bridge.
        // An install-phase agent grant is served by the install hooks alone on the same socket,
        // so those units wait until they are done; the egress unit never waits, as every flow
        // of the install hooks goes through it.
        let install_grant = meta.ssh_agent.as_ref().is_some_and(|a| a.install.is_some());
        let mut on_event = |e: sandbox::Event| {
            let kinds = match e {
                sandbox::Event::Created if install_grant => {
                    meta.egress.is_some().then(|| vec![Kind::Egress])
                }
                sandbox::Event::Created => Some(service_kinds(&meta)),
                sandbox::Event::Booted if install_grant => Some(service_kinds(&meta)),
                _ => None,
            };
            if let Some(kinds) = kinds.filter(|_| req.host_services.is_some()) {
                sync_services(ctx, &req.name, &kinds, &meta);
            }
            on(e);
        };
        sandbox::create(
            &ctx.vm,
            req,
            &plan,
            |ids| drop_install_rules(ctx, req, ids),
            &mut on_event,
        )
    })();
    if result.is_err() && req.host_services.is_some() {
        // A failed first start removes the machine, and the units that were installed with it.
        let gone = matches!(sandbox::find(&ctx.vm, &req.name), Ok(None));
        if gone && let Err(e) = ctx.services.remove(&req.name) {
            crate::warning!("removing the host services of {}: {e:#}", req.name);
        }
        if gone && let Err(e) = crate::egress::forget(&ctx.paths, &req.name) {
            crate::warning!("forgetting the egress state of {}: {e:#}", req.name);
        }
    }
    let rollback = result.is_err() && (!added.is_empty() || added_remote.is_some());
    let gone = rollback
        && match sandbox::find(&ctx.vm, &req.name) {
            Ok(found) => found.is_none(),
            Err(e) => {
                // Unknown whether the sandbox is gone: keep what it added (`rm` drops it).
                let name = &req.name;
                crate::warning!(
                    "couldn't check whether {name} still exists ({e:#}); what this create \
                     added was kept, and `bento rm {name}` removes it if the sandbox exists"
                );
                if !added.is_empty() {
                    crate::warning!(
                        "if it doesn't, remove its rules with `bento policy rm network \
                         --sandbox {name} --id <id>` (rule ids: {})",
                        added.join(", ")
                    );
                }
                false
            }
        };
    if gone {
        // Best effort: the create error is what matters.
        if !added.is_empty()
            && let Ok(mut policy) = Policy::load(&ctx.paths)
        {
            for id in &added {
                policy.remove_rules(Some(&req.name), Some(id), None, None, None, None);
            }
            let _ = policy.save(&ctx.paths);
        }
        if let Some(repo) = added_remote {
            let _ = clone::remove_remote(repo, &req.name);
        }
    }
    if result.is_ok() {
        for w in egress_warnings(ctx, &req.name) {
            crate::warning!("{w}");
        }
    }
    result
}

/// The sockets units serve for a new sandbox: the host has a service manager and the sandbox gets
/// a bridge, a runtime agent grant or hosted egress.
fn plan_services<R: Runner>(
    ctx: &Ctx<R>,
    req: &CreateRequest,
) -> Option<crate::host_service::Sockets> {
    let meta = sandbox::create::meta(req);
    (!service_kinds(&meta).is_empty() && !name::is_internal(&req.name))
        .then(|| ctx.services.plan(&req.name))
        .flatten()
}

/// Removes the install-phase kit rules of `name` that an interrupted create or `kit add` left in
/// the policy.
fn drop_stale_install_rules<R: Runner>(ctx: &Ctx<R>, name: &str) -> Result<()> {
    let mut policy = Policy::load(&ctx.paths)?;
    let stale: Vec<String> = policy
        .rules_for(Some(name))
        .filter(|(r, s)| s.is_some() && r.is_kit_install())
        .map(|(r, _)| r.id.clone())
        .collect();
    if !stale.is_empty() {
        policy.remove_rules_by_ids(name, &stale);
        policy.save(&ctx.paths)?;
    }
    Ok(())
}

/// Removes a new sandbox's install-phase kit rules from the policy and returns its network
/// without them. Only this sandbox's rules change, so only its network needs pushing.
fn drop_install_rules<R: Runner>(
    ctx: &Ctx<R>,
    req: &CreateRequest,
    ids: &[String],
) -> Result<NetworkSpec> {
    let mut policy = Policy::load(&ctx.paths)?;
    policy.remove_rules_by_ids(&req.name, ids);
    policy.save(&ctx.paths)?;
    Ok(compile::network(
        &policy,
        &req.name,
        &req.rec.credential_hosts,
        req.rec.host_access,
        req.egress.is_some(),
    ))
}

/// Pushes the policy (as just saved) to running sandboxes. Failures are warnings: the policy
/// applies on each sandbox's next start anyway.
pub fn push_network<R: Runner>(ctx: &Ctx<R>, policy: &Policy) -> Result<()> {
    push_network_with(ctx, policy, &sandbox::Listing::new(&ctx.vm))
}

/// `push_network` for a caller that already listed (or will list) the sandboxes.
pub fn push_network_with<R: Runner>(
    ctx: &Ctx<R>,
    policy: &Policy,
    sandboxes: &sandbox::Listing<R>,
) -> Result<()> {
    // Before the first download there is no smolvm to ask, and no sandbox to update.
    if ctx.smolvm.managed && !ctx.smolvm.bin.is_file() {
        return Ok(());
    }
    let sandboxes = match sandboxes.get() {
        Ok(s) => s,
        Err(e) => {
            crate::warning!(
                "couldn't update running sandboxes ({e:#}); the change applies when they next start"
            );
            return Ok(());
        }
    };
    let mut updated = 0;
    for sb in (sandboxes.iter()).filter(|s| s.is_running() && s.in_setup(&ctx.paths)) {
        let network = compile::network_of(policy, &sb.meta);
        match ctx.vm.update_network(&sb.machine, &network) {
            Ok(()) => updated += 1,
            Err(e) => crate::warning!(
                "{}: the change applies on its next start ({e:#})",
                sb.name()
            ),
        }
    }
    if updated > 0 {
        writeln!(&ctx.out, "Updated {updated} running sandbox(es)")?;
    }
    Ok(())
}

#[cfg(test)]
mod services_tests;

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
