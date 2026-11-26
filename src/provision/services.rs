//! A sandbox's host service units (`host_service`): which it needs, keeping them current, and
//! removing those of sandboxes smolvm no longer has.

use crate::ctx::Ctx;
use crate::host_service::Kind;
use crate::sandbox::{self, CreateRequest, Meta, Sandbox, name};
use crate::smolvm::Runner;

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
pub(super) fn sync_services<R: Runner>(ctx: &Ctx<R>, name: &str, kinds: &[Kind], meta: &Meta) {
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

/// The sockets units serve for a new sandbox: the host has a service manager and the sandbox gets
/// a bridge, a runtime agent grant or hosted egress.
pub(super) fn plan_services<R: Runner>(
    ctx: &Ctx<R>,
    req: &CreateRequest,
) -> Option<crate::host_service::Sockets> {
    let meta = sandbox::create::meta(req);
    (!service_kinds(&meta).is_empty() && !name::is_internal(&req.name))
        .then(|| ctx.services.plan(&req.name))
        .flatten()
}
