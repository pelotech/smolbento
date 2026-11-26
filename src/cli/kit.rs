//! `bento kit inspect|validate|add`.

mod doc;
mod mounts;

use std::io::Write;

use anyhow::{Context, Result, anyhow, bail};

use super::Ctx;
use super::args::{Format, KitArgOpts, KitCmd, KitRefArgs, SignOpts};

use crate::kits::apply::apply;
use crate::kits::args::{ArgValues, NoResolvedValue};
use crate::kits::model::{Content, Format as KitFormat, ImageConfig, Kind, Kit, Source};
use crate::kits::registry::auth::Logins;
use crate::kits::resolve::{
    NO_SANDBOX_WORKDIR, check_named_formats, mixing_format, resolve_for, supported,
};
use crate::kits::trust::signing;
use crate::kits::{apply, artifact, capability, guest, load, registry};
use crate::policy::{Decision, Policy, compile};
use crate::provision;
use crate::sandbox::labels::{self, KitRecord};
use crate::sandbox::{self, CreateRequest, KitPhase, Recorded, Sandbox};
use crate::secrets::SecretsFile;
use crate::smolvm::Runner;
use crate::workspace::Workspace;
use doc::Doc;

/// The sandbox `kit inspect|validate` ask `may_host` about: there is none yet, and only an
/// internal (`_`) name changes the answer, so a plain name stands in. A kit's name could be internal.
const STAND_IN: &str = "sandbox";

pub fn run<R: Runner>(ctx: &mut Ctx<R>, cmd: KitCmd) -> Result<i32> {
    match cmd {
        KitCmd::Inspect {
            kit,
            // The loader accepts `extends:` and ignores it, so there is no parent to merge.
            resolved: _,
        } => inspect(ctx, &kit),
        KitCmd::Validate { kit } => validate(ctx, &kit),
        KitCmd::Add {
            sandbox,
            reference,
            args,
            yes,
        } => add(ctx, &sandbox, &reference, &args, yes),
        KitCmd::Pack { directory, output } => pack(ctx, &directory, output.as_deref()),
        KitCmd::Push {
            directory,
            reference,
            sign,
            signing,
        } => push(ctx, &directory, &reference, sign, &signing),
        KitCmd::Pull { reference, output } => pull(ctx, &reference, output.as_deref()),
        KitCmd::Mounts(cmd) => mounts::run(ctx, cmd),
        KitCmd::Sign { reference, signing } => sign(ctx, &reference, &signing),
        KitCmd::Verify {
            reference,
            key,
            certificate_identity,
            certificate_identity_regexp,
            certificate_oidc_issuer,
            certificate_oidc_issuer_regexp,
            insecure_ignore_tlog,
            output,
        } => {
            let pick = |exact: Option<String>, regexp: Option<String>| {
                exact
                    .map(signing::Match::Exact)
                    .or(regexp.map(signing::Match::Regexp))
            };
            let policy = match key {
                Some(k) => VerifyPolicy::Key(k),
                None => VerifyPolicy::Keyless {
                    identity: pick(certificate_identity, certificate_identity_regexp),
                    issuer: pick(certificate_oidc_issuer, certificate_oidc_issuer_regexp),
                    ignore_tlog: insecure_ignore_tlog,
                },
            };
            verify(ctx, &reference, policy, output.pick())
        }
    }
}

/// DIRECTORY read as a v2 kit after the loader's own checks, as `kit pack` and `kit push` check
/// it; errors read like sbx's (`invalid artifact: …`).
fn checked_payload<R: Runner>(ctx: &Ctx<R>, directory: &str) -> Result<artifact::Payload> {
    let dir = ctx.cwd.join(directory);
    (|| {
        if !dir.is_dir() {
            bail!("artifact directory: stat {directory}: no such file or directory");
        }
        let payload = artifact::read_dir(&dir).context("manifest")?;
        // The directory itself, never a shipped kit or registry ref that shares its name.
        load::load_with(ctx, &dir.display().to_string(), true)?;
        Ok(payload)
    })()
    .context("invalid artifact")
}

/// `kit push`: publishes DIRECTORY to REFERENCE as sbx's v2 kit artifact, signed with `--sign`.
fn push<R: Runner>(
    ctx: &Ctx<R>,
    directory: &str,
    reference: &str,
    sign: bool,
    opts: &SignOpts,
) -> Result<i32> {
    registry::tagged_reference(reference)?;
    let given = opts.key.is_some()
        || opts.identity_token.is_some()
        || opts.identity_token_file.is_some()
        || !opts.tlog_upload;
    if given && !sign {
        bail!("--key, --identity-token, --identity-token-file and --tlog-upload need --sign");
    }
    // Everything signing needs is checked before anything is published.
    let signing = match sign {
        true => Some((signer(opts)?, signing::cosign()?)),
        false => None,
    };
    let payload = checked_payload(ctx, directory)?;
    let registries = SecretsFile::load(&ctx.paths)?.host_registries();
    let logins = Logins::new(&registries, &*ctx.store);
    let manifest = registry::push_v2(reference, &payload, logins)?;
    let digest = crate::util::sha256_digest(&manifest);
    writeln!(&ctx.out, "Pushed {reference} ({digest})")?;
    if let Some((signer, cosign)) = signing {
        // The manifest just pushed, not whatever the tag points at by now.
        sign_manifest(ctx, reference, &manifest, &signer, &cosign, logins)?;
    }
    Ok(0)
}

const LOCAL_SIGNING: &str = "signing and verifying a local kit directory isn't supported yet; \
                             push it and use the registry reference";

/// The signer `--key`, `--identity-token(-file)` and `--tlog-upload` describe.
fn signer(o: &SignOpts) -> Result<signing::Signer> {
    if let Some(k) = &o.key {
        return Ok(signing::Signer::Key(k.clone()));
    }
    if !o.tlog_upload {
        return Err(super::Unsupported(
            "keyless signing without the transparency log isn't supported yet (it needs a \
             timestamp authority); sign with --key for a private kit"
                .into(),
        )
        .into());
    }
    let token = match (&o.identity_token, &o.identity_token_file) {
        (Some(v), _) => Some(signing::Token::Value(v.clone())),
        (None, Some(f)) => Some(signing::Token::File(f.clone())),
        (None, None) => None,
    };
    Ok(signing::Signer::Keyless { token })
}

/// Signs MANIFEST, the kit at REFERENCE, and attaches the signature.
fn sign_manifest<R: Runner>(
    ctx: &Ctx<R>,
    reference: &str,
    manifest: &[u8],
    signer: &signing::Signer,
    cosign: &std::path::Path,
    logins: Logins,
) -> Result<()> {
    let bundle = signing::sign_blob(cosign, manifest, signer)?;
    registry::push_signature(reference, manifest, &bundle, logins)?;
    writeln!(&ctx.out, "Signed {reference}")?;
    Ok(())
}

/// A published kit's reference, for `sign` and `verify`: a local path is refused (exit 2), and
/// one without a tag or digest is invalid, as in sbx.
fn published(reference: &str) -> Result<()> {
    if reference_kind(reference) != "registry" {
        return Err(super::Unsupported(LOCAL_SIGNING.into()).into());
    }
    let name = reference.rsplit('/').next().unwrap_or_default();
    if !reference.contains('@') && !name.contains(':') {
        bail!("fetch kit manifest: invalid reference");
    }
    Ok(())
}

/// `kit sign`: signs a published kit, as sbx does for an OCI reference.
fn sign<R: Runner>(ctx: &Ctx<R>, reference: &str, opts: &SignOpts) -> Result<i32> {
    published(reference)?;
    let signer = signer(opts)?;
    let cosign = signing::cosign()?;
    let registries = SecretsFile::load(&ctx.paths)?.host_registries();
    let logins = Logins::new(&registries, &*ctx.store);
    let (manifest, _) = registry::kit_manifest(reference, logins)?;
    sign_manifest(ctx, reference, &manifest, &signer, &cosign, logins)?;
    Ok(0)
}

/// `kit verify`'s policy before its keyless parts are checked.
enum VerifyPolicy {
    Key(std::path::PathBuf),
    Keyless {
        identity: Option<signing::Match>,
        issuer: Option<signing::Match>,
        ignore_tlog: bool,
    },
}

/// `kit verify --format json|yaml`: sbx's result.
#[derive(serde::Serialize)]
struct Verified<'a> {
    reference: &'a str,
    kind: &'static str,
    verified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    identity: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    issuer: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// `kit verify`: checks the signatures attached to a published kit; verified when any passes.
fn verify<R: Runner>(
    ctx: &Ctx<R>,
    reference: &str,
    policy: VerifyPolicy,
    format: Format,
) -> Result<i32> {
    published(reference)?;
    let policy = match policy {
        VerifyPolicy::Key(k) => signing::Policy::Key(k),
        VerifyPolicy::Keyless {
            identity,
            issuer,
            ignore_tlog,
        } => signing::Policy::Keyless {
            identity: identity.context(
                "keyless verification requires --certificate-identity or \
                 --certificate-identity-regexp (or --key for a key-based signature)",
            )?,
            issuer: issuer.context(
                "keyless verification requires --certificate-oidc-issuer or \
                 --certificate-oidc-issuer-regexp",
            )?,
            ignore_tlog,
        },
    };
    let checked = (|| {
        let cosign = signing::cosign()?;
        let registries = SecretsFile::load(&ctx.paths)?.host_registries();
        let logins = Logins::new(&registries, &*ctx.store);
        let (manifest, digest) = registry::kit_manifest(reference, logins)?;
        let bundles = registry::signatures_of(reference, &digest, logins)?;
        signing::verify_any(&cosign, &manifest, &bundles, std::slice::from_ref(&policy))?;
        anyhow::Ok(())
    })();
    let (identity, issuer) = match &policy {
        signing::Policy::Keyless {
            identity, issuer, ..
        } => (Some(identity.as_str()), Some(issuer.as_str())),
        signing::Policy::Key(_) => (None, None),
    };
    if format == Format::Table {
        checked?;
        writeln!(&ctx.out, "  ✓ {reference} — verified (oci)")?;
        if let (Some(id), Some(iss)) = (identity, issuer) {
            writeln!(&ctx.out, "      identity {id}")?;
            writeln!(&ctx.out, "      issuer {iss}")?;
        }
        return Ok(0);
    }
    let report = Verified {
        reference,
        kind: "oci",
        verified: checked.is_ok(),
        identity: identity.filter(|_| checked.is_ok()),
        issuer: issuer.filter(|_| checked.is_ok()),
        error: checked.as_ref().err().map(|e| format!("{e:#}")),
    };
    write!(
        &ctx.out,
        "{}",
        format.structured(&report)?.unwrap_or_default()
    )?;
    Ok(if checked.is_ok() { 0 } else { 1 })
}

/// Writes a file `kit pack` or `kit pull` produces, whole or not at all, mode 0644.
fn write_output(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    crate::config::write_atomic(path, bytes, Some(0o644), crate::config::Symlink::Follow)
}

/// `kit pull`: saves the payload of the v2 kit at REFERENCE (its files, as a tar.gz).
fn pull<R: Runner>(ctx: &Ctx<R>, reference: &str, output: Option<&str>) -> Result<i32> {
    // As in sbx, the source policy applies to a pull (not to a push).
    crate::kits::trust::check(&Source::Registry(reference.into()), &ctx.settings)?;
    let registries = SecretsFile::load(&ctx.paths)?.host_registries();
    let logins = Logins::new(&registries, &*ctx.store);
    let payload = crate::kits::registry::fetch_payload(reference, &ctx.paths.kit_cache(), logins)?;
    let shown = output.map_or_else(|| crate::kits::registry::pull_name(reference), String::from);
    let path = ctx.cwd.join(&shown);
    write_output(&path, &payload).with_context(|| format!("writing {shown}"))?;
    writeln!(&ctx.out, "Pulled {reference} to {shown}")?;
    Ok(0)
}

/// `kit pack`: validates DIRECTORY as a v2 kit and writes its ZIP, as sbx does.
fn pack<R: Runner>(ctx: &Ctx<R>, directory: &str, output: Option<&str>) -> Result<i32> {
    let dir = ctx.cwd.join(directory);
    checked_payload(ctx, directory)?;
    let bytes = artifact::zip(&dir)?;
    let shown = match output {
        Some(o) if !o.ends_with(".zip") => {
            bail!("pack: destination {o} must have a .zip extension")
        }
        Some(o) => o.to_string(),
        None => {
            let yaml = std::fs::read_to_string(dir.join("spec.yaml"))?;
            format!("{}.zip", crate::kits::v2::name_in(&yaml, &dir)?)
        }
    };
    let path = ctx.cwd.join(&shown);
    let parent = path.parent().unwrap_or(&ctx.cwd);
    if !parent.is_dir() {
        bail!(
            "pack: resolve directory of {shown}: lstat {}: no such file or directory",
            parent.display()
        );
    }
    write_output(&path, &bytes)?;
    writeln!(&ctx.out, "Packed artifact {shown}")?;
    Ok(0)
}

/// The kit as loaded, without resolving it: sbx's summary table (then which capabilities
/// smolbento supports), or its v2-shaped descriptor as JSON or YAML.
fn inspect<R: Runner>(ctx: &Ctx<R>, a: &KitRefArgs) -> Result<i32> {
    // Only checked: inspecting doesn't expand anything.
    a.args.values()?;
    let kit = load::load_with(ctx, &a.reference, a.offline)?;
    let format = a.output.pick();
    let doc = Doc::new(&kit);
    let mut out = &ctx.out;
    // As a create would resolve it, so the two agree.
    let hosted = crate::provision::may_host(ctx, STAND_IN)?;
    if let Some(text) = format.structured(&doc)? {
        write!(out, "{text}")?;
    } else {
        write!(out, "{}", doc.table(&kit))?;
        if !kit.caps.is_empty() {
            writeln!(out, "Capabilities:")?;
            let mut rows = Vec::new();
            for c in &kit.caps {
                rows.push(vec![
                    c.ty.clone(),
                    if c.optional { "yes" } else { "no" }.into(),
                    if supported(c, hosted) {
                        "supported"
                    } else {
                        "not supported"
                    }
                    .into(),
                ]);
            }
            write!(
                out,
                "{}",
                super::table(&["TYPE", "OPTIONAL", "SUPPORT"], rows)
            )?;
        }
        write!(out, "{}", doc.extras_table())?;
    }
    Ok(0)
}

/// Loads and resolves the kit on its own: a workload by itself, a mixin on an empty workload that
/// provides whatever the mixin requires, at a version its constraints accept.
fn validate<R: Runner>(ctx: &Ctx<R>, a: &KitRefArgs) -> Result<i32> {
    let (reference, format) = (a.reference.as_str(), a.output.pick());
    let checked = check_kit(ctx, reference, &a.args, a.offline);
    if format == Format::Table {
        for w in checked? {
            crate::warning!("{w}");
        }
        writeln!(&ctx.out, "✓ {reference} — valid")?;
        return Ok(0);
    }
    let (valid, warnings, errors) = match &checked {
        Ok(w) => (true, w.clone(), vec![]),
        Err(e) => (false, vec![], vec![format!("{e:#}")]),
    };
    let report = Report {
        reference,
        kind: reference_kind(reference),
        valid,
        warnings,
        errors,
    };
    if format == Format::Json {
        writeln!(&ctx.out, "{}", serde_json::to_string(&report)?)?;
    } else {
        write!(&ctx.out, "{}", serde_saphyr::to_string(&report)?)?;
    }
    Ok(if valid { 0 } else { 1 })
}

/// `validate --format json|yaml`: sbx's result, with the failure messages when invalid.
#[derive(serde::Serialize)]
struct Report<'a> {
    reference: &'a str,
    kind: &'static str,
    valid: bool,
    warnings: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    errors: Vec<String>,
}

/// Loads and checks the kit; returns the warnings.
fn check_kit<R: Runner>(
    ctx: &Ctx<R>,
    reference: &str,
    args: &KitArgOpts,
    offline: bool,
) -> Result<Vec<String>> {
    let values = args.values()?;
    let mut kit = load::load_with(ctx, reference, offline)?;
    if offline
        && kit.kind == Kind::Workload
        && kit.command.is_none()
        && matches!(&kit.content, Content::Image(i) if !i.is_empty())
    {
        bail!(
            "kit {reference}: its command comes from the image config, which needs a registry \
             lookup; --offline can't validate it"
        );
    }
    load::check_launchable(ctx, &mut kit, None)?;
    // As a create would resolve it, so the two agree.
    let hosted = crate::provision::may_host(ctx, STAND_IN)?;
    let resolve = |w, m| resolve_for(w, m, &values, NO_SANDBOX_WORKDIR, &[], hosted);
    let resolved = match kit.kind {
        Kind::Workload => resolve(kit, vec![]),
        Kind::Mixin => {
            let mut base = empty_workload("validate");
            // A version within each require's constraints; a malformed one fails in `resolve`.
            base.provides = kit
                .requires
                .iter()
                .filter_map(|r| capability::parse_require(r).ok())
                .map(|r| capability::witness(&r))
                .collect();
            resolve(base, vec![kit])
        }
    };
    // sbx's validate says the artifact failed validation when an arg has no value.
    let plan = resolved.map_err(|e| {
        if e.root_cause().is::<NoResolvedValue>() {
            anyhow::anyhow!("{e:#}; artifact validation failed")
        } else {
            e
        }
    })?;
    Ok(plan.skipped_warnings())
}

/// What sort of reference `validate --format json` reports, from the text alone (a failed load
/// has no source): sbx's `directory` for a kit directory.
fn reference_kind(reference: &str) -> &'static str {
    let local = [".", ".."].contains(&reference)
        || ["/", "./", "../", "~/"]
            .iter()
            .any(|p| reference.starts_with(p));
    if !local {
        return if load::is_builtin(reference) {
            "builtin"
        } else {
            "registry"
        };
    }
    let file = [".yaml", ".yml", "Smolfile", ".smolfile"]
        .iter()
        .any(|e| reference.ends_with(e));
    if file { "file" } else { "directory" }
}

/// A workload with nothing in it, for `kit add`: the existing sandbox's workload kit is among its
/// recorded kits already. The placeholder digest lets `apply` record it.
fn empty_workload(name: &str) -> Kit {
    Kit {
        content: Content::Image(String::new()),
        digest: Some("sha256:recorded".into()),
        ..Kit::new(name, Kind::Workload, Source::Registry(String::new()))
    }
}

/// A recorded kit as a mixin that only provides: its capabilities were applied already.
fn recorded_kit(r: &KitRecord) -> Kit {
    // Only `provides` matters; the placeholder digest lets `apply` record any ref, even one a
    // hand-edited record left unpinned or empty (its line is dropped again below).
    Kit {
        name: r.name.clone(),
        source: Source::Registry(r.reference.clone()),
        digest: Some("sha256:recorded".into()),
        kind: Kind::Mixin,
        provides: r.provides.clone(),
        content: Content::None,
        ..empty_workload("")
    }
}

fn add<R: Runner>(
    ctx: &Ctx<R>,
    name: &str,
    reference: &str,
    args: &KitArgOpts,
    yes: bool,
) -> Result<i32> {
    let values = args.values()?;
    let mut sb = sandbox::get(&ctx.vm, name)?;
    let kit = load::load(ctx, reference)?;
    if kit.kind != Kind::Mixin {
        bail!("{reference} is a workload kit, not a mixin; only mixins can be added to a sandbox");
    }
    // Before anything changes, the sandbox's start included.
    let recreate = apply::needs_recreate(&kit, &values.for_kit(&kit)?)?;
    if !recreate.is_empty() {
        bail!("recreate required: {}", recreate.join(", "));
    }
    let started = !sb.is_running();
    provision::ensure_running(ctx, &mut sb)?;
    add_running(ctx, &sb, kit, &values, yes, started).map_err(|e| {
        if started {
            anyhow!("{e:#}\n({name} was started for this and is still running)")
        } else {
            e
        }
    })
}

/// `add` once the sandbox runs; `started` says whether `add` started it.
fn add_running<R: Runner>(
    ctx: &Ctx<R>,
    sb: &Sandbox,
    kit: Kit,
    values: &ArgValues,
    yes: bool,
    started: bool,
) -> Result<i32> {
    let name = sb.name();
    let existing = &sb.meta.rec.kits;
    if existing.iter().any(|r| r.name == kit.name) {
        bail!("kit {} is already in {name}", kit.name);
    }
    let mut named: Vec<(&str, Option<KitFormat>)> = existing
        .iter()
        .map(|r| (r.name.as_str(), r.format))
        .collect();
    named.push((kit.name.as_str(), mixing_format(&kit)));
    check_named_formats(&named)?;
    let kit_name = kit.name.clone();
    // The workload's own record (named like the sandbox's agent) is the workload, not a mixin.
    let (own, others): (Vec<&KitRecord>, Vec<&KitRecord>) =
        existing.iter().partition(|r| r.name == sb.meta.agent);
    let mixins: Vec<Kit> = others
        .into_iter()
        .map(recorded_kit)
        .chain(std::iter::once(kit))
        .collect();
    // Install hooks run as the create ran them: in a v3 workload's image WORKDIR, with its image
    // user's HOME. Its agent files are the recorded `sbx.agent-file`, or none.
    let mut workload = empty_workload(&sb.meta.agent);
    workload.provides = own.iter().flat_map(|r| r.provides.clone()).collect();
    let rec = &sb.meta.rec;
    workload.config = rec.user.clone().map(|user| ImageConfig {
        workdir: rec.image_workdir.clone().unwrap_or_default(),
        user,
        ..Default::default()
    });
    // The image's `Env` and the create's `-e` aren't kept with the sandbox: `${{ kit.env.* }}`
    // reads the kits' exports and the sandbox's runtime-owned values only here (no id: missing).
    let id = rec.id.as_deref().unwrap_or_default();
    let runtime: Vec<_> = sandbox::env::runtime_env(&sb.meta.name, id, &sb.workdir())
        .into_iter()
        .filter(|(_, v)| !v.is_empty())
        .collect();
    let hosted = sb.meta.egress.is_some();
    let plan = resolve_for(workload, mixins, values, &sb.workdir(), &runtime, hosted)?;
    plan.warn_skipped();

    // In memory until approved.
    let mut policy = provision::ensure_policy(ctx)?;
    let secrets = SecretsFile::load(&ctx.paths)?;
    // The workspaces place the agent file (and keep context out of mounts); a workload kit's
    // agent file was recorded at create.
    let mut req = CreateRequest {
        rec: Recorded {
            agent_files: sb.meta.rec.agent_files.clone(),
            agent_context: sb.meta.rec.agent_context,
            ..Default::default()
        },
        name: name.to_string(),
        workspaces: sb
            .meta
            .workspaces
            .iter()
            .map(|w| Workspace::from_label(w))
            .collect(),
        ..Default::default()
    };
    let (mut steps, added) = apply(
        &plan,
        &mut req,
        &mut policy,
        &secrets,
        &*ctx.store,
        &ctx.paths.kit_cache(),
        &|| provision::host_git_identity(ctx),
    )?;
    let mut hosts: Vec<String> = added
        .iter()
        .filter_map(|id| policy.find(id))
        .filter(|(r, _)| r.decision == Decision::Allow)
        .flat_map(|(r, _)| r.resources.clone())
        .collect();
    hosts.sort();
    hosts.dedup();
    if !hosts.is_empty() && !yes {
        approve(ctx, &kit_name, &hosts, started)?;
    }

    // The record (`sbx.kits`) and startup script go after the existing ones. The recorded kits'
    // records in `req` carry the placeholder digest, so only the new kit's is taken.
    let mut kits = existing.clone();
    kits.extend(req.rec.kits.iter().find(|k| k.name == kit_name).cloned());
    steps.kit_names = kits.iter().map(|k| k.name.clone()).collect();
    steps.startup_d = (steps.startup_d.pop())
        .map(|(_, body)| (format!("{:02}-{kit_name}.sh", existing.len() + 1), body))
        .into_iter()
        .collect();

    // Pushes the sandbox's network: this add's install-phase rules are open while they're stored.
    let push = |policy: &Policy| -> Result<()> {
        let network = compile::network_of(policy, &sb.meta);
        // An open network (allow-all) has no allow list to change, and smolvm can't add one live.
        if network == crate::smolvm::NetworkSpec::Open {
            return Ok(());
        }
        ctx.vm.update_network(&sb.machine, &network)
    };
    // `None`: opening the kit's network, before any hook ran.
    let result = (|| -> std::result::Result<(), (Option<KitPhase>, anyhow::Error)> {
        // Install rules an interrupted add left are pushed too: `added` doesn't list them.
        if !added.is_empty() || !steps.install_rules.is_empty() {
            let open = || -> Result<()> {
                let ids: Vec<String> = added.iter().chain(&steps.install_rules).cloned().collect();
                let saved = policy.save_rules(&ctx.paths, name, &ids)?;
                push(&saved).context("applying the kit's network rules")
            };
            open().map_err(|e| (None, e))?;
        }
        sandbox::apply_kit_steps(
            &ctx.vm,
            sb,
            &steps,
            || {
                if steps.install_rules.is_empty() {
                    return Ok(());
                }
                let policy = Policy::update(&ctx.paths, |p| {
                    p.remove_rules_by_ids(name, &steps.install_rules);
                    Ok(p.clone())
                })?;
                push(&policy).context("removing the install-phase network rules")
            },
            &mut |_| {},
        )
        .map_err(|(phase, e)| (Some(phase), e))
    })();
    if let Err((phase, e)) = result {
        let hooks_ran = !steps.install.is_empty()
            && matches!(phase, Some(KitPhase::Install | KitPhase::AfterInstall));
        let mut msg = match phase {
            Some(KitPhase::Write) if added.is_empty() => {
                format!("kit add failed; files it wrote may remain: {e:#}")
            }
            Some(KitPhase::Write) => format!(
                "kit add failed; its network rules were removed, but files it wrote may remain: \
                 {e:#}"
            ),
            _ if hooks_ran => format!(
                "kit add failed; nothing was kept, but install hooks may have changed the \
                 sandbox: {e:#}"
            ),
            _ => format!("kit add failed; nothing was kept: {e:#}"),
        };
        if !added.is_empty() {
            let rollback = || -> Result<()> {
                let policy = Policy::update(&ctx.paths, |p| {
                    p.remove_rules_by_ids(name, &added);
                    Ok(p.clone())
                })?;
                push(&policy)
            };
            if let Err(r) = rollback() {
                msg.push_str(&format!(
                    "\nremoving the kit's network rules failed too ({r:#}); remove them with \
                     `bento policy rm network --sandbox {name} --id <id>` (rule ids: {})",
                    added.join(", ")
                ));
            }
        }
        bail!(msg);
    }
    ctx.vm
        .set_label(&sb.machine, labels::KITS, &labels::kits_value(&kits))
        .context("recording the kit in the sandbox's labels")?;
    // The first kit with agent context settles the version the later ones keep to.
    if let Some(v) = req
        .rec
        .agent_context
        .filter(|v| sb.meta.rec.agent_context != Some(*v))
    {
        ctx.vm
            .set_label(&sb.machine, labels::AGENT_CONTEXT, &v.to_string())
            .context("recording the agent-context version in the sandbox's labels")?;
    }
    // Like a create (R30): the kit stays, and each later start warns until its hooks succeed.
    if let Some((file, _)) = steps.startup_d.first()
        && let Err(e) =
            sandbox::run_startup(&ctx.vm, sb, Some(&format!("{}/{file}", guest::STARTUP_DIR)))
    {
        crate::warning!(
            "kit {kit_name}'s startup hooks failed: {e:#}; later starts warn until they \
             succeed"
        );
    }
    writeln!(&ctx.out, "Added kit {kit_name} to {name}")?;
    Ok(0)
}

/// Asks before a kit widens the sandbox's network access (SPEC-v3 §7.4); declining is an error.
fn approve<R: Runner>(ctx: &Ctx<R>, kit: &str, hosts: &[String], started: bool) -> Result<()> {
    if !ctx.can_prompt() {
        bail!("kit add needs --yes to grant network access without a terminal");
    }
    if super::ask(ctx, &format!("Allow {kit} to reach: {}?", hosts.join(", ")))? {
        Ok(())
    } else {
        // `add` notes the start itself.
        bail!(if started {
            "aborted"
        } else {
            "aborted; nothing was changed"
        })
    }
}

#[cfg(test)]
mod tests;
