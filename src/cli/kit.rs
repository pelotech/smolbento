//! `sbt kit inspect|validate|add`.

use std::io::Write;

use anyhow::{Context, Result, anyhow, bail};

use super::Ctx;
use super::args::{KitArgOpts, KitCmd, KitFormat};
use super::kit_doc::Doc;
use super::plan;
use crate::kits::apply::apply;
use crate::kits::args::{ArgValues, NoResolvedValue};
use crate::kits::model::{Cap, CapBody, Content, ImageConfig, Kind, Kit, Source};
use crate::kits::resolve::{resolve, resolve_for};
use crate::kits::{capability, compose, guest, load};
use crate::policy::{Decision, Policy, compile};
use crate::sandbox::{self, CreateRequest, KitPhase, Sandbox};
use crate::secrets::SecretsFile;
use crate::smolvm::{ExecSpec, Runner};
use crate::workspace::Workspace;

/// Reads the guest's kits record; a sandbox without one has no kits.
const READ_KITS: &str = "[ ! -e /etc/smolbento/kits ] || cat /etc/smolbento/kits";

pub fn run<R: Runner>(ctx: &mut Ctx<R>, cmd: KitCmd) -> Result<i32> {
    match cmd {
        KitCmd::Inspect {
            reference,
            args,
            format,
            json,
            offline,
        } => inspect(ctx, &reference, &args, format_of(format, json), offline),
        KitCmd::Validate {
            reference,
            args,
            format,
            json,
            offline,
        } => validate(ctx, &reference, &args, format_of(format, json), offline),
        KitCmd::Add {
            sandbox,
            reference,
            args,
            yes,
        } => add(ctx, &sandbox, &reference, &args, yes),
        KitCmd::Pack(_) => pending("pack"),
        KitCmd::Push(_) => pending("push"),
        KitCmd::Pull(_) => pending("pull"),
        KitCmd::Sign(_) => pending("sign"),
        KitCmd::Verify(_) => pending("verify"),
    }
}

/// sbx kit subcommands smolbento doesn't have yet: exit 2, like other pending commands.
fn pending(sub: &str) -> Result<i32> {
    Err(super::Unsupported(format!("`sbt kit {sub}` is not implemented yet")).into())
}

/// `--json` is `--format json`.
fn format_of(format: Option<KitFormat>, json: bool) -> KitFormat {
    if json {
        KitFormat::Json
    } else {
        format.unwrap_or(KitFormat::Table)
    }
}

fn arg_values(a: &KitArgOpts) -> Result<ArgValues> {
    ArgValues::parse(&a.kit_args_file, &a.kit_arg)
}

/// The kit as loaded, without resolving it: sbx's summary table (then which capabilities
/// smolbento supports), or its v2-shaped descriptor as JSON or YAML.
fn inspect<R: Runner>(
    ctx: &Ctx<R>,
    reference: &str,
    args: &KitArgOpts,
    format: KitFormat,
    offline: bool,
) -> Result<i32> {
    // Only checked: inspecting doesn't expand anything.
    arg_values(args)?;
    let kit = load::load_with(ctx, reference, offline)?;
    let doc = Doc::new(&kit);
    let mut out = &ctx.out;
    match format {
        KitFormat::Json => writeln!(out, "{}", doc.json()?)?,
        KitFormat::Yaml => write!(out, "{}", doc.yaml()?)?,
        KitFormat::Table => {
            write!(out, "{}", doc.table(&kit))?;
            if !kit.caps.is_empty() {
                writeln!(out, "Capabilities:")?;
                let mut rows = vec![vec!["TYPE".into(), "OPTIONAL".into(), "SUPPORT".into()]];
                for c in &kit.caps {
                    rows.push(vec![
                        c.ty.clone(),
                        if c.optional { "yes" } else { "no" }.into(),
                        if supported(c) {
                            "supported"
                        } else {
                            "not supported"
                        }
                        .into(),
                    ]);
                }
                write!(out, "{}", super::table(rows))?;
            }
            write!(out, "{}", doc.extras_table())?;
        }
    }
    Ok(0)
}

/// Whether smolbento can provide the capability (`resolve` fails a required one it can't).
fn supported(c: &Cap) -> bool {
    match &c.body {
        CapBody::Unsupported => false,
        CapBody::Credential(r) => r.oauth.as_ref().is_none_or(|o| o.passthrough),
        // Method and path qualifiers aren't enforced.
        CapBody::Network { install, runtime } => [install, runtime]
            .iter()
            .flat_map(|r| r.allow.iter().chain(&r.deny))
            .all(|n| n.methods.is_empty() && n.paths.is_empty()),
        // `authenticate` limits aren't enforced yet (Phase 5g).
        CapBody::SshAgent { authenticate, .. } => authenticate.is_empty(),
        _ => true,
    }
}

/// Loads and resolves the kit on its own: a workload by itself, a mixin on an empty workload that
/// provides whatever the mixin requires, at a version its constraints accept.
fn validate<R: Runner>(
    ctx: &Ctx<R>,
    reference: &str,
    args: &KitArgOpts,
    format: KitFormat,
    offline: bool,
) -> Result<i32> {
    let checked = check_kit(ctx, reference, args, offline);
    if format == KitFormat::Table {
        for w in checked? {
            eprintln!("warning: {w}");
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
    if format == KitFormat::Json {
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
    let values = arg_values(args)?;
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
    load::check_launchable(ctx, &mut kit)?;
    let resolved = match kit.kind {
        Kind::Workload => resolve(kit, vec![], &values),
        Kind::Mixin => {
            let mut base = empty_workload("validate");
            // A version within each require's constraints; a malformed one fails in `resolve`.
            base.provides = kit
                .requires
                .iter()
                .filter_map(|r| capability::parse_require(r).ok())
                .map(|r| capability::witness(&r))
                .collect();
            resolve(base, vec![kit], &values)
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
        return if reference == "docker" {
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

/// A synthetic preset workload with nothing in it: the existing sandbox's agent for `kit add`.
fn empty_workload(name: &str) -> Kit {
    Kit {
        name: name.to_string(),
        source: Source::Preset(String::new()),
        digest: None,
        kind: Kind::Workload,
        provides: vec![],
        requires: vec![],
        integrates: vec![],
        conflicts: vec![],
        args: Default::default(),
        caps: vec![],
        env: vec![],
        content: Content::Image(String::new()),
        command: None,
        config: None,
        reference: None,
    }
}

/// What in `kit` only a create can apply (spec "Data flow", `kit add`), in a fixed order.
fn needs_recreate(kit: &Kit) -> Result<Vec<&'static str>> {
    let mut what = Vec::new();
    if compose::has_layers(kit)? {
        what.push("image layers");
    }
    for c in &kit.caps {
        let need = match &c.body {
            // A passthrough OAuth credential only adds network rules.
            CapBody::Credential(r) if r.env.is_some() || !r.inject.is_empty() => "credentials",
            CapBody::Port { .. } => "ports",
            CapBody::Volume { .. } => "volumes",
            CapBody::HostMount { .. } => "host mounts",
            CapBody::AgentSkills { .. } | CapBody::AgentSkill { .. } => "agent skills",
            // The agent socket is mounted at create.
            CapBody::SshAgent { .. } => "SSH agent",
            CapBody::Resources { .. } => "resources",
            CapBody::LongRunning => "long-running",
            _ => continue,
        };
        what.push(need);
    }
    if !kit.env.is_empty() {
        what.push("environment variables");
    }
    let order = [
        "image layers",
        "credentials",
        "ports",
        "volumes",
        "host mounts",
        "SSH agent",
        "resources",
        "environment variables",
        "long-running",
    ];
    what.sort_by_key(|w| order.iter().position(|o| o == w));
    what.dedup();
    Ok(what)
}

/// One `/etc/smolbento/kits` line: `name<TAB>ref<TAB>provides`.
struct Recorded {
    name: String,
    reference: String,
    provides: Vec<String>,
}

fn parse_record(text: &str) -> Vec<Recorded> {
    text.lines()
        .filter(|l| {
            let named = !l.split('\t').next().unwrap_or_default().trim().is_empty();
            if !named && !l.trim().is_empty() {
                eprintln!("warning: ignoring a malformed line in /etc/smolbento/kits: {l:?}");
            }
            named
        })
        .map(|l| {
            let mut f = l.split('\t');
            let name = f.next().unwrap_or_default().to_string();
            let reference = f.next().unwrap_or_default().to_string();
            let provides = f
                .next()
                .unwrap_or_default()
                .split(',')
                .filter(|p| !p.is_empty())
                .map(String::from)
                .collect();
            Recorded {
                name,
                reference,
                provides,
            }
        })
        .collect()
}

/// A recorded kit as a mixin that only provides: its capabilities were applied already.
fn recorded_kit(r: &Recorded) -> Kit {
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
    let values = arg_values(args)?;
    let mut sb = sandbox::get(&ctx.vm, name)?;
    let kit = load::load(ctx, reference)?;
    if kit.kind != Kind::Mixin {
        bail!("{reference} is a workload kit, not a mixin; only mixins can be added to a sandbox");
    }
    // Before anything changes, the sandbox's start included.
    let recreate = needs_recreate(&kit)?;
    if !recreate.is_empty() {
        bail!("recreate required: {}", recreate.join(", "));
    }
    let started = !sb.is_running();
    plan::ensure_running(ctx, &mut sb)?;
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
    let record = ctx
        .vm
        .exec_captured(&ExecSpec {
            name: sb.machine.clone(),
            user: Some("root".into()),
            cmd: vec!["sh".into(), "-c".into(), READ_KITS.into()],
            ..Default::default()
        })
        .context("reading the sandbox's kits")?
        .stdout;
    let existing = parse_record(&record);
    if existing.iter().any(|r| r.name == kit.name) {
        bail!("kit {} is already in {name}", kit.name);
    }
    let kit_name = kit.name.clone();
    let mixins: Vec<Kit> = existing
        .iter()
        .map(recorded_kit)
        .chain(std::iter::once(kit))
        .collect();
    // Install hooks run where the create ran them: a v3 workload's image WORKDIR.
    let mut workload = empty_workload(&sb.meta.agent);
    // A workload kit, whatever its name, isn't a preset: create gives every one a command
    // (`sbx.command`), and its agent file is the recorded `sbx.agent-file` or none.
    if sb.meta.command.is_some() {
        workload.source = Source::Registry(String::new());
        workload.digest = Some("sha256:recorded".into());
    } else {
        // A preset provides its agent name, as at create (the image isn't recorded: version 0).
        workload.provides = vec![load::preset_provide(&sb.meta.agent, "")];
    }
    workload.config = sb.meta.image_workdir.clone().map(|workdir| ImageConfig {
        workdir,
        ..Default::default()
    });
    let plan = resolve_for(workload, mixins, values, &sb.workdir())?;
    plan.warn_skipped();

    // In memory until approved.
    let mut policy = plan::ensure_policy(ctx)?;
    let secrets = SecretsFile::load(&ctx.paths)?;
    // The workspaces place the agent file (and keep context out of mounts); a workload kit's
    // agent file was recorded at create.
    let mut req = CreateRequest {
        name: name.to_string(),
        workspaces: sb
            .meta
            .workspaces
            .iter()
            .map(|w| Workspace::from_label(w))
            .collect(),
        agent_file: sb.meta.agent_file.clone(),
        ..Default::default()
    };
    let (mut steps, added) = apply(
        &plan,
        &mut req,
        &mut policy,
        &secrets,
        &*ctx.store,
        &ctx.paths.kit_cache(),
        &|| plan::host_git_identity(ctx),
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

    // The record and startup script go after the existing ones.
    let line = steps
        .kits_record
        .lines()
        .find(|l| l.split('\t').next() == Some(kit_name.as_str()))
        .context("the kit's record line")?
        .to_string();
    let mut record = record;
    if !record.is_empty() && !record.ends_with('\n') {
        record.push('\n');
    }
    steps.kits_record = format!("{record}{line}\n");
    let startup = steps.startup_d.pop().map(|(_, body)| {
        let file = format!("{:02}-{kit_name}.sh", existing.len() + 1);
        (format!("{}/{file}", guest::STARTUP_DIR), file, body)
    });
    steps.startup_d = startup
        .iter()
        .map(|(_, file, body)| (file.clone(), body.clone()))
        .collect();

    // Opens this add's install-phase rules (and no others) until they're removed.
    let push = |policy: &Policy| -> Result<()> {
        let network = compile::network_with(
            policy,
            name,
            &sb.meta.credential_hosts,
            &steps.install_rules,
            sb.meta.host_access,
        );
        ctx.vm.update_network(&sb.machine, &network)
    };
    // `None`: opening the kit's network, before any hook ran.
    let result = (|| -> std::result::Result<(), (Option<KitPhase>, anyhow::Error)> {
        // Install rules an interrupted add left are opened too: `added` doesn't list them.
        if !added.is_empty() || !steps.install_rules.is_empty() {
            let open = || -> Result<()> {
                policy.save(&ctx.paths)?;
                push(&policy).context("applying the kit's network rules")
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
                let mut policy = Policy::load(&ctx.paths)?;
                policy.remove_rules_by_ids(name, &steps.install_rules);
                policy.save(&ctx.paths)?;
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
                let mut policy = Policy::load(&ctx.paths)?;
                policy.remove_rules_by_ids(name, &added);
                policy.save(&ctx.paths)?;
                push(&policy)
            };
            if let Err(r) = rollback() {
                msg.push_str(&format!(
                    "\nremoving the kit's network rules failed too ({r:#}); remove them with \
                     `sbt policy rm network --sandbox {name} --id <id>` (rule ids: {})",
                    added.join(", ")
                ));
            }
        }
        bail!(msg);
    }
    // Like a create (R30): the kit stays, and later starts fail until its hooks succeed.
    if let Some((path, _, _)) = &startup
        && let Err(e) = sandbox::run_startup(&ctx.vm, sb, Some(path))
    {
        eprintln!(
            "warning: kit {kit_name}'s startup hooks failed: {e:#}; later starts fail until they \
             succeed"
        );
    }
    writeln!(&ctx.out, "Added kit {kit_name} to {name}")?;
    Ok(0)
}

/// Asks before a kit widens the sandbox's network access (SPEC-v3 §7.4); declining is an error.
fn approve<R: Runner>(ctx: &Ctx<R>, kit: &str, hosts: &[String], started: bool) -> Result<()> {
    if !ctx.stdin_tty {
        bail!("kit add needs --yes to grant network access without a terminal");
    }
    // A question, not command output: stderr, like the secret value prompt.
    let mut err = std::io::stderr().lock();
    write!(err, "Allow {kit} to reach: {}? [y/N] ", hosts.join(", "))?;
    err.flush()?;
    drop(err);
    if super::is_yes(&ctx.read_line()?) {
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
mod tests {
    use std::fs;

    use super::super::testutil::*;
    use crate::kits::guest;
    use crate::kits::model::{Hook, HookCmd};
    use crate::policy::Policy;

    const MACHINE: &str = "sbx-dev";
    const BASE: &str = "base\tghcr.io/acme/base@sha256:00\tbase\n";

    fn kit_env() -> TestEnv {
        test_env(&[("SMOLBENTO_KIT_ALLOW_LOCAL_KITS", "true")])
    }

    fn v2_fixture(name: &str) -> String {
        format!(
            "{}/tests/fixtures/kits/v2/{name}",
            env!("CARGO_MANIFEST_DIR")
        )
    }

    /// A running shell sandbox `dev` whose guest kits record is `record`.
    fn dev_sandbox(t: &TestEnv, record: &str) {
        dev_sandbox_in(t, "running", record);
    }

    fn dev_sandbox_in(t: &TestEnv, state: &str, record: &str) {
        dev_sandbox_labeled(t, state, &[("sbx.agent", "shell")], record);
    }

    /// `dev` with `labels` besides its name.
    fn dev_sandbox_labeled(t: &TestEnv, state: &str, labels: &[(&str, &str)], record: &str) {
        let fake = t.ctx.vm.runner();
        let mut all = vec![("sbx.name", "dev")];
        all.extend_from_slice(labels);
        fake.ok(
            &["machine", "status", "-n", MACHINE],
            &machine_json(MACHINE, state, &all),
        );
        fake.ok(
            &[
                "machine",
                "exec",
                "--name",
                MACHINE,
                "-u",
                "root",
                "--",
                "sh",
                "-c",
                super::READ_KITS,
            ],
            record,
        );
    }

    const NET_KIT: &str = r#"{"schemaVersion":"3","kind":"mixin","name":"net",
        "provides":["net@1.0.0"],"requires":["base"],
        "capabilities":[
          {"type":"com.docker.sandbox/network-policy@1","config":{
            "install":{"allow":["pkg.example.com"]},"runtime":{"allow":["api.net.example"]}}},
          {"type":"com.docker.sandbox/lifecycle@1","config":{
            "install":[{"command":"echo hi"}],
            "startup":[{"command":"echo up"}],
            "files":[{"path":"/home/agent/.netrc2","content":"x"}]}},
          {"type":"com.docker.sandbox/agent-context@1","config":{"content":"Use net."}}]}"#;

    fn install_script() -> String {
        let h = Hook {
            command: HookCmd::Shell("echo hi".into()),
            user: None,
            env: vec![],
            background: false,
            clean_env: true,
        };
        format!("cd / && {}", guest::hook_script(&h))
    }

    /// Resources of `net`'s rules (`created_via = kit:net`).
    fn kit_rules(t: &TestEnv) -> Vec<String> {
        Policy::load(&t.ctx.paths)
            .unwrap()
            .all_rules()
            .filter(|(r, _)| r.created_via == "kit:net")
            .flat_map(|(r, _)| r.resources.clone())
            .collect()
    }

    fn dev_calls(t: &TestEnv) -> Vec<String> {
        t.ctx
            .vm
            .runner()
            .call_lines()
            .into_iter()
            .filter(|l| l.contains(MACHINE) && !l.contains("machine status"))
            .collect()
    }

    #[test]
    fn host_mount_and_ssh_agent_without_authenticate_are_supported() {
        let cap = |body| super::Cap {
            ty: String::new(),
            optional: false,
            body,
        };
        let host = cap(super::CapBody::HostMount {
            path: "/data".into(),
            mode: None,
        });
        assert!(super::supported(&host));
        assert!(!super::supported(&cap(super::CapBody::Unsupported)));
        let ssh = |authenticate: Vec<String>| {
            cap(super::CapBody::SshAgent {
                phases: vec![crate::kits::model::SshPhase::Runtime],
                unrestricted: false,
                sign: vec!["git".into()],
                authenticate,
            })
        };
        assert!(super::supported(&ssh(vec![])));
        assert!(!super::supported(&ssh(vec!["github.com".into()])));
    }

    #[test]
    fn inspect_prints_sbxs_table_then_the_capability_support() {
        let mut t = kit_env();
        v3_kit(&t, "net", NET_KIT, &[]);
        sbt(&mut t.ctx, &["kit", "inspect", "./net"]).unwrap();
        let out = t.stdout();
        let (head, rest) = out.split_once("Capabilities:\n").expect(&out);
        let template = head.lines().nth(3).unwrap();
        assert!(template.starts_with("Template: sbx-kit-src:net-"), "{out}");
        let head = head.replacen(template, "Template: T", 1);
        insta::assert_snapshot!(head, @r"
        Name: net
        Kind: mixin
        Schema: v3
        Template: T
        Policies:
          Network: 2 allow, 0 deny
        Credentials: 0 sources
        Commands: 1 install, 1 startup, 1 init files
        ");
        assert!(rest.contains("com.docker.sandbox/agent-context@1"), "{out}");
    }

    #[test]
    fn inspect_counts_a_v2_kits_credentials_and_rules() {
        let mut t = kit_env();
        let full = v2_fixture("full");
        sbt(&mut t.ctx, &["kit", "inspect", &full]).unwrap();
        let out = t.stdout();
        let head = out.split_once("Capabilities:").expect(&out).0;
        insta::assert_snapshot!(head, @r"
        Name: full-kit
        Kind: workload
        Schema: v2
        Policies:
          Network: 2 allow, 1 deny
        Credentials: 2 sources
        Commands: 2 install, 2 startup, 4 init files
        ");
        assert!(t.ctx.vm.runner().call_lines().is_empty());
    }

    #[test]
    fn inspect_json_is_the_v2_shaped_document_even_for_v3() {
        let mut t = kit_env();
        let full = v2_fixture("full");
        sbt(&mut t.ctx, &["kit", "inspect", &full, "--format", "json"]).unwrap();
        let json = t.stdout();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            [
                "credentials",
                "kind",
                "name",
                "permissions",
                "sandbox",
                "schemaVersion",
                "setup",
                "smolbento"
            ]
        );
        assert_eq!(v["schemaVersion"], "2");
        assert_eq!(v["kind"], "sandbox");
        assert_eq!(v["name"], "full-kit");
        assert_eq!(
            v["sandbox"],
            serde_json::json!({"image": "ghcr.io/example/agent:1.2",
                "resources": {"cpu": 2, "memory": "4g"}})
        );
        assert_eq!(
            v["permissions"],
            serde_json::json!({"network": {
                "allow": ["api.example.com", "*.cdn.example.com"],
                "deny": ["telemetry.example.com"]}})
        );
        assert_eq!(v["credentials"][0]["service"], "example");
        assert_eq!(v["credentials"][0]["apiKey"]["name"], "EXAMPLE_API_KEY");
        assert_eq!(
            v["setup"]["install"][1],
            serde_json::json!({"command": "echo hi", "user": "1000"})
        );
        // Two `setup.files` plus the two static files under `files/home` and `files/workspace`.
        assert_eq!(v["setup"]["files"].as_array().unwrap().len(), 4);

        sbt(&mut t.ctx, &["kit", "inspect", &full, "--json"]).unwrap();
        assert_eq!(t.stdout(), json, "--json is --format json");

        v3_kit(&t, "net", NET_KIT, &[]);
        sbt(&mut t.ctx, &["kit", "inspect", "./net", "--json"]).unwrap();
        let v: serde_json::Value = serde_json::from_str(&t.stdout()).unwrap();
        assert_eq!(v["schemaVersion"], "2");
        assert_eq!(v["kind"], "mixin");
        assert_eq!(
            v["permissions"]["network"]["allow"],
            serde_json::json!(["pkg.example.com", "api.net.example"])
        );
        assert_eq!(
            v["setup"]["install"],
            serde_json::json!([{"command": "echo hi"}])
        );
    }

    #[test]
    fn inspect_yaml_carries_the_same_document() {
        let mut t = kit_env();
        let full = v2_fixture("full");
        sbt(&mut t.ctx, &["kit", "inspect", &full, "--format", "json"]).unwrap();
        let json: serde_json::Value = serde_json::from_str(&t.stdout()).unwrap();
        sbt(&mut t.ctx, &["kit", "inspect", &full, "--format", "yaml"]).unwrap();
        let yaml = t.stdout();
        assert!(yaml.starts_with("schemaVersion: "), "{yaml}");
        let back: serde_json::Value = serde_saphyr::from_str(&yaml).unwrap();
        assert_eq!(back, json);
    }

    #[test]
    fn inspect_keeps_smolbentos_details_after_sbxs_table_and_under_one_json_key() {
        let mut t = kit_env();
        let kit = NET_KIT.replace(
            r#""provides":["net@1.0.0"]"#,
            r#""provides":["net@1.0.0"],"conflicts":["old"],"integrates":["extra"],
            "args":{"mode":{"default":"fast","enum":["fast","slow"]},"id":{"required":true}}"#,
        )
        .replace(
            r#""capabilities":["#,
            r#""capabilities":[
          {"type":"com.docker.sandbox/credential@1","config":{"service":"my-api","phase":"runtime","apiKey":{
            "inject":[{"domain":"api.x.com","header":"x-key"},{"domain":"up.x.com"}]}}},
          {"type":"com.docker.sandbox/credential@1","config":{"service":"droid","phase":"runtime","apiKey":{"name":"FACTORY_API_KEY"}}},
          {"type":"com.docker.sandbox/credential@1","config":{"service":"other","phase":"runtime","apiKey":{"name":"OTHER_KEY"}}},"#,
        );
        v3_kit(&t, "net", &kit, &[]);
        sbt(&mut t.ctx, &["kit", "inspect", "./net"]).unwrap();
        let out = t.stdout();
        let tail = out.split_once("Source: ").expect(&out).1;
        let tail: Vec<&str> = tail.lines().collect();
        assert!(tail[0].ends_with("(local v3)"), "{out}");
        assert!(tail[1].starts_with("Digest: sha256:"), "{out}");
        assert_eq!(
            &tail[2..],
            [
                "Provides: net@1.0.0",
                "Requires: base",
                "Integrates: extra",
                "Conflicts: old",
                "Credentials:",
                "  my-api  sent to api.x.com, up.x.com",
                "  droid  sent to api.factory.ai, app.factory.ai, relay.factory.ai",
                "  other  sent to the service's own hosts",
                "Args:",
                "  id  required",
                "  mode  default \"fast\", one of fast|slow",
            ],
            "{out}"
        );

        sbt(&mut t.ctx, &["kit", "inspect", "./net", "--json"]).unwrap();
        let v: serde_json::Value = serde_json::from_str(&t.stdout()).unwrap();
        let x = &v["smolbento"];
        assert_eq!(x["sourceType"], "local v3");
        assert_eq!(x["provides"], serde_json::json!(["net@1.0.0"]));
        assert_eq!(x["conflicts"], serde_json::json!(["old"]));
        assert_eq!(x["args"]["id"], serde_json::json!({"required": true}));
        assert_eq!(
            x["args"]["mode"],
            serde_json::json!({"required": false, "default": "fast", "enum": ["fast", "slow"]})
        );
        assert!(x["digest"].as_str().unwrap().starts_with("sha256:"));
    }

    #[test]
    fn validate_reports_every_failure_as_json_or_yaml_and_exits_1() {
        let mut t = kit_env();
        let net = NET_KIT.replace(
            r#""capabilities":["#,
            r#""args":{"id":{"required":true}},"capabilities":["#,
        );
        v3_kit(&t, "needarg", &net, &[]);
        let cases: [(&str, &str, &str); 3] = [
            ("./missing", "directory", "doesn't exist"),
            ("docker.io/x/y:1", "registry", "--offline"),
            ("./needarg", "directory", "argument id is required"),
        ];
        for (reference, kind, msg) in cases {
            let offline = if reference.starts_with("docker.io") {
                "--offline"
            } else {
                "--json"
            };
            let mut argv = vec!["kit", "validate", reference, "--format", "json"];
            if offline == "--offline" {
                argv.push(offline);
            }
            assert_eq!(sbt(&mut t.ctx, &argv).unwrap(), 1, "{reference}");
            let v: serde_json::Value = serde_json::from_str(&t.stdout()).unwrap();
            assert_eq!(v["reference"], reference);
            assert_eq!(v["kind"], kind);
            assert_eq!(v["valid"], false);
            assert_eq!(v["warnings"], serde_json::json!([]));
            let errors = v["errors"].as_array().unwrap();
            assert_eq!(errors.len(), 1, "{v}");
            assert!(errors[0].as_str().unwrap().contains(msg), "{v}");
        }
        v3_kit(
            &t,
            "odd",
            r#"{"schemaVersion":"3","kind":"mixin","name":"odd","capabilities":[
            {"type":"com.docker.sandbox/usb-device@1","optional":false}]}"#,
            &[],
        );
        assert_eq!(
            sbt(&mut t.ctx, &["kit", "validate", "./odd", "--json"]).unwrap(),
            1
        );
        let v: serde_json::Value = serde_json::from_str(&t.stdout()).unwrap();
        assert!(
            v["errors"][0].as_str().unwrap().contains("usb-device"),
            "{v}"
        );
        // yaml, and the plain error for a table.
        assert_eq!(
            sbt(
                &mut t.ctx,
                &["kit", "validate", "./missing", "--format", "yaml"]
            )
            .unwrap(),
            1
        );
        let y = t.stdout();
        assert!(
            y.starts_with("reference: ./missing\nkind: directory\nvalid: false\n"),
            "{y}"
        );
        let back: serde_json::Value = serde_saphyr::from_str(&y).unwrap();
        assert_eq!(back["valid"], false);
        sbt(&mut t.ctx, &["kit", "validate", "./missing"]).unwrap_err();
        assert_eq!(t.stdout(), "");
        // A success has no `errors` key.
        sbt(
            &mut t.ctx,
            &[
                "kit",
                "validate",
                &v2_fixture("tool-mixin"),
                "--format",
                "yaml",
            ],
        )
        .unwrap();
        assert!(!t.stdout().contains("errors"));
    }

    #[test]
    fn inspect_rejects_an_unknown_format() {
        let mut t = kit_env();
        let e = sbt(
            &mut t.ctx,
            &["kit", "inspect", &v2_fixture("full"), "--format", "xml"],
        )
        .unwrap_err();
        assert!(format!("{e:#}").contains("xml"), "{e:#}");
    }

    #[test]
    fn offline_takes_local_v2_without_the_source_policy_and_refuses_the_network() {
        // Local kits are refused by default: --offline skips that check, as in sbx.
        let mut t = test_env(&[("SMOLBENTO_KIT_ALLOW_LOCAL_KITS", "false")]);
        let full = v2_fixture("full");
        sbt(&mut t.ctx, &["kit", "inspect", &full]).unwrap_err();
        sbt(&mut t.ctx, &["kit", "inspect", &full, "--offline"]).unwrap();
        assert!(t.stdout().starts_with("Name: full-kit"));
        let tool = v2_fixture("tool-mixin");
        sbt(&mut t.ctx, &["kit", "validate", &tool, "--offline"]).unwrap();
        // A workload that takes its command from an image would need a registry lookup.
        let e = sbt(&mut t.ctx, &["kit", "validate", &full, "--offline"]).unwrap_err();
        assert!(format!("{e:#}").contains("--offline"), "{e:#}");

        let e = sbt(
            &mut t.ctx,
            &["kit", "inspect", "docker.io/x/y:1", "--offline"],
        )
        .unwrap_err();
        assert!(format!("{e:#}").contains("--offline"), "{e:#}");
        let e = sbt(
            &mut t.ctx,
            &["kit", "validate", "ghcr.io/x/y:1", "--offline"],
        )
        .unwrap_err();
        assert!(format!("{e:#}").contains("--offline"), "{e:#}");
        assert!(t.ctx.vm.runner().call_lines().is_empty());
    }

    #[test]
    fn offline_refuses_a_v3_source_directory_before_building() {
        let mut t = kit_env();
        v3_kit(&t, "net", NET_KIT, &[]);
        let e = sbt(&mut t.ctx, &["kit", "inspect", "./net", "--offline"]).unwrap_err();
        let msg = format!("{e:#}");
        assert!(
            msg.contains("--offline") && msg.contains("v3 source kit"),
            "{msg}"
        );
        assert!(t.ctx.vm.runner().call_lines().is_empty());
    }

    #[test]
    fn validate_json_reports_the_reference_kind_and_warnings() {
        let mut t = kit_env();
        let tool = v2_fixture("tool-mixin");
        sbt(&mut t.ctx, &["kit", "validate", &tool, "--json"]).unwrap();
        let v: serde_json::Value = serde_json::from_str(&t.stdout()).unwrap();
        assert_eq!(
            v,
            serde_json::json!({"reference": tool, "kind": "directory", "valid": true,
                "warnings": []})
        );
        v3_kit(
            &t,
            "odd",
            r#"{"schemaVersion":"3","kind":"mixin","name":"odd","capabilities":[
            {"type":"com.docker.sandbox/usb-device@1","optional":true}]}"#,
            &[],
        );
        sbt(&mut t.ctx, &["kit", "validate", "./odd", "--json"]).unwrap();
        let v: serde_json::Value = serde_json::from_str(&t.stdout()).unwrap();
        assert_eq!(v["reference"], "./odd");
        assert_eq!(v["kind"], "directory");
        assert_eq!(
            v["warnings"],
            serde_json::json!([
                "kit odd: skipping com.docker.sandbox/usb-device@1 (not supported)"
            ])
        );
    }

    #[test]
    fn inspect_marks_unsupported_capabilities() {
        let mut t = kit_env();
        v3_kit(
            &t,
            "odd",
            r#"{"schemaVersion":"3","kind":"mixin","name":"odd","capabilities":[
                {"type":"com.docker.sandbox/usb-device@1","optional":true}]}"#,
            &[],
        );
        sbt(&mut t.ctx, &["kit", "inspect", "./odd"]).unwrap();
        let out = t.stdout();
        let l = out
            .lines()
            .find(|l| l.starts_with("com.docker.sandbox/usb-device@1"))
            .unwrap_or_else(|| panic!("{out}"));
        assert!(l.contains("yes") && l.ends_with("not supported"), "{l}");
    }

    #[test]
    fn validate_prints_ok_or_fails_with_the_error() {
        let mut t = kit_env();
        assert_eq!(
            sbt(&mut t.ctx, &["kit", "validate", &v2_fixture("tool-mixin")]).unwrap(),
            0
        );
        assert_eq!(
            t.stdout(),
            format!("✓ {} — valid\n", v2_fixture("tool-mixin"))
        );

        let yaml = fs::read_to_string(format!(
            "{}/tests/fixtures/kits/v3/bad-config-key.yaml",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap();
        let v: serde_json::Value = serde_saphyr::from_str(&yaml).unwrap();
        v3_kit(&t, "bad", &v.to_string(), &[]);
        let e = sbt(&mut t.ctx, &["kit", "validate", "./bad"]).unwrap_err();
        assert!(format!("{e:#}").contains("sise"), "{e:#}");
        assert_eq!(super::super::exit_code(&e), 1);
        assert_eq!(t.stdout(), "");
    }

    #[test]
    fn validate_accepts_a_mixin_whose_provides_name_a_kit_arg() {
        let mut t = kit_env();
        let yaml = fs::read_to_string(format!(
            "{}/tests/fixtures/kits/v3/claude-mixin.yaml",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap();
        let v: serde_json::Value = serde_saphyr::from_str(&yaml).unwrap();
        v3_kit(&t, "claude-mixin", &v.to_string(), &[]);
        assert_eq!(
            sbt(&mut t.ctx, &["kit", "validate", "./claude-mixin"]).unwrap(),
            0
        );
        assert_eq!(
            sbt(
                &mut t.ctx,
                &[
                    "kit",
                    "validate",
                    "./claude-mixin",
                    "--kit-arg",
                    "version=2.2.0"
                ]
            )
            .unwrap(),
            0
        );
    }

    #[test]
    fn validate_refuses_a_workload_without_a_command() {
        let mut t = kit_env();
        v3_kit(
            &t,
            "nocmd",
            r#"{"schemaVersion":"3","kind":"workload","name":"nocmd"}"#,
            &[],
        );
        let e = sbt(&mut t.ctx, &["kit", "validate", "./nocmd"]).unwrap_err();
        assert_eq!(
            format!("{e:#}"),
            "workload kit image declares no ENTRYPOINT or CMD; the image config is the runtime \
             contract"
        );
        assert_eq!(t.stdout(), "");
    }

    #[test]
    fn validate_refuses_a_v2_workload_without_an_image_or_command() {
        let mut t = kit_env();
        let kit = t.ctx.cwd.join("noimg");
        fs::create_dir(&kit).unwrap();
        fs::write(
            kit.join("spec.yaml"),
            "schemaVersion: \"2\"\nkind: sandbox\nname: noimg\n",
        )
        .unwrap();
        let e = sbt(&mut t.ctx, &["kit", "validate", "./noimg"]).unwrap_err();
        assert_eq!(
            format!("{e:#}"),
            "workload kit declares no image or command"
        );
    }

    #[test]
    fn validate_accepts_v2_workspace_files() {
        let mut t = kit_env();
        let ws = v2_fixture("workspace-files");
        assert_eq!(sbt(&mut t.ctx, &["kit", "validate", &ws]).unwrap(), 0);
        assert_eq!(t.stdout(), format!("✓ {ws} — valid\n"));
    }

    #[test]
    fn validate_checks_kit_args() {
        let mut t = kit_env();
        let e = sbt(
            &mut t.ctx,
            &[
                "kit",
                "validate",
                &v2_fixture("tool-mixin"),
                "--kit-arg",
                "nope=1",
            ],
        )
        .unwrap_err();
        assert!(format!("{e:#}").contains("nope"), "{e:#}");
    }

    #[test]
    fn validate_reports_a_used_arg_with_no_value_like_sbx() {
        let mut t = kit_env();
        let dir = t.ctx.cwd.join("chk");
        fs::create_dir(&dir).unwrap();
        fs::write(
            dir.join("spec.yaml"),
            "schemaVersion: \"2\"\nkind: mixin\nname: chk\nargs:\n  opt:\n    description: d\n\
             setup:\n  install:\n    - command: echo ${{ kit.args.opt }}\n",
        )
        .unwrap();
        let e = sbt(&mut t.ctx, &["kit", "validate", "./chk"]).unwrap_err();
        assert_eq!(
            format!("{e:#}"),
            "kit chk: create-phase kit arg \"opt\" has no resolved value; \
             artifact validation failed"
        );
        assert_eq!(
            sbt(
                &mut t.ctx,
                &["kit", "validate", "./chk", "--kit-arg", "opt="]
            )
            .unwrap(),
            0
        );
    }

    #[test]
    fn adding_a_layered_mixin_needs_a_recreate() {
        let mut t = kit_env();
        dev_sandbox(&t, BASE);
        v3_kit(
            &t,
            "layered",
            r#"{"schemaVersion":"3","kind":"mixin","name":"layered"}"#,
            &[b"layer"],
        );
        let e = sbt(&mut t.ctx, &["kit", "add", "dev", "./layered", "--yes"]).unwrap_err();
        assert_eq!(format!("{e:#}"), "recreate required: image layers");
        assert!(dev_calls(&t).is_empty(), "{:#?}", dev_calls(&t));
        assert!(kit_rules(&t).is_empty());
    }

    #[test]
    fn adding_a_mixin_with_a_host_mount_needs_a_recreate() {
        let mut t = kit_env();
        dev_sandbox(&t, BASE);
        v3_kit(
            &t,
            "hm",
            r#"{"schemaVersion":"3","kind":"mixin","name":"hm","capabilities":[
                {"type":"com.docker.sandbox/host-mount@1","config":{"path":"/home/agent/x"}}]}"#,
            &[],
        );
        let e = sbt(&mut t.ctx, &["kit", "add", "dev", "./hm", "--yes"]).unwrap_err();
        assert_eq!(format!("{e:#}"), "recreate required: host mounts");
        assert!(dev_calls(&t).is_empty(), "{:#?}", dev_calls(&t));
    }

    #[test]
    fn adding_a_mixin_with_a_bundled_skill_needs_a_recreate() {
        let mut t = kit_env();
        dev_sandbox(&t, BASE);
        v3_kit(
            &t,
            "sk",
            r#"{"schemaVersion":"3","kind":"mixin","name":"sk","capabilities":[
                {"type":"com.docker.sandbox/agent-skill@1","config":{"path":"/usr/share/x/pr"}}]}"#,
            &[],
        );
        let e = sbt(&mut t.ctx, &["kit", "add", "dev", "./sk", "--yes"]).unwrap_err();
        assert_eq!(format!("{e:#}"), "recreate required: agent skills");
        assert!(dev_calls(&t).is_empty(), "{:#?}", dev_calls(&t));
    }

    /// The agent socket is mounted at create.
    #[test]
    fn adding_a_mixin_with_an_ssh_agent_needs_a_recreate() {
        let mut t = kit_env();
        dev_sandbox(&t, BASE);
        v3_kit(
            &t,
            "sa",
            r#"{"schemaVersion":"3","kind":"mixin","name":"sa","capabilities":[
                {"type":"com.docker.sandbox/host-mount@1","config":{"path":"/home/agent/x"}},
                {"type":"com.docker.sandbox/ssh-agent@1","config":{"phase":"runtime"}}]}"#,
            &[],
        );
        let e = sbt(&mut t.ctx, &["kit", "add", "dev", "./sa", "--yes"]).unwrap_err();
        assert_eq!(
            format!("{e:#}"),
            "recreate required: host mounts, SSH agent"
        );
        assert!(dev_calls(&t).is_empty(), "{:#?}", dev_calls(&t));
    }

    #[test]
    fn adding_a_mixin_with_ports_and_env_needs_a_recreate() {
        let mut t = kit_env();
        dev_sandbox(&t, BASE);
        let e = sbt(
            &mut t.ctx,
            &["kit", "add", "dev", &v2_fixture("tool-mixin"), "--yes"],
        )
        .unwrap_err();
        assert_eq!(
            format!("{e:#}"),
            "recreate required: ports, environment variables"
        );
        assert!(dev_calls(&t).is_empty(), "{:#?}", dev_calls(&t));
    }

    #[test]
    fn add_applies_a_network_and_hook_mixin_live() {
        let mut t = kit_env();
        set_policy(&t, "mode = \"deny-all\"\n");
        dev_sandbox(&t, BASE);
        v3_kit(&t, "net", NET_KIT, &[]);
        sbt(&mut t.ctx, &["kit", "add", "dev", "./net", "--yes"]).unwrap();
        assert!(t.stdout().contains("Added kit net to dev"));

        let lines = dev_calls(&t);
        let pos = |what: &str, pred: &dyn Fn(&String) -> bool| {
            lines
                .iter()
                .position(pred)
                .unwrap_or_else(|| panic!("no {what} in {lines:#?}"))
        };
        let read = pos("read", &|l| l.ends_with(super::READ_KITS));
        let open = pos("install network", &|l| {
            l.starts_with("machine update")
                && l.contains(" pkg.example.com")
                && l.contains(" api.net.example")
        });
        let hook = pos("hook", &|l| {
            *l == format!(
                "machine exec --name {MACHINE} -u root -- sh -c {}",
                install_script()
            )
        });
        let close = pos("runtime network", &|l| {
            l.starts_with("machine update")
                && l.contains("--reset-allow-list")
                && l.contains(" api.net.example")
                && !l.contains("pkg.example.com")
        });
        let file = pos("file", &|l| l.contains("/home/agent/.netrc2"));
        let context = pos("context", &|l| l.contains("Use net."));
        let startup_cp = pos("startup.d cp", &|l| {
            l.starts_with("machine cp ")
                && l.ends_with(&format!("{MACHINE}:/etc/smolbento/startup.d/02-net.sh"))
        });
        let script = Some("/etc/smolbento/startup.d/02-net.sh");
        let started = pos("startup", &|l| {
            *l == format!(
                "machine exec --name {MACHINE} -u root -- sh -c {}",
                crate::sandbox::startup_cmd(script)
            )
        });
        assert!(
            read < open
                && open < hook
                && hook < close
                && close < file
                && file < context
                && context < startup_cp
                && startup_cp < started,
            "{lines:#?}"
        );
        assert_eq!(lines.last(), Some(&lines[started]), "{lines:#?}");

        let uploads: std::collections::BTreeMap<String, String> =
            t.ctx.vm.runner().uploads().into_iter().collect();
        let kits = &uploads[&format!("{MACHINE}:{}", guest::KITS_FILE)];
        let net_dir = t.ctx.cwd.join("net").canonicalize().unwrap();
        // The record keeps each provide with its version, for a later `kit add`'s requires.
        assert_eq!(
            *kits,
            format!("{BASE}net\t{}\tnet@1.0.0\n", net_dir.display())
        );
        assert_eq!(
            uploads[&format!("{MACHINE}:{}", guest::STARTUP_PATH)],
            guest::STARTUP_RUNNER
        );
        assert_eq!(kit_rules(&t), vec!["api.net.example".to_string()]);
    }

    /// Whether `script` ran in `dev` as root, inline or copied in.
    fn ran(t: &TestEnv, script: &str) -> bool {
        let inline = format!("machine exec --name {MACHINE} -u root -- sh -c {script}");
        dev_calls(t).contains(&inline)
            || t.ctx.vm.runner().uploads().iter().any(|(_, c)| c == script)
    }

    #[test]
    fn add_indexes_a_mixin_context_beside_the_workspace() {
        let mut t = kit_env();
        dev_sandbox_labeled(
            &t,
            "running",
            &[
                ("sbx.agent", "claude"),
                ("sbx.workspace", "/w/proj"),
                ("sbx.workspaces", r#"["/w/proj"]"#),
            ],
            BASE,
        );
        v3_kit(&t, "net", NET_KIT, &[]);
        sbt(&mut t.ctx, &["kit", "add", "dev", "./net", "--yes"]).unwrap();
        let path = "/w/kits-agent-context/net.md";
        assert!(ran(&t, &guest::kit_context_script(path, &["Use net."])));
        let index = guest::kits_index_script("/w/CLAUDE.md", &[("net".into(), path.into())]);
        assert!(ran(&t, &index), "{:#?}", dev_calls(&t));
    }

    #[test]
    fn add_indexes_into_a_workload_kits_recorded_agent_file() {
        let mut t = kit_env();
        dev_sandbox_labeled(
            &t,
            "running",
            &[("sbx.agent", "wl"), ("sbx.agent-file", "/x/AGENTS.md")],
            BASE,
        );
        v3_kit(&t, "net", NET_KIT, &[]);
        sbt(&mut t.ctx, &["kit", "add", "dev", "./net", "--yes"]).unwrap();
        let path = "/x/kits-agent-context/net.md";
        let index = guest::kits_index_script("/x/AGENTS.md", &[("net".into(), path.into())]);
        assert!(ran(&t, &index), "{:#?}", dev_calls(&t));
    }

    #[test]
    fn add_drops_a_mixin_context_when_the_workload_has_no_agent_file() {
        // A workload kit named like a preset is still a workload kit: no preset agent file.
        for agent in ["wl", "claude"] {
            let mut t = kit_env();
            dev_sandbox_labeled(
                &t,
                "running",
                &[
                    ("sbx.agent", agent),
                    ("sbx.command", r#"["/bin/agent"]"#),
                    ("sbx.workspace", "/w/proj"),
                    ("sbx.workspaces", r#"["/w/proj"]"#),
                ],
                BASE,
            );
            v3_kit(&t, "net", NET_KIT, &[]);
            sbt(&mut t.ctx, &["kit", "add", "dev", "./net", "--yes"]).unwrap();
            assert_no_net_context(&t);
        }
    }

    fn assert_no_net_context(t: &TestEnv) {
        assert!(
            !dev_calls(t).iter().any(|l| l.contains("Use net."))
                && !t
                    .ctx
                    .vm
                    .runner()
                    .uploads()
                    .iter()
                    .any(|(_, c)| c.contains("Use net.")),
            "{:#?}",
            dev_calls(t)
        );
    }

    /// R30 for `kit add`: the kit stays and the sandbox keeps running.
    #[test]
    fn a_failing_startup_hook_on_kit_add_only_warns() {
        let mut t = kit_env();
        set_policy(&t, "mode = \"deny-all\"\n");
        dev_sandbox(&t, BASE);
        v3_kit(&t, "net", NET_KIT, &[]);
        let script = Some("/etc/smolbento/startup.d/02-net.sh");
        t.ctx.vm.runner().on(
            &[
                "machine",
                "exec",
                "--name",
                MACHINE,
                "-u",
                "root",
                "--",
                "sh",
                "-c",
                &crate::sandbox::startup_cmd(script),
            ],
            crate::smolvm::Output {
                code: 2,
                ..Default::default()
            },
        );
        sbt(&mut t.ctx, &["kit", "add", "dev", "./net", "--yes"]).unwrap();
        assert!(t.stdout().contains("Added kit net to dev"));
        let lines = dev_calls(&t);
        assert!(
            !lines.iter().any(|l| l.starts_with("machine stop")),
            "{lines:#?}"
        );
    }

    #[test]
    fn add_runs_install_hooks_in_the_recorded_image_workdir() {
        let mut t = kit_env();
        set_policy(&t, "mode = \"deny-all\"\n");
        dev_sandbox(&t, BASE);
        t.ctx.vm.runner().ok(
            &["machine", "status", "-n", MACHINE],
            &machine_json(
                MACHINE,
                "running",
                &[
                    ("sbx.name", "dev"),
                    ("sbx.agent", "shell"),
                    ("sbx.workdir", "/x"),
                ],
            ),
        );
        v3_kit(&t, "net", NET_KIT, &[]);
        sbt(&mut t.ctx, &["kit", "add", "dev", "./net", "--yes"]).unwrap();
        let want = format!(
            "machine exec --name {MACHINE} -u root -- sh -c {}",
            install_script().replacen("cd / ", "cd '/x' ", 1)
        );
        assert!(dev_calls(&t).contains(&want), "{:#?}", dev_calls(&t));
    }

    #[test]
    fn add_opens_install_rules_an_interrupted_add_left() {
        use crate::kits::model::{NetRule, Rules};
        let mut t = kit_env();
        set_policy(&t, "mode = \"deny-all\"\n");
        // Both of net's rules are already there, so this add adds none.
        let rules = |h: &str| Rules {
            allow: vec![NetRule {
                host: h.into(),
                methods: vec![],
                paths: vec![],
            }],
            deny: vec![],
        };
        let mut policy = Policy::load(&t.ctx.paths).unwrap();
        policy
            .add_kit_rules("dev", "net", &rules("api.net.example"), false)
            .unwrap();
        policy
            .add_kit_rules("dev", "net", &rules("pkg.example.com"), true)
            .unwrap();
        policy.save(&t.ctx.paths).unwrap();
        dev_sandbox(&t, BASE);
        v3_kit(&t, "net", NET_KIT, &[]);
        sbt(&mut t.ctx, &["kit", "add", "dev", "./net", "--yes"]).unwrap();

        let lines = dev_calls(&t);
        let hook = lines
            .iter()
            .position(|l| l.ends_with(&install_script()))
            .unwrap_or_else(|| panic!("{lines:#?}"));
        assert!(
            lines[..hook]
                .iter()
                .any(|l| l.starts_with("machine update") && l.contains(" pkg.example.com")),
            "{lines:#?}"
        );
        let p = Policy::load(&t.ctx.paths).unwrap();
        assert!(p.all_rules().all(|(r, _)| !r.is_kit_install()), "{p:?}");
    }

    #[test]
    fn add_without_yes_and_without_a_terminal_changes_nothing() {
        let mut t = kit_env();
        set_policy(&t, "mode = \"deny-all\"\n");
        dev_sandbox(&t, BASE);
        v3_kit(&t, "net", NET_KIT, &[]);
        let e = sbt(&mut t.ctx, &["kit", "add", "dev", "./net"]).unwrap_err();
        assert_eq!(
            format!("{e:#}"),
            "kit add needs --yes to grant network access without a terminal"
        );
        let lines = dev_calls(&t);
        assert!(
            lines
                .iter()
                .all(|l| l.ends_with(super::READ_KITS) && l.contains("machine exec")),
            "{lines:#?}"
        );
        assert!(kit_rules(&t).is_empty());
    }

    #[test]
    fn add_asks_before_granting_network_and_declining_changes_nothing() {
        let mut t = kit_env();
        set_policy(&t, "mode = \"deny-all\"\n");
        dev_sandbox(&t, BASE);
        v3_kit(&t, "net", NET_KIT, &[]);
        t.answer("n\n");
        let e = sbt(&mut t.ctx, &["kit", "add", "dev", "./net"]).unwrap_err();
        assert_eq!(format!("{e:#}"), "aborted; nothing was changed");
        assert!(kit_rules(&t).is_empty());
    }

    #[test]
    fn a_mixin_without_network_needs_no_approval() {
        let mut t = kit_env();
        dev_sandbox(&t, BASE);
        v3_kit(
            &t,
            "quiet",
            r#"{"schemaVersion":"3","kind":"mixin","name":"quiet","capabilities":[
                {"type":"com.docker.sandbox/lifecycle@1","config":{"install":[{"command":"echo hi"}]}}]}"#,
            &[],
        );
        sbt(&mut t.ctx, &["kit", "add", "dev", "./quiet"]).unwrap();
        let lines = dev_calls(&t);
        assert!(
            !lines.iter().any(|l| l.starts_with("machine update")),
            "{lines:#?}"
        );
        assert!(
            !lines.iter().any(|l| l.contains("startup.d")),
            "no startup hooks: {lines:#?}"
        );
    }

    #[test]
    fn add_meets_a_requires_on_the_sandboxs_agent_preset() {
        let mut t = kit_env();
        dev_sandbox_labeled(&t, "running", &[("sbx.agent", "claude")], "");
        v3_kit(
            &t,
            "forclaude",
            r#"{"schemaVersion":"3","kind":"mixin","name":"forclaude","requires":["claude"],
                "capabilities":[{"type":"com.docker.sandbox/lifecycle@1",
                "config":{"install":[{"command":"echo hi"}]}}]}"#,
            &[],
        );
        sbt(&mut t.ctx, &["kit", "add", "dev", "./forclaude"]).unwrap();
    }

    #[test]
    fn add_refuses_a_kit_already_in_the_sandbox_and_unmet_requirements() {
        let mut t = kit_env();
        dev_sandbox(&t, "net\tghcr.io/acme/net@sha256:01\tnet\n");
        v3_kit(&t, "net", NET_KIT, &[]);
        let e = sbt(&mut t.ctx, &["kit", "add", "dev", "./net", "--yes"]).unwrap_err();
        assert_eq!(format!("{e:#}"), "kit net is already in dev");

        // No base kit: a missing record is no kits, and `requires: base` is unmet.
        let mut t = kit_env();
        dev_sandbox(&t, "");
        v3_kit(&t, "net", NET_KIT, &[]);
        let e = sbt(&mut t.ctx, &["kit", "add", "dev", "./net", "--yes"]).unwrap_err();
        assert_eq!(
            format!("{e:#}"),
            "resolve: the kit set is not coherent:\n  - ./net requires \"base\" but nothing in \
             the set provides it; add a kit that provides com.docker.kit/base"
        );
        assert!(kit_rules(&t).is_empty());
    }

    #[test]
    fn add_matches_versioned_requires_against_the_recorded_provides() {
        let kit = NET_KIT.replace(r#""requires":["base"]"#, r#""requires":["base >= 2, < 3"]"#);
        // An old record's bare provide has no version: it meets only unconstrained requires.
        let mut t = kit_env();
        dev_sandbox(&t, BASE);
        v3_kit(&t, "net", &kit, &[]);
        let e = sbt(&mut t.ctx, &["kit", "add", "dev", "./net", "--yes"]).unwrap_err();
        assert_eq!(
            format!("{e:#}"),
            "resolve: the kit set is not coherent:\n  - ./net requires \"base >= 2, < 3\" but the \
             set only offers base (unversioned, from base)"
        );

        let mut t = kit_env();
        dev_sandbox(&t, "base\tghcr.io/acme/base@sha256:00\tbase@2.4.1\n");
        v3_kit(&t, "net", &kit, &[]);
        sbt(&mut t.ctx, &["kit", "add", "dev", "./net", "--yes"]).unwrap();
    }

    #[test]
    fn validate_checks_a_mixin_against_a_set_that_meets_its_requires() {
        let mut t = kit_env();
        let kit = NET_KIT.replace(
            r#""requires":["base"]"#,
            r#""requires":["base > 2.1, < 3","com.example/tool = 1.4"]"#,
        );
        v3_kit(&t, "net", &kit, &[]);
        assert_eq!(sbt(&mut t.ctx, &["kit", "validate", "./net"]).unwrap(), 0);
        assert_eq!(t.stdout(), "✓ ./net — valid\n");
    }

    #[test]
    fn add_refuses_a_workload_kit() {
        let mut t = kit_env();
        dev_sandbox(&t, BASE);
        let e = sbt(
            &mut t.ctx,
            &["kit", "add", "dev", &v2_fixture("tool-workload"), "--yes"],
        )
        .unwrap_err();
        assert!(format!("{e:#}").contains("not a mixin"), "{e:#}");
    }

    #[test]
    fn a_failed_install_hook_drops_the_kits_rules() {
        let mut t = kit_env();
        set_policy(&t, "mode = \"deny-all\"\n");
        let mut policy = Policy::load(&t.ctx.paths).unwrap();
        let mine = policy
            .add_rule(
                Some("dev"),
                crate::policy::Decision::Allow,
                "mine.example",
                "added",
                None,
                None,
            )
            .unwrap();
        policy.save(&t.ctx.paths).unwrap();
        dev_sandbox(&t, BASE);
        v3_kit(&t, "net", NET_KIT, &[]);
        t.ctx.vm.runner().fail(
            &[
                "machine",
                "exec",
                "--name",
                MACHINE,
                "-u",
                "root",
                "--",
                "sh",
                "-c",
                &install_script(),
            ],
            "exec",
            "apt broke",
        );
        let e = sbt(&mut t.ctx, &["kit", "add", "dev", "./net", "--yes"]).unwrap_err();
        let m = format!("{e:#}");
        assert!(
            m.starts_with("kit add failed; nothing was kept, but install hooks may have changed")
                && m.contains("kit net install hook 1 failed")
                && m.contains("apt broke"),
            "{m}"
        );
        assert!(kit_rules(&t).is_empty());
        let policy = Policy::load(&t.ctx.paths).unwrap();
        assert_eq!(
            policy.find(&mine).map(|(r, s)| (r.resources.clone(), s)),
            Some((vec!["mine.example".to_string()], Some("dev"))),
            "the user's own rule stays"
        );
        let lines = dev_calls(&t);
        let last_update = lines
            .iter()
            .rfind(|l| l.starts_with("machine update"))
            .unwrap();
        assert!(!last_update.contains("api.net.example"), "{lines:#?}");
        assert!(last_update.contains("mine.example"), "{lines:#?}");
        assert!(!lines.iter().any(|l| l.contains("machine delete")));
        assert!(
            !lines
                .iter()
                .any(|l| l.starts_with("machine cp") && l.ends_with(guest::KITS_FILE)),
            "{lines:#?}"
        );
    }

    #[test]
    fn a_failed_network_push_is_not_blamed_on_hooks() {
        let mut t = kit_env();
        set_policy(&t, "mode = \"deny-all\"\n");
        dev_sandbox(&t, BASE);
        v3_kit(&t, "net", NET_KIT, &[]);
        t.ctx
            .vm
            .runner()
            .once_fail(&["machine", "update", "-n", MACHINE], "net", "no route");
        let e = sbt(&mut t.ctx, &["kit", "add", "dev", "./net", "--yes"]).unwrap_err();
        let m = format!("{e:#}");
        assert!(
            m.starts_with("kit add failed; nothing was kept: ") && !m.contains("install hooks"),
            "{m}"
        );
        assert!(m.contains("no route"), "{m}");
        assert!(kit_rules(&t).is_empty());
        assert!(
            !dev_calls(&t).iter().any(|l| l.contains("echo hi")),
            "no hook ran"
        );
    }

    #[test]
    fn a_failed_write_without_kit_rules_claims_no_rule_removal() {
        let mut t = kit_env();
        dev_sandbox(&t, BASE);
        v3_kit(
            &t,
            "quiet",
            r#"{"schemaVersion":"3","kind":"mixin","name":"quiet","capabilities":[
                {"type":"com.docker.sandbox/lifecycle@1","config":{"install":[{"command":"echo hi"}]}}]}"#,
            &[],
        );
        // The startup files' `mkdir`, the first write.
        t.ctx.vm.runner().fail(
            &[
                "machine",
                "exec",
                "--name",
                MACHINE,
                "-u",
                "root",
                "--",
                "sh",
                "-c",
                "mkdir -p '/etc/smolbento'",
            ],
            "exec",
            "disk full",
        );
        let e = sbt(&mut t.ctx, &["kit", "add", "dev", "./quiet"]).unwrap_err();
        let m = format!("{e:#}");
        assert!(
            m.starts_with("kit add failed; files it wrote may remain: ") && !m.contains("rules"),
            "{m}"
        );
    }

    #[test]
    fn a_malformed_kits_record_line_does_not_block_adding() {
        let mut t = kit_env();
        set_policy(&t, "mode = \"deny-all\"\n");
        let record = format!("{BASE}odd\n\tno-name\tx\nloose\tunpinned-ref\tl\n");
        dev_sandbox(&t, &record);
        v3_kit(&t, "net", NET_KIT, &[]);
        sbt(&mut t.ctx, &["kit", "add", "dev", "./net", "--yes"]).unwrap();
        let uploads: std::collections::BTreeMap<String, String> =
            t.ctx.vm.runner().uploads().into_iter().collect();
        let kits = &uploads[&format!("{MACHINE}:{}", guest::KITS_FILE)];
        let net_dir = t.ctx.cwd.join("net").canonicalize().unwrap();
        assert_eq!(
            *kits,
            format!("{record}net\t{}\tnet@1.0.0\n", net_dir.display())
        );
    }

    #[test]
    fn a_refusal_after_starting_a_stopped_sandbox_says_so() {
        let mut t = kit_env();
        set_policy(&t, "mode = \"deny-all\"\n");
        dev_sandbox_in(&t, "stopped", BASE);
        v3_kit(&t, "net", NET_KIT, &[]);
        let e = sbt(&mut t.ctx, &["kit", "add", "dev", "./net"]).unwrap_err();
        assert_eq!(
            format!("{e:#}"),
            "kit add needs --yes to grant network access without a terminal\n\
             (dev was started for this and is still running)"
        );
        assert!(
            dev_calls(&t).iter().any(|l| l.starts_with("machine start")),
            "{:#?}",
            dev_calls(&t)
        );
    }
}
