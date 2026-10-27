//! `sbt kit inspect|validate|add`.

use std::io::{BufRead, Write};

use anyhow::{Context, Result, anyhow, bail};
use serde_json::json;

use super::Ctx;
use super::args::{KitArgOpts, KitCmd};
use super::plan;
use crate::kits::apply::apply;
use crate::kits::args::ArgValues;
use crate::kits::model::{Cap, CapBody, Content, Kind, Kit, Source};
use crate::kits::resolve::resolve;
use crate::kits::{compose, guest, load};
use crate::policy::{Decision, Policy, compile};
use crate::sandbox::{self, CreateRequest, KitPhase, Sandbox};
use crate::secrets::SecretsFile;
use crate::smolvm::{ExecSpec, Runner};

/// Reads the guest's kits record; a sandbox without one has no kits.
const READ_KITS: &str = "[ ! -e /etc/smolbento/kits ] || cat /etc/smolbento/kits";

pub fn run<R: Runner>(ctx: &mut Ctx<R>, cmd: KitCmd) -> Result<i32> {
    match cmd {
        KitCmd::Inspect {
            reference,
            args,
            json,
        } => inspect(ctx, &reference, &args, json),
        KitCmd::Validate { reference, args } => validate(ctx, &reference, &args),
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

fn arg_values(a: &KitArgOpts) -> Result<ArgValues> {
    ArgValues::parse(&a.kit_args_file, &a.kit_arg)
}

/// The kit as loaded, without resolving it: what it is and what it asks for.
fn inspect<R: Runner>(ctx: &Ctx<R>, reference: &str, args: &KitArgOpts, json: bool) -> Result<i32> {
    // Only checked: inspecting doesn't expand anything.
    arg_values(args)?;
    let kit = load::load(ctx, reference)?;
    let mut out = &ctx.out;
    let (source, from) = source_of(&kit.source);
    if json {
        let args: serde_json::Map<String, serde_json::Value> = kit
            .args
            .iter()
            .map(|(name, a)| {
                (
                    name.clone(),
                    json!({
                        "default": a.default,
                        "required": a.required,
                        "pattern": a.pattern,
                        "enum": a.enum_values,
                        "env": a.env,
                    }),
                )
            })
            .collect();
        let caps: Vec<_> = kit
            .caps
            .iter()
            .map(|c| json!({"type": c.ty, "optional": c.optional, "supported": supported(c)}))
            .collect();
        let v = json!({
            "name": kit.name,
            "kind": kind_name(kit.kind),
            "source": source,
            "sourceType": from,
            "digest": kit.digest,
            "provides": kit.provides,
            "requires": kit.requires,
            "args": args,
            "capabilities": caps,
        });
        writeln!(out, "{}", serde_json::to_string_pretty(&v)?)?;
        return Ok(0);
    }
    let list = |l: &[String]| {
        if l.is_empty() {
            "-".to_string()
        } else {
            l.join(", ")
        }
    };
    writeln!(out, "Name:      {}", kit.name)?;
    writeln!(out, "Kind:      {}", kind_name(kit.kind))?;
    writeln!(out, "Source:    {source} ({from})")?;
    writeln!(out, "Digest:    {}", kit.digest.as_deref().unwrap_or("-"))?;
    writeln!(out, "Provides:  {}", list(&kit.provides))?;
    writeln!(out, "Requires:  {}", list(&kit.requires))?;
    if kit.args.is_empty() {
        writeln!(out, "Args:      -")?;
    } else {
        writeln!(out, "Args:")?;
        for (name, a) in &kit.args {
            let mut what = Vec::new();
            if a.required {
                what.push("required".to_string());
            }
            if let Some(d) = &a.default {
                what.push(format!("default {d:?}"));
            }
            if !a.enum_values.is_empty() {
                what.push(format!("one of {}", a.enum_values.join("|")));
            }
            if let Some(p) = &a.pattern {
                what.push(format!("pattern {p}"));
            }
            writeln!(out, "  {name}  {}", what.join(", "))?;
        }
    }
    if kit.caps.is_empty() {
        writeln!(out, "Capabilities: -")?;
        return Ok(0);
    }
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
    Ok(0)
}

fn kind_name(k: Kind) -> &'static str {
    match k {
        Kind::Workload => "workload",
        Kind::Mixin => "mixin",
    }
}

/// The ref or path, and what kind of source it is.
fn source_of(s: &Source) -> (String, &'static str) {
    match s {
        Source::Registry(r) => (r.clone(), "registry"),
        Source::Preset(r) => (r.clone(), "preset"),
        Source::LocalV3(p) => (p.display().to_string(), "local v3"),
        Source::LocalV2(p) => (p.display().to_string(), "local v2"),
        Source::Smolfile(p) => (p.display().to_string(), "smolfile"),
    }
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
        _ => true,
    }
}

/// Loads and resolves the kit on its own: a workload by itself, a mixin on an empty workload that
/// provides whatever the mixin requires.
fn validate<R: Runner>(ctx: &Ctx<R>, reference: &str, args: &KitArgOpts) -> Result<i32> {
    let values = arg_values(args)?;
    let kit = load::load(ctx, reference)?;
    let plan = match kit.kind {
        Kind::Workload => resolve(kit, vec![], &values)?,
        Kind::Mixin => {
            let mut base = empty_workload("validate");
            base.provides = kit.requires.clone();
            resolve(base, vec![kit], &values)?
        }
    };
    plan.warn_skipped();
    writeln!(&ctx.out, "ok")?;
    Ok(0)
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
        args: Default::default(),
        caps: vec![],
        env: vec![],
        content: Content::Image(String::new()),
        command: None,
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
    let plan = resolve(empty_workload(&sb.meta.agent), mixins, values)?;
    plan.warn_skipped();

    // In memory until approved.
    let mut policy = plan::ensure_policy(ctx)?;
    let secrets = SecretsFile::load(&ctx.paths)?;
    let mut req = CreateRequest {
        name: name.to_string(),
        ..Default::default()
    };
    let (mut steps, added) = apply(
        &plan,
        &mut req,
        &mut policy,
        &secrets,
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

    let push = |policy: &Policy| -> Result<()> {
        let network = compile::network(policy, name, &sb.meta.credential_hosts);
        ctx.vm.update_network(&sb.machine, &network)
    };
    // `None`: opening the kit's network, before any hook ran.
    let result = (|| -> std::result::Result<(), (Option<KitPhase>, anyhow::Error)> {
        if !added.is_empty() {
            let open = || -> Result<()> {
                policy.save(&ctx.paths)?;
                push(&policy).context("applying the kit's network rules")
            };
            open().map_err(|e| (None, e))?;
        }
        sandbox::apply_kit_steps(&ctx.vm, sb, &steps, || {
            if steps.install_rules.is_empty() {
                return Ok(());
            }
            let mut policy = Policy::load(&ctx.paths)?;
            policy.remove_rules_by_ids(name, &steps.install_rules);
            policy.save(&ctx.paths)?;
            push(&policy).context("removing the install-phase network rules")
        })
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
    if let Some((path, _, _)) = &startup {
        sandbox::run_kit_startup(&ctx.vm, sb, path);
    }
    writeln!(&ctx.out, "Added kit {kit_name} to {name}")?;
    Ok(0)
}

/// Asks before a kit widens the sandbox's network access (SPEC-v3 §7.4); declining is an error.
fn approve<R: Runner>(ctx: &Ctx<R>, kit: &str, hosts: &[String], started: bool) -> Result<()> {
    if !ctx.stdin_tty {
        bail!("kit add needs --yes to grant network access without a terminal");
    }
    let mut out = &ctx.out;
    write!(out, "Allow {kit} to reach: {}? [y/N] ", hosts.join(", "))?;
    out.flush()?;
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    if matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
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
    use crate::kits::registry::fixtures::oci_layout;
    use crate::policy::Policy;

    const MACHINE: &str = "sbx-dev";
    const BASE: &str = "base\tghcr.io/acme/base@sha256:00\tbase\n";

    fn kit_env() -> TestEnv {
        test_env(&[("SMOLBENTO_KIT_ALLOW_LOCAL", "true")])
    }

    fn v2_fixture(name: &str) -> String {
        format!(
            "{}/tests/fixtures/kits/v2/{name}",
            env!("CARGO_MANIFEST_DIR")
        )
    }

    /// A local v3 kit directory `dir` whose `_builder` build hands back `descriptor` (JSON) with
    /// `layers`.
    fn v3_kit(t: &TestEnv, dir: &str, descriptor: &str, layers: &[&[u8]]) {
        let kit = t.ctx.cwd.join(dir);
        fs::create_dir(&kit).unwrap();
        fs::write(
            kit.join("kit.yaml"),
            "# syntax=docker/sandbox-kit:3\nschemaVersion: \"3\"\nkind: mixin\n",
        )
        .unwrap();
        let out = tempfile::tempdir().unwrap();
        oci_layout(out.path(), Some(descriptor), layers, "{}");
        let mut b = tar::Builder::new(Vec::new());
        b.append_dir_all(".", out.path()).unwrap();
        t.ctx
            .vm
            .runner()
            .ok(
                &["machine", "status", "-n", "sbx-_builder"],
                &machine_json(
                    "sbx-_builder",
                    "running",
                    &[("sbx.name", "_builder"), ("sbx.docker", "true")],
                ),
            )
            .download(&b.into_inner().unwrap());
    }

    /// A running shell sandbox `dev` whose guest kits record is `record`.
    fn dev_sandbox(t: &TestEnv, record: &str) {
        dev_sandbox_in(t, "running", record);
    }

    fn dev_sandbox_in(t: &TestEnv, state: &str, record: &str) {
        let fake = t.ctx.vm.runner();
        fake.ok(
            &["machine", "status", "-n", MACHINE],
            &machine_json(
                MACHINE,
                state,
                &[("sbx.name", "dev"), ("sbx.agent", "shell")],
            ),
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
        "provides":["net"],"requires":["base"],
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
    fn inspect_lists_a_v2_kits_capabilities() {
        let mut t = kit_env();
        let full = v2_fixture("full");
        sbt(&mut t.ctx, &["kit", "inspect", &full]).unwrap();
        let out = t.stdout();
        assert!(out.contains("Name:") && out.contains("full-kit"), "{out}");
        assert!(out.contains("workload"), "{out}");
        assert!(out.contains("local v2"), "{out}");
        let caps: Vec<&str> = out
            .lines()
            .filter(|l| l.starts_with("com.docker.sandbox/"))
            .collect();
        let want = [
            ("resources@1", "supported"),
            ("network-policy@1", "supported"),
            ("credential@1", "supported"),
            // OAuth without passthrough (sentinel tokens).
            ("credential@1", "not supported"),
            ("port@1", "supported"),
            ("port@1", "supported"),
            ("volume@1", "supported"),
            ("volume@1", "supported"),
            ("lifecycle@1", "supported"),
            ("agent-context@2", "supported"),
        ];
        assert_eq!(caps.len(), want.len(), "{out}");
        for (l, (ty, support)) in caps.iter().zip(want) {
            let cols: Vec<&str> = l
                .split("   ")
                .map(str::trim)
                .filter(|c| !c.is_empty())
                .collect();
            assert_eq!(
                cols,
                vec![format!("com.docker.sandbox/{ty}").as_str(), "no", support],
                "{out}"
            );
        }
        assert!(t.ctx.vm.runner().call_lines().is_empty());

        sbt(&mut t.ctx, &["kit", "inspect", &full, "--json"]).unwrap();
        let v: serde_json::Value = serde_json::from_str(&t.stdout()).unwrap();
        assert_eq!(v["name"], "full-kit");
        assert_eq!(v["kind"], "workload");
        assert_eq!(v["sourceType"], "local v2");
        let caps = v["capabilities"].as_array().unwrap();
        assert_eq!(caps.len(), want.len());
        assert_eq!(caps[2]["supported"], true, "{v}");
        assert_eq!(caps[3]["supported"], false, "{v}");
        assert_eq!(caps[0]["optional"], false);
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
        assert_eq!(t.stdout(), "ok\n");

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
        let started = pos("startup", &|l| {
            l.contains(" -d -- sh -c ") && l.contains("'/etc/smolbento/startup.d/02-net.sh'")
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
        assert_eq!(*kits, format!("{BASE}net\t{}\tnet\n", net_dir.display()));
        assert_eq!(
            uploads[&format!("{MACHINE}:{}", guest::STARTUP_PATH)],
            guest::STARTUP_RUNNER
        );
        assert_eq!(kit_rules(&t), vec!["api.net.example".to_string()]);
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
        assert!(format!("{e:#}").contains("requires 'base'"), "{e:#}");
        assert!(kit_rules(&t).is_empty());
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
        assert_eq!(*kits, format!("{record}net\t{}\tnet\n", net_dir.display()));
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
