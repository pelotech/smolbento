//! `sbt env`: a sandbox declared in sbxenv.yaml files.

use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};

use super::{
    Ctx, EnvApplyOpts, EnvCmd, EnvCommon, RunArgs, SandboxOpts, SecretSource, Unsupported, confirm,
};
use crate::env::file::SecretDecl;
use crate::env::load::{ArgInputs, Loaded, load};
use crate::env::spec::{EnvSpec, Op, Overrides, spec, summary};
use crate::sandbox;
use crate::secrets::{SecretEntry, SecretsFile, Source, resolve::resolve, scope_for};
use crate::smolvm::Runner;

pub fn run<R: Runner>(ctx: &mut Ctx<R>, cmd: EnvCmd) -> Result<i32> {
    match cmd {
        EnvCmd::Create(a) => create(ctx, &a.common, &a.apply),
        EnvCmd::Run(a) => env_run(ctx, &a.common, &a.apply, a.detach),
        EnvCmd::Exec(_) => not_yet("exec"),
        EnvCmd::Rm(_) => not_yet("rm"),
        EnvCmd::Plan(_) => not_yet("plan"),
    }
}

fn not_yet(cmd: &str) -> Result<i32> {
    Err(Unsupported(format!("`sbt env {cmd}` is not implemented yet")).into())
}

fn create<R: Runner>(ctx: &mut Ctx<R>, c: &EnvCommon, a: &EnvApplyOpts) -> Result<i32> {
    let (loaded, spec, mut secrets) = prepare(ctx, c, a)?;
    if sandbox::find(&ctx.vm, &spec.name)?.is_some() {
        bail!(
            "sandbox \"{}\" already exists; attach to it with `sbt env run`, or remove it with \
             `sbt env rm` and create it again",
            spec.name
        );
    }
    write!(&ctx.out, "{}", summary(&loaded, &spec, Op::Create, &[]))?;
    approve(ctx, &loaded, a.force, "create")?;
    provision(ctx, &mut secrets, &spec)?;
    let args = super::CreateArgs {
        targets: spec.targets,
        opts: spec.opts,
        no_progress: false,
    };
    super::lifecycle::create(ctx, &args)
}

fn env_run<R: Runner>(
    ctx: &mut Ctx<R>,
    c: &EnvCommon,
    a: &EnvApplyOpts,
    detach: bool,
) -> Result<i32> {
    let (loaded, spec, mut secrets) = prepare(ctx, c, a)?;
    let exists = sandbox::find(&ctx.vm, &spec.name)?.is_some();
    let op = if exists { Op::Run } else { Op::Create };
    write!(&ctx.out, "{}", summary(&loaded, &spec, op, &[]))?;
    approve(ctx, &loaded, a.force, "run")?;
    let args = if exists {
        // Attach as it was created, with the file's current env for this session.
        RunArgs {
            targets: vec![],
            opts: SandboxOpts {
                name: Some(spec.name),
                ..Default::default()
            },
            detach,
            rm: false,
            new: false,
            detach_keys: None,
            agent_args: vec![],
            session_env: spec.env,
        }
    } else {
        provision(ctx, &mut secrets, &spec)?;
        RunArgs {
            targets: spec.targets,
            opts: spec.opts,
            detach,
            rm: false,
            new: false,
            detach_keys: None,
            agent_args: vec![],
            session_env: vec![],
        }
    };
    super::run::run(ctx, &args)
}

/// Loads the files and turns them into create options, refusing cloud-only flags first.
fn prepare<R: Runner>(
    ctx: &Ctx<R>,
    c: &EnvCommon,
    a: &EnvApplyOpts,
) -> Result<(Loaded, EnvSpec, SecretsFile)> {
    let cloud = [
        (a.on_timeout.is_some(), "--on-timeout"),
        (a.ttl.is_some(), "--ttl"),
    ];
    if let Some((_, flag)) = cloud.iter().find(|(set, _)| *set) {
        return Err(Unsupported(format!("{flag} is a Docker Cloud option")).into());
    }
    let home = ctx.env.get("HOME").context("HOME is not set")?;
    let inputs = ArgInputs {
        files: c.env_args_file.clone(),
        flags: c.env_arg.clone(),
    };
    let loaded = load(&c.paths, &inputs, &ctx.cwd, Path::new(home))?;
    let secrets = SecretsFile::load(&ctx.paths)?;
    let overrides = Overrides {
        name: c.name.clone(),
        clone: a.clone,
        kit_arg: a.kit_arg.clone(),
        kit_args_file: a.kit_args_file.clone(),
    };
    let spec = spec(&loaded, &overrides, &secrets)?;
    Ok((loaded, spec, secrets))
}

/// sbx asks before every `env create` and `env run`; `--force` approves this invocation.
fn approve<R: Runner>(ctx: &Ctx<R>, loaded: &Loaded, force: bool, cmd: &str) -> Result<()> {
    if !force && !ctx.stdin_tty {
        bail!(
            "{} changes things outside the sandbox that have not been approved; approve them by \
             running this in a terminal, or approve this invocation with --force (-f)\n  \
             try: sbt env {cmd} --force",
            loaded.files[0].display()
        );
    }
    confirm(ctx, "Apply?", force)
}

/// Stores the file's secrets at the sandbox's scope. Every source is checked before any is
/// stored; a later failure (the create, say) leaves them for `env rm`, as in sbx.
fn provision<R: Runner>(ctx: &Ctx<R>, secrets: &mut SecretsFile, spec: &EnvSpec) -> Result<()> {
    if spec.secrets.is_empty() {
        return Ok(());
    }
    let scope = scope_for(Some(&spec.name));
    let mut sources = Vec::new();
    for (service, decl) in &spec.secrets {
        let source = source(ctx, service, &scope, decl)
            .map_err(|e| anyhow!("secret \"{service}\": {e:#}"))?;
        sources.push((service, source));
    }
    let mut out = &ctx.out;
    writeln!(out, "\nPROVISION\n  Scope:  {}", spec.name)?;
    for (service, source) in sources {
        let kind = match (&source.token, &source.reference) {
            (Some(_), _) => "literal",
            (_, Some(_)) => "reference",
            _ => "command",
        };
        super::secret::store(ctx, secrets, service, source)?;
        writeln!(out, "  ✓ {service} — secret · {kind}")?;
    }
    Ok(())
}

/// What `secret set --sandbox` would take for `decl`: a snapshot becomes its value now; a
/// reference or command is resolved once to check it (unless `noVerify`), and the value dropped.
fn source<R: Runner>(
    ctx: &Ctx<R>,
    service: &str,
    scope: &str,
    decl: &SecretDecl,
) -> Result<SecretSource> {
    let sandbox = scope.strip_prefix("sandbox:").map(String::from);
    if let Some(v) = &decl.value {
        return Ok(SecretSource {
            token: Some(v.clone()),
            reference: None,
            command: None,
            sandbox,
        });
    }
    let source = match (&decl.r#ref, &decl.command) {
        (Some(r), _) => Source::Ref {
            reference: r.clone(),
        },
        (_, Some(c)) => Source::Command { command: c.clone() },
        _ => bail!("no value, ref or command"),
    };
    let snapshot = decl.snapshot == Some(true);
    let resolved = if snapshot || decl.no_verify != Some(true) {
        let entry = SecretEntry {
            service: service.into(),
            scope: scope.into(),
            source: source.clone(),
        };
        Some(resolve(&entry, ctx.store.as_ref())?)
    } else {
        None
    };
    Ok(match source {
        _ if snapshot => SecretSource {
            token: resolved,
            reference: None,
            command: None,
            sandbox,
        },
        Source::Ref { reference } => SecretSource {
            token: None,
            reference: Some(reference),
            command: None,
            sandbox,
        },
        Source::Command { command } => SecretSource {
            token: None,
            reference: None,
            command: Some(command),
            sandbox,
        },
        Source::Keychain => unreachable!("built from a ref or command"),
    })
}

#[cfg(test)]
mod tests {
    use super::super::testutil::*;
    use super::super::{Cli, Cmd, EnvCmd, exit_code};
    use crate::secrets::{SecretEntry, SecretsFile, Source};
    use clap::Parser;

    const FILE: &str = "schemaVersion: \"1\"\nagent: claude\nworkspace: .\n\
        sandboxOptions:\n  cpus: 2\n  memory: 4g\nenv:\n  X: one\nports:\n  - sandbox: 80\n    host: 8080\n";

    /// A test env with HOME set and `text` as `<cwd>/sbxenv.yaml`.
    fn with_file(text: &str) -> TestEnv {
        let mut t = test_env(&[]);
        let home = t.ctx.cwd.parent().unwrap().display().to_string();
        t.ctx.env.insert("HOME".into(), home);
        std::fs::write(t.ctx.cwd.join("sbxenv.yaml"), text).unwrap();
        t
    }

    /// Sandbox `claude-proj` doesn't exist for `lookups` status calls, then exists.
    fn missing_then_created(t: &TestEnv, lookups: usize) {
        let fake = t.ctx.vm.runner();
        let ws = t.ctx.cwd.display().to_string();
        fake.ok(
            &["machine", "status"],
            &machine_json(
                "sbx-claude-proj",
                "created",
                &[
                    ("sbx.name", "claude-proj"),
                    ("sbx.agent", "claude"),
                    ("sbx.workspace", ws.as_str()),
                ],
            ),
        );
        for _ in 0..lookups {
            fake.once_fail(&["machine", "status"], "NOT_FOUND", "vm not found");
        }
    }

    fn existing(t: &TestEnv, state: &str) {
        let ws = t.ctx.cwd.display().to_string();
        t.ctx.vm.runner().ok(
            &["machine", "status"],
            &machine_json(
                "sbx-claude-proj",
                state,
                &[
                    ("sbx.name", "claude-proj"),
                    ("sbx.agent", "claude"),
                    ("sbx.workspace", ws.as_str()),
                ],
            ),
        );
    }

    /// Call lines with what differs between test envs masked: fresh UUIDs (SANDBOX_ID) and
    /// temp directories.
    fn lines(t: &TestEnv) -> Vec<String> {
        let uuid =
            regex_lite::Regex::new("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
                .unwrap();
        let tmp = regex_lite::Regex::new(r"/[^ :]*/\.tmp[A-Za-z0-9]+").unwrap();
        t.ctx
            .vm
            .runner()
            .call_lines()
            .iter()
            .map(|l| {
                tmp.replace_all(&uuid.replace_all(l, "UUID"), "TMP")
                    .into_owned()
            })
            .collect()
    }

    fn creates(t: &TestEnv) -> Vec<String> {
        lines(t)
            .into_iter()
            .filter(|l| l.starts_with("machine create"))
            .collect()
    }

    fn scoped(t: &TestEnv) -> Vec<SecretEntry> {
        SecretsFile::load(&t.ctx.paths)
            .unwrap()
            .secrets
            .into_iter()
            .filter(|e| e.scope == "sandbox:claude-proj")
            .collect()
    }

    fn stored(t: &TestEnv, service: &str) -> Option<String> {
        t.ctx
            .store
            .get(&format!("sandbox:claude-proj/{service}"))
            .unwrap()
    }

    #[test]
    fn create_force_runs_what_sbt_create_runs() {
        let mut env = with_file(FILE);
        missing_then_created(&env, 2);
        sbt(&mut env.ctx, &["env", "create", "--force"]).unwrap();
        let out = env.stdout();
        assert!(
            out.starts_with("ENVIRONMENT\n  Name: claude-proj\n"),
            "{out}"
        );
        assert!(out.ends_with("Created sandbox claude-proj\n"), "{out}");
        assert!(!out.contains("PROVISION"), "{out}");

        let mut plain = with_file(FILE);
        missing_then_created(&plain, 1);
        let ws = plain.ctx.cwd.display().to_string();
        sbt(
            &mut plain.ctx,
            &[
                "create",
                "claude",
                &ws,
                "--name",
                "claude-proj",
                "--cpus",
                "2",
                "-m",
                "4g",
                "-e",
                "X=one",
                "-p",
                "8080:80/tcp",
            ],
        )
        .unwrap();
        let mut env_lines = lines(&env);
        // env create looks the name up once more, for its own "already exists" error.
        let lookup = env_lines
            .iter()
            .position(|l| l.starts_with("machine status"))
            .unwrap();
        env_lines.remove(lookup);
        assert_eq!(env_lines, lines(&plain));
    }

    #[test]
    fn create_provisions_scoped_secrets_before_the_create() {
        let mut t = with_file(&format!(
            "{FILE}secrets:\n  github:\n    value: ghp_dummy\n"
        ));
        missing_then_created(&t, 2);
        sbt(&mut t.ctx, &["env", "create", "-f"]).unwrap();
        let out = t.stdout();
        assert!(
            out.contains("\nPROVISION\n  Scope:  claude-proj\n  ✓ github — secret · literal\n"),
            "{out}"
        );
        assert!(!out.contains("ghp_dummy"), "{out}");
        assert_eq!(scoped(&t)[0].source, Source::Keychain);
        assert_eq!(stored(&t, "github").as_deref(), Some("ghp_dummy"));
        let create = &creates(&t)[0];
        assert!(create.contains("github"), "the create binds it: {create}");
        assert!(!create.contains("ghp_dummy"), "{create}");
    }

    #[test]
    fn without_force_or_a_terminal_nothing_happens() {
        let mut t = with_file(&format!(
            "{FILE}secrets:\n  github:\n    value: ghp_dummy\n"
        ));
        missing_then_created(&t, 2);
        let file = t.ctx.cwd.join("sbxenv.yaml").display().to_string();
        for cmd in ["create", "run"] {
            let err = sbt(&mut t.ctx, &["env", cmd]).unwrap_err().to_string();
            assert_eq!(
                err,
                format!(
                    "{file} changes things outside the sandbox that have not been approved; \
                     approve them by running this in a terminal, or approve this invocation with \
                     --force (-f)\n  try: sbt env {cmd} --force"
                )
            );
        }
        assert!(t.stdout().starts_with("ENVIRONMENT\n"));
        assert!(creates(&t).is_empty());
        assert!(
            lines(&t)
                .iter()
                .all(|l| l == "--version" || l.starts_with("machine status")),
            "{:?}",
            lines(&t)
        );
        assert!(scoped(&t).is_empty());
    }

    #[test]
    fn create_of_an_existing_sandbox_fails() {
        let mut t = with_file(FILE);
        existing(&t, "running");
        let err = sbt(&mut t.ctx, &["env", "create", "-f"])
            .unwrap_err()
            .to_string();
        assert_eq!(
            err,
            "sandbox \"claude-proj\" already exists; attach to it with `sbt env run`, or remove it \
             with `sbt env rm` and create it again"
        );
        assert!(creates(&t).is_empty());
    }

    #[test]
    fn a_failed_create_leaves_the_secret() {
        let mut t = with_file(&format!(
            "{FILE}secrets:\n  github:\n    value: ghp_dummy\n"
        ));
        missing_then_created(&t, 2);
        t.ctx
            .vm
            .runner()
            .fail(&["machine", "create"], "CREATE_FAILED", "no space left");
        assert!(sbt(&mut t.ctx, &["env", "create", "-f"]).is_err());
        assert_eq!(scoped(&t).len(), 1);
        assert_eq!(stored(&t, "github").as_deref(), Some("ghp_dummy"));
    }

    #[test]
    fn snapshot_stores_the_resolved_value_as_a_literal() {
        let mut t = with_file(&format!(
            "{FILE}secrets:\n  github:\n    command: printf snap\n    snapshot: true\n"
        ));
        missing_then_created(&t, 2);
        sbt(&mut t.ctx, &["env", "create", "-f"]).unwrap();
        assert!(t.stdout().contains("  ✓ github — secret · literal\n"));
        assert_eq!(scoped(&t)[0].source, Source::Keychain);
        assert_eq!(stored(&t, "github").as_deref(), Some("snap"));
    }

    #[test]
    fn sources_are_verified_unless_no_verify() {
        let mut t = with_file(&format!(
            "{FILE}secrets:\n  github:\n    command: \"false\"\n"
        ));
        missing_then_created(&t, 2);
        let err = sbt(&mut t.ctx, &["env", "create", "-f"])
            .unwrap_err()
            .to_string();
        assert!(err.starts_with("secret \"github\": "), "{err}");
        assert!(scoped(&t).is_empty());
        assert!(creates(&t).is_empty());

        let mut t = with_file(&format!(
            "{FILE}secrets:\n  github:\n    command: \"false\"\n    noVerify: true\n"
        ));
        missing_then_created(&t, 2);
        sbt(&mut t.ctx, &["env", "create", "-f"]).unwrap();
        assert!(t.stdout().contains("  ✓ github — secret · command\n"));
        assert_eq!(
            scoped(&t)[0].source,
            Source::Command {
                command: "false".into()
            }
        );
        assert_eq!(stored(&t, "github"), None);
    }

    #[test]
    fn run_of_an_existing_sandbox_attaches_with_the_files_env() {
        let mut t = with_file(&FILE.replace("X: one", "X: two"));
        existing(&t, "running");
        t.ctx.vm.runner().interactive_exit(0);
        assert_eq!(sbt(&mut t.ctx, &["env", "run", "-f"]).unwrap(), 0);
        let exec = t.ctx.vm.runner().interactive_calls()[0].join(" ");
        assert!(exec.contains("-e X=two"), "{exec}");
        assert!(creates(&t).is_empty());
        assert!(scoped(&t).is_empty());
    }

    #[test]
    fn run_of_a_new_sandbox_creates_it_and_detaches() {
        let mut t = with_file(FILE);
        // env run looks the name up, run twice more, and plan::create once more.
        missing_then_created(&t, 4);
        assert_eq!(sbt(&mut t.ctx, &["env", "run", "-d", "-f"]).unwrap(), 0);
        assert_eq!(creates(&t).len(), 1);
        assert!(t.stdout().ends_with("claude-proj\n"));
        assert!(t.ctx.vm.runner().interactive_calls().is_empty());
    }

    #[test]
    fn plan_and_cloud_flags_exit_2() {
        let mut t = with_file(FILE);
        let err = sbt(&mut t.ctx, &["env", "plan"]).unwrap_err();
        assert_eq!(err.to_string(), "`sbt env plan` is not implemented yet");
        assert_eq!(exit_code(&err), 2);
        let err = sbt(&mut t.ctx, &["env", "create", "--on-timeout", "stop"]).unwrap_err();
        assert_eq!(exit_code(&err), 2, "{err}");
        assert!(creates(&t).is_empty());
    }

    #[test]
    fn clone_takes_an_optional_value() {
        let clone = |args: &[&str]| {
            let cli = Cli::try_parse_from(["sbt", "env", "create"].iter().chain(args)).unwrap();
            match cli.command {
                Some(Cmd::Env(EnvCmd::Create(a))) => (a.apply.clone, a.common.paths),
                other => panic!("{other:?}"),
            }
        };
        assert_eq!(clone(&[]), (None, vec![]));
        assert_eq!(clone(&["--clone", "./p"]), (Some(true), vec!["./p".into()]));
        assert_eq!(clone(&["--clone=true"]).0, Some(true));
        assert_eq!(clone(&["--clone=false"]).0, Some(false));
    }
}
