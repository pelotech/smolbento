//! `sbt env`: a sandbox declared in sbxenv.yaml files.

use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};

use super::{
    Ctx, EnvApplyOpts, EnvCmd, EnvCommon, EnvExecArgs, EnvRmArgs, ExecArgs, RunArgs, SandboxOpts,
    SecretSource, Unsupported, confirm_or,
};
use crate::env::file::SecretDecl;
use crate::env::load::{ArgInputs, Loaded, load};
use crate::env::spec::{EnvSpec, Op, Overrides, name, remove_summary, spec, summary};
use crate::sandbox;
use crate::secrets::{SecretEntry, SecretsFile, Source, resolve::resolve, scope_for};
use crate::smolvm::Runner;

pub fn run<R: Runner>(ctx: &mut Ctx<R>, cmd: EnvCmd) -> Result<i32> {
    match cmd {
        EnvCmd::Create(a) => create(ctx, &a.common, &a.apply),
        EnvCmd::Run(a) => env_run(ctx, &a.common, &a.apply, a.detach),
        EnvCmd::Exec(a) => env_exec(ctx, a),
        EnvCmd::Rm(a) => env_rm(ctx, a),
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
    approve(ctx, &loaded, a.force)?;
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
    approve(ctx, &loaded, a.force)?;
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
            no_progress: false,
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
            no_progress: false,
            new: false,
            detach_keys: None,
            agent_args: vec![],
            session_env: vec![],
        }
    };
    super::run::run(ctx, &args)
}

/// Loads the files for `exec` and `rm`, which need only the name: no kit or workspace checks.
fn load_name<R: Runner>(
    ctx: &Ctx<R>,
    paths: &[String],
    name_flag: Option<&str>,
    env_arg: &[String],
    env_args_file: &[std::path::PathBuf],
) -> Result<(Loaded, String)> {
    let home = ctx.env.get("HOME").context("HOME is not set")?;
    let inputs = ArgInputs {
        files: env_args_file.to_vec(),
        flags: env_arg.to_vec(),
    };
    let loaded = load(paths, &inputs, &ctx.cwd, Path::new(home))?;
    let name = name(&loaded, name_flag)?;
    Ok((loaded, name))
}

fn env_exec<R: Runner>(ctx: &mut Ctx<R>, a: EnvExecArgs) -> Result<i32> {
    // Without `--` every positional is the command and the file comes from the current directory.
    let (paths, command) = if a.command.is_empty() {
        (vec![], a.paths)
    } else {
        (a.paths, a.command)
    };
    if command.is_empty() {
        bail!("specify a command to run, e.g. `sbt env exec -- bash`");
    }
    let (loaded, name) = load_name(ctx, &paths, a.name.as_deref(), &a.env_arg, &a.env_args_file)?;
    if sandbox::find(&ctx.vm, &name)?.is_none() {
        bail!("sandbox '{name}' not found for this environment\n  try: sbt env create");
    }
    // The file's env first, so the user's -e wins.
    let mut env: Vec<String> = loaded
        .file
        .env
        .iter()
        .flatten()
        .map(|(k, v)| format!("{k}={v}"))
        .collect();
    env.extend(a.env);
    super::exec::exec(
        ctx,
        &ExecArgs {
            interactive: a.interactive,
            tty: a.tty,
            env,
            env_file: a.env_file,
            user: a.user,
            workdir: a.workdir,
            privileged: a.privileged,
            detach: a.detach,
            detach_keys: a.detach_keys,
            sandbox: name,
            command,
        },
    )
}

fn env_rm<R: Runner>(ctx: &mut Ctx<R>, a: EnvRmArgs) -> Result<i32> {
    let c = &a.common;
    let (loaded, name) = load_name(
        ctx,
        &c.paths,
        c.name.as_deref(),
        &c.env_arg,
        &c.env_args_file,
    )?;
    let scope = scope_for(Some(&name));
    let scoped: Vec<String> = SecretsFile::load(&ctx.paths)?
        .secrets
        .into_iter()
        .filter(|e| e.scope == scope)
        .map(|e| e.service)
        .collect();
    let all = sandbox::list(&ctx.vm)?;
    let sb = all.iter().find(|sb| sb.name() == name);
    if sb.is_none() && scoped.is_empty() {
        eprintln!("error: sandbox '{name}' not found\n  try: sbt ls");
        return Ok(0);
    }
    if let Some(sb) = sb {
        let forks = super::lifecycle::remaining_forks(sb, &all, &[&name]);
        if !forks.is_empty() {
            bail!(
                "{name} has forks; remove its forks first: {}",
                forks.join(", ")
            );
        }
    }
    write!(&ctx.out, "{}", remove_summary(&loaded, &name, &scoped))?;
    confirm_or(
        ctx,
        "Remove?",
        a.force,
        "stdin is not a terminal; use --force to skip confirmation",
    )?;
    match sb {
        Some(sb) => {
            super::lifecycle::delete_sandbox(ctx, sb, true)?;
            writeln!(&ctx.out, "Removed sandbox {name}")?;
        }
        // No sandbox: only the secrets (and any stale policy) are left to forget.
        None => super::secret::forget_sandbox(ctx, &name, true)?,
    }
    if !scoped.is_empty() {
        writeln!(&ctx.out, "Removed secrets scoped to {name}")?;
    }
    Ok(0)
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
fn approve<R: Runner>(ctx: &Ctx<R>, loaded: &Loaded, force: bool) -> Result<()> {
    // The command as given, quoted for the shell, with `--force` added (sbx does the same).
    let words: Vec<String> = ctx.args.iter().map(|a| shell_word(a)).collect();
    let refusal = format!(
        "{} changes things outside the sandbox that have not been approved; approve them by \
         running this in a terminal, or approve this invocation with --force (-f)\n  \
         try: sbt {} --force",
        loaded.files[0].display(),
        words.join(" ")
    );
    confirm_or(ctx, "Apply?", force, &refusal)
}

/// `s` as one shell word: as is when that's safe, else single-quoted.
fn shell_word(s: &str) -> String {
    let plain = |c: char| c.is_ascii_alphanumeric() || "-_./:=@%+,".contains(c);
    if !s.is_empty() && s.chars().all(plain) {
        s.to_string()
    } else {
        sandbox::sh_quote(s)
    }
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
        assert!(
            out.ends_with(
                "  ✓ Created sandbox claude-proj\n        try: sbt run --name claude-proj\n"
            ),
            "{out}"
        );
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
    fn create_binds_the_mounts_of_the_file() {
        let mut t = with_file(
            "schemaVersion: \"1\"\nagent: shell\nkits:\n  - ./hm\nmounts:\n  /home/agent/.hm: ./data\n",
        );
        t.ctx
            .env
            .insert("SMOLBENTO_KIT_ALLOW_LOCAL_KITS".into(), "true".into());
        let ws = t.ctx.cwd.display().to_string();
        t.ctx.vm.runner().ok(
            &["machine", "status"],
            &machine_json(
                "sbx-shell-proj",
                "created",
                &[
                    ("sbx.name", "shell-proj"),
                    ("sbx.agent", "shell"),
                    ("sbx.workspace", ws.as_str()),
                ],
            ),
        );
        t.ctx
            .vm
            .runner()
            .once_fail(&["machine", "status"], "NOT_FOUND", "vm not found");
        // env create looks the name up once more, for its own "already exists" error.
        t.ctx
            .vm
            .runner()
            .once_fail(&["machine", "status"], "NOT_FOUND", "vm not found");
        v3_kit(
            &t,
            "hm",
            r#"{"schemaVersion":"3","kind":"mixin","name":"hm","capabilities":[
                {"type":"com.docker.sandbox/host-mount@1","config":{"path":"/home/agent/.hm"}}]}"#,
            &[],
        );
        std::fs::create_dir(t.ctx.cwd.join("data")).unwrap();
        sbt(&mut t.ctx, &["env", "create", "--force"]).unwrap();
        let create = creates(&t).remove(0);
        assert!(
            create.contains(" -v TMP/proj/data:/home/agent/.hm "),
            "{create}"
        );
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
    fn the_force_hint_repeats_the_original_arguments() {
        let mut t = with_file(FILE);
        let text = format!("{FILE}args:\n  v:\n    default: a\n");
        std::fs::write(t.ctx.cwd.join("my env.yaml"), text).unwrap();
        missing_then_created(&t, 1);
        let err = sbt(
            &mut t.ctx,
            &[
                "env",
                "create",
                "my env.yaml",
                "--name",
                "box",
                "--env-arg",
                "v=x y",
            ],
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.ends_with(
                "\n  try: sbt env create 'my env.yaml' --name box --env-arg 'v=x y' --force"
            ),
            "{err}"
        );
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

    fn listed(t: &TestEnv, extra: &[(&str, &str)]) {
        let mut labels = vec![("sbx.name", "claude-proj"), ("sbx.agent", "claude")];
        labels.extend_from_slice(extra);
        let json = machine_json("sbx-claude-proj", "created", &labels);
        t.ctx
            .vm
            .runner()
            .ok(&["machine", "ls", "--json"], &format!("[{json}]"));
    }

    #[test]
    fn exec_splits_paths_from_the_command_at_dashes() {
        let mut t = with_file(FILE);
        existing(&t, "running");
        t.ctx.vm.runner().interactive_exit(3);
        let file = t.ctx.cwd.join("sbxenv.yaml").display().to_string();
        let code = sbt(&mut t.ctx, &["env", "exec", &file, "--", "npm", "test"]).unwrap();
        assert_eq!(code, 3);
        let call = t.ctx.vm.runner().interactive_calls()[0].join(" ");
        assert!(call.ends_with("-- npm test"), "{call}");
        assert!(call.contains("--name sbx-claude-proj"), "{call}");
    }

    #[test]
    fn exec_without_dashes_takes_every_positional_as_the_command() {
        let mut t = with_file(FILE);
        existing(&t, "running");
        t.ctx.vm.runner().interactive_exit(0);
        sbt(&mut t.ctx, &["env", "exec", "go", "test", "./..."]).unwrap();
        let call = t.ctx.vm.runner().interactive_calls()[0].join(" ");
        assert!(call.ends_with("-- go test ./..."), "{call}");
    }

    #[test]
    fn exec_passes_the_files_env_and_the_users_wins() {
        let mut t = with_file(FILE);
        existing(&t, "running");
        t.ctx.vm.runner().interactive_exit(0);
        sbt(&mut t.ctx, &["env", "exec", "-e", "X=mine", "--", "env"]).unwrap();
        let call = t.ctx.vm.runner().interactive_calls()[0].join(" ");
        let (file, user) = (call.find("-e X=one"), call.find("-e X=mine"));
        assert!(file.is_some() && user.is_some() && file < user, "{call}");
    }

    #[test]
    fn exec_of_a_missing_sandbox_fails() {
        let mut t = with_file(FILE);
        t.ctx
            .vm
            .runner()
            .fail(&["machine", "status"], "NOT_FOUND", "vm not found");
        let err = sbt(&mut t.ctx, &["env", "exec", "--", "ls"])
            .unwrap_err()
            .to_string();
        assert_eq!(
            err,
            "sandbox 'claude-proj' not found for this environment\n  try: sbt env create"
        );
        assert!(t.ctx.vm.runner().interactive_calls().is_empty());
    }

    #[test]
    fn exec_works_when_the_workspace_is_gone() {
        let mut t = with_file(&FILE.replace("workspace: .", "workspace: ./gone"));
        existing(&t, "running");
        t.ctx.vm.runner().interactive_exit(0);
        sbt(&mut t.ctx, &["env", "exec", "--", "ls"]).unwrap();
    }

    fn set_scoped(t: &mut TestEnv, scope: &[&str]) {
        let mut a = vec!["secret", "set", "github", "-t", "tok"];
        a.extend_from_slice(scope);
        sbt(&mut t.ctx, &a).unwrap();
    }

    fn deletes(t: &TestEnv) -> Vec<String> {
        lines(t)
            .into_iter()
            .filter(|l| l.starts_with("machine delete"))
            .collect()
    }

    #[test]
    fn rm_force_removes_the_sandbox_and_only_its_scoped_secret() {
        let mut t = with_file(FILE);
        set_scoped(&mut t, &["--sandbox", "claude-proj"]);
        set_scoped(&mut t, &[]);
        listed(&t, &[]);
        assert_eq!(sbt(&mut t.ctx, &["env", "rm", "--force"]).unwrap(), 0);
        let out = t.stdout();
        assert!(out.contains("ENVIRONMENT\n  Name: claude-proj\n"), "{out}");
        assert!(out.contains("  - github\n"), "{out}");
        assert!(
            out.ends_with("Removed sandbox claude-proj\nRemoved secrets scoped to claude-proj\n"),
            "{out}"
        );
        assert_eq!(deletes(&t).len(), 1, "{:?}", lines(&t));
        assert!(scoped(&t).is_empty());
        assert_eq!(stored(&t, "github"), None);
        let global = SecretsFile::load(&t.ctx.paths).unwrap();
        assert!(global.secrets.iter().any(|e| e.scope == "global"));
        assert_eq!(
            t.ctx.store.get("global/github").unwrap().as_deref(),
            Some("tok")
        );
    }

    #[test]
    fn rm_without_a_terminal_or_force_changes_nothing() {
        let mut t = with_file(FILE);
        set_scoped(&mut t, &["--sandbox", "claude-proj"]);
        listed(&t, &[]);
        let err = sbt(&mut t.ctx, &["env", "rm"]).unwrap_err().to_string();
        assert_eq!(
            err,
            "stdin is not a terminal; use --force to skip confirmation"
        );
        assert!(t.stdout().contains("ENVIRONMENT\n"));
        assert!(deletes(&t).is_empty());
        assert_eq!(scoped(&t).len(), 1);
    }

    #[test]
    fn rm_of_nothing_exits_0() {
        let mut t = with_file(FILE);
        t.ctx.vm.runner().ok(&["machine", "ls", "--json"], "[]");
        assert_eq!(sbt(&mut t.ctx, &["env", "rm", "-f"]).unwrap(), 0);
        assert_eq!(t.stdout(), "");
        assert!(deletes(&t).is_empty());
    }

    #[test]
    fn rm_with_only_scoped_secrets_removes_them() {
        let mut t = with_file(FILE);
        set_scoped(&mut t, &["--sandbox", "claude-proj"]);
        t.ctx.vm.runner().ok(&["machine", "ls", "--json"], "[]");
        sbt(&mut t.ctx, &["env", "rm", "-f"]).unwrap();
        assert!(
            t.stdout()
                .ends_with("\nRemoved secrets scoped to claude-proj\n"),
            "{}",
            t.stdout()
        );
        assert!(!t.stdout().contains("Removed sandbox"));
        assert!(scoped(&t).is_empty());
        assert_eq!(stored(&t, "github"), None);
    }

    #[test]
    fn rm_refuses_a_sandbox_with_forks() {
        let mut t = with_file(FILE);
        let a = machine_json(
            "sbx-claude-proj",
            "created",
            &[("sbx.name", "claude-proj"), ("sbx.agent", "claude")],
        );
        let b = machine_json(
            "sbx-claude-proj-fork-1",
            "created",
            &[
                ("sbx.name", "claude-proj-fork-1"),
                ("sbx.fork-of", "claude-proj"),
            ],
        );
        t.ctx
            .vm
            .runner()
            .ok(&["machine", "ls", "--json"], &format!("[{a},{b}]"));
        let err = sbt(&mut t.ctx, &["env", "rm", "-f"])
            .unwrap_err()
            .to_string();
        assert_eq!(
            err,
            "claude-proj has forks; remove its forks first: claude-proj-fork-1"
        );
        assert!(deletes(&t).is_empty());
    }

    #[test]
    fn rm_needs_the_required_args() {
        let mut t = with_file(&format!("{FILE}args:\n  channel:\n    required: true\n"));
        assert!(sbt(&mut t.ctx, &["env", "rm", "-f"]).is_err());
        assert!(sbt(&mut t.ctx, &["env", "exec", "--", "ls"]).is_err());
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
