//! `sbt env`: a sandbox declared in sbxenv.yaml files.

use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};

use super::env_spec::{
    EnvSpec, LIFECYCLE, Overrides, binding_resources, header, lifecycle, lifecycle_resources, name,
    remove_summary, resources, spec, vars,
};
use super::{
    Ctx, EnvApplyOpts, EnvCmd, EnvCommon, EnvExecArgs, EnvOverrideOpts, EnvRmArgs, EnvRunArgs,
    ExecArgs, RunArgs, SandboxOpts, SecretSource, Unsupported, confirm_or,
};
use crate::env::approval::{self, Need};
use crate::env::file::{Binding, HostCommand, SecretDecl};
use crate::env::lifecycle::{self as host_lifecycle, Phase, Vars};
use crate::env::load::{ArgInputs, Loaded, load};
use crate::env::plan::{HOST_COMMANDS, Line, Resource, UNCHANGED_HOST_COMMANDS, When, render};
use crate::sandbox;
use crate::secrets::{
    RegistryEntry, SecretEntry, SecretsFile, Source, resolve::resolve, scope_for,
};
use crate::smolvm::Runner;

pub fn run<R: Runner>(ctx: &mut Ctx<R>, cmd: EnvCmd) -> Result<i32> {
    match cmd {
        EnvCmd::Create(a) => create(ctx, &a.common, &a.apply),
        EnvCmd::Run(a) => env_run(ctx, a),
        EnvCmd::Exec(a) => env_exec(ctx, a),
        EnvCmd::Rm(a) => env_rm(ctx, a),
        EnvCmd::Plan(a) => env_plan(ctx, &a.common, &a.overrides),
    }
}

/// What applying would do, against what was approved and whether the sandbox exists.
struct Planned {
    resources: Vec<Resource>,
    need: Need,
    /// The `ENVIRONMENT` block.
    header: String,
    lines: Vec<Line>,
}

impl Planned {
    /// The plan as printed. An apply whose approved commands ask all the same says so, in place
    /// of the plain warning.
    fn text(&self, applying: bool) -> String {
        let warning = if applying && self.need == Need::HostCommands {
            UNCHANGED_HOST_COMMANDS
        } else {
            HOST_COMMANDS
        };
        format!("{}{}", self.header, render(&self.lines, warning))
    }
}

/// `skip_host_commands` leaves the lifecycle commands out of the plan and of both sides of the
/// approval: skipping them neither approves nor forgets them.
fn planned<R: Runner>(
    ctx: &Ctx<R>,
    loaded: &Loaded,
    spec: &EnvSpec,
    exists: bool,
    skip_host_commands: bool,
) -> Result<Planned> {
    let mut resources = resources(loaded, spec);
    let mut record = approval::load(&ctx.paths, &spec.name, &loaded.files);
    let mut kept = Vec::new();
    if skip_host_commands {
        resources.retain(|r| r.section != LIFECYCLE);
        if let Some(r) = record.take() {
            kept = r
                .approved
                .iter()
                .filter(|r| r.section == LIFECYCLE)
                .cloned()
                .collect();
            record = Some(r.without(LIFECYCLE));
        }
    }
    let need = approval::need(
        record.as_ref(),
        &resources,
        ctx.settings.bool("env.rememberHostCommands")?,
    );
    Ok(Planned {
        lines: approval::lines(record.as_ref(), &resources, exists),
        header: header(loaded, &spec.name),
        // What a yes records: the plan shown, and the approved commands it left out.
        resources: resources.into_iter().chain(kept).collect(),
        need,
    })
}

/// Runs a lifecycle phase, or says it was skipped.
fn host_phase<R: Runner>(
    ctx: &Ctx<R>,
    phase: Phase,
    commands: &[HostCommand],
    vars: &Vars,
    skip: bool,
) -> Result<()> {
    if skip {
        if !commands.is_empty() {
            eprintln!(
                "warning: skipping the host commands declared for {} (--skip-host-commands)",
                phase.name()
            );
        }
        return Ok(());
    }
    host_lifecycle::run(&ctx.out, ctx.stdout_tty, phase, commands, vars)
}

/// Prints what applying would do and whether it would ask. Changes nothing.
fn env_plan<R: Runner>(ctx: &mut Ctx<R>, c: &EnvCommon, o: &EnvOverrideOpts) -> Result<i32> {
    let (loaded, spec, _) = prepare(ctx, c, o)?;
    let exists = sandbox::find(&ctx.vm, &spec.name)?.is_some();
    let plan = planned(ctx, &loaded, &spec, exists, o.skip_host_commands)?;
    let status = match plan.need {
        Need::Changed => "○ not approved yet — applying asks once",
        Need::HostCommands => {
            "✓ approved as it stands — applying asks again for the commands it declares here"
        }
        Need::No => "✓ already approved — applying asks nothing",
    };
    writeln!(&ctx.out, "{}  {status}", plan.text(false))?;
    Ok(0)
}

/// Refuses the flags that only Docker Cloud has.
fn refuse_cloud(a: &EnvApplyOpts) -> Result<()> {
    let cloud = [
        (a.on_timeout.is_some(), "--on-timeout"),
        (a.ttl.is_some(), "--ttl"),
    ];
    match cloud.iter().find(|(set, _)| *set) {
        Some((_, flag)) => Err(Unsupported(format!("{flag} is a Docker Cloud option")).into()),
        None => Ok(()),
    }
}

fn create<R: Runner>(ctx: &mut Ctx<R>, c: &EnvCommon, a: &EnvApplyOpts) -> Result<i32> {
    refuse_cloud(a)?;
    let (loaded, spec, mut secrets) = prepare(ctx, c, &a.overrides)?;
    if sandbox::find(&ctx.vm, &spec.name)?.is_some() {
        bail!(
            "sandbox \"{}\" already exists; attach to it with `sbt env run`, or remove it with \
             `sbt env rm` and create it again",
            spec.name
        );
    }
    let skip = a.overrides.skip_host_commands;
    let plan = planned(ctx, &loaded, &spec, false, skip)?;
    write!(&ctx.out, "{}", plan.text(true))?;
    approve(ctx, &loaded, &spec.name, &plan, a.force)?;
    let vars = vars(&loaded, &spec.name);
    host_phase(
        ctx,
        Phase::Initialize,
        &spec.lifecycle.initialize,
        &vars,
        skip,
    )?;
    provision(ctx, &mut secrets, &spec)?;
    create_sandbox(ctx, &spec, &vars, skip)?;
    Ok(0)
}

/// Creates the sandbox and runs `postCreate`. A failure there keeps the sandbox, as in sbx.
fn create_sandbox<R: Runner>(
    ctx: &mut Ctx<R>,
    spec: &EnvSpec,
    vars: &Vars,
    skip_host_commands: bool,
) -> Result<()> {
    let args = super::CreateArgs {
        targets: spec.targets.clone(),
        opts: spec.opts.clone(),
        no_progress: false,
    };
    super::lifecycle::create(ctx, &args)?;
    let commands = &spec.lifecycle.post_create;
    host_phase(ctx, Phase::PostCreate, commands, vars, skip_host_commands).map_err(|e| {
        anyhow!(
            "{e:#}; remove this environment's sandbox and provisioned secrets\n  try: sbt env rm"
        )
    })
}

fn env_run<R: Runner>(ctx: &mut Ctx<R>, run: EnvRunArgs) -> Result<i32> {
    let a = &run.apply;
    refuse_cloud(a)?;
    let (loaded, spec, mut secrets) = prepare(ctx, &run.common, &a.overrides)?;
    let exists = sandbox::find(&ctx.vm, &spec.name)?.is_some();
    let skip = a.overrides.skip_host_commands;
    let plan = planned(ctx, &loaded, &spec, exists, skip)?;
    write!(&ctx.out, "{}", plan.text(true))?;
    approve(ctx, &loaded, &spec.name, &plan, a.force)?;
    let vars = vars(&loaded, &spec.name);
    host_phase(
        ctx,
        Phase::Initialize,
        &spec.lifecycle.initialize,
        &vars,
        skip,
    )?;
    if !exists {
        // Created first and attached to afterwards, so `postCreate` runs in between.
        provision(ctx, &mut secrets, &spec)?;
        create_sandbox(ctx, &spec, &vars, skip)?;
    }
    // Attach as it was created, with the file's current env and launch command for this session.
    let args = RunArgs {
        opts: SandboxOpts {
            name: Some(spec.name),
            ..Default::default()
        },
        detach: run.detach,
        session_env: spec.env,
        entrypoint: spec.entrypoint,
        // Arguments given after `--` take `cmd`'s place, as in sbx.
        agent_args: if run.args.is_empty() {
            spec.cmd.unwrap_or_default()
        } else {
            run.args
        },
        ..Default::default()
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
    // What is stored for the sandbox, removed with it.
    let stored = SecretsFile::load(&ctx.paths)?;
    let scope = scope_for(Some(&name));
    let scoped = stored.secrets.iter().filter(|e| e.scope == scope);
    let scoped: Vec<String> = scoped.map(|e| e.service.clone()).collect();
    let registries = stored.registries.iter();
    let registries = registries.filter(|r| r.sandbox.as_deref() == Some(name.as_str()));
    let registries: Vec<String> = registries.map(|r| r.host.clone()).collect();
    let all = sandbox::list(&ctx.vm)?;
    let sb = all.iter().find(|sb| sb.name() == name);
    // `preRemove` runs whether or not the sandbox is still there, as in sbx.
    let lifecycle = lifecycle(&loaded);
    let skip = a.skip_host_commands;
    let to_run: Vec<Resource> = lifecycle_resources(&loaded, &lifecycle)
        .into_iter()
        .filter(|r| r.when == When::Removal && !skip)
        .collect();
    // `--prune-bindings` removes each service's whole binding, as in sbx.
    let pruned: Vec<(String, Binding)> = (loaded.file.bindings.iter().flatten())
        .filter(|(service, _)| a.prune_bindings && stored.bindings.contains_key(*service))
        .map(|(service, b)| (service.clone(), b.clone()))
        .collect();
    let nothing_stored =
        sb.is_none() && scoped.is_empty() && registries.is_empty() && pruned.is_empty();
    if let Some(sb) = sb {
        let forks = super::lifecycle::remaining_forks(sb, &all, &[&name]);
        if !forks.is_empty() {
            bail!(
                "{name} has forks; remove its forks first: {}",
                forks.join(", ")
            );
        }
    }
    // With nothing to remove and nothing to run there is nothing to confirm.
    if !(nothing_stored && to_run.is_empty()) {
        let summary = remove_summary(
            sb.map(|_| name.as_str()),
            &scoped,
            &binding_resources(&pruned),
            &registries,
            &to_run,
        );
        write!(&ctx.out, "{}{summary}", header(&loaded, &name))?;
        confirm_or(
            ctx,
            "Remove?",
            a.force,
            "stdin is not a terminal; use --force to skip confirmation",
        )?;
    }
    if nothing_stored {
        eprintln!("error: sandbox '{name}' not found\n  try: sbt ls");
    }
    let vars = vars(&loaded, &name);
    if let Err(e) = host_phase(ctx, Phase::PreRemove, &lifecycle.pre_remove, &vars, skip) {
        eprintln!("warning: the preRemove commands did not finish: {e:#}");
    }
    match sb {
        Some(sb) => {
            super::lifecycle::delete_sandbox(ctx, sb, true)?;
            writeln!(&ctx.out, "Removed sandbox {name}")?;
        }
        // No sandbox: only the secrets (and any stale policy) are left to forget.
        None if !nothing_stored => super::secret::forget_sandbox(ctx, &name, true)?,
        None => {}
    }
    if !pruned.is_empty() {
        let mut secrets = SecretsFile::load(&ctx.paths)?;
        for (service, _) in &pruned {
            secrets.bindings.remove(service);
        }
        secrets.save(&ctx.paths)?;
        let file = ctx.paths.secrets_file();
        writeln!(
            &ctx.out,
            "Removed declared bindings from {}",
            file.display()
        )?;
    }
    // Also when nothing else was left: a plain `rm` of the sandbox leaves the approval.
    approval::forget(&ctx.paths, &name)?;
    if !scoped.is_empty() || !registries.is_empty() {
        writeln!(&ctx.out, "Removed secrets scoped to {name}")?;
    }
    Ok(0)
}

/// Loads the files and turns them into create options.
fn prepare<R: Runner>(
    ctx: &Ctx<R>,
    c: &EnvCommon,
    o: &EnvOverrideOpts,
) -> Result<(Loaded, EnvSpec, SecretsFile)> {
    let home = ctx.env.get("HOME").context("HOME is not set")?;
    let inputs = ArgInputs {
        files: c.env_args_file.clone(),
        flags: c.env_arg.clone(),
    };
    let loaded = load(&c.paths, &inputs, &ctx.cwd, Path::new(home))?;
    let secrets = SecretsFile::load(&ctx.paths)?;
    let overrides = Overrides {
        name: c.name.clone(),
        clone: o.clone,
        kit_arg: o.kit_arg.clone(),
        kit_args_file: o.kit_args_file.clone(),
    };
    let spec = spec(&loaded, &overrides, &secrets)?;
    Ok((loaded, spec, secrets))
}

/// Applying an approved, unchanged environment asks nothing. Otherwise `--force` approves this
/// invocation only, and a yes on a terminal is recorded: before applying, so a create that then
/// fails doesn't ask again.
fn approve<R: Runner>(
    ctx: &Ctx<R>,
    loaded: &Loaded,
    name: &str,
    plan: &Planned,
    force: bool,
) -> Result<()> {
    if plan.need == Need::No || force {
        return Ok(());
    }
    if !ctx.stdin_tty {
        // The command as given, quoted for the shell, with `--force` added (sbx does the same).
        let words: Vec<String> = ctx.args.iter().map(|a| shell_word(a)).collect();
        let file = match loaded.files.as_slice() {
            [one] => one.display().to_string(),
            all => {
                let all: Vec<String> = all.iter().map(|f| f.display().to_string()).collect();
                format!("the merged environment ({})", all.join(", "))
            }
        };
        let retry = format!("\n  try: sbt {} --force", words.join(" "));
        if plan.need == Need::HostCommands {
            bail!(
                "{file} declares commands that run on this machine, which must be approved on \
                 every invocation; approve the plan by running it in a terminal or with --force \
                 (-f), or remember approval until the plan changes with the setting below{retry}\n   \
                 or: sbt settings set env.rememberHostCommands true"
            );
        }
        bail!(
            "{file} changes things outside the sandbox that have not been approved; approve them \
             by running this in a terminal, or approve this invocation with --force (-f){retry}"
        );
    }
    let mut out = &ctx.out;
    write!(out, "  Approve this plan? (y/N) ")?;
    out.flush()?;
    if !super::is_yes(&ctx.read_line()?) {
        bail!("aborted");
    }
    approval::save(&ctx.paths, name, &loaded.files, &plan.resources, ctx.now)
}

/// `s` as one shell word: as is when that's safe, else single-quoted.
fn shell_word(s: &str) -> String {
    let plain = |c: char| c.is_ascii_alphanumeric() || "-_./:=@%+,".contains(c);
    if !s.is_empty() && s.chars().all(plain) {
        s.to_string()
    } else {
        crate::util::sh_quote(s)
    }
}

/// Stores the file's secrets at the sandbox's scope. Every source is checked before any is
/// stored; a later failure (the create, say) leaves them for `env rm`, as in sbx.
fn provision<R: Runner>(ctx: &Ctx<R>, secrets: &mut SecretsFile, spec: &EnvSpec) -> Result<()> {
    if spec.secrets.is_empty()
        && spec.registries.is_empty()
        && spec.mcp.is_empty()
        && spec.bindings.is_empty()
    {
        return Ok(());
    }
    // Before anything is stored, as sbx checks a server when it registers it.
    for (name, url) in &spec.mcp {
        crate::mcp::check_reachable(name, url)?;
    }
    let scope = scope_for(Some(&spec.name));
    let mut sources = Vec::new();
    for (service, decl) in &spec.secrets {
        let source = source(ctx, service, &scope, decl)
            .map_err(|e| anyhow!("secret \"{service}\": {e:#}"))?;
        sources.push((service, source));
    }
    // A registry login is a stored value: its sources are resolved once, now.
    let mut logins = Vec::new();
    for (host, decl) in &spec.registries {
        let resolve = |what: &str, d: &SecretDecl| {
            source_value(ctx, d).map_err(|e| anyhow!("registry \"{host}\": {what}: {e:#}"))
        };
        let entry = RegistryEntry {
            host: host.to_ascii_lowercase(),
            username: decl
                .username
                .as_ref()
                .map(|u| resolve("username", u))
                .transpose()?,
            auth_endpoint: None,
            sandbox: Some(spec.name.clone()),
        };
        logins.push((entry, resolve("secret", &decl.secret)?));
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
    for (entry, value) in logins {
        let host = entry.host.clone();
        super::secret::put_registry(ctx, secrets, entry, &value)?;
        writeln!(out, "  ✓ {host} — registry")?;
    }
    // As in sbx, an MCP server is registered for the host and stays after `env rm`.
    for (name, url) in &spec.mcp {
        let server = crate::mcp::Server::Remote {
            url: url.clone(),
            headers: Default::default(),
        };
        crate::mcp::register(&ctx.paths, name, server)?;
        writeln!(out, "  ✓ {name} — mcp")?;
    }
    if !spec.bindings.is_empty() {
        // Merged into the global ones, as sbx does: every sandbox created afterwards uses them.
        for (service, b) in &spec.bindings {
            let (api_key, oauth) = b.domains();
            secrets.bind(service, &api_key, &oauth);
            writeln!(out, "  ✓ {service} — binding")?;
        }
        secrets.save(&ctx.paths)?;
        let file = ctx.paths.secrets_file();
        writeln!(out, "  ✓ Binding saved to {}", file.display())?;
    }
    Ok(())
}

/// The value of a registry source now: a literal, or what its reference or command gives.
fn source_value<R: Runner>(ctx: &Ctx<R>, decl: &SecretDecl) -> Result<String> {
    let source = match (&decl.value, &decl.r#ref, &decl.command) {
        (Some(v), _, _) => return Ok(v.clone()),
        (_, Some(r), _) => Source::Ref {
            reference: r.clone(),
        },
        (_, _, Some(c)) => Source::Command { command: c.clone() },
        _ => bail!("needs a value, ref or command"),
    };
    let entry = SecretEntry {
        service: "registry".into(),
        scope: "global".into(),
        source,
    };
    resolve(&entry, &*ctx.store)
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
    use super::super::{Cli, Cmd, EnvCmd, exit_code};
    use crate::secrets::{SecretEntry, SecretsFile, Source};
    use crate::testutil::*;
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

    fn missing_then_created(t: &TestEnv, lookups: usize) {
        t.project_creatable(lookups);
    }

    fn existing(t: &TestEnv, state: &str) {
        t.project(state);
    }

    /// Call lines with what differs between test envs masked: fresh UUIDs (SANDBOX_ID) and
    /// temp directories.
    fn lines(t: &TestEnv) -> Vec<String> {
        let uuid =
            regex_lite::Regex::new("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
                .unwrap();
        let tmp = regex_lite::Regex::new(r"/[^ :]*/\.tmp[A-Za-z0-9]+").unwrap();
        t.calls()
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
            out.starts_with("ENVIRONMENT\n  Name:  claude-proj\n"),
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
        // It also keeps the file read-only in the sandbox, as sbx does (the label; starts apply it).
        // (`lines` shows temporary directories as TMP.)
        let label = " --label sbx.read-only-files=[\"TMP/proj/sbxenv.yaml\"]";
        let create = env_lines
            .iter()
            .position(|l| l.starts_with("machine create"))
            .unwrap();
        assert!(env_lines[create].contains(label), "{}", env_lines[create]);
        env_lines[create] = env_lines[create].replace(label, "");
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
        t.machine(
            "sbx-shell-proj",
            "created",
            &[
                ("sbx.name", "shell-proj"),
                ("sbx.agent", "shell"),
                ("sbx.workspace", ws.as_str()),
            ],
        );
        t.runner()
            .once_fail(&["machine", "status"], "NOT_FOUND", "vm not found");
        // env create looks the name up once more, for its own "already exists" error.
        t.runner()
            .once_fail(&["machine", "status"], "NOT_FOUND", "vm not found");
        v3_kit(
            &t,
            "hm",
            r#"{"schemaVersion":"3","kind":"mixin","name":"hm","capabilities":[
                {"type":"com.docker.sandbox/host-mount@1","config":{"path":"/home/agent/.hm"}}]}"#,
            &[],
        );
        std::fs::create_dir(t.ctx.cwd.join("data")).unwrap();
        t.sbt(&["env", "create", "--force"]).unwrap();
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
        t.sbt(&["env", "create", "-f"]).unwrap();
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
            let err = t.sbt_err(&["env", cmd]);
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
        let err = t.sbt_err(&[
            "env",
            "create",
            "my env.yaml",
            "--name",
            "box",
            "--env-arg",
            "v=x y",
        ]);
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
        let err = t.sbt_err(&["env", "create", "-f"]);
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
        t.runner()
            .fail(&["machine", "create"], "CREATE_FAILED", "no space left");
        assert!(t.sbt(&["env", "create", "-f"]).is_err());
        assert_eq!(scoped(&t).len(), 1);
        assert_eq!(stored(&t, "github").as_deref(), Some("ghp_dummy"));
    }

    #[test]
    fn snapshot_stores_the_resolved_value_as_a_literal() {
        let mut t = with_file(&format!(
            "{FILE}secrets:\n  github:\n    command: printf snap\n    snapshot: true\n"
        ));
        missing_then_created(&t, 2);
        t.sbt(&["env", "create", "-f"]).unwrap();
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
        let err = t.sbt_err(&["env", "create", "-f"]);
        assert!(err.starts_with("secret \"github\": "), "{err}");
        assert!(scoped(&t).is_empty());
        assert!(creates(&t).is_empty());

        let mut t = with_file(&format!(
            "{FILE}secrets:\n  github:\n    command: \"false\"\n    noVerify: true\n"
        ));
        missing_then_created(&t, 2);
        t.sbt(&["env", "create", "-f"]).unwrap();
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
        t.runner().interactive_exit(0);
        assert_eq!(t.sbt(&["env", "run", "-f"]).unwrap(), 0);
        let exec = t.runner().interactive_calls()[0].join(" ");
        assert!(exec.contains("-e X=two"), "{exec}");
        assert!(creates(&t).is_empty());
        assert!(scoped(&t).is_empty());
    }

    #[test]
    fn run_of_a_new_sandbox_creates_it_and_detaches() {
        let mut t = with_file(FILE);
        // env run looks the name up, and the create once more; the attach finds it.
        missing_then_created(&t, 2);
        assert_eq!(t.sbt(&["env", "run", "-d", "-f"]).unwrap(), 0);
        assert_eq!(creates(&t).len(), 1);
        assert!(t.stdout().ends_with("claude-proj\n"));
        assert!(t.runner().interactive_calls().is_empty());
    }

    fn listed(t: &TestEnv, extra: &[(&str, &str)]) {
        let mut labels = vec![("sbx.name", "claude-proj"), ("sbx.agent", "claude")];
        labels.extend_from_slice(extra);
        let json = machine_json("sbx-claude-proj", "created", &labels);
        t.runner()
            .ok(&["machine", "ls", "--json"], &format!("[{json}]"));
    }

    #[test]
    fn exec_splits_paths_from_the_command_at_dashes() {
        let mut t = with_file(FILE);
        existing(&t, "running");
        t.runner().interactive_exit(3);
        let file = t.ctx.cwd.join("sbxenv.yaml").display().to_string();
        let code = t.sbt(&["env", "exec", &file, "--", "npm", "test"]).unwrap();
        assert_eq!(code, 3);
        let call = t.runner().interactive_calls()[0].join(" ");
        assert!(call.ends_with("-- npm test"), "{call}");
        assert!(call.contains("--name sbx-claude-proj"), "{call}");
    }

    #[test]
    fn exec_without_dashes_takes_every_positional_as_the_command() {
        let mut t = with_file(FILE);
        existing(&t, "running");
        t.runner().interactive_exit(0);
        t.sbt(&["env", "exec", "go", "test", "./..."]).unwrap();
        let call = t.runner().interactive_calls()[0].join(" ");
        assert!(call.ends_with("-- go test ./..."), "{call}");
    }

    #[test]
    fn exec_passes_the_files_env_and_the_users_wins() {
        let mut t = with_file(FILE);
        existing(&t, "running");
        t.runner().interactive_exit(0);
        t.sbt(&["env", "exec", "-e", "X=mine", "--", "env"])
            .unwrap();
        let call = t.runner().interactive_calls()[0].join(" ");
        let (file, user) = (call.find("-e X=one"), call.find("-e X=mine"));
        assert!(file.is_some() && user.is_some() && file < user, "{call}");
    }

    #[test]
    fn exec_of_a_missing_sandbox_fails() {
        let mut t = with_file(FILE);
        t.no_machine();
        let err = t.sbt_err(&["env", "exec", "--", "ls"]);
        assert_eq!(
            err,
            "sandbox 'claude-proj' not found for this environment\n  try: sbt env create"
        );
        assert!(t.runner().interactive_calls().is_empty());
    }

    #[test]
    fn exec_works_when_the_workspace_is_gone() {
        let mut t = with_file(&FILE.replace("workspace: .", "workspace: ./gone"));
        existing(&t, "running");
        t.runner().interactive_exit(0);
        t.sbt(&["env", "exec", "--", "ls"]).unwrap();
    }

    fn set_scoped(t: &mut TestEnv, scope: &[&str]) {
        let mut a = vec!["secret", "set", "github", "-t", "tok"];
        a.extend_from_slice(scope);
        t.sbt(&a).unwrap();
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
        assert_eq!(t.sbt(&["env", "rm", "--force"]).unwrap(), 0);
        let out = t.stdout();
        assert!(out.contains("ENVIRONMENT\n  Name:  claude-proj\n"), "{out}");
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
        let err = t.sbt_err(&["env", "rm"]);
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
        t.runner().ok(&["machine", "ls", "--json"], "[]");
        assert_eq!(t.sbt(&["env", "rm", "-f"]).unwrap(), 0);
        assert_eq!(t.stdout(), "");
        assert!(deletes(&t).is_empty());
    }

    #[test]
    fn rm_with_only_scoped_secrets_removes_them() {
        let mut t = with_file(FILE);
        set_scoped(&mut t, &["--sandbox", "claude-proj"]);
        t.runner().ok(&["machine", "ls", "--json"], "[]");
        t.sbt(&["env", "rm", "-f"]).unwrap();
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
        t.runner()
            .ok(&["machine", "ls", "--json"], &format!("[{a},{b}]"));
        let err = t.sbt_err(&["env", "rm", "-f"]);
        assert_eq!(
            err,
            "claude-proj has forks; remove its forks first: claude-proj-fork-1"
        );
        assert!(deletes(&t).is_empty());
    }

    #[test]
    fn rm_needs_the_required_args() {
        let mut t = with_file(&format!("{FILE}args:\n  channel:\n    required: true\n"));
        assert!(t.sbt(&["env", "rm", "-f"]).is_err());
        assert!(t.sbt(&["env", "exec", "--", "ls"]).is_err());
    }

    #[test]
    fn cloud_flags_exit_2() {
        let mut t = with_file(FILE);
        let err = t
            .sbt(&["env", "create", "--on-timeout", "stop"])
            .unwrap_err();
        assert_eq!(exit_code(&err), 2, "{err}");
        assert!(creates(&t).is_empty());
    }

    const COMMAND_SECRET: &str = "secrets:\n  github:\n    command: printf tok\n";

    /// `text` as the file, approved on a terminal and created. Afterwards there is no terminal
    /// and the sandbox exists.
    fn approved(text: &str) -> TestEnv {
        let mut t = with_file(text);
        missing_then_created(&t, 2);
        t.answer("y\n");
        t.sbt(&["env", "create"]).unwrap();
        assert!(t.stdout().contains("\n  Approve this plan? (y/N) "));
        t.ctx.stdin_tty = false;
        t
    }

    fn record(t: &TestEnv) -> Option<String> {
        std::fs::read_to_string(t.ctx.paths.env_records().join("claude-proj.toml")).ok()
    }

    /// `env plan`'s output with the project directory masked.
    fn plan(t: &mut TestEnv) -> String {
        t.sbt(&["env", "plan"]).unwrap();
        t.stdout()
            .replace(&t.ctx.cwd.display().to_string(), "<proj>")
    }

    #[test]
    fn plan_of_a_fresh_environment() {
        let mut t = with_file(&format!("{FILE}{COMMAND_SECRET}"));
        t.no_machine();
        insta::assert_snapshot!(plan(&mut t));
        assert!(creates(&t).is_empty());
        assert_eq!(record(&t), None, "a plan records nothing");
    }

    #[test]
    fn plan_of_an_approved_environment() {
        let mut t = approved(FILE);
        assert_eq!(
            plan(&mut t),
            "ENVIRONMENT\n  Name:  claude-proj\n  File:  <proj>/sbxenv.yaml\n\n  \
             0 to add · 0 to change · 0 to destroy\n  \
             ✓ already approved — applying asks nothing\n"
        );
    }

    #[test]
    fn plan_of_a_changed_environment() {
        let mut t = approved(FILE);
        let changed = FILE.replace("X: one", "X: two").replace("8080", "8081");
        std::fs::write(t.ctx.cwd.join("sbxenv.yaml"), changed).unwrap();
        insta::assert_snapshot!(plan(&mut t));
    }

    #[test]
    fn plan_of_approved_host_commands_before_a_create() {
        let mut t = approved(&format!("{FILE}{COMMAND_SECRET}"));
        t.no_machine();
        insta::assert_snapshot!(plan(&mut t));
    }

    #[test]
    fn an_approved_environment_applies_without_a_terminal() {
        let mut t = approved(FILE);
        // Attaching, and creating it again after a plain `rm`.
        t.sbt(&["env", "run", "-d"]).unwrap();
        missing_then_created(&t, 2);
        t.sbt(&["env", "create"]).unwrap();
        assert_eq!(creates(&t).len(), 2);
    }

    #[test]
    fn force_approves_nothing() {
        let mut t = with_file(FILE);
        missing_then_created(&t, 2);
        t.sbt(&["env", "create", "--force"]).unwrap();
        assert_eq!(record(&t), None);
        let err = t.sbt_err(&["env", "run", "-d"]);
        assert!(err.contains("have not been approved"), "{err}");

        // Nor does it replace an earlier approval.
        let mut t = approved(FILE);
        let before = record(&t);
        std::fs::write(
            t.ctx.cwd.join("sbxenv.yaml"),
            FILE.replace("X: one", "X: two"),
        )
        .unwrap();
        t.sbt(&["env", "run", "-d", "--force"]).unwrap();
        assert_eq!(record(&t), before);
    }

    #[test]
    fn a_changed_file_asks_again() {
        let mut t = approved(FILE);
        std::fs::write(
            t.ctx.cwd.join("sbxenv.yaml"),
            FILE.replace("X: one", "X: two"),
        )
        .unwrap();
        let err = t.sbt_err(&["env", "run", "-d"]);
        assert!(err.contains("have not been approved"), "{err}");
        // Declining on a terminal records nothing new.
        let before = record(&t);
        t.answer("n\n");
        assert_eq!(t.sbt_err(&["env", "run", "-d"]), "aborted");
        assert_eq!(record(&t), before);
    }

    #[test]
    fn unchanged_host_commands_ask_every_time_unless_remembered() {
        let mut t = approved(&format!("{FILE}{COMMAND_SECRET}"));
        let file = t.ctx.cwd.join("sbxenv.yaml").display().to_string();
        let refusal = |cmd: &str| {
            format!(
                "{file} declares commands that run on this machine, which must be approved on \
                 every invocation; approve the plan by running it in a terminal or with --force \
                 (-f), or remember approval until the plan changes with the setting below\n  \
                 try: sbt env {cmd} --force\n   \
                 or: sbt settings set env.rememberHostCommands true"
            )
        };
        // As in sbx: also when attaching, where the secret's command doesn't run again.
        assert_eq!(t.sbt_err(&["env", "run", "-d"]), refusal("run -d"));
        t.stdout();
        missing_then_created(&t, 2);
        assert_eq!(t.sbt_err(&["env", "create"]), refusal("create"));
        let out = t.stdout();
        assert!(
            out.ends_with(
                "  ! nothing in this plan has changed, but its commands run on this machine, \
                 outside the sandbox, with your own privileges, which needs explicit approval on \
                 each run\n"
            ),
            "{out}"
        );

        t.ctx
            .settings
            .set("env.rememberHostCommands", "true")
            .unwrap();
        existing(&t, "running");
        t.sbt(&["env", "run", "-d"]).unwrap();
        missing_then_created(&t, 2);
        t.sbt(&["env", "create"]).unwrap();
    }

    #[test]
    fn env_rm_forgets_the_approval() {
        let mut t = approved(FILE);
        assert!(record(&t).is_some());
        listed(&t, &[]);
        t.sbt(&["env", "rm", "--force"]).unwrap();
        assert_eq!(record(&t), None);
    }

    #[test]
    fn env_rm_forgets_the_approval_when_nothing_else_is_left() {
        // The sandbox went with a plain `rm`, which leaves the approval.
        let mut t = approved(FILE);
        t.runner().ok(&["machine", "ls", "--json"], "[]");
        t.sbt(&["env", "rm", "--force"]).unwrap();
        assert_eq!(record(&t), None);
    }

    #[test]
    fn what_a_secret_or_a_port_does_is_part_of_the_approval() {
        // `snapshot` decides whether the command runs once or at every start; `hostIP` where
        // the port listens.
        let file = |snapshot: bool, host_ip: &str| {
            format!(
                "schemaVersion: \"1\"\nagent: claude\nworkspace: .\nports:\n  - sandbox: 80\n    \
                 host: 8080\n{host_ip}secrets:\n  github:\n    command: printf tok\n    \
                 snapshot: {snapshot}\n"
            )
        };
        const IP: &str = "    hostIP: 127.0.0.1\n";
        for changed in [file(false, IP), file(true, "")] {
            let mut t = approved(&file(true, IP));
            t.ctx
                .settings
                .set("env.rememberHostCommands", "true")
                .unwrap();
            t.sbt(&["env", "run", "-d"]).unwrap();
            std::fs::write(t.ctx.cwd.join("sbxenv.yaml"), changed).unwrap();
            let err = t.sbt_err(&["env", "run", "-d"]);
            assert!(err.contains("have not been approved"), "{err}");
        }
        let mut t = approved(&file(true, IP));
        t.no_machine();
        let plan = plan(&mut t);
        assert!(plan.contains("      snapshot: true\n"), "{plan}");
        assert!(plan.contains("      hostIP: 127.0.0.1\n"), "{plan}");
    }

    #[cfg(unix)]
    #[test]
    fn the_record_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let t = approved(FILE);
        let path = t.ctx.paths.env_records().join("claude-proj.toml");
        let mode = std::fs::metadata(path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    /// A file whose lifecycle commands append their phase to `<cwd>/log`.
    fn lifecycle_file(extra: &str) -> String {
        format!(
            "{FILE}lifecycle:\n  initialize:\n    - command: echo init >> log\n  \
             postCreate:\n    - command: echo post >> log\n  \
             preRemove:\n    - command: echo pre >> log\n{extra}"
        )
    }

    fn log(t: &TestEnv) -> String {
        std::fs::read_to_string(t.ctx.cwd.join("log")).unwrap_or_default()
    }

    #[test]
    fn lifecycle_phases_run_around_the_create_and_on_every_run() {
        let mut t = with_file(&lifecycle_file(""));
        missing_then_created(&t, 2);
        t.sbt(&["env", "create", "--force"]).unwrap();
        assert_eq!(log(&t), "init\npost\n");
        let out = t.stdout();
        let (init, created, post) = (
            out.find("\nHOST INITIALIZE\n  ○ echo init >> log\n")
                .unwrap(),
            out.find("Created sandbox claude-proj").unwrap(),
            out.find("\nHOST POST-CREATE\n").unwrap(),
        );
        assert!(init < created && created < post, "{out}");

        // Attaching: `initialize` again, nothing else.
        t.sbt(&["env", "run", "-d", "--force"]).unwrap();
        assert_eq!(log(&t), "init\npost\ninit\n");
        // `env exec` runs none.
        t.sbt(&["env", "exec", "--", "true"]).unwrap();
        assert_eq!(log(&t), "init\npost\ninit\n");
    }

    #[test]
    fn a_failing_initialize_creates_and_stores_nothing() {
        let mut t = with_file(&format!(
            "{FILE}secrets:\n  github:\n    value: ghp_dummy\nlifecycle:\n  initialize:\n    \
             - command: exit 7\n"
        ));
        missing_then_created(&t, 2);
        for cmd in ["create", "run"] {
            assert_eq!(
                t.sbt_err(&["env", cmd, "--force"]),
                "initialize[0] (exit 7): exit status 7"
            );
        }
        assert!(creates(&t).is_empty());
        assert!(scoped(&t).is_empty());
    }

    #[test]
    fn a_failing_post_create_keeps_the_sandbox() {
        let mut t = with_file(&format!(
            "{FILE}lifecycle:\n  postCreate:\n    - command: exit 4\n"
        ));
        missing_then_created(&t, 2);
        assert_eq!(
            t.sbt_err(&["env", "run", "--force"]),
            "postCreate[0] (exit 4): exit status 4; remove this environment's sandbox and \
             provisioned secrets\n  try: sbt env rm"
        );
        assert_eq!(creates(&t).len(), 1);
        assert!(deletes(&t).is_empty());
        assert!(t.runner().interactive_calls().is_empty(), "not attached");
    }

    #[test]
    fn pre_remove_runs_with_or_without_the_sandbox_and_never_stops_the_removal() {
        let mut t = with_file(&lifecycle_file("    - command: exit 3\n"));
        listed(&t, &[]);
        t.sbt(&["env", "rm", "--force"]).unwrap();
        assert_eq!(log(&t), "pre\n");
        let out = t.stdout();
        assert!(
            out.contains("\nLIFECYCLE\n  > preRemove: echo pre >> log\n      workdir: "),
            "{out}"
        );
        assert!(out.contains(" · 1 to destroy · 2 to run\n"), "{out}");
        assert!(out.contains("\nHOST PRE-REMOVE\n"), "{out}");
        assert!(out.ends_with("Removed sandbox claude-proj\n"), "{out}");
        assert_eq!(deletes(&t).len(), 1);

        // The sandbox is gone already: the commands still run.
        t.runner().ok(&["machine", "ls", "--json"], "[]");
        t.sbt(&["env", "rm", "--force"]).unwrap();
        assert_eq!(log(&t), "pre\npre\n");
        assert_eq!(deletes(&t).len(), 1);
    }

    #[test]
    fn skip_host_commands_skips_every_phase_and_leaves_the_approval() {
        let mut t = approved(&lifecycle_file(""));
        assert_eq!(log(&t), "init\npost\n");
        let before = record(&t);
        // Approved, and the lifecycle commands (which would ask every time) are left out.
        t.sbt(&["env", "run", "-d", "--skip-host-commands"])
            .unwrap();
        listed(&t, &[]);
        t.sbt(&["env", "rm", "--force", "--skip-host-commands"])
            .unwrap();
        assert_eq!(log(&t), "init\npost\n", "nothing more ran");
        let out = t.stdout();
        assert!(!out.contains("LIFECYCLE"), "{out}");
        assert!(!out.contains("HOST "), "{out}");
        // Until the `env rm`, the record was untouched.
        assert!(before.unwrap().contains("initialize[0]"));

        // A yes given with the flag approves what was shown and nothing else: a command changed
        // meanwhile stays unapproved, and the record keeps the one approved before.
        let mut t = approved(&lifecycle_file(""));
        let changed = lifecycle_file("")
            .replace("X: one", "X: two")
            .replace("echo init >> log", "echo CHANGED >> log");
        std::fs::write(t.ctx.cwd.join("sbxenv.yaml"), changed).unwrap();
        t.answer("y\n");
        t.sbt(&["env", "run", "-d", "--skip-host-commands"])
            .unwrap();
        assert!(!t.stdout().contains("CHANGED"), "the plan left it out");
        let record = record(&t).unwrap();
        assert!(record.contains("value\", \"two"), "{record}");
        assert!(record.contains("initialize: echo init >> log"), "{record}");
        assert!(!record.contains("CHANGED"), "{record}");
        t.ctx.stdin_tty = false;
        let err = t.sbt_err(&["env", "run", "-d"]);
        assert!(err.contains("have not been approved"), "{err}");
        assert_eq!(log(&t), "init\npost\n", "the changed command never ran");
    }

    #[test]
    fn env_run_launches_the_entrypoint_and_cmd() {
        let launch = "entrypoint: [\"/bin/sh\", \"-c\"]\ncmd: [\"echo hi\"]\n";
        let mut t = with_file(&format!("{FILE}{launch}"));
        existing(&t, "running");
        t.sbt(&["env", "run", "--force"]).unwrap();
        let call = t.runner().interactive_calls()[0].join(" ");
        assert!(call.ends_with(" -- /bin/sh -c echo hi"), "{call}");
        assert!(t.stdout().contains("\nAGENT LAUNCH\n  + entrypoint\n"));

        // Only `cmd`: the agent's own command with those arguments, as `-- ARGS` (measured: sbx
        // treats the two alike).
        let mut t = with_file(&format!("{FILE}cmd: [\"--version\"]\n"));
        existing(&t, "running");
        t.sbt(&["env", "run", "--force"]).unwrap();
        let call = t.runner().interactive_calls()[0].join(" ");
        assert!(
            call.ends_with(" -- claude --dangerously-skip-permissions --version"),
            "{call}"
        );

        // Plain `run` doesn't know the file.
        let mut t = with_file(&format!("{FILE}{launch}"));
        existing(&t, "running");
        t.sbt(&["run", "--name", "claude-proj"]).unwrap();
        let call = t.runner().interactive_calls()[0].join(" ");
        assert!(!call.contains("/bin/sh -c echo hi"), "{call}");
    }

    const REGISTRY: &str = "registries:\n  GHCR.io:\n    username:\n      value: me\n    \
        secret:\n      command: printf 'reg-%s' tok3n\n";

    fn registries(t: &TestEnv) -> Vec<crate::secrets::RegistryEntry> {
        SecretsFile::load(&t.ctx.paths).unwrap().registries
    }

    #[test]
    fn registries_are_stored_for_the_sandbox_and_removed_with_it() {
        let mut t = with_file(&format!("{FILE}{REGISTRY}"));
        // A host-wide login for the same host stays as it is.
        t.ctx.store.set("registry:ghcr.io", "host-wide").unwrap();
        missing_then_created(&t, 2);
        t.sbt(&["env", "create", "--force"]).unwrap();
        let out = t.stdout();
        assert!(
            out.contains("\nPROVISION\n  Scope:  claude-proj\n  ✓ ghcr.io — registry\n"),
            "{out}"
        );
        assert!(!out.contains("reg-tok3n"), "{out}");
        let stored = registries(&t);
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].host, "ghcr.io");
        assert_eq!(stored[0].username.as_deref(), Some("me"));
        assert_eq!(stored[0].sandbox.as_deref(), Some("claude-proj"));
        let get = |t: &TestEnv, key: &str| t.ctx.store.get(key).unwrap();
        assert_eq!(
            get(&t, "sandbox-registry:claude-proj/ghcr.io").as_deref(),
            Some("reg-tok3n")
        );
        t.sbt(&["secret", "ls"]).unwrap();
        let ls = t.stdout();
        assert!(
            ls.contains("claude-proj   registry   ghcr.io   (stored)"),
            "{ls}"
        );
        // As in sbx, the sandbox's own listing has it too, and only it.
        t.sbt(&["secret", "ls", "--sandbox", "claude-proj"])
            .unwrap();
        let ls = t.stdout();
        assert!(
            ls.contains("claude-proj   registry   ghcr.io   (stored)"),
            "{ls}"
        );
        t.sbt(&["secret", "ls", "--sandbox", "other"]).unwrap();
        assert!(!t.stdout().contains("ghcr.io"));

        listed(&t, &[]);
        t.sbt(&["env", "rm", "--force"]).unwrap();
        let out = t.stdout();
        assert!(out.contains("\nREGISTRIES\n  - ghcr.io\n"), "{out}");
        assert!(out.contains(" · 2 to destroy\n"), "{out}");
        assert!(
            out.ends_with("Removed secrets scoped to claude-proj\n"),
            "{out}"
        );
        assert!(registries(&t).is_empty());
        assert_eq!(get(&t, "sandbox-registry:claude-proj/ghcr.io"), None);
        assert_eq!(get(&t, "registry:ghcr.io").as_deref(), Some("host-wide"));
    }

    #[test]
    fn a_plain_rm_removes_the_sandboxs_registry_login() {
        let mut t = with_file(&format!("{FILE}{REGISTRY}"));
        missing_then_created(&t, 2);
        t.sbt(&["env", "create", "--force"]).unwrap();
        listed(&t, &[]);
        t.sbt(&["rm", "-f", "claude-proj"]).unwrap();
        assert!(registries(&t).is_empty());
        let key = "sandbox-registry:claude-proj/ghcr.io";
        assert_eq!(t.ctx.store.get(key).unwrap(), None);
    }

    #[test]
    fn a_registry_source_that_fails_stops_before_the_create() {
        let bad = REGISTRY.replace("printf 'reg-%s' tok3n", "exit 1");
        let mut t = with_file(&format!("{FILE}{bad}"));
        missing_then_created(&t, 2);
        let err = t.sbt_err(&["env", "create", "--force"]);
        assert!(err.starts_with("registry \"GHCR.io\": secret: "), "{err}");
        assert!(creates(&t).is_empty());
        assert!(registries(&t).is_empty());
    }

    #[test]
    fn env_run_detached_launches_nothing_and_no_workspace_means_mountless() {
        // Both measured on sbx 0.53.
        let file = "schemaVersion: \"1\"\nagent: claude\nname: claude-proj\n\
                    entrypoint: [\"/bin/sh\", \"-c\"]\ncmd: [\"echo hi\"]\n";
        let mut t = with_file(file);
        missing_then_created(&t, 2);
        t.sbt(&["env", "run", "-d", "--force"]).unwrap();
        assert!(t.runner().interactive_calls().is_empty());
        let create = &creates(&t)[0];
        let cwd = t.ctx.cwd.display().to_string();
        assert!(!create.contains(&cwd), "no workspace mount: {create}");
    }

    #[test]
    fn another_set_of_files_is_another_environment() {
        let mut t = approved(FILE);
        std::fs::write(t.ctx.cwd.join("same.yaml"), "env:\n  X: one\n").unwrap();
        let err = t.sbt_err(&["env", "run", "-d", "sbxenv.yaml", "same.yaml"]);
        let dir = t.ctx.cwd.display().to_string();
        assert!(
            err.starts_with(&format!(
                "the merged environment ({dir}/sbxenv.yaml, {dir}/same.yaml) changes things \
                 outside the sandbox that have not been approved"
            )),
            "{err}"
        );
        let out = t.stdout();
        assert!(
            out.contains(&format!(
                "  Name:   claude-proj\n  Files:  {dir}/sbxenv.yaml\n          {dir}/same.yaml\n"
            )),
            "{out}"
        );
        assert!(
            out.contains("  ! claude-proj — present, not recorded as applied"),
            "{out}"
        );
    }

    #[test]
    fn env_plan_stores_nothing() {
        let mut t = with_file(&format!(
            "{FILE}secrets:\n  github:\n    value: ghp_dummy\n{REGISTRY}"
        ));
        t.no_machine();
        t.sbt(&["env", "plan"]).unwrap();
        assert!(scoped(&t).is_empty());
        assert!(registries(&t).is_empty());
        assert_eq!(record(&t), None);
    }

    #[test]
    fn unchanged_host_commands_ask_on_a_terminal_too() {
        let mut t = approved(&lifecycle_file(""));
        t.answer("y\n");
        t.sbt(&["env", "run", "-d"]).unwrap();
        let out = t.stdout();
        assert!(
            out.contains(
                "  ! nothing in this plan has changed, but its commands run on this machine, \
                 outside the sandbox, with your own privileges, which needs explicit approval on \
                 each run\n  Approve this plan? (y/N) "
            ),
            "{out}"
        );
    }

    #[test]
    fn a_failing_initialize_stores_no_registry_login() {
        let mut t = with_file(&format!(
            "{FILE}{REGISTRY}lifecycle:\n  initialize:\n    - command: exit 7\n"
        ));
        missing_then_created(&t, 2);
        assert!(
            t.sbt_err(&["env", "create", "--force"])
                .ends_with("exit status 7")
        );
        assert!(registries(&t).is_empty());
    }

    #[test]
    fn env_run_creates_runs_post_create_then_attaches_with_the_launch_command() {
        let launch = "entrypoint: [\"/bin/sh\", \"-c\"]\ncmd: [\"echo hi\"]\n";
        let mut t = with_file(&format!(
            "{FILE}{launch}lifecycle:\n  postCreate:\n    - command: echo post >> log\n"
        ));
        missing_then_created(&t, 2);
        t.sbt(&["env", "run", "--force"]).unwrap();
        assert_eq!(log(&t), "post\n");
        let out = t.stdout();
        let (created, post) = (
            out.find("Created sandbox claude-proj").unwrap(),
            out.find("HOST POST-CREATE").unwrap(),
        );
        assert!(created < post, "{out}");
        let call = t.runner().interactive_calls()[0].join(" ");
        assert!(call.ends_with(" -- /bin/sh -c echo hi"), "{call}");
    }

    #[test]
    fn arguments_after_dashes_replace_cmd_or_go_to_the_agent() {
        // Both measured on sbx 0.53: with an override they replace `cmd` (the plan still shows
        // the file's), without one the agent gets them.
        let launch = "entrypoint: [\"/bin/sh\", \"-c\"]\ncmd: [\"echo from-file\"]\n";
        let mut t = with_file(&format!("{FILE}{launch}"));
        existing(&t, "running");
        t.sbt(&["env", "run", "--force", "--", "echo from-args"])
            .unwrap();
        let call = t.runner().interactive_calls()[0].join(" ");
        assert!(call.ends_with(" -- /bin/sh -c echo from-args"), "{call}");
        assert!(t.stdout().contains("argv: \"[\\\"echo from-file\\\"]\""));

        let mut t = with_file(FILE);
        existing(&t, "running");
        t.sbt(&["env", "run", "--force", "--", "--version"])
            .unwrap();
        let call = t.runner().interactive_calls()[0].join(" ");
        assert!(
            call.ends_with(" -- claude --dangerously-skip-permissions --version"),
            "{call}"
        );

        // Paths still come before the dashes.
        let mut t = with_file(FILE);
        existing(&t, "running");
        t.sbt(&["env", "run", "--force", "sbxenv.yaml", "--", "-c"])
            .unwrap();
        let call = t.runner().interactive_calls()[0].join(" ");
        assert!(
            call.ends_with(" -- claude --dangerously-skip-permissions -c"),
            "{call}"
        );
    }

    const BINDING: &str = "secrets:\n  github:\n    value: ghp_dummy\nbindings:\n  github:\n    apiKey:\n      domains: [uploads.github.com]\n";

    fn bindings(t: &TestEnv) -> Vec<String> {
        let f = SecretsFile::load(&t.ctx.paths).unwrap();
        f.bindings.keys().cloned().collect()
    }

    #[test]
    fn bindings_are_saved_globally_and_send_the_credential_there() {
        let mut t = with_file(&format!("{FILE}{BINDING}"));
        missing_then_created(&t, 2);
        t.sbt(&["env", "create", "--force"]).unwrap();
        let out = t.stdout();
        assert!(
            out.contains("\nBINDINGS\n  + github\n      apiKey.domains: uploads.github.com\n"),
            "{out}"
        );
        let file = t.ctx.paths.secrets_file().display().to_string();
        assert!(
            out.contains(&format!(
                "  ✓ github — binding\n  ✓ Binding saved to {file}\n"
            )),
            "{out}"
        );
        assert_eq!(bindings(&t), ["github"]);
        let create = &creates(&t)[0];
        assert!(create.contains("uploads.github.com"), "{create}");
    }

    #[test]
    fn env_rm_keeps_bindings_unless_pruned() {
        let mut t = with_file(&format!("{FILE}{BINDING}"));
        missing_then_created(&t, 2);
        t.sbt(&["env", "create", "--force"]).unwrap();
        listed(&t, &[]);
        t.sbt(&["env", "rm", "--force"]).unwrap();
        assert_eq!(bindings(&t), ["github"]);
        t.stdout();
        // The sandbox is gone: only the binding is left to prune.
        t.runner().ok(&["machine", "ls", "--json"], "[]");
        t.sbt(&["env", "rm", "--force", "--prune-bindings"])
            .unwrap();
        let out = t.stdout();
        assert!(
            out.contains("\nBINDINGS\n  - github\n      apiKey.domains: uploads.github.com\n"),
            "{out}"
        );
        assert!(out.contains("Removed declared bindings from "), "{out}");
        assert!(bindings(&t).is_empty());
    }

    #[test]
    fn a_binding_for_an_unknown_service_is_refused() {
        let mut t = with_file(&format!(
            "{FILE}bindings:\n  nosuch:\n    apiKey:\n      domains: [a.example]\n"
        ));
        missing_then_created(&t, 2);
        let err = t.sbt_err(&["env", "create", "--force"]);
        assert!(err.starts_with("unknown service 'nosuch'"), "{err}");
    }

    #[test]
    fn mcp_url_servers_are_registered_and_attached() {
        let mut t = with_file(&format!(
            "{FILE}mcp:\n  servers:\n    - name: deep\n      url: https://mcp.deepwiki.com/mcp\n"
        ));
        missing_then_created(&t, 2);
        t.sbt(&["env", "create", "--force"]).unwrap();
        let out = t.stdout();
        assert!(
            out.contains("\nMCP SERVERS\n  + deep\n      url: https://mcp.deepwiki.com/mcp\n"),
            "{out}"
        );
        assert!(out.contains("  ✓ deep — mcp\n"), "{out}");
        let registered = crate::mcp::McpFile::load(&t.ctx.paths).unwrap();
        assert!(registered.servers.contains_key("deep"));
        let create = &creates(&t)[0];
        assert!(create.contains("sbx.mcp=deep"), "{create}");
        // It stays after `env rm`, as in sbx.
        listed(&t, &[]);
        t.sbt(&["env", "rm", "--force"]).unwrap();
        let registered = crate::mcp::McpFile::load(&t.ctx.paths).unwrap();
        assert!(registered.servers.contains_key("deep"));
    }

    #[test]
    fn an_unreachable_mcp_server_fails_the_create_before_anything_is_stored() {
        // As sbx, which contacts the server when it registers it.
        let mut t = with_file(&format!(
            "{FILE}secrets:\n  github:\n    value: ghp_dummy\n\
             mcp:\n  servers:\n    - name: gone\n      url: https://mcp.example.invalid/mcp\n"
        ));
        missing_then_created(&t, 2);
        let err = t.sbt_err(&["env", "create", "--force"]);
        assert!(
            err.starts_with(
                "register mcp server \"gone\": server \"gone\": discovery failed: connecting to \
                 server https://mcp.example.invalid/mcp: "
            ),
            "{err}"
        );
        assert!(creates(&t).is_empty());
        assert!(scoped(&t).is_empty());
        assert!(
            crate::mcp::McpFile::load(&t.ctx.paths)
                .unwrap()
                .servers
                .is_empty()
        );
    }

    #[test]
    fn the_record_never_holds_a_secret_value() {
        let t = approved(&format!(
            "{FILE}secrets:\n  github:\n    value: s3cr3t-value\n"
        ));
        let record = record(&t).unwrap();
        assert!(!record.contains("s3cr3t-value"), "{record}");
        assert!(record.contains("sha256:"), "{record}");
    }

    #[test]
    fn a_broken_record_is_no_approval() {
        let mut t = approved(FILE);
        std::fs::write(t.ctx.paths.env_records().join("claude-proj.toml"), "x = [").unwrap();
        let err = t.sbt_err(&["env", "run", "-d"]);
        assert!(err.contains("have not been approved"), "{err}");
    }

    #[test]
    fn clone_takes_an_optional_value() {
        let clone = |args: &[&str]| {
            let cli = Cli::try_parse_from(["sbt", "env", "create"].iter().chain(args)).unwrap();
            match cli.command {
                Some(Cmd::Env(EnvCmd::Create(a))) => (a.apply.overrides.clone, a.common.paths),
                other => panic!("{other:?}"),
            }
        };
        assert_eq!(clone(&[]), (None, vec![]));
        assert_eq!(clone(&["--clone", "./p"]), (Some(true), vec!["./p".into()]));
        assert_eq!(clone(&["--clone=true"]).0, Some(true));
        assert_eq!(clone(&["--clone=false"]).0, Some(false));
    }
}
