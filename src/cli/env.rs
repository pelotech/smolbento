//! `bento env`: a sandbox declared in sbxenv.yaml files.

use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};

use super::env_spec::{
    EnvSpec, LIFECYCLE, binding_resources, header, lifecycle, lifecycle_resources, name,
    remove_summary, resources, spec, vars,
};
use super::{
    Ctx, EnvApplyOpts, EnvCmd, EnvCommon, EnvExecArgs, EnvOverrideOpts, EnvRmArgs, EnvRunArgs,
    ExecArgs, RunArgs, SandboxOpts, SecretSource, confirm_or,
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
        EnvCmd::Create(a) => apply(ctx, &a.common, &a.apply, false).map(|_| 0),
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
            crate::warning!(
                "skipping the host commands declared for {} (--skip-host-commands)",
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
    super::refuse_as(
        &[
            (a.on_timeout.is_some(), "--on-timeout"),
            (a.ttl.is_some(), "--ttl"),
        ],
        "is a Docker Cloud option",
    )
}

/// What `env create` and `env run` share: shows the plan, asks, runs `initialize` and creates
/// the sandbox unless it exists, which only `attach` allows.
fn apply<R: Runner>(
    ctx: &mut Ctx<R>,
    c: &EnvCommon,
    a: &EnvApplyOpts,
    attach: bool,
) -> Result<EnvSpec> {
    refuse_cloud(a)?;
    let (loaded, spec, mut secrets) = prepare(ctx, c, &a.overrides)?;
    let exists = sandbox::find(&ctx.vm, &spec.name)?.is_some();
    if exists && !attach {
        bail!(
            "sandbox \"{}\" already exists; attach to it with `bento env run`, or remove it with \
             `bento env rm` and create it again",
            spec.name
        );
    }
    let skip = a.overrides.skip_host_commands;
    let plan = planned(ctx, &loaded, &spec, exists, skip)?;
    write!(&ctx.out, "{}", plan.text(true))?;
    approve(ctx, &loaded, &spec.name, &plan, a.force)?;
    let vars = vars(&loaded, &spec.name);
    let initialize = &spec.lifecycle.initialize;
    host_phase(ctx, Phase::Initialize, initialize, &vars, skip)?;
    if !exists {
        // Created first and attached to afterwards, so `postCreate` runs in between.
        provision(ctx, &mut secrets, &spec)?;
        create_sandbox(ctx, &spec, &vars, skip)?;
    }
    Ok(spec)
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
            "{e:#}; remove this environment's sandbox and provisioned secrets\n  try: bento env rm"
        )
    })
}

fn env_run<R: Runner>(ctx: &mut Ctx<R>, run: EnvRunArgs) -> Result<i32> {
    let spec = apply(ctx, &run.common, &run.apply, true)?;
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
    let loaded = load_files(ctx, paths, env_arg, env_args_file)?;
    let name = name(&loaded, name_flag)?;
    Ok((loaded, name))
}

/// Loads the environment files with their arguments.
fn load_files<R: Runner>(
    ctx: &Ctx<R>,
    paths: &[String],
    env_arg: &[String],
    env_args_file: &[std::path::PathBuf],
) -> Result<Loaded> {
    let home = ctx.env.get("HOME").context("HOME is not set")?;
    let inputs = ArgInputs {
        files: env_args_file.to_vec(),
        flags: env_arg.to_vec(),
    };
    load(paths, &inputs, &ctx.cwd, Path::new(home))
}

fn env_exec<R: Runner>(ctx: &mut Ctx<R>, a: EnvExecArgs) -> Result<i32> {
    // Without `--` every positional is the command and the file comes from the current directory.
    let (paths, command) = if a.command.is_empty() {
        (vec![], a.paths)
    } else {
        (a.paths, a.command)
    };
    if command.is_empty() {
        bail!("specify a command to run, e.g. `bento env exec -- bash`");
    }
    let (loaded, name) = load_name(ctx, &paths, a.name.as_deref(), &a.env_arg, &a.env_args_file)?;
    if sandbox::find(&ctx.vm, &name)?.is_none() {
        bail!("sandbox '{name}' not found for this environment\n  try: bento env create");
    }
    // The file's env first, so the user's -e wins.
    let mut env: Vec<String> = loaded
        .file
        .env
        .iter()
        .flatten()
        .map(|(k, v)| format!("{k}={v}"))
        .collect();
    let mut flags = a.flags;
    env.append(&mut flags.env);
    flags.env = env;
    let args = ExecArgs {
        flags,
        sandbox: name,
        command,
    };
    super::exec::exec(ctx, &args)
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
        super::lifecycle::check_no_forks(sb, &all, &[&name])?;
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
        eprintln!("error: {}", sandbox::not_found(&name));
    }
    let vars = vars(&loaded, &name);
    if let Err(e) = host_phase(ctx, Phase::PreRemove, &lifecycle.pre_remove, &vars, skip) {
        crate::warning!("the preRemove commands did not finish: {e:#}");
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
    let loaded = load_files(ctx, &c.paths, &c.env_arg, &c.env_args_file)?;
    let secrets = SecretsFile::load(&ctx.paths)?;
    let spec = spec(&loaded, c.name.as_deref(), o, &secrets)?;
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
    if !ctx.can_prompt() {
        // The command as given, quoted for the shell, with `--force` added (sbx does the same).
        let words: Vec<String> = ctx.args.iter().map(|a| shell_word(a)).collect();
        let file = match loaded.files.as_slice() {
            [one] => one.display().to_string(),
            all => {
                let all: Vec<String> = all.iter().map(|f| f.display().to_string()).collect();
                format!("the merged environment ({})", all.join(", "))
            }
        };
        let retry = format!("\n  try: bento {} --force", words.join(" "));
        if plan.need == Need::HostCommands {
            bail!(
                "{file} declares commands that run on this machine, which must be approved on \
                 every invocation; approve the plan by running it in a terminal or with --force \
                 (-f), or remember approval until the plan changes with the setting below{retry}\n   \
                 or: bento settings set env.rememberHostCommands true"
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
            sandbox,
            ..Default::default()
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
            sandbox,
            ..Default::default()
        },
        Source::Ref { reference } => SecretSource {
            reference: Some(reference),
            sandbox,
            ..Default::default()
        },
        Source::Command { command } => SecretSource {
            command: Some(command),
            sandbox,
            ..Default::default()
        },
        Source::Keychain => unreachable!("built from a ref or command"),
    })
}

#[cfg(test)]
#[path = "env_tests.rs"]
mod tests;
