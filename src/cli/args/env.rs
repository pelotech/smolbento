//! `env`: environment files.

use std::path::PathBuf;

use clap::{Args, Subcommand};

#[derive(Debug, Subcommand)]
pub enum EnvCmd {
    /// Create a sandbox environment from sbxenv.yaml
    Create(EnvCreateArgs),
    /// Create (if needed) and attach to a sandbox environment
    Run(EnvRunArgs),
    /// Execute a command inside a sandbox environment
    Exec(EnvExecArgs),
    /// Remove a sandbox environment and its scoped resources
    Rm(EnvRmArgs),
    /// Show what applying an environment would change, without changing anything
    Plan(EnvPlanArgs),
}

/// What every `env` command takes.
#[derive(Debug, Clone, Default, Args)]
pub struct EnvCommon {
    /// sbxenv.yaml files, or directories holding one (default: the current directory)
    #[arg(value_name = "PATH")]
    pub paths: Vec<String>,
    /// Name for the sandbox, overriding 'name:' in sbxenv.yaml and the derived <agent>-<directory> (every 'bento env' command addressing this environment needs the same value)
    #[arg(long)]
    pub name: Option<String>,
    /// Value for an argument the environment file declares, as name=value (can be repeated)
    #[arg(long = "env-arg", value_name = "NAME=VALUE")]
    pub env_arg: Vec<String>,
    /// File of name=value environment arguments, one per line (can be repeated); --env-arg overrides
    #[arg(long = "env-args-file", value_name = "FILE")]
    pub env_args_file: Vec<PathBuf>,
}

/// Flags of `env create`, `env run` and `env plan` that override the file.
#[derive(Debug, Clone, Default, Args)]
pub struct EnvOverrideOpts {
    /// Override workspace.clone in sbxenv.yaml (see 'bento create --clone')
    #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    pub clone: Option<bool>,
    /// Value for an argument a kit declares, as name=value for every kit or kit.name=value for one (can be repeated); overrides the args a kits: entry pins in sbxenv.yaml
    #[arg(long = "kit-arg", value_name = "NAME=VALUE")]
    pub kit_arg: Vec<String>,
    /// File of name=value kit arguments, one per line (can be repeated); --kit-arg overrides
    #[arg(long = "kit-args-file", value_name = "FILE")]
    pub kit_args_file: Vec<PathBuf>,
    /// Skip the host lifecycle commands the environment declares
    #[arg(long = "skip-host-commands")]
    pub skip_host_commands: bool,
}

/// What `env create` and `env run` take besides `EnvCommon`.
#[derive(Debug, Clone, Default, Args)]
pub struct EnvApplyOpts {
    #[command(flatten)]
    pub overrides: EnvOverrideOpts,
    /// Apply the environment plan without asking
    #[arg(short = 'f', long)]
    pub force: bool,
    #[arg(long = "on-timeout", hide = true)]
    pub on_timeout: Option<String>,
    #[arg(long, hide = true)]
    pub ttl: Option<String>,
}

#[derive(Debug, Args)]
pub struct EnvCreateArgs {
    #[command(flatten)]
    pub common: EnvCommon,
    #[command(flatten)]
    pub apply: EnvApplyOpts,
}

/// `env plan`: what `env create` takes, without `--force`.
#[derive(Debug, Args)]
pub struct EnvPlanArgs {
    #[command(flatten)]
    pub common: EnvCommon,
    #[command(flatten)]
    pub overrides: EnvOverrideOpts,
}

#[derive(Debug, Args)]
pub struct EnvRunArgs {
    #[command(flatten)]
    pub common: EnvCommon,
    #[command(flatten)]
    pub apply: EnvApplyOpts,
    /// Create/start the sandbox without attaching
    #[arg(short = 'd', long)]
    pub detach: bool,
    /// Arguments after --: they replace the file's cmd when it sets entrypoint or cmd, else go to
    /// the agent
    #[arg(last = true, value_name = "ARG")]
    pub args: Vec<String>,
}

/// `env exec`: `exec`'s flags, the `EnvCommon` ones, then `[PATH...] -- CMD...`.
#[derive(Debug, Args)]
pub struct EnvExecArgs {
    #[command(flatten)]
    pub flags: super::ExecFlags,
    /// Name for the sandbox, overriding 'name:' in sbxenv.yaml and the derived <agent>-<directory> (every 'bento env' command addressing this environment needs the same value)
    #[arg(long)]
    pub name: Option<String>,
    /// Value for an argument the environment file declares, as name=value (can be repeated)
    #[arg(long = "env-arg", value_name = "NAME=VALUE")]
    pub env_arg: Vec<String>,
    /// File of name=value environment arguments, one per line (can be repeated); --env-arg overrides
    #[arg(long = "env-args-file", value_name = "FILE")]
    pub env_args_file: Vec<PathBuf>,
    /// sbxenv.yaml files or directories before `--`; without `--` every positional is the command
    #[arg(value_name = "PATH")]
    pub paths: Vec<String>,
    /// The command to run
    #[arg(last = true, value_name = "COMMAND")]
    pub command: Vec<String>,
}

#[derive(Debug, Args)]
pub struct EnvRmArgs {
    #[command(flatten)]
    pub common: EnvCommon,
    /// Skip confirmation prompts and delete even if in use (e.g. an open SSH connection)
    #[arg(short = 'f', long)]
    pub force: bool,
    /// Also remove the bindings this environment declares from the global ones (other sandboxes may use them)
    #[arg(long = "prune-bindings")]
    pub prune_bindings: bool,
    /// Skip the host lifecycle commands the environment declares
    #[arg(long = "skip-host-commands")]
    pub skip_host_commands: bool,
}
