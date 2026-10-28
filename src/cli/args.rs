//! The sbx command line, flag for flag. Commands from later phases parse and report "not implemented yet".

use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, Parser, Subcommand, ValueEnum};

use super::Unsupported;

#[derive(Debug, Parser)]
#[command(
    name = "sbt",
    version,
    about = "Docker Sandboxes (sbx) compatible agent sandboxes on smolvm microVMs"
)]
pub struct Cli {
    /// Print each smolvm command line
    #[arg(short = 'D', long, global = true)]
    pub debug: bool,
    /// Docker Cloud sandboxes (not supported)
    #[arg(long, global = true, hide = true)]
    pub cloud: bool,
    #[command(subcommand)]
    pub command: Option<Cmd>,
}

#[derive(Debug, Subcommand)]
pub enum Cmd {
    /// Create a sandbox if needed and attach to its agent
    Run(RunArgs),
    /// Create and start a sandbox
    Create(CreateArgs),
    /// Run a command in a sandbox
    Exec(ExecArgs),
    /// List sandboxes
    Ls(LsArgs),
    /// Start stopped sandboxes
    Start {
        #[arg(required = true)]
        sandboxes: Vec<String>,
    },
    /// Stop sandboxes, keeping their state
    Stop {
        #[arg(required = true)]
        sandboxes: Vec<String>,
    },
    /// Remove sandboxes
    Rm(RmArgs),
    /// Remove stopped sandboxes
    Prune(PruneArgs),
    /// Remove every sandbox and smolbento's session state
    Reset(ResetArgs),
    /// Copy files between the host and a sandbox
    Cp(CpArgs),
    /// Copy a running sandbox (memory, processes, disk) for parallel attempts
    Fork(ForkArgs),
    /// Show smolbento and smolvm versions
    Version,
    /// Generate shell completions
    Completion { shell: clap_complete::Shell },
    /// Check smolbento's environment
    Diagnose,
    /// Read and change settings
    #[command(subcommand)]
    Settings(SettingsCmd),
    /// Accepted for sbx compatibility; smolbento needs no daemon
    Daemon(Passthrough),
    /// Publish or unpublish ports on a sandbox (127.0.0.1 only)
    Ports(PortsArgs),
    /// Network policy
    #[command(subcommand)]
    Policy(PolicyCmd),
    /// Secrets for agents: sandboxes see placeholders, smolvm sends the real value
    #[command(subcommand)]
    Secret(SecretCmd),
    /// Inspect, validate and add kits
    #[command(subcommand)]
    Kit(KitCmd),
    /// MCP servers (not implemented yet)
    Mcp(Passthrough),
    /// Manage a sandbox declared in an sbxenv.yaml file
    #[command(subcommand)]
    Env(EnvCmd),
    /// Sandbox templates (not implemented yet)
    Template(Passthrough),
    /// Agent skills (not implemented yet)
    Skills(Passthrough),
    /// SSH access (not implemented yet)
    Setup(Passthrough),
    /// Dashboard (not implemented yet)
    Tui(Passthrough),
    #[command(hide = true)]
    Login(Passthrough),
    #[command(hide = true)]
    Logout(Passthrough),
    #[command(hide = true)]
    Move(Passthrough),
    #[command(hide = true)]
    Ttl(Passthrough),
    #[command(hide = true)]
    Attach(Passthrough),
    #[command(hide = true)]
    Volume(Passthrough),
    /// git runs this for a clone sandbox's remote (`uploadpack`); stdout is git's stream
    #[command(name = "_upload-pack", hide = true)]
    UploadPack {
        sandbox: String,
        /// The remote's placeholder path, which git appends; ignored
        #[arg(hide = true)]
        path: Option<String>,
    },
}

impl Cmd {
    pub fn name(&self) -> &'static str {
        match self {
            Cmd::Run(_) => "run",
            Cmd::Create(_) => "create",
            Cmd::Exec(_) => "exec",
            Cmd::Ls(_) => "ls",
            Cmd::Start { .. } => "start",
            Cmd::Stop { .. } => "stop",
            Cmd::Rm(_) => "rm",
            Cmd::Prune(_) => "prune",
            Cmd::Reset(_) => "reset",
            Cmd::Cp(_) => "cp",
            Cmd::Fork(_) => "fork",
            Cmd::Version => "version",
            Cmd::Completion { .. } => "completion",
            Cmd::Diagnose => "diagnose",
            Cmd::Settings(_) => "settings",
            Cmd::Daemon(_) => "daemon",
            Cmd::Ports(_) => "ports",
            Cmd::Policy(_) => "policy",
            Cmd::Secret(_) => "secret",
            Cmd::Kit(_) => "kit",
            Cmd::Mcp(_) => "mcp",
            Cmd::Env(_) => "env",
            Cmd::Template(_) => "template",
            Cmd::Skills(_) => "skills",
            Cmd::Setup(_) => "setup",
            Cmd::Tui(_) => "tui",
            Cmd::Login(_) => "login",
            Cmd::Logout(_) => "logout",
            Cmd::Move(_) => "move",
            Cmd::Ttl(_) => "ttl",
            Cmd::Attach(_) => "attach",
            Cmd::Volume(_) => "volume",
            Cmd::UploadPack { .. } => "_upload-pack",
        }
    }

    /// Commands that talk to smolvm (and so check its version first).
    pub fn needs_smolvm(&self) -> bool {
        matches!(
            self,
            Cmd::Run(_)
                | Cmd::Create(_)
                | Cmd::Exec(_)
                | Cmd::Ls(_)
                | Cmd::Start { .. }
                | Cmd::Stop { .. }
                | Cmd::Rm(_)
                | Cmd::Prune(_)
                | Cmd::Reset(_)
                | Cmd::Cp(_)
                | Cmd::Fork(_)
                | Cmd::Ports(_)
                | Cmd::UploadPack { .. }
                | Cmd::Env(EnvCmd::Create(_) | EnvCmd::Run(_) | EnvCmd::Exec(_) | EnvCmd::Rm(_))
        )
    }

    pub fn is_cloud_only(&self) -> bool {
        matches!(
            self,
            Cmd::Login(_)
                | Cmd::Logout(_)
                | Cmd::Move(_)
                | Cmd::Ttl(_)
                | Cmd::Attach(_)
                | Cmd::Volume(_)
        )
    }
}

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
    /// Show what an environment would change outside the sandbox (not implemented yet)
    Plan(Passthrough),
}

/// What every `env` command takes.
#[derive(Debug, Clone, Default, Args)]
pub struct EnvCommon {
    /// sbxenv.yaml files, or directories holding one (default: the current directory)
    #[arg(value_name = "PATH")]
    pub paths: Vec<String>,
    /// Name for the sandbox, overriding 'name:' in sbxenv.yaml and the derived <agent>-<directory> (every 'sbt env' command addressing this environment needs the same value)
    #[arg(long)]
    pub name: Option<String>,
    /// Value for an argument the environment file declares, as name=value (can be repeated)
    #[arg(long = "env-arg", value_name = "NAME=VALUE")]
    pub env_arg: Vec<String>,
    /// File of name=value environment arguments, one per line (can be repeated); --env-arg overrides
    #[arg(long = "env-args-file", value_name = "FILE")]
    pub env_args_file: Vec<PathBuf>,
}

/// What `env create` and `env run` take besides `EnvCommon`.
#[derive(Debug, Clone, Default, Args)]
pub struct EnvApplyOpts {
    /// Override workspace.clone in sbxenv.yaml (see 'sbt create --clone')
    #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    pub clone: Option<bool>,
    /// Apply the environment plan without asking
    #[arg(short = 'f', long)]
    pub force: bool,
    /// Value for an argument a kit declares, as name=value for every kit or kit.name=value for one (can be repeated); overrides the args a kits: entry pins in sbxenv.yaml
    #[arg(long = "kit-arg", value_name = "NAME=VALUE")]
    pub kit_arg: Vec<String>,
    /// File of name=value kit arguments, one per line (can be repeated); --kit-arg overrides
    #[arg(long = "kit-args-file", value_name = "FILE")]
    pub kit_args_file: Vec<PathBuf>,
    /// Skip the host lifecycle commands the environment declares (smolbento runs none)
    #[arg(long = "skip-host-commands")]
    pub skip_host_commands: bool,
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

#[derive(Debug, Args)]
pub struct EnvRunArgs {
    #[command(flatten)]
    pub common: EnvCommon,
    #[command(flatten)]
    pub apply: EnvApplyOpts,
    /// Create/start the sandbox without attaching
    #[arg(short = 'd', long)]
    pub detach: bool,
}

/// `env exec`: `ExecArgs`' flags, the `EnvCommon` ones, then `[PATH...] -- CMD...`.
#[derive(Debug, Args)]
pub struct EnvExecArgs {
    /// Keep stdin open
    #[arg(short = 'i', long)]
    pub interactive: bool,
    /// Allocate a terminal
    #[arg(short = 't', long)]
    pub tty: bool,
    /// Environment variable: KEY=VALUE, or KEY to copy the host's value
    #[arg(short = 'e', long = "env")]
    pub env: Vec<String>,
    /// Read environment variables from a file
    #[arg(long = "env-file")]
    pub env_file: Vec<PathBuf>,
    /// User to run as (default: agent)
    #[arg(short = 'u', long)]
    pub user: Option<String>,
    /// Working directory (default: the primary workspace)
    #[arg(short = 'w', long)]
    pub workdir: Option<String>,
    /// Run as root
    #[arg(long)]
    pub privileged: bool,
    /// Not supported (as in sbx)
    #[arg(short = 'd', long)]
    pub detach: bool,
    #[arg(long = "detach-keys", hide = true)]
    pub detach_keys: Option<String>,
    /// Name for the sandbox, overriding 'name:' in sbxenv.yaml and the derived <agent>-<directory> (every 'sbt env' command addressing this environment needs the same value)
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
    /// Also remove this environment's bindings from the global credentials.yaml (smolbento keeps none)
    #[arg(long = "prune-bindings")]
    pub prune_bindings: bool,
    /// Skip the host lifecycle commands the environment declares (smolbento runs none)
    #[arg(long = "skip-host-commands")]
    pub skip_host_commands: bool,
}

#[derive(Debug, Args)]
pub struct PortsArgs {
    pub sandbox: String,
    /// [[127.0.0.1:]HOST:]PORT[/proto]; no host port picks a free one
    #[arg(long)]
    pub publish: Vec<String>,
    /// HOST:PORT[/proto]
    #[arg(long)]
    pub unpublish: Vec<String>,
}

#[derive(Debug, Args)]
pub struct ForkArgs {
    /// Sandbox to copy
    pub sandbox: String,
    /// Name of the copy (default: <sandbox>-fork-<n>)
    #[arg(long)]
    pub name: Option<String>,
    /// Number of copies
    #[arg(long, default_value_t = 1, conflicts_with = "name",
          value_parser = clap::value_parser!(u32).range(1..))]
    pub count: u32,
}

/// `kit inspect --format`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum KitFormat {
    Table,
    Json,
    Yaml,
}

#[derive(Debug, Subcommand)]
pub enum KitCmd {
    /// Show what a kit provides and requests
    Inspect {
        /// Kit: a registry reference or a local path (./dir, descriptor or Smolfile)
        reference: String,
        #[command(flatten)]
        args: KitArgOpts,
        /// Output format
        #[arg(long, value_enum)]
        format: Option<KitFormat>,
        /// Output in JSON format
        #[arg(long)]
        json: bool,
        /// Skip the source policy check; local kits only, no network
        #[arg(long)]
        offline: bool,
    },
    /// Check a kit without running it
    Validate {
        /// Kit: a registry reference or a local path (./dir, descriptor or Smolfile)
        reference: String,
        #[command(flatten)]
        args: KitArgOpts,
        /// Output format
        #[arg(long, value_enum)]
        format: Option<KitFormat>,
        /// Output in JSON format
        #[arg(long)]
        json: bool,
        /// Skip the source policy check; local kits only, no network
        #[arg(long)]
        offline: bool,
    },
    /// Add a mixin kit to an existing sandbox
    Add {
        /// Sandbox name
        sandbox: String,
        /// Mixin kit: a registry reference or a local path (./dir or descriptor)
        reference: String,
        #[command(flatten)]
        args: KitArgOpts,
        /// Grant the kit's network access without asking
        #[arg(long, short = 'y')]
        yes: bool,
    },
    #[command(hide = true)]
    Pack(Passthrough),
    #[command(hide = true)]
    Push(Passthrough),
    #[command(hide = true)]
    Pull(Passthrough),
    #[command(hide = true)]
    Sign(Passthrough),
    #[command(hide = true)]
    Verify(Passthrough),
}

/// Kit argument flags, as on `run` and `create`.
#[derive(Debug, Clone, Default, Args)]
pub struct KitArgOpts {
    /// Kit argument: NAME=VALUE, or KIT.NAME=VALUE for one kit (repeatable)
    #[arg(long = "kit-arg", value_name = "NAME=VALUE")]
    pub kit_arg: Vec<String>,
    /// Read kit arguments (NAME=VALUE lines) from a file (repeatable)
    #[arg(long = "kit-args-file", value_name = "FILE")]
    pub kit_args_file: Vec<PathBuf>,
}

/// Arguments of a command that isn't implemented yet, kept so sbx command lines still parse.
#[derive(Debug, Args)]
pub struct Passthrough {
    #[arg(trailing_var_arg = true, allow_hyphen_values = true, hide = true)]
    pub args: Vec<String>,
}

/// Options shared by `run` and `create`.
#[derive(Debug, Clone, Default, Args)]
pub struct SandboxOpts {
    /// Sandbox name (default: <agent>-<workspace basename>)
    #[arg(long)]
    pub name: Option<String>,
    /// Number of CPUs (0 = all host CPUs)
    #[arg(long)]
    pub cpus: Option<u32>,
    /// Memory, e.g. 4g (default: half of host memory, 512MiB to 32GiB)
    #[arg(short = 'm', long)]
    pub memory: Option<String>,
    /// Environment variable: KEY=VALUE, or KEY to copy the host's value
    #[arg(short = 'e', long = "env")]
    pub env: Vec<String>,
    /// Read environment variables from a file
    #[arg(long = "env-file")]
    pub env_file: Vec<PathBuf>,
    /// Publish a port: [[IP:]HOST:]PORT[/proto]
    #[arg(short = 'p', long = "publish")]
    pub publish: Vec<String>,
    /// Image to use instead of the agent's template
    #[arg(short = 't', long)]
    pub template: Option<String>,
    /// Image pull policy (only `missing` is supported)
    #[arg(long)]
    pub pull: Option<String>,
    /// Work on a private clone of the git repo; its commits come back via the sandbox-<name> git remote
    #[arg(long)]
    pub clone: bool,
    /// Add a kit: registry reference or local path, e.g. ./kit (repeatable)
    #[arg(long, value_name = "REF")]
    pub kit: Vec<String>,
    /// Kit argument: NAME=VALUE, or KIT.NAME=VALUE for one kit (repeatable)
    #[arg(long = "kit-arg", value_name = "NAME=VALUE")]
    pub kit_arg: Vec<String>,
    /// Read kit arguments (NAME=VALUE lines) from a file (repeatable)
    #[arg(long = "kit-args-file", value_name = "FILE")]
    pub kit_args_file: Vec<PathBuf>,
    /// Kit args an sbxenv.yaml pins: (kit source as given to `--kit`, `NAME=VALUE`s). Beneath
    /// `--kit-arg` and `--kit-args-file`.
    #[arg(skip)]
    pub kit_pins: Vec<(String, Vec<String>)>,
    /// Add a per-sandbox network deny rule at creation time. Can be specified multiple times.
    /// The rule applies only to the new sandbox and can be listed or removed later with
    /// 'sbt policy ls <NAME>' or 'sbt policy rm network --sandbox <NAME> --resource <HOST>'
    #[arg(long = "deny-network", value_name = "HOST", value_delimiter = ',')]
    pub deny_network: Vec<String>,
    /// Agent skills: off, readonly or readwrite (not implemented yet)
    #[arg(long)]
    pub skills: Option<String>,
    /// Static MCP servers (not implemented yet)
    #[arg(long = "static-mcp")]
    pub static_mcp: Option<String>,
    #[arg(long = "allow-network", hide = true)]
    pub allow_network: Option<String>,
    #[arg(long = "image-ref", hide = true)]
    pub image_ref: Option<String>,
    #[arg(long, hide = true)]
    pub platform: Option<String>,
    #[arg(long, hide = true)]
    pub ttl: Option<String>,
    #[arg(long = "on-timeout", hide = true)]
    pub on_timeout: Option<String>,
    #[arg(short = 'v', long = "volume", hide = true)]
    pub volume: Vec<String>,
}

impl SandboxOpts {
    /// Rejects flags from later phases and Docker Cloud-only flags.
    pub fn check_supported(&self) -> Result<()> {
        let pending = [
            (self.skills.is_some(), "--skills"),
            (self.static_mcp.is_some(), "--static-mcp"),
        ];
        if let Some((_, flag)) = pending.iter().find(|(set, _)| *set) {
            return Err(Unsupported(format!("{flag} is not implemented yet")).into());
        }
        let cloud = [
            (self.allow_network.is_some(), "--allow-network"),
            (self.image_ref.is_some(), "--image-ref"),
            (self.platform.is_some(), "--platform"),
            (self.ttl.is_some(), "--ttl"),
            (self.on_timeout.is_some(), "--on-timeout"),
            (!self.volume.is_empty(), "--volume"),
        ];
        if let Some((_, flag)) = cloud.iter().find(|(set, _)| *set) {
            return Err(Unsupported(format!("{flag} is a Docker Cloud option")).into());
        }
        if let Some(p) = self.pull.as_deref().filter(|p| *p != "missing") {
            return Err(Unsupported(format!(
                "--pull {p} is not implemented yet; smolvm pulls missing images"
            ))
            .into());
        }
        Ok(())
    }
}

#[derive(Debug, Args)]
pub struct RunArgs {
    /// Agent or workload kit (registry reference or local path, e.g. ./kit), then workspace paths (default: the current directory)
    pub targets: Vec<String>,
    #[command(flatten)]
    pub opts: SandboxOpts,
    /// Start the sandbox and leave it running
    #[arg(short = 'd', long)]
    pub detach: bool,
    /// Remove the sandbox when the agent exits
    #[arg(long)]
    pub rm: bool,
    #[arg(long, hide = true)]
    pub new: bool,
    #[arg(long = "detach-keys", hide = true)]
    pub detach_keys: Option<String>,
    /// Arguments for the agent
    #[arg(last = true)]
    pub agent_args: Vec<String>,
    /// Extra env for the agent's session (`env run` of an existing sandbox: the file's env).
    #[arg(skip)]
    pub session_env: Vec<(String, String)>,
}

#[derive(Debug, Args)]
pub struct CreateArgs {
    /// Agent or workload kit (registry reference or local path, e.g. ./kit), then workspace paths (none: a mountless sandbox)
    #[arg(required = true)]
    pub targets: Vec<String>,
    #[command(flatten)]
    pub opts: SandboxOpts,
    /// Accepted for sbx compatibility
    #[arg(long = "no-progress")]
    pub no_progress: bool,
}

#[derive(Debug, Args)]
pub struct ExecArgs {
    /// Keep stdin open
    #[arg(short = 'i', long)]
    pub interactive: bool,
    /// Allocate a terminal
    #[arg(short = 't', long)]
    pub tty: bool,
    /// Environment variable: KEY=VALUE, or KEY to copy the host's value
    #[arg(short = 'e', long = "env")]
    pub env: Vec<String>,
    /// Read environment variables from a file
    #[arg(long = "env-file")]
    pub env_file: Vec<PathBuf>,
    /// User to run as (default: agent)
    #[arg(short = 'u', long)]
    pub user: Option<String>,
    /// Working directory (default: the primary workspace)
    #[arg(short = 'w', long)]
    pub workdir: Option<String>,
    /// Run as root
    #[arg(long)]
    pub privileged: bool,
    /// Not supported (as in sbx)
    #[arg(short = 'd', long)]
    pub detach: bool,
    #[arg(long = "detach-keys", hide = true)]
    pub detach_keys: Option<String>,
    pub sandbox: String,
    #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
    pub command: Vec<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, ValueEnum)]
pub enum Format {
    #[default]
    Table,
    Json,
    Yaml,
}

#[derive(Debug, Default, Args)]
pub struct LsArgs {
    /// Output format
    #[arg(long, value_enum)]
    pub format: Option<Format>,
    /// Same as --format json
    #[arg(long)]
    pub json: bool,
    /// Only print names
    #[arg(short = 'q', long)]
    pub quiet: bool,
}

#[derive(Debug, Args)]
pub struct RmArgs {
    pub sandboxes: Vec<String>,
    /// Remove every sandbox
    #[arg(long)]
    pub all: bool,
    /// Don't ask for confirmation
    #[arg(short = 'f', long)]
    pub force: bool,
}

#[derive(Debug, Args)]
pub struct PruneArgs {
    /// Show what would be removed
    #[arg(long = "dry-run")]
    pub dry_run: bool,
    /// Filter: until=<timestamp|duration>
    #[arg(long)]
    pub filter: Vec<String>,
    /// Don't ask for confirmation
    #[arg(short = 'f', long)]
    pub force: bool,
}

#[derive(Debug, Args)]
pub struct ResetArgs {
    /// Don't ask for confirmation
    #[arg(short = 'f', long)]
    pub force: bool,
    /// Keep stored secrets
    #[arg(long = "preserve-secrets")]
    pub preserve_secrets: bool,
}

#[derive(Debug, Args)]
pub struct CpArgs {
    /// Follow symbolic links in the host source
    #[arg(short = 'L', long = "follow-link")]
    pub follow_link: bool,
    pub src: String,
    pub dst: String,
}

#[derive(Debug, Subcommand)]
pub enum SettingsCmd {
    /// List settings
    Ls {
        #[arg(long = "no-trunc")]
        no_trunc: bool,
    },
    /// Print a setting's value
    Get { key: String },
    /// Change a setting
    Set { key: String, value: String },
    /// Reset a setting to its default
    Unset { key: String },
}

#[derive(Debug, Subcommand)]
pub enum PolicyCmd {
    /// Choose the network policy for all sandboxes
    Init {
        mode: crate::policy::Mode,
        #[arg(long, hide = true)]
        sandbox: Option<String>,
    },
    /// Allow network access
    Allow {
        #[command(subcommand)]
        kind: RuleKind,
    },
    /// Deny network access
    Deny {
        #[command(subcommand)]
        kind: RuleKind,
    },
    /// Remove rules
    Rm {
        #[command(subcommand)]
        kind: PolicyRmKind,
    },
    /// List rules
    Ls(PolicyLsArgs),
    /// Show one rule
    Inspect {
        id: String,
        #[arg(long)]
        json: bool,
    },
    /// Show requests the policy blocked
    Log(PolicyLogArgs),
    /// Test whether a host is allowed
    Check {
        #[command(subcommand)]
        kind: CheckKind,
    },
    /// Remove every rule and the chosen mode
    Reset {
        #[arg(short = 'f', long)]
        force: bool,
    },
    /// Blocked hosts waiting for a decision
    #[command(subcommand)]
    Approval(ApprovalCmd),
    #[command(hide = true)]
    Refresh(Passthrough),
}

#[derive(Debug, Subcommand)]
pub enum RuleKind {
    /// Network rule
    Network(RuleArgs),
}

#[derive(Debug, Args)]
pub struct RuleArgs {
    /// Comma-separated hosts, wildcards (*.x, **.x), IPs or CIDRs
    pub resources: String,
    /// Apply to one sandbox only
    #[arg(long)]
    pub sandbox: Option<String>,
    /// Only tcp is supported
    #[arg(long)]
    pub protocol: Option<String>,
    /// HTTP methods (stored, not enforced)
    #[arg(long)]
    pub method: Option<String>,
    /// HTTP path (stored, not enforced)
    #[arg(long)]
    pub path: Option<String>,
}

#[derive(Debug, Subcommand)]
pub enum PolicyRmKind {
    /// Remove network rules
    Network(PolicyRmArgs),
}

#[derive(Debug, Args)]
pub struct PolicyRmArgs {
    /// Rule id
    #[arg(long)]
    pub id: Option<String>,
    /// Remove this resource from every rule listing it
    #[arg(long)]
    pub resource: Option<String>,
    #[arg(long)]
    pub sandbox: Option<String>,
    #[arg(short = 'f', long)]
    pub force: bool,
}

#[derive(Debug, Default, Args)]
pub struct PolicyLsArgs {
    /// Only rules that apply to this sandbox
    pub sandbox: Option<String>,
    /// Show every resource and enforcement notes
    #[arg(long)]
    pub wide: bool,
    #[arg(long, value_enum)]
    pub format: Option<Format>,
    #[arg(long)]
    pub json: bool,
    #[arg(short = 'q', long)]
    pub quiet: bool,
    /// Only rules from this source
    #[arg(long, value_name = "local|org|kit")]
    pub source: Option<String>,
    /// Only allow or only deny rules
    #[arg(long, value_name = "allow|deny")]
    pub decision: Option<String>,
    #[arg(long = "created-via", hide = true)]
    pub created_via: Option<String>,
    #[arg(long = "type", hide = true)]
    pub kind: Option<String>,
    #[arg(long, hide = true)]
    pub protocol: Option<String>,
    #[arg(long = "include-inactive", hide = true)]
    pub include_inactive: bool,
}

#[derive(Debug, Args)]
pub struct PolicyLogArgs {
    pub sandbox: Option<String>,
    /// Events read per sandbox
    #[arg(long, default_value_t = 50)]
    pub limit: usize,
    /// all, network or filesystem (only network has events)
    #[arg(long = "type")]
    pub kind: Option<String>,
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Subcommand)]
pub enum CheckKind {
    /// Check a network destination
    Network(CheckArgs),
}

#[derive(Debug, Args)]
pub struct CheckArgs {
    pub target: String,
    #[arg(long)]
    pub sandbox: Option<String>,
    #[arg(long)]
    pub protocol: Option<String>,
    #[arg(long)]
    pub verbose: bool,
}

#[derive(Debug, Subcommand)]
pub enum ApprovalCmd {
    /// Blocked hosts with no rule yet
    Ls {
        #[arg(long)]
        json: bool,
    },
    /// Show one blocked host
    Inspect { id: String },
    /// Allow or deny a blocked host
    Respond {
        /// The blocked host (as shown by `approval ls`)
        id: String,
        decision: crate::policy::Decision,
        #[arg(long)]
        sandbox: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
pub enum SecretCmd {
    /// Set a secret for a built-in service (anthropic, claude, github, openai, …)
    Set(SecretSetArgs),
    /// Set a secret for any host and environment variable
    SetCustom(SecretCustomArgs),
    /// List secrets (never values)
    Ls(SecretLsArgs),
    /// Remove secrets
    Rm(SecretRmArgs),
    #[command(hide = true)]
    Import(Passthrough),
}

#[derive(Debug, Args)]
pub struct SecretSource {
    /// The value (prefer the prompt: values on the command line reach shell history)
    #[arg(short = 't', long = "token", alias = "value")]
    pub token: Option<String>,
    /// op://vault/item/field (1Password) or an AWS Secrets Manager ARN, read at each start
    #[arg(long = "ref")]
    pub reference: Option<String>,
    /// Host command whose output is the value, run at each start
    #[arg(long)]
    pub command: Option<String>,
    /// Only for this sandbox
    #[arg(long)]
    pub sandbox: Option<String>,
}

#[derive(Debug, Args)]
pub struct SecretSetArgs {
    pub service: Option<String>,
    #[command(flatten)]
    pub source: SecretSource,
    #[arg(short = 'f', long)]
    pub force: bool,
    #[arg(long, hide = true)]
    pub oauth: bool,
    /// Store a pull credential for this container registry (host only)
    #[arg(long, value_name = "HOST")]
    pub registry: Option<String>,
    /// Registry username (omit for a token-only login)
    #[arg(long)]
    pub username: Option<String>,
    /// Read the registry password or token from standard input
    #[arg(long = "password-stdin")]
    pub password_stdin: bool,
    /// Trust this exact HTTPS URL as the registry's Bearer authentication endpoint
    #[arg(long = "registry-auth-endpoint", value_name = "URL")]
    pub registry_auth_endpoint: Option<String>,
    #[arg(long, hide = true)]
    pub refresh: Option<String>,
    #[arg(long = "all-sandboxes", hide = true)]
    pub all_sandboxes: bool,
    #[arg(long = "no-verify", hide = true)]
    pub no_verify: bool,
    #[arg(long = "show-error", hide = true)]
    pub show_error: bool,
}

#[derive(Debug, Args)]
pub struct SecretCustomArgs {
    /// Hosts the secret is sent to (repeatable)
    #[arg(long = "host", required = true)]
    pub hosts: Vec<String>,
    /// Environment variable that holds the placeholder
    #[arg(long, required = true)]
    pub env: String,
    #[command(flatten)]
    pub source: SecretSource,
    #[arg(long, hide = true)]
    pub placeholder: Option<String>,
}

#[derive(Debug, Args)]
pub struct SecretLsArgs {
    /// Only global secrets
    #[arg(short = 'g', long)]
    pub global: bool,
    #[arg(long)]
    pub sandbox: Option<String>,
    #[arg(long)]
    pub service: Option<String>,
    #[arg(short = 'q', long)]
    pub quiet: bool,
}

#[derive(Debug, Args)]
pub struct SecretRmArgs {
    pub service: Option<String>,
    #[arg(long)]
    pub sandbox: Option<String>,
    /// Remove every secret
    #[arg(long)]
    pub all: bool,
    #[arg(short = 'f', long)]
    pub force: bool,
    /// Remove the pull credential for this container registry
    #[arg(long, value_name = "HOST")]
    pub registry: Option<String>,
    #[arg(long = "all-sandboxes", hide = true)]
    pub all_sandboxes: bool,
}
