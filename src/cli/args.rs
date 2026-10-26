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
    /// Publish or unpublish ports (not implemented yet)
    Ports(Passthrough),
    /// Network policy (not implemented yet)
    Policy(Passthrough),
    /// Secrets (not implemented yet)
    Secret(Passthrough),
    /// Kits (not implemented yet)
    Kit(Passthrough),
    /// MCP servers (not implemented yet)
    Mcp(Passthrough),
    /// sbxenv.yaml environments (not implemented yet)
    Env(Passthrough),
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
    /// Work on a private clone of the git repo (not implemented yet)
    #[arg(long)]
    pub clone: bool,
    /// Add a kit (not implemented yet)
    #[arg(long)]
    pub kit: Vec<String>,
    #[arg(long = "kit-arg", hide = true)]
    pub kit_arg: Vec<String>,
    #[arg(long = "kit-args-file", hide = true)]
    pub kit_args_file: Vec<PathBuf>,
    /// Deny all network access for this sandbox (bound secrets' hosts stay reachable)
    #[arg(long = "deny-network")]
    pub deny_network: bool,
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
            (self.clone, "--clone"),
            (
                !self.kit.is_empty() || !self.kit_arg.is_empty() || !self.kit_args_file.is_empty(),
                "--kit",
            ),
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
    /// Agent, then workspace paths (default: the current directory)
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
}

#[derive(Debug, Args)]
pub struct CreateArgs {
    /// Agent, then workspace paths (none: a mountless sandbox)
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
