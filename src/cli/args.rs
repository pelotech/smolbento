//! The sbx command line, flag for flag. Commands from later phases parse and report "not implemented yet".

use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, Parser, Subcommand, ValueEnum};

mod env;
mod kit;
mod mcp;
mod policy;
mod secret;
mod skills;
mod template;

pub use env::*;
pub use kit::*;
pub use mcp::*;
pub use policy::*;
pub use secret::*;
pub use skills::*;
pub use template::*;

use super::Unsupported;

#[derive(Debug, Parser)]
#[command(
    name = "bento",
    // As `sbx --version`: "bento version vX.Y.Z".
    version = concat!("version v", env!("CARGO_PKG_VERSION")),
    about = "Docker Sandboxes (sbx) compatible agent sandboxes on smolvm microVMs"
)]
pub struct Cli {
    /// Print each smolvm command line
    #[arg(short = 'D', long, global = true)]
    pub debug: bool,
    /// Docker Cloud sandboxes (not supported)
    #[arg(long, global = true, hide = true)]
    pub cloud: bool,
    /// Never prompt; commands that need an answer fail with the command to run instead
    #[arg(long = "no-input", global = true)]
    pub no_input: bool,
    #[command(subcommand)]
    pub command: Option<Cmd>,
}

#[derive(Debug, Subcommand)]
pub enum Cmd {
    /// Create a sandbox if needed and attach to its agent
    #[command(
        after_help = "Examples:\n  bento run claude\n  bento run claude ~/code/api\n  bento run codex . -- --model o3"
    )]
    Run(RunArgs),
    /// Create and start a sandbox
    Create(CreateArgs),
    /// Run a command in a sandbox
    #[command(
        after_help = "Examples:\n  bento exec claude-myrepo git status\n  bento exec -it claude-myrepo bash"
    )]
    Exec(ExecArgs),
    /// List sandboxes
    #[command(visible_alias = "list")]
    Ls(LsArgs),
    /// Show a sandbox's details
    Inspect(InspectArgs),
    /// Start stopped sandboxes
    Start {
        /// Sandboxes to start
        #[arg(required = true)]
        sandboxes: Vec<String>,
    },
    /// Stop sandboxes, keeping their state
    Stop {
        /// Sandboxes to stop
        #[arg(required = true)]
        sandboxes: Vec<String>,
        #[command(flatten)]
        output: OutputArgs,
    },
    /// Remove sandboxes
    #[command(visible_aliases = ["remove", "delete"])]
    Rm(RmArgs),
    /// Remove stopped sandboxes
    Prune(PruneArgs),
    /// Reset smolbento to a fresh install: removes every sandbox, settings, policy, templates,
    /// kits, skills and secrets
    Reset(ResetArgs),
    /// Copy files between the host and a sandbox
    #[command(
        after_help = "Examples:\n  bento cp ./notes.md claude-myrepo:/tmp/notes.md\n  bento cp claude-myrepo:/home/agent/.bash_history ./history"
    )]
    Cp(CpArgs),
    /// Copy a running sandbox (memory, processes, disk) for parallel attempts
    Fork(ForkArgs),
    /// Show smolbento and smolvm versions
    Version(OutputArgs),
    /// Generate shell completions
    Completion { shell: clap_complete::Shell },
    /// Check smolbento's environment
    Diagnose(DiagnoseArgs),
    /// Read and change settings
    #[command(subcommand)]
    Settings(SettingsCmd),
    /// Accepted for sbx compatibility; smolbento needs no daemon
    Daemon(Passthrough),
    /// Run smolbento's smolvm (the pinned release) on smolbento's sandboxes (smolbento only)
    #[command(after_help = "Examples:\n  bento smolvm --version\n  bento smolvm machine ls --json")]
    Smolvm(Passthrough),
    /// Publish or unpublish ports on a sandbox (127.0.0.1 only)
    Ports(PortsArgs),
    /// Network policy
    #[command(subcommand)]
    Policy(PolicyCmd),
    /// Secrets for agents: sandboxes see placeholders, smolvm sends the real value
    #[command(subcommand, visible_alias = "secrets")]
    Secret(SecretCmd),
    /// Inspect, validate and add kits
    #[command(subcommand)]
    Kit(KitCmd),
    /// Register MCP servers for sandboxes
    #[command(subcommand)]
    Mcp(McpCmd),
    /// Manage a sandbox declared in an sbxenv.yaml file
    #[command(subcommand)]
    Env(EnvCmd),
    /// Save sandboxes as templates and manage them
    #[command(subcommand)]
    Template(TemplateCmd),
    /// Manage skills shared with agents in sandboxes (experimental)
    #[command(subcommand)]
    Skills(SkillsCmd),
    /// Set up host integrations
    #[command(subcommand)]
    Setup(SetupCmd),
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
    /// Serves a sandbox's browser and clipboard bridge until killed, as an attached session does
    /// (for e2e tests, which can't attach)
    #[command(name = "_bridge", hide = true)]
    Bridge { sandbox: String },
    /// The SSH server `ssh NAME.sbx` talks to, run by the `ProxyCommand` that `setup ssh` writes
    #[command(subcommand, hide = true)]
    Ssh(SshCmd),
    /// Serves one connection to a sandbox's agent or bridge socket on stdin (run by the unit that
    /// owns the socket)
    #[command(name = "_serve", hide = true)]
    Serve { kind: String, sandbox: String },
}

impl Cmd {
    /// Commands that talk to smolvm (and so check its version first).
    pub fn needs_smolvm(&self) -> bool {
        matches!(
            self,
            Cmd::Run(_)
                | Cmd::Create(_)
                | Cmd::Exec(_)
                | Cmd::Ls(_)
                | Cmd::Inspect(_)
                | Cmd::Start { .. }
                | Cmd::Stop { .. }
                | Cmd::Rm(_)
                | Cmd::Prune(_)
                | Cmd::Reset(_)
                | Cmd::Cp(_)
                | Cmd::Fork(_)
                | Cmd::Ports(_)
                | Cmd::UploadPack { .. }
                | Cmd::Bridge { .. }
                | Cmd::Ssh(_)
                | Cmd::Smolvm(_)
                | Cmd::Template(TemplateCmd::Save(_))
                | Cmd::Env(EnvCmd::Create(_) | EnvCmd::Run(_) | EnvCmd::Exec(_) | EnvCmd::Rm(_))
        )
    }
}

#[derive(Debug, Subcommand)]
pub enum SshCmd {
    /// Serves SSH for the sandbox named by HOST (NAME.sbx) on stdin and stdout
    Proxy { host: String },
}

#[derive(Debug, Subcommand)]
pub enum SetupCmd {
    /// Let `ssh NAME.sbx` reach a sandbox (adds a managed block to ~/.ssh/config)
    Ssh(SetupSshArgs),
}

#[derive(Debug, Args)]
pub struct SetupSshArgs {
    /// Add connections for desktop apps (not supported)
    #[arg(long)]
    pub auto_create: bool,
    #[command(subcommand)]
    pub cmd: Option<SetupSshCmd>,
}

#[derive(Debug, Subcommand)]
pub enum SetupSshCmd {
    /// Remove the managed block from ~/.ssh/config
    #[command(visible_alias = "rm")]
    Remove,
}

#[derive(Debug, Args)]
pub struct PortsArgs {
    /// Sandbox name
    pub sandbox: String,
    /// [[127.0.0.1:]HOST:]PORT[/proto]; no host port picks a free one
    #[arg(short = 'p', long)]
    pub publish: Vec<String>,
    /// HOST:PORT[/proto]
    #[arg(long)]
    pub unpublish: Vec<String>,
    #[command(flatten)]
    pub output: OutputArgs,
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

/// Arguments taken unparsed: `smolvm`'s and `daemon`'s, and those of sbx commands that aren't
/// implemented, so their command lines still parse.
#[derive(Debug, Args)]
pub struct Passthrough {
    #[arg(trailing_var_arg = true, allow_hyphen_values = true, hide = true)]
    pub args: Vec<String>,
}

/// An environment file's `sandboxOptions.rootSize`, `dockerSize` and `clonedWorkspaceSize`, as
/// written (such as `30g`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DiskSizes {
    pub root: Option<String>,
    pub docker: Option<String>,
    pub cloned_workspace: Option<String>,
}

/// Options shared by `run` and `create`.
#[derive(Debug, Clone, Default, Args)]
pub struct SandboxOpts {
    #[arg(long, hide = true)]
    pub profile: Option<String>,
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
    /// Image pull policy: missing, or never with a saved template
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
    /// An environment file's `sandboxOptions.fuse: false`.
    #[arg(skip)]
    pub no_fuse: bool,
    /// An environment file's `sandboxOptions` disk sizes.
    #[arg(skip)]
    pub disk: DiskSizes,
    /// An environment's files in its mounted workspaces, kept read-only in the guest.
    #[arg(skip)]
    pub read_only_files: Vec<String>,
    /// Bind a host directory to a kit host-mount@1 path (can be repeated): HOST:SANDBOX_PATH. Can
    /// only be used when creating a new sandbox.
    #[arg(long, value_name = "HOST:SANDBOX_PATH")]
    pub mount: Vec<String>,
    /// Add a per-sandbox network deny rule at creation time. Can be specified multiple times.
    /// The rule applies only to the new sandbox and can be listed or removed later with
    /// 'bento policy ls <NAME>' or 'bento policy rm network --sandbox <NAME> --resource <HOST>'
    #[arg(long = "deny-network", value_name = "HOST", value_delimiter = ',')]
    pub deny_network: Vec<String>,
    /// Shared skills: off, readonly (store linked in read-only) or readwrite (store mounted over
    /// the agent's skills directory). Default: skills.defaultMode
    #[arg(long)]
    pub skills: Option<String>,
    /// Registered MCP servers for the agent, comma-separated (see `bento mcp`), or `none`
    #[arg(long = "static-mcp", value_name = "SERVERS")]
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
        super::refuse_as(
            &[
                (self.allow_network.is_some(), "--allow-network"),
                (self.image_ref.is_some(), "--image-ref"),
                (self.platform.is_some(), "--platform"),
                (self.ttl.is_some(), "--ttl"),
                (self.on_timeout.is_some(), "--on-timeout"),
                (!self.volume.is_empty(), "--volume"),
            ],
            "is a Docker Cloud option",
        )?;
        super::refuse(&[(self.profile.is_some(), "--profile")])?;
        if let Some(p) = self
            .pull
            .as_deref()
            .filter(|p| !matches!(*p, "missing" | "never"))
        {
            return Err(Unsupported(format!(
                "--pull {p} is not implemented yet; smolvm pulls missing images"
            ))
            .into());
        }
        Ok(())
    }
}

#[derive(Debug, Default, Args)]
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
    /// Suppress progress output
    #[arg(long = "no-progress")]
    pub no_progress: bool,
    /// Directory to start the agent session in: absolute, or relative to the sandbox workspace.
    /// Applies to this session only, so it works on a re-attach too
    #[arg(short = 'w', long)]
    pub workdir: Option<String>,
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
    /// What to launch in place of the agent's program (`env run`: the file's `entrypoint`).
    #[arg(skip)]
    pub entrypoint: Option<Vec<String>>,
}

#[derive(Debug, Args)]
pub struct CreateArgs {
    /// Agent or workload kit (registry reference or local path, e.g. ./kit), then workspace paths (none: a mountless sandbox)
    #[arg(required = true)]
    pub targets: Vec<String>,
    #[command(flatten)]
    pub opts: SandboxOpts,
    /// Suppress progress output
    #[arg(long = "no-progress")]
    pub no_progress: bool,
}

/// The flags `exec` and `env exec` share.
#[derive(Debug, Args)]
pub struct ExecFlags {
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
}

#[derive(Debug, Args)]
pub struct ExecArgs {
    #[command(flatten)]
    pub flags: ExecFlags,
    /// Sandbox name
    pub sandbox: String,
    /// Command and its arguments
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

impl Format {
    /// `value` as JSON or YAML; `None` for a table, which each command draws itself.
    pub fn structured<T: serde::Serialize>(self, value: &T) -> anyhow::Result<Option<String>> {
        Ok(match self {
            Format::Table => None,
            Format::Json => Some(format!("{}\n", serde_json::to_string_pretty(value)?)),
            Format::Yaml => Some(serde_saphyr::to_string(value)?),
        })
    }
}

/// `--format` and `--json`, as sbx has them on every command that prints something.
#[derive(Debug, Clone, Copy, Default, Args)]
pub struct OutputArgs {
    /// Output format: table, json or yaml
    #[arg(long, value_enum)]
    pub format: Option<Format>,
    /// Output in JSON format
    #[arg(long)]
    pub json: bool,
}

impl OutputArgs {
    /// `--json` wins over `--format`, which defaults to a table.
    pub fn pick(&self) -> Format {
        if self.json {
            Format::Json
        } else {
            self.format.unwrap_or_default()
        }
    }

    pub fn is_table(&self) -> bool {
        self.pick() == Format::Table
    }

    /// `value` as JSON or YAML, as asked; `None` when the command should print its table.
    pub fn structured<T: serde::Serialize>(&self, value: &T) -> anyhow::Result<Option<String>> {
        self.pick().structured(value)
    }
}

/// `diagnose --format`: the usual formats, and sbx's report to paste into a GitHub issue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum DiagnoseFormat {
    Table,
    Json,
    Yaml,
    GithubIssue,
}

impl DiagnoseFormat {
    /// The format every command has; `None` for the report only `diagnose` prints.
    pub fn shared(self) -> Option<Format> {
        match self {
            DiagnoseFormat::Table => Some(Format::Table),
            DiagnoseFormat::Json => Some(Format::Json),
            DiagnoseFormat::Yaml => Some(Format::Yaml),
            DiagnoseFormat::GithubIssue => None,
        }
    }
}

#[derive(Debug, Default, Args)]
pub struct DiagnoseArgs {
    /// Output format: table, json, yaml or github-issue
    #[arg(long, value_enum)]
    pub format: Option<DiagnoseFormat>,
    /// Output in JSON format
    #[arg(long)]
    pub json: bool,
    /// sbx sends the report to Docker support; smolbento has nowhere to send one
    #[arg(long, hide = true)]
    pub upload: bool,
}

#[derive(Debug, Default, Args)]
pub struct LsArgs {
    #[command(flatten)]
    pub output: OutputArgs,
    /// Only print names
    #[arg(short = 'q', long)]
    pub quiet: bool,
}

#[derive(Debug, Args)]
pub struct InspectArgs {
    /// Sandbox name
    pub sandbox: String,
    #[command(flatten)]
    pub output: OutputArgs,
}

#[derive(Debug, Args)]
pub struct RmArgs {
    /// Sandboxes to remove
    pub sandboxes: Vec<String>,
    /// Remove every sandbox
    #[arg(long)]
    pub all: bool,
    /// Don't ask for confirmation
    #[arg(short = 'f', long)]
    pub force: bool,
    #[command(flatten)]
    pub output: OutputArgs,
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
    #[command(flatten)]
    pub output: OutputArgs,
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
    /// Host path, or SANDBOX:/absolute/path
    pub src: String,
    /// Host path, or SANDBOX:/absolute/path (one side must be a sandbox)
    pub dst: String,
}

#[derive(Debug, Subcommand)]
pub enum SettingsCmd {
    /// List settings
    #[command(visible_alias = "list")]
    Ls {
        /// Show full descriptions
        #[arg(long = "no-trunc")]
        no_trunc: bool,
        /// Only print keys
        #[arg(short = 'q', long)]
        quiet: bool,
        #[command(flatten)]
        output: OutputArgs,
    },
    /// Print a setting's value
    Get {
        /// Setting key (see `bento settings ls`)
        key: String,
        #[command(flatten)]
        output: OutputArgs,
    },
    /// Change a setting
    Set { key: String, value: String },
    /// Reset a setting to its default
    Unset { key: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Cmd {
        Cli::try_parse_from(std::iter::once("sbt").chain(args.iter().copied()))
            .unwrap()
            .command
            .unwrap()
    }

    #[test]
    fn sbx_aliases_name_their_commands() {
        assert!(matches!(parse(&["list"]), Cmd::Ls(_)));
        for rm in ["remove", "delete"] {
            assert!(matches!(parse(&[rm, "a"]), Cmd::Rm(_)));
        }
        assert!(matches!(
            parse(&["secrets", "list"]),
            Cmd::Secret(SecretCmd::Ls(_))
        ));
        for rm in ["remove", "delete", "unset"] {
            assert!(matches!(
                parse(&["secret", rm, "github"]),
                Cmd::Secret(SecretCmd::Rm(_))
            ));
        }
        assert!(matches!(
            parse(&["settings", "list"]),
            Cmd::Settings(SettingsCmd::Ls { .. })
        ));
        assert!(matches!(
            parse(&["policy", "list"]),
            Cmd::Policy(PolicyCmd::Ls(_))
        ));
        for rm in ["remove", "delete"] {
            assert!(matches!(
                parse(&["policy", rm, "network", "--resource", "x.com"]),
                Cmd::Policy(PolicyCmd::Rm { .. })
            ));
            assert!(matches!(
                parse(&["mcp", rm, "linear"]),
                Cmd::Mcp(McpCmd::Rm { .. })
            ));
        }
        // sbx's short and no-op flags.
        parse(&["policy", "check", "network", "-v", "x.com"]);
        parse(&["policy", "approval", "ls", "-q"]);
        parse(&["mcp", "rm", "-f", "linear"]);
        parse(&["skills", "import", "-v"]);
    }
}
