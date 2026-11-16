//! `policy` and `approval`: network rules and pending requests.

use clap::{Args, Subcommand};

use super::{OutputArgs, Passthrough};

#[derive(Debug, Subcommand)]
pub enum PolicyCmd {
    /// Choose the network policy for all sandboxes
    Init {
        /// The policy to use
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
    #[command(visible_aliases = ["remove", "delete"])]
    Rm {
        #[command(subcommand)]
        kind: PolicyRmKind,
    },
    /// List rules
    #[command(visible_alias = "list")]
    Ls(PolicyLsArgs),
    /// Show one rule
    Inspect {
        /// Rule ID (as shown by `bento policy ls`)
        id: String,
        #[command(flatten)]
        output: OutputArgs,
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
        /// Don't ask for confirmation
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
    /// Hosts, wildcards, IPs or CIDRs, separated by commas
    #[command(
        after_help = "Examples:\n  bento policy allow network api.example.com,*.example.org\n  bento policy deny network tracking.example.com\n  bento policy allow network internal.example.com --sandbox claude-myrepo"
    )]
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
    #[arg(long, hide = true)]
    pub method: Option<String>,
    #[arg(long, hide = true)]
    pub path: Option<String>,
    #[arg(long, hide = true)]
    pub query: Option<String>,
    /// Rule id
    #[arg(long)]
    pub id: Option<String>,
    /// Remove this resource from every rule listing it
    #[arg(long)]
    pub resource: Option<String>,
    /// Only this sandbox's rules
    #[arg(long)]
    pub sandbox: Option<String>,
    /// Don't ask for confirmation
    #[arg(short = 'f', long)]
    pub force: bool,
}

#[derive(Debug, Default, Args)]
pub struct PolicyLsArgs {
    #[arg(long, hide = true)]
    pub profile: Option<String>,
    /// Only rules that apply to this sandbox
    pub sandbox: Option<String>,
    /// Show every resource and enforcement notes
    #[arg(long)]
    pub wide: bool,
    #[command(flatten)]
    pub output: OutputArgs,
    /// Only display rule IDs
    #[arg(short = 'q', long)]
    pub quiet: bool,
    /// Only rules from this source
    #[arg(long, value_name = "local|org|kit|mcp")]
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
    /// Only this sandbox's requests
    pub sandbox: Option<String>,
    /// Events read per sandbox
    #[arg(long, default_value_t = 50)]
    pub limit: usize,
    /// all, network or filesystem (only network has events)
    #[arg(long = "type")]
    pub kind: Option<String>,
    #[command(flatten)]
    pub output: OutputArgs,
}

#[derive(Debug, Subcommand)]
pub enum CheckKind {
    /// Check a network destination
    Network(CheckArgs),
}

#[derive(Debug, Args)]
pub struct CheckArgs {
    /// Host, host:port, IP or URL to check
    pub target: String,
    /// Check in this sandbox's context
    #[arg(long)]
    pub sandbox: Option<String>,
    /// Protocol (only tcp)
    #[arg(long)]
    pub protocol: Option<String>,
    /// Accepted as in sbx; the deciding rule is always printed
    #[arg(short = 'v', long)]
    pub verbose: bool,
    #[command(flatten)]
    pub output: OutputArgs,
}

#[derive(Debug, Subcommand)]
pub enum ApprovalCmd {
    /// Blocked hosts with no rule yet
    Ls {
        /// Only display approval IDs
        #[arg(short = 'q', long)]
        quiet: bool,
        #[command(flatten)]
        output: OutputArgs,
    },
    /// Show one blocked host
    Inspect { id: String },
    /// Allow or deny a blocked host
    Respond {
        /// The blocked host (as shown by `approval ls`)
        id: String,
        /// allow or deny
        decision: crate::policy::Decision,
        /// Only for this sandbox
        #[arg(long)]
        sandbox: Option<String>,
    },
}
