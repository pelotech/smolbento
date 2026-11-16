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
    /// With --resource: only the rule with these HTTP methods
    #[arg(long)]
    pub method: Option<String>,
    /// With --resource: only the rule with this HTTP path
    #[arg(long)]
    pub path: Option<String>,
    /// With --resource: only the rule with this query (smolbento's rules have none)
    #[arg(long)]
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
    /// Summarise what applies to this sandbox
    pub sandbox: Option<String>,
    /// Show a row per rule, with every resource
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
    #[arg(long, value_name = "allow|deny", hide_possible_values = true)]
    pub decision: Option<crate::policy::Decision>,
    /// Only rules created this way
    #[arg(
        long = "created-via",
        value_name = "default|added|provisioned|approval"
    )]
    pub created_via: Option<String>,
    /// Only rules of this type
    #[arg(
        long = "type",
        value_name = "all|network|http|filesystem",
        default_value = "all"
    )]
    pub kind: Option<String>,
    /// Only rules for this protocol
    #[arg(long, value_name = "tcp|udp")]
    pub protocol: Option<String>,
    /// Accepted as in sbx; every smolbento rule is active
    #[arg(long = "include-inactive")]
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
    /// Protocol: tcp (the default) or udp
    #[arg(long)]
    pub protocol: Option<String>,
    /// Also print the action, the resource and the kind of denial
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
    Inspect {
        /// Approval ID (as shown by `approval ls`)
        id: String,
    },
    /// Answer a pending approval
    Respond {
        /// Approval ID (as shown by `approval ls`)
        id: String,
        /// allow or deny, in place of --option: adds the rule for every sandbox (smolbento only)
        #[arg(conflicts_with = "option")]
        decision: Option<crate::policy::Decision>,
        /// The option to answer with (as shown by `approval ls`)
        #[arg(long, value_name = "OPTION-ID")]
        option: Option<String>,
        /// Only for this sandbox
        #[arg(long)]
        sandbox: Option<String>,
    },
}
