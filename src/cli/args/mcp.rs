//! `mcp`: registered MCP servers.

use clap::{Args, Subcommand};

use super::{OutputArgs, Passthrough};

/// `bento mcp`: MCP servers registered on the host, attached with `run|create --static-mcp`.
#[derive(Debug, Subcommand)]
pub enum McpCmd {
    /// Register an MCP server
    Add(Box<McpAddArgs>),
    /// List registered MCP servers
    #[command(visible_alias = "list")]
    Ls(McpLsArgs),
    /// Show a registered MCP server
    Inspect(McpInspectArgs),
    /// Remove a registered MCP server
    #[command(visible_aliases = ["remove", "delete"])]
    Rm {
        /// Server name
        name: String,
        /// Accepted as in sbx; smolbento never asks before removing a server
        #[arg(short = 'f', long)]
        force: bool,
    },
    /// Authorize OAuth servers (not supported: smolbento has no MCP gateway)
    Auth(Passthrough),
    /// Attach a server to a running sandbox (not supported: smolbento has no MCP gateway)
    Load(Passthrough),
    /// Detach a server from a running sandbox (not supported: smolbento has no MCP gateway)
    Unload(Passthrough),
}

#[derive(Debug, Args)]
pub struct McpAddArgs {
    #[arg(long = "disable-http2", hide = true)]
    pub disable_http2: bool,
    #[arg(long = "skip-ssrf-check", hide = true)]
    pub skip_ssrf_check: bool,
    #[arg(long = "callback-port", hide = true)]
    pub callback_port: Option<String>,
    #[arg(long, hide = true)]
    pub scope: Vec<String>,
    #[arg(long = "no-scope", hide = true)]
    pub no_scope: bool,
    /// Server name
    pub name: String,
    /// The server's URL
    #[arg(long)]
    pub url: Option<String>,
    /// A request header, `Name: value` (repeatable). `${name}` in the value is the secret
    /// `mcp:<server>:<name>`
    #[arg(long = "header", value_name = "NAME: VALUE")]
    pub header: Vec<String>,
    /// A command that runs the server inside the sandbox
    #[arg(long)]
    pub command: Option<String>,
    /// An argument of --command (repeatable)
    #[arg(long = "args", allow_hyphen_values = true)]
    pub args: Vec<String>,
    #[arg(long, hide = true)]
    pub local: bool,
    #[arg(long, hide = true)]
    pub dir: Option<String>,
    #[arg(long = "client-id", hide = true)]
    pub client_id: Option<String>,
    #[arg(long = "oauth-authorization-server", hide = true)]
    pub oauth_authorization_server: Option<String>,
    #[arg(long, hide = true)]
    pub resource: Option<String>,
    #[arg(long = "skip-auth", hide = true)]
    pub skip_auth: bool,
}

#[derive(Debug, Args)]
pub struct McpLsArgs {
    #[command(flatten)]
    pub output: OutputArgs,
    /// Only display server names
    #[arg(short = 'q', long)]
    pub quiet: bool,
}

#[derive(Debug, Args)]
pub struct McpInspectArgs {
    /// Server name
    pub name: String,
    #[command(flatten)]
    pub output: OutputArgs,
}
