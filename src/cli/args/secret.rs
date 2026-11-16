//! `secret`: stored secrets and registry logins.

use clap::{Args, Subcommand};

use super::{OutputArgs, Passthrough};

#[derive(Debug, Subcommand)]
pub enum SecretCmd {
    /// Set a secret for a built-in service (anthropic, claude, github, openai, …)
    #[command(
        after_help = "Examples:\n  bento secret set anthropic\n  bento secret set github --command 'gh auth token'\n  bento secret set openai --sandbox claude-myrepo"
    )]
    Set(SecretSetArgs),
    /// Set a secret for any host and environment variable
    SetCustom(SecretCustomArgs),
    /// List secrets (never values)
    #[command(visible_alias = "list")]
    Ls(SecretLsArgs),
    /// Remove secrets
    #[command(visible_aliases = ["remove", "delete", "unset"])]
    Rm(SecretRmArgs),
    #[command(hide = true)]
    Import(Passthrough),
}

#[derive(Debug, Default, Args)]
pub struct SecretSource {
    /// The value (prefer the prompt: values on the command line reach shell history)
    #[arg(short = 't', long = "token", alias = "value")]
    pub token: Option<String>,
    /// Read the value from stdin (one trailing newline is dropped)
    #[arg(long = "value-stdin")]
    pub value_stdin: bool,
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
    /// Service name, such as anthropic, github or openai
    pub service: Option<String>,
    #[command(flatten)]
    pub source: SecretSource,
    /// Overwrite an existing secret without confirmation
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
    #[arg(long = "no-verify", hide = true)]
    pub no_verify: bool,
    #[arg(long = "show-error", hide = true)]
    pub show_error: bool,
    #[arg(long, hide = true)]
    pub refresh: Option<String>,
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
    /// Only list secrets for one sandbox
    #[arg(long)]
    pub sandbox: Option<String>,
    /// Filter by secret service name
    #[arg(long)]
    pub service: Option<String>,
    /// Only display secret names
    #[arg(short = 'q', long)]
    pub quiet: bool,
    #[command(flatten)]
    pub output: OutputArgs,
}

#[derive(Debug, Args)]
pub struct SecretRmArgs {
    /// Service whose secret to remove
    pub service: Option<String>,
    /// Only this sandbox's secret
    #[arg(long)]
    pub sandbox: Option<String>,
    /// Remove every secret
    #[arg(long)]
    pub all: bool,
    /// Don't ask for confirmation
    #[arg(short = 'f', long)]
    pub force: bool,
    /// Remove the pull credential for this container registry
    #[arg(long, value_name = "HOST")]
    pub registry: Option<String>,
    #[arg(long = "all-sandboxes", hide = true)]
    pub all_sandboxes: bool,
}
