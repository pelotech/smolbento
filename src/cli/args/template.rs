//! `template`: saved templates.

use std::path::PathBuf;

use clap::{Args, Subcommand};

use super::{OutputArgs, Passthrough};

/// `bento template` (local; sbx's `--cloud` templates aren't supported).
#[derive(Debug, Subcommand)]
pub enum TemplateCmd {
    /// Save a snapshot of the sandbox as a template
    Save(TemplateSaveArgs),
    /// List templates
    #[command(visible_alias = "list")]
    Ls(TemplateLsArgs),
    /// Remove a template
    #[command(visible_aliases = ["remove", "delete"])]
    Rm(TemplateRmArgs),
    /// Load a template from a file made by `template save --output`
    Load(TemplateLoadArgs),
    #[command(hide = true)]
    Inspect(Passthrough),
}

#[derive(Debug, Args)]
pub struct TemplateSaveArgs {
    #[arg(long = "capture-mode", hide = true)]
    pub capture_mode: Option<String>,
    #[arg(long, hide = true)]
    pub description: Option<String>,
    /// Sandbox to save
    pub sandbox: String,
    /// Template name, e.g. myimage:v1.0
    pub tag: String,
    /// Also export the template to a file
    #[arg(short = 'o', long)]
    pub output: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct TemplateLsArgs {
    #[arg(long, short = 'a', hide = true)]
    pub all: bool,
    #[arg(long, hide = true)]
    pub digests: bool,
    #[arg(long = "no-trunc", hide = true)]
    pub no_trunc: bool,
    #[command(flatten)]
    pub output: OutputArgs,
    /// Only display template names
    #[arg(short = 'q', long)]
    pub quiet: bool,
}

#[derive(Debug, Args)]
pub struct TemplateRmArgs {
    /// Template name or ID (prefix)
    pub name: String,
    /// Skip confirmation prompts
    #[arg(short = 'f', long)]
    pub force: bool,
    #[command(flatten)]
    pub output: OutputArgs,
}

#[derive(Debug, Args)]
pub struct TemplateLoadArgs {
    #[arg(long = "capture-mode", hide = true)]
    pub capture_mode: Option<String>,
    #[arg(long, hide = true)]
    pub description: Option<String>,
    /// File made by `bento template save --output`
    pub file: PathBuf,
    /// sbx's cloud template name; refused for local templates
    #[arg(hide = true)]
    pub name: Option<String>,
}
