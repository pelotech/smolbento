//! `skills`: the shared skills store.

use clap::{Args, Subcommand};

use super::OutputArgs;

/// `bento skills` (sbx's are experimental too).
#[derive(Debug, Subcommand)]
pub enum SkillsCmd {
    /// Add skills from a Git repository
    #[command(visible_alias = "a")]
    Add(SkillsAddArgs),
    /// Import skills from supported agent directories
    Import(SkillsImportArgs),
    /// List installed skills
    #[command(visible_alias = "list")]
    Ls(SkillsLsArgs),
    /// Remove installed skills
    #[command(visible_alias = "remove")]
    Rm(SkillsRmArgs),
    /// Update skills added from repositories
    #[command(visible_alias = "upgrade")]
    Update(SkillsUpdateArgs),
}

#[derive(Debug, Args)]
pub struct SkillsAddArgs {
    /// Git URL or GitHub owner/repository
    pub repository: String,
    /// Add only the named skill (repeatable or comma-separated)
    #[arg(short = 's', long = "skill", value_delimiter = ',')]
    pub skill: Vec<String>,
    /// Overwrite existing skills without prompting
    #[arg(short = 'f', long)]
    pub force: bool,
}

#[derive(Debug, Args)]
pub struct SkillsImportArgs {
    /// Preview which skills would be imported without copying anything
    #[arg(long)]
    pub dry_run: bool,
    /// Overwrite existing skills without prompting
    #[arg(short = 'f', long)]
    pub force: bool,
    /// Also list the checked directories that do not exist
    #[arg(short = 'v', long)]
    pub verbose: bool,
}

#[derive(Debug, Args)]
pub struct SkillsLsArgs {
    #[command(flatten)]
    pub output: OutputArgs,
    /// Only display skill names
    #[arg(short = 'q', long)]
    pub quiet: bool,
}

#[derive(Debug, Args)]
pub struct SkillsRmArgs {
    /// Skills to remove
    #[arg(required = true)]
    pub skills: Vec<String>,
    /// Skip confirmation prompts
    #[arg(short = 'f', long)]
    pub force: bool,
}

#[derive(Debug, Args)]
pub struct SkillsUpdateArgs {
    /// Skills to update (default: all)
    pub skills: Vec<String>,
}
