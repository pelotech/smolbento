//! `sbt skills`: the shared skills store (spec Phase 5c §1).

use std::io::Write;

use anyhow::{Result, bail};
use serde::Serialize;

use super::args::{KitFormat, SkillsCmd, SkillsLsArgs, SkillsRmArgs};
use super::{Ctx, confirm};
use crate::skills::store::Store;
use crate::smolvm::Runner;

/// sbx's note after a store change.
#[allow(dead_code)] // used by add/import (Tasks 4-5)
pub const NOTE: &str = "Sandboxes sharing skills read-only link store entries at start, so a newly stored skill appears there after their next start; read-write sandboxes see it immediately. Agents may also scan skills only on startup.";

pub fn run<R: Runner>(ctx: &mut Ctx<R>, cmd: SkillsCmd) -> Result<i32> {
    let store = Store::new(&ctx.paths);
    match cmd {
        SkillsCmd::Ls(a) => ls(ctx, &store, &a)?,
        SkillsCmd::Rm(a) => rm(ctx, &store, &a)?,
        // Tasks 4 and 5 replace this arm.
        SkillsCmd::Add(_) | SkillsCmd::Import(_) | SkillsCmd::Update(_) => {
            bail!("not implemented yet")
        }
    }
    Ok(0)
}

#[derive(Serialize)]
struct Listing<'a> {
    store: String,
    skills: &'a [String],
}

fn ls<R: Runner>(ctx: &Ctx<R>, store: &Store, a: &SkillsLsArgs) -> Result<()> {
    let names = store.list()?;
    let path = store.dir.display().to_string();
    let format = if a.json {
        KitFormat::Json
    } else {
        a.format.unwrap_or(KitFormat::Table)
    };
    let mut out = &ctx.out;
    let doc = Listing {
        store: path.clone(),
        skills: &names,
    };
    match format {
        _ if a.quiet => names.iter().try_for_each(|n| writeln!(out, "{n}"))?,
        KitFormat::Json => writeln!(out, "{}", serde_json::to_string_pretty(&doc)?)?,
        KitFormat::Yaml => write!(out, "{}", serde_saphyr::to_string(&doc)?)?,
        KitFormat::Table if names.is_empty() => writeln!(out, "No skills found in {path}")?,
        KitFormat::Table => {
            // sbx pads the name column to its widest cell plus 4 spaces.
            let w = names.iter().map(|n| n.len()).chain([5]).max().unwrap_or(5) + 4;
            writeln!(out, "{:<w$}STORE", "SKILL")?;
            for n in &names {
                writeln!(out, "{n:<w$}{path}")?;
            }
        }
    }
    Ok(())
}

/// sbx's prompt rule: ask on a terminal, else require `--force`.
pub fn confirm_or_force<R: Runner>(
    ctx: &Ctx<R>,
    question: &str,
    force: bool,
    refusal: &str,
    cmd: &str,
) -> Result<()> {
    if !force && !ctx.stdin_tty {
        bail!("{refusal}\n  try: sbt skills {cmd} --help");
    }
    confirm(ctx, question, force)
}

fn rm<R: Runner>(ctx: &Ctx<R>, store: &Store, a: &SkillsRmArgs) -> Result<()> {
    if let Some(n) = a.skills.iter().find(|n| !store.has(n)) {
        bail!("skill {n:?} is not installed\n  try: sbt skills ls");
    }
    let q = format!(
        "Remove {}? Running agents may be reading them.",
        a.skills.join(", ")
    );
    confirm_or_force(
        ctx,
        &q,
        a.force,
        "stdin is not a terminal; use --force to skip confirmation",
        "rm",
    )?;
    let mut sources = store.sources()?;
    for n in &a.skills {
        store.remove(n)?;
        sources.skills.remove(n);
        writeln!(&ctx.out, "Removed skill {n}")?;
    }
    store.save_sources(&sources)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::cli::testutil::{sbt, test_env};

    fn put(t: &crate::cli::testutil::TestEnv, name: &str) {
        let d = t.ctx.paths.skills_store().join(name);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("SKILL.md"), "s").unwrap();
    }

    #[test]
    fn ls_formats() {
        let mut t = test_env(&[]);
        let store = t.ctx.paths.skills_store().display().to_string();
        sbt(&mut t.ctx, &["skills", "ls"]).unwrap();
        assert_eq!(t.stdout(), format!("No skills found in {store}\n"));
        sbt(&mut t.ctx, &["skills", "ls", "--json"]).unwrap();
        assert_eq!(
            t.stdout(),
            format!("{{\n  \"store\": \"{store}\",\n  \"skills\": []\n}}\n")
        );
        sbt(&mut t.ctx, &["skills", "ls", "--format", "yaml"]).unwrap();
        assert_eq!(t.stdout(), format!("store: {store}\nskills: []\n"));
        put(&t, "beta");
        put(&t, "alpha");
        sbt(&mut t.ctx, &["skills", "list"]).unwrap();
        assert_eq!(
            t.stdout(),
            format!("SKILL    STORE\nalpha    {store}\nbeta     {store}\n")
        );
        sbt(&mut t.ctx, &["skills", "ls", "-q"]).unwrap();
        assert_eq!(t.stdout(), "alpha\nbeta\n");
        sbt(&mut t.ctx, &["skills", "ls", "--format", "yaml"]).unwrap();
        assert_eq!(
            t.stdout(),
            format!("store: {store}\nskills:\n- alpha\n- beta\n")
        );
    }

    #[test]
    fn rm_confirms_checks_every_name_and_updates_sources() {
        let mut t = test_env(&[]);
        put(&t, "a");
        put(&t, "b");
        let e = sbt(&mut t.ctx, &["skills", "rm", "a"])
            .unwrap_err()
            .to_string();
        assert!(
            e.starts_with("stdin is not a terminal; use --force to skip confirmation"),
            "{e}"
        );
        let e = sbt(&mut t.ctx, &["skills", "rm", "a", "nope", "-f"])
            .unwrap_err()
            .to_string();
        assert_eq!(e, "skill \"nope\" is not installed\n  try: sbt skills ls");
        assert!(t.ctx.paths.skills_store().join("a").exists());
        sbt(&mut t.ctx, &["skills", "remove", "a", "b", "--force"]).unwrap();
        assert_eq!(t.stdout(), "Removed skill a\nRemoved skill b\n");
    }
}
