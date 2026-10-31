//! `sbt skills`: the shared skills store (spec Phase 5c §1).

use std::collections::BTreeMap;
use std::io::Write;
use std::path::PathBuf;

use anyhow::{Result, bail};
use serde::Serialize;

use super::args::{
    KitFormat, SkillsAddArgs, SkillsCmd, SkillsImportArgs, SkillsLsArgs, SkillsRmArgs,
    SkillsUpdateArgs,
};
use super::{Ctx, confirm_or};
use crate::skills::import::{Event, scan};
use crate::skills::repo::{self, Checkout};
use crate::skills::store::{Source, Sources, Store};
use crate::smolvm::Runner;

/// sbx's note after a store change.
pub const NOTE: &str = "Sandboxes sharing skills read-only link store entries at start, so a newly stored skill appears there after their next start; read-write sandboxes see it immediately. Agents may also scan skills only on startup.";

pub fn run<R: Runner>(ctx: &mut Ctx<R>, cmd: SkillsCmd) -> Result<i32> {
    let store = Store::new(&ctx.paths);
    match cmd {
        SkillsCmd::Ls(a) => ls(ctx, &store, &a)?,
        SkillsCmd::Rm(a) => rm(ctx, &store, &a)?,
        SkillsCmd::Add(a) => add(ctx, &store, &a)?,
        SkillsCmd::Update(a) => return update(ctx, &store, &a),
        SkillsCmd::Import(a) => import(ctx, &store, &a)?,
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

fn rm<R: Runner>(ctx: &Ctx<R>, store: &Store, a: &SkillsRmArgs) -> Result<()> {
    if let Some(n) = a.skills.iter().find(|n| !store.has(n)) {
        bail!("skill {n:?} is not installed\n  try: sbt skills ls");
    }
    let q = format!(
        "Remove {}? Running agents may be reading them.",
        a.skills.join(", ")
    );
    confirm_or(
        ctx,
        &q,
        a.force,
        "stdin is not a terminal; use --force to skip confirmation\n  try: sbt skills rm --help",
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

fn add<R: Runner>(ctx: &Ctx<R>, store: &Store, a: &SkillsAddArgs) -> Result<()> {
    let url = repo::parse_url(&a.repository)
        .map_err(|e| anyhow::anyhow!("{e}\n  try: sbt skills add --help"))?;
    add_url(ctx, store, &url, &a.skill, a.force)
}

/// `add` after the URL check (tests pass a local path).
fn add_url<R: Runner>(
    ctx: &Ctx<R>,
    store: &Store,
    url: &str,
    only: &[String],
    force: bool,
) -> Result<()> {
    let checkout = repo::clone(url)?;
    let found = repo::discover(checkout.root(), &repo::repo_name(url))?;
    let picked = pick(&found, only)?;
    let replacing: Vec<&str> = picked
        .keys()
        .filter(|n| store.has(n))
        .map(|n| n.as_str())
        .collect();
    if !replacing.is_empty() {
        let q = format!("Replace {}?", replacing.join(", "));
        confirm_or(
            ctx,
            &q,
            force,
            "stdin is not a terminal; pass --force to skip the confirmation\n  try: sbt skills add --help",
        )?;
    }
    install(ctx, store, &checkout, &picked, "Added")?;
    let n = picked.len();
    writeln!(
        &ctx.out,
        "Added {n} skill{} into {}",
        if n == 1 { "" } else { "s" },
        store.dir.display()
    )?;
    writeln!(&ctx.out, "{NOTE}")?;
    Ok(())
}

fn import<R: Runner>(ctx: &Ctx<R>, store: &Store, a: &SkillsImportArgs) -> Result<()> {
    let home = ctx
        .env
        .get("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| anyhow::anyhow!("HOME is not set"))?;
    let events = scan(&home);
    let picks: Vec<(&String, &PathBuf)> = events
        .iter()
        .filter_map(|e| match e {
            Event::Pick { name, from } => Some((name, from)),
            _ => None,
        })
        .collect();
    let mut missing = Vec::new();
    for e in &events {
        match e {
            Event::Pick { name, .. } if a.dry_run => {
                let verb = if store.has(name) { "replace" } else { "import" };
                writeln!(&ctx.out, "Would {verb} skill {name:?}")?;
            }
            Event::Pick { .. } => {}
            Event::Duplicate { name, dir } => eprintln!(
                "warning: skipping skill {name:?} from {}: already imported from an earlier source",
                dir.display()
            ),
            Event::Loose(n) => eprintln!("warning: skipping {n:?}: not a directory"),
            Event::Missing(d) => missing.push(d),
        }
    }
    // sbx prints the missing-source notices after the picks, on stdout.
    for d in missing {
        writeln!(
            &ctx.out,
            "No skills directory found at {}; nothing to import",
            d.display()
        )?;
    }
    // Nothing to import: no summary, and nothing written.
    if picks.is_empty() {
        return Ok(());
    }
    let n = picks.len();
    let s = if n == 1 { "" } else { "s" };
    if a.dry_run {
        writeln!(
            &ctx.out,
            "Dry run: {n} skill{s} would be imported into {}",
            store.dir.display()
        )?;
        return Ok(());
    }
    let replacing: Vec<&str> = picks
        .iter()
        .filter(|(n, _)| store.has(n))
        .map(|(n, _)| n.as_str())
        .collect();
    if !replacing.is_empty() {
        let q = format!("Replace {}?", replacing.join(", "));
        confirm_or(
            ctx,
            &q,
            a.force,
            "stdin is not a terminal; pass --force to skip the confirmation\n  try: sbt skills import --help",
        )?;
    }
    let mut sources = store.sources()?;
    for (name, from) in &picks {
        store.install(name, from)?;
        sources.skills.remove(*name);
    }
    store.save_sources(&sources)?;
    writeln!(
        &ctx.out,
        "Imported {n} skill{s} into {}",
        store.dir.display()
    )?;
    writeln!(&ctx.out, "{NOTE}")?;
    Ok(())
}

fn pick(found: &BTreeMap<String, PathBuf>, only: &[String]) -> Result<BTreeMap<String, PathBuf>> {
    if found.is_empty() {
        bail!("no SKILL.md found in the repository\n  try: sbt skills add --help");
    }
    if only.is_empty() {
        return Ok(found.clone());
    }
    only.iter()
        .map(|n| match found.get(n) {
            Some(p) => Ok((n.clone(), p.clone())),
            None => bail!(
                "skill {n:?} not found in repository; available skills: {}\n  try: sbt skills add --help",
                found.keys().cloned().collect::<Vec<_>>().join(", ")
            ),
        })
        .collect()
}

/// Copies `picked` into the store and records the checkout as their source.
fn install<R: Runner>(
    ctx: &Ctx<R>,
    store: &Store,
    c: &Checkout,
    picked: &BTreeMap<String, PathBuf>,
    verb: &str,
) -> Result<()> {
    let mut sources = store.sources()?;
    for (name, dir) in picked {
        store.install(name, dir)?;
        sources.skills.insert(
            name.clone(),
            Source {
                repository: c.url.clone(),
                commit: c.commit.clone(),
            },
        );
        writeln!(&ctx.out, "{verb} skill {name}")?;
    }
    store.save_sources(&sources)
}

fn update<R: Runner>(ctx: &Ctx<R>, store: &Store, a: &SkillsUpdateArgs) -> Result<i32> {
    let sources = store.sources()?;
    if a.skills.is_empty() && sources.skills.is_empty() {
        writeln!(&ctx.out, "No repository-installed skills found")?;
        return Ok(0);
    }
    let names: Vec<String> = if a.skills.is_empty() {
        sources.skills.keys().cloned().collect()
    } else {
        a.skills.clone()
    };
    for n in &names {
        if !sources.skills.contains_key(n) {
            bail!(
                "skill {n:?} was not installed from a repository; install it from a repository\n  try: sbt skills add --help"
            );
        }
    }
    let mut by_repo: BTreeMap<&str, Vec<&String>> = BTreeMap::new();
    for n in &names {
        by_repo
            .entry(sources.skills[n].repository.as_str())
            .or_default()
            .push(n);
    }
    let (mut code, mut updated) = (0, 0);
    for (url, skills) in by_repo {
        // One repository failing doesn't stop the others.
        match update_repo(ctx, store, &sources, url, &skills) {
            Ok((c, n)) => {
                code = code.max(c);
                updated += n;
            }
            Err(e) => {
                eprintln!("error: {url}: {e:#}");
                code = 1;
            }
        }
    }
    if updated > 0 {
        writeln!(
            &ctx.out,
            "Updated {updated} skill{} in {}",
            if updated == 1 { "" } else { "s" },
            store.dir.display()
        )?;
    }
    Ok(code)
}

/// Updates `skills` from `url`: the exit code, and how many it updated.
fn update_repo<R: Runner>(
    ctx: &Ctx<R>,
    store: &Store,
    sources: &Sources,
    url: &str,
    skills: &[&String],
) -> Result<(i32, usize)> {
    let c = repo::clone(url)?;
    let found = repo::discover(c.root(), &repo::repo_name(url))?;
    let mut code = 0;
    let mut picked = BTreeMap::new();
    for &n in skills {
        if sources.skills[n].commit == c.commit {
            writeln!(&ctx.out, "Skill {n:?} is already up to date")?;
        } else if let Some(dir) = found.get(n) {
            picked.insert(n.clone(), dir.clone());
        } else {
            eprintln!("error: skill {n:?} is no longer in {url}");
            code = 1;
        }
    }
    install(ctx, store, &c, &picked, "Updated")?;
    Ok((code, picked.len()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::testutil::test_env;

    fn put(t: &crate::cli::testutil::TestEnv, name: &str) {
        let d = t.ctx.paths.skills_store().join(name);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("SKILL.md"), "s").unwrap();
    }

    #[test]
    fn ls_formats() {
        let mut t = test_env(&[]);
        let store = t.ctx.paths.skills_store().display().to_string();
        t.sbt(&["skills", "ls"]).unwrap();
        assert_eq!(t.stdout(), format!("No skills found in {store}\n"));
        t.sbt(&["skills", "ls", "--json"]).unwrap();
        assert_eq!(
            t.stdout(),
            format!("{{\n  \"store\": \"{store}\",\n  \"skills\": []\n}}\n")
        );
        t.sbt(&["skills", "ls", "--format", "yaml"]).unwrap();
        assert_eq!(t.stdout(), format!("store: {store}\nskills: []\n"));
        put(&t, "beta");
        put(&t, "alpha");
        t.sbt(&["skills", "list"]).unwrap();
        assert_eq!(
            t.stdout(),
            format!("SKILL    STORE\nalpha    {store}\nbeta     {store}\n")
        );
        t.sbt(&["skills", "ls", "-q"]).unwrap();
        assert_eq!(t.stdout(), "alpha\nbeta\n");
        t.sbt(&["skills", "ls", "--format", "yaml"]).unwrap();
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
        let e = t.sbt_err(&["skills", "rm", "a"]);
        assert!(
            e.starts_with("stdin is not a terminal; use --force to skip confirmation"),
            "{e}"
        );
        let e = t.sbt_err(&["skills", "rm", "a", "nope", "-f"]);
        assert_eq!(e, "skill \"nope\" is not installed\n  try: sbt skills ls");
        assert!(t.ctx.paths.skills_store().join("a").exists());
        t.sbt(&["skills", "remove", "a", "b", "--force"]).unwrap();
        assert_eq!(t.stdout(), "Removed skill a\nRemoved skill b\n");
    }

    const NOSIGN: [&str; 6] = [
        "-c",
        "commit.gpgsign=false",
        "-c",
        "user.name=t",
        "-c",
        "user.email=t@t",
    ];

    fn commit(dir: &std::path::Path, extra: &[&str], msg: &str) {
        let mut a: Vec<&str> = NOSIGN.to_vec();
        a.extend(["commit", "-q"]);
        a.extend(extra);
        a.extend(["-m", msg]);
        crate::testgit::git(dir, &a);
    }

    fn skills_repo(dir: &std::path::Path, body: &str) {
        for p in ["alpha/SKILL.md", "nested/beta/SKILL.md"] {
            let f = dir.join(p);
            std::fs::create_dir_all(f.parent().unwrap()).unwrap();
            std::fs::write(f, body).unwrap();
        }
        crate::testgit::git(dir, &["init", "-q"]);
        crate::testgit::git(dir, &["add", "-A"]);
        commit(dir, &[], body);
    }

    #[test]
    fn add_installs_records_and_refuses_replacing_without_force() {
        let t = test_env(&[]);
        let r = tempfile::tempdir().unwrap();
        skills_repo(r.path(), "v1");
        let url = r.path().to_str().unwrap();
        let store = Store::new(&t.ctx.paths);
        add_url(&t.ctx, &store, url, &[], false).unwrap();
        let s = store.dir.display();
        assert_eq!(
            t.stdout(),
            format!("Added skill alpha\nAdded skill beta\nAdded 2 skills into {s}\n{NOTE}\n")
        );
        assert_eq!(store.sources().unwrap().skills["alpha"].repository, url);
        let e = add_url(&t.ctx, &store, url, &["alpha".into()], false)
            .unwrap_err()
            .to_string();
        assert!(
            e.starts_with("stdin is not a terminal; pass --force to skip the confirmation"),
            "{e}"
        );
        let e = add_url(&t.ctx, &store, url, &["nosuch".into()], true)
            .unwrap_err()
            .to_string();
        assert!(
            e.starts_with(
                "skill \"nosuch\" not found in repository; available skills: alpha, beta"
            ),
            "{e}"
        );
        add_url(&t.ctx, &store, url, &["alpha".into()], true).unwrap();
        assert!(
            t.stdout()
                .starts_with("Added skill alpha\nAdded 1 skill into ")
        );
    }

    #[test]
    fn add_refuses_local_paths() {
        let mut t = test_env(&[]);
        let e = t.sbt_err(&["skills", "add", "file:///tmp/x"]);
        assert!(e.starts_with("repository must be a remote Git URL or GitHub owner/repository: file: invalid protocol"), "{e}");
    }

    #[test]
    fn update_refreshes_changed_repos_only() {
        let mut t = test_env(&[]);
        let r = tempfile::tempdir().unwrap();
        skills_repo(r.path(), "v1");
        let store = Store::new(&t.ctx.paths);
        add_url(&t.ctx, &store, r.path().to_str().unwrap(), &[], false).unwrap();
        t.stdout();
        assert_eq!(t.sbt(&["skills", "update"]).unwrap(), 0);
        assert_eq!(
            t.stdout(),
            "Skill \"alpha\" is already up to date\nSkill \"beta\" is already up to date\n"
        );
        std::fs::write(r.path().join("alpha/SKILL.md"), "v2").unwrap();
        commit(r.path(), &["-a"], "v2");
        t.sbt(&["skills", "upgrade", "alpha"]).unwrap();
        let s = store.dir.display();
        assert_eq!(
            t.stdout(),
            format!("Updated skill alpha\nUpdated 1 skill in {s}\n")
        );
        assert_eq!(
            std::fs::read_to_string(store.dir.join("alpha/SKILL.md")).unwrap(),
            "v2"
        );
        std::fs::create_dir_all(store.dir.join("mine")).unwrap();
        let e = t.sbt_err(&["skills", "update", "mine"]);
        assert!(
            e.starts_with(
                "skill \"mine\" was not installed from a repository; install it from a repository"
            ),
            "{e}"
        );
    }

    #[test]
    fn update_goes_on_past_a_repository_that_fails() {
        let mut t = test_env(&[]);
        let p = tempfile::tempdir().unwrap();
        let (a, b) = (p.path().join("a"), p.path().join("b"));
        skills_repo(&a, "v1"); // alpha, beta
        std::fs::create_dir_all(b.join("gamma")).unwrap();
        std::fs::write(b.join("gamma/SKILL.md"), "v1").unwrap();
        crate::testgit::git(&b, &["init", "-q"]);
        crate::testgit::git(&b, &["add", "-A"]);
        commit(&b, &[], "v1");
        let store = Store::new(&t.ctx.paths);
        add_url(&t.ctx, &store, a.to_str().unwrap(), &[], false).unwrap();
        add_url(&t.ctx, &store, b.to_str().unwrap(), &[], false).unwrap();
        t.stdout();
        std::fs::write(b.join("gamma/SKILL.md"), "v2").unwrap();
        commit(&b, &["-a"], "v2");
        std::fs::remove_dir_all(&a).unwrap(); // sorts first, fails to clone
        assert_eq!(t.sbt(&["skills", "update"]).unwrap(), 1);
        assert_eq!(
            t.stdout(),
            format!(
                "Updated skill gamma\nUpdated 1 skill in {}\n",
                store.dir.display()
            )
        );
        assert_eq!(
            std::fs::read_to_string(store.dir.join("gamma/SKILL.md")).unwrap(),
            "v2"
        );
        assert!(store.dir.join("alpha").exists());
    }

    #[test]
    fn update_reports_a_skill_gone_from_its_repository_and_updates_the_rest() {
        let mut t = test_env(&[]);
        let r = tempfile::tempdir().unwrap();
        skills_repo(r.path(), "v1");
        let store = Store::new(&t.ctx.paths);
        add_url(&t.ctx, &store, r.path().to_str().unwrap(), &[], false).unwrap();
        t.stdout();
        std::fs::remove_dir_all(r.path().join("nested")).unwrap();
        std::fs::write(r.path().join("alpha/SKILL.md"), "v2").unwrap();
        crate::testgit::git(r.path(), &["add", "-A"]);
        commit(r.path(), &[], "v2");
        assert_eq!(t.sbt(&["skills", "update"]).unwrap(), 1);
        assert_eq!(
            t.stdout(),
            format!(
                "Updated skill alpha\nUpdated 1 skill in {}\n",
                store.dir.display()
            )
        );
        assert_eq!(
            std::fs::read_to_string(store.dir.join("alpha/SKILL.md")).unwrap(),
            "v2"
        );
    }

    /// A committed repo at `<tmp>/<name>` holding `files`.
    fn named_repo(name: &str, files: &[(&str, &str)]) -> (tempfile::TempDir, std::path::PathBuf) {
        let t = tempfile::tempdir().unwrap();
        let r = t.path().join(name);
        for (p, body) in files {
            let f = r.join(p);
            std::fs::create_dir_all(f.parent().unwrap()).unwrap();
            std::fs::write(f, body).unwrap();
        }
        crate::testgit::git(&r, &["init", "-q"]);
        crate::testgit::git(&r, &["add", "-A"]);
        commit(&r, &[], "v1");
        (t, r)
    }

    #[test]
    fn a_skill_md_at_the_root_installs_the_repository_as_one_skill() {
        let t = test_env(&[]);
        let (_d, r) = named_repo(
            "affiliate-skills",
            &[
                ("SKILL.md", "---\nname: affiliate-check\n---\n"),
                (".env.example", "X=1"),
                ("skills/nested/SKILL.md", "n"),
            ],
        );
        let store = Store::new(&t.ctx.paths);
        add_url(&t.ctx, &store, r.to_str().unwrap(), &[], false).unwrap();
        assert!(
            t.stdout()
                .starts_with("Added skill affiliate-check\nAdded 1 skill into ")
        );
        let s = store.dir.join("affiliate-check");
        assert!(s.join(".env.example").is_file());
        assert!(s.join("skills/nested/SKILL.md").is_file());
        assert!(!s.join(".git").exists());
        assert_eq!(store.list().unwrap(), ["affiliate-check"]);
        // Without a frontmatter name: the repository's basename.
        let (_d, r) = named_repo("solo.git", &[("SKILL.md", "plain")]);
        add_url(&t.ctx, &store, r.to_str().unwrap(), &[], false).unwrap();
        assert!(store.has("solo"));
    }

    #[test]
    fn add_and_update_name_skills_from_their_frontmatter() {
        let mut t = test_env(&[]);
        let (_d, r) = named_repo(
            "skills",
            &[("template/SKILL.md", "---\nname: template-skill\n---\nv1")],
        );
        let url = r.to_str().unwrap();
        let store = Store::new(&t.ctx.paths);
        add_url(&t.ctx, &store, url, &["template-skill".into()], false).unwrap();
        t.stdout();
        assert!(store.has("template-skill") && !store.has("template"));
        std::fs::write(
            r.join("template/SKILL.md"),
            "---\nname: template-skill\n---\nv2",
        )
        .unwrap();
        commit(&r, &["-a"], "v2");
        t.sbt(&["skills", "update"]).unwrap();
        assert_eq!(
            t.stdout(),
            format!(
                "Updated skill template-skill\nUpdated 1 skill in {}\n",
                store.dir.display()
            )
        );
        assert!(
            std::fs::read_to_string(store.dir.join("template-skill/SKILL.md"))
                .unwrap()
                .ends_with("v2")
        );
    }

    #[test]
    fn update_with_no_repository_skills_says_so() {
        let mut t = test_env(&[]);
        assert_eq!(t.sbt(&["skills", "update"]).unwrap(), 0);
        assert_eq!(t.stdout(), "No repository-installed skills found\n");
    }

    #[test]
    fn a_failed_clone_says_why_on_one_line() {
        let t = test_env(&[]);
        let d = tempfile::tempdir().unwrap();
        let store = Store::new(&t.ctx.paths);
        let e = add_url(
            &t.ctx,
            &store,
            d.path().join("nope").to_str().unwrap(),
            &[],
            false,
        )
        .unwrap_err()
        .to_string();
        assert!(
            e.starts_with("clone skills repository: exit status 128: "),
            "{e}"
        );
    }

    #[test]
    fn import_with_nothing_to_import_prints_only_the_notices() {
        let home = tempfile::tempdir().unwrap();
        let h = home.path();
        let mut t = test_env(&[("HOME", h.to_str().unwrap())]);
        let want: String = crate::skills::import::SOURCES
            .iter()
            .map(|s| {
                format!(
                    "No skills directory found at {}; nothing to import\n",
                    h.join(s).display()
                )
            })
            .collect();
        for args in [
            &["skills", "import", "--dry-run"][..],
            &["skills", "import"],
        ] {
            t.sbt(args).unwrap();
            assert_eq!(t.stdout(), want, "{args:?}");
        }
        let store = Store::new(&t.ctx.paths);
        assert!(!store.dir.exists() && !store.meta.exists());
    }

    #[test]
    fn import_in_sbx_order_with_warnings() {
        let home = tempfile::tempdir().unwrap();
        let h = home.path();
        for p in [
            ".agents/skills/beta",
            ".claude/skills/alpha/scripts",
            ".claude/skills/beta",
        ] {
            std::fs::create_dir_all(h.join(p)).unwrap();
        }
        std::fs::write(h.join(".claude/skills/loose.txt"), "x").unwrap();
        std::os::unix::fs::symlink(
            h.join(".agents/skills/beta"),
            h.join(".claude/skills/linked"),
        )
        .unwrap();
        let mut t = test_env(&[("HOME", h.to_str().unwrap())]);
        let store = t.ctx.paths.skills_store().display().to_string();
        t.sbt(&["skills", "import", "--dry-run"]).unwrap();
        let out = t.stdout();
        assert_eq!(out.lines().next().unwrap(), "Would import skill \"beta\"");
        assert!(
            out.contains("Would import skill \"alpha\"\nWould import skill \"linked\"\n"),
            "{out}"
        );
        assert!(
            out.ends_with(&format!(
                "Dry run: 3 skills would be imported into {store}\n"
            )),
            "{out}"
        );
        assert!(!t.ctx.paths.skills_store().exists());
        t.sbt(&["skills", "import"]).unwrap();
        assert!(
            t.stdout()
                .contains(&format!("Imported 3 skills into {store}\n"))
        );
        let e = t.sbt_err(&["skills", "import"]);
        assert!(
            e.starts_with("stdin is not a terminal; pass --force to skip the confirmation"),
            "{e}"
        );
        t.sbt(&["skills", "import", "-f"]).unwrap();
    }

    #[test]
    fn scan_events() {
        use crate::skills::import::{Event, scan};
        let home = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(home.path().join(".claude/skills/a")).unwrap();
        std::fs::write(home.path().join(".claude/skills/x.txt"), "").unwrap();
        let ev = scan(home.path());
        assert!(matches!(&ev[0], Event::Missing(p) if p.ends_with(".agents/skills")));
        assert!(matches!(&ev[1], Event::Pick { name, .. } if name == "a"));
        assert!(matches!(&ev[2], Event::Loose(n) if n == "x.txt"));
        assert_eq!(ev.len(), 7); // 5 missing sources + pick + loose
    }
}
