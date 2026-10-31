//! `sbt template`: saved sandbox templates (spec Phase 5d).

use std::io::Write;

use anyhow::{Context, Result, bail};
use serde::Serialize;

use super::args::{
    KitFormat, TemplateCmd, TemplateLoadArgs, TemplateLsArgs, TemplateRmArgs, TemplateSaveArgs,
};
use super::lifecycle::stop_sandbox;
use super::ls::age;
use super::progress::Progress;
use super::{Ctx, Unsupported, confirm, confirm_or, table};
use crate::sandbox;
use crate::smolvm::Runner;
use crate::templates::{Entry, Store, TemplateRef};

pub fn run<R: Runner>(ctx: &mut Ctx<R>, cmd: TemplateCmd) -> Result<i32> {
    match cmd {
        TemplateCmd::Inspect(_) => Err(Unsupported(
            "'template inspect' requires --cloud in v1; local templates are smolvm packs; \
             list them with sbt template ls"
                .into(),
        )
        .into()),
        TemplateCmd::Save(a) => save(ctx, &a).map(|()| 0),
        TemplateCmd::Ls(a) => ls(ctx, &a).map(|()| 0),
        TemplateCmd::Rm(a) => rm(ctx, &a).map(|()| 0),
        TemplateCmd::Load(a) => load(ctx, &a).map(|()| 0),
    }
}

#[derive(Serialize)]
struct Row<'a> {
    id: &'a str,
    repository: &'a str,
    tag: &'a str,
    flavor: &'a str,
    created_at: &'a str,
    size: u64,
}

fn format(json: bool, format: Option<KitFormat>) -> KitFormat {
    if json {
        KitFormat::Json
    } else {
        format.unwrap_or(KitFormat::Table)
    }
}

fn ls<R: Runner>(ctx: &Ctx<R>, a: &TemplateLsArgs) -> Result<()> {
    let all = Store::new(&ctx.paths).list()?;
    let rows: Vec<Row> = all
        .iter()
        .map(|e| Row {
            id: &e.id,
            repository: &e.repository,
            tag: &e.tag,
            flavor: &e.agent,
            created_at: &e.created_at,
            size: e.size,
        })
        .collect();
    let mut out = &ctx.out;
    match format(a.json, a.format) {
        _ if a.quiet => all.iter().try_for_each(|e| writeln!(out, "{}", e.full()))?,
        KitFormat::Json => writeln!(out, "{}", serde_json::to_string_pretty(&rows)?)?,
        KitFormat::Yaml => write!(out, "{}", serde_saphyr::to_string(&rows)?)?,
        KitFormat::Table => {
            let head = ["REPOSITORY", "TAG", "IMAGE ID", "FLAVOR", "CREATED"];
            let mut lines = vec![head.map(String::from).to_vec()];
            for e in &all {
                let created = humantime::parse_rfc3339(&e.created_at)
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map_or_else(String::new, |d| age(ctx.now - d.as_secs() as i64));
                lines.push(vec![
                    e.repository.clone(),
                    e.tag.clone(),
                    e.id.clone(),
                    e.agent.clone(),
                    created,
                ]);
            }
            write!(out, "{}", table(lines))?;
        }
    }
    Ok(())
}

#[derive(Serialize)]
struct Removed<'a> {
    action: &'a str,
    resource: &'a str,
    name: &'a str,
}

fn rm<R: Runner>(ctx: &Ctx<R>, a: &TemplateRmArgs) -> Result<()> {
    let store = Store::new(&ctx.paths);
    let found = store.find(&a.name).map_err(|e| {
        if e.downcast_ref::<crate::templates::Ambiguous>().is_some() {
            anyhow::anyhow!(
                "cannot remove template \"{n}\": \"{n}\" matches more than one template\n  try: sbt template ls",
                n = a.name
            )
        } else {
            e
        }
    })?;
    let Some(e) = found else {
        bail!(
            "cannot remove template \"{n}\": no template \"{n}\"\n  try: sbt template ls",
            n = a.name
        );
    };
    let q = format!("Remove template \"{}\"? This cannot be undone.", a.name);
    confirm_or(
        ctx,
        &q,
        a.force,
        "stdin is not a terminal; pass --force to skip the confirmation\n  try: sbt template rm --force",
    )?;
    store.remove(&e)?;
    let mut out = &ctx.out;
    match format(a.json, a.format) {
        KitFormat::Table => writeln!(out, "Removed template {}", a.name)?,
        f => {
            let doc = [Removed {
                action: "removed",
                resource: "template",
                name: &a.name,
            }];
            if f == KitFormat::Json {
                writeln!(out, "{}", serde_json::to_string_pretty(&doc)?)?;
            } else {
                write!(out, "{}", serde_saphyr::to_string(&doc)?)?;
            }
        }
    }
    Ok(())
}

fn load<R: Runner>(ctx: &Ctx<R>, a: &TemplateLoadArgs) -> Result<()> {
    if a.name.is_some() {
        bail!("'template load' (local) takes one argument (FILE)\n  try: sbt template load --help");
    }
    let f = a.file.display();
    let p = Progress::for_ctx(ctx, false);
    let step = p.step(&format!("image from {f}"), "loading");
    match Store::new(&ctx.paths).import(&a.file) {
        Ok(_) => step.done("loaded"),
        Err(e) => {
            step.fail();
            return Err(e);
        }
    }
    writeln!(&ctx.out, "Loaded image from {f}")?;
    Ok(())
}

fn save<R: Runner>(ctx: &Ctx<R>, a: &TemplateSaveArgs) -> Result<()> {
    let r = TemplateRef::parse(&a.tag)?;
    let sb = sandbox::get(&ctx.vm, &a.sandbox)?;
    if let Some(t) = &sb.meta.template {
        bail!(
            "cannot save {}: it was created from template {t}, and smolvm can't save a sandbox \
             made from a template yet",
            sb.name()
        );
    }
    if crate::agents::find(&sb.meta.agent).is_none() {
        bail!(
            "cannot save {}: templates of kit workload sandboxes aren't supported yet",
            sb.name()
        );
    }
    if sb.is_running() {
        let refused = || {
            anyhow::anyhow!(
                "cannot save a running sandbox; stop it first with:\n  try: sbt stop {}",
                sb.name()
            )
        };
        if !ctx.stdin_tty {
            return Err(refused());
        }
        let q = format!(
            "Sandbox {} is running and must be stopped before saving. Stop it now?",
            sb.name()
        );
        confirm(ctx, &q, false).map_err(|_| refused())?;
        stop_sandbox(ctx, &sb)?;
    }
    let store = Store::new(&ctx.paths);
    let p = Progress::for_ctx(ctx, false);
    let step = p.step(&format!("image in sandbox {}", sb.name()), "snapshotting");
    // The temp dir is removed on drop, so a failed pack leaves nothing behind.
    let tmp = store.temp_dir()?;
    let out = tmp.path().join("pack");
    if let Err(e) = ctx.vm.pack_from_vm(&sb.machine, &out) {
        step.fail();
        return Err(e).context(format!("saving {}", sb.name()));
    }
    step.done("snapshotted");
    let created = std::time::UNIX_EPOCH + std::time::Duration::from_secs(ctx.now.max(0) as u64);
    let entry = store.add(
        Entry {
            repository: r.repository,
            tag: r.tag,
            agent: sb.meta.agent.clone(),
            image: sb.image.clone().unwrap_or_default(),
            docker: sb.meta.docker,
            created_at: humantime::format_rfc3339_seconds(created).to_string(),
            ..Default::default()
        },
        &tmp.path().join("pack.smolmachine"),
    )?;
    if let Some(file) = &a.output {
        let f = file.display();
        let step = p.step(&format!("image to {f}"), "exporting");
        if let Err(e) = store.export(&entry, file) {
            step.fail();
            return Err(e);
        }
        step.done("exported");
        writeln!(&ctx.out, "Exported image to {f}")?;
    }
    writeln!(&ctx.out, "Saved template {}", entry.full())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::cli::testutil::*;
    use crate::templates::Store;

    /// A sandbox `a` (machine `sbx-a`) and a pack step that writes the stub and `pack.smolmachine`.
    fn env_with_sandbox(state: &str, extra: &[(&str, &str)]) -> TestEnv {
        let t = test_env(&[]);
        let mut labels = vec![
            ("sbx.name", "a"),
            ("sbx.agent", "shell"),
            ("sbx.docker", "true"),
        ];
        labels.extend_from_slice(extra);
        let r = t.ctx.vm.runner();
        r.ok(
            &["machine", "status", "-n", "sbx-a"],
            &machine_json("sbx-a", state, &labels),
        );
        r.ok(&["machine", "stop"], "");
        r.ok(&["pack", "create"], "");
        r.during(&["pack", "create"], |args| {
            let out = args.last().unwrap();
            std::fs::write(out, "stub").unwrap();
            std::fs::write(format!("{out}.smolmachine"), "packed").unwrap();
        });
        t
    }

    #[test]
    fn save_packs_a_stopped_sandbox() {
        let mut t = env_with_sandbox("stopped", &[]);
        sbt(&mut t.ctx, &["template", "save", "a", "chk-tpl:v1"]).unwrap();
        let out = t.stdout();
        assert!(
            out.ends_with("Saved template docker.io/library/chk-tpl:v1\n"),
            "{out}"
        );
        let line = t
            .ctx
            .vm
            .runner()
            .call_lines()
            .into_iter()
            .find(|l| l.starts_with("pack"))
            .unwrap();
        assert!(
            line.starts_with("pack create --from-vm sbx-a --no-sign -o "),
            "{line}"
        );
        let store = Store::new(&t.ctx.paths);
        let e = store.find("chk-tpl:v1").unwrap().unwrap();
        assert_eq!(
            (e.agent.as_str(), e.image.as_str(), e.docker),
            ("shell", "img", true)
        );
        assert_eq!(std::fs::read_to_string(store.pack(&e)).unwrap(), "packed");
        // Only the index and the pack are left: the stub and temp dir are gone.
        assert_eq!(std::fs::read_dir(&store.dir).unwrap().count(), 2);
    }

    #[test]
    fn a_bare_name_is_latest() {
        let mut t = env_with_sandbox("stopped", &[]);
        sbt(&mut t.ctx, &["template", "save", "a", "chk-tpl"]).unwrap();
        assert!(
            t.stdout()
                .ends_with("Saved template docker.io/library/chk-tpl:latest\n")
        );
    }

    #[test]
    fn a_running_sandbox_without_a_terminal_is_refused() {
        let mut t = env_with_sandbox("running", &[]);
        let err = sbt(&mut t.ctx, &["template", "save", "a", "t"])
            .unwrap_err()
            .to_string();
        assert_eq!(
            err,
            "cannot save a running sandbox; stop it first with:\n  try: sbt stop a"
        );
        assert!(
            !t.ctx
                .vm
                .runner()
                .call_lines()
                .iter()
                .any(|l| l.starts_with("pack"))
        );
    }

    #[test]
    fn a_template_sandbox_is_refused() {
        let mut t = env_with_sandbox("stopped", &[("sbx.template", "docker.io/library/t:v1")]);
        let err = sbt(&mut t.ctx, &["template", "save", "a", "t2"])
            .unwrap_err()
            .to_string();
        assert_eq!(
            err,
            "cannot save a: it was created from template docker.io/library/t:v1, and smolvm \
             can't save a sandbox made from a template yet"
        );
    }

    #[test]
    fn a_kit_workload_sandbox_is_refused_before_any_pack() {
        let mut t = env_with_sandbox("running", &[("sbx.agent", "my-kit")]);
        let err = sbt(&mut t.ctx, &["template", "save", "a", "t2"])
            .unwrap_err()
            .to_string();
        assert_eq!(
            err,
            "cannot save a: templates of kit workload sandboxes aren't supported yet"
        );
        let calls = t.ctx.vm.runner().call_lines();
        assert!(!calls.iter().any(|l| l.starts_with("pack")), "{calls:?}");
        assert!(!calls.iter().any(|l| l.contains("stop")), "{calls:?}");
    }

    #[test]
    fn rm_refuses_an_ambiguous_id_prefix() {
        let mut t = test_env(&[]);
        let a = with_template(&t, "t:a");
        with_template(&t, "t:b");
        // Give the second entry an id sharing the first's 8-char prefix, by editing the index.
        let idx = Store::new(&t.ctx.paths).dir.join(crate::templates::INDEX);
        let mut v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&idx).unwrap()).unwrap();
        v["templates"][1]["id"] = format!("{}ffff", &a.id[..8]).into();
        std::fs::write(&idx, v.to_string()).unwrap();
        let err = sbt(&mut t.ctx, &["template", "rm", "-f", &a.id[..6]])
            .unwrap_err()
            .to_string();
        let n = &a.id[..6];
        assert_eq!(
            err,
            format!(
                "cannot remove template \"{n}\": \"{n}\" matches more than one template\n  try: sbt template ls"
            )
        );
        assert_eq!(Store::new(&t.ctx.paths).list().unwrap().len(), 2);
    }

    #[test]
    fn output_exports_an_archive() {
        let mut t = env_with_sandbox("stopped", &[]);
        let file = t.ctx.cwd.join("t.tar");
        let f = file.to_str().unwrap();
        sbt(
            &mut t.ctx,
            &["template", "save", "a", "t:v1", "--output", f],
        )
        .unwrap();
        let out = t.stdout();
        let want = format!("Exported image to {f}\nSaved template docker.io/library/t:v1\n");
        assert!(out.ends_with(&want), "{out}");
        assert!(file.exists());
    }

    #[test]
    fn a_failed_pack_leaves_no_template() {
        let mut t = env_with_sandbox("stopped", &[]);
        t.ctx
            .vm
            .runner()
            .fail(&["pack", "create"], "AGENT", "timed out");
        assert!(sbt(&mut t.ctx, &["template", "save", "a", "t"]).is_err());
        let store = Store::new(&t.ctx.paths);
        assert!(store.list().unwrap().is_empty());
        let left: Vec<_> = std::fs::read_dir(&store.dir).unwrap().collect();
        assert!(left.is_empty(), "temp dir removed: {left:?}");
    }

    fn with_template(t: &TestEnv, name: &str) -> crate::templates::Entry {
        let store = Store::new(&t.ctx.paths);
        let src = t
            .ctx
            .cwd
            .join(format!("{}.smolmachine", name.replace(':', "_")));
        std::fs::write(&src, name).unwrap();
        let r = crate::templates::TemplateRef::parse(name).unwrap();
        store
            .add(
                crate::templates::Entry {
                    repository: r.repository,
                    tag: r.tag,
                    agent: "shell".into(),
                    image: "img".into(),
                    created_at: "1970-01-12T13:46:30Z".into(),
                    ..Default::default()
                },
                &src,
            )
            .unwrap()
    }

    #[test]
    fn ls_table_json_and_quiet() {
        let mut t = test_env(&[]);
        let e = with_template(&t, "chk-tpl:v1");
        sbt(&mut t.ctx, &["template", "ls"]).unwrap();
        let out = t.stdout();
        let mut lines = out.lines();
        let header = lines.next().unwrap();
        assert!(
            header.starts_with("REPOSITORY") && header.contains("IMAGE ID"),
            "{out}"
        );
        let row = lines.next().unwrap();
        assert!(row.starts_with("docker.io/library/chk-tpl"), "{row}");
        assert!(
            row.contains(&e.id) && row.contains("shell") && row.contains("10s"),
            "{row}"
        );
        sbt(&mut t.ctx, &["template", "ls", "--json"]).unwrap();
        let v: serde_json::Value = serde_json::from_str(&t.stdout()).unwrap();
        assert_eq!(
            v,
            serde_json::json!([{"id": e.id, "repository": "docker.io/library/chk-tpl",
                "tag": "v1", "flavor": "shell", "created_at": "1970-01-12T13:46:30Z",
                "size": e.size}])
        );
        sbt(&mut t.ctx, &["template", "ls", "-q"]).unwrap();
        assert_eq!(t.stdout(), "docker.io/library/chk-tpl:v1\n");
    }

    #[test]
    fn rm_needs_force_without_a_terminal() {
        let mut t = test_env(&[]);
        with_template(&t, "t:v1");
        let err = sbt(&mut t.ctx, &["template", "rm", "t:v1"])
            .unwrap_err()
            .to_string();
        assert_eq!(
            err,
            "stdin is not a terminal; pass --force to skip the confirmation\n  try: sbt template rm --force"
        );
        sbt(&mut t.ctx, &["template", "rm", "-f", "t:v1"]).unwrap();
        assert_eq!(t.stdout(), "Removed template t:v1\n");
        assert!(Store::new(&t.ctx.paths).list().unwrap().is_empty());
    }

    #[test]
    fn rm_by_id_prefix_and_json() {
        let mut t = test_env(&[]);
        let e = with_template(&t, "t:v2");
        sbt(&mut t.ctx, &["template", "rm", "-f", "--json", &e.id[..6]]).unwrap();
        let v: serde_json::Value = serde_json::from_str(&t.stdout()).unwrap();
        assert_eq!(
            v,
            serde_json::json!([{"action": "removed", "resource": "template", "name": &e.id[..6]}])
        );
    }

    #[test]
    fn rm_missing() {
        let mut t = test_env(&[]);
        let err = sbt(&mut t.ctx, &["template", "rm", "-f", "t:nope"])
            .unwrap_err()
            .to_string();
        assert_eq!(
            err,
            "cannot remove template \"t:nope\": no template \"t:nope\"\n  try: sbt template ls"
        );
    }

    #[test]
    fn load_round_trips_an_export() {
        let mut t = test_env(&[]);
        let e = with_template(&t, "t:v1");
        let store = Store::new(&t.ctx.paths);
        let file = t.ctx.cwd.join("t.tar");
        store.export(&e, &file).unwrap();
        store.remove(&e).unwrap();
        let f = file.to_str().unwrap();
        sbt(&mut t.ctx, &["template", "load", f]).unwrap();
        assert!(t.stdout().ends_with(&format!("Loaded image from {f}\n")));
        assert_eq!(store.list().unwrap(), vec![e]);
    }

    #[test]
    fn load_refuses_a_name() {
        let mut t = test_env(&[]);
        let err = sbt(&mut t.ctx, &["template", "load", "x.tar", "name"])
            .unwrap_err()
            .to_string();
        assert_eq!(
            err,
            "'template load' (local) takes one argument (FILE)\n  try: sbt template load --help"
        );
    }
}
