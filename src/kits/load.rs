//! Turns a kit REF (a path or a registry reference) into a `Kit`.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use crate::agents::Agent;
use crate::cli::Ctx;
use crate::kits::model::{Content, Kind, Kit, Source};
use crate::kits::{builder, registry, smolfile, trust, v2};
use crate::smolvm::Runner;

/// Loads the kit REF names. `trust::check` runs on the source before anything is read, built
/// or pulled. Presets (`agents::find`) are the caller's business, so `claude` never lands here.
pub fn load<R: Runner>(ctx: &Ctx<R>, reference: &str) -> Result<Kit> {
    let Some(path) = local_path(ctx, reference)? else {
        trust::check(&Source::Registry(reference.to_string()), &ctx.settings)?;
        return registry::pull(reference, &ctx.paths.kit_cache());
    };
    // The local check is the same for every local kind, so it runs before anything is read.
    trust::check(&Source::LocalV3(path.clone()), &ctx.settings)?;
    if path.is_dir() {
        return load_dir(ctx, &path);
    }
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();
    if name == "Smolfile" || name.ends_with(".smolfile") {
        return smolfile::load(&path);
    }
    if is_descriptor(&path) {
        // buildx needs the whole directory as its context.
        let dir = path.parent().context("kit file has no parent directory")?;
        return load_v3(ctx, dir);
    }
    bail!(
        "{} isn't a kit: expected a directory, a Smolfile or a kit descriptor",
        path.display()
    )
}

/// A canonical host path when REF is path-like (or exists relative to the cwd), else `None`.
fn local_path<R: Runner>(ctx: &Ctx<R>, reference: &str) -> Result<Option<PathBuf>> {
    let path = if let Some(rest) = reference.strip_prefix("~/") {
        let home = ctx.env.get("HOME").context("HOME is not set")?;
        Path::new(home).join(rest)
    } else {
        ctx.cwd.join(reference)
    };
    let looks_local = ["/", "./", "../", "~/"]
        .iter()
        .any(|p| reference.starts_with(p));
    if !looks_local && !path.exists() {
        return Ok(None);
    }
    match path.canonicalize() {
        Ok(p) => Ok(Some(p)),
        Err(_) => bail!("kit path {reference} doesn't exist"),
    }
}

fn load_dir<R: Runner>(ctx: &Ctx<R>, dir: &Path) -> Result<Kit> {
    let spec = dir.join("spec.yaml");
    if spec.is_file() {
        let yaml =
            fs::read_to_string(&spec).with_context(|| format!("reading {}", spec.display()))?;
        let mut kit = v2::parse(&yaml, dir)?;
        kit.source = Source::LocalV2(dir.to_path_buf());
        return Ok(kit);
    }
    load_v3(ctx, dir)
}

fn load_v3<R: Runner>(ctx: &Ctx<R>, dir: &Path) -> Result<Kit> {
    let source = Source::LocalV3(dir.to_path_buf());
    let descriptors = fs::read_dir(dir)
        .with_context(|| format!("reading {}", dir.display()))?
        .filter_map(|e| e.ok())
        .filter(|e| is_descriptor(&e.path()))
        .count();
    match descriptors {
        0 => bail!(
            "{} isn't a kit: no spec.yaml or kit descriptor",
            dir.display()
        ),
        1 => {}
        _ => bail!(
            "{} has several kit descriptors; keep one *.yaml starting with `{}`",
            dir.display(),
            builder::SYNTAX
        ),
    }
    let built = builder::build(ctx, dir)?;
    registry::read_layout(&built, source)
}

/// A `*.yaml`/`*.yml` file whose first line is the v3 syntax line.
fn is_descriptor(path: &Path) -> bool {
    let yaml = matches!(
        path.extension().and_then(|e| e.to_str()),
        Some("yaml" | "yml")
    );
    if !yaml || !path.is_file() {
        return false;
    }
    let Ok(bytes) = fs::read(path) else {
        return false;
    };
    let first = bytes.split(|b| *b == b'\n').next().unwrap_or_default();
    String::from_utf8_lossy(first).trim_end() == builder::SYNTAX
}

/// A preset as a workload kit: the image and command, no capabilities.
pub fn preset_kit(agent: &Agent, image: &str) -> Kit {
    Kit {
        name: agent.name.to_string(),
        source: Source::Registry(image.to_string()),
        digest: None,
        kind: Kind::Workload,
        provides: vec![],
        requires: vec![],
        args: Default::default(),
        caps: vec![],
        env: vec![],
        content: Content::Image(image.to_string()),
        command: Some(agent.command.iter().map(|s| s.to_string()).collect()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agents;
    use crate::cli::testutil::*;

    fn allow_local() -> TestEnv {
        test_env(&[("SMOLBENTO_KIT_ALLOW_LOCAL", "true")])
    }

    const V2: &str = "schemaVersion: \"2\"\nkind: mixin\nname: my-kit\n";

    #[test]
    fn a_v2_directory_loads_as_v2() {
        let t = allow_local();
        let dir = t.ctx.cwd.join("kit");
        fs::create_dir(&dir).unwrap();
        fs::write(dir.join("spec.yaml"), V2).unwrap();
        let k = load(&t.ctx, "./kit").unwrap();
        assert_eq!(k.name, "my-kit");
        assert_eq!(k.source, Source::LocalV2(dir.canonicalize().unwrap()));
        assert!(t.ctx.vm.runner().call_lines().is_empty());
    }

    #[test]
    fn a_bare_relative_name_that_exists_is_a_path() {
        let t = allow_local();
        let dir = t.ctx.cwd.join("kit");
        fs::create_dir(&dir).unwrap();
        fs::write(dir.join("spec.yaml"), V2).unwrap();
        assert_eq!(load(&t.ctx, "kit").unwrap().name, "my-kit");
    }

    #[test]
    fn a_smolfile_path_loads_as_smolfile() {
        let t = allow_local();
        let p = t.ctx.cwd.join("dev.smolfile");
        fs::write(&p, "image = \"alpine\"\n").unwrap();
        let k = load(&t.ctx, "dev.smolfile").unwrap();
        assert_eq!(k.source, Source::Smolfile(p.canonicalize().unwrap()));
    }

    #[test]
    fn a_refused_local_source_fails_before_any_runner_call() {
        let t = test_env(&[("SMOLBENTO_KIT_ALLOW_LOCAL", "false")]);
        let dir = t.ctx.cwd.join("kit");
        fs::create_dir(&dir).unwrap();
        fs::write(
            dir.join("k.yaml"),
            "# syntax=docker/sandbox-kit:3\nschemaVersion: \"3\"\nkind: mixin\n",
        )
        .unwrap();
        let e = load(&t.ctx, "./kit").unwrap_err();
        assert!(
            format!("{e:#}").contains("local kits are disabled"),
            "{e:#}"
        );
        assert!(t.ctx.vm.runner().call_lines().is_empty());
    }

    #[test]
    fn trust_is_checked_before_the_directory_is_classified() {
        let t = test_env(&[("SMOLBENTO_KIT_ALLOW_LOCAL", "false")]);
        fs::create_dir(t.ctx.cwd.join("empty")).unwrap();
        let e = load(&t.ctx, "./empty").unwrap_err();
        assert!(
            format!("{e:#}").contains("local kits are disabled"),
            "{e:#}"
        );
    }

    /// A directory `twin-kit` with two v3 descriptors.
    fn twin_kit(t: &TestEnv) -> PathBuf {
        let dir = t.ctx.cwd.join("twin-kit");
        fs::create_dir(&dir).unwrap();
        for n in ["a.yaml", "b.yaml"] {
            fs::write(dir.join(n), "# syntax=docker/sandbox-kit:3\nkind: mixin\n").unwrap();
        }
        dir.canonicalize().unwrap()
    }

    #[test]
    fn several_descriptors_are_an_error_for_a_directory_and_for_a_file() {
        for r in ["./twin-kit", "./twin-kit/a.yaml"] {
            let t = allow_local();
            let dir = twin_kit(&t);
            let m = format!("{:#}", load(&t.ctx, r).unwrap_err());
            assert!(
                m.contains("several kit descriptors") && m.contains(&dir.display().to_string()),
                "{m}"
            );
            assert!(t.ctx.vm.runner().call_lines().is_empty(), "{r}");
        }
    }

    #[test]
    fn a_descriptor_file_builds_its_parent_directory() {
        use crate::kits::registry::fixtures::oci_layout;
        let t = allow_local();
        let dir = t.ctx.cwd.join("kit");
        fs::create_dir(&dir).unwrap();
        fs::write(
            dir.join("m.yaml"),
            "# syntax=docker/sandbox-kit:3\nschemaVersion: \"3\"\nkind: mixin\n",
        )
        .unwrap();
        // What `docker buildx --output type=oci` hands back, as a tar of the layout.
        let out = tempfile::tempdir().unwrap();
        oci_layout(
            out.path(),
            Some(r#"{"schemaVersion":"3","kind":"mixin","name":"m"}"#),
            &[],
            "{}",
        );
        let mut b = tar::Builder::new(Vec::new());
        b.append_dir_all(".", out.path()).unwrap();
        let fake = t.ctx.vm.runner();
        fake.ok(
            &["machine", "status"],
            &machine_json(
                "sbx-_builder",
                "running",
                &[("sbx.name", "_builder"), ("sbx.docker", "true")],
            ),
        )
        .download(&b.into_inner().unwrap());
        let k = load(&t.ctx, "./kit/m.yaml").unwrap();
        // The source is the parent directory, the build context buildx was given.
        assert_eq!(k.source, Source::LocalV3(dir.canonicalize().unwrap()));
        let lines = fake.call_lines();
        assert!(
            lines.iter().any(|l| l.starts_with("machine cp /")),
            "{lines:?}"
        );
    }

    #[test]
    fn a_missing_path_and_a_non_kit_directory_are_errors() {
        let t = allow_local();
        let e = load(&t.ctx, "./nope").unwrap_err();
        assert!(
            format!("{e:#}").contains("kit path ./nope doesn't exist"),
            "{e:#}"
        );
        fs::create_dir(t.ctx.cwd.join("empty")).unwrap();
        let e = load(&t.ctx, "./empty").unwrap_err();
        assert!(
            format!("{e:#}").contains("no spec.yaml or kit descriptor"),
            "{e:#}"
        );
    }

    #[test]
    fn a_disallowed_registry_ref_is_refused_before_pulling() {
        let t = test_env(&[("SMOLBENTO_KIT_SOURCES", "ghcr.io/ok/*")]);
        let e = load(&t.ctx, "evil.example/x/y:1").unwrap_err();
        assert!(format!("{e:#}").contains("isn't allowed"), "{e:#}");
    }

    #[test]
    fn preset_kit_keeps_image_and_command() {
        let a = agents::find("claude").unwrap();
        let k = preset_kit(a, "img:1");
        assert_eq!(k.name, "claude");
        assert_eq!(k.kind, Kind::Workload);
        assert_eq!(k.content, Content::Image("img:1".into()));
        assert_eq!(k.source, Source::Registry("img:1".into()));
        assert_eq!(
            k.command.unwrap(),
            a.command.iter().map(|s| s.to_string()).collect::<Vec<_>>()
        );
    }
}
