//! Pick the `sbxenv.yaml` files, check their args, expand and merge them, check the result.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use regex_lite::Regex;
use serde_json::Value;

use super::file::{ArgDecl, EnvFile, RawFile, read};
use crate::cli::Unsupported;

pub struct Loaded {
    pub files: Vec<PathBuf>,
    pub project_dir: PathBuf,
    pub file: EnvFile,
}

/// `--env-args-file` paths and `--env-arg` flags.
#[derive(Default)]
pub struct ArgInputs {
    pub files: Vec<PathBuf>,
    pub flags: Vec<String>,
}

/// `paths` as given on the command line; `cwd` and `home` come from the Ctx.
pub fn load(paths: &[String], args: &ArgInputs, cwd: &Path, home: &Path) -> Result<Loaded> {
    let (files, user_default) = select(paths, cwd, home)?;
    let project_dir = match paths.first() {
        Some(p) => {
            let p = cwd.join(p);
            if p.is_dir() {
                p
            } else {
                p.parent().unwrap_or(cwd).to_path_buf()
            }
        }
        None => cwd.to_path_buf(),
    };
    let raws = files.iter().map(|f| read(f)).collect::<Result<Vec<_>>>()?;
    let first = files[0].display().to_string();
    if user_default {
        check_user_defaults(&raws[0])?;
    }

    let values = arg_values(&raws, args, &first)?;
    let mut merged = Value::Object(Default::default());
    for raw in &raws {
        let mut v = raw.expand(&values, &project_dir)?;
        if let Some(Value::String(s)) = v.get("workspace") {
            v["workspace"] = serde_json::json!({ "path": s });
        }
        merge(&mut merged, v);
    }
    let file: EnvFile =
        serde_json::from_value(merged).map_err(|e| anyhow::anyhow!("invalid {first}: {e}"))?;
    check_merged(&file, &first)?;
    check_supported(&file)?;
    Ok(Loaded {
        files,
        project_dir,
        file,
    })
}

/// The files to read, and whether the first is the user-level `~/.sbxenv.yaml`.
fn select(paths: &[String], cwd: &Path, home: &Path) -> Result<(Vec<PathBuf>, bool)> {
    let mut files = Vec::new();
    if paths.is_empty() {
        let user = home.join(".sbxenv.yaml");
        let user_default = user.is_file();
        if user_default {
            files.push(user);
        }
        let project = cwd.join("sbxenv.yaml");
        if project.is_file() {
            files.push(project);
        }
        if files.is_empty() {
            bail!(
                "no sbxenv.yaml found at {}",
                cwd.join("sbxenv.yaml").display()
            );
        }
        return Ok((files, user_default));
    }
    for p in paths {
        let p = cwd.join(p);
        if p.is_dir() {
            let f = p.join("sbxenv.yaml");
            if !f.is_file() {
                bail!("no sbxenv.yaml found at {}", f.display());
            }
            files.push(f);
        } else if p.is_file() {
            files.push(p);
        } else {
            bail!("{}: no such file", p.display());
        }
    }
    Ok((files, false))
}

fn check_user_defaults(raw: &RawFile) -> Result<()> {
    let file = raw.path.display();
    if raw.value.get("name").is_some() {
        bail!(
            "invalid {file}: \"name\" is not allowed in a user-level environment file; .sbxenv.yaml is merged beneath every project, and \"name\" identifies a single one (to keep describing one project, move the file to that project's sbxenv.yaml)"
        );
    }
    let path = match raw.value.get("workspace") {
        Some(Value::String(s)) => Some(s.as_str()),
        Some(w) => w.get("path").and_then(Value::as_str),
        None => None,
    };
    if let Some(p) = path {
        let p = raw.restore(p);
        let rooted = p == "${{ env.projectDir }}" || p.starts_with("${{ env.projectDir }}/");
        if !rooted {
            bail!(
                "invalid {file}: \"workspace\" in a user-level environment file must be rooted at ${{{{ env.projectDir }}}}, which resolves to each invocation's project directory \u{2014} write \"workspace: ${{{{ env.projectDir }}}}\" to mount each project's own directory (any other path names one directory and would mount it under every project; to keep describing one project, move the file to that project's sbxenv.yaml)"
            );
        }
    }
    Ok(())
}

/// Merges the files' declarations, checks them, and settles every argument's value.
fn arg_values(
    raws: &[RawFile],
    inputs: &ArgInputs,
    first: &str,
) -> Result<BTreeMap<String, String>> {
    let mut decls: BTreeMap<String, ArgDecl> = BTreeMap::new();
    for raw in raws {
        for (name, d) in raw.args()? {
            let at = decls.entry(name).or_default();
            at.default = d.default.or(at.default.take());
            at.required = d.required.or(at.required);
            at.description = d.description.or(at.description.take());
            at.pattern = d.pattern.or(at.pattern.take());
            match (d.r#enum, &mut at.r#enum) {
                (Some(new), Some(old)) => old.extend(new),
                (new, old) => *old = new.or(old.take()),
            }
        }
    }
    let name_ok = Regex::new(r"^[A-Za-z_][A-Za-z0-9_-]*$").unwrap();
    for (name, d) in &decls {
        if !name_ok.is_match(name) {
            bail!("invalid {first}: args[\"{name}\"]: invalid name");
        }
        if d.default.is_some() == (d.required == Some(true)) {
            bail!(
                "invalid {first}: args[\"{name}\"] must declare either a default or required: true"
            );
        }
        if d.r#enum.is_some() && d.pattern.is_some() {
            bail!("invalid {first}: args[\"{name}\"] cannot declare both enum and pattern");
        }
    }

    let mut given: Vec<(String, String)> = Vec::new();
    for f in &inputs.files {
        let text =
            std::fs::read_to_string(f).map_err(|e| anyhow::anyhow!("{}: {e}", f.display()))?;
        for (i, line) in text.lines().enumerate() {
            let t = line.trim();
            if t.is_empty() || t.starts_with('#') {
                continue;
            }
            let Some((k, v)) = t.split_once('=') else {
                bail!("{}:{}: expected NAME=VALUE", f.display(), i + 1);
            };
            given.push((k.trim().to_string(), v.to_string()));
        }
    }
    for flag in &inputs.flags {
        let Some((k, v)) = flag.split_once('=') else {
            bail!("--env-arg {flag}: expected NAME=VALUE");
        };
        given.push((k.to_string(), v.to_string()));
    }

    let mut values = BTreeMap::new();
    for (k, v) in given {
        if !decls.contains_key(&k) {
            let known: Vec<&str> = decls.keys().map(String::as_str).collect();
            bail!(
                "{first} does not declare this argument: {k}; it declares: {}",
                known.join(", ")
            );
        }
        values.insert(k, v);
    }
    for (name, d) in &decls {
        let Some(v) = values.get(name).cloned().or_else(|| d.default.clone()) else {
            bail!(
                "{first} requires an argument: {name}; supply it and re-run: --env-arg {name}=<value>"
            );
        };
        let why = match (&d.r#enum, &d.pattern) {
            (Some(allowed), _) if !allowed.contains(&v) => {
                let list: Vec<String> = allowed.iter().map(|a| format!("\"{a}\"")).collect();
                Some(format!("\"{v}\" is not one of {}", list.join(", ")))
            }
            (_, Some(p)) => {
                let re = Regex::new(&format!("^(?:{p})$")).map_err(|e| {
                    anyhow::anyhow!("invalid {first}: args[\"{name}\"]: pattern: {e}")
                })?;
                (!re.is_match(&v)).then(|| format!("\"{v}\" does not match pattern \"{p}\""))
            }
            _ => None,
        };
        if let Some(why) = why {
            bail!(
                "{first} rejected a value: {name} ({why}); its args: block declares what this argument accepts"
            );
        }
        values.insert(name.clone(), v);
    }
    Ok(values)
}

/// Objects merge by key, arrays concatenate, anything else replaces.
fn merge(base: &mut Value, over: Value) {
    match (base, over) {
        (Value::Object(a), Value::Object(b)) => {
            for (k, v) in b {
                match a.get_mut(&k) {
                    Some(slot) => merge(slot, v),
                    None => {
                        a.insert(k, v);
                    }
                }
            }
        }
        (Value::Array(a), Value::Array(b)) => a.extend(b),
        (slot, v) => *slot = v,
    }
}

fn check_merged(f: &EnvFile, first: &str) -> Result<()> {
    let Some(version) = &f.schema_version else {
        bail!("invalid {first}: schemaVersion is required");
    };
    if version != "1" {
        bail!("invalid {first}: unsupported schemaVersion \"{version}\" (supported: 1)");
    }
    if f.agent.is_none() {
        bail!("invalid {first}: agent is required");
    }
    for (name, s) in f.secrets.iter().flatten() {
        let sources = [s.value.is_some(), s.r#ref.is_some(), s.command.is_some()];
        let why = if sources.iter().filter(|x| **x).count() != 1 {
            "must specify only one of 'value', 'ref', or 'command'"
        } else if s.snapshot == Some(true) && s.refresh.is_some() {
            "snapshot cannot be combined with refresh"
        } else if s.snapshot == Some(true) && s.value.is_some() {
            "snapshot requires ref or command"
        } else if s.snapshot == Some(true) && s.no_verify == Some(true) {
            "snapshot cannot be combined with noVerify"
        } else {
            continue;
        };
        bail!("invalid {first}: secret \"{name}\": {why}");
    }
    Ok(())
}

/// Fields that parse but aren't implemented: one line each, exit 2.
fn check_supported(f: &EnvFile) -> Result<()> {
    let mut bad: Vec<String> = [
        ("lifecycle", f.lifecycle.is_some()),
        ("bindings", f.bindings.is_some()),
        ("registries", f.registries.is_some()),
        ("mcp", f.mcp.is_some()),
        ("mounts", f.mounts.is_some()),
    ]
    .iter()
    .filter(|(_, set)| *set)
    .map(|(n, _)| n.to_string())
    .collect();
    if let Some(o) = &f.sandbox_options {
        let opts = [
            ("profile", o.profile.is_some()),
            ("skills", o.skills.is_some()),
            ("display", o.display.is_some()),
            ("gpu", o.gpu.is_some()),
            ("usb", o.usb.is_some()),
            ("writableEnvFiles", o.writable_env_files.is_some()),
            (
                "pullPolicy",
                o.pull_policy.as_deref().is_some_and(|p| p != "missing"),
            ),
        ];
        bad.extend(
            opts.iter()
                .filter(|(_, set)| *set)
                .map(|(n, _)| format!("sandboxOptions.{n}")),
        );
    }
    if bad.is_empty() {
        return Ok(());
    }
    let lines: Vec<String> = bad
        .iter()
        .map(|n| format!("env: {n} is not supported yet"))
        .collect();
    Err(Unsupported(lines.join("\n")).into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env::file::Workspace;

    struct T {
        dir: tempfile::TempDir,
    }

    impl T {
        fn new() -> T {
            let t = T {
                dir: tempfile::tempdir().unwrap(),
            };
            std::fs::create_dir(t.home()).unwrap();
            std::fs::create_dir(t.cwd()).unwrap();
            t
        }
        fn home(&self) -> PathBuf {
            self.dir.path().join("home")
        }
        fn cwd(&self) -> PathBuf {
            self.dir.path().join("proj")
        }
        fn write(&self, rel: &str, text: &str) -> PathBuf {
            let p = self.dir.path().join(rel);
            std::fs::write(&p, text).unwrap();
            p
        }
        fn load(&self, paths: &[&str], args: &ArgInputs) -> Result<Loaded> {
            let paths: Vec<String> = paths.iter().map(|s| s.to_string()).collect();
            load(&paths, args, &self.cwd(), &self.home())
        }
        fn err(&self, paths: &[&str], args: &ArgInputs) -> String {
            self.load(paths, args).err().unwrap().to_string()
        }
    }

    const MIN: &str = "schemaVersion: \"1\"\nagent: claude\n";

    fn none() -> ArgInputs {
        ArgInputs::default()
    }

    fn flags(f: &[&str]) -> ArgInputs {
        ArgInputs {
            files: vec![],
            flags: f.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn sbx_base_plus_local_example() {
        let t = T::new();
        t.write(
            "proj/base.sbxenv.yaml",
            "schemaVersion: \"1\"\nname: web-app\nagent: claude\nworkspace: ./web-app\nenv:\n  NODE_ENV: development\nsandboxOptions:\n  cpus: 4\n  memory: 8g\n",
        );
        t.write(
            "proj/local.sbxenv.yaml",
            "env:\n  LOG_LEVEL: debug\nsandboxOptions:\n  memory: 12g\n",
        );
        let l = t
            .load(&["base.sbxenv.yaml", "local.sbxenv.yaml"], &none())
            .unwrap();
        let o = l.file.sandbox_options.unwrap();
        assert_eq!(o.cpus, Some(4));
        assert_eq!(o.memory.as_deref(), Some("12g"));
        let env = l.file.env.unwrap();
        assert_eq!(env["NODE_ENV"], "development");
        assert_eq!(env["LOG_LEVEL"], "debug");
        assert_eq!(l.files.len(), 2);
    }

    #[test]
    fn ports_concatenate() {
        let t = T::new();
        t.write("proj/a.yaml", &format!("{MIN}ports:\n  - sandbox: 80\n"));
        t.write("proj/b.yaml", "ports:\n  - sandbox: 81\n");
        let l = t.load(&["a.yaml", "b.yaml"], &none()).unwrap();
        assert_eq!(l.file.ports.unwrap().len(), 2);
    }

    #[test]
    fn enum_lists_concatenate() {
        let t = T::new();
        t.write(
            "proj/a.yaml",
            &format!("{MIN}args:\n  c:\n    default: stable\n    enum: [stable, beta]\n"),
        );
        t.write("proj/b.yaml", "args:\n  c:\n    enum: [nightly]\n");
        t.load(&["a.yaml", "b.yaml"], &flags(&["c=nightly"]))
            .unwrap();
        let e = t.err(&["a.yaml", "b.yaml"], &flags(&["c=other"]));
        assert!(
            e.contains("is not one of \"stable\", \"beta\", \"nightly\""),
            "{e}"
        );
    }

    #[test]
    fn override_without_schema_loads_single_file_without_it_fails() {
        let t = T::new();
        t.write("proj/a.yaml", MIN);
        t.write("proj/b.yaml", "env:\n  X: \"y\"\n");
        t.load(&["a.yaml", "b.yaml"], &none()).unwrap();
        let e = t.err(&["b.yaml"], &none());
        assert!(e.ends_with("b.yaml: schemaVersion is required"), "{e}");
        t.write("proj/c.yaml", "schemaVersion: \"1\"\n");
        assert!(
            t.err(&["c.yaml"], &none())
                .ends_with("c.yaml: agent is required")
        );
    }

    #[test]
    fn unsupported_schema_version() {
        let t = T::new();
        t.write("proj/a.yaml", "schemaVersion: \"2\"\nagent: claude\n");
        let e = t.err(&["a.yaml"], &none());
        assert!(
            e.ends_with("a.yaml: unsupported schemaVersion \"2\" (supported: 1)"),
            "{e}"
        );
    }

    #[test]
    fn selection() {
        let t = T::new();
        let cwd = t.cwd();
        let e = t.err(&[], &none());
        assert_eq!(
            e,
            format!("no sbxenv.yaml found at {}/sbxenv.yaml", cwd.display())
        );
        let e = t.err(&["."], &none());
        assert_eq!(
            e,
            format!("no sbxenv.yaml found at {}/./sbxenv.yaml", cwd.display())
        );
        assert!(
            t.err(&["nope.yaml"], &none())
                .ends_with("nope.yaml: no such file")
        );
        t.write("proj/sbxenv.yaml", MIN);
        let l = t.load(&[], &none()).unwrap();
        assert_eq!(l.project_dir, cwd);
        let l = t.load(&["."], &none()).unwrap();
        assert_eq!(l.files.len(), 1);
        t.write("proj/other.yaml", MIN);
        let l = t.load(&["other.yaml"], &none()).unwrap();
        assert_eq!(l.project_dir, cwd);
    }

    #[test]
    fn user_defaults_alone_then_beneath_project_and_skipped_with_a_path() {
        let t = T::new();
        t.write("home/.sbxenv.yaml", &format!("{MIN}env:\n  U: one\n"));
        let l = t.load(&[], &none()).unwrap();
        assert_eq!(l.files.len(), 1);
        t.write("proj/sbxenv.yaml", "env:\n  P: two\n");
        let l = t.load(&[], &none()).unwrap();
        assert_eq!(l.files.len(), 2);
        assert_eq!(l.file.env.unwrap().len(), 2);
        let e = t.err(&["sbxenv.yaml"], &none());
        assert!(e.ends_with("sbxenv.yaml: schemaVersion is required"), "{e}");
    }

    #[test]
    fn user_defaults_restrictions() {
        let t = T::new();
        t.write("home/.sbxenv.yaml", &format!("{MIN}name: x\n"));
        let e = t.err(&[], &none());
        assert!(
            e.contains(".sbxenv.yaml: \"name\" is not allowed in a user-level environment file; "),
            "{e}"
        );
        t.write("home/.sbxenv.yaml", &format!("{MIN}workspace: ./sub\n"));
        let e = t.err(&[], &none());
        assert!(e.contains("\"workspace\" in a user-level environment file must be rooted at ${{ env.projectDir }}, which"), "{e}");
        t.write(
            "home/.sbxenv.yaml",
            &format!("{MIN}workspace:\n  path: /elsewhere\n"),
        );
        assert!(t.err(&[], &none()).contains("must be rooted at"));
        for ok in ["${{ env.projectDir }}", "${{env.projectDir}}/sub"] {
            t.write("home/.sbxenv.yaml", &format!("{MIN}workspace: {ok}\n"));
            t.load(&[], &none()).unwrap();
        }
    }

    #[test]
    fn args_declaration_errors() {
        let t = T::new();
        t.write(
            "proj/a.yaml",
            &format!("{MIN}args:\n  x:\n    description: d\n"),
        );
        let e = t.err(&["a.yaml"], &none());
        assert!(
            e.ends_with("a.yaml: args[\"x\"] must declare either a default or required: true"),
            "{e}"
        );
        t.write(
            "proj/a.yaml",
            &format!("{MIN}args:\n  x:\n    default: a\n    required: true\n"),
        );
        assert!(t.err(&["a.yaml"], &none()).contains("must declare either"));
        t.write(
            "proj/a.yaml",
            &format!("{MIN}args:\n  x:\n    default: a\n    enum: [a]\n    pattern: a\n"),
        );
        assert!(
            t.err(&["a.yaml"], &none())
                .contains("both enum and pattern")
        );
        t.write(
            "proj/a.yaml",
            &format!("{MIN}args:\n  \"1x\":\n    default: a\n"),
        );
        assert!(t.err(&["a.yaml"], &none()).contains("invalid name"));
    }

    #[test]
    fn args_value_errors() {
        let t = T::new();
        t.write(
            "proj/a.yaml",
            &format!("{MIN}args:\n  channel:\n    default: stable\n    enum: [stable, beta]\n  cpus:\n    default: \"2\"\n    pattern: \"[1-9][0-9]*\"\n  x:\n    required: true\n"),
        );
        let p = t.dir.path().join("proj/a.yaml").display().to_string();
        let e = t.err(&["a.yaml"], &none());
        assert_eq!(
            e,
            format!("{p} requires an argument: x; supply it and re-run: --env-arg x=<value>")
        );
        let e = t.err(&["a.yaml"], &flags(&["nope=1"]));
        assert_eq!(
            e,
            format!("{p} does not declare this argument: nope; it declares: channel, cpus, x")
        );
        let e = t.err(&["a.yaml"], &flags(&["x=1", "channel=nightly"]));
        assert_eq!(
            e,
            format!(
                "{p} rejected a value: channel (\"nightly\" is not one of \"stable\", \"beta\"); its args: block declares what this argument accepts"
            )
        );
        for bad in ["0", "12x"] {
            let e = t.err(&["a.yaml"], &flags(&["x=1", &format!("cpus={bad}")]));
            assert!(
                e.contains(&format!(
                    "cpus (\"{bad}\" does not match pattern \"[1-9][0-9]*\")"
                )),
                "{e}"
            );
        }
        assert!(
            t.err(&["a.yaml"], &flags(&["x"]))
                .contains("expected NAME=VALUE")
        );
    }

    #[test]
    fn args_file_then_flag_precedence() {
        let t = T::new();
        t.write(
            "proj/a.yaml",
            &format!("{MIN}args:\n  a:\n    default: d\n  b:\n    default: d\nenv:\n  A: ${{{{ env.args.a }}}}\n  B: ${{{{ env.args.b }}}}\n"),
        );
        let f1 = t.write("one.env", "# c\n\na=file1=x\nb=file1\n");
        let f2 = t.write("two.env", "a=file2\n");
        let inputs = ArgInputs {
            files: vec![f1.clone(), f2],
            flags: vec!["b=flag".into()],
        };
        let env = t.load(&["a.yaml"], &inputs).unwrap().file.env.unwrap();
        assert_eq!(env["A"], "file2");
        assert_eq!(env["B"], "flag");
        let env = t
            .load(
                &["a.yaml"],
                &ArgInputs {
                    files: vec![f1.clone()],
                    flags: vec![],
                },
            )
            .unwrap()
            .file
            .env
            .unwrap();
        assert_eq!(env["A"], "file1=x");
        let bad = t.write("bad.env", "ok=1\nnoequals\n");
        let e = t.err(
            &["a.yaml"],
            &ArgInputs {
                files: vec![bad.clone()],
                flags: vec![],
            },
        );
        assert!(e.ends_with("bad.env:2: expected NAME=VALUE"), "{e}");
    }

    #[test]
    fn secret_checks() {
        let t = T::new();
        let cases = [
            (
                "{value: a, ref: b}",
                "must specify only one of 'value', 'ref', or 'command'",
            ),
            (
                "{}",
                "must specify only one of 'value', 'ref', or 'command'",
            ),
            (
                "{ref: a, snapshot: true, refresh: 1h}",
                "snapshot cannot be combined with refresh",
            ),
            (
                "{value: a, snapshot: true}",
                "snapshot requires ref or command",
            ),
            (
                "{ref: a, snapshot: true, noVerify: true}",
                "snapshot cannot be combined with noVerify",
            ),
        ];
        for (decl, why) in cases {
            t.write("proj/a.yaml", &format!("{MIN}secrets:\n  github: {decl}\n"));
            let e = t.err(&["a.yaml"], &none());
            assert!(
                e.ends_with(&format!("a.yaml: secret \"github\": {why}")),
                "{e}"
            );
        }
        t.write(
            "proj/a.yaml",
            &format!("{MIN}secrets:\n  github: {{ref: a, snapshot: true}}\n"),
        );
        t.load(&["a.yaml"], &none()).unwrap();
    }

    #[test]
    fn workspace_string_and_object_merge() {
        let t = T::new();
        t.write(
            "proj/a.yaml",
            &format!("{MIN}workspace:\n  path: ./x\n  clone: true\n"),
        );
        t.write("proj/b.yaml", "workspace: ./y\n");
        let w = t
            .load(&["a.yaml", "b.yaml"], &none())
            .unwrap()
            .file
            .workspace;
        let Some(Workspace::Object { path, clone }) = w else {
            panic!("not an object")
        };
        assert!(path.ends_with("/y"));
        assert_eq!(clone, Some(true));
    }

    #[test]
    fn out_of_scope_fields_are_one_unsupported_error() {
        let t = T::new();
        t.write(
            "proj/a.yaml",
            &format!("{MIN}lifecycle:\n  onCreate: x\nmcp:\n  - a\nsandboxOptions:\n  gpu: true\n  pullPolicy: always\n"),
        );
        let e = t.load(&["a.yaml"], &none()).err().unwrap();
        assert!(e.downcast_ref::<Unsupported>().is_some());
        assert_eq!(
            e.to_string(),
            "env: lifecycle is not supported yet\nenv: mcp is not supported yet\nenv: sandboxOptions.gpu is not supported yet\nenv: sandboxOptions.pullPolicy is not supported yet"
        );
        t.write(
            "proj/a.yaml",
            &format!("{MIN}sandboxOptions:\n  pullPolicy: missing\n"),
        );
        t.load(&["a.yaml"], &none()).unwrap();
    }
}
