//! One `sbxenv.yaml`: read and tokenize, substitute references, make paths absolute, type-check.
//!
//! References (`${{ ... }}`) are swapped for tokens before parsing, so the YAML parser sees plain
//! words in every context. `expand` puts the text back, after the arg values are known.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use anyhow::{Context, Result, bail};
use regex_lite::Regex;
use serde::Deserialize;
use serde_json::{Map, Value};

const ESCAPE: &str = "__sbxenv_esc__";

static REF: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\$\{\{\s*([^}]*?)\s*\}\}").unwrap());
// What may precede a plain scalar that is a whole value: `key: ` or `- `, never a quote.
static BEFORE_OK: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"^\s*(?:-\s+)*(?:[^\s"'\-#][^"']*:\s+)?$"#).unwrap());
static TOKEN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"__sbxenv_(?:ref_(\d+)|esc)__").unwrap());

/// One file, read and tokenized; references not yet substituted.
pub struct RawFile {
    pub path: PathBuf,
    pub dir: PathBuf,
    pub value: Value,
    refs: Vec<Ref>,
}

struct Ref {
    expr: String,
    line: usize,
    /// The whole value of a plain (unquoted) `key:` or `- ` scalar.
    alone: bool,
}

#[derive(Deserialize, Default, Clone, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArgDecl {
    pub default: Option<String>,
    pub required: Option<bool>,
    pub description: Option<String>,
    pub r#enum: Option<Vec<String>>,
    pub pattern: Option<String>,
}

/// The typed file. Every field optional (required ones are checked after merging).
#[derive(Deserialize, Default, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EnvFile {
    pub schema_version: Option<String>,
    pub name: Option<String>,
    pub agent: Option<String>,
    pub args: Option<BTreeMap<String, ArgDecl>>,
    pub kits: Option<Vec<KitEntry>>,
    pub workspace: Option<Workspace>,
    pub additional_workspaces: Option<Vec<ExtraWorkspace>>,
    pub env: Option<BTreeMap<String, String>>,
    pub ports: Option<Vec<Port>>,
    pub secrets: Option<BTreeMap<String, SecretDecl>>,
    pub sandbox_options: Option<SandboxOptions>,
    // Out of scope: kept as raw values so they can be refused by name.
    pub lifecycle: Option<Value>,
    pub bindings: Option<Value>,
    pub registries: Option<Value>,
    pub mcp: Option<Value>,
    pub mounts: Option<Value>,
}

#[derive(Deserialize, Debug)]
#[serde(untagged)]
pub enum KitEntry {
    Source(String),
    Pinned {
        source: String,
        args: Option<BTreeMap<String, String>>,
    },
}

#[derive(Deserialize, Debug)]
#[serde(untagged)]
pub enum Workspace {
    Path(String),
    Object { path: String, clone: Option<bool> },
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExtraWorkspace {
    pub path: String,
    pub read_only: Option<bool>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Port {
    pub sandbox: u16,
    pub host: Option<u16>,
    pub protocol: Option<String>,
    #[serde(rename = "hostIP")]
    pub host_ip: Option<String>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecretDecl {
    pub value: Option<String>,
    pub r#ref: Option<String>,
    pub command: Option<String>,
    pub snapshot: Option<bool>,
    pub refresh: Option<String>,
    pub backend: Option<String>,
    pub no_verify: Option<bool>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SandboxOptions {
    pub template: Option<String>,
    pub memory: Option<String>,
    pub cpus: Option<u32>,
    pub pull_policy: Option<String>,
    pub profile: Option<Value>,
    pub skills: Option<Value>,
    pub display: Option<Value>,
    pub gpu: Option<Value>,
    pub usb: Option<Value>,
    pub writable_env_files: Option<Value>,
}

pub fn read(path: &Path) -> Result<RawFile> {
    let path = std::path::absolute(path)?;
    let dir = path.parent().map(Path::to_path_buf).unwrap_or_default();
    let text =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    let (tokenized, refs) = tokenize(&text);
    let mut value: Value = serde_saphyr::from_str(&tokenized)
        .map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;
    if value.is_null() {
        value = Value::Object(Map::new());
    }
    let file = RawFile {
        path,
        dir,
        value,
        refs,
    };
    file.check_placement()?;
    Ok(file)
}

/// Replaces `$${{` and `${{ expr }}` with tokens, recording each reference.
fn tokenize(text: &str) -> (String, Vec<Ref>) {
    let escaped = text.replace("$${{", ESCAPE);
    let mut out = String::new();
    let mut refs = Vec::new();
    let mut last = 0;
    for c in REF.captures_iter(&escaped) {
        let m = c.get(0).unwrap();
        let line_start = escaped[..m.start()].rfind('\n').map_or(0, |i| i + 1);
        let line_end = escaped[m.end()..]
            .find('\n')
            .map_or(escaped.len(), |i| m.end() + i);
        let before = &escaped[line_start..m.start()];
        let after = &escaped[m.end()..line_end];
        let after_ok = after.trim().is_empty()
            || (after.starts_with(char::is_whitespace) && after.trim_start().starts_with('#'));
        out.push_str(&escaped[last..m.start()]);
        out.push_str(&format!("__sbxenv_ref_{}__", refs.len()));
        last = m.end();
        refs.push(Ref {
            expr: c[1].to_string(),
            line: escaped[..m.start()].matches('\n').count() + 1,
            alone: !before.trim().is_empty() && BEFORE_OK.is_match(before) && after_ok,
        });
    }
    out.push_str(&escaped[last..]);
    (out, refs)
}

fn has_token(s: &str) -> bool {
    s.contains("__sbxenv_ref_")
}

impl RawFile {
    fn name(&self) -> String {
        self.path.display().to_string()
    }

    /// References aren't allowed in field names or the `args:` block.
    fn check_placement(&self) -> Result<()> {
        fn walk(v: &Value, in_args: bool) -> bool {
            match v {
                Value::Object(m) => m.iter().any(|(k, x)| has_token(k) || walk(x, in_args)),
                Value::Array(a) => a.iter().any(|x| walk(x, in_args)),
                Value::String(s) => in_args && has_token(s),
                _ => false,
            }
        }
        let bad = match &self.value {
            Value::Object(m) => m.iter().any(|(k, x)| has_token(k) || walk(x, k == "args")),
            _ => false,
        };
        if bad {
            bail!(
                "{}: references aren't allowed in field names or the args: block",
                self.name()
            );
        }
        Ok(())
    }

    /// The `args` block as written (refs aren't allowed there), or an empty map.
    pub fn args(&self) -> Result<BTreeMap<String, ArgDecl>> {
        let Some(block) = self.value.get("args") else {
            return Ok(BTreeMap::new());
        };
        let block = self.substitute(block, &BTreeMap::new(), Path::new(""))?;
        serde_json::from_value(block).map_err(|e| anyhow::anyhow!("{}: args: {e}", self.name()))
    }

    /// Substitutes references, makes relative paths absolute, and type-checks the result.
    pub fn expand(&self, args: &BTreeMap<String, String>, project_dir: &Path) -> Result<Value> {
        let mut value = self.substitute(&self.value, args, project_dir)?;
        self.absolutize(&mut value);
        self.type_check(&value)?;
        Ok(value)
    }

    fn text_of(
        &self,
        r: &Ref,
        args: &BTreeMap<String, String>,
        project_dir: &Path,
    ) -> Result<String> {
        if let Some(name) = r.expr.strip_prefix("env.args.") {
            return match args.get(name) {
                Some(v) => Ok(v.clone()),
                None => bail!(
                    "the environment references an argument it does not declare: {name} ({}:{}); every ${{{{ env.args.<name> }}}} must be declared in the file's args: block",
                    self.name(),
                    r.line
                ),
            };
        }
        match r.expr.as_str() {
            "env.projectDir" => Ok(project_dir.display().to_string()),
            "env.fileDir" => Ok(self.dir.display().to_string()),
            other => bail!(
                "{}:{}: unknown reference ${{{{ {other} }}}}; use env.args.<name>, env.projectDir or env.fileDir",
                self.name(),
                r.line
            ),
        }
    }

    fn substitute(
        &self,
        v: &Value,
        args: &BTreeMap<String, String>,
        project_dir: &Path,
    ) -> Result<Value> {
        Ok(match v {
            Value::Object(m) => Value::Object(
                m.iter()
                    .map(|(k, x)| Ok((k.clone(), self.substitute(x, args, project_dir)?)))
                    .collect::<Result<_>>()?,
            ),
            Value::Array(a) => Value::Array(
                a.iter()
                    .map(|x| self.substitute(x, args, project_dir))
                    .collect::<Result<_>>()?,
            ),
            Value::String(s) => self.substitute_str(s, args, project_dir)?,
            other => other.clone(),
        })
    }

    fn substitute_str(
        &self,
        s: &str,
        args: &BTreeMap<String, String>,
        project_dir: &Path,
    ) -> Result<Value> {
        let index =
            |c: &regex_lite::Captures| c.get(1).and_then(|n| n.as_str().parse::<usize>().ok());
        // A plain scalar that is exactly one reference becomes a number or bool when the text is
        // one; anything else stays the text as written.
        if let Some(c) = TOKEN.captures(s).filter(|c| c[0].len() == s.len())
            && let Some(r) = index(&c).and_then(|n| self.refs.get(n)).filter(|r| r.alone)
        {
            let text = self.text_of(r, args, project_dir)?;
            return Ok(match serde_saphyr::from_str::<Value>(&text) {
                Ok(v) if v.is_number() || v.is_boolean() => v,
                _ => Value::String(text),
            });
        }
        let mut out = String::new();
        let mut last = 0;
        for c in TOKEN.captures_iter(s) {
            let m = c.get(0).unwrap();
            out.push_str(&s[last..m.start()]);
            match index(&c).and_then(|n| self.refs.get(n)) {
                Some(r) => out.push_str(&self.text_of(r, args, project_dir)?),
                None => out.push_str("${{"),
            }
            last = m.end();
        }
        out.push_str(&s[last..]);
        Ok(Value::String(out))
    }

    /// Relative `workspace`, `additionalWorkspaces[].path` and local kit sources become absolute
    /// against the file's directory (symlinks are not resolved).
    fn absolutize(&self, value: &mut Value) {
        let abs = |s: &mut String| {
            if let Ok(p) = std::path::absolute(self.dir.join(&*s)) {
                *s = lexical(&p).display().to_string();
            }
        };
        let local = |s: &str| s == "." || s == ".." || s.starts_with("./") || s.starts_with("../");
        let fix = |v: &mut Value, key: &str, only_local: bool| {
            let slot = match v {
                Value::Object(m) => m.get_mut(key),
                _ => None,
            };
            if let Some(Value::String(s)) = slot
                && (!only_local || local(s))
            {
                abs(s);
            }
        };
        let Value::Object(top) = value else { return };
        match top.get_mut("workspace") {
            Some(Value::String(s)) => abs(s),
            Some(w) => fix(w, "path", false),
            None => {}
        }
        if let Some(Value::Array(list)) = top.get_mut("additionalWorkspaces") {
            list.iter_mut().for_each(|w| fix(w, "path", false));
        }
        if let Some(Value::Array(list)) = top.get_mut("kits") {
            for k in list {
                match k {
                    Value::String(s) if local(s) => abs(s),
                    other => fix(other, "source", true),
                }
            }
        }
    }

    fn type_check(&self, value: &Value) -> Result<()> {
        let Err(e) = serde_json::from_value::<EnvFile>(value.clone()) else {
            return Ok(());
        };
        let msg = e.to_string();
        if let Some(field) = msg
            .strip_prefix("unknown field `")
            .and_then(|r| r.split('`').next())
        {
            bail!("{}: unknown field \"{field}\"", self.name());
        }
        match culprit(value) {
            Some(path) => bail!("{}: {path}: {msg}", self.name()),
            None => bail!("{}: {msg}", self.name()),
        }
    }
}

/// Folds `..` away by name (std's `absolute` keeps it), without touching the filesystem.
fn lexical(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            std::path::Component::ParentDir => {
                out.pop();
            }
            c => out.push(c),
        }
    }
    out
}

enum Seg {
    Key(String),
    Idx(usize),
}

/// The field path whose value alone makes the file fail to type-check (serde doesn't name it).
fn culprit(root: &Value) -> Option<String> {
    fn wrap(path: &[Seg], leaf: Value) -> Value {
        path.iter().rev().fold(leaf, |inner, seg| match seg {
            Seg::Key(k) => Value::Object(Map::from_iter([(k.clone(), inner)])),
            Seg::Idx(_) => Value::Array(vec![inner]),
        })
    }
    // A child on its own can lack siblings the parent requires; that isn't its fault.
    let fails = |path: &[Seg], leaf: &Value| {
        serde_json::from_value::<EnvFile>(wrap(path, leaf.clone()))
            .err()
            .is_some_and(|e| !e.to_string().starts_with("missing field"))
    };
    let mut path = Vec::new();
    let mut at = root;
    'down: loop {
        let children: Vec<(Seg, &Value)> = match at {
            Value::Object(m) => m.iter().map(|(k, x)| (Seg::Key(k.clone()), x)).collect(),
            Value::Array(a) => a
                .iter()
                .enumerate()
                .map(|(i, x)| (Seg::Idx(i), x))
                .collect(),
            _ => break,
        };
        for (seg, child) in children {
            path.push(seg);
            if fails(&path, child) {
                at = child;
                continue 'down;
            }
            path.pop();
        }
        break;
    }
    if path.is_empty() {
        return None;
    }
    let mut out = String::new();
    for seg in &path {
        match seg {
            Seg::Key(k) if out.is_empty() => out.push_str(k),
            Seg::Key(k) => out.push_str(&format!(".{k}")),
            Seg::Idx(i) => out.push_str(&format!("[{i}]")),
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load(yaml: &str) -> (tempfile::TempDir, RawFile) {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("sbxenv.yaml");
        std::fs::write(&p, yaml).unwrap();
        let f = read(&p).unwrap();
        (d, f)
    }

    fn args(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn expand(yaml: &str, a: &[(&str, &str)]) -> Result<Value> {
        let (_d, f) = load(yaml);
        f.expand(&args(a), Path::new("/proj"))
    }

    #[test]
    fn unquoted_reference_is_typed_quoted_is_a_string() {
        let v = expand(
            "sandboxOptions:\n  cpus: ${{ env.args.n }}\n",
            &[("n", "4")],
        )
        .unwrap();
        assert_eq!(v["sandboxOptions"]["cpus"], 4);
        let v = expand("env:\n  N: \"${{ env.args.n }}\"\n", &[("n", "4")]).unwrap();
        assert_eq!(v["env"]["N"], "4");
        let e = expand(
            "sandboxOptions:\n  cpus: \"${{ env.args.n }}\"\n",
            &[("n", "4")],
        )
        .unwrap_err();
        assert!(e.to_string().contains("sandboxOptions.cpus"), "{e}");
    }

    #[test]
    fn bool_reference_is_typed() {
        let v = expand(
            "additionalWorkspaces:\n  - path: /x\n    readOnly: ${{ env.args.b }}\n",
            &[("b", "true")],
        )
        .unwrap();
        assert_eq!(v["additionalWorkspaces"][0]["readOnly"], true);
    }

    #[test]
    fn non_number_non_bool_text_is_kept_exactly() {
        for t in ["echo hi # note", "'x'", ""] {
            let v = expand("env:\n  X: ${{ env.args.c }}\n", &[("c", t)]).unwrap();
            assert_eq!(v["env"]["X"], t, "{t:?}");
        }
    }

    #[test]
    fn escapes_and_dollars_stay_literal() {
        let v = expand(
            "env:\n  LIT: \"$PATH:/x and $${{ env.args.c }}\"\n",
            &[("c", "1")],
        )
        .unwrap();
        assert_eq!(v["env"]["LIT"], "$PATH:/x and ${{ env.args.c }}");
    }

    #[test]
    fn dir_references_work_without_spaces() {
        let (d, f) = load("env:\n  A: ${{env.fileDir}}\n  B: ${{ env.projectDir }}\n");
        let v = f.expand(&args(&[]), Path::new("/proj")).unwrap();
        assert_eq!(v["env"]["A"], f.dir.display().to_string());
        assert_eq!(f.dir, std::path::absolute(d.path()).unwrap());
        assert_eq!(v["env"]["B"], "/proj");
    }

    #[test]
    fn substituted_text_is_not_expanded_again() {
        let v = expand(
            "env:\n  X: ${{ env.args.a }}\n",
            &[("a", "${{ env.args.x }}")],
        )
        .unwrap();
        assert_eq!(v["env"]["X"], "${{ env.args.x }}");
    }

    #[test]
    fn colon_in_a_substituted_plain_scalar_stays_one_string() {
        let v = expand("env:\n  X: ${{ env.args.a }}\n", &[("a", "k: v")]).unwrap();
        assert_eq!(v["env"]["X"], "k: v");
    }

    #[test]
    fn undeclared_argument_names_file_and_line() {
        let (_d, f) = load("agent: shell\nenv:\n  X: ${{ env.args.nope }}\n");
        let e = f
            .expand(&args(&[]), Path::new("/proj"))
            .unwrap_err()
            .to_string();
        assert!(
            e.starts_with("the environment references an argument it does not declare: nope ("),
            "{e}"
        );
        assert!(e.contains("sbxenv.yaml:3); every ${{ env.args.<name> }} must be declared in the file's args: block"), "{e}");
    }

    #[test]
    fn references_in_keys_or_args_are_refused() {
        for y in [
            "env:\n  ${{ env.args.k }}: v\n",
            "args:\n  x:\n    default: ${{ env.fileDir }}\n",
        ] {
            let d = tempfile::tempdir().unwrap();
            let p = d.path().join("sbxenv.yaml");
            std::fs::write(&p, y).unwrap();
            let e = read(&p).err().unwrap().to_string();
            assert!(
                e.contains("references aren't allowed in field names or the args: block"),
                "{e}"
            );
        }
    }

    #[test]
    fn unknown_reference_is_named() {
        let e = expand("env:\n  X: ${{ env.home }}\n", &[])
            .unwrap_err()
            .to_string();
        assert!(e.contains("env.home"), "{e}");
    }

    #[test]
    fn relative_paths_become_absolute() {
        let (_d, f) = load(
            "workspace: ./ws\nkits: [./k, org/k, /abs/k]\nadditionalWorkspaces:\n  - path: ../x\n",
        );
        let v = f.expand(&args(&[]), Path::new("/proj")).unwrap();
        let dir = f.dir.display().to_string();
        assert_eq!(v["workspace"], format!("{dir}/ws"));
        assert_eq!(
            v["kits"],
            serde_json::json!([format!("{dir}/k"), "org/k", "/abs/k"])
        );
        let parent = f.dir.parent().unwrap().display().to_string();
        assert_eq!(v["additionalWorkspaces"][0]["path"], format!("{parent}/x"));
    }

    #[test]
    fn unknown_field_is_refused_by_name() {
        let e = expand("bogus: 1\n", &[]).unwrap_err().to_string();
        assert!(e.ends_with("unknown field \"bogus\""), "{e}");
    }

    #[test]
    fn wrong_type_names_the_field_path() {
        let e = expand("sandboxOptions:\n  cpus: lots\n", &[])
            .unwrap_err()
            .to_string();
        assert!(e.contains(": sandboxOptions.cpus: "), "{e}");
        let e = expand("ports:\n  - sandbox: 80\n  - sandbox: x\n", &[])
            .unwrap_err()
            .to_string();
        assert!(e.contains(": ports[1].sandbox: "), "{e}");
    }

    #[test]
    fn args_block_reads_declarations() {
        let (_d, f) = load("args:\n  n:\n    default: \"4\"\n    enum: [\"4\", \"8\"]\n");
        let a = f.args().unwrap();
        assert_eq!(a["n"].default.as_deref(), Some("4"));
        assert_eq!(a["n"].r#enum.as_ref().unwrap().len(), 2);
    }
}
