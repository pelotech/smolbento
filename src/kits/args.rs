//! Kit argument values (`--kit-arg`, `--kit-args-file`) and `${{ kit.* }}` placeholder expansion.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::LazyLock;

use anyhow::{Context, Result, anyhow, bail};
use regex_lite::Regex;
use serde_json::Value;

use crate::kits::model::{ArgDef, Kit};

#[derive(Debug, Default)]
pub struct ArgValues {
    shared: BTreeMap<String, String>,
    /// Keyed by (kit name, arg name).
    scoped: BTreeMap<(String, String), String>,
    /// What an sbxenv.yaml pins for one kit, keyed like `scoped`; beneath every flag.
    pinned: BTreeMap<(String, String), String>,
}

impl ArgValues {
    /// Files in order, then `--kit-arg`s; later wins. `KIT.NAME=V` is scoped.
    pub fn parse(files: &[PathBuf], flags: &[String]) -> Result<ArgValues> {
        let mut v = ArgValues::default();
        for f in files {
            let text = std::fs::read_to_string(f)
                .with_context(|| format!("reading kit args file {}", f.display()))?;
            for (i, line) in text.lines().enumerate() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                v.insert(line)
                    .with_context(|| format!("{}:{}", f.display(), i + 1))?;
            }
        }
        // Errors name the argument, never its value (it may be a token).
        for (i, flag) in flags.iter().enumerate() {
            v.insert(flag).with_context(|| match flag.split_once('=') {
                Some((name, _)) => format!("invalid --kit-arg {:?}", name.trim()),
                None => format!("invalid --kit-arg #{}", i + 1),
            })?;
        }
        Ok(v)
    }

    /// Pins `NAME=VALUE` args for the kit named `kit`.
    pub fn pin(&mut self, kit: &str, args: &[String]) -> Result<()> {
        for a in args {
            let (name, value) = a
                .split_once('=')
                .ok_or_else(|| anyhow!("kit {kit}: expected name=value"))?;
            self.pinned.insert(
                (kit.to_string(), name.trim().to_string()),
                value.to_string(),
            );
        }
        Ok(())
    }

    fn insert(&mut self, entry: &str) -> Result<()> {
        let (key, value) = entry
            .split_once('=')
            .ok_or_else(|| anyhow!("expected name=value"))?;
        let key = key.trim();
        // Arg names have no dots, so the first dot separates a non-empty kit scope.
        match key.split_once('.') {
            Some((kit, name)) if !kit.is_empty() => {
                if name.is_empty() {
                    bail!("missing argument name in {key:?}");
                }
                self.scoped
                    .insert((kit.to_string(), name.to_string()), value.to_string());
            }
            _ => {
                if key.is_empty() {
                    bail!("missing argument name");
                }
                self.shared.insert(key.to_string(), value.to_string());
            }
        }
        Ok(())
    }

    /// The effective values for one kit: scoped beats shared beats pinned beats default. Errors on an
    /// invalid pattern (given a value or not), missing required, pattern/enum mismatch. Unknown
    /// names are checked by `check_unknown`.
    pub fn for_kit(&self, kit: &Kit) -> Result<BTreeMap<String, String>> {
        let mut out = BTreeMap::new();
        for (name, def) in &kit.args {
            let re = def
                .pattern
                .as_deref()
                // SPEC §6: matched against the whole value.
                .map(|p| {
                    Regex::new(&format!("^(?:{p})$"))
                        .with_context(|| format!("invalid pattern {p:?}"))
                })
                .transpose()
                .with_context(|| format!("kit {}: argument {name}", kit.name))?;
            let given = self
                .scoped
                .get(&(kit.name.clone(), name.clone()))
                .or_else(|| self.shared.get(name))
                .or_else(|| self.pinned.get(&(kit.name.clone(), name.clone())))
                .or(def.default.as_ref());
            let Some(value) = given else {
                if def.required {
                    bail!("kit {}: argument {name} is required", kit.name);
                }
                continue;
            };
            validate(def, re.as_ref(), value)
                .with_context(|| format!("kit {}: argument {name}", kit.name))?;
            out.insert(name.clone(), value.clone());
        }
        Ok(out)
    }

    /// Every given name must be declared by at least one kit (scoped: by that kit). A scoped
    /// name for a kit not in the set is ignored, as in sbx.
    pub fn check_unknown(&self, kits: &[Kit]) -> Result<()> {
        for name in self.shared.keys() {
            if !kits.iter().any(|k| k.args.contains_key(name)) {
                bail!("unknown kit argument {name}");
            }
        }
        for (kit, name) in self.scoped.keys().chain(self.pinned.keys()) {
            let Some(k) = kits.iter().find(|k| &k.name == kit) else {
                continue;
            };
            if !k.args.contains_key(name) {
                bail!("kit {kit} does not declare argument {name}");
            }
        }
        Ok(())
    }
}

/// Checks `value` against the enum and the compiled `pattern`. Errors say which constraint
/// failed, never the value.
fn validate(def: &ArgDef, pattern: Option<&Regex>, value: &str) -> Result<()> {
    if !def.enum_values.is_empty() && !def.enum_values.iter().any(|e| e == value) {
        bail!("the value is not one of: {}", def.enum_values.join(", "));
    }
    if let Some(re) = pattern
        && !re.is_match(value)
    {
        bail!(
            "the value does not match pattern {:?}",
            def.pattern.as_deref().unwrap_or_default()
        );
    }
    Ok(())
}

/// A declared optional arg with no value and no default, used in a placeholder (sbx errors the
/// same way). An explicit empty value is a value.
#[derive(Debug, thiserror::Error)]
#[error("create-phase kit arg {0:?} has no resolved value")]
pub struct NoResolvedValue(pub String);

/// A kit reference, `${{ kit.args.NAME }}` or `${{ kit.env.NAME }}` (the spec's `argRef` and
/// `envRef`): group 1 is `args` or `env`, group 2 the name.
pub(crate) static KIT_REF: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\$\{\{\s*kit\.(args|env)\.([A-Za-z_][A-Za-z0-9_]*)\s*\}\}").unwrap()
});

/// Where a kit reference starts, well formed or not (the spec's `kitPlaceholderOpener`).
static KIT_OPENER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\$\{\{\s*kit\.(args|env)\b").unwrap());

/// Expands `${{ kit.args.NAME }}` and `${{ kit.env.NAME }}`; undeclared names are errors, and so
/// are declared ones in `unresolved` (no value, no default). Any other `${{ … }}` (a GitHub
/// Actions expression in a kit file, say) is text, as SPEC §6 has it; a malformed kit reference
/// is an error. `$VAR` and `${VAR}` are left for the shell.
pub fn expand(
    s: &str,
    args: &BTreeMap<String, String>,
    unresolved: &BTreeSet<String>,
    env: &BTreeMap<String, String>,
) -> Result<String> {
    let mut out = String::with_capacity(s.len());
    let mut done = 0;
    for open in KIT_OPENER.find_iter(s) {
        let at = &s[open.start()..];
        let reference = KIT_REF
            .captures(at)
            .filter(|c| c.get(0).is_some_and(|m| m.start() == 0))
            .ok_or_else(|| anyhow!("malformed kit placeholder in {s:?}"))?;
        let name = &reference[2];
        let value = if &reference[1] == "args" {
            match args.get(name) {
                Some(v) => v,
                None if unresolved.contains(name) => {
                    return Err(NoResolvedValue(name.into()).into());
                }
                None => bail!("undeclared kit argument {name:?} in placeholder"),
            }
        } else {
            env.get(name)
                .ok_or_else(|| anyhow!("undeclared kit env {name:?} in placeholder"))?
        };
        out.push_str(&s[done..open.start()]);
        out.push_str(value);
        done = open.start() + reference[0].len();
    }
    out.push_str(&s[done..]);
    Ok(out)
}

/// Whether a config holds a kit reference, well formed or not, in a string or a map key.
pub fn has_ref(v: &Value) -> bool {
    match v {
        Value::String(s) => KIT_OPENER.is_match(s),
        Value::Array(a) => a.iter().any(has_ref),
        Value::Object(m) => m.iter().any(|(k, x)| KIT_OPENER.is_match(k) || has_ref(x)),
        _ => false,
    }
}

/// Expands every string and map key of a capability's config with `ex` (SPEC-v3 §6): the
/// document, not its text, so a value lands whole whatever it holds. A string that is one whole
/// `kit.args` reference takes the type its value spells (`typed`), except under a key in `text`, which stays
/// text (`volume@1`'s `size` and `mode`). Two keys that expand to one are an error.
pub fn expand_value(
    v: &Value,
    text: &[&str],
    ex: &dyn Fn(&str) -> Result<String>,
) -> Result<Value> {
    Ok(match v {
        Value::String(s) if is_whole_arg_ref(s) => typed(ex(s)?),
        Value::String(s) => Value::String(ex(s)?),
        Value::Array(a) => Value::Array(
            a.iter()
                .map(|x| expand_value(x, &[], ex))
                .collect::<Result<_>>()?,
        ),
        Value::Object(m) => {
            let mut out = serde_json::Map::new();
            for (k, x) in m {
                let key = ex(k)?;
                let x = match x {
                    Value::String(s) if text.contains(&key.as_str()) => Value::String(ex(s)?),
                    x => expand_value(x, &[], ex)?,
                };
                if out.insert(key.clone(), x).is_some() {
                    bail!("two keys expand to {key:?}");
                }
            }
            Value::Object(out)
        }
        v => v.clone(),
    })
}

/// Whether `s` is nothing but a `kit.args` reference: only those take their value's type (the
/// spec's `wholeArgRef`); an environment value is always text.
fn is_whole_arg_ref(s: &str) -> bool {
    KIT_REF.captures(s).is_some_and(|c| {
        let m = c.get(0).expect("the whole match");
        m.start() == 0 && m.end() == s.len() && &c[1] == "args"
    })
}

/// The value a whole reference's text spells, when the spelling survives a round trip (the
/// spec's `typedScalar`): `true`, `8080` and `1.5` do; `1.0`, `007` and `1e5` stay text.
fn typed(s: String) -> Value {
    if let Ok(b) = s.parse::<bool>() {
        return b.into();
    }
    if let Ok(n) = s.parse::<i64>()
        && n.to_string() == s
    {
        return n.into();
    }
    if let Ok(f) = s.parse::<f64>()
        && f.is_finite()
        && f.to_string() == s
    {
        return f.into();
    }
    Value::String(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kits::model::{Kind, Source};

    fn kit(name: &str, args: &[(&str, ArgDef)]) -> Kit {
        Kit {
            args: args
                .iter()
                .map(|(n, d)| (n.to_string(), d.clone()))
                .collect(),
            ..Kit::new(name, Kind::Mixin, Source::Registry(name.into()))
        }
    }

    #[test]
    fn files_then_flags_last_wins_and_scoped_beats_shared() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("a.args");
        std::fs::write(&f, "# c\nchannel=stable\n\nteam=alpha\n").unwrap();
        let v = ArgValues::parse(&[f], &["channel=beta".into(), "m.channel=edge".into()]).unwrap();
        let m = kit(
            "m",
            &[("channel", ArgDef::default()), ("team", ArgDef::default())],
        );
        let n = kit("n", &[("channel", ArgDef::default())]);
        assert_eq!(v.for_kit(&m).unwrap()["channel"], "edge");
        assert_eq!(v.for_kit(&n).unwrap()["channel"], "beta");
        assert_eq!(v.for_kit(&m).unwrap()["team"], "alpha");
    }

    #[test]
    fn required_pattern_enum_and_unknown_fail_before_create() {
        let req = ArgDef {
            required: true,
            ..Default::default()
        };
        assert!(
            ArgValues::parse(&[], &[])
                .unwrap()
                .for_kit(&kit("k", &[("t", req)]))
                .is_err()
        );
        let pat = ArgDef {
            pattern: Some("^[0-9]+$".into()),
            ..Default::default()
        };
        let v = ArgValues::parse(&[], &["t=s3cret".into()]).unwrap();
        let e = format!("{:#}", v.for_kit(&kit("k", &[("t", pat)])).unwrap_err());
        assert_eq!(
            e,
            "kit k: argument t: the value does not match pattern \"^[0-9]+$\""
        );
        let en = ArgDef {
            enum_values: vec!["a".into(), "b".into()],
            ..Default::default()
        };
        let e = format!("{:#}", v.for_kit(&kit("k", &[("t", en)])).unwrap_err());
        assert_eq!(e, "kit k: argument t: the value is not one of: a, b");
        let v = ArgValues::parse(&[], &["nope=1".into()]).unwrap();
        assert!(v.check_unknown(&[kit("k", &[])]).is_err());
    }

    #[test]
    fn a_pattern_matches_the_whole_value() {
        // SPEC §6: an unanchored pattern still has to match all of the value.
        let pat = ArgDef {
            pattern: Some("[0-9]+|ok".into()),
            ..Default::default()
        };
        let k = kit("k", &[("t", pat)]);
        let check = |value: &str| {
            ArgValues::parse(&[], &[format!("t={value}")])
                .unwrap()
                .for_kit(&k)
                .map(|v| v["t"].clone())
        };
        assert_eq!(check("42").unwrap(), "42");
        assert_eq!(check("ok").unwrap(), "ok");
        for bad in ["abc1;rm", "42x", "okay"] {
            let e = format!("{:#}", check(bad).unwrap_err());
            assert_eq!(
                e,
                "kit k: argument t: the value does not match pattern \"[0-9]+|ok\""
            );
        }
    }

    #[test]
    fn an_invalid_pattern_is_an_error_without_a_value() {
        let bad = ArgDef {
            pattern: Some("([a-z".into()),
            ..Default::default()
        };
        let e = ArgValues::default()
            .for_kit(&kit("k", &[("t", bad)]))
            .unwrap_err();
        assert!(
            format!("{e:#}").starts_with("kit k: argument t: invalid pattern \"([a-z\""),
            "{e:#}"
        );
    }

    #[test]
    fn a_bad_flag_names_the_argument_not_its_value() {
        let e = ArgValues::parse(&[], &["=s3cret".into()]).unwrap_err();
        assert!(!format!("{e:#}").contains("s3cret"), "{e:#}");
        let e = ArgValues::parse(&[], &["ok=1".into(), "s3cret".into()]).unwrap_err();
        assert_eq!(
            format!("{e:#}"),
            "invalid --kit-arg #2: expected name=value"
        );
    }

    #[test]
    fn defaults_apply_and_values_may_contain_equals() {
        let def = ArgDef {
            default: Some("d".into()),
            ..Default::default()
        };
        let k = kit("k", &[("a", def), ("b", ArgDef::default())]);
        let v = ArgValues::parse(&[], &["b=x=y".into()]).unwrap();
        let got = v.for_kit(&k).unwrap();
        assert_eq!(got["a"], "d");
        assert_eq!(got["b"], "x=y");
        v.check_unknown(&[k]).unwrap();
    }

    #[test]
    fn a_scoped_arg_for_an_absent_kit_is_ignored_like_sbx() {
        let k = kit("k", &[("a", ArgDef::default())]);
        let v = ArgValues::parse(&[], &["other.opt=v".into()]).unwrap();
        v.check_unknown(std::slice::from_ref(&k)).unwrap();
        assert!(v.for_kit(&k).unwrap().is_empty());
        // An undeclared name on a kit in the set, or an unscoped one, is still an error.
        let v = ArgValues::parse(&[], &["k.zzz=1".into()]).unwrap();
        assert_eq!(
            v.check_unknown(std::slice::from_ref(&k))
                .unwrap_err()
                .to_string(),
            "kit k does not declare argument zzz"
        );
        let v = ArgValues::parse(&[], &["zzz=1".into()]).unwrap();
        assert_eq!(
            v.check_unknown(std::slice::from_ref(&k))
                .unwrap_err()
                .to_string(),
            "unknown kit argument zzz"
        );
        let v = ArgValues::parse(&[], &["k.a=1".into()]).unwrap();
        v.check_unknown(&[k]).unwrap();
    }

    #[test]
    fn malformed_file_line_names_file_and_line() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("bad.args");
        std::fs::write(&f, "ok=1\n\nnoequals\n").unwrap();
        let err = format!("{:#}", ArgValues::parse(&[f], &[]).unwrap_err());
        assert!(err.contains("bad.args:3"), "{err}");
    }

    #[test]
    fn expand_args_and_env_and_refuse_undeclared() {
        let a = BTreeMap::from([("v".to_string(), "1.2".to_string())]);
        let e = BTreeMap::from([("HOME".to_string(), "/home/agent".to_string())]);
        let none = BTreeSet::new();
        assert_eq!(
            expand("${{ kit.env.HOME }}/v${{kit.args.v}}", &a, &none, &e).unwrap(),
            "/home/agent/v1.2"
        );
        assert!(expand("${{ kit.args.x }}", &a, &none, &e).is_err());
        assert!(expand("${{ kit.args.v", &a, &none, &e).is_err());
        assert_eq!(
            expand("$HOME ${HOME} stay", &a, &none, &e).unwrap(),
            "$HOME ${HOME} stay"
        );
    }

    #[test]
    fn other_placeholders_are_text_and_bad_kit_ones_are_errors() {
        let a = BTreeMap::from([("v".to_string(), "1.2".to_string())]);
        let none = BTreeSet::new();
        let ex = |s: &str| expand(s, &a, &none, &BTreeMap::new());
        // SPEC §6: only kit.args and kit.env are references; a workflow in a kit file keeps its own.
        let workflow = "ref: ${{ github.sha }} v${{ kit.args.v }} ${{ kit.envy }} ${{ secrets.X";
        assert_eq!(
            ex(workflow).unwrap(),
            "ref: ${{ github.sha }} v1.2 ${{ kit.envy }} ${{ secrets.X"
        );
        for bad in [
            "${{ kit.args }}",
            "${{ kit.args.a-b }}",
            "${{ kit.env.1X }}",
            "x ${{kit.args.v",
        ] {
            let err = format!("{:#}", ex(bad).unwrap_err());
            assert_eq!(err, format!("malformed kit placeholder in {bad:?}"));
        }
    }

    /// `expand_value` with `kit.args.v` set to `value` and `kit.args.k` to `key`.
    fn expand_with(doc: Value, text: &[&str], value: &str) -> Result<Value> {
        let args = BTreeMap::from([
            ("v".to_string(), value.to_string()),
            ("k".to_string(), "key".to_string()),
        ]);
        let ex = |s: &str| expand(s, &args, &BTreeSet::new(), &BTreeMap::new());
        expand_value(&doc, text, &ex)
    }

    #[test]
    fn a_whole_reference_takes_the_type_its_value_spells() {
        let whole = serde_json::json!("${{ kit.args.v }}");
        for (value, want) in [
            ("8080", serde_json::json!(8080)),
            ("-1", serde_json::json!(-1)),
            ("1.5", serde_json::json!(1.5)),
            ("true", serde_json::json!(true)),
            // Spellings that don't survive a round trip stay text.
            ("1.0", serde_json::json!("1.0")),
            ("007", serde_json::json!("007")),
            ("1e5", serde_json::json!("1e5")),
            ("NaN", serde_json::json!("NaN")),
            ("True", serde_json::json!("True")),
            ("", serde_json::json!("")),
        ] {
            assert_eq!(
                expand_with(whole.clone(), &[], value).unwrap(),
                want,
                "{value}"
            );
        }
        // Embedded in text, or under a text key, a reference is text.
        let doc = serde_json::json!({"a": "port ${{ kit.args.v }}", "mode": "${{ kit.args.v }}"});
        assert_eq!(
            expand_with(doc, &["mode"], "755").unwrap(),
            serde_json::json!({"a": "port 755", "mode": "755"})
        );
    }

    /// The spec types a whole `kit.args` reference only: an environment value is text, so a file's
    /// `content: ${{ kit.env.IS_SANDBOX }}` stays the string "1".
    #[test]
    fn a_whole_env_reference_stays_text() {
        let env = BTreeMap::from([("IS_SANDBOX".to_string(), "1".to_string())]);
        let ex = |s: &str| expand(s, &BTreeMap::new(), &BTreeSet::new(), &env);
        let doc = serde_json::json!({"content": "${{ kit.env.IS_SANDBOX }}"});
        assert_eq!(
            expand_value(&doc, &[], &ex).unwrap(),
            serde_json::json!({"content": "1"})
        );
    }

    #[test]
    fn a_value_lands_whole_and_is_not_expanded_again() {
        let doc = serde_json::json!(["${{ kit.args.v }}", "x ${{ kit.args.v }}"]);
        let value = r#"a "quoted" \n ${{ kit.args.k }}"#;
        assert_eq!(
            expand_with(doc, &[], value).unwrap(),
            serde_json::json!([value, format!("x {value}")])
        );
    }

    /// tck: SPEC-v3 §6/expanded-key-collision-rejected
    #[test]
    fn keys_expand_and_two_that_become_one_are_an_error() {
        let doc = serde_json::json!({"${{ kit.args.k }}": 1, "other": 2});
        assert_eq!(
            expand_with(doc, &[], "").unwrap(),
            serde_json::json!({"key": 1, "other": 2})
        );
        let doc = serde_json::json!({"${{ kit.args.k }}": 1, "key": 2});
        let e = expand_with(doc, &[], "").unwrap_err();
        assert_eq!(format!("{e:#}"), r#"two keys expand to "key""#);
    }

    #[test]
    fn has_ref_finds_kit_references_in_strings_and_keys_only() {
        assert!(has_ref(&serde_json::json!({"a": ["${{ kit.args.x }}"]})));
        assert!(has_ref(&serde_json::json!({"${{ kit.env.HOME }}": 1})));
        assert!(
            has_ref(&serde_json::json!("${{ kit.args.x")),
            "malformed still counts"
        );
        assert!(!has_ref(
            &serde_json::json!({"a": "${{ github.sha }}", "b": 1})
        ));
    }
}
