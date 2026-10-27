//! Kit argument values (`--kit-arg`, `--kit-args-file`) and `${{ kit.* }}` placeholder expansion.

use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::{Context, Result, anyhow, bail};
use regex_lite::Regex;

use crate::kits::model::{ArgDef, Kit};

#[derive(Debug, Default)]
pub struct ArgValues {
    shared: BTreeMap<String, String>,
    /// Keyed by (kit name, arg name).
    scoped: BTreeMap<(String, String), String>,
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

    /// The effective values for one kit: scoped beats shared beats default. Errors on an
    /// invalid pattern (given a value or not), missing required, pattern/enum mismatch. Unknown
    /// names are checked by `check_unknown`.
    pub fn for_kit(&self, kit: &Kit) -> Result<BTreeMap<String, String>> {
        let mut out = BTreeMap::new();
        for (name, def) in &kit.args {
            let re = def
                .pattern
                .as_deref()
                .map(|p| Regex::new(p).with_context(|| format!("invalid pattern {p:?}")))
                .transpose()
                .with_context(|| format!("kit {}: argument {name}", kit.name))?;
            let given = self
                .scoped
                .get(&(kit.name.clone(), name.clone()))
                .or_else(|| self.shared.get(name))
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

    /// Every given name must be declared by at least one kit (scoped: by that kit).
    pub fn check_unknown(&self, kits: &[Kit]) -> Result<()> {
        for name in self.shared.keys() {
            if !kits.iter().any(|k| k.args.contains_key(name)) {
                bail!("unknown kit argument {name}");
            }
        }
        for (kit, name) in self.scoped.keys() {
            let Some(k) = kits.iter().find(|k| &k.name == kit) else {
                bail!("unknown kit {kit} in argument {kit}.{name}");
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
        bail!("the value does not match pattern {:?}", re.as_str());
    }
    Ok(())
}

/// Expands `${{ kit.args.NAME }}` and `${{ kit.env.NAME }}`; undeclared names are errors.
/// `$VAR` and `${VAR}` are left for the shell.
pub fn expand(
    s: &str,
    args: &BTreeMap<String, String>,
    env: &BTreeMap<String, String>,
) -> Result<String> {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(start) = rest.find("${{") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 3..];
        let end = after
            .find("}}")
            .ok_or_else(|| anyhow!("unterminated placeholder in {s:?}"))?;
        let expr = after[..end].trim();
        let value = if let Some(n) = expr.strip_prefix("kit.args.") {
            args.get(n)
                .ok_or_else(|| anyhow!("undeclared kit argument {n:?} in placeholder"))?
        } else if let Some(n) = expr.strip_prefix("kit.env.") {
            env.get(n)
                .ok_or_else(|| anyhow!("undeclared kit env {n:?} in placeholder"))?
        } else {
            bail!("unsupported placeholder {expr:?}");
        };
        out.push_str(value);
        rest = &after[end + 2..];
    }
    out.push_str(rest);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kits::model::{Content, Kind, Source};

    fn kit(name: &str, args: &[(&str, ArgDef)]) -> Kit {
        Kit {
            name: name.into(),
            source: Source::Registry(name.into()),
            digest: None,
            kind: Kind::Mixin,
            provides: vec![],
            requires: vec![],
            args: args
                .iter()
                .map(|(n, d)| (n.to_string(), d.clone()))
                .collect(),
            caps: vec![],
            env: vec![],
            content: Content::None,
            command: None,
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
    fn scoped_unknown_kit_or_arg_is_rejected() {
        let k = kit("k", &[("a", ArgDef::default())]);
        let v = ArgValues::parse(&[], &["other.a=1".into()]).unwrap();
        assert!(v.check_unknown(std::slice::from_ref(&k)).is_err());
        let v = ArgValues::parse(&[], &["k.zzz=1".into()]).unwrap();
        assert!(v.check_unknown(std::slice::from_ref(&k)).is_err());
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
        assert_eq!(
            expand("${{ kit.env.HOME }}/v${{kit.args.v}}", &a, &e).unwrap(),
            "/home/agent/v1.2"
        );
        assert!(expand("${{ kit.args.x }}", &a, &e).is_err());
        assert!(expand("${{ kit.args.v", &a, &e).is_err());
        assert_eq!(
            expand("$HOME ${HOME} stay", &a, &e).unwrap(),
            "$HOME ${HOME} stay"
        );
    }
}
