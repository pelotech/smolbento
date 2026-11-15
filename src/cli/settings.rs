use anyhow::Result;
use std::io::Write;

use super::{Ctx, SettingsCmd, table};
use crate::config::{SETTINGS, Settings, Source};
use crate::smolvm::Runner;

pub fn run<R: Runner>(ctx: &mut Ctx<R>, cmd: SettingsCmd) -> Result<i32> {
    match cmd {
        SettingsCmd::Ls {
            no_trunc,
            quiet,
            output,
        } => {
            let docs = SETTINGS
                .iter()
                .map(|d| doc(&ctx.settings, d))
                .collect::<Result<Vec<_>>>()?;
            let text = if quiet {
                SETTINGS.iter().map(|d| format!("{}\n", d.key)).collect()
            } else {
                match output.structured(&docs)? {
                    Some(s) => s,
                    None => render(&ctx.settings, no_trunc)?,
                }
            };
            write!(&ctx.out, "{text}")?
        }
        SettingsCmd::Get { key, output } => {
            let value = ctx.settings.value(&key)?;
            let def = SETTINGS.iter().find(|d| d.key == key);
            match def.map(|d| doc(&ctx.settings, d)).transpose()? {
                Some(d) if output.pick() != super::Format::Table => {
                    write!(&ctx.out, "{}", output.structured(&d)?.unwrap_or_default())?
                }
                _ => writeln!(&ctx.out, "{value}")?,
            }
        }
        SettingsCmd::Set { key, value } => ctx.settings.set(&key, &value)?,
        SettingsCmd::Unset { key } => ctx.settings.unset(&key)?,
    }
    Ok(0)
}

/// A setting as sbx's `--json` shows one: `{default, description, key, source, type, value}`.
/// Booleans are JSON booleans; everything else is a string.
fn doc(settings: &Settings, def: &crate::config::SettingDef) -> Result<serde_json::Value> {
    let (value, source) = settings.get(def.key)?;
    let is_bool = matches!(def.default, "true" | "false");
    let typed = |v: &str| match v {
        "true" if is_bool => serde_json::Value::Bool(true),
        "false" if is_bool => serde_json::Value::Bool(false),
        other => other.into(),
    };
    Ok(serde_json::json!({
        "default": typed(def.default),
        "description": def.help,
        "key": def.key,
        "source": match source {
            Source::Env => "envvar",
            Source::File => "override",
            Source::Default => "default",
        },
        "type": if is_bool { "bool" } else { "string" },
        "value": typed(&value),
    }))
}

pub fn render(settings: &Settings, no_trunc: bool) -> Result<String> {
    let mut rows = vec![vec![
        "KEY".into(),
        "VALUE".into(),
        "SOURCE".into(),
        "DESCRIPTION".into(),
    ]];
    for def in SETTINGS {
        let (value, source) = settings.get(def.key)?;
        let source = match source {
            Source::Env => format!("env ({})", def.env),
            Source::File => "config".into(),
            Source::Default => "default".into(),
        };
        let help = if no_trunc || def.help.chars().count() <= 50 {
            def.help.to_string()
        } else {
            format!("{}…", def.help.chars().take(49).collect::<String>())
        };
        rows.push(vec![def.key.into(), value, source, help]);
    }
    Ok(table(rows))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;

    #[test]
    fn set_get_unset() {
        let mut t = test_env(&[]);
        t.sbt(&["settings", "set", "docker.enabled", "false"])
            .unwrap();
        assert_eq!(t.ctx.settings.value("docker.enabled").unwrap(), "false");
        let listing = render(&t.ctx.settings, true).unwrap();
        let row = listing
            .lines()
            .find(|l| l.starts_with("docker.enabled"))
            .unwrap();
        assert_eq!(
            row.split_whitespace().take(3).collect::<Vec<_>>(),
            vec!["docker.enabled", "false", "config"]
        );
        t.sbt(&["settings", "unset", "docker.enabled"]).unwrap();
        assert_eq!(t.ctx.settings.value("docker.enabled").unwrap(), "true");
        assert!(t.sbt(&["settings", "get", "nope"]).is_err());
    }

    #[test]
    fn ls_and_get_as_json_and_quiet() {
        let mut t = test_env(&[("SMOLBENTO_DOCKER", "false")]);
        t.sbt(&["settings", "get", "docker.enabled", "--json"])
            .unwrap();
        let v: serde_json::Value = serde_json::from_str(&t.stdout()).unwrap();
        assert_eq!(
            v,
            serde_json::json!({
                "default": true,
                "description": "Use Docker-enabled agent images and run a private dockerd in each sandbox",
                "key": "docker.enabled",
                "source": "envvar",
                "type": "bool",
                "value": false,
            })
        );
        t.sbt(&["settings", "get", "docker.enabled"]).unwrap();
        assert_eq!(t.stdout(), "false\n");
        t.sbt(&["settings", "ls", "--format", "json"]).unwrap();
        let all: Vec<serde_json::Value> = serde_json::from_str(&t.stdout()).unwrap();
        assert_eq!(all.len(), SETTINGS.len());
        assert_eq!(all[0]["key"], SETTINGS[0].key);
        t.sbt(&["settings", "ls", "-q"]).unwrap();
        let keys = t.stdout();
        assert_eq!(keys.lines().count(), SETTINGS.len());
        assert_eq!(keys.lines().next(), Some(SETTINGS[0].key));
    }

    #[test]
    fn set_validates_kit_allowed_sources() {
        let mut t = test_env(&[]);
        for bad in ["docker.io/", "[1]", r#"[""]"#, r#"["docker.io/", ""]"#] {
            let e = t.sbt_err(&["settings", "set", "kit.allowedSources", bad]);
            assert!(e.contains("kit.allowedSources"), "{bad}: {e}");
        }
        assert_eq!(
            t.ctx.settings.value("kit.allowedSources").unwrap(),
            r#"["docker.io/","ghcr.io/pelotech/smolbento/"]"#,
            "a refused value is not saved"
        );
        t.sbt(&[
            "settings",
            "set",
            "kit.allowedSources",
            r#"["ghcr.io","*"]"#,
        ])
        .unwrap();
        assert_eq!(
            t.ctx.settings.value("kit.allowedSources").unwrap(),
            r#"["ghcr.io","*"]"#
        );
    }

    #[test]
    fn ls_lists_the_clone_fetch_on_exit_setting() {
        let t = test_env(&[]);
        let listing = render(&t.ctx.settings, true).unwrap();
        let row = listing
            .lines()
            .find(|l| l.starts_with("clone.fetch-on-exit"))
            .expect("listed");
        assert_eq!(
            row.split_whitespace().take(3).collect::<Vec<_>>(),
            vec!["clone.fetch-on-exit", "true", "default"]
        );
    }
}
