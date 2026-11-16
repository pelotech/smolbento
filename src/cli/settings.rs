use anyhow::Result;
use std::io::Write;

use super::{Ctx, SettingsCmd, table};
use crate::config::{SETTINGS, SettingDef, Settings, Source};
use crate::smolvm::Runner;

pub fn run<R: Runner>(ctx: &mut Ctx<R>, cmd: SettingsCmd) -> Result<i32> {
    match cmd {
        SettingsCmd::Ls {
            no_trunc,
            quiet,
            output,
        } => {
            let text = if quiet {
                SETTINGS.iter().map(|d| format!("{}\n", d.key)).collect()
            } else if output.is_table() {
                render(&ctx.settings, no_trunc)?
            } else {
                let docs = SETTINGS
                    .iter()
                    .map(|d| doc(&ctx.settings, d))
                    .collect::<Result<Vec<_>>>()?;
                output.structured(&docs)?.unwrap_or_default()
            };
            write!(&ctx.out, "{text}")?
        }
        SettingsCmd::Get { key, output } => {
            // An unknown key is an error before anything is printed.
            let def = Settings::def(&key)?;
            let text = match output.structured(&doc(&ctx.settings, def)?)? {
                Some(doc) => doc,
                None => format!("{}\n", ctx.settings.value(&key)?),
            };
            write!(&ctx.out, "{text}")?
        }
        SettingsCmd::Set { key, value } => ctx.settings.set(&key, &value)?,
        SettingsCmd::Unset { key } => ctx.settings.unset(&key)?,
    }
    Ok(0)
}

/// A setting as sbx's `--json` shows one: `{default, description, key, source, type, value}`.
/// Booleans are JSON booleans; everything else is a string.
fn doc(settings: &Settings, def: &SettingDef) -> Result<serde_json::Value> {
    let (value, source) = settings.get(def.key)?;
    let typed = |v: &str| match v {
        "true" if def.is_bool() => serde_json::Value::Bool(true),
        "false" if def.is_bool() => serde_json::Value::Bool(false),
        other => other.into(),
    };
    Ok(serde_json::json!({
        "default": typed(def.default),
        "description": def.help,
        "key": def.key,
        "source": source_word(source),
        "type": type_word(def),
        "value": typed(&value),
    }))
}

fn type_word(def: &SettingDef) -> &'static str {
    if def.is_bool() { "bool" } else { "string" }
}

/// sbx's words for where a value comes from.
fn source_word(source: Source) -> &'static str {
    match source {
        Source::Env => "envvar",
        Source::File => "override",
        Source::Default => "default",
    }
}

/// `text` cut to `max` characters, ending in `…` when it was longer (as sbx cuts cells).
fn cut(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    format!("{}…", text.chars().take(max - 1).collect::<String>())
}

/// sbx's listing: a table sorted by key with long cells cut, or with `no_trunc` one block per
/// setting in full. `RESTART` is sbx's (settings its daemon reads once); smolbento has none.
pub fn render(settings: &Settings, no_trunc: bool) -> Result<String> {
    let mut defs: Vec<&SettingDef> = SETTINGS.iter().collect();
    defs.sort_by_key(|d| d.key);
    let head = ["KEY", "VALUE", "TYPE", "SOURCE", "RESTART", "DESCRIPTION"];
    let mut rows = Vec::new();
    let mut blocks = String::new();
    for def in defs {
        let (value, source) = settings.get(def.key)?;
        if no_trunc {
            blocks.push_str(&format!(
                "  Key:          {}\n  Value:        {value}\n  Type:         {}\n  \
                 Source:       {}\n  Description:  {}\n\n",
                def.key,
                type_word(def),
                source_word(source),
                def.help
            ));
        } else {
            rows.push(vec![
                def.key.into(),
                cut(&value, 32),
                type_word(def).into(),
                source_word(source).into(),
                String::new(),
                cut(def.help, 48),
            ]);
        }
    }
    Ok(if no_trunc { blocks } else { table(&head, rows) })
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
        let listing = render(&t.ctx.settings, false).unwrap();
        let row = listing
            .lines()
            .find(|l| l.starts_with("docker.enabled"))
            .unwrap();
        assert_eq!(
            row.split_whitespace().take(4).collect::<Vec<_>>(),
            vec!["docker.enabled", "false", "bool", "override"]
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
    fn ls_table_is_sbxs() {
        let t = test_env(&[]);
        let table = render(&t.ctx.settings, false).unwrap();
        let mut lines = table.lines();
        assert_eq!(
            lines.next().unwrap().split_whitespace().collect::<Vec<_>>(),
            ["KEY", "VALUE", "TYPE", "SOURCE", "RESTART", "DESCRIPTION"]
        );
        // Sorted by key, with long values and descriptions cut.
        let keys: Vec<&str> = lines
            .map(|l| l.split_whitespace().next().unwrap())
            .collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted);
        let signers = table
            .lines()
            .find(|l| l.starts_with("kit.trustedSigners"))
            .unwrap();
        assert!(signers.contains("…"), "{signers}");
        assert!(table.lines().all(|l| l.chars().count() < 160), "{table}");
        // --no-trunc: one block per setting, in full.
        let blocks = render(&t.ctx.settings, true).unwrap();
        assert!(
            blocks.starts_with("  Key:          browser.enabled\n  Value:        true\n  Type:         bool\n  Source:       default\n  Description:  "),
            "{blocks}"
        );
        assert!(!blocks.contains("…"));
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
        let listing = render(&t.ctx.settings, false).unwrap();
        let row = listing
            .lines()
            .find(|l| l.starts_with("clone.fetch-on-exit"))
            .expect("listed");
        assert_eq!(
            row.split_whitespace().take(4).collect::<Vec<_>>(),
            vec!["clone.fetch-on-exit", "true", "bool", "default"]
        );
    }
}
