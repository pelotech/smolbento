use anyhow::Result;
use std::io::Write;

use super::{Ctx, SettingsCmd, table};
use crate::config::{SETTINGS, Settings, Source};
use crate::smolvm::Runner;

pub fn run<R: Runner>(ctx: &mut Ctx<R>, cmd: SettingsCmd) -> Result<i32> {
    match cmd {
        SettingsCmd::Ls { no_trunc } => write!(&ctx.out, "{}", render(&ctx.settings, no_trunc)?)?,
        SettingsCmd::Get { key } => writeln!(&ctx.out, "{}", ctx.settings.value(&key)?)?,
        SettingsCmd::Set { key, value } => ctx.settings.set(&key, &value)?,
        SettingsCmd::Unset { key } => ctx.settings.unset(&key)?,
    }
    Ok(0)
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
    use super::super::testutil::*;
    use super::*;

    #[test]
    fn set_get_unset() {
        let mut t = test_env(&[]);
        sbt(&mut t.ctx, &["settings", "set", "docker.enabled", "false"]).unwrap();
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
        sbt(&mut t.ctx, &["settings", "unset", "docker.enabled"]).unwrap();
        assert_eq!(t.ctx.settings.value("docker.enabled").unwrap(), "true");
        assert!(sbt(&mut t.ctx, &["settings", "get", "nope"]).is_err());
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
