//! Snapshots of --help, so changes to the sbx-compatible surface are deliberate.

use clap::CommandFactory;
use smolbento::cli::Cli;

fn help(path: &[&str]) -> String {
    let mut cmd = Cli::command();
    cmd.build();
    for name in path {
        cmd = cmd
            .find_subcommand(name)
            .expect("subcommand exists")
            .clone();
    }
    cmd.render_long_help()
        .to_string()
        .lines()
        .map(str::trim_end)
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn help_snapshots() {
    for path in [
        vec![],
        vec!["run"],
        vec!["create"],
        vec!["exec"],
        vec!["ls"],
        vec!["rm"],
        vec!["prune"],
        vec!["cp"],
        vec!["fork"],
        vec!["settings"],
        vec!["policy"],
        vec!["secret"],
        vec!["ports"],
        vec!["kit"],
        vec!["kit", "inspect"],
        vec!["kit", "validate"],
        vec!["kit", "add"],
    ] {
        let name = if path.is_empty() {
            "sbt".to_string()
        } else {
            format!("sbt-{}", path.join("-"))
        };
        insta::assert_snapshot!(name, help(&path));
    }
}
