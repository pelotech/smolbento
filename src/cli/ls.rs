//! ls: sbx's columns (SANDBOX AGENT STATUS PORTS WORKSPACE CREATED) or JSON/YAML.

use std::time::{Duration, UNIX_EPOCH};

use anyhow::Result;
use serde::Serialize;

use super::{Ctx, Format, LsArgs, table};
use crate::sandbox::{self, Sandbox};
use crate::smolvm::{MachineState, PublishedPort, Runner};

pub fn run<R: Runner>(ctx: &mut Ctx<R>, a: &LsArgs) -> Result<i32> {
    let sandboxes = sandbox::list(&ctx.vm)?;
    let format = if a.json {
        Format::Json
    } else {
        a.format.unwrap_or_default()
    };
    print!("{}", render(&sandboxes, format, a.quiet, ctx.now)?);
    Ok(0)
}

#[derive(Serialize)]
struct Row<'a> {
    name: &'a str,
    agent: &'a str,
    status: &'static str,
    ports: &'a [PublishedPort],
    workspace: Option<&'a str>,
    created_at: String,
}

fn status(state: MachineState) -> &'static str {
    match state {
        MachineState::Running => "running",
        MachineState::Stopped => "stopped",
        MachineState::Created => "created",
        MachineState::Other => "unknown",
    }
}

pub fn render(sandboxes: &[Sandbox], format: Format, quiet: bool, now: i64) -> Result<String> {
    if quiet {
        return Ok(sandboxes
            .iter()
            .map(|s| format!("{}\n", s.name()))
            .collect());
    }
    let rows: Vec<Row> = sandboxes
        .iter()
        .map(|s| Row {
            name: s.name(),
            agent: &s.meta.agent,
            status: status(s.state),
            ports: &s.ports,
            workspace: s.meta.workspace.as_deref(),
            created_at: humantime::format_rfc3339_seconds(
                UNIX_EPOCH + Duration::from_secs(s.meta.created.max(0) as u64),
            )
            .to_string(),
        })
        .collect();
    match format {
        Format::Json => Ok(format!("{}\n", serde_json::to_string_pretty(&rows)?)),
        Format::Yaml => Ok(serde_saphyr::to_string(&rows)?),
        Format::Table if rows.is_empty() => Ok("No sandboxes found\n".into()),
        Format::Table => {
            let mut lines = vec![
                [
                    "SANDBOX",
                    "AGENT",
                    "STATUS",
                    "PORTS",
                    "WORKSPACE",
                    "CREATED",
                ]
                .map(String::from)
                .to_vec(),
            ];
            for (row, sb) in rows.iter().zip(sandboxes) {
                let dot = if sb.is_running() { "●" } else { "○" };
                let ports = row
                    .ports
                    .iter()
                    .map(|p| format!("127.0.0.1:{}->{}", p.host, p.guest))
                    .collect::<Vec<_>>()
                    .join(", ");
                lines.push(vec![
                    row.name.into(),
                    row.agent.into(),
                    format!("{dot} {}", row.status),
                    ports,
                    row.workspace.unwrap_or("-").into(),
                    age(now - sb.meta.created),
                ]);
            }
            Ok(table(lines))
        }
    }
}

/// sbx-style relative age: `5s`, `2m`, `3h`, `4d`.
pub fn age(secs: i64) -> String {
    let s = secs.max(0);
    match s {
        0..60 => format!("{s}s"),
        60..3600 => format!("{}m", s / 60),
        3600..86400 => format!("{}h", s / 3600),
        _ => format!("{}d", s / 86400),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::Meta;
    use crate::smolvm::{MachineState, PublishedPort};

    fn sb(
        name: &str,
        state: MachineState,
        created: i64,
        ports: Vec<PublishedPort>,
        workspace: Option<&str>,
    ) -> Sandbox {
        Sandbox {
            meta: Meta {
                name: name.into(),
                agent: "claude".into(),
                workspace: workspace.map(String::from),
                workspaces: workspace.map(|w| vec![w.to_string()]).unwrap_or_default(),
                created,
                docker: true,
                secrets: vec![],
            },
            machine: format!("sbx-{name}"),
            state,
            ports,
        }
    }

    fn sample() -> Vec<Sandbox> {
        vec![
            sb(
                "claude-myrepo",
                MachineState::Running,
                999_998,
                vec![PublishedPort {
                    host: 18080,
                    guest: 80,
                }],
                Some("/Users/dev/myrepo"),
            ),
            sb(
                "shell-scratch",
                MachineState::Stopped,
                900_000,
                vec![],
                None,
            ),
        ]
    }

    #[test]
    fn table() {
        insta::assert_snapshot!(render(&sample(), Format::Table, false, 1_000_000).unwrap());
    }

    #[test]
    fn json() {
        insta::assert_snapshot!(render(&sample(), Format::Json, false, 1_000_000).unwrap());
    }

    #[test]
    fn yaml() {
        insta::assert_snapshot!(render(&sample(), Format::Yaml, false, 1_000_000).unwrap());
    }

    #[test]
    fn quiet_and_empty() {
        assert_eq!(
            render(&sample(), Format::Table, true, 0).unwrap(),
            "claude-myrepo\nshell-scratch\n"
        );
        assert_eq!(
            render(&[], Format::Table, false, 0).unwrap(),
            "No sandboxes found\n"
        );
        assert_eq!(render(&[], Format::Json, false, 0).unwrap(), "[]\n");
    }

    #[test]
    fn ages() {
        assert_eq!(age(5), "5s");
        assert_eq!(age(125), "2m");
        assert_eq!(age(7200), "2h");
        assert_eq!(age(3 * 86400), "3d");
    }
}
