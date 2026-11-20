//! inspect: one sandbox's details, as sbx's `inspect` shows them (the rows smolbento can fill).

use std::collections::BTreeMap;
use std::io::Write;

use anyhow::Result;
use serde::Serialize;

use super::{Ctx, Format, InspectArgs};
use crate::sandbox::{self, Sandbox, session};
use crate::smolvm::Runner;

pub fn run<R: Runner>(ctx: &mut Ctx<R>, a: &InspectArgs) -> Result<i32> {
    let sb = sandbox::get(&ctx.vm, &a.sandbox)?;
    let sessions = session::live_sessions(&ctx.paths.sessions(), sb.name());
    let format = a.output.pick();
    write!(&ctx.out, "{}", render(&sb, sessions, format)?)?;
    Ok(0)
}

/// sbx's JSON/YAML keys; empty and unknown values are left out, as sbx does.
#[derive(Serialize)]
struct Details<'a> {
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    mounts: BTreeMap<&'a str, &'a str>,
    /// RFC 3339, as sbx 0.53 writes it.
    created_at: String,
    name: &'a str,
    agent: &'a str,
    /// The kits' refs, as sbx lists them.
    kits: Vec<String>,
    state: &'static str,
    /// `v` and the smolbento version that created it (sbx 0.51); absent for older sandboxes.
    #[serde(skip_serializing_if = "Option::is_none")]
    created_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    image: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    workspace: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    clone_source: Option<&'a str>,
    #[serde(skip_serializing_if = "<[String]>::is_empty")]
    secrets: &'a [String],
    #[serde(skip_serializing_if = "Vec::is_empty")]
    ports: Vec<String>,
    /// The registered MCP servers chosen with `--static-mcp`; absent without the flag.
    #[serde(skip_serializing_if = "Option::is_none")]
    mcp_servers: Option<&'a [String]>,
    sessions: usize,
}

pub fn render(sb: &Sandbox, sessions: usize, format: Format) -> Result<String> {
    let m = &sb.meta;
    let d = Details {
        mounts: m
            .host_mounts
            .iter()
            .map(|(guest, host)| (guest.as_str(), host.as_str()))
            .collect(),
        created_at: super::rfc3339(m.created),
        name: sb.name(),
        agent: &m.agent,
        kits: m.rec.kits.iter().map(|k| k.reference.clone()).collect(),
        state: super::ls::status(sb.state),
        created_version: m.version.as_ref().map(|v| format!("v{v}")),
        image: sb.image.as_deref(),
        workspace: m.workspace.as_deref(),
        clone_source: m.clone_repo.as_deref(),
        secrets: &m.rec.secrets,
        // smolvm publishes TCP on 127.0.0.1 only; sbx's measured form.
        ports: sb
            .ports
            .iter()
            .map(|p| format!("127.0.0.1:{}->{}/tcp4", p.host, p.guest))
            .collect(),
        mcp_servers: m.mcp.as_deref(),
        sessions,
    };
    Ok(format.structured(&d)?.unwrap_or_else(|| table(&d)))
}

/// sbx's layout: a blank line, then two-space indented keys padded to 17 columns.
fn table(d: &Details) -> String {
    let list = |items: &[String], empty: &str| {
        if items.is_empty() {
            empty.to_string()
        } else {
            items.join(", ")
        }
    };
    let mounts: Vec<String> = d.mounts.iter().map(|(g, h)| format!("{h}:{g}")).collect();
    let mut rows = vec![
        ("Name", d.name.to_string()),
        ("Agent", d.agent.to_string()),
        ("Kits", list(&d.kits, "none")),
        ("State", d.state.to_string()),
    ];
    if let Some(v) = &d.created_version {
        rows.push(("Created with", v.clone()));
    }
    rows.extend([
        ("Image", d.image.unwrap_or("-").to_string()),
        ("Workspace", d.workspace.unwrap_or("-").to_string()),
        ("Clone source", d.clone_source.unwrap_or("-").to_string()),
    ]);
    if !mounts.is_empty() {
        rows.push(("Host mounts", mounts.join(", ")));
    }
    rows.extend([
        ("Secrets", list(d.secrets, "none")),
        ("Ports", list(&d.ports, "none published")),
    ]);
    if let Some(servers) = d.mcp_servers {
        rows.push(("MCP servers", list(servers, "none")));
    }
    rows.push(("Sessions", d.sessions.to_string()));
    let mut out = String::from("\n");
    for (key, value) in rows {
        out.push_str(&format!("  {:<17}{value}\n", format!("{key}:")));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::labels::KitRecord;
    use crate::sandbox::{Meta, Recorded};
    use crate::testutil::*;

    /// `machine status --json` for a sandbox with `meta`'s labels.
    fn status(t: &TestEnv, meta: &Meta, state: &str, image: Option<&str>, ports: &str) {
        let mut m = serde_json::json!({
            "name": format!("sbx-{}", meta.name),
            "state": state,
            "labels": meta.to_labels(),
            "created_at": 999_000,
            "published_ports": serde_json::from_str::<serde_json::Value>(ports).unwrap(),
        });
        if let Some(i) = image {
            m["image"] = i.into();
        }
        t.runner().ok(&["machine", "status"], &m.to_string());
    }

    /// A running clone sandbox with kits, a host mount, secrets, a port and one live session.
    fn full(t: &TestEnv) -> session::Session {
        let meta = Meta {
            rec: Recorded {
                secrets: vec!["anthropic".into(), "github".into()],
                kits: ["ghcr.io/example/kit:1@sha256:abc", "/Users/dev/kits/cache"]
                    .map(|r| KitRecord {
                        name: "k".into(),
                        reference: r.into(),
                        provides: vec![],
                        format: None,
                        args: Default::default(),
                    })
                    .to_vec(),
                ..Default::default()
            },
            name: "claude-proj".into(),
            agent: "claude".into(),
            workspace: Some("/Users/dev/proj".into()),
            workspaces: vec!["/Users/dev/proj".into()],
            created: 999_000,
            version: Some("0.27.0".into()),
            clone_repo: Some("/Users/dev/proj".into()),
            host_mounts: BTreeMap::from([(
                "/home/agent/.cache/x".into(),
                "/Users/dev/.local/share/smolbento/kit-host-mounts/aa/bb".into(),
            )]),
            ..Default::default()
        };
        status(
            t,
            &meta,
            "running",
            Some("docker/sandbox-templates:claude-code"),
            r#"[{"host":18080,"guest":8080},{"host":3000,"guest":3000}]"#,
        );
        session::Session::register(&t.ctx.paths.sessions(), "claude-proj").unwrap()
    }

    /// A stopped mountless sandbox with nothing optional.
    fn bare(t: &TestEnv) {
        let meta = Meta {
            name: "shell-x".into(),
            agent: "shell".into(),
            created: 999_000,
            ..Default::default()
        };
        status(t, &meta, "stopped", None, "[]");
    }

    #[test]
    fn mcp_servers_are_shown_when_they_were_chosen() {
        let chosen = |servers: Option<Vec<String>>| Meta {
            name: "shell-x".into(),
            agent: "shell".into(),
            created: 999_000,
            mcp: servers,
            ..Default::default()
        };
        let mut t = test_env(&[]);
        status(
            &t,
            &chosen(Some(vec!["linear".into(), "files".into()])),
            "stopped",
            None,
            "[]",
        );
        t.sbt(&["inspect", "shell-x"]).unwrap();
        let out = t.stdout();
        assert!(
            out.contains("\n  MCP servers:     linear, files\n"),
            "{out}"
        );
        t.sbt(&["inspect", "shell-x", "--json"]).unwrap();
        let json: serde_json::Value = serde_json::from_str(&t.stdout()).unwrap();
        assert_eq!(json["mcp_servers"], serde_json::json!(["linear", "files"]));

        // `--static-mcp none`: chosen, and empty.
        let mut t = test_env(&[]);
        status(&t, &chosen(Some(vec![])), "stopped", None, "[]");
        t.sbt(&["inspect", "shell-x"]).unwrap();
        assert!(t.stdout().contains("\n  MCP servers:     none\n"));

        // Without the flag there is no row and no key.
        let mut t = test_env(&[]);
        status(&t, &chosen(None), "stopped", None, "[]");
        t.sbt(&["inspect", "shell-x"]).unwrap();
        assert!(!t.stdout().contains("MCP servers"));
        t.sbt(&["inspect", "shell-x", "--json"]).unwrap();
        let json: serde_json::Value = serde_json::from_str(&t.stdout()).unwrap();
        assert!(json.get("mcp_servers").is_none(), "{json}");
    }

    #[test]
    fn creation_time_and_version_are_shown_as_in_sbx() {
        let mut t = test_env(&[]);
        let _s = full(&t);
        t.sbt(&["inspect", "claude-proj", "--json"]).unwrap();
        let json: serde_json::Value = serde_json::from_str(&t.stdout()).unwrap();
        assert_eq!(json["created_at"], "1970-01-12T13:30:00Z");
        assert_eq!(json["created_version"], "v0.27.0");
        t.sbt(&["inspect", "claude-proj"]).unwrap();
        assert!(
            t.stdout().contains("\n  Created with:    v0.27.0\n"),
            "{}",
            t.stdout()
        );
        // A sandbox from before the label has a time and no version.
        let mut t = test_env(&[]);
        bare(&t);
        t.sbt(&["inspect", "shell-x", "--json"]).unwrap();
        let json: serde_json::Value = serde_json::from_str(&t.stdout()).unwrap();
        assert!(json.get("created_version").is_none(), "{json}");
        assert!(json.get("created_at").is_some(), "{json}");
    }

    #[test]
    fn table_full() {
        let mut t = test_env(&[]);
        let _s = full(&t);
        t.sbt(&["inspect", "claude-proj"]).unwrap();
        insta::assert_snapshot!(t.stdout());
    }

    #[test]
    fn table_bare() {
        let mut t = test_env(&[]);
        bare(&t);
        t.sbt(&["inspect", "shell-x"]).unwrap();
        let out = t.stdout();
        // insta ignores leading blank lines; sbx starts with one.
        assert!(out.starts_with("\n  Name:            shell-x\n"), "{out:?}");
        insta::assert_snapshot!(out);
    }

    #[test]
    fn json_full() {
        let mut t = test_env(&[]);
        let _s = full(&t);
        t.sbt(&["inspect", "claude-proj", "--json"]).unwrap();
        insta::assert_snapshot!(t.stdout());
    }

    #[test]
    fn json_bare() {
        let mut t = test_env(&[]);
        bare(&t);
        t.sbt(&["inspect", "shell-x", "--format", "json"]).unwrap();
        insta::assert_snapshot!(t.stdout());
    }

    #[test]
    fn yaml_full() {
        let mut t = test_env(&[]);
        let _s = full(&t);
        t.sbt(&["inspect", "claude-proj", "--format", "yaml"])
            .unwrap();
        insta::assert_snapshot!(t.stdout());
    }

    #[test]
    fn yaml_bare() {
        let mut t = test_env(&[]);
        bare(&t);
        t.sbt(&["inspect", "shell-x", "--format", "yaml"]).unwrap();
        insta::assert_snapshot!(t.stdout());
    }

    #[test]
    fn not_found() {
        let mut t = test_env(&[]);
        t.runner()
            .fail(&["machine", "status"], "NOT_FOUND", "machine not found");
        let err = t.sbt(&["inspect", "nope"]).unwrap_err();
        assert_eq!(err.to_string(), "sandbox 'nope' not found\n  try: bento ls");
        assert_eq!(t.stdout(), "");
    }
}
