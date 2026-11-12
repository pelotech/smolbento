//! `sbt mcp`: the MCP servers registered on the host.

use std::collections::BTreeMap;
use std::io::Write;

use anyhow::{Context, Result, bail};
use serde::Serialize;

use super::{Ctx, Format, McpAddArgs, McpCmd, McpInspectArgs, McpLsArgs, Unsupported, table};
use crate::mcp::{self, McpFile, Server};
use crate::smolvm::Runner;

pub fn run<R: Runner>(ctx: &Ctx<R>, cmd: McpCmd) -> Result<i32> {
    match cmd {
        McpCmd::Add(a) => add(ctx, a)?,
        McpCmd::Ls(a) => ls(ctx, &a)?,
        McpCmd::Inspect(a) => inspect(ctx, &a)?,
        McpCmd::Rm { name } => {
            let mut file = McpFile::load(&ctx.paths)?;
            if file.servers.remove(&name).is_none() {
                bail!(unknown(&name));
            }
            file.save(&ctx.paths)?;
            writeln!(&ctx.out, "Removed MCP server {name}")?;
        }
        McpCmd::Auth(_) => return Err(no_gateway("mcp auth")),
        McpCmd::Load(_) => return Err(no_gateway("mcp load")),
        McpCmd::Unload(_) => return Err(no_gateway("mcp unload")),
    }
    Ok(0)
}

fn unknown(name: &str) -> String {
    format!("no MCP server named '{name}' (see `sbt mcp ls`)")
}

/// What sbx does through its MCP gateway, which smolbento doesn't have.
fn no_gateway(what: &str) -> anyhow::Error {
    Unsupported(format!(
        "`sbt {what}` is not supported: smolbento has no MCP gateway (servers are attached \
         with `run|create --static-mcp`)"
    ))
    .into()
}

fn add<R: Runner>(ctx: &Ctx<R>, a: McpAddArgs) -> Result<()> {
    let unsupported = [
        (a.local, "--local"),
        (a.dir.is_some(), "--dir"),
        (a.client_id.is_some(), "--client-id"),
        (
            a.oauth_authorization_server.is_some(),
            "--oauth-authorization-server",
        ),
        (a.resource.is_some(), "--resource"),
        (a.skip_auth, "--skip-auth"),
    ];
    if let Some((_, flag)) = unsupported.iter().find(|(set, _)| *set) {
        return Err(Unsupported(format!(
            "{flag} is not supported: smolbento has no MCP gateway or OAuth for MCP servers"
        ))
        .into());
    }
    mcp::check_name(&a.name)?;
    let server = match (a.url, a.command) {
        (Some(url), None) => {
            if !a.args.is_empty() {
                bail!("--args needs --command");
            }
            let mut headers = BTreeMap::new();
            for h in &a.header {
                let (name, value) = h
                    .split_once(':')
                    .with_context(|| format!("--header '{h}': expected `Name: value`"))?;
                headers.insert(name.trim().to_string(), value.trim().to_string());
            }
            mcp::check_remote(&url, &headers)?;
            Server::Remote { url, headers }
        }
        (None, Some(command)) => {
            if !a.header.is_empty() {
                bail!("--header needs --url");
            }
            if command.trim().is_empty() {
                bail!("--command is empty");
            }
            Server::Command {
                command,
                args: a.args,
            }
        }
        _ => bail!("specify --url or --command (one of them)"),
    };
    let mut file = McpFile::load(&ctx.paths)?;
    match file.servers.get(&a.name) {
        Some(existing) if *existing == server => {}
        Some(_) => bail!(
            "MCP server {0} is already registered differently; `sbt mcp rm {0}` first",
            a.name
        ),
        None => {
            file.servers.insert(a.name.clone(), server.clone());
            file.save(&ctx.paths)?;
        }
    }
    let mut out = &ctx.out;
    writeln!(out, "Registered MCP server {}", a.name)?;
    for secret in secrets(&a.name, &server) {
        writeln!(out, "Set its secret with: sbt secret set {secret}")?;
    }
    Ok(())
}

/// The `mcp:` secrets a server's headers name.
fn secrets(name: &str, server: &Server) -> Vec<String> {
    match server {
        Server::Remote { headers, .. } => headers
            .values()
            .filter_map(|v| mcp::placeholder(v))
            .map(|p| mcp::secret_name(name, p))
            .collect(),
        Server::Command { .. } => Vec::new(),
    }
}

#[derive(Serialize)]
struct Row<'a> {
    name: &'a str,
    #[serde(rename = "type")]
    kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    url: Option<&'a str>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    headers: BTreeMap<&'a str, &'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    command: Option<&'a str>,
    #[serde(skip_serializing_if = "<[String]>::is_empty")]
    args: &'a [String],
    /// The secrets its headers take their values from.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    secrets: Vec<String>,
}

impl<'a> Row<'a> {
    fn new(name: &'a str, server: &'a Server) -> Self {
        let secrets = secrets(name, server);
        match server {
            Server::Remote { url, headers } => Row {
                name,
                kind: "remote",
                url: Some(url),
                headers: headers
                    .iter()
                    .map(|(k, v)| (k.as_str(), v.as_str()))
                    .collect(),
                command: None,
                args: &[],
                secrets,
            },
            Server::Command { command, args } => Row {
                name,
                kind: "command",
                url: None,
                headers: BTreeMap::new(),
                command: Some(command),
                args,
                secrets,
            },
        }
    }

    /// The URL, or the command line.
    fn target(&self) -> String {
        match (self.url, self.command) {
            (Some(url), _) => url.to_string(),
            (_, Some(command)) => std::iter::once(command)
                .chain(self.args.iter().map(String::as_str))
                .collect::<Vec<_>>()
                .join(" "),
            _ => String::new(),
        }
    }
}

fn ls<R: Runner>(ctx: &Ctx<R>, a: &McpLsArgs) -> Result<()> {
    let file = McpFile::load(&ctx.paths)?;
    let rows: Vec<Row> = file.servers.iter().map(|(n, s)| Row::new(n, s)).collect();
    let mut out = &ctx.out;
    match Format::pick(a.json, a.format) {
        _ if a.quiet => rows.iter().try_for_each(|r| writeln!(out, "{}", r.name))?,
        Format::Json => writeln!(out, "{}", serde_json::to_string_pretty(&rows)?)?,
        Format::Yaml => write!(out, "{}", serde_saphyr::to_string(&rows)?)?,
        Format::Table if rows.is_empty() => writeln!(out, "No MCP servers registered")?,
        Format::Table => {
            let mut lines = vec![["NAME", "TYPE", "TARGET"].map(String::from).to_vec()];
            lines.extend(
                rows.iter()
                    .map(|r| vec![r.name.to_string(), r.kind.to_string(), r.target()]),
            );
            write!(out, "{}", table(lines))?;
        }
    }
    Ok(())
}

fn inspect<R: Runner>(ctx: &Ctx<R>, a: &McpInspectArgs) -> Result<()> {
    let file = McpFile::load(&ctx.paths)?;
    let server = file
        .servers
        .get(&a.name)
        .with_context(|| unknown(&a.name))?;
    let row = Row::new(&a.name, server);
    let mut out = &ctx.out;
    match Format::pick(a.json, a.format) {
        Format::Json => writeln!(out, "{}", serde_json::to_string_pretty(&row)?)?,
        Format::Yaml => write!(out, "{}", serde_saphyr::to_string(&row)?)?,
        Format::Table => {
            writeln!(out, "Name:     {}", row.name)?;
            writeln!(out, "Type:     {}", row.kind)?;
            match server {
                Server::Remote { url, headers } => {
                    writeln!(out, "URL:      {url}")?;
                    for (name, value) in headers {
                        writeln!(out, "Header:   {name}: {value}")?;
                    }
                }
                Server::Command { .. } => writeln!(out, "Command:  {}", row.target())?,
            }
            for secret in &row.secrets {
                writeln!(out, "Secret:   {secret}")?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::cli::exit_code;
    use crate::testutil::*;

    const LINEAR: [&str; 7] = [
        "mcp",
        "add",
        "linear",
        "--url",
        "https://mcp.linear.app/sse",
        "--header",
        "Authorization: Bearer ${api-key}",
    ];
    const FILES: [&str; 9] = [
        "mcp",
        "add",
        "files",
        "--command",
        "npx",
        "--args",
        "-y",
        "--args",
        "srv",
    ];

    #[test]
    fn add_ls_inspect_rm() {
        let mut t = test_env(&[]);
        t.sbt(&LINEAR).unwrap();
        t.sbt(&FILES).unwrap();
        let listed = |t: &mut TestEnv, args: &[&str]| {
            // `stdout` takes what was written so far.
            t.stdout();
            t.sbt(args).unwrap();
            t.stdout()
        };
        assert_eq!(listed(&mut t, &["mcp", "ls", "-q"]), "files\nlinear\n");
        let json: serde_json::Value =
            serde_json::from_str(&listed(&mut t, &["mcp", "ls", "--json"])).unwrap();
        let names: Vec<&str> = json
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, ["files", "linear"]);
        assert_eq!(
            listed(&mut t, &["mcp", "ls"]),
            "NAME     TYPE      TARGET\n\
             files    command   npx -y srv\n\
             linear   remote    https://mcp.linear.app/sse\n"
        );
        let shown = listed(&mut t, &["mcp", "inspect", "linear"]);
        assert!(shown.contains("https://mcp.linear.app/sse"), "{shown}");
        assert!(
            shown.contains("Authorization: Bearer ${api-key}"),
            "{shown}"
        );
        assert!(shown.contains("mcp:linear:api-key"), "{shown}");
        t.sbt(&["mcp", "rm", "linear"]).unwrap();
        assert_eq!(listed(&mut t, &["mcp", "ls", "-q"]), "files\n");
        assert_eq!(
            t.sbt_err(&["mcp", "rm", "linear"]),
            "no MCP server named 'linear' (see `sbt mcp ls`)"
        );
        assert_eq!(
            t.sbt_err(&["mcp", "inspect", "linear"]),
            "no MCP server named 'linear' (see `sbt mcp ls`)"
        );
    }

    #[test]
    fn an_empty_list_says_so() {
        let mut t = test_env(&[]);
        t.sbt(&["mcp", "ls"]).unwrap();
        assert_eq!(t.stdout(), "No MCP servers registered\n");
    }

    #[test]
    fn add_needs_exactly_one_of_url_and_command() {
        let mut t = test_env(&[]);
        for args in [
            &["mcp", "add", "x"][..],
            &[
                "mcp",
                "add",
                "x",
                "--url",
                "https://a.b/",
                "--command",
                "npx",
            ],
        ] {
            let err = t.sbt_err(args);
            assert!(err.contains("--url or --command"), "{err}");
        }
        let err = t.sbt_err(&["mcp", "add", "x", "--command", "npx", "--header", "A: b"]);
        assert!(err.contains("--header needs --url"), "{err}");
        let err = t.sbt_err(&["mcp", "add", "x", "--url", "https://a.b/", "--args", "y"]);
        assert!(err.contains("--args needs --command"), "{err}");
        let err = t.sbt_err(&[
            "mcp",
            "add",
            "x",
            "--url",
            "https://a.b/",
            "--header",
            "nocolon",
        ]);
        assert!(err.contains("Name: value"), "{err}");
        let err = t.sbt_err(&["mcp", "add", "bad name", "--url", "https://a.b/"]);
        assert!(err.contains("invalid MCP server name"), "{err}");
    }

    #[test]
    fn re_adding_the_same_is_fine_and_a_different_one_is_an_error() {
        let mut t = test_env(&[]);
        t.sbt(&LINEAR).unwrap();
        t.sbt(&LINEAR).unwrap();
        let err = t.sbt_err(&["mcp", "add", "linear", "--url", "https://other.example/mcp"]);
        assert!(err.contains("already registered"), "{err}");
    }

    #[test]
    fn unsupported_parts_exit_2() {
        let mut t = test_env(&[]);
        for (args, what) in [
            (&["mcp", "auth", "x"][..], "mcp auth"),
            (&["mcp", "load", "x", "--sandbox", "s"], "mcp load"),
            (&["mcp", "unload", "x", "--sandbox", "s"], "mcp unload"),
            (
                &[
                    "mcp",
                    "add",
                    "x",
                    "--url",
                    "https://a.b/",
                    "--client-id",
                    "c",
                ],
                "--client-id",
            ),
            (
                &["mcp", "add", "x", "--url", "https://a.b/", "--local"],
                "--local",
            ),
            (
                &["mcp", "add", "x", "--command", "c", "--dir", "/d"],
                "--dir",
            ),
            (
                &[
                    "mcp",
                    "add",
                    "x",
                    "--url",
                    "https://a.b/",
                    "--resource",
                    "r",
                ],
                "--resource",
            ),
            (
                &["mcp", "add", "x", "--url", "https://a.b/", "--skip-auth"],
                "--skip-auth",
            ),
            (
                &[
                    "mcp",
                    "add",
                    "x",
                    "--url",
                    "https://a.b/",
                    "--oauth-authorization-server",
                    "https://as/",
                ],
                "--oauth-authorization-server",
            ),
        ] {
            let err = t.sbt(args).unwrap_err();
            assert_eq!(exit_code(&err), 2, "{args:?}: {err}");
            assert!(err.to_string().contains(what), "{args:?}: {err}");
        }
        assert!(
            crate::mcp::McpFile::load(&t.ctx.paths)
                .unwrap()
                .servers
                .is_empty()
        );
    }

    #[test]
    fn add_tells_which_secret_to_set() {
        let mut t = test_env(&[]);
        t.sbt(&LINEAR).unwrap();
        assert_eq!(
            t.stdout(),
            "Registered MCP server linear\n\
             Set its secret with: sbt secret set mcp:linear:api-key\n"
        );
        let mut t = test_env(&[]);
        t.sbt(&FILES).unwrap();
        assert_eq!(t.stdout(), "Registered MCP server files\n");
    }
}
