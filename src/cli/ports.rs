//! `bento ports`: publish ports on a sandbox (smolvm applies TCP changes live, and UDP ones only
//! while it's stopped).

use anyhow::{Result, bail};
use std::io::Write;

use super::{Ctx, PortsArgs, table};
use crate::provision;
use crate::sandbox::{self, options};
use crate::smolvm::{PortMap, PublishedPort, Runner};

pub fn run<R: Runner>(ctx: &mut Ctx<R>, a: &PortsArgs) -> Result<i32> {
    let mut sb = sandbox::get(&ctx.vm, &a.sandbox)?;
    if a.publish.is_empty() && a.unpublish.is_empty() {
        write!(&ctx.out, "{}", list(&sb.ports, &a.output)?)?;
        return Ok(0);
    }
    let publish = a
        .publish
        .iter()
        .map(|p| options::parse_publish(p, &options::free_port))
        .collect::<Result<Vec<PortMap>>>()?;
    let no_free = || -> Result<u16> { bail!("--unpublish needs HOST:PORT") };
    let unpublish = a
        .unpublish
        .iter()
        .map(|p| options::parse_publish(p, &no_free))
        .collect::<Result<Vec<PortMap>>>()?;
    let udp = publish.iter().chain(&unpublish).any(|p| p.udp);
    if udp && sb.is_running() {
        bail!(
            "smolvm can't change UDP ports on a running sandbox; `bento stop {}` first, or publish it when creating",
            sb.name()
        );
    }
    if !publish.is_empty() && !udp {
        // sbx starts a stopped sandbox to publish on it; UDP ports can only change while stopped.
        provision::ensure_running(ctx, &mut sb)?;
    }
    if !publish.is_empty() {
        ctx.vm.publish(&sb.machine, &publish)?;
    }
    if !unpublish.is_empty() {
        ctx.vm.unpublish(&sb.machine, &unpublish)?;
    }
    if a.output.is_table() {
        for p in &publish {
            writeln!(&ctx.out, "Published 127.0.0.1:{} -> {}", p.host, p.guest)?;
        }
        for p in &unpublish {
            writeln!(&ctx.out, "Unpublished 127.0.0.1:{}", p.host)?;
        }
    } else {
        // The ports this call published, as the listing shows them.
        let published: Vec<PublishedPort> = publish
            .iter()
            .filter(|p| !p.udp)
            .map(|p| PublishedPort {
                host: p.host,
                guest: p.guest,
            })
            .collect();
        write!(&ctx.out, "{}", list(&published, &a.output)?)?;
    }
    Ok(0)
}

/// The published ports: sbx's JSON/YAML rows, or the table.
fn list(ports: &[PublishedPort], output: &super::OutputArgs) -> Result<String> {
    /// In sbx's key order.
    #[derive(serde::Serialize)]
    struct Row {
        host_ip: &'static str,
        host_port: u16,
        sandbox_port: u16,
        protocol: &'static str,
    }
    let rows: Vec<Row> = ports
        .iter()
        .map(|p| Row {
            host_ip: "127.0.0.1",
            host_port: p.host,
            sandbox_port: p.guest,
            protocol: "tcp",
        })
        .collect();
    Ok(output
        .structured(&rows)?
        .unwrap_or_else(|| render_list(ports)))
}

fn render_list(ports: &[PublishedPort]) -> String {
    if ports.is_empty() {
        return "No published ports\n".into();
    }
    let mut lines = vec![vec!["HOST".to_string(), "SANDBOX PORT".to_string()]];
    for p in ports {
        lines.push(vec![format!("127.0.0.1:{}", p.host), p.guest.to_string()]);
    }
    table(lines)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;

    fn sandbox(t: &TestEnv, state: &str) {
        t.sandbox("a1", state, &[]);
    }

    #[test]
    fn list_as_json_has_sbxs_keys() {
        let ports = [PublishedPort {
            host: 18999,
            guest: 8999,
        }];
        let json = super::super::OutputArgs {
            json: true,
            ..Default::default()
        };
        let v: serde_json::Value = serde_json::from_str(&list(&ports, &json).unwrap()).unwrap();
        assert_eq!(
            v,
            serde_json::json!([{"host_ip": "127.0.0.1", "host_port": 18999, "sandbox_port": 8999, "protocol": "tcp"}])
        );
        // Without a format it's the table.
        let table = list(&ports, &Default::default()).unwrap();
        assert!(table.starts_with("HOST"), "{table}");
    }

    #[test]
    fn publish_with_json_prints_the_published_ports_not_text() {
        let mut t = test_env(&[]);
        sandbox(&t, "running");
        t.sbt(&["ports", "a1", "--publish", "8080:80", "--json"])
            .unwrap();
        let v: serde_json::Value = serde_json::from_str(&t.stdout()).unwrap();
        assert_eq!(
            v,
            serde_json::json!([{"host_ip": "127.0.0.1", "host_port": 8080, "sandbox_port": 80, "protocol": "tcp"}])
        );
        t.sbt(&["ports", "a1", "--unpublish", "8080:80", "--json"])
            .unwrap();
        assert_eq!(t.stdout(), "[]\n");
    }

    #[test]
    fn publish_starts_a_stopped_sandbox_then_updates() {
        let mut t = test_env(&[]);
        sandbox(&t, "stopped");
        t.sbt(&["ports", "a1", "--publish", "8080:80"]).unwrap();
        let lines = t.calls();
        assert!(lines.contains(&"machine start -n sbx-a1 --branchable".to_string()));
        assert_eq!(lines.last().unwrap(), "machine update -n sbx-a1 -p 8080:80");
    }

    #[test]
    fn unpublish_and_udp_rules() {
        let mut t = test_env(&[]);
        sandbox(&t, "running");
        t.sbt(&["ports", "a1", "--unpublish", "8080:80"]).unwrap();
        assert_eq!(
            t.calls().last().unwrap(),
            "machine update -n sbx-a1 --remove-port 8080:80"
        );
        assert!(
            t.sbt_err(&["ports", "a1", "--unpublish", "80"])
                .contains("HOST:PORT")
        );
        let err = t.sbt_err(&["ports", "a1", "--publish", "5353:53/udp"]);
        assert!(err.contains("stop"), "{err}");
    }

    #[test]
    fn udp_ports_change_on_a_stopped_sandbox_without_starting_it() {
        let mut t = test_env(&[]);
        sandbox(&t, "stopped");
        t.sbt(&[
            "ports",
            "a1",
            "--publish",
            "5353:53/udp",
            "--publish",
            "8080:80",
        ])
        .unwrap();
        t.sbt(&["ports", "a1", "--unpublish", "5353:53/udp"])
            .unwrap();
        let lines = t.calls();
        assert!(
            !lines.iter().any(|l| l.contains("machine start")),
            "{lines:?}"
        );
        let updates: Vec<&String> = lines.iter().filter(|l| l.contains("update")).collect();
        assert_eq!(
            updates,
            [
                "machine update -n sbx-a1 -p 5353:53/udp -p 8080:80",
                "machine update -n sbx-a1 --remove-port 5353:53/udp"
            ]
        );
    }

    #[test]
    fn list_without_flags() {
        let mut t = test_env(&[]);
        sandbox(&t, "running");
        assert_eq!(t.sbt(&["ports", "a1"]).unwrap(), 0);
        assert!(!t.calls().iter().any(|l| l.contains("update")));
    }

    #[test]
    fn list_output() {
        assert_eq!(render_list(&[]), "No published ports\n");
        let listed = render_list(&[PublishedPort {
            host: 8080,
            guest: 80,
        }]);
        let mut rows = listed
            .lines()
            .map(|l| l.split_whitespace().collect::<Vec<_>>());
        assert_eq!(rows.next().unwrap(), ["HOST", "SANDBOX", "PORT"]);
        assert_eq!(rows.next().unwrap(), ["127.0.0.1:8080", "80"]);
    }
}
