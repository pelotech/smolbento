//! `bento ports`: publish ports on a sandbox (smolvm applies TCP changes live, and UDP ones only
//! while it's stopped).

use anyhow::{Result, bail};
use std::io::Write;

use super::{Ctx, PortsArgs, table};
use crate::provision;
use crate::sandbox::{self, labels, options};
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
        let was_stopped = !sb.is_running();
        provision::ensure_running(ctx, &mut sb)?;
        if was_stopped {
            // Its start picked new host ports: their label is the current one.
            sb = sandbox::get(&ctx.vm, &a.sandbox)?;
        }
    }
    // The picked ones are picked again at each start, as sbx: recorded until unpublished.
    let gone: Vec<String> = unpublish.iter().map(PortMap::arg).collect();
    let mut auto: Vec<String> = (sb.meta.rec.auto_ports.iter())
        .filter(|p| !gone.contains(p))
        .cloned()
        .collect();
    auto.extend(
        (a.publish.iter().zip(&publish))
            .filter(|(spec, _)| options::picks_host(spec))
            .map(|(_, p)| p.arg()),
    );
    ctx.vm.update(&sb.machine, &unpublish, &publish, &[])?;
    // Its own update: the machine may be running (see `Smolvm::update`).
    if auto != sb.meta.rec.auto_ports {
        ctx.vm
            .set_label(&sb.machine, labels::AUTO_PORTS, &auto.join(","))?;
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
    let mut lines = Vec::new();
    for p in ports {
        lines.push(vec![format!("127.0.0.1:{}", p.host), p.guest.to_string()]);
    }
    table(&["HOST", "SANDBOX PORT"], lines)
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

    /// A port published without a host port is picked again at each start (as sbx): recorded on
    /// publish, forgotten on unpublish.
    #[test]
    fn a_picked_port_is_recorded_until_unpublished() {
        let mut t = test_env(&[]);
        t.sandbox("a1", "running", &[("sbx.auto-ports", "40001:80")]);
        t.sbt(&["ports", "a1", "--publish", "81"]).unwrap();
        // Two updates: smolvm refuses ports and labels together on a running machine.
        let calls = t.calls();
        let [publish, label] = &calls[calls.len() - 2..] else {
            unreachable!()
        };
        let port = publish
            .strip_prefix("machine update -n sbx-a1 -p ")
            .unwrap_or_else(|| panic!("{publish}"));
        let picked = label
            .strip_prefix("machine update -n sbx-a1 --label sbx.auto-ports=40001:80,")
            .unwrap_or_else(|| panic!("{label}"));
        assert!(picked.ends_with(":81") && port == picked, "{calls:?}");
        t.sbt(&["ports", "a1", "--unpublish", "40001:80"]).unwrap();
        let calls = t.calls();
        assert_eq!(
            calls[calls.len() - 2..],
            [
                "machine update -n sbx-a1 --remove-port 40001:80",
                "machine update -n sbx-a1 --label sbx.auto-ports=",
            ]
        );
    }

    /// Publishing on a stopped sandbox starts it, which picks new host ports: the label keeps
    /// those, not the ones from before the start.
    #[test]
    fn publishing_on_a_stopped_sandbox_keeps_the_ports_its_start_picked() {
        let mut t = test_env(&[]);
        // After the start: what its re-pick recorded.
        t.sandbox("a1", "running", &[("sbx.auto-ports", "45000:80")]);
        t.runner().once_ok(
            &["machine", "status"],
            &crate::testutil::sandbox_json("a1", "stopped", &[("sbx.auto-ports", "40001:80")]),
        );
        t.sbt(&["ports", "a1", "--publish", "81"]).unwrap();
        let label = t.calls().last().unwrap().clone();
        assert!(
            label.starts_with("machine update -n sbx-a1 --label sbx.auto-ports=45000:80,"),
            "{label}"
        );
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
        assert!(!t.made("machine start"), "{lines:?}");
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
