//! `sbt ports`: publish ports on a sandbox (smolvm applies TCP changes live, and UDP ones only
//! while it's stopped).

use anyhow::{Result, bail};

use super::{Ctx, PortsArgs, plan, table};
use crate::sandbox::{self, options};
use crate::smolvm::{PortMap, PublishedPort, Runner};

pub fn run<R: Runner>(ctx: &mut Ctx<R>, a: &PortsArgs) -> Result<i32> {
    let mut sb = sandbox::get(&ctx.vm, &a.sandbox)?;
    if a.publish.is_empty() && a.unpublish.is_empty() {
        print!("{}", render_list(&sb.ports));
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
            "smolvm can't change UDP ports on a running sandbox; `sbt stop {}` first, or publish it when creating",
            sb.name()
        );
    }
    if !publish.is_empty() && !udp {
        // sbx starts a stopped sandbox to publish on it; UDP ports can only change while stopped.
        plan::ensure_running(ctx, &mut sb)?;
    }
    if !publish.is_empty() {
        ctx.vm.publish(&sb.machine, &publish)?;
        for p in &publish {
            println!("Published 127.0.0.1:{} -> {}", p.host, p.guest);
        }
    }
    if !unpublish.is_empty() {
        ctx.vm.unpublish(&sb.machine, &unpublish)?;
        for p in &unpublish {
            println!("Unpublished 127.0.0.1:{}", p.host);
        }
    }
    Ok(0)
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
    use super::super::testutil::*;
    use super::*;

    fn sandbox(t: &TestEnv, state: &str) {
        t.ctx.vm.runner().ok(
            &["machine", "status"],
            &machine_json("sbx-a1", state, &[("sbx.name", "a1")]),
        );
    }

    #[test]
    fn publish_starts_a_stopped_sandbox_then_updates() {
        let mut t = test_env(&[]);
        sandbox(&t, "stopped");
        sbt(&mut t.ctx, &["ports", "a1", "--publish", "8080:80"]).unwrap();
        let lines = t.ctx.vm.runner().call_lines();
        assert!(lines.contains(&"machine start -n sbx-a1".to_string()));
        assert_eq!(lines.last().unwrap(), "machine update -n sbx-a1 -p 8080:80");
    }

    #[test]
    fn unpublish_and_udp_rules() {
        let mut t = test_env(&[]);
        sandbox(&t, "running");
        sbt(&mut t.ctx, &["ports", "a1", "--unpublish", "8080:80"]).unwrap();
        assert_eq!(
            t.ctx.vm.runner().call_lines().last().unwrap(),
            "machine update -n sbx-a1 --remove-port 8080:80"
        );
        assert!(
            sbt(&mut t.ctx, &["ports", "a1", "--unpublish", "80"])
                .unwrap_err()
                .to_string()
                .contains("HOST:PORT")
        );
        let err = sbt(&mut t.ctx, &["ports", "a1", "--publish", "5353:53/udp"])
            .unwrap_err()
            .to_string();
        assert!(err.contains("stop"), "{err}");
    }

    #[test]
    fn udp_ports_change_on_a_stopped_sandbox_without_starting_it() {
        let mut t = test_env(&[]);
        sandbox(&t, "stopped");
        sbt(
            &mut t.ctx,
            &[
                "ports",
                "a1",
                "--publish",
                "5353:53/udp",
                "--publish",
                "8080:80",
            ],
        )
        .unwrap();
        sbt(&mut t.ctx, &["ports", "a1", "--unpublish", "5353:53/udp"]).unwrap();
        let lines = t.ctx.vm.runner().call_lines();
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
        assert_eq!(sbt(&mut t.ctx, &["ports", "a1"]).unwrap(), 0);
        assert!(
            !t.ctx
                .vm
                .runner()
                .call_lines()
                .iter()
                .any(|l| l.contains("update"))
        );
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
