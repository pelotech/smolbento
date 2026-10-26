use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::{Context, Result, anyhow};

use super::{EgressEvent, Machine, NetworkSpec, Output, Runner, SmolvmError};

/// A `-v` mount: a host directory at a guest path, or (no host) a directory on the machine's own disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mount {
    pub host: Option<PathBuf>,
    pub guest: String,
    pub read_only: bool,
}

impl Mount {
    fn arg(&self) -> String {
        match &self.host {
            Some(host) => {
                let mut arg = format!("{}:{}", host.display(), self.guest);
                if self.read_only {
                    arg.push_str(":ro");
                }
                arg
            }
            None => self.guest.clone(),
        }
    }
}

/// A published port. smolvm binds the host side on 127.0.0.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortMap {
    pub host: u16,
    pub guest: u16,
    pub udp: bool,
}

impl PortMap {
    fn arg(&self) -> String {
        format!(
            "{}:{}{}",
            self.host,
            self.guest,
            if self.udp { "/udp" } else { "" }
        )
    }
}

/// A secret the guest sees only as a placeholder; smolvm substitutes the real value (from the
/// `machine start` environment) on HTTPS requests to `hosts`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credential {
    pub name: String,
    pub env_var: String,
    pub hosts: Vec<String>,
}

impl Credential {
    fn arg(&self) -> String {
        // smolvm would read `NAME=VAR@` as a credential for no host at all.
        debug_assert!(
            !self.hosts.is_empty(),
            "a credential needs at least one host"
        );
        format!("{}={}@{}", self.name, self.env_var, self.hosts.join(","))
    }
}

/// Everything `smolvm machine create` needs for a sandbox.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CreateSpec {
    pub name: String,
    pub image: String,
    pub labels: BTreeMap<String, String>,
    pub network: NetworkSpec,
    /// Ranges refused before anything is allowed (smolvm accepts these at create only).
    pub deny_cidrs: Vec<String>,
    pub credentials: Vec<Credential>,
    pub mounts: Vec<Mount>,
    pub workdir: Option<String>,
    pub cpus: Option<u32>,
    pub memory_mib: Option<u64>,
    pub env: Vec<(String, String)>,
    pub ports: Vec<PortMap>,
    pub user: Option<String>,
    pub cmd: Vec<String>,
}

fn flag(args: &mut Vec<String>, name: &str, value: impl Into<String>) {
    args.push(name.into());
    args.push(value.into());
}

impl CreateSpec {
    pub fn to_args(&self) -> Vec<String> {
        let mut a = vec!["machine".to_string(), "create".to_string()];
        flag(&mut a, "-n", &self.name);
        flag(&mut a, "--image", &self.image);
        a.extend(self.network.create_args());
        for c in &self.deny_cidrs {
            flag(&mut a, "--deny-cidr", c);
        }
        for c in &self.credentials {
            flag(&mut a, "--credential", c.arg());
        }
        for (k, v) in &self.labels {
            flag(&mut a, "--label", format!("{k}={v}"));
        }
        for m in &self.mounts {
            flag(&mut a, "-v", m.arg());
        }
        if let Some(w) = &self.workdir {
            flag(&mut a, "-w", w);
        }
        if let Some(c) = self.cpus {
            flag(&mut a, "--cpus", c.to_string());
        }
        if let Some(m) = self.memory_mib {
            flag(&mut a, "--mem", m.to_string());
        }
        for (k, v) in &self.env {
            flag(&mut a, "-e", format!("{k}={v}"));
        }
        for p in &self.ports {
            flag(&mut a, "-p", p.arg());
        }
        if let Some(u) = &self.user {
            flag(&mut a, "-u", u);
        }
        if !self.cmd.is_empty() {
            a.push("--".into());
            a.extend(self.cmd.iter().cloned());
        }
        a
    }
}

/// One `smolvm machine exec`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExecSpec {
    pub name: String,
    pub user: Option<String>,
    pub workdir: Option<String>,
    pub env: Vec<(String, String)>,
    pub interactive: bool,
    pub tty: bool,
    pub detach: bool,
    pub cmd: Vec<String>,
}

impl ExecSpec {
    pub fn to_args(&self) -> Vec<String> {
        let mut a = vec!["machine".to_string(), "exec".to_string()];
        flag(&mut a, "--name", &self.name);
        if let Some(u) = &self.user {
            flag(&mut a, "-u", u);
        }
        if let Some(w) = &self.workdir {
            flag(&mut a, "-w", w);
        }
        for (k, v) in &self.env {
            flag(&mut a, "-e", format!("{k}={v}"));
        }
        for (on, f) in [
            (self.interactive, "-i"),
            (self.tty, "-t"),
            (self.detach, "-d"),
        ] {
            if on {
                a.push(f.into());
            }
        }
        a.push("--".into());
        a.extend(self.cmd.iter().cloned());
        a
    }
}

/// Typed access to the smolvm CLI.
pub struct Smolvm<R: Runner> {
    runner: R,
}

fn args(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| s.to_string()).collect()
}

/// The output of a smolvm call that must have succeeded.
fn checked(out: Output) -> Result<Output> {
    if out.code != 0 {
        return Err(SmolvmError::from_output(&out).into());
    }
    Ok(out)
}

impl<R: Runner> Smolvm<R> {
    pub fn new(runner: R) -> Self {
        Self { runner }
    }

    pub fn runner(&self) -> &R {
        &self.runner
    }

    fn call(&self, args: Vec<String>) -> Result<Output> {
        checked(self.runner.run(&args)?)
    }

    /// The smolvm version, e.g. `1.32.2`.
    pub fn version(&self) -> Result<String> {
        let out = self.call(args(&["--version"]))?;
        out.stdout
            .split_whitespace()
            .last()
            .map(str::to_string)
            .ok_or_else(|| anyhow!("smolvm --version printed nothing"))
    }

    pub fn list(&self) -> Result<Vec<Machine>> {
        let out = self.call(args(&["machine", "ls", "--json"]))?;
        Ok(serde_json::from_str(&out.stdout)?)
    }

    /// `None` when the machine doesn't exist.
    pub fn status(&self, name: &str) -> Result<Option<Machine>> {
        let out = self
            .runner
            .run(&args(&["machine", "status", "-n", name, "--json"]))?;
        if out.code != 0 {
            let err = SmolvmError::from_output(&out);
            return if err.is_not_found() {
                Ok(None)
            } else {
                Err(err.into())
            };
        }
        Ok(Some(serde_json::from_str(&out.stdout)?))
    }

    pub fn create(&self, spec: &CreateSpec) -> Result<()> {
        self.call(spec.to_args()).map(drop)
    }

    /// `env` reaches the smolvm process only: it's how secret values get to credentials. `remove`
    /// names inherited variables to drop, so a credential without a value isn't the host's.
    pub fn start(&self, name: &str, env: &[(String, String)], remove: &[String]) -> Result<()> {
        let out =
            self.runner
                .run_with_env(&args(&["machine", "start", "-n", name]), env, remove)?;
        checked(out).map(drop)
    }

    /// Replaces the machine's whole allow list; applies live on a running machine.
    pub fn update_network(&self, name: &str, network: &NetworkSpec) -> Result<()> {
        let mut a = args(&["machine", "update", "-n", name]);
        a.extend(network.update_args());
        self.call(a).map(drop)
    }

    pub fn publish(&self, name: &str, ports: &[PortMap]) -> Result<()> {
        self.update_ports(name, "-p", ports)
    }

    pub fn unpublish(&self, name: &str, ports: &[PortMap]) -> Result<()> {
        self.update_ports(name, "--remove-port", ports)
    }

    fn update_ports(&self, name: &str, port_flag: &str, ports: &[PortMap]) -> Result<()> {
        if ports.is_empty() {
            return Ok(());
        }
        let mut a = args(&["machine", "update", "-n", name]);
        for p in ports {
            flag(&mut a, port_flag, p.arg());
        }
        self.call(a).map(drop)
    }

    /// Recent requests the machine's policy refused, oldest first.
    pub fn egress_events(&self, name: &str, limit: usize) -> Result<Vec<EgressEvent>> {
        let limit = limit.to_string();
        let out = self.call(args(&[
            "machine",
            "egress-events",
            "--name",
            name,
            "--json",
            "--limit",
            &limit,
        ]))?;
        serde_json::from_str(&out.stdout)
            .with_context(|| format!("parsing the egress events of {name}"))
    }

    pub fn stop(&self, name: &str) -> Result<()> {
        self.call(args(&["machine", "stop", "-n", name])).map(drop)
    }

    pub fn delete(&self, name: &str) -> Result<()> {
        self.call(args(&["machine", "delete", "-n", name, "-f"]))
            .map(drop)
    }

    pub fn cp(&self, src: &str, dst: &str) -> Result<()> {
        self.call(args(&["machine", "cp", src, dst])).map(drop)
    }

    /// Runs an exec attached to this terminal and returns the command's exit code.
    pub fn exec(&self, spec: &ExecSpec) -> Result<i32> {
        self.runner.interactive(&spec.to_args())
    }

    /// Runs an exec with captured output; fails if it exits non-zero.
    pub fn exec_captured(&self, spec: &ExecSpec) -> Result<Output> {
        self.call(spec.to_args())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smolvm::fake::FakeRunner;
    use crate::smolvm::{AllowList, MachineState};

    #[test]
    fn create_args() {
        let spec = CreateSpec {
            name: "sbx-claude-repo".into(),
            image: "img:1".into(),
            labels: BTreeMap::from([("sbx.name".into(), "claude-repo".into())]),
            mounts: vec![
                Mount {
                    host: Some("/w".into()),
                    guest: "/w".into(),
                    read_only: false,
                },
                Mount {
                    host: Some("/docs".into()),
                    guest: "/docs".into(),
                    read_only: true,
                },
                Mount {
                    host: None,
                    guest: "/var/lib/docker".into(),
                    read_only: false,
                },
            ],
            workdir: Some("/w".into()),
            cpus: Some(2),
            memory_mib: Some(4096),
            env: vec![("A".into(), "1".into())],
            ports: vec![
                PortMap {
                    host: 8080,
                    guest: 80,
                    udp: false,
                },
                PortMap {
                    host: 53,
                    guest: 53,
                    udp: true,
                },
            ],
            user: Some("root".into()),
            cmd: vec!["sleep".into(), "infinity".into()],
            ..Default::default()
        };
        assert_eq!(
            spec.to_args().join(" "),
            "machine create -n sbx-claude-repo --image img:1 --net --net-backend virtio-net \
             --label sbx.name=claude-repo -v /w:/w -v /docs:/docs:ro -v /var/lib/docker -w /w \
             --cpus 2 --mem 4096 -e A=1 -p 8080:80 -p 53:53/udp -u root -- sleep infinity"
        );
    }

    #[test]
    fn create_args_with_policy_and_credentials() {
        let spec = CreateSpec {
            name: "sbx-a1".into(),
            image: "img".into(),
            network: NetworkSpec::Restricted(AllowList::new(
                vec!["api.x.com".into()],
                vec![],
                vec![],
            )),
            deny_cidrs: vec!["10.0.0.0/8".into()],
            credentials: vec![Credential {
                name: "gh_token".into(),
                env_var: "GH_TOKEN".into(),
                hosts: vec!["github.com".into(), "api.github.com".into()],
            }],
            ..Default::default()
        };
        assert_eq!(
            spec.to_args().join(" "),
            "machine create -n sbx-a1 --image img --net-backend virtio-net --allow-host api.x.com \
             --allow-cidr 127.0.0.0/8 --allow-cidr ::1/128 --deny-cidr 10.0.0.0/8 \
             --credential gh_token=GH_TOKEN@github.com,api.github.com"
        );
    }

    #[test]
    fn start_passes_env_to_the_child_only() {
        let vm = Smolvm::new(FakeRunner::new());
        vm.start("m", &[("TOK".into(), "secret".into())], &["GONE".into()])
            .unwrap();
        assert_eq!(vm.runner().call_lines(), vec!["machine start -n m"]);
        assert_eq!(
            vm.runner().envs(),
            vec![vec![("TOK".to_string(), "secret".to_string())]]
        );
        assert_eq!(vm.runner().removed(), vec![vec!["GONE".to_string()]]);
    }

    #[test]
    fn live_updates() {
        let vm = Smolvm::new(FakeRunner::new());
        let p = PortMap {
            host: 8080,
            guest: 80,
            udp: false,
        };
        vm.update_network("m", &NetworkSpec::Open).unwrap();
        vm.publish("m", &[p]).unwrap();
        vm.unpublish("m", &[p]).unwrap();
        assert_eq!(
            vm.runner().call_lines(),
            vec![
                "machine update -n m --net --reset-allow-list",
                "machine update -n m -p 8080:80",
                "machine update -n m --remove-port 8080:80",
            ]
        );
    }

    #[test]
    fn publishing_no_ports_makes_no_call() {
        let vm = Smolvm::new(FakeRunner::new());
        vm.publish("m", &[]).unwrap();
        vm.unpublish("m", &[]).unwrap();
        assert!(vm.runner().call_lines().is_empty());
    }

    #[test]
    #[should_panic(expected = "at least one host")]
    #[cfg(debug_assertions)]
    fn a_credential_without_hosts_is_refused() {
        let c = Credential {
            name: "t".into(),
            env_var: "T".into(),
            hosts: vec![],
        };
        c.arg();
    }

    #[test]
    fn egress_events_parse_errors_name_the_machine() {
        let fake = FakeRunner::new();
        fake.ok(&["machine", "egress-events"], "not json");
        let err = Smolvm::new(fake).egress_events("m1", 5).unwrap_err();
        let text = format!("{err:#}");
        assert!(
            text.contains("egress events of m1") && text.contains("line 1"),
            "{text}"
        );
    }

    #[test]
    fn start_failure_is_an_error() {
        let fake = FakeRunner::new();
        fake.fail(&["machine", "start"], "SMOLVM_ERROR", "boom");
        let err = Smolvm::new(fake).start("m", &[], &[]).unwrap_err();
        assert_eq!(err.to_string(), "smolvm: boom");
    }

    #[test]
    fn egress_events_parse() {
        let fake = FakeRunner::new();
        fake.ok(
            &["machine", "egress-events"],
            r#"[{"timestamp":"2026-10-26T14:37:58Z","operation":"resolve","dest":"example.com"}]"#,
        );
        let vm = Smolvm::new(fake);
        let events = vm.egress_events("m", 50).unwrap();
        assert_eq!(events[0].dest, "example.com");
        assert_eq!(
            vm.runner().call_lines(),
            vec!["machine egress-events --name m --json --limit 50"]
        );
    }

    #[test]
    fn exec_args() {
        let spec = ExecSpec {
            name: "sbx-a".into(),
            user: Some("agent".into()),
            workdir: Some("/w".into()),
            env: vec![("K".into(), "v".into())],
            interactive: true,
            tty: true,
            detach: false,
            cmd: vec!["ls".into(), "-la".into()],
        };
        assert_eq!(
            spec.to_args().join(" "),
            "machine exec --name sbx-a -u agent -w /w -e K=v -i -t -- ls -la"
        );
    }

    #[test]
    fn version_takes_last_word() {
        let fake = FakeRunner::new();
        fake.ok(&["--version"], "smolvm 1.32.2\n");
        assert_eq!(Smolvm::new(fake).version().unwrap(), "1.32.2");
    }

    #[test]
    fn status_not_found_is_none() {
        let fake = FakeRunner::new();
        fake.fail(&["machine", "status"], "NOT_FOUND", "vm not found: x");
        assert!(Smolvm::new(fake).status("x").unwrap().is_none());
    }

    #[test]
    fn status_other_error_is_err() {
        let fake = FakeRunner::new();
        fake.fail(&["machine", "status"], "SMOLVM_ERROR", "db locked");
        let err = Smolvm::new(fake).status("x").unwrap_err();
        assert_eq!(err.to_string(), "smolvm: db locked");
    }

    #[test]
    fn list_parses_json() {
        let fake = FakeRunner::new();
        fake.ok(
            &["machine", "ls", "--json"],
            include_str!("../../tests/fixtures/smolvm/ls.json"),
        );
        let machines = Smolvm::new(fake).list().unwrap();
        assert_eq!(machines[0].state, MachineState::Running);
    }

    #[test]
    fn lifecycle_calls() {
        let vm = Smolvm::new(FakeRunner::new());
        vm.start("m", &[], &[]).unwrap();
        vm.stop("m").unwrap();
        vm.delete("m").unwrap();
        vm.cp("/a", "m:/b").unwrap();
        assert_eq!(
            vm.runner().call_lines(),
            vec![
                "machine start -n m",
                "machine stop -n m",
                "machine delete -n m -f",
                "machine cp /a m:/b",
            ]
        );
    }

    #[test]
    fn exec_is_interactive_and_returns_code() {
        let fake = FakeRunner::new();
        fake.interactive_exit(3);
        let vm = Smolvm::new(fake);
        let code = vm
            .exec(&ExecSpec {
                name: "m".into(),
                cmd: vec!["false".into()],
                ..Default::default()
            })
            .unwrap();
        assert_eq!(code, 3);
        assert_eq!(
            vm.runner().interactive_calls()[0].join(" "),
            "machine exec --name m -- false"
        );
    }
}
