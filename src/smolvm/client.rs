use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::{Result, anyhow};

use super::{Machine, Output, Runner, SmolvmError};

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

/// Everything `smolvm machine create` needs for a sandbox.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CreateSpec {
    pub name: String,
    pub image: String,
    pub labels: BTreeMap<String, String>,
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
        // Open egress for now (no network policy yet); virtio-net is what lets smolvm change the allow
        // list and published ports on a running machine.
        a.extend(["--net", "--net-backend", "virtio-net"].map(String::from));
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

impl<R: Runner> Smolvm<R> {
    pub fn new(runner: R) -> Self {
        Self { runner }
    }

    pub fn runner(&self) -> &R {
        &self.runner
    }

    fn call(&self, args: Vec<String>) -> Result<Output> {
        let out = self.runner.run(&args)?;
        if out.code != 0 {
            return Err(SmolvmError::from_output(&out).into());
        }
        Ok(out)
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

    pub fn start(&self, name: &str) -> Result<()> {
        self.call(args(&["machine", "start", "-n", name])).map(drop)
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
    use crate::smolvm::MachineState;
    use crate::smolvm::fake::FakeRunner;

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
        };
        assert_eq!(
            spec.to_args().join(" "),
            "machine create -n sbx-claude-repo --image img:1 --net --net-backend virtio-net \
             --label sbx.name=claude-repo -v /w:/w -v /docs:/docs:ro -v /var/lib/docker -w /w \
             --cpus 2 --mem 4096 -e A=1 -p 8080:80 -p 53:53/udp -u root -- sleep infinity"
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
        vm.start("m").unwrap();
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
