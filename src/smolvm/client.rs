use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// smolvm's state directory variable; smolbento sets it on every call (`locate`).
pub(super) const DATA_DIR: &str = "SMOLVM_DATA_DIR";

use anyhow::{Context, Result, anyhow};

use super::{
    EgressEvent, Machine, NetworkSpec, Output, PullProgress, Runner, SmolvmError, pull_progress,
};

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
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Credential {
    /// Its lowercase form names the binding (`Credential::binding`).
    pub env_var: String,
    pub hosts: Vec<String>,
    /// smolvm sets this header to the value itself (`:set-header=`), for inject-only credentials.
    pub set_header: Option<String>,
}

impl Credential {
    /// A binding's name: its variable, lowercased. One variable holds one value, so the name is
    /// unique, and `secret set` can name the bindings it refreshes.
    pub(crate) fn binding(env_var: &str) -> String {
        env_var.to_ascii_lowercase()
    }

    fn arg(&self) -> String {
        // smolvm would read `NAME=VAR@` as a credential for no host at all.
        debug_assert!(
            !self.hosts.is_empty(),
            "a credential needs at least one host"
        );
        let name = Self::binding(&self.env_var);
        let mut arg = format!("{name}={}@{}", self.env_var, self.hosts.join(","));
        if let Some(h) = &self.set_header {
            arg.push_str(&format!(":set-header={h}"));
        }
        arg
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
    /// `--smolfile`: a Smolfile kit's configuration, which may also name the image.
    pub smolfile: Option<PathBuf>,
    /// `--from`: a saved template's pack, which stands in for `--image` (smolvm refuses both).
    pub from: Option<PathBuf>,
    pub mounts: Vec<Mount>,
    /// `--mount-socket`: (host socket, guest path), connected to the host path at connect time.
    pub mount_sockets: Vec<(PathBuf, String)>,
    pub workdir: Option<String>,
    pub cpus: Option<u32>,
    pub memory_mib: Option<u64>,
    /// `--storage`: the disk with image layers and guest-only volumes (Docker's data); GiB.
    pub storage_gib: Option<u32>,
    /// `--overlay`: the disk with the root filesystem's changes; GiB.
    pub overlay_gib: Option<u32>,
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
        if let Some(p) = &self.from {
            flag(&mut a, "--from", p.display().to_string());
        // smolvm takes the image from the Smolfile when `--image` is left out.
        } else if self.smolfile.is_none() || !self.image.is_empty() {
            flag(&mut a, "--image", &self.image);
        }
        if let Some(s) = &self.smolfile {
            flag(&mut a, "--smolfile", s.display().to_string());
        }
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
        for (host, guest) in &self.mount_sockets {
            flag(
                &mut a,
                "--mount-socket",
                format!("{}:{guest}", host.display()),
            );
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
        if let Some(s) = self.storage_gib {
            flag(&mut a, "--storage", s.to_string());
        }
        if let Some(o) = self.overlay_gib {
            flag(&mut a, "--overlay", o.to_string());
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
    /// Prints output as it arrives rather than when the command ends, and without the 11 MiB
    /// cap of a buffered exec. For an exec whose output goes straight to the user.
    pub stream: bool,
    /// smolvm kills the command after this long (`--timeout`).
    pub timeout: Option<std::time::Duration>,
    pub cmd: Vec<String>,
}

impl ExecSpec {
    /// `cmd` in `machine` as `user`, with no other options.
    pub fn new(machine: &str, user: &str, cmd: Vec<String>) -> Self {
        Self {
            name: machine.into(),
            user: Some(user.into()),
            cmd,
            ..Default::default()
        }
    }

    /// `sh -c script` in `machine` as `user`.
    pub fn sh(machine: &str, user: &str, script: impl Into<String>) -> Self {
        Self::new(machine, user, vec!["sh".into(), "-c".into(), script.into()])
    }

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
            (self.stream, "--stream"),
        ] {
            if on {
                a.push(f.into());
            }
        }
        if let Some(t) = self.timeout {
            flag(&mut a, "--timeout", format!("{}s", t.as_secs()));
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

/// `machine ls --json` output (empty when there are none).
fn machines(out: &Output) -> Result<Vec<Machine>> {
    if out.stdout.trim().is_empty() {
        return Ok(Vec::new());
    }
    Ok(serde_json::from_str(&out.stdout)?)
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

    /// The smolvm version, e.g. `1.34.1`.
    pub fn version(&self) -> Result<String> {
        let out = self.call(args(&["--version"]))?;
        out.stdout
            .split_whitespace()
            .last()
            .map(str::to_string)
            .ok_or_else(|| anyhow!("smolvm --version printed nothing"))
    }

    pub fn list(&self) -> Result<Vec<Machine>> {
        machines(&self.call(args(&["machine", "ls", "--json"]))?)
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

    /// Starts the machine, calling `on_progress` as smolvm pulls the image (only when it has to
    /// pull). `env` reaches the smolvm process only: it's how secret values get to credentials.
    /// `remove` names inherited variables to drop, so a credential without a value isn't the
    /// host's. `branchable` lets `bento fork` branch it later, at a cost: smolvm doesn't reclaim
    /// its idle memory, and on Linux other processes running as the user can read the VM
    /// process's memory.
    pub fn start(
        &self,
        name: &str,
        branchable: bool,
        env: &[(String, String)],
        remove: &[String],
        on_progress: &mut dyn FnMut(PullProgress),
    ) -> Result<()> {
        let mut a = args(&["machine", "start", "-n", name]);
        if branchable {
            a.push("--branchable".into());
        }
        let mut on_line = |line: &str| {
            if let Some(p) = pull_progress(line) {
                on_progress(p);
            }
        };
        checked(self.runner.run_streaming(&a, env, remove, &mut on_line)?).map(drop)
    }

    /// Hands the running machine new values for the credentials bound to `env`'s variables, without
    /// a restart (smolvm 1.35.4): `env` reaches the smolvm process only, and the machine uses the
    /// values from its next request.
    pub fn refresh_credentials(&self, name: &str, env: &[(String, String)]) -> Result<()> {
        let mut a = args(&["machine", "credentials", "refresh", "-n", name]);
        a.extend(env.iter().map(|(v, _)| Credential::binding(v)));
        checked(self.runner.run_with_env(&a, env, &[])?).map(drop)
    }

    /// Adds or replaces credential bindings on a running or stopped machine (smolvm 1.36.1); smolvm
    /// reads each value from `env`, which reaches the smolvm process only. A running machine that
    /// booted with no bindings takes them from its next start.
    pub fn add_credentials(
        &self,
        name: &str,
        creds: &[Credential],
        env: &[(String, String)],
    ) -> Result<()> {
        let mut a = args(&["machine", "credentials", "add", "-n", name]);
        for c in creds {
            flag(&mut a, "--credential", c.arg());
        }
        checked(self.runner.run_with_env(&a, env, &[])?).map(drop)
    }

    /// Packs the stopped machine's filesystem into `<out>.smolmachine` (and an executable stub
    /// at `out`, which callers delete). Unsigned: the stub is never run.
    pub fn pack_from_vm(&self, machine: &str, out: &Path) -> Result<()> {
        let mut a = args(&["pack", "create", "--from-vm", machine, "--no-sign"]);
        flag(&mut a, "-o", out.display().to_string());
        self.call(a).map(drop)
    }

    /// A copy-on-write child of the running, branchable `from`: its memory, processes and disk. Its
    /// credential values come from this process's environment, like `start`'s.
    pub fn branch(
        &self,
        from: &str,
        name: &str,
        labels: &[(String, String)],
        vars: &[(String, String)],
        env: &[(String, String)],
        remove: &[String],
    ) -> Result<()> {
        let mut a = args(&["machine", "branch", "--from", from, "-n", name]);
        for (k, v) in labels {
            flag(&mut a, "--label", format!("{k}={v}"));
        }
        // Per-branch variables: the child's exec sessions see them (not secrets; they're argv).
        for (k, v) in vars {
            flag(&mut a, "-e", format!("{k}={v}"));
        }
        checked(self.runner.run_with_env(&a, env, remove)?).map(drop)
    }

    /// Replaces the machine's whole allow list; applies live on a running machine.
    pub fn update_network(&self, name: &str, network: &NetworkSpec) -> Result<()> {
        let mut a = args(&["machine", "update", "-n", name]);
        a.extend(network.update_args());
        self.call(a).map(drop)
    }

    /// Sets one label; works running or stopped (smolvm 1.35).
    pub fn set_label(&self, name: &str, key: &str, value: &str) -> Result<()> {
        self.call(args(&[
            "machine",
            "update",
            "-n",
            name,
            "--label",
            &format!("{key}={value}"),
        ]))?;
        Ok(())
    }

    /// Sets several labels in one update, so they change together; running or stopped.
    pub fn set_labels(&self, name: &str, labels: &[(&str, String)]) -> Result<()> {
        let mut a = args(&["machine", "update", "-n", name]);
        for (k, v) in labels {
            flag(&mut a, "--label", format!("{k}={v}"));
        }
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

    /// `list` against smolvm's own default state (without smolbento's `SMOLVM_DATA_DIR`), where
    /// sandboxes from before smolbento kept its own state may still be.
    pub fn list_default_state(&self) -> Result<Vec<Machine>> {
        machines(&self.call_default_state(&["machine", "ls", "--json"])?)
    }

    /// `delete` in smolvm's own default state (see `list_default_state`).
    pub fn delete_default_state(&self, name: &str) -> Result<()> {
        self.call_default_state(&["machine", "delete", "-n", name, "-f"])
            .map(drop)
    }

    /// A call without smolbento's `SMOLVM_DATA_DIR`.
    fn call_default_state(&self, a: &[&str]) -> Result<Output> {
        checked(
            self.runner
                .run_with_env(&args(a), &[], &[DATA_DIR.to_string()])?,
        )
    }

    pub fn delete(&self, name: &str) -> Result<()> {
        self.call(args(&["machine", "delete", "-n", name, "-f"]))
            .map(drop)
    }

    pub fn cp(&self, src: &str, dst: &str) -> Result<()> {
        self.call(args(&["machine", "cp", src, dst])).map(drop)
    }

    /// Uploads the host folder `src` into exactly `dst` in the running machine (smolvm 1.35.4).
    /// `dst`'s parent must exist.
    pub fn upload_folder(&self, name: &str, src: &Path, dst: &str) -> Result<()> {
        let src = src.display().to_string();
        self.call(args(&[
            "machine",
            "files",
            "--name",
            name,
            "upload-folder",
            &src,
            dst,
        ]))
        .map(drop)
    }

    /// Downloads the running machine's file `src` to the host's `dst` (smolvm 1.35.4).
    pub fn download(&self, name: &str, src: &str, dst: &Path) -> Result<()> {
        let dst = dst.display().to_string();
        self.call(args(&[
            "machine", "files", "--name", name, "download", src, &dst,
        ]))
        .map(drop)
    }

    /// Downloads the running machine's directory `src` to the host's `dst` as a tar archive,
    /// without following its links (smolvm 1.35.4).
    pub fn archive(&self, name: &str, src: &str, dst: &Path) -> Result<()> {
        let dst = dst.display().to_string();
        self.call(args(&[
            "machine", "files", "--name", name, "archive", src, &dst,
        ]))
        .map(drop)
    }

    /// Whether `path` in the running machine is a directory: `machine files list` lists only
    /// directories (smolvm 1.35.4), and its error for anything else has no code of its own.
    pub fn is_dir(&self, name: &str, path: &str) -> bool {
        self.call(args(&[
            "machine", "files", "--name", name, "list", path, "--json",
        ]))
        .is_ok()
    }

    /// Runs an exec attached to this terminal and returns the command's exit code.
    pub fn exec(&self, spec: &ExecSpec) -> Result<i32> {
        self.runner.interactive(&spec.to_args())
    }

    /// Starts processes with piped or pty stdio (`None` when the runner can't).
    pub fn spawner(&self) -> Result<Option<crate::smolvm::ProcessSpawner>> {
        self.runner.spawner()
    }

    /// Runs an exec with captured output; fails if it exits non-zero.
    pub fn exec_captured(&self, spec: &ExecSpec) -> Result<Output> {
        self.call(spec.to_args())
    }

    /// `exec_captured` that returns a non-zero exit as output too, for callers that report the
    /// guest command's own stdout and stderr.
    pub fn exec_output(&self, spec: &ExecSpec) -> Result<Output> {
        self.runner.run(&spec.to_args())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smolvm::fake::FakeRunner;
    use crate::smolvm::{AllowList, MachineState};

    #[test]
    fn start_is_branchable_only_when_asked() {
        let fake = FakeRunner::new();
        fake.ok(&["machine", "start"], "");
        let vm = Smolvm::new(fake);
        vm.start("m", true, &[], &[], &mut |_| {}).unwrap();
        vm.start("m", false, &[], &[], &mut |_| {}).unwrap();
        assert_eq!(
            vm.runner().call_lines(),
            vec!["machine start -n m --branchable", "machine start -n m"]
        );
    }

    #[test]
    fn branch_passes_labels_in_argv_and_secrets_in_env() {
        let fake = FakeRunner::new();
        fake.ok(&["machine", "branch"], "");
        let vm = Smolvm::new(fake);
        vm.branch(
            "sbx-a",
            "sbx-a-fork-1",
            &[
                ("sbx.name".into(), "a-fork-1".into()),
                ("sbx.fork-of".into(), "a".into()),
            ],
            &[("V".into(), "1".into())],
            &[("TOK".into(), "secret-value".into())],
            &["GH_TOKEN".into()],
        )
        .unwrap();
        let line = &vm.runner().call_lines()[0];
        assert_eq!(
            line,
            "machine branch --from sbx-a -n sbx-a-fork-1 --label sbx.name=a-fork-1 \
             --label sbx.fork-of=a -e V=1"
        );
        assert!(!line.contains("secret-value"));
        assert_eq!(
            vm.runner().envs()[0],
            vec![("TOK".into(), "secret-value".into())]
        );
        assert_eq!(vm.runner().removed()[0], vec!["GH_TOKEN".to_string()]);
    }

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
            mount_sockets: vec![("/tmp/sbt-501/ab.sock".into(), "/run/b.sock".into())],
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
             --label sbx.name=claude-repo -v /w:/w -v /docs:/docs:ro -v /var/lib/docker \
             --mount-socket /tmp/sbt-501/ab.sock:/run/b.sock -w /w --cpus 2 --mem 4096 -e A=1 \
             -p 8080:80 -p 53:53/udp -u root -- sleep infinity"
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
                env_var: "GH_TOKEN".into(),
                hosts: vec!["github.com".into(), "api.github.com".into()],
                ..Default::default()
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
        vm.start(
            "m",
            true,
            &[("TOK".into(), "secret".into())],
            &["GONE".into()],
            &mut |_| {},
        )
        .unwrap();
        assert_eq!(
            vm.runner().call_lines(),
            vec!["machine start -n m --branchable"]
        );
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
    fn add_credentials_args() {
        let vm = Smolvm::new(FakeRunner::new());
        let creds = [
            Credential {
                env_var: "GH_TOKEN".into(),
                hosts: vec!["github.com".into(), "api.github.com".into()],
                set_header: None,
            },
            Credential {
                env_var: "X_KEY".into(),
                hosts: vec!["x.example".into()],
                set_header: Some("X-Api-Key".into()),
            },
        ];
        let env = [
            ("GH_TOKEN".to_string(), "secret-gh".to_string()),
            ("X_KEY".to_string(), "secret-x".to_string()),
        ];
        vm.add_credentials("sbx-a", &creds, &env).unwrap();
        let line = &vm.runner().call_lines()[0];
        assert_eq!(
            line,
            "machine credentials add -n sbx-a \
             --credential gh_token=GH_TOKEN@github.com,api.github.com \
             --credential x_key=X_KEY@x.example:set-header=X-Api-Key"
        );
        assert!(!line.contains("secret-"));
        assert_eq!(vm.runner().envs(), [env.to_vec()]);
    }

    #[test]
    fn set_labels_updates_them_in_one_call() {
        let vm = Smolvm::new(FakeRunner::new());
        vm.set_labels("sbx-x", &[("sbx.a", "1".into()), ("sbx.b", "x,y".into())])
            .unwrap();
        assert_eq!(
            vm.runner().call_lines(),
            ["machine update -n sbx-x --label sbx.a=1 --label sbx.b=x,y"]
        );
    }

    #[test]
    fn set_label_updates_one_label() {
        let vm = Smolvm::new(FakeRunner::new());
        vm.set_label("sbx-x", "sbx.kits", "[]").unwrap();
        assert_eq!(
            vm.runner().call_lines(),
            ["machine update -n sbx-x --label sbx.kits=[]"]
        );
    }

    #[test]
    fn emptying_the_host_list_is_one_reset() {
        let vm = Smolvm::new(FakeRunner::new());
        let deny_all = NetworkSpec::Restricted(AllowList::new(vec![], vec![], vec![]));
        vm.update_network("m", &deny_all).unwrap();
        assert_eq!(
            vm.runner().call_lines(),
            [
                "machine update -n m --reset-allow-list --allow-cidr 127.0.0.0/8 --allow-cidr ::1/128"
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
    fn create_from_a_pack_replaces_the_image() {
        let spec = CreateSpec {
            name: "sbx-b".into(),
            image: "img:1".into(),
            from: Some("/d/templates/abc.smolmachine".into()),
            ..Default::default()
        };
        let line = spec.to_args().join(" ");
        assert!(
            line.starts_with("machine create -n sbx-b --from /d/templates/abc.smolmachine"),
            "{line}"
        );
        assert!(!line.contains("--image"), "{line}");
    }

    #[test]
    fn create_sizes_the_disks_in_gib() {
        let spec = CreateSpec {
            name: "sbx-d".into(),
            image: "img:1".into(),
            storage_gib: Some(30),
            overlay_gib: Some(24),
            ..Default::default()
        };
        let line = spec.to_args().join(" ");
        assert!(line.contains(" --storage 30 --overlay 24"), "{line}");
        let plain = CreateSpec::default().to_args().join(" ");
        assert!(
            !plain.contains("--storage") && !plain.contains("--overlay"),
            "{plain}"
        );
    }

    #[test]
    fn pack_from_vm_args() {
        let fake = FakeRunner::new();
        fake.ok(&["pack", "create"], "");
        let vm = Smolvm::new(fake);
        vm.pack_from_vm("sbx-a", Path::new("/t/pack")).unwrap();
        assert_eq!(
            vm.runner().call_lines(),
            vec!["pack create --from-vm sbx-a --no-sign -o /t/pack"]
        );
    }

    #[test]
    fn set_header_and_smolfile_args() {
        let spec = CreateSpec {
            name: "m".into(),
            smolfile: Some("/k/Smolfile".into()),
            credentials: vec![Credential {
                env_var: "SBX_KIT_X".into(),
                hosts: vec!["api.x.com".into()],
                set_header: Some("authorization".into()),
            }],
            ..Default::default()
        };
        assert_eq!(
            spec.to_args().join(" "),
            "machine create -n m --smolfile /k/Smolfile --net --net-backend virtio-net \
             --credential sbx_kit_x=SBX_KIT_X@api.x.com:set-header=authorization"
        );
    }

    #[test]
    #[should_panic(expected = "at least one host")]
    #[cfg(debug_assertions)]
    fn a_credential_without_hosts_is_refused() {
        let c = Credential {
            env_var: "T".into(),
            hosts: vec![],
            ..Default::default()
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
    fn start_reports_pull_progress_and_still_passes_env() {
        let fake = FakeRunner::new();
        fake.progress(
            &["machine", "start"],
            &[
                "Pulling image alpine...",
                "Pulling image alpine... [==>                 ] 10%",
                "something else",
                "Pulling image alpine... [====================] 100% — syncing...",
                "Pulling image alpine... done.",
            ],
        );
        let vm = Smolvm::new(fake);
        let mut seen = Vec::new();
        vm.start("m", false, &[("T".into(), "v".into())], &[], &mut |p| {
            seen.push(p)
        })
        .unwrap();
        assert_eq!(seen, [PullProgress::Percent(10), PullProgress::Syncing]);
        assert_eq!(vm.runner().call_lines(), vec!["machine start -n m"]);
        assert_eq!(
            vm.runner().envs(),
            vec![vec![("T".to_string(), "v".to_string())]]
        );
    }

    #[test]
    fn start_failure_is_an_error() {
        let fake = FakeRunner::new();
        fake.fail(&["machine", "start"], "SMOLVM_ERROR", "boom");
        let err = Smolvm::new(fake)
            .start("m", true, &[], &[], &mut |_| {})
            .unwrap_err();
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
    fn sh_builds_a_shell_exec_as_a_user() {
        assert_eq!(
            ExecSpec::sh("sbx-a", "root", "id").to_args().join(" "),
            "machine exec --name sbx-a -u root -- sh -c id"
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
            stream: false,
            timeout: None,
            cmd: vec!["ls".into(), "-la".into()],
        };
        assert_eq!(
            spec.to_args().join(" "),
            "machine exec --name sbx-a -u agent -w /w -e K=v -i -t -- ls -la"
        );
        let bounded = ExecSpec {
            timeout: Some(std::time::Duration::from_secs(2)),
            ..ExecSpec::new("sbx-a", "root", vec!["true".into()])
        };
        assert_eq!(
            bounded.to_args().join(" "),
            "machine exec --name sbx-a -u root --timeout 2s -- true"
        );
        let plain = ExecSpec {
            name: "sbx-a".into(),
            stream: true,
            cmd: vec!["ls".into()],
            ..Default::default()
        };
        assert_eq!(
            plain.to_args().join(" "),
            "machine exec --name sbx-a --stream -- ls"
        );
    }

    #[test]
    fn version_takes_last_word() {
        let fake = FakeRunner::new();
        fake.ok(&["--version"], "smolvm 1.34.1\n");
        assert_eq!(Smolvm::new(fake).version().unwrap(), "1.34.1");
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
        vm.start("m", true, &[], &[], &mut |_| {}).unwrap();
        vm.stop("m").unwrap();
        vm.delete("m").unwrap();
        vm.cp("/a", "m:/b").unwrap();
        vm.upload_folder("m", Path::new("/kit"), "/build/1/ctx")
            .unwrap();
        vm.download("m", "/build/1/kit.tar", Path::new("/c/kit.tar"))
            .unwrap();
        vm.archive("m", "/w/src", Path::new("/c/src.tar")).unwrap();
        assert!(vm.is_dir("m", "/w/src"));
        assert_eq!(
            vm.runner().call_lines(),
            vec![
                "machine start -n m --branchable",
                "machine stop -n m",
                "machine delete -n m -f",
                "machine cp /a m:/b",
                "machine files --name m upload-folder /kit /build/1/ctx",
                "machine files --name m download /build/1/kit.tar /c/kit.tar",
                "machine files --name m archive /w/src /c/src.tar",
                "machine files --name m list /w/src --json",
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
