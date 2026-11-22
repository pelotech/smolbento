use std::path::{Path, PathBuf};

use crate::bridge;
use crate::smolvm::{CreateSpec, Credential, Mount, NetworkSpec, PortMap};
use crate::ssh_agent::{self as agent, AgentLabel};
use crate::workspace::clone::{CloneSource, SOURCE_MOUNT};
use crate::workspace::{MOUNTLESS_WORKDIR, Workspace};

use super::labels::{Engine, Meta, Recorded};
use super::name;

/// Everything decided about a new sandbox before it's created.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CreateRequest {
    pub name: String,
    pub agent: String,
    pub image: String,
    /// Primary first. Empty for a mountless sandbox.
    pub workspaces: Vec<Workspace>,
    pub cpus: u32,
    pub memory_mib: u64,
    /// Disk sizes in GiB; `None` keeps smolvm's defaults.
    pub storage_gib: Option<u32>,
    pub overlay_gib: Option<u32>,
    pub env: Vec<(String, String)>,
    pub ports: Vec<PortMap>,
    /// The sandbox's private dockerd (the `sbx.docker` label); `kits::apply` sets it from the
    /// applied kits' `dockerd@1`.
    pub engine: Engine,
    pub created: i64,
    pub network: NetworkSpec,
    pub deny_cidrs: Vec<String>,
    pub credentials: Vec<Credential>,
    /// Hosted egress: set when `credentials` are swapped by bento's interceptor, not smolvm.
    pub egress: Option<crate::egress::Prepared>,
    /// What `meta` records as labels unchanged.
    pub rec: Recorded,
    /// `--clone`: the host repo the sandbox clones; its git dir replaces the primary workspace's
    /// mount.
    pub clone: Option<CloneSource>,
    /// The user gave `--cpus` / `-m`, which a kit's `resources@1` doesn't override.
    pub cpus_set: bool,
    pub memory_set: bool,
    /// The workload declares `sbx@1`: the host launches its agent (in `run` or `exec`, under
    /// bash), so its image entrypoint isn't started at boot.
    pub launched_by_host: bool,
    /// `(host, guest)`: the `--mount` bindings until kits are applied; then every kit
    /// `host-mount@1`, in kit order (the `sbx.host-mounts` label).
    pub host_mounts: Vec<(PathBuf, String)>,
    /// Extra guest-only volumes (kit `volume@1`, non-tmpfs).
    pub volumes: Vec<String>,
    /// tmpfs volumes, mounted by a kit startup step (`mount -t tmpfs`), not by smolvm.
    pub tmpfs: Vec<String>,
    /// A Smolfile workload kit, passed with `--smolfile`.
    pub smolfile: Option<PathBuf>,
    /// Created without the browser and clipboard bridge: the host's socket directory isn't
    /// private (`drop_unsafe_bridge`).
    pub no_bridge: bool,
    /// The host sockets units serve for this sandbox (`host_service`); `None`: they are served
    /// while a session is attached, at the `bridge::host_socket` paths.
    pub host_services: Option<crate::host_service::Sockets>,
    /// The SSH agent granted per phase once availability and the socket directory were checked
    /// (the `sbx.ssh-agent` label); `None`: no agent.
    pub ssh_agent: Option<AgentLabel>,
    /// `--skills` resolved (Phase 5c); the directories come from `prepare_create`.
    pub skills_mode: crate::skills::Mode,
    /// The store mount and `sbx.skills` label; `None` without skills directories.
    pub skills: Option<crate::skills::Setup>,
    /// `-t` named a saved template (`rec.template`): its pack, created with `--from` in place of
    /// the image.
    pub template_pack: Option<PathBuf>,
    /// The `--static-mcp` value as given; `provision` resolves it into `mcp_servers`.
    pub mcp: Option<String>,
    /// The registered MCP servers attached (the `sbx.mcp` label); `None` without the flag.
    pub mcp_servers: Option<Vec<String>>,
}

impl CreateRequest {
    /// The sandbox's working directory in the guest, as `Sandbox::workdir` gives it once created:
    /// the primary workspace (inside the clone with `--clone`), or sbx's mountless directory.
    pub fn workdir(&self) -> String {
        self.workspaces.first().map_or_else(
            || MOUNTLESS_WORKDIR.into(),
            |w| w.path.display().to_string(),
        )
    }
}

/// The machine's workload user, which smolvm maps the workspace to: the session user
/// (`Meta::session_user`), root for an internal sandbox (`_builder`).
pub(super) fn workload_user(meta: &Meta) -> String {
    if name::is_internal(&meta.name) {
        return "root".into();
    }
    meta.session_user().into()
}

/// The labels the sandbox gets.
pub fn meta(req: &CreateRequest) -> Meta {
    let primary = req.workspaces.first().map(|w| w.path.display().to_string());
    Meta {
        name: req.name.clone(),
        agent: req.agent.clone(),
        workspace: primary,
        workspaces: req.workspaces.iter().map(Workspace::label).collect(),
        created: req.created,
        version: Some(env!("CARGO_PKG_VERSION").into()),
        engine: req.engine,
        rec: req.rec.clone(),
        clone_repo: req.clone.as_ref().map(|c| c.top.display().to_string()),
        fork_of: None,
        // Internal sandboxes (`_builder`) never have a user attached.
        bridge: !req.no_bridge && !name::is_internal(&req.name),
        service: req.host_services.is_some() && !name::is_internal(&req.name),
        host_mounts: req
            .host_mounts
            .iter()
            .map(|(host, guest)| (guest.clone(), host.display().to_string()))
            .collect(),
        // Internal sandboxes run untrusted build steps: never an agent.
        egress: req.egress.as_ref().map(|p| p.label.clone()),
        ssh_agent: req
            .ssh_agent
            .clone()
            .filter(|_| !name::is_internal(&req.name)),
        skills: req.skills.as_ref().map(|s| s.label.clone()),
        mcp: req.mcp_servers.clone(),
    }
}

/// Leaves the bridge out when `private` says the host's socket directory (`/tmp/sbt-<uid>`)
/// isn't private to this user; returns the warning.
pub fn drop_unsafe_bridge(
    req: &mut CreateRequest,
    private: impl FnOnce(&Path) -> bool,
) -> Option<String> {
    let dir = bridge::socket_dir();
    // Units serve a sandbox's sockets from their own directory, checked by `HostServices::plan`.
    if !meta(req).bridge || req.host_services.is_some() || private(&dir) {
        return None;
    }
    req.no_bridge = true;
    Some(format!(
        "warning: {} isn't a private directory owned by you; {} gets no browser or clipboard bridge",
        dir.display(),
        req.name
    ))
}

pub fn spec(req: &CreateRequest) -> CreateSpec {
    let meta = meta(req);
    let mut mounts = Vec::new();
    let mut rest = req.workspaces.iter();
    match (&req.clone, rest.next()) {
        // The primary workspace is the clone: its git dir and a guest-only volume stand in for it.
        (Some(c), Some(_)) => {
            mounts.push(Mount {
                host: Some(c.git_dir.clone()),
                guest: SOURCE_MOUNT.into(),
                read_only: true,
            });
            mounts.push(Mount {
                host: None,
                guest: c.top.display().to_string(),
                read_only: false,
            });
        }
        (None, Some(w)) => mounts.push(w.mount()),
        (_, None) => {}
    }
    mounts.extend(rest.map(Workspace::mount));
    mounts.extend(req.host_mounts.iter().map(|(host, guest)| Mount {
        host: Some(host.clone()),
        guest: guest.clone(),
        read_only: false,
    }));
    if let Some(s) = &req.skills {
        mounts.extend(crate::skills::mounts(&s.store, &s.label));
    }
    for v in &req.volumes {
        // Two kits may ask for the same volume.
        if !mounts.iter().any(|m| m.guest == *v) {
            mounts.push(Mount {
                host: None,
                guest: v.clone(),
                read_only: false,
            });
        }
    }
    let mut mount_sockets = Vec::new();
    if meta.bridge {
        let host = match &req.host_services {
            Some(s) => s.bridge.clone(),
            None => bridge::host_socket(&req.name),
        };
        mount_sockets.push((host, bridge::GUEST_SOCKET.into()));
    }
    let mut env = req.env.clone();
    if let Some(grant) = &meta.ssh_agent {
        let host = match &req.host_services {
            Some(s) => s.agent.clone(),
            None => bridge::agent_socket(&req.name),
        };
        mount_sockets.push((host, agent::GUEST_SOCKET.into()));
        // A runtime grant's sessions find the agent; an install-only one's hooks set it themselves
        // (`kits::apply`). The user's -e wins.
        if grant.runtime.is_some() {
            crate::util::env_default(&mut env, "SSH_AUTH_SOCK", agent::GUEST_SOCKET);
        }
    }
    // Hosted egress: the guest gets placeholders and the CA, and smolvm no credential.
    if let Some(p) = &req.egress {
        mounts.push(Mount {
            host: Some(p.ca_guest_dir.clone()),
            guest: "/run/smol/credentials".into(),
            read_only: true,
        });
        env.extend(
            p.label
                .bindings
                .iter()
                .map(|b| (b.env.clone(), b.placeholder.clone())),
        );
        for var in [
            "SSL_CERT_FILE",
            "NODE_EXTRA_CA_CERTS",
            "REQUESTS_CA_BUNDLE",
            "CURL_CA_BUNDLE",
            "GIT_SSL_CAINFO",
        ] {
            crate::util::env_default(&mut env, var, "/run/smolvm/ca-bundle.pem");
        }
    }
    CreateSpec {
        name: name::machine_name(&req.name),
        image: req.image.clone(),
        labels: meta.to_labels(),
        mounts,
        mount_sockets,
        workdir: meta.clone_repo.clone().or_else(|| meta.workspace.clone()),
        cpus: Some(req.cpus),
        memory_mib: Some(req.memory_mib),
        storage_gib: req.storage_gib,
        overlay_gib: req.overlay_gib,
        env,
        ports: req.ports.clone(),
        network: req.network.clone(),
        deny_cidrs: req.deny_cidrs.clone(),
        credentials: if req.egress.is_some() {
            Vec::new()
        } else {
            req.credentials.clone()
        },
        smolfile: req.smolfile.clone(),
        from: req.template_pack.clone(),
        // The workload user is the one sessions run as: smolvm shows the workspace as owned by
        // it. Startup steps exec as root explicitly.
        user: Some(workload_user(&meta)),
        cmd: boot_command(req),
    }
}

/// What the machine runs at every boot (smolvm reruns it on each start, and keeps the machine up
/// after it exits). A v3 workload kit launches its image's `Entrypoint` + `Cmd`, as the kit spec's
/// default launch mode says (an image user, `sbx.user`, marks a v3 workload), unless it declares
/// `sbx@1` (the host launches its agent, as for every built-in agent); every other sandbox, the
/// internal builder included, just idles for `exec` and sessions.
fn boot_command(req: &CreateRequest) -> Vec<String> {
    match (&req.rec.user, &req.rec.command) {
        (Some(_), Some(c))
            if !c.is_empty() && !req.launched_by_host && !name::is_internal(&req.name) =>
        {
            c.clone()
        }
        _ => vec!["sleep".into(), "infinity".into()],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssh_agent::Access;

    fn request(docker: bool, workspaces: Vec<Workspace>) -> CreateRequest {
        CreateRequest {
            name: "claude.repo".into(),
            agent: "claude".into(),
            image: "img".into(),
            workspaces,
            cpus: 2,
            memory_mib: 4096,
            env: vec![("A".into(), "1".into())],
            ports: vec![PortMap {
                host: 8080,
                guest: 80,
                udp: false,
            }],
            engine: if docker { Engine::Auto } else { Engine::Off },
            created: 1000,
            ..Default::default()
        }
    }

    #[test]
    fn the_workload_user_is_the_session_user() {
        let user = |name: &str, user: Option<&str>| {
            let mut req = request(false, vec![]);
            req.name = name.into();
            req.rec.user = user.map(String::from);
            spec(&req).user
        };
        // No image user: `agent`. A v3 workload: its image user, `0` when the image names none.
        assert_eq!(user("claude.repo", None).as_deref(), Some("agent"));
        assert_eq!(
            user("tool", Some("somebody:1001")).as_deref(),
            Some("somebody:1001")
        );
        assert_eq!(user("tool", Some("0")).as_deref(), Some("0"));
        // The internal builder stays root.
        assert_eq!(user("_builder", None).as_deref(), Some("root"));
    }

    #[test]
    fn a_v3_workload_boots_its_image_command_and_everything_else_idles() {
        let cmd = |name: &str, user: Option<&str>, command: Option<&[&str]>| {
            let mut req = request(false, vec![]);
            req.name = name.into();
            req.rec.user = user.map(String::from);
            req.rec.command = command.map(|c| c.iter().map(|s| s.to_string()).collect());
            spec(&req)
        };
        let idle = ["sleep", "infinity"];
        // A v3 workload (an image user): its Entrypoint + Cmd, as that user, after `--`.
        let wl = cmd(
            "tool",
            Some("somebody:1001"),
            Some(&["/bin/agent", "--x", "run"]),
        );
        assert_eq!(wl.cmd, ["/bin/agent", "--x", "run"]);
        let args = wl.to_args();
        let tail = &args[args.len() - 6..];
        assert_eq!(
            tail,
            ["-u", "somebody:1001", "--", "/bin/agent", "--x", "run"]
        );
        // No image user, a v2 workload (a command but no image user), a v3 image without a command,
        // and the internal builder keep `sleep infinity`.
        assert_eq!(cmd("claude.repo", None, None).cmd, idle);
        // A built-in agent's kit idles too: its agent starts in `run` or `exec`, on a terminal.
        let mut req = request(false, vec![]);
        req.name = "claude-x".into();
        req.rec.user = Some("agent".into());
        req.rec.command = Some(vec!["claude".into()]);
        req.launched_by_host = true;
        assert_eq!(spec(&req).cmd, idle);
        assert_eq!(cmd("tool", None, Some(&["wl"])).cmd, idle);
        assert_eq!(cmd("tool", Some("0"), None).cmd, idle);
        assert_eq!(cmd("tool", Some("0"), Some(&[])).cmd, idle);
        assert_eq!(cmd("_builder", Some("0"), Some(&["wl"])).cmd, idle);
    }

    #[test]
    fn a_template_sandbox_is_created_from_its_pack() {
        let mut req = request(false, vec![]);
        req.rec.template = Some("docker.io/library/t:v1".into());
        req.template_pack = Some("/d/templates/abc.smolmachine".into());
        let spec = spec(&req);
        assert_eq!(
            spec.from,
            Some(PathBuf::from("/d/templates/abc.smolmachine"))
        );
        assert_eq!(
            spec.labels.get("sbx.template").unwrap(),
            "docker.io/library/t:v1"
        );
    }

    /// Docker's storage comes from the docker kit's `volume@1`s (`req.volumes`).
    #[test]
    fn spec_with_workspace_and_docker() {
        let ws = vec![
            Workspace {
                path: "/w/repo".into(),
                read_only: false,
            },
            Workspace {
                path: "/w/docs".into(),
                read_only: true,
            },
        ];
        let mut req = request(true, ws);
        req.volumes = vec!["/var/lib/docker".into(), "/var/lib/containerd".into()];
        let spec = spec(&req);
        assert_eq!(spec.name, "sbx-claude_repo");
        assert_eq!(spec.labels["sbx.name"], "claude.repo");
        assert_eq!(spec.labels["sbx.workspace"], "/w/repo");
        assert_eq!(spec.labels["sbx.docker"], "true");
        let mounts: Vec<String> = spec
            .to_args()
            .windows(2)
            .filter(|w| w[0] == "-v")
            .map(|w| w[1].clone())
            .collect();
        assert_eq!(
            mounts,
            vec![
                "/w/repo:/w/repo",
                "/w/docs:/w/docs:ro",
                "/var/lib/docker",
                "/var/lib/containerd"
            ]
        );
        assert_eq!(spec.workdir.as_deref(), Some("/w/repo"));
        assert_eq!(spec.user.as_deref(), Some("agent"));
        assert_eq!(spec.cmd, vec!["sleep", "infinity"]);
    }

    #[test]
    fn new_sandboxes_get_the_bridge_socket_and_label() {
        let args = spec(&request(false, vec![])).to_args();
        let socket = format!(
            "{}:/run/smolbento/bridge.sock",
            bridge::host_socket("claude.repo").display()
        );
        assert!(
            args.windows(2)
                .any(|w| w[0] == "--mount-socket" && w[1] == socket),
            "{args:?}"
        );
        assert!(args.contains(&"sbx.bridge=true".to_string()), "{args:?}");
        // Not the internal builder: nobody attaches to it.
        let mut req = request(false, vec![]);
        req.name = "_builder".into();
        let args = spec(&req).to_args();
        assert!(!args.contains(&"--mount-socket".to_string()), "{args:?}");
        assert!(
            !args.iter().any(|a| a.starts_with("sbx.bridge")),
            "{args:?}"
        );
    }

    #[test]
    fn a_socket_dir_that_isnt_private_means_no_bridge() {
        let mut req = request(false, vec![]);
        let mut checked = None;
        let warning = drop_unsafe_bridge(&mut req, |dir| {
            checked = Some(dir.to_path_buf());
            false
        });
        let dir = bridge::socket_dir();
        assert_eq!(checked.as_deref(), Some(dir.as_path()));
        assert_eq!(
            warning.unwrap(),
            format!(
                "warning: {} isn't a private directory owned by you; claude.repo gets no browser \
                 or clipboard bridge",
                dir.display()
            )
        );
        let args = spec(&req).to_args();
        assert!(!args.contains(&"--mount-socket".to_string()), "{args:?}");
        assert!(
            !args.iter().any(|a| a.starts_with("sbx.bridge")),
            "{args:?}"
        );
        // A private one keeps it.
        let mut req = request(false, vec![]);
        assert_eq!(drop_unsafe_bridge(&mut req, |_| true), None);
        assert!(spec(&req).to_args().contains(&"--mount-socket".to_string()));
        // The builder has no bridge to drop: nothing checked.
        let mut req = request(false, vec![]);
        req.name = "_builder".into();
        assert_eq!(drop_unsafe_bridge(&mut req, |_| panic!("checked")), None);
    }

    #[test]
    fn host_mounts_go_after_workspaces_and_before_volumes() {
        let ws = vec![Workspace {
            path: "/w/repo".into(),
            read_only: false,
        }];
        let mut req = request(false, ws);
        req.host_mounts = vec![("/data/x".into(), "/home/agent/x".into())];
        req.volumes = vec!["/var/lib/docker".into()];
        let spec = spec(&req);
        let mounts: Vec<String> = spec
            .to_args()
            .windows(2)
            .filter(|w| w[0] == "-v")
            .map(|w| w[1].clone())
            .collect();
        assert_eq!(
            mounts,
            vec![
                "/w/repo:/w/repo",
                "/data/x:/home/agent/x",
                "/var/lib/docker"
            ]
        );
        assert_eq!(
            spec.labels["sbx.host-mounts"],
            r#"{"/home/agent/x":"/data/x"}"#
        );
        let plain = super::spec(&request(false, vec![]));
        assert!(!plain.labels.contains_key("sbx.host-mounts"));
    }

    #[test]
    fn clone_mounts_the_git_dir_read_only_and_a_guest_volume() {
        let ws = vec![
            Workspace {
                path: "/w/repo/sub".into(),
                read_only: false,
            },
            Workspace {
                path: "/w/docs".into(),
                read_only: true,
            },
        ];
        let mut req = request(false, ws);
        req.clone = Some(CloneSource {
            top: "/w/repo".into(),
            git_dir: "/w/repo/.git".into(),
        });
        let spec = spec(&req);
        let mounts: Vec<String> = spec
            .to_args()
            .windows(2)
            .filter(|w| w[0] == "-v")
            .map(|w| w[1].clone())
            .collect();
        assert_eq!(
            mounts,
            vec![
                "/w/repo/.git:/run/sandbox/source:ro",
                "/w/repo",
                "/w/docs:/w/docs:ro",
            ]
        );
        // The clone isn't there until the first start, so the workload starts in the volume.
        assert_eq!(spec.workdir.as_deref(), Some("/w/repo"));
        assert_eq!(spec.labels["sbx.clone"], "true");
        assert_eq!(spec.labels["sbx.clone-top"], "/w/repo");
        assert_eq!(spec.labels["sbx.workspace"], "/w/repo/sub");
    }

    #[test]
    fn clone_at_the_repo_top_has_no_clone_top_label() {
        let ws = vec![Workspace {
            path: "/w/repo".into(),
            read_only: false,
        }];
        let mut req = request(false, ws);
        req.clone = Some(CloneSource {
            top: "/w/repo".into(),
            git_dir: "/w/repo/.git".into(),
        });
        let spec = spec(&req);
        assert_eq!(spec.labels["sbx.clone"], "true");
        assert!(!spec.labels.contains_key("sbx.clone-top"));
    }

    #[test]
    fn mountless_without_docker() {
        let spec = spec(&request(false, vec![]));
        assert!(spec.mounts.is_empty());
        assert_eq!(spec.workdir, None);
        assert!(!spec.labels.contains_key("sbx.workspace"));
        assert_eq!(spec.labels["sbx.docker"], "false");
    }

    fn runtime_and_install(runtime: Option<Access>, install: Option<Access>) -> Option<AgentLabel> {
        Some(AgentLabel { runtime, install })
    }

    fn unrestricted() -> Option<Access> {
        Some(Access {
            sign: None,
            authenticate: vec![],
        })
    }

    fn agent_mounts(args: &[String]) -> Vec<String> {
        args.windows(2)
            .filter(|w| w[0] == "--mount-socket" && w[1].ends_with(":/run/ssh-agent.sock"))
            .map(|w| w[1].clone())
            .collect()
    }

    fn agent_env(args: &[String]) -> Vec<String> {
        args.windows(2)
            .filter(|w| w[0] == "-e" && w[1].starts_with("SSH_AUTH_SOCK="))
            .map(|w| w[1].clone())
            .collect()
    }

    /// A runtime grant: the socket, `SSH_AUTH_SOCK` in the sandbox env, and the label.
    #[test]
    fn a_runtime_grant_mounts_the_agent_socket_and_sets_ssh_auth_sock() {
        let mut req = request(false, vec![]);
        req.ssh_agent = runtime_and_install(
            unrestricted(),
            Some(Access {
                sign: Some(vec!["git".into()]),
                authenticate: vec![],
            }),
        );
        let spec = spec(&req);
        let args = spec.to_args();
        assert_eq!(
            agent_mounts(&args),
            [format!(
                "{}:/run/ssh-agent.sock",
                bridge::agent_socket("claude.repo").display()
            )]
        );
        assert_eq!(agent_env(&args), ["SSH_AUTH_SOCK=/run/ssh-agent.sock"]);
        assert_eq!(
            spec.labels["sbx.ssh-agent"],
            r#"{"runtime":{"sign":null},"install":{"sign":["git"]}}"#
        );
        // The bridge socket is still there.
        assert!(
            args.iter()
                .any(|a| a.ends_with(":/run/smolbento/bridge.sock")),
            "{args:?}"
        );
        // The user's -e wins.
        req.env.push(("SSH_AUTH_SOCK".into(), "/mine".into()));
        assert_eq!(
            agent_env(&super::spec(&req).to_args()),
            ["SSH_AUTH_SOCK=/mine"]
        );
    }

    /// An install-only grant: the socket and label, but `SSH_AUTH_SOCK` only for install hooks.
    #[test]
    fn an_install_only_grant_mounts_the_socket_without_ssh_auth_sock() {
        let mut req = request(false, vec![]);
        req.ssh_agent = runtime_and_install(None, unrestricted());
        let spec = spec(&req);
        let args = spec.to_args();
        assert_eq!(agent_mounts(&args).len(), 1, "{args:?}");
        assert!(agent_env(&args).is_empty(), "{args:?}");
        assert_eq!(spec.labels["sbx.ssh-agent"], r#"{"install":{"sign":null}}"#);
    }

    #[test]
    fn no_grant_means_no_agent_socket_env_or_label() {
        let spec = spec(&request(false, vec![]));
        let args = spec.to_args();
        assert!(agent_mounts(&args).is_empty(), "{args:?}");
        assert!(agent_env(&args).is_empty(), "{args:?}");
        assert!(!spec.labels.contains_key("sbx.ssh-agent"));
        // Nor for the internal builder, whatever it was given.
        let mut req = request(false, vec![]);
        req.name = "_builder".into();
        req.ssh_agent = runtime_and_install(unrestricted(), None);
        let args = super::spec(&req).to_args();
        assert!(agent_mounts(&args).is_empty(), "{args:?}");
        assert!(agent_env(&args).is_empty(), "{args:?}");
    }
}
