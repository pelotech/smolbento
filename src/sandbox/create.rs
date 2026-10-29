use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::bridge;
use crate::smolvm::{CreateSpec, Credential, Mount, NetworkSpec, PortMap};
use crate::workspace::clone::{CloneSource, SOURCE_MOUNT};
use crate::workspace::{MOUNTLESS_WORKDIR, Workspace};

use super::labels::{CredFormat, Meta};
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
    pub env: Vec<(String, String)>,
    pub ports: Vec<PortMap>,
    /// The sandbox has a private dockerd (the `sbx.docker` label). Before kits are applied: the
    /// image should get the `docker` kit; `kits::apply` then sets it from the applied kits.
    pub docker: bool,
    pub created: i64,
    pub network: NetworkSpec,
    pub deny_cidrs: Vec<String>,
    pub credentials: Vec<Credential>,
    /// Services the credentials come from (the `sbx.secrets` label).
    pub secrets: Vec<String>,
    /// The credentials' hosts, sorted (the `sbx.credential-hosts` label).
    pub credential_hosts: Vec<String>,
    /// The credentials' env vars, sorted (the `sbx.credential-env` label).
    pub credential_env: Vec<String>,
    /// Stored registry hosts the kit builder binds (the `sbx.registries` label).
    pub registries: Vec<String>,
    /// `--clone`: the host repo the sandbox clones; its git dir replaces the primary workspace's
    /// mount.
    pub clone: Option<CloneSource>,
    /// The user gave `--cpus` / `-m`, which a kit's `resources@1` doesn't override.
    pub cpus_set: bool,
    pub memory_set: bool,
    /// Pinned refs of the applied kits (the `sbx.kits` label).
    pub kits: Vec<String>,
    /// The workload kit's launch argv (the `sbx.command` label).
    pub command: Option<Vec<String>>,
    /// A v3 workload kit's image user (the `sbx.user` label).
    pub user: Option<String>,
    /// A v3 workload kit's image WORKDIR, when not `/` (the `sbx.workdir` label).
    pub image_workdir: Option<String>,
    /// A workload kit's agent file in the guest (the `sbx.agent-file` label). `kits::apply`
    /// uses one already set (`kit add`) instead of deriving it.
    pub agent_file: Option<String>,
    /// Env vars of install-only credentials (the `sbx.credential-install` label).
    pub credential_install: Vec<String>,
    /// Kit credential value formats by env var (`sbx.credential-format.<ENV>` labels).
    pub credential_formats: BTreeMap<String, CredFormat>,
    /// Kit credential env vars to their service (`sbx.credential-service.<ENV>` labels).
    pub credential_services: BTreeMap<String, String>,
    /// `long-running@1` (the `sbx.long-running` label).
    pub long_running: bool,
    /// Created without the host loopback deny, as a `localhost` rule applied (the
    /// `sbx.host-access` label).
    pub host_access: bool,
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

/// The labels the sandbox gets.
pub fn meta(req: &CreateRequest) -> Meta {
    let primary = req.workspaces.first().map(|w| w.path.display().to_string());
    Meta {
        name: req.name.clone(),
        agent: req.agent.clone(),
        workspace: primary,
        workspaces: req.workspaces.iter().map(Workspace::label).collect(),
        created: req.created,
        docker: req.docker,
        secrets: req.secrets.clone(),
        credential_hosts: req.credential_hosts.clone(),
        credential_env: req.credential_env.clone(),
        registries: req.registries.clone(),
        clone_repo: req.clone.as_ref().map(|c| c.top.display().to_string()),
        fork_of: None,
        kits: req.kits.clone(),
        command: req.command.clone(),
        user: req.user.clone(),
        image_workdir: req.image_workdir.clone(),
        agent_file: req.agent_file.clone(),
        credential_install: req.credential_install.clone(),
        long_running: req.long_running,
        host_access: req.host_access,
        // Internal sandboxes (`_builder`) never have a user attached.
        bridge: !req.no_bridge && !name::is_internal(&req.name),
        credential_formats: req.credential_formats.clone(),
        credential_services: req.credential_services.clone(),
        host_mounts: req
            .host_mounts
            .iter()
            .map(|(host, guest)| (guest.clone(), host.display().to_string()))
            .collect(),
        ssh_agent: None,
    }
}

/// Leaves the bridge out when `private` says the host's socket directory (`/tmp/sbt-<uid>`)
/// isn't private to this user; returns the warning.
pub fn drop_unsafe_bridge(
    req: &mut CreateRequest,
    private: impl FnOnce(&Path) -> bool,
) -> Option<String> {
    let dir = bridge::socket_dir();
    if !meta(req).bridge || private(&dir) {
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
    let mount_sockets = if meta.bridge {
        vec![(bridge::host_socket(&req.name), bridge::GUEST_SOCKET.into())]
    } else {
        vec![]
    };
    CreateSpec {
        name: name::machine_name(&req.name),
        image: req.image.clone(),
        labels: meta.to_labels(),
        mounts,
        mount_sockets,
        workdir: meta.clone_repo.clone().or_else(|| meta.workspace.clone()),
        cpus: Some(req.cpus),
        memory_mib: Some(req.memory_mib),
        env: req.env.clone(),
        ports: req.ports.clone(),
        network: req.network.clone(),
        deny_cidrs: req.deny_cidrs.clone(),
        credentials: req.credentials.clone(),
        smolfile: req.smolfile.clone(),
        // The workload runs as root so startup steps (dockerd) can; agents exec as `agent`.
        user: Some("root".into()),
        cmd: vec!["sleep".into(), "infinity".into()],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            docker,
            created: 1000,
            ..Default::default()
        }
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
        assert_eq!(spec.user.as_deref(), Some("root"));
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
}
