use crate::smolvm::{CreateSpec, Credential, Mount, NetworkSpec, PortMap};
use crate::workspace::Workspace;
use crate::workspace::clone::{CloneSource, SOURCE_MOUNT};

use super::labels::Meta;
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
    /// Give the sandbox a private dockerd (storage on the machine's own disk).
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
    /// `--clone`: the host repo the sandbox clones; its git dir replaces the primary workspace's
    /// mount.
    pub clone: Option<CloneSource>,
}

/// Docker can't keep its storage on the overlay root filesystem, so these are directories on the
/// machine's own disk (they survive restarts).
const DOCKER_VOLUMES: [&str; 2] = ["/var/lib/docker", "/var/lib/containerd"];

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
        clone_repo: req.clone.as_ref().map(|c| c.top.display().to_string()),
        fork_of: None,
    }
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
    if req.docker {
        mounts.extend(DOCKER_VOLUMES.map(|d| Mount {
            host: None,
            guest: d.into(),
            read_only: false,
        }));
    }
    CreateSpec {
        name: name::machine_name(&req.name),
        image: req.image.clone(),
        labels: meta.to_labels(),
        mounts,
        workdir: meta.clone_repo.clone().or_else(|| meta.workspace.clone()),
        cpus: Some(req.cpus),
        memory_mib: Some(req.memory_mib),
        env: req.env.clone(),
        ports: req.ports.clone(),
        network: req.network.clone(),
        deny_cidrs: req.deny_cidrs.clone(),
        credentials: req.credentials.clone(),
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
        let spec = spec(&request(true, ws));
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
