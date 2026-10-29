//! The browser and clipboard bridge: guest shims (`xdg-open`, `wl-copy`, …) that reach the host
//! over a socket smolvm mounts into the sandbox, served while a user is attached.

pub mod agent;
pub mod filter;
mod host;
mod relay;
mod server;
mod shims;

use std::fs;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::kits::registry::hex;

pub use host::{attach, handlers};
pub use server::{Handlers, Server, serve};
pub use shims::{install_cmd, remove_cmd};

/// Where the host socket appears in the guest (`--mount-socket`).
pub const GUEST_SOCKET: &str = "/run/smolbento/bridge.sock";

/// The sandbox's host socket: `/tmp/sbt-<uid>/<first 16 hex of sha256(name)>.sock`. Short on every
/// OS (macOS caps socket paths near 104 bytes) and fixed at create, so it can't follow `TMPDIR`.
pub fn host_socket(name: &str) -> PathBuf {
    socket_in(crate::sandbox::host_uid(), name)
}

/// The sandbox's host SSH agent socket (`ssh-agent@1`), beside its bridge socket:
/// `/tmp/sbt-<uid>/<first 16 hex of sha256(name)>.agent.sock`.
pub fn agent_socket(name: &str) -> PathBuf {
    agent_socket_in(crate::sandbox::host_uid(), name)
}

/// The directory of this user's host sockets, `/tmp/sbt-<uid>`.
pub fn socket_dir() -> PathBuf {
    dir_of(crate::sandbox::host_uid())
}

fn dir_of(uid: u32) -> PathBuf {
    PathBuf::from(format!("/tmp/sbt-{uid}"))
}

fn socket_in(uid: u32, name: &str) -> PathBuf {
    dir_of(uid).join(format!("{}.sock", socket_id(name)))
}

fn agent_socket_in(uid: u32, name: &str) -> PathBuf {
    dir_of(uid).join(format!("{}.agent.sock", socket_id(name)))
}

fn socket_id(name: &str) -> String {
    hex(&Sha256::digest(name.as_bytes()))[..16].to_string()
}

/// Whether `dir` is private to this user, for a sandbox's socket (checked at create and at every
/// start): created 0700 if missing, else a real directory (not a symlink) we own with mode 0700. In the shared `/tmp`, another
/// user could create it first and receive what the sandbox sends.
pub fn private_dir(dir: &Path) -> bool {
    private_dir_of(dir, crate::sandbox::host_uid())
}

fn private_dir_of(dir: &Path, uid: u32) -> bool {
    let _ = fs::DirBuilder::new().mode(0o700).create(dir);
    fs::symlink_metadata(dir)
        .is_ok_and(|m| m.is_dir() && m.uid() == uid && m.mode() & 0o777 == 0o700)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_socket_is_short_and_per_user_and_name() {
        let p = socket_in(501, "claude-myrepo");
        let s = p.display().to_string();
        assert!(
            s.starts_with("/tmp/sbt-501/") && s.ends_with(".sock"),
            "{s}"
        );
        let file = p.file_stem().unwrap().to_str().unwrap();
        assert_eq!(file.len(), 16);
        assert!(file.bytes().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(
            file,
            &hex(&Sha256::digest(b"claude-myrepo"))[..16],
            "first 16 hex of sha256(name)"
        );
        assert_ne!(p, socket_in(501, "other"));
        assert_ne!(p, socket_in(502, "claude-myrepo"));
        // Well under macOS's ~104-byte socket path limit, whatever the name.
        assert!(socket_in(u32::MAX, &"x".repeat(200)).as_os_str().len() < 50);
        assert_eq!(p.parent().unwrap(), dir_of(501));
    }

    #[test]
    fn the_agent_socket_sits_beside_the_bridge_socket() {
        let id = &hex(&Sha256::digest(b"claude-myrepo"))[..16];
        assert_eq!(
            agent_socket_in(501, "claude-myrepo"),
            PathBuf::from(format!("/tmp/sbt-501/{id}.agent.sock"))
        );
        assert_eq!(agent_socket("a").parent(), host_socket("a").parent());
        assert!(
            agent_socket_in(u32::MAX, &"x".repeat(200))
                .as_os_str()
                .len()
                < 60
        );
    }

    #[test]
    fn a_socket_dir_must_be_ours_a_real_dir_and_0700() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let me = crate::sandbox::host_uid();
        // Missing: created 0700.
        let dir = tmp.path().join("sbt");
        assert!(private_dir_of(&dir, me));
        let mode = fs::metadata(&dir).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);
        assert!(private_dir_of(&dir, me), "an existing private dir");
        // Someone else's (as another uid would see it).
        assert!(!private_dir_of(&dir, me + 1));
        // Readable by others.
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(!private_dir_of(&dir, me));
        // A symlink to a private dir, or a file.
        let real = tmp.path().join("real");
        fs::DirBuilder::new().mode(0o700).create(&real).unwrap();
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(!private_dir_of(&link, me));
        let file = tmp.path().join("file");
        fs::write(&file, "").unwrap();
        assert!(!private_dir_of(&file, me));
    }
}
