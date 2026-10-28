//! The browser and clipboard bridge: guest shims (`xdg-open`, `wl-copy`, …) that reach the host
//! over a socket smolvm mounts into the sandbox, served while a user is attached.

mod shims;

use std::path::PathBuf;

use sha2::{Digest, Sha256};

use crate::kits::registry::hex;

pub use shims::install_cmd;

/// Where the host socket appears in the guest (`--mount-socket`).
pub const GUEST_SOCKET: &str = "/run/smolbento/bridge.sock";

/// The sandbox's host socket: `/tmp/sbt-<uid>/<first 16 hex of sha256(name)>.sock`. Short on every
/// OS (macOS caps socket paths near 104 bytes) and fixed at create, so it can't follow `TMPDIR`.
pub fn host_socket(name: &str) -> PathBuf {
    socket_in(crate::sandbox::host_uid(), name)
}

fn socket_in(uid: u32, name: &str) -> PathBuf {
    let id = hex(&Sha256::digest(name.as_bytes()));
    PathBuf::from(format!("/tmp/sbt-{uid}/{}.sock", &id[..16]))
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
    }
}
