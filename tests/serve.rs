//! `_serve` under inetd-style launch (launchd `inetdCompatibility`): stdin, stdout and stderr all
//! start attached to the untrusted guest socket, so startup errors must never write to fds 1 or 2.

use std::io::Read;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};

#[test]
fn serve_never_leaks_startup_errors_onto_the_guest_socket() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("config.toml"), "not valid toml = [\n").unwrap();

    let (mut client, server) = UnixStream::pair().unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_smolbento"))
        .args(["_serve", "bridge", "box"])
        .env("SMOLBENTO_CONFIG_DIR", dir.path())
        .env("SMOLBENTO_DATA_DIR", dir.path())
        .env("SMOLBENTO_CACHE_DIR", dir.path())
        .stdin(Stdio::from(OwnedFd::from(server.try_clone().unwrap())))
        .stdout(Stdio::from(OwnedFd::from(server.try_clone().unwrap())))
        .stderr(Stdio::from(OwnedFd::from(server)))
        .spawn()
        .unwrap();

    let mut leaked = Vec::new();
    client.read_to_end(&mut leaked).unwrap();
    let _ = child.wait().unwrap();
    assert!(
        leaked.is_empty(),
        "host output leaked onto the guest socket: {:?}",
        String::from_utf8_lossy(&leaked)
    );
}
