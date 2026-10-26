//! Behaviour of the built binary that unit tests can't see.

use std::os::fd::{FromRawFd, OwnedFd};
use std::process::{Command, Stdio};

/// `sbt ls | head -1` and friends: the reader goes away early. That must end the program quietly,
/// like other Unix tools, not with a panic.
#[test]
fn closed_stdout_does_not_panic() {
    let mut fds = [0; 2];
    // SAFETY: pipe fills both fds on success; the read end is closed at once and the write end is
    // owned by `OwnedFd` from here on.
    let write_end = unsafe {
        assert_eq!(libc::pipe(fds.as_mut_ptr()), 0);
        libc::close(fds[0]);
        OwnedFd::from_raw_fd(fds[1])
    };
    let out = Command::new(env!("CARGO_BIN_EXE_smolbento"))
        .args(["completion", "zsh"])
        .stdout(Stdio::from(write_end))
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("panicked"),
        "panicked on a closed stdout:\n{stderr}"
    );
    assert_ne!(
        out.status.code(),
        Some(101),
        "exited like a panic: {:?}",
        out.status
    );
}
