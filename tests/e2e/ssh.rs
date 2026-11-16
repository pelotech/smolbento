use std::process::Stdio;

use super::*;

/// `ssh -F CONFIG ARGS`, with this test's smolbento environment (the `ProxyCommand` inherits it).
fn ssh(e: &E2e, config: &Path, args: &[&str]) -> Output {
    e.env(
        Command::new("ssh")
            .args(["-F", config.to_str().unwrap(), "-o", "BatchMode=yes"])
            .args(args),
    )
    .stdin(Stdio::null())
    .output()
    .unwrap()
}

/// `bento setup ssh` against a throwaway HOME, so your `~/.ssh/config` is never touched. Returns the
/// config path to hand to `ssh -F`. (smolvm runs with the real HOME: only this call has the fake.)
fn setup(e: &E2e, args: &[&str]) -> PathBuf {
    let home = e.dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let out = e
        .env(
            Command::new(env!("CARGO_BIN_EXE_smolbento"))
                .args(["setup", "ssh"])
                .args(args),
        )
        .env("HOME", &home)
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", err_text(&out));
    home.join(".ssh/config")
}

#[test]
#[ignore = "boots real VMs; run with `just e2e`"]
pub(crate) fn ssh_runs_commands_shells_forwards_and_starts_the_sandbox() {
    let e = E2e::new("ssh");
    e.create_alpine_offline();
    let config = setup(&e, &[]);
    let cfg = std::fs::read_to_string(&config).unwrap();
    assert!(
        cfg.contains("Host *.sbx") && cfg.contains("ssh proxy %n"),
        "{cfg}"
    );
    let host = format!("{}.sbx", e.name);

    // exec: output, the session user, the workspace, the exit status.
    let out = ssh(&e, &config, &[&host, "echo hi; id -un; pwd"]);
    assert!(out.status.success(), "{}", err_text(&out));
    assert_eq!(
        out_text(&out),
        format!("hi\nagent\n{}\n", e.workspace().display())
    );
    let out = ssh(&e, &config, &[&host, "echo to-err >&2; exit 7"]);
    assert_eq!(out.status.code(), Some(7));
    assert_eq!(err_text(&out), "to-err\n");

    // A pty: `tty` succeeds, and the size is the one the client sent.
    let out = ssh(&e, &config, &["-tt", &host, "tty; stty size"]);
    let text = out_text(&out);
    assert!(out.status.success(), "{text}\n{}", err_text(&out));
    assert!(
        text.contains("/dev/") && !text.contains("not a tty"),
        "{text}"
    );
    assert!(
        text.lines().any(|l| l.trim().split(' ').count() == 2
            && l.trim().chars().all(|c| c.is_ascii_digit() || c == ' ')),
        "{text}"
    );

    // Local forwarding to a listener in the guest.
    let mut listener = e
        .env(Command::new(env!("CARGO_BIN_EXE_smolbento")).args([
            "exec",
            &e.name,
            "sh",
            "-c",
            "while true; do echo pong | nc -l -p 4000; done",
        ]))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let local = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let mut tunnel = e
        .env(Command::new("ssh").args([
            "-F",
            config.to_str().unwrap(),
            "-N",
            "-o",
            "ExitOnForwardFailure=yes",
        ]))
        .args(["-L", &format!("{local}:localhost:4000"), &host])
        .stdin(Stdio::null())
        .spawn()
        .unwrap();
    let mut got = String::new();
    wait_until(60, || {
        got = host_get_raw(local);
        got.contains("pong")
    });
    let _ = tunnel.kill();
    let _ = tunnel.wait();
    let _ = listener.kill();
    let _ = listener.wait();
    assert!(got.contains("pong"), "forward gave {got:?}");

    // A stopped sandbox is started by connecting; a missing one is an error.
    e.ok(&["stop", &e.name]);
    assert_eq!(e.state(), "stopped");
    let out = ssh(&e, &config, &[&host, "echo again"]);
    assert_eq!(out_text(&out), "again\n", "{}", err_text(&out));
    assert_eq!(e.state(), "running");
    let out = ssh(&e, &config, &[&format!("{}-nope.sbx", e.name), "true"]);
    assert_eq!(out.status.code(), Some(255));
    assert!(err_text(&out).contains("create the sandbox first"));

    setup(&e, &["remove"]);
    assert_eq!(std::fs::read_to_string(&config).unwrap(), "");
}

/// What a connection to the host's `127.0.0.1:port` reads (empty when it fails).
fn host_get_raw(port: u16) -> String {
    use std::io::Read;
    let Ok(mut s) = std::net::TcpStream::connect(("127.0.0.1", port)) else {
        return String::new();
    };
    let _ = s.set_read_timeout(Some(std::time::Duration::from_secs(10)));
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}
