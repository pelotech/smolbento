use super::*;

/// smolvm dials host loopback when a guest connects to its gateway; smolbento denies that. Only
/// bytes arriving prove reachability: smolvm's stack accepts every SYN, so `nc -z` can't tell.
#[test]
#[ignore = "boots real VMs; run with `just e2e`"]
pub(crate) fn host_loopback_is_unreachable() {
    use std::io::Read;
    use std::time::{Duration, Instant};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    let received = std::thread::spawn(move || {
        let mut got = Vec::new();
        // Until the guest's probe is done, then 2s more for bytes in flight.
        let mut until = None;
        while until.is_none_or(|t| Instant::now() < t) {
            if until.is_none() && rx.try_recv().is_ok() {
                until = Some(Instant::now() + Duration::from_secs(2));
            }
            if let Ok((mut stream, _)) = listener.accept() {
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let mut buf = [0u8; 64];
                if let Ok(n) = stream.read(&mut buf) {
                    got.extend_from_slice(&buf[..n]);
                }
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        got
    });
    let e = E2e::new("lo");
    e.create_alpine();
    let probe = format!(
        "gw=$(ip route | awk '/default/ {{print $3}}'); echo probe | nc -w 3 \"$gw\" {port}; true"
    );
    e.sbt(&["exec", &e.name, "sh", "-c", &probe]);
    tx.send(()).unwrap();
    let got = received.join().unwrap();
    assert!(
        got.is_empty(),
        "the host's 127.0.0.1:{port} got {:?} from the sandbox",
        String::from_utf8_lossy(&got)
    );
}

/// A host service on 127.0.0.1 (random port) answering every connection with `200 ok`, for the
/// life of the test process. Returns its port.
pub(crate) fn host_service() -> u16 {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(2)));
            let _ = stream.read(&mut [0u8; 1024]);
            let _ = stream.write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok");
        }
    });
    port
}

/// sbx's host services: a `localhost:PORT` rule lets sandboxes created with host access reach
/// the host as `host.docker.internal:PORT`, opened and closed live. Under smolvm 1.32.4 it opens
/// every host port (see SECURITY.md), so only the open/closed transitions are checked.
#[test]
#[ignore = "boots real VMs; run with `just e2e`"]
pub(crate) fn host_services_open_and_close_live() {
    let port = host_service();
    let url = format!("http://host.docker.internal:{port}/");
    let rule = format!("localhost:{port}");

    // Created under deny-all without a localhost rule: the loopback deny stays for its life.
    let a = E2e::new("hs0");
    a.ok(&["policy", "init", "deny-all"]);
    a.create_alpine_offline();
    assert!(!reachable(&a, &url), "no rule, no host access");
    let out = a.sbt(&["policy", "allow", "network", "--sandbox", &a.name, &rule]);
    assert!(out.status.success(), "{out:?}");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains(&format!(
            "note: {} were created without host access; recreate them to use it",
            a.name
        )),
        "{err}"
    );
    assert!(
        err.contains(&format!(
            "warning: smolvm can't open a single host port yet; this opens every port on your \
             host's localhost to sandbox {}",
            a.name
        )),
        "{err}"
    );
    assert!(!reachable(&a, &url), "created without host access");

    // A sandbox-scoped localhost rule before create: created with host access.
    let b = E2e::new("hs1");
    b.ok(&["policy", "init", "deny-all"]);
    b.ok(&["policy", "allow", "network", "--sandbox", &b.name, &rule]);
    b.create_alpine_offline();
    let boot = root_out(&b.name, "cat /proc/sys/kernel/random/boot_id");
    assert!(reachable(&b, &url), "created with host access");
    b.ok(&[
        "policy",
        "rm",
        "network",
        "--sandbox",
        &b.name,
        "--resource",
        &rule,
    ]);
    assert!(wait_until(10, || !reachable(&b, &url)), "live rm closes it");
    b.ok(&["policy", "allow", "network", "--sandbox", &b.name, &rule]);
    assert!(
        wait_until(10, || reachable(&b, &url)),
        "live allow reopens it"
    );
    assert_eq!(
        root_out(&b.name, "cat /proc/sys/kernel/random/boot_id"),
        boot,
        "no restart"
    );
}

/// Polls `check` every second until it returns true or `secs` pass.
pub(crate) fn wait_until(secs: u64, mut check: impl FnMut() -> bool) -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(secs);
    loop {
        if check() {
            return true;
        }
        if std::time::Instant::now() > deadline {
            return false;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}
