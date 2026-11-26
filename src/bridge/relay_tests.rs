use super::*;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;

#[test]
fn pass_through_refuses_bare_line_breaks_and_nul() {
    for bad in [
        "HTTP/1.1 200 OK\nX: 1\r\n\r\nhi",
        "HTTP/1.1 200 OK\r\nX: 1\nContent-Length: 99\r\n\r\nhi",
        "HTTP/1.1 200 OK\r\nX: a\0b\r\n\r\nhi",
    ] {
        assert!(pass_through(bad).is_none(), "{bad:?}");
    }
    assert!(pass_through("HTTP/1.1 200 OK\r\nX: 1\r\n\r\nhi").is_some());
}
use std::process::Command;
use std::sync::Mutex;
use std::time::Duration;

type Calls = Arc<Mutex<Vec<Vec<String>>>>;

/// A fake smolvm that records its argv and answers with `out`.
fn fake(out: Output) -> (Exec, Calls) {
    let calls = Calls::default();
    let c = calls.clone();
    let exec: Exec = Box::new(move |args| {
        c.lock().unwrap().push(args.to_vec());
        Ok(out.clone())
    });
    (exec, calls)
}

fn guest(user: &str) -> Guest {
    Guest {
        machine: "sbx-m".into(),
        user: user.into(),
    }
}

/// A browser's request to the relay on port 8085.
fn req(method: &str, target: &str) -> Request {
    Request {
        method: method.into(),
        path: target.into(),
        host: Some("localhost:8085".into()),
        body: Vec::new(),
    }
}

fn answered(stdout: &str) -> Output {
    Output {
        code: 0,
        stdout: stdout.into(),
        stderr: String::new(),
    }
}

/// The `sh -c` script of a recorded exec, after checking the rest of its argv.
fn script(call: &[String]) -> String {
    script_as(call, "agent")
}

fn script_as(call: &[String], user: &str) -> String {
    let head: Vec<&str> = call[..call.len() - 1].iter().map(String::as_str).collect();
    assert_eq!(
        head,
        [
            "machine", "exec", "--name", "sbx-m", "-u", user, "--", "sh", "-c"
        ]
    );
    call.last().unwrap().clone()
}

#[test]
fn replays_as_the_sessions_user() {
    // A v3 workload's image user (`sbx.user`), which may have no `agent` account.
    let (exec, calls) = fake(answered("HTTP/1.1 200 OK\r\n\r\n"));
    replay(&exec, &guest("1000:staff"), 8085, &req("GET", "/cb"));
    script_as(&calls.lock().unwrap()[0], "1000:staff");
}

#[test]
fn only_relays_requests_for_this_hosts_port() {
    let (exec, calls) = fake(answered("HTTP/1.1 200 OK\r\n\r\nok"));
    for host in ["localhost:8085", "LocalHost:8085", "127.0.0.1:8085"] {
        let r = Request {
            host: Some(host.into()),
            ..req("GET", "/cb")
        };
        let resp = replay(&exec, &guest("agent"), 8085, &r);
        assert_eq!(status_of(&resp), "HTTP/1.1 200 OK", "{host}");
    }
    assert_eq!(calls.lock().unwrap().len(), 3);
    for host in [
        None,
        Some("evil.example:8085"),
        Some("localhost"),
        Some("localhost:8086"),
        Some("127.0.0.1"),
        Some("[::1]:8085"),
        Some(""),
    ] {
        let r = Request {
            host: host.map(String::from),
            ..req("GET", "/cb")
        };
        let resp = replay(&exec, &guest("agent"), 8085, &r);
        assert_eq!(status_of(&resp), "HTTP/1.1 403 Forbidden", "{host:?}");
    }
    assert_eq!(
        calls.lock().unwrap().len(),
        3,
        "a refused request ran nothing"
    );
}

#[test]
fn replays_the_request_in_the_sandbox_as_the_agent() {
    let (exec, calls) = fake(answered(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nok",
    ));
    replay(
        &exec,
        &guest("agent"),
        8085,
        &req("GET", "/cb?code=a&state=b"),
    );
    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    let s = script(&calls[0]);
    assert!(
        s.contains("'http://127.0.0.1:8085/cb?code=a&state=b'"),
        "{s}"
    );
}

/// Runs a replay script under `sh` with only the given fake commands on PATH, each printing
/// its argv one per line; returns stdout and the exit code.
fn run_script(s: &str, commands: &[&str]) -> (String, i32) {
    let dir = tempfile::tempdir().unwrap();
    for c in commands {
        let p = dir.path().join(c);
        std::fs::write(&p, "#!/bin/sh\nprintf '%s\\n' \"$0\" \"$@\"\n").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let out = Command::new("/bin/sh")
        .args(["-c", s])
        .env("PATH", dir.path())
        .output()
        .unwrap();
    let stdout = String::from_utf8(out.stdout).unwrap();
    // Drop the fake's directory from $0.
    let stdout = stdout.replace(&format!("{}/", dir.path().display()), "");
    (stdout, out.status.code().unwrap_or(-1))
}

fn script_for(method: &str, target: &str) -> String {
    let (exec, calls) = fake(answered(""));
    replay(&exec, &guest("agent"), 8085, &req(method, target));
    script(&calls.lock().unwrap()[0])
}

#[test]
fn the_browsers_path_reaches_curl_as_one_argument() {
    // From the browser: untrusted.
    let target = "/cb?x='$(touch${IFS}/tmp/pwned)'&y=`id`;z\"{a,b}[1-2]";
    let (out, code) = run_script(&script_for("GET", target), &["curl", "wget"]);
    assert_eq!(code, 0);
    let url = format!("http://127.0.0.1:8085{target}");
    assert_eq!(
        out.lines().collect::<Vec<_>>(),
        [
            "curl",
            "-s",
            "-g",
            "-i",
            "-m",
            "10",
            "--noproxy",
            "*",
            "-X",
            "GET",
            &url
        ]
    );
    let (out, _) = run_script(&script_for("POST", "/cb"), &["curl"]);
    assert!(out.contains("-X\nPOST\n"), "{out}");
}

#[test]
fn falls_back_to_wget_for_a_get_without_curl() {
    let (out, code) = run_script(&script_for("GET", "/cb?c=1"), &["wget"]);
    assert_eq!(code, 0);
    assert_eq!(
        out,
        "HTTP/1.1 200 OK\r\n\r\nwget\n-qO-\n-T\n10\n--max-redirect=0\nhttp://127.0.0.1:8085/cb?c=1\n"
    );
    // Not for another method, and not without either.
    let (out, code) = run_script(&script_for("POST", "/cb"), &["wget"]);
    assert_ne!(code, 0);
    assert_eq!(out, "");
    assert_ne!(run_script(&script_for("GET", "/cb"), &[]).1, 0);
}

#[test]
fn passes_the_guests_response_through() {
    let (exec, _) = fake(answered(
        "HTTP/1.1 302 Found\r\nLocation: /done\r\nTransfer-Encoding: chunked\r\n\
         Connection: keep-alive\r\nContent-Length: 99\r\n\r\n<p>signed in</p>",
    ));
    let resp = replay(&exec, &guest("agent"), 8085, &req("GET", "/cb"));
    assert_eq!(
        String::from_utf8(resp).unwrap(),
        "HTTP/1.1 302 Found\r\nLocation: /done\r\nContent-Length: 16\r\n\
         Connection: close\r\n\r\n<p>signed in</p>"
    );
    // wget's: a status line and the body.
    let (exec, _) = fake(answered("HTTP/1.1 200 OK\r\n\r\nhello"));
    let resp = replay(&exec, &guest("agent"), 8085, &req("GET", "/cb"));
    assert_eq!(
        String::from_utf8(resp).unwrap(),
        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello"
    );
}

fn status_of(resp: &[u8]) -> String {
    String::from_utf8_lossy(resp)
        .lines()
        .next()
        .unwrap_or_default()
        .to_string()
}

#[test]
fn a_guest_that_doesnt_answer_is_a_bad_gateway() {
    for out in [
        Output {
            code: 7,
            stdout: String::new(),
            stderr: String::new(),
        },
        answered(""),
        answered("not http"),
    ] {
        let (exec, _) = fake(out);
        let resp = replay(&exec, &guest("agent"), 8085, &req("GET", "/cb"));
        assert_eq!(status_of(&resp), "HTTP/1.1 502 Bad Gateway");
    }
    let exec: Exec = Box::new(|_| anyhow::bail!("no smolvm"));
    let resp = replay(&exec, &guest("agent"), 8085, &req("GET", "/cb"));
    assert_eq!(status_of(&resp), "HTTP/1.1 502 Bad Gateway");
}

#[test]
fn refuses_odd_requests_without_running_anything() {
    let (exec, calls) = fake(answered("HTTP/1.1 200 OK\r\n\r\n"));
    for (method, target) in [
        ("GET", "http://evil.example/"),
        ("GET", "*"),
        ("GET", ""),
        ("G-T", "/cb"),
        ("get", "/cb"),
        ("", "/cb"),
    ] {
        let resp = replay(&exec, &guest("agent"), 8085, &req(method, target));
        assert_eq!(
            status_of(&resp),
            "HTTP/1.1 400 Bad Request",
            "{method} {target}"
        );
    }
    assert!(calls.lock().unwrap().is_empty());
}

/// A port nothing listens on just now.
fn free_port() -> u16 {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn get(port: u16, raw: &str) -> String {
    let mut s = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(raw.as_bytes()).unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).unwrap();
    out
}

#[test]
fn relays_a_browsers_request_until_dropped() {
    let (exec, calls) = fake(answered("HTTP/1.1 200 OK\r\n\r\nyou can close this tab"));
    let mut relays = Relays::new(exec, "sbx-m", "agent");
    let port = free_port();
    assert_eq!(relays.start(port), None);
    // Started once: a second start is a no-op.
    assert_eq!(relays.start(port), None);
    let out = get(
        port,
        &format!("GET /cb?code=1 HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n"),
    );
    assert_eq!(
        out,
        "HTTP/1.1 200 OK\r\nContent-Length: 22\r\nConnection: close\r\n\r\nyou can close this tab"
    );
    let out = get(port, "GET /nope HTTP/1.1\r\nno colon\r\n\r\n");
    assert!(out.starts_with("HTTP/1.1 400 "), "{out}");
    {
        let calls = calls.lock().unwrap();
        assert_eq!(calls.len(), 1, "the bad request ran nothing");
        let s = script(&calls[0]);
        assert!(
            s.contains(&format!("'http://127.0.0.1:{port}/cb?code=1'")),
            "{s}"
        );
    }
    drop(relays);
    assert!(TcpStream::connect((Ipv4Addr::LOCALHOST, port)).is_err());
}

#[test]
fn a_taken_port_warns_once() {
    let taken = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = taken.local_addr().unwrap().port();
    let (exec, calls) = fake(answered(""));
    let mut relays = Relays::new(exec, "sbx-m", "agent");
    let warning = relays.start(port).expect("a warning");
    let want = format!("warning: can't listen on 127.0.0.1:{port} for the login callback: ");
    assert!(warning.starts_with(&want), "{warning}");
    assert!(warning.len() > want.len(), "{warning}");
    assert_eq!(relays.start(port), None);
    assert!(calls.lock().unwrap().is_empty());
}

/// The relay can't take over a host service listening on every address (macOS would let
/// the bind to 127.0.0.1 succeed).
#[test]
fn a_port_served_on_every_address_is_taken() {
    let blockers = [
        TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0)).ok(),
        // Skipped where the host has no IPv6.
        TcpListener::bind((Ipv6Addr::UNSPECIFIED, 0)).ok(),
    ];
    assert!(blockers[0].is_some());
    for taken in blockers.iter().flatten() {
        let port = taken.local_addr().unwrap().port();
        let (exec, calls) = fake(answered(""));
        let mut relays = Relays::new(exec, "sbx-m", "agent");
        let warning = relays.start(port).expect("a warning");
        assert!(
            warning.starts_with(&format!("warning: can't listen on 127.0.0.1:{port} ")),
            "{warning}"
        );
        assert!(relays.threads.is_empty());
        assert!(calls.lock().unwrap().is_empty());
    }
}

#[test]
fn a_session_starts_at_most_four_relays_and_warns_once() {
    let (exec, _) = fake(answered(""));
    let mut relays = Relays::new(exec, "sbx-m", "agent");
    let mut ports = BTreeSet::new();
    while ports.len() < 6 {
        ports.insert(free_port());
    }
    let ports: Vec<u16> = ports.into_iter().collect();
    for &p in &ports[..4] {
        assert_eq!(relays.start(p), None);
    }
    assert_eq!(
        relays.start(ports[4]).as_deref(),
        Some(
            format!(
                "warning: this session already relays 4 login callbacks; not relaying \
                 localhost:{} or any more",
                ports[4]
            )
            .as_str()
        )
    );
    assert_eq!(relays.start(ports[5]), None, "warned once");
    assert_eq!(relays.threads.len(), 4);
    assert!(TcpStream::connect((Ipv4Addr::LOCALHOST, ports[4])).is_err());
}

/// A process whose relays outlive its connection holds one of the sandbox's relay slots while
/// they run, so lingering relays are bounded across processes, not only per process.
#[test]
fn lingering_relays_hold_one_of_the_sandboxs_slots() {
    let dir = tempfile::tempdir().unwrap();
    let slots = vec![dir.path().join("b.relay0")];
    let lingering = |lifetime| {
        let (exec, _) = fake(answered(""));
        let mut r = Relays::new(exec, "sbx-m", "agent").lingering(slots.clone());
        r.lifetime = lifetime;
        r
    };
    let mut first = lingering(Duration::from_millis(300));
    assert_eq!(first.start(free_port()), None);
    let mut second = lingering(Duration::from_millis(300));
    let port = free_port();
    assert_eq!(
        second.start(port).as_deref(),
        Some(
            format!(
                "warning: the sandbox's other sessions already relay login callbacks; not \
                 relaying localhost:{port}"
            )
            .as_str()
        )
    );
    assert!(TcpStream::connect((Ipv4Addr::LOCALHOST, port)).is_err());
    // Once the first's relays have run out, its slot is free.
    drop(first);
    assert_eq!(second.start(free_port()), None);
}

#[test]
fn a_relay_closes_after_its_lifetime() {
    let (exec, _) = fake(answered(""));
    let mut relays = Relays::new(exec, "sbx-m", "agent");
    relays.lifetime = Duration::from_millis(200);
    let port = free_port();
    assert_eq!(relays.start(port), None);
    assert!(TcpStream::connect((Ipv4Addr::LOCALHOST, port)).is_ok());
    let until = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect((Ipv4Addr::LOCALHOST, port)).is_ok() {
        assert!(Instant::now() < until, "still listening");
        thread::sleep(POLL);
    }
    // Not started again: one try per port.
    assert_eq!(relays.start(port), None);
    assert!(TcpStream::connect((Ipv4Addr::LOCALHOST, port)).is_err());
}

#[test]
fn a_slow_browser_is_cut_off_and_drop_is_prompt() {
    let (exec, _) = fake(answered("HTTP/1.1 200 OK\r\n\r\n"));
    let mut relays = Relays::new(exec, "sbx-m", "agent");
    let port = free_port();
    assert_eq!(relays.start(port), None);
    // A half-sent request, then the session ends.
    let mut s = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
    s.write_all(b"GET /cb HTTP/1.1\r\n").unwrap();
    thread::sleep(Duration::from_millis(100));
    let started = Instant::now();
    drop(relays);
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "{:?}",
        started.elapsed()
    );
}
