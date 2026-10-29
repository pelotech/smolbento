//! The login callback relay: a login in the sandbox (an OAuth client) listens on the guest's
//! `127.0.0.1:PORT`, which a published port can't reach, and the host's browser is sent to
//! `http://localhost:PORT/…`. We listen on the host's `127.0.0.1:PORT` and replay each request in
//! the sandbox with `curl`, returning the guest's answer.

use std::collections::BTreeSet;
use std::io::Write;
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Instant;

use anyhow::Result;

use super::server::{self, DEADLINE, POLL, Response};
use crate::sandbox::sh_quote;
use crate::smolvm::{ExecSpec, Output};

/// Runs `smolvm ARGS`. Its own, not the session's runner, which can't move to another thread.
pub type Exec = Box<dyn Fn(&[String]) -> Result<Output> + Send + Sync>;

/// A session's relays, one per port; dropping it stops them.
pub struct Relays {
    exec: Arc<Exec>,
    machine: String,
    /// Ports already started or that failed: each is tried once per session.
    tried: BTreeSet<u16>,
    stop: Arc<AtomicBool>,
    threads: Vec<JoinHandle<()>>,
}

impl Relays {
    pub fn new(exec: Exec, machine: &str) -> Relays {
        Relays {
            exec: Arc::new(exec),
            machine: machine.into(),
            tried: BTreeSet::new(),
            stop: Arc::default(),
            threads: Vec::new(),
        }
    }

    /// Starts relaying `port` to the sandbox, once. A warning when the host's port is taken.
    pub fn start(&mut self, port: u16) -> Option<String> {
        if !self.tried.insert(port) {
            return None;
        }
        let listener = match listen(port) {
            Ok(l) => l,
            Err(e) => {
                return Some(format!(
                    "warning: can't listen on 127.0.0.1:{port} for the login callback: {e}"
                ));
            }
        };
        let (exec, machine, stop) = (self.exec.clone(), self.machine.clone(), self.stop.clone());
        self.threads.push(thread::spawn(move || {
            accept_loop(&listener, port, &exec, &machine, &stop)
        }));
        None
    }
}

impl Drop for Relays {
    /// Stops the listeners (within `POLL`, or once a running replay returns).
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
    }
}

/// Loopback only: the browser is on this host.
fn listen(port: u16) -> std::io::Result<TcpListener> {
    let l = TcpListener::bind((Ipv4Addr::LOCALHOST, port))?;
    l.set_nonblocking(true)?;
    Ok(l)
}

/// One request at a time, like the bridge.
fn accept_loop(listener: &TcpListener, port: u16, exec: &Exec, machine: &str, stop: &AtomicBool) {
    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, _)) => answer(&stream, port, exec, machine, stop),
            Err(_) => thread::sleep(POLL),
        }
    }
}

fn answer(stream: &TcpStream, port: u16, exec: &Exec, machine: &str, stop: &AtomicBool) {
    // Accepted sockets inherit non-blocking mode on some systems.
    if stream.set_nonblocking(false).is_err() || stream.set_write_timeout(Some(DEADLINE)).is_err() {
        return;
    }
    let resp = match server::read_within(stream, Instant::now() + DEADLINE, stop) {
        Ok(req) => replay(exec, machine, port, &req.method, &req.path),
        Err(resp) => ours(&resp),
    };
    let _ = (&mut &*stream).write_all(&resp);
}

/// The replay's response to the browser.
fn replay(exec: &Exec, machine: &str, port: u16, method: &str, target: &str) -> Vec<u8> {
    // Only what a browser sends: a plain method and a path (no absolute URL).
    if method.is_empty()
        || !method.bytes().all(|b| b.is_ascii_uppercase())
        || !target.starts_with('/')
    {
        return ours(&server::bad_request());
    }
    let spec = ExecSpec {
        name: machine.into(),
        user: Some("agent".into()),
        cmd: vec!["sh".into(), "-c".into(), replay_cmd(port, method, target)],
        ..Default::default()
    };
    match exec(&spec.to_args()) {
        Ok(out) if out.code == 0 => pass_through(&out.stdout),
        _ => None,
    }
    .unwrap_or_else(|| {
        ours(&Response::new(
            502,
            "the login callback in the sandbox didn't answer",
        ))
    })
}

/// The guest command: `curl`, or for a GET `wget` (body only, so we add a `200`). The target
/// came from the browser: it is quoted, and `-g` stops curl reading `[]{}` as globs.
fn replay_cmd(port: u16, method: &str, target: &str) -> String {
    let url = sh_quote(&format!("http://127.0.0.1:{port}{target}"));
    let m = sh_quote(method);
    // 10s: within the browser's patience, and the session's end waits for a running replay.
    format!(
        "u={url}\n\
         if command -v curl >/dev/null 2>&1; then exec curl -s -g -i -m 10 -X {m} \"$u\"; fi\n\
         [ {m} = GET ] && command -v wget >/dev/null 2>&1 || exit 127\n\
         printf 'HTTP/1.1 200 OK\\r\\n\\r\\n'\n\
         exec wget -qO- -S -T 10 \"$u\""
    )
}

/// The guest's status line, headers and body, framed for one response on a closing connection
/// (curl has already undone any chunking). `None` for output that isn't an HTTP response.
fn pass_through(guest: &str) -> Option<Vec<u8>> {
    let (head, body) = guest.split_once("\r\n\r\n")?;
    let mut lines = head.split("\r\n");
    let status = lines.next().filter(|l| l.starts_with("HTTP/"))?;
    let mut out = format!("{status}\r\n");
    for header in lines {
        let name = header.split(':').next().unwrap_or_default().trim();
        let framing = [
            "content-length",
            "transfer-encoding",
            "connection",
            "keep-alive",
        ];
        if !framing.iter().any(|f| name.eq_ignore_ascii_case(f)) {
            out += header;
            out += "\r\n";
        }
    }
    out += &format!(
        "Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    Some(out.into_bytes())
}

/// One of our own (error) responses, as bytes.
fn ours(resp: &Response) -> Vec<u8> {
    let mut out = Vec::new();
    let _ = server::write_response(&mut out, resp);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::os::unix::fs::PermissionsExt;
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

    fn guest(stdout: &str) -> Output {
        Output {
            code: 0,
            stdout: stdout.into(),
            stderr: String::new(),
        }
    }

    /// The `sh -c` script of a recorded exec, after checking the rest of its argv.
    fn script(call: &[String]) -> String {
        let head: Vec<&str> = call[..call.len() - 1].iter().map(String::as_str).collect();
        assert_eq!(
            head,
            [
                "machine", "exec", "--name", "sbx-m", "-u", "agent", "--", "sh", "-c"
            ]
        );
        call.last().unwrap().clone()
    }

    #[test]
    fn replays_the_request_in_the_sandbox_as_the_agent() {
        let (exec, calls) = fake(guest(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nok",
        ));
        replay(&exec, "sbx-m", 8085, "GET", "/cb?code=a&state=b");
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
        let (exec, calls) = fake(guest(""));
        replay(&exec, "sbx-m", 8085, method, target);
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
            ["curl", "-s", "-g", "-i", "-m", "10", "-X", "GET", &url]
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
            "HTTP/1.1 200 OK\r\n\r\nwget\n-qO-\n-S\n-T\n10\nhttp://127.0.0.1:8085/cb?c=1\n"
        );
        // Not for another method, and not without either.
        let (out, code) = run_script(&script_for("POST", "/cb"), &["wget"]);
        assert_ne!(code, 0);
        assert_eq!(out, "");
        assert_ne!(run_script(&script_for("GET", "/cb"), &[]).1, 0);
    }

    #[test]
    fn passes_the_guests_response_through() {
        let (exec, _) = fake(guest(
            "HTTP/1.1 302 Found\r\nLocation: /done\r\nTransfer-Encoding: chunked\r\n\
             Connection: keep-alive\r\nContent-Length: 99\r\n\r\n<p>signed in</p>",
        ));
        let resp = replay(&exec, "sbx-m", 8085, "GET", "/cb");
        assert_eq!(
            String::from_utf8(resp).unwrap(),
            "HTTP/1.1 302 Found\r\nLocation: /done\r\nContent-Length: 16\r\n\
             Connection: close\r\n\r\n<p>signed in</p>"
        );
        // wget's: a status line and the body.
        let (exec, _) = fake(guest("HTTP/1.1 200 OK\r\n\r\nhello"));
        let resp = replay(&exec, "sbx-m", 8085, "GET", "/cb");
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
            guest(""),
            guest("not http"),
        ] {
            let (exec, _) = fake(out);
            let resp = replay(&exec, "sbx-m", 8085, "GET", "/cb");
            assert_eq!(status_of(&resp), "HTTP/1.1 502 Bad Gateway");
        }
        let exec: Exec = Box::new(|_| anyhow::bail!("no smolvm"));
        let resp = replay(&exec, "sbx-m", 8085, "GET", "/cb");
        assert_eq!(status_of(&resp), "HTTP/1.1 502 Bad Gateway");
    }

    #[test]
    fn refuses_odd_requests_without_running_anything() {
        let (exec, calls) = fake(guest("HTTP/1.1 200 OK\r\n\r\n"));
        for (method, target) in [
            ("GET", "http://evil.example/"),
            ("GET", "*"),
            ("GET", ""),
            ("G-T", "/cb"),
            ("get", "/cb"),
            ("", "/cb"),
        ] {
            let resp = replay(&exec, "sbx-m", 8085, method, target);
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
        let (exec, calls) = fake(guest("HTTP/1.1 200 OK\r\n\r\nyou can close this tab"));
        let mut relays = Relays::new(exec, "sbx-m");
        let port = free_port();
        assert_eq!(relays.start(port), None);
        // Started once: a second start is a no-op.
        assert_eq!(relays.start(port), None);
        let out = get(port, "GET /cb?code=1 HTTP/1.1\r\nHost: localhost\r\n\r\n");
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
        let (exec, calls) = fake(guest(""));
        let mut relays = Relays::new(exec, "sbx-m");
        let warning = relays.start(port).expect("a warning");
        let want = format!("warning: can't listen on 127.0.0.1:{port} for the login callback: ");
        assert!(warning.starts_with(&want), "{warning}");
        assert!(warning.len() > want.len(), "{warning}");
        assert_eq!(relays.start(port), None);
        assert!(calls.lock().unwrap().is_empty());
    }

    #[test]
    fn a_slow_browser_is_cut_off_and_drop_is_prompt() {
        let (exec, _) = fake(guest("HTTP/1.1 200 OK\r\n\r\n"));
        let mut relays = Relays::new(exec, "sbx-m");
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
}
