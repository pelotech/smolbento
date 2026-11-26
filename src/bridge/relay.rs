//! The login callback relay: a login in the sandbox (an OAuth client) listens on the guest's
//! `127.0.0.1:PORT`, which a published port can't reach, and the host's browser is sent to
//! `http://localhost:PORT/…`. We listen on the host's `127.0.0.1:PORT` and replay each request in
//! the sandbox with `curl`, returning the guest's answer.

use std::collections::BTreeSet;
use std::fs::File;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use anyhow::Result;

use super::http::{self, Request, Response};
use super::listener::{DEADLINE, POLL, Stream};
use crate::smolvm::{ExecSpec, Output};
use crate::util::sh_quote;

/// Runs `smolvm ARGS`. Its own, not the session's runner, which can't move to another thread.
/// The guest is untrusted: it must be bounded by `REPLAY_TIMEOUT` and `MAX_REPLAY`.
pub type Exec = Box<dyn Fn(&[String]) -> Result<Output> + Send + Sync>;

/// How long a replay may run before smolvm is killed (`502`).
pub(super) const REPLAY_TIMEOUT: Duration = Duration::from_secs(15);
/// The most a replay may answer with (`502` beyond).
pub(super) const MAX_REPLAY: usize = 1 << 20;
/// Relays a session may start: a login needs one.
const MAX_RELAYS: usize = 4;
/// How long a relay listens: a login's callback comes within minutes.
const LIFETIME: Duration = Duration::from_secs(10 * 60);
/// How long the check for a host service already on the port waits for it to answer.
const PROBE: Duration = Duration::from_millis(200);

/// Where replays run: the sandbox's machine, as the session's user.
struct Guest {
    machine: String,
    user: String,
}

/// A session's relays, one per port; dropping it stops them.
pub struct Relays {
    exec: Arc<Exec>,
    guest: Arc<Guest>,
    /// Ports already started or that failed: each is tried once per session.
    tried: BTreeSet<u16>,
    /// Warned that `MAX_RELAYS` were started.
    warned_full: bool,
    lifetime: Duration,
    /// Set, dropping waits for the relays to run their `lifetime` out instead of stopping them: a
    /// unit's `_serve bridge` handles one connection, and a login's relay outlives it. Its relays
    /// then hold one of these slot files (`host_service::RELAY_SLOTS` per sandbox), bounding the
    /// processes they keep alive.
    linger: Option<Vec<PathBuf>>,
    /// The slot held while lingering relays run.
    held: Option<File>,
    stop: Arc<AtomicBool>,
    /// One per started relay.
    threads: Vec<JoinHandle<()>>,
}

impl Relays {
    /// Replays run in `machine` as `user`.
    pub fn new(exec: Exec, machine: &str, user: &str) -> Relays {
        Relays {
            exec: Arc::new(exec),
            guest: Arc::new(Guest {
                machine: machine.into(),
                user: user.into(),
            }),
            tried: BTreeSet::new(),
            warned_full: false,
            lifetime: LIFETIME,
            linger: None,
            held: None,
            stop: Arc::default(),
            threads: Vec::new(),
        }
    }

    /// Relays outlive the `Relays` value: dropping it waits for them, holding one of `slots`.
    pub fn lingering(mut self, slots: Vec<PathBuf>) -> Relays {
        self.linger = Some(slots);
        self
    }

    /// Starts relaying `port` to the sandbox for `LIFETIME`, once, up to `MAX_RELAYS` a session.
    /// A warning when the host's port is taken, or (once) when the session has its relays.
    pub fn start(&mut self, port: u16) -> Option<String> {
        if !self.tried.insert(port) {
            return None;
        }
        if self.threads.len() == MAX_RELAYS {
            if std::mem::replace(&mut self.warned_full, true) {
                return None;
            }
            return Some(format!(
                "warning: this session already relays {MAX_RELAYS} login callbacks; not relaying \
                 localhost:{port} or any more"
            ));
        }
        if let Some(slots) = &self.linger
            && self.held.is_none()
        {
            self.held = crate::host_service::acquire_slot(slots);
            if self.held.is_none() {
                return Some(format!(
                    "warning: the sandbox's other sessions already relay login callbacks; not \
                     relaying localhost:{port}"
                ));
            }
        }
        let listener = match listen(port) {
            Ok(l) => l,
            Err(e) => {
                return Some(format!(
                    "warning: can't listen on 127.0.0.1:{port} for the login callback: {e}"
                ));
            }
        };
        let (exec, guest, stop) = (self.exec.clone(), self.guest.clone(), self.stop.clone());
        let until = Instant::now() + self.lifetime;
        self.threads.push(thread::spawn(move || {
            accept_loop(&listener, port, &exec, &guest, &stop, until)
        }));
        None
    }
}

impl Drop for Relays {
    /// Stops the listeners (within `POLL`, or once a running replay returns).
    fn drop(&mut self) {
        if self.linger.is_none() {
            self.stop.store(true, Ordering::Relaxed);
        }
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
    }
}

/// Loopback only: the browser is on this host.
fn listen(port: u16) -> std::io::Result<TcpListener> {
    if in_use(port) {
        return Err(std::io::ErrorKind::AddrInUse.into());
    }
    let l = TcpListener::bind((Ipv4Addr::LOCALHOST, port))?;
    l.set_nonblocking(true)?;
    Ok(l)
}

/// Whether something on the host answers on `localhost:PORT`. On macOS our bind to
/// `127.0.0.1:PORT` succeeds while a service listens on `0.0.0.0:PORT` or `[::]:PORT`
/// (`SO_REUSEADDR`), and then takes that service's loopback connections.
fn in_use(port: u16) -> bool {
    [
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
    ]
    .into_iter()
    .any(|ip| TcpStream::connect_timeout(&SocketAddr::new(ip, port), PROBE).is_ok())
}

/// One request at a time, like the bridge, until a stop or `until`.
fn accept_loop(
    listener: &TcpListener,
    port: u16,
    exec: &Exec,
    guest: &Guest,
    stop: &AtomicBool,
    until: Instant,
) {
    while !stop.load(Ordering::Relaxed) && Instant::now() < until {
        match listener.accept() {
            Ok((stream, _)) => answer(&stream, port, exec, guest, stop),
            Err(_) => thread::sleep(POLL),
        }
    }
}

fn answer(stream: &TcpStream, port: u16, exec: &Exec, guest: &Guest, stop: &AtomicBool) {
    if stream.blocking().is_err() {
        return;
    }
    let resp = match http::read_within(stream, Instant::now() + DEADLINE, stop) {
        Ok(req) => replay(exec, guest, port, &req),
        Err(resp) => ours(&resp),
    };
    let _ = (&mut &*stream).write_all(&resp);
}

/// The replay's response to the browser.
fn replay(exec: &Exec, guest: &Guest, port: u16, req: &Request) -> Vec<u8> {
    // Only for this host's own page: a DNS-rebinding page would send its own name.
    let host = req.host.as_deref().unwrap_or_default();
    if !host.eq_ignore_ascii_case(&format!("localhost:{port}"))
        && host != format!("127.0.0.1:{port}")
    {
        return ours(&Response::new(403, "not a localhost request"));
    }
    let (method, target) = (req.method.as_str(), req.path.as_str());
    // Only what a browser sends: a plain method and a path (no absolute URL).
    if method.is_empty()
        || !method.bytes().all(|b| b.is_ascii_uppercase())
        || !target.starts_with('/')
    {
        return ours(&http::bad_request());
    }
    let spec = ExecSpec::sh(
        &guest.machine,
        &guest.user,
        replay_cmd(port, method, target),
    );
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
/// came from the browser: it is quoted, and `-g` stops curl reading `[]{}` as globs. No proxy,
/// and no redirects followed: the browser follows them.
fn replay_cmd(port: u16, method: &str, target: &str) -> String {
    let url = sh_quote(&format!("http://127.0.0.1:{port}{target}"));
    let m = sh_quote(method);
    // 10s: within the browser's patience, and the session's end waits for a running replay.
    format!(
        "u={url}\n\
         if command -v curl >/dev/null 2>&1; then exec curl -s -g -i -m 10 --noproxy '*' -X {m} \"$u\"; fi\n\
         [ {m} = GET ] && command -v wget >/dev/null 2>&1 || exit 127\n\
         printf 'HTTP/1.1 200 OK\\r\\n\\r\\n'\n\
         exec wget -qO- -T 10 --max-redirect=0 \"$u\""
    )
}

/// The guest's status line, headers and body, framed for one response on a closing connection
/// (curl has already undone any chunking). `None` for output that isn't an HTTP response.
/// The body is treated as text (smolvm's output is read as UTF-8): fine for callback pages.
fn pass_through(guest: &str) -> Option<Vec<u8>> {
    let (head, body) = guest.split_once("\r\n\r\n")?;
    // Only CRLF may break a line: a bare CR or LF would let a header smuggle in a second framing.
    if head.replace("\r\n", "").contains(['\r', '\n', '\0']) {
        return None;
    }
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
    let _ = http::write_response(&mut out, resp);
    out
}

#[cfg(test)]
#[path = "relay_tests.rs"]
mod tests;
