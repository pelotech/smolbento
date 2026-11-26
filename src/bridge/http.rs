//! The host end of the bridge socket: a listener thread that answers the shims' requests with a
//! minimal HTTP/1.1 (one request per connection, `Connection: close`).

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::Result;

use super::listener::{DEADLINE, Deadline, POLL, Server, Stream, spawn};

/// Opens a URL on the host.
pub type Opener = Box<dyn Fn(&str) -> Result<()> + Send + Sync>;
/// Sets the host clipboard to the given text.
pub type Copier = Box<dyn Fn(&[u8]) -> Result<()> + Send + Sync>;
/// Starts the login callback relay for a port (once per port; later calls do nothing).
pub type Relay = Box<dyn Fn(u16) + Send + Sync>;

/// What the requests do; tests inject their own opener and copier.
pub struct Handlers {
    /// The `browser.enabled` and `clipboard.textCopy` settings.
    pub allowed: super::Allowed,
    pub open: Opener,
    pub copy: Copier,
    pub relay: Relay,
}

/// Request bodies above this are refused (`413`).
const MAX_BODY: usize = 1 << 20;
/// Longest request or header line.
const MAX_LINE: u64 = 8 << 10;
const MAX_HEADERS: usize = 100;

/// Serves `path` until the returned `Server` is dropped. `None` when another session already
/// serves it (a connect succeeds); a stale socket file is replaced. The directory is created 0700
/// and must be the caller's.
pub fn serve(path: &Path, handlers: Handlers) -> Result<Option<Server>> {
    serve_within(path, handlers, DEADLINE)
}

fn serve_within(path: &Path, handlers: Handlers, deadline: Duration) -> Result<Option<Server>> {
    spawn(path, move |listener, stop| {
        accept_loop(listener, &stop, &handlers, deadline);
    })
}

/// Handles one connection at a time on this thread: a guest can't make the host start more.
fn accept_loop(listener: &UnixListener, stop: &AtomicBool, h: &Handlers, deadline: Duration) {
    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, _)) => handle(&stream, h, Instant::now() + deadline, stop),
            // Nothing waiting, or a connection that went away before we took it.
            Err(_) => thread::sleep(POLL),
        }
    }
}

/// Answers the one request on `stream`, as a unit's `_serve bridge` does.
pub fn serve_connection(stream: &UnixStream, h: &Handlers) {
    handle(
        stream,
        h,
        Instant::now() + DEADLINE,
        &AtomicBool::new(false),
    );
}

/// Answers one request. Request bodies (clipboard text) are never logged.
fn handle(stream: &UnixStream, h: &Handlers, until: Instant, stop: &AtomicBool) {
    if stream.blocking().is_err() {
        return;
    }
    let resp = match read_within(stream, until, stop) {
        Ok(req) => route(h, &req),
        Err(resp) => resp,
    };
    let _ = write_response(&mut &*stream, &resp);
}

/// Reads one request from a client (the bridge's, or a browser's at the login relay) until
/// `until` for the whole request (not per read), or a stop.
pub(super) fn read_within<S: Stream>(
    stream: &S,
    until: Instant,
    stop: &AtomicBool,
) -> Result<Request, Response> {
    read_request(&mut BufReader::new(Deadline {
        stream,
        until,
        stop,
    }))
}

#[derive(Debug, PartialEq)]
pub(super) struct Request {
    pub method: String,
    pub path: String,
    /// The `Host` header, which the login relay checks.
    pub host: Option<String>,
    pub body: Vec<u8>,
}

#[derive(Debug, PartialEq)]
pub(super) struct Response {
    pub status: u16,
    body: String,
}

impl Response {
    pub(super) fn new(status: u16, body: &str) -> Response {
        let body = if body.is_empty() {
            String::new()
        } else {
            format!("{body}\n")
        };
        Response { status, body }
    }
}

pub(super) fn bad_request() -> Response {
    Response::new(400, "bad request")
}

/// One CRLF- (or LF-) terminated line, without its ending.
fn line(r: &mut impl BufRead) -> Result<String, Response> {
    let mut s = String::new();
    r.take(MAX_LINE)
        .read_line(&mut s)
        .map_err(|_| bad_request())?;
    let Some(s) = s.strip_suffix('\n') else {
        return Err(bad_request());
    };
    Ok(s.strip_suffix('\r').unwrap_or(s).to_string())
}

fn read_request(r: &mut impl BufRead) -> Result<Request, Response> {
    let start = line(r)?;
    let mut parts = start.split(' ');
    let (Some(method), Some(path), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(bad_request());
    };
    if !version.starts_with("HTTP/1.") {
        return Err(bad_request());
    }
    let mut len = 0;
    let mut host = None;
    for n in 0.. {
        let header = line(r)?;
        if header.is_empty() {
            break;
        }
        if n == MAX_HEADERS {
            return Err(bad_request());
        }
        let (name, value) = header.split_once(':').ok_or_else(bad_request)?;
        if name.eq_ignore_ascii_case("content-length") {
            len = value.trim().parse().map_err(|_| bad_request())?;
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(bad_request());
        } else if name.eq_ignore_ascii_case("host") {
            host = Some(value.trim().to_string());
        }
    }
    if len > MAX_BODY {
        return Err(Response::new(413, "request body too large"));
    }
    let mut body = vec![0; len];
    r.read_exact(&mut body).map_err(|_| bad_request())?;
    Ok(Request {
        method: method.to_string(),
        path: path.to_string(),
        host,
        body,
    })
}

fn route(h: &Handlers, req: &Request) -> Response {
    if !matches!(req.path.as_str(), "/open" | "/copy") {
        return Response::new(404, "not found");
    }
    if req.method != "POST" {
        return Response::new(405, "use POST");
    }
    if req.path == "/open" {
        open(h, &req.body)
    } else if !h.allowed.copy {
        Response::new(
            403,
            "copying to the host clipboard is off; enable it with \
             `bento settings set clipboard.textCopy true`",
        )
    } else {
        done((h.copy)(&req.body))
    }
}

fn open(h: &Handlers, body: &[u8]) -> Response {
    if !h.allowed.browser {
        return Response::new(403, "browser is disabled");
    }
    let Ok(url) = std::str::from_utf8(body) else {
        return bad_request();
    };
    // sbx's rule and text; the shim then prints the URL for the user instead.
    if !url
        .get(..8)
        .is_some_and(|s| s.eq_ignore_ascii_case("https://"))
    {
        return Response::new(400, "only https URLs are supported");
    }
    // Characters never valid in a URL: they would reach `open`/`xdg-open` (a shell script).
    if url
        .chars()
        .any(|c| c.is_control() || c.is_whitespace() || "`\"\\<>{}|^".contains(c))
    {
        return Response::new(400, "invalid URL");
    }
    // A login's callback server in the sandbox: relay the browser's callback to it.
    if let Some(port) = callback_port(url) {
        (h.relay)(port);
    }
    done((h.open)(url))
}

/// The port of a URL's (URL-decoded) `redirect_uri` when it is `http://localhost:PORT…` or
/// `http://127.0.0.1:PORT…`.
fn callback_port(url: &str) -> Option<u16> {
    let url = url.split('#').next()?;
    let (_, query) = url.split_once('?')?;
    let value = query
        .split('&')
        .find_map(|p| p.strip_prefix("redirect_uri="))?;
    let uri = percent_decode(value);
    if !uri.get(..7)?.eq_ignore_ascii_case("http://") {
        return None;
    }
    let rest = &uri[7..];
    let (host, rest) = rest.split_once(':')?;
    if !host.eq_ignore_ascii_case("localhost") && host != "127.0.0.1" {
        return None;
    }
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let port = &rest[..end];
    if !port.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    port.parse().ok().filter(|&p| p != 0)
}

/// `%XX` decoding; anything else (an invalid escape too) is kept.
fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    let digit = |j: usize| b.get(j).and_then(|&c| (c as char).to_digit(16));
    while i < b.len() {
        match (b[i], digit(i + 1), digit(i + 2)) {
            (b'%', Some(hi), Some(lo)) => {
                out.push((hi * 16 + lo) as u8);
                i += 3;
            }
            (c, ..) => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// `204` for a handler that worked, else `502` with its error.
fn done(result: Result<()>) -> Response {
    match result {
        Ok(()) => Response::new(204, ""),
        Err(e) => Response::new(502, &format!("{e:#}")),
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        204 => "No Content",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Content Too Large",
        502 => "Bad Gateway",
        _ => "Error",
    }
}

pub(super) fn write_response(w: &mut impl Write, resp: &Response) -> std::io::Result<()> {
    let status = resp.status;
    let mut head = format!("HTTP/1.1 {status} {}\r\n", reason(status));
    if status != 204 {
        head += &format!(
            "Content-Type: text/plain\r\nContent-Length: {}\r\n",
            resp.body.len()
        );
    }
    head += "Connection: close\r\n\r\n";
    w.write_all(head.as_bytes())?;
    w.write_all(resp.body.as_bytes())?;
    w.flush()
}

#[cfg(test)]
#[path = "http_tests.rs"]
mod tests;
