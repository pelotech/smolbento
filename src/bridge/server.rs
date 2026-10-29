//! The host end of the bridge socket: a listener thread that answers the shims' requests with a
//! minimal HTTP/1.1 (one request per connection, `Connection: close`).

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};

/// Opens a URL on the host.
pub type Opener = Box<dyn Fn(&str) -> Result<()> + Send + Sync>;
/// Sets the host clipboard to the given text.
pub type Copier = Box<dyn Fn(&[u8]) -> Result<()> + Send + Sync>;
/// Starts the login callback relay for a port (once per port; later calls do nothing).
pub type Relay = Box<dyn Fn(u16) + Send + Sync>;

/// What the requests do; tests inject their own opener and copier.
pub struct Handlers {
    /// The `browser.enabled` setting.
    pub browser_enabled: bool,
    pub open: Opener,
    pub copy: Copier,
    pub relay: Relay,
}

/// Request bodies above this are refused (`413`).
const MAX_BODY: usize = 1 << 20;
/// Longest request or header line.
const MAX_LINE: u64 = 8 << 10;
const MAX_HEADERS: usize = 100;
/// How long a client has, from its connect, to send its whole request; also how long writing the
/// answer may take. Requests are handled one at a time, so this bounds what a slow client holds.
pub(super) const DEADLINE: Duration = Duration::from_secs(10);
/// How often the accept loop and a request being read check for a stop.
pub(super) const POLL: Duration = Duration::from_millis(50);

/// A running listener. Dropping it stops the thread (within `POLL`, or once a running opener or
/// copier returns; those have their own timeout), so no request is handled after it, and removes
/// the socket file, if it is still the one this process bound.
pub struct Server {
    path: PathBuf,
    ino: u64,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

/// Serves `path` until the returned `Server` is dropped. `None` when another session already
/// serves it (a connect succeeds); a stale socket file is replaced. The directory is created 0700
/// and must be the caller's.
pub fn serve(path: &Path, handlers: Handlers) -> Result<Option<Server>> {
    serve_within(path, handlers, DEADLINE)
}

fn serve_within(path: &Path, handlers: Handlers, deadline: Duration) -> Result<Option<Server>> {
    let Some(listener) = bind(path)? else {
        return Ok(None);
    };
    let ino = fs::symlink_metadata(path)?.ino();
    listener.set_nonblocking(true)?;
    let stop = Arc::new(AtomicBool::new(false));
    let thread = {
        let stop = stop.clone();
        thread::spawn(move || accept_loop(&listener, &stop, &handlers, deadline))
    };
    Ok(Some(Server {
        path: path.to_path_buf(),
        ino,
        stop,
        thread: Some(thread),
    }))
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
        if fs::symlink_metadata(&self.path).is_ok_and(|m| m.ino() == self.ino) {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn bind(path: &Path) -> Result<Option<UnixListener>> {
    if let Some(dir) = path.parent() {
        private_dir(dir)?;
    }
    if fs::symlink_metadata(path).is_ok() {
        if UnixStream::connect(path).is_ok() {
            return Ok(None);
        }
        fs::remove_file(path).with_context(|| format!("removing stale {}", path.display()))?;
    }
    match UnixListener::bind(path) {
        Ok(l) => Ok(Some(l)),
        // Another session bound it since the check.
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => Ok(None),
        Err(e) => Err(e).with_context(|| format!("listening on {}", path.display())),
    }
}

/// Creates `dir` 0700, or checks that an existing one is a directory of ours (it is under the
/// shared `/tmp`) and tightens it to 0700.
fn private_dir(dir: &Path) -> Result<()> {
    match fs::DirBuilder::new().mode(0o700).create(dir) {
        Err(e) if e.kind() != std::io::ErrorKind::AlreadyExists => {
            return Err(e).with_context(|| format!("creating {}", dir.display()));
        }
        _ => {}
    }
    let m = fs::symlink_metadata(dir)?;
    if !m.is_dir() || m.uid() != crate::sandbox::host_uid() {
        bail!("{} isn't a directory owned by you", dir.display());
    }
    if m.mode() & 0o777 != 0o700 {
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
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

/// Answers one request. Request bodies (clipboard text) are never logged.
fn handle(stream: &UnixStream, h: &Handlers, until: Instant, stop: &AtomicBool) {
    // Accepted sockets inherit non-blocking mode on some systems.
    if stream.set_nonblocking(false).is_err() || stream.set_write_timeout(Some(DEADLINE)).is_err() {
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

/// A socket that can wait a while for data: Unix (the bridge) or TCP (the login relay).
pub(super) trait Stream {
    fn read_for(&self, buf: &mut [u8], timeout: Duration) -> std::io::Result<usize>;
}

impl Stream for UnixStream {
    fn read_for(&self, buf: &mut [u8], timeout: Duration) -> std::io::Result<usize> {
        self.set_read_timeout(Some(timeout))?;
        (&mut &*self).read(buf)
    }
}

impl Stream for std::net::TcpStream {
    fn read_for(&self, buf: &mut [u8], timeout: Duration) -> std::io::Result<usize> {
        self.set_read_timeout(Some(timeout))?;
        (&mut &*self).read(buf)
    }
}

struct Deadline<'a, S> {
    stream: &'a S,
    until: Instant,
    stop: &'a AtomicBool,
}

impl<S: Stream> Read for Deadline<'_, S> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        use std::io::ErrorKind::{Interrupted, TimedOut, WouldBlock};
        loop {
            let left = self.until.saturating_duration_since(Instant::now());
            if left.is_zero() || self.stop.load(Ordering::Relaxed) {
                return Err(TimedOut.into());
            }
            // Wake up every POLL to see a stop.
            match self.stream.read_for(buf, left.min(POLL)) {
                Err(e) if matches!(e.kind(), WouldBlock | TimedOut | Interrupted) => {}
                r => return r,
            }
        }
    }
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
    } else {
        done((h.copy)(&req.body))
    }
}

fn open(h: &Handlers, body: &[u8]) -> Response {
    if !h.browser_enabled {
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
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::sync::Mutex;

    /// Handlers that record what they were asked to open, copy and relay; `fail` makes opening
    /// and copying fail.
    fn recording(enabled: bool, fail: bool) -> (Handlers, Arc<Mutex<Vec<String>>>) {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let (o, c, r) = (seen.clone(), seen.clone(), seen.clone());
        let h = Handlers {
            browser_enabled: enabled,
            open: Box::new(move |url| {
                o.lock().unwrap().push(format!("open {url}"));
                if fail {
                    bail!("no browser");
                }
                Ok(())
            }),
            copy: Box::new(move |text| {
                c.lock()
                    .unwrap()
                    .push(format!("copy {}", String::from_utf8_lossy(text)));
                if fail {
                    bail!("no clipboard");
                }
                Ok(())
            }),
            relay: Box::new(move |port| r.lock().unwrap().push(format!("relay {port}"))),
        };
        (h, seen)
    }

    fn post(path: &str, body: &str) -> Request {
        Request {
            method: "POST".into(),
            path: path.into(),
            host: None,
            body: body.as_bytes().to_vec(),
        }
    }

    fn parse(raw: &[u8]) -> Result<Request, Response> {
        read_request(&mut Cursor::new(raw))
    }

    fn status(raw: &[u8]) -> u16 {
        parse(raw).unwrap_err().status
    }

    #[test]
    fn parses_a_post_with_a_body() {
        let raw = b"POST /copy HTTP/1.1\r\nHost: bridge\r\ncontent-length: 5\r\n\r\nhi\nyo";
        let want = Request {
            host: Some("bridge".into()),
            ..post("/copy", "hi\nyo")
        };
        assert_eq!(parse(raw).unwrap(), want);
        // No Content-Length: no body. No Host.
        let raw = b"POST /open HTTP/1.1\r\n\r\n";
        assert_eq!(parse(raw).unwrap(), post("/open", ""));
    }

    #[test]
    fn refuses_bad_requests() {
        for raw in [
            &b""[..],
            b"POST /open\r\n\r\n",
            b"POST /open HTTP/1.1\r\n",
            b"POST /open SPDY/3\r\n\r\n",
            b"POST /open HTTP/1.1\r\nno colon\r\n\r\n",
            b"POST /open HTTP/1.1\r\nContent-Length: x\r\n\r\n",
            b"POST /open HTTP/1.1\r\nContent-Length: 9\r\n\r\nshort",
            b"POST /open HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n",
        ] {
            assert_eq!(status(raw), 400, "{}", String::from_utf8_lossy(raw));
        }
        let long = format!("POST /{} HTTP/1.1\r\n\r\n", "x".repeat(MAX_LINE as usize));
        assert_eq!(status(long.as_bytes()), 400);
        let many = format!(
            "POST / HTTP/1.1\r\n{}\r\n",
            "A: b\r\n".repeat(MAX_HEADERS + 1)
        );
        assert_eq!(status(many.as_bytes()), 400);
    }

    #[test]
    fn refuses_a_body_over_1_mib() {
        let raw = format!(
            "POST /copy HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
            MAX_BODY + 1
        );
        assert_eq!(status(raw.as_bytes()), 413);
        let ok = format!(
            "POST /copy HTTP/1.1\r\nContent-Length: {MAX_BODY}\r\n\r\n{}",
            "x".repeat(MAX_BODY)
        );
        assert_eq!(parse(ok.as_bytes()).unwrap().body.len(), MAX_BODY);
    }

    #[test]
    fn routes_by_path_and_method() {
        let (h, seen) = recording(true, false);
        assert_eq!(route(&h, &post("/nope", "")).status, 404);
        let get = Request {
            method: "GET".into(),
            ..post("/copy", "")
        };
        assert_eq!(route(&h, &get).status, 405);
        assert!(seen.lock().unwrap().is_empty());
    }

    #[test]
    fn open_opens_https_urls() {
        let (h, seen) = recording(true, false);
        let url = "https://example.com/a?b=c%20d";
        assert_eq!(route(&h, &post("/open", url)).status, 204);
        assert_eq!(*seen.lock().unwrap(), vec![format!("open {url}")]);
    }

    #[test]
    fn finds_a_loopback_redirect_uris_port() {
        for (url, port) in [
            // URL-encoded, as OAuth clients send it.
            (
                "https://auth.example.com/authorize?client_id=x&redirect_uri=http%3A%2F%2Flocalhost%3A8085%2Fcallback&state=y",
                Some(8085),
            ),
            (
                "https://a.example/o?redirect_uri=http%3a%2f%2f127.0.0.1%3a54545%2Fcb%3Fx%3D1",
                Some(54545),
            ),
            // Not encoded, no path, first parameter, upper-case scheme and host.
            (
                "https://a.example/o?redirect_uri=http://127.0.0.1:9000",
                Some(9000),
            ),
            (
                "https://a.example/o?redirect_uri=HTTP://LocalHost:1455/x",
                Some(1455),
            ),
            (
                "https://a.example/o?a=1&redirect_uri=http://localhost:80?q#f",
                Some(80),
            ),
            // Other hosts.
            (
                "https://a.example/o?redirect_uri=http%3A%2F%2Fexample.com%3A8085%2Fcb",
                None,
            ),
            (
                "https://a.example/o?redirect_uri=http://localhost.evil.com:8085/",
                None,
            ),
            (
                "https://a.example/o?redirect_uri=http://127.0.0.1.nip.io:8085/",
                None,
            ),
            (
                "https://a.example/o?redirect_uri=http://localhost:8085@evil.com/",
                None,
            ),
            ("https://a.example/o?redirect_uri=http://[::1]:8085/", None),
            // Not http, or no usable port.
            (
                "https://a.example/o?redirect_uri=https://localhost:8085/",
                None,
            ),
            (
                "https://a.example/o?redirect_uri=http%3A%2F%2Flocalhost%2Fcb",
                None,
            ),
            (
                "https://a.example/o?redirect_uri=http://localhost:/cb",
                None,
            ),
            (
                "https://a.example/o?redirect_uri=http://localhost:0/cb",
                None,
            ),
            (
                "https://a.example/o?redirect_uri=http://localhost:65536/cb",
                None,
            ),
            (
                "https://a.example/o?redirect_uri=http://localhost:80x/cb",
                None,
            ),
            // Another parameter, the path, or the fragment.
            (
                "https://a.example/o?my_redirect_uri=http://localhost:8085/",
                None,
            ),
            (
                "https://a.example/redirect_uri=http://localhost:8085/",
                None,
            ),
            (
                "https://a.example/o#redirect_uri=http://localhost:8085/",
                None,
            ),
            ("https://a.example/o", None),
        ] {
            assert_eq!(callback_port(url), port, "{url}");
        }
    }

    #[test]
    fn percent_decoding_keeps_what_isnt_an_escape() {
        assert_eq!(percent_decode("a%3A%2fb"), "a:/b");
        assert_eq!(percent_decode("100%"), "100%");
        assert_eq!(percent_decode("%zz%4"), "%zz%4");
        assert_eq!(percent_decode("%+1%-f"), "%+1%-f");
        assert_eq!(percent_decode("%C3%A9+x"), "é+x");
    }

    #[test]
    fn open_starts_the_relay_before_opening() {
        let (h, seen) = recording(true, false);
        let url = "https://a.example/o?redirect_uri=http%3A%2F%2Flocalhost%3A8085%2Fcb";
        assert_eq!(route(&h, &post("/open", url)).status, 204);
        assert_eq!(
            *seen.lock().unwrap(),
            vec!["relay 8085".to_string(), format!("open {url}")]
        );
        // No loopback redirect_uri: no relay.
        seen.lock().unwrap().clear();
        let other = "https://a.example/o?redirect_uri=https%3A%2F%2Fexample.com%2Fcb";
        assert_eq!(route(&h, &post("/open", other)).status, 204);
        assert_eq!(*seen.lock().unwrap(), vec![format!("open {other}")]);
        // Nor for a URL that isn't opened.
        seen.lock().unwrap().clear();
        let (off, off_seen) = recording(false, false);
        assert_eq!(route(&off, &post("/open", url)).status, 403);
        assert!(off_seen.lock().unwrap().is_empty());
    }

    #[test]
    fn open_refuses_other_schemes_with_sbx_text() {
        let (h, seen) = recording(true, false);
        for url in [
            "http://example.com",
            "file:///etc/passwd",
            "javascript:x",
            "",
            "https",
        ] {
            let r = route(&h, &post("/open", url));
            assert_eq!(r.status, 400, "{url}");
            assert_eq!(r.body, "only https URLs are supported\n", "{url}");
        }
        for url in [
            "https://a b",
            "https://a\n",
            "https://a\u{7f}",
            "https://a/`id`",
            "https://a/\"x",
            "https://a/\\x",
            "https://a/<x>",
            "https://a/{x}",
            "https://a/x|y",
            "https://a/x^y",
            "https://a/\u{85}",
        ] {
            let r = route(&h, &post("/open", url));
            assert_eq!(
                (r.status, r.body.as_str()),
                (400, "invalid URL\n"),
                "{url:?}"
            );
        }
        let bad_utf8 = Request {
            body: b"https://\xff".to_vec(),
            ..post("/open", "")
        };
        assert_eq!(route(&h, &bad_utf8).status, 400);
        assert!(seen.lock().unwrap().is_empty());
    }

    #[test]
    fn open_is_forbidden_when_the_browser_is_disabled() {
        let (h, seen) = recording(false, false);
        let r = route(&h, &post("/open", "https://example.com"));
        assert_eq!((r.status, r.body.as_str()), (403, "browser is disabled\n"));
        assert!(seen.lock().unwrap().is_empty());
        // Copying still works.
        assert_eq!(route(&h, &post("/copy", "x")).status, 204);
    }

    #[test]
    fn a_failed_open_or_copy_is_a_bad_gateway() {
        let (h, _) = recording(true, true);
        let r = route(&h, &post("/open", "https://example.com"));
        assert_eq!((r.status, r.body.as_str()), (502, "no browser\n"));
        let r = route(&h, &post("/copy", "x"));
        assert_eq!((r.status, r.body.as_str()), (502, "no clipboard\n"));
    }

    #[test]
    fn copy_passes_the_bytes_unchanged() {
        let (h, seen) = recording(true, false);
        assert_eq!(route(&h, &post("/copy", "a\r\n b\n\n")).status, 204);
        assert_eq!(*seen.lock().unwrap(), vec!["copy a\r\n b\n\n"]);
    }

    #[test]
    fn responses_close_the_connection() {
        let mut out = Vec::new();
        let resp = Response {
            status: 400,
            body: "only https URLs are supported\n".into(),
        };
        write_response(&mut out, &resp).unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\nContent-Length: 30\r\n\
             Connection: close\r\n\r\nonly https URLs are supported\n"
        );
        let mut out = Vec::new();
        write_response(
            &mut out,
            &Response {
                status: 204,
                body: String::new(),
            },
        )
        .unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n"
        );
    }

    /// Sends `raw` over the socket and returns the whole answer.
    fn request(path: &Path, raw: &[u8]) -> String {
        let mut s = UnixStream::connect(path).unwrap();
        s.write_all(raw).unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).unwrap();
        out
    }

    fn sock(dir: &tempfile::TempDir) -> PathBuf {
        dir.path().join("sbt").join("x.sock")
    }

    #[test]
    fn serves_requests_until_dropped_and_removes_its_socket() {
        let dir = tempfile::tempdir().unwrap();
        let path = sock(&dir);
        let (h, seen) = recording(true, false);
        let server = serve(&path, h).unwrap().expect("bound");
        let mode = fs::metadata(path.parent().unwrap()).unwrap().mode();
        assert_eq!(mode & 0o777, 0o700);
        for _ in 0..2 {
            let out = request(
                &path,
                b"POST /copy HTTP/1.1\r\nHost: bridge\r\nContent-Length: 2\r\n\r\nhi",
            );
            assert!(out.starts_with("HTTP/1.1 204 "), "{out}");
        }
        let out = request(&path, b"POST /x HTTP/1.1\r\n\r\n");
        assert!(out.starts_with("HTTP/1.1 404 "), "{out}");
        let out = request(
            &path,
            b"POST /copy HTTP/1.1\r\nContent-Length: 99999999\r\n\r\n",
        );
        assert!(out.starts_with("HTTP/1.1 413 "), "{out}");
        assert_eq!(seen.lock().unwrap().len(), 2);
        drop(server);
        assert!(!path.exists());
        assert!(UnixStream::connect(&path).is_err());
    }

    #[test]
    fn a_served_socket_is_left_to_its_session() {
        let dir = tempfile::tempdir().unwrap();
        let path = sock(&dir);
        let first = serve(&path, recording(true, false).0)
            .unwrap()
            .expect("bound");
        assert!(serve(&path, recording(true, false).0).unwrap().is_none());
        // Still the first session's.
        let out = request(&path, b"POST /copy HTTP/1.1\r\n\r\n");
        assert!(out.starts_with("HTTP/1.1 204 "), "{out}");
        drop(first);
    }

    #[test]
    fn a_stale_socket_is_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let path = sock(&dir);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        // A socket file nobody listens on, as a crashed session leaves.
        drop(UnixListener::bind(&path).unwrap());
        assert!(path.exists());
        let server = serve(&path, recording(true, false).0)
            .unwrap()
            .expect("bound");
        let out = request(&path, b"POST /copy HTTP/1.1\r\n\r\n");
        assert!(out.starts_with("HTTP/1.1 204 "), "{out}");
        drop(server);
        assert!(!path.exists());
    }

    #[test]
    fn only_removes_the_socket_it_bound() {
        let dir = tempfile::tempdir().unwrap();
        let path = sock(&dir);
        let server = serve(&path, recording(true, false).0)
            .unwrap()
            .expect("bound");
        // Another session took over the path (ours looked stale to it).
        fs::remove_file(&path).unwrap();
        let other = UnixListener::bind(&path).unwrap();
        drop(server);
        assert!(path.exists(), "the other session's socket stays");
        drop(other);
    }

    #[test]
    fn tightens_its_own_directory_and_refuses_another_kind() {
        let dir = tempfile::tempdir().unwrap();
        let path = sock(&dir);
        let parent = path.parent().unwrap();
        fs::create_dir(parent).unwrap();
        fs::set_permissions(parent, fs::Permissions::from_mode(0o755)).unwrap();
        drop(serve(&path, recording(true, false).0).unwrap());
        assert_eq!(fs::metadata(parent).unwrap().mode() & 0o777, 0o700);
        // A symlink planted in its place is refused.
        fs::remove_dir(parent).unwrap();
        std::os::unix::fs::symlink(dir.path(), parent).unwrap();
        let err = serve(&path, recording(true, false).0)
            .err()
            .expect("refused");
        assert!(err.to_string().contains("isn't a directory"), "{err:#}");
    }

    #[test]
    fn a_trickling_client_is_cut_off_at_the_deadline() {
        let dir = tempfile::tempdir().unwrap();
        let path = sock(&dir);
        let deadline = Duration::from_millis(300);
        let server = serve_within(&path, recording(true, false).0, deadline)
            .unwrap()
            .expect("bound");
        let mut slow = UnixStream::connect(&path).unwrap();
        slow.write_all(b"POST /copy HTTP/1.1\r\n").unwrap();
        // One header byte every 20 ms, well inside any per-read timeout, for up to 3 s.
        let writer = slow.try_clone().unwrap();
        let trickle = thread::spawn(move || {
            for _ in 0..150 {
                if (&writer).write_all(b"X").is_err() {
                    break;
                }
                thread::sleep(Duration::from_millis(20));
            }
        });
        // Fails rather than hangs when the server never cuts it off.
        slow.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let started = Instant::now();
        let mut out = String::new();
        let _ = slow.read_to_string(&mut out);
        let took = started.elapsed();
        assert!(took < Duration::from_secs(2), "cut off after {took:?}");
        assert!(out.is_empty() || out.starts_with("HTTP/1.1 400 "), "{out}");
        // The next client is served.
        let out = request(&path, b"POST /copy HTTP/1.1\r\n\r\n");
        assert!(out.starts_with("HTTP/1.1 204 "), "{out}");
        drop(slow);
        trickle.join().unwrap();
        drop(server);
    }

    #[test]
    fn drop_returns_promptly_while_a_slow_client_is_connected() {
        let dir = tempfile::tempdir().unwrap();
        let path = sock(&dir);
        let server = serve(&path, recording(true, false).0)
            .unwrap()
            .expect("bound");
        let mut slow = UnixStream::connect(&path).unwrap();
        slow.write_all(b"POST /copy HTTP/1.1\r\n").unwrap();
        // Let the accept loop take it and start waiting for the rest.
        thread::sleep(POLL * 4);
        let started = Instant::now();
        drop(server);
        let took = started.elapsed();
        assert!(took < Duration::from_secs(1), "drop took {took:?}");
        assert!(!path.exists());
    }
}
