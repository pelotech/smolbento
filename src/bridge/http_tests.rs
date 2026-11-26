use super::*;
use anyhow::bail;
use std::fs;
use std::io::Cursor;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;

/// Handlers that record what they were asked to open, copy and relay; `fail` makes opening
/// and copying fail.
fn recording(enabled: bool, fail: bool) -> (Handlers, Arc<Mutex<Vec<String>>>) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let (o, c, r) = (seen.clone(), seen.clone(), seen.clone());
    let h = Handlers {
        allowed: super::super::Allowed {
            browser: enabled,
            copy: true,
        },
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
fn copy_is_forbidden_unless_text_copy_is_enabled() {
    let (mut h, seen) = recording(true, false);
    h.allowed.copy = false;
    let r = route(&h, &post("/copy", "secret"));
    assert_eq!(
        (r.status, r.body.as_str()),
        (
            403,
            "copying to the host clipboard is off; enable it with \
             `bento settings set clipboard.textCopy true`\n"
        )
    );
    assert!(seen.lock().unwrap().is_empty());
    // Opening URLs still works.
    assert_eq!(route(&h, &post("/open", "https://example.com")).status, 204);
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
fn one_connection_on_any_socket_is_answered() {
    let (h, seen) = recording(true, false);
    let (mut client, server) = UnixStream::pair().unwrap();
    let t = thread::spawn(move || serve_connection(&server, &h));
    client
        .write_all(b"POST /copy HTTP/1.1\r\nHost: bridge\r\nContent-Length: 2\r\n\r\nhi")
        .unwrap();
    let mut out = String::new();
    client.read_to_string(&mut out).unwrap();
    t.join().unwrap();
    assert!(out.starts_with("HTTP/1.1 204 "), "{out}");
    assert_eq!(*seen.lock().unwrap(), ["copy hi"]);
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
    fs::DirBuilder::new()
        .mode(0o700)
        .create(path.parent().unwrap())
        .unwrap();
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
fn refuses_a_directory_that_isnt_private() {
    let dir = tempfile::tempdir().unwrap();
    let path = sock(&dir);
    let parent = path.parent().unwrap();
    // Open to others: whatever is in it may have been planted, so it isn't tightened and used.
    fs::create_dir(parent).unwrap();
    fs::set_permissions(parent, fs::Permissions::from_mode(0o755)).unwrap();
    let err = serve(&path, recording(true, false).0)
        .err()
        .expect("refused");
    assert!(err.to_string().contains("mode 755"), "{err:#}");
    assert_eq!(fs::metadata(parent).unwrap().mode() & 0o777, 0o755);
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
