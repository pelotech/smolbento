//! Relaying one intercepted flow from smolvm to the interceptor.

use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use smolvm_protocol::intercept::{InterceptEndpoint, VERDICT_CONNECTED};
use smolvm_protocol::sni::{MAX_CLIENT_HELLO, Peek, peek_client_hello};

use crate::name::flow_id;

/// A flow the relay asks about: the name its first bytes ask for, if any, what they are, and its
/// destination.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Flow {
    pub name: Option<String>,
    pub kind: FlowKind,
    pub ip: IpAddr,
    pub port: u16,
}

/// What a flow's first bytes are. A flow decided from its destination alone is `Other`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlowKind {
    /// A TLS ClientHello.
    Tls,
    /// An HTTP/1 request.
    Http,
    /// Anything else, including nothing.
    Other,
}

/// Whether a flow may go on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny,
}

/// Decides each flow, once from its destination (`name: None`) and once more after its first bytes.
pub type Decide = std::sync::Arc<dyn Fn(&Flow) -> Decision + Send + Sync>;

/// smolvm's gateway, which the host can't dial.
pub const GATEWAY: IpAddr = IpAddr::V4(Ipv4Addr::new(100, 96, 0, 1));

/// The verdict that refuses a flow: `ECONNREFUSED`, in `connect_verdict`'s errno convention.
const REFUSED: u8 = 111;

/// How long the first-bytes read waits for more after the last bytes arrived.
const FIRST_BYTES_IDLE: Duration = Duration::from_millis(200);

/// How long a flow may take to present its preamble, the interceptor to answer with a verdict, and
/// the guest to send its first bytes (the interceptor waits for those itself, and gives up first).
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

/// Relay one flow: check smolvm's preamble against `front` and `decide` its destination, open a flow
/// to `inner` for it (the gateway dialled as loopback), pass the connect verdict back, read the guest's
/// first bytes and `decide` again with the name they ask for, then forward them and copy bytes both
/// ways until both sides close. A guest that sends nothing in time is closed without that decide.
///
/// A preamble with the wrong token is an error and the flow is dropped without touching `inner`. A
/// destination deny answers `ECONNREFUSED` without touching `inner`; a name deny closes both sides and
/// sends `inner` nothing.
pub fn relay(
    guest: TcpStream,
    front: &InterceptEndpoint,
    inner: &InterceptEndpoint,
    decide: &Decide,
) -> std::io::Result<()> {
    relay_with_timeout(guest, front, inner, decide, HANDSHAKE_TIMEOUT)
}

fn relay_with_timeout(
    mut guest: TcpStream,
    front: &InterceptEndpoint,
    inner: &InterceptEndpoint,
    decide: &Decide,
    handshake: Duration,
) -> std::io::Result<()> {
    guest.set_read_timeout(Some(handshake))?;
    let dest = front.read_preamble(&mut guest)?;
    let flow = |(name, kind)| Flow {
        name,
        kind,
        ip: dest.ip(),
        port: dest.port(),
    };
    if decide(&flow((None, FlowKind::Other))) == Decision::Deny {
        return guest.write_all(&[REFUSED]);
    }
    let dial = if dest.ip() == GATEWAY {
        SocketAddr::new(Ipv4Addr::LOCALHOST.into(), dest.port())
    } else {
        dest
    };
    let mut upstream = TcpStream::connect(inner.addr)?;
    upstream.write_all(&inner.preamble(dial))?;
    upstream.set_read_timeout(Some(handshake))?;
    let mut verdict = [0u8; 1];
    upstream.read_exact(&mut verdict)?;
    guest.write_all(&verdict)?;
    if verdict[0] != VERDICT_CONNECTED {
        return Ok(());
    }

    let first = read_first_bytes(&mut guest, handshake)?;
    // Silent past the wait (the interceptor gives up on it too), or closed: nothing to decide.
    if first.is_empty() || decide(&flow(flow_id(&first))) == Decision::Deny {
        let _ = guest.shutdown(Shutdown::Both);
        let _ = upstream.shutdown(Shutdown::Both);
        return Ok(());
    }
    upstream.write_all(&first)?;

    guest.set_read_timeout(None)?;
    upstream.set_read_timeout(None)?;
    let (mut guest_rx, mut upstream_tx) = (guest.try_clone()?, upstream.try_clone()?);
    let up = std::thread::spawn(move || {
        let r = std::io::copy(&mut guest_rx, &mut upstream_tx);
        let _ = upstream_tx.shutdown(Shutdown::Write);
        r
    });
    let (mut upstream_rx, mut guest_tx) = (upstream, guest);
    let down = std::io::copy(&mut upstream_rx, &mut guest_tx);
    let _ = guest_tx.shutdown(Shutdown::Write);
    let up = up
        .join()
        .map_err(|_| std::io::Error::other("relay thread panicked"))?;
    down.and(up).map(|_| ())
}

/// Read what the guest sends first: wait up to `wait` for its first bytes (and while they may still
/// grow into an HTTP request line), then read until a whole ClientHello (or bytes that aren't one) or
/// the end of HTTP headers is in, nothing more arrives for `FIRST_BYTES_IDLE`, the guest closes, or
/// `MAX_CLIENT_HELLO` bytes. Empty when nothing came, or when an HTTP request line is still
/// unfinished then: with no name to decide by, the flow is closed.
fn read_first_bytes(guest: &mut TcpStream, wait: Duration) -> std::io::Result<Vec<u8>> {
    let deadline = Instant::now() + wait;
    guest.set_read_timeout(Some(wait))?;
    let mut first = Vec::new();
    let mut chunk = [0u8; 4096];
    while first.len() < MAX_CLIENT_HELLO {
        let want = chunk.len().min(MAX_CLIENT_HELLO - first.len());
        match guest.read(&mut chunk[..want]) {
            Ok(0) => break,
            Ok(n) => first.extend_from_slice(&chunk[..n]),
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => break,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
        // TLS-looking bytes end only on the ClientHello check, as its random bytes may hold a blank
        // line: plain HTTP waits for its headers' end, after any empty lines a server skips before
        // the request line.
        let head = head(&first);
        let done = if first[0] == 0x16 {
            peek_client_hello(&first) != Peek::Incomplete
        } else {
            head.windows(4).any(|w| w == b"\r\n\r\n") || head.windows(2).any(|w| w == b"\n\n")
        };
        if done {
            break;
        }
        // A request line still coming may pause as long as the first bytes may: cut short, it
        // would have no name.
        let idle = if request_line_pending(head) {
            // One deadline for the whole wait: a trickle can't restart it.
            match deadline.checked_duration_since(Instant::now()) {
                Some(left) if !left.is_zero() => left,
                _ => break,
            }
        } else {
            FIRST_BYTES_IDLE
        };
        guest.set_read_timeout(Some(idle))?;
    }
    // A request line that never finished has no name to decide it by: nothing goes on.
    if request_line_pending(head(&first)) {
        first.clear();
    }
    Ok(first)
}

/// `first` after any empty lines, which a server skips before an HTTP request line.
fn head(first: &[u8]) -> &[u8] {
    let start = first.iter().position(|b| !matches!(b, b'\r' | b'\n'));
    start.map_or(&[][..], |s| &first[s..])
}

/// Whether `head` may still grow into an HTTP/1 request line: a prefix of a method, or a method, a
/// space and more, with no `\n` yet.
fn request_line_pending(head: &[u8]) -> bool {
    const METHODS: [&[u8]; 9] = [
        b"GET", b"HEAD", b"POST", b"PUT", b"DELETE", b"CONNECT", b"OPTIONS", b"TRACE", b"PATCH",
    ];
    !head.contains(&b'\n')
        && METHODS.iter().any(|m| match head.strip_prefix(*m) {
            Some(rest) => rest.first().is_none_or(|&b| b == b' '),
            None => m.starts_with(head),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::name::client_hello;
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    fn allow() -> Decide {
        Arc::new(|_| Decision::Allow)
    }

    /// A `Decide` that denies when `deny` says so, and the flows it was asked about.
    fn recording(
        deny: impl Fn(&Flow) -> bool + Send + Sync + 'static,
    ) -> (Decide, Arc<Mutex<Vec<Flow>>>) {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = seen.clone();
        let decide: Decide = Arc::new(move |f: &Flow| {
            log.lock().unwrap().push(f.clone());
            if deny(f) {
                Decision::Deny
            } else {
                Decision::Allow
            }
        });
        (decide, seen)
    }

    fn names(seen: &Mutex<Vec<Flow>>) -> Vec<Option<String>> {
        seen.lock()
            .unwrap()
            .iter()
            .map(|f| f.name.clone())
            .collect()
    }

    fn endpoint(l: &TcpListener, b: u8) -> InterceptEndpoint {
        InterceptEndpoint {
            addr: l.local_addr().unwrap(),
            token: [b; 32],
        }
    }

    /// A connected (client, server-side) pair.
    fn pair() -> (TcpStream, TcpStream) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let c = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        (c, l.accept().unwrap().0)
    }

    #[test]
    fn relay_forwards_the_destination_and_verdict() {
        let seen = guest_sends(443, &[b"ping"], Duration::ZERO, b"pong");
        assert_eq!(seen[0].ip, Ipv4Addr::new(1, 2, 3, 4));
        assert_eq!(seen[0].port, 443);
    }

    #[test]
    fn relay_drops_a_flow_with_the_wrong_token() {
        let inner_l = TcpListener::bind("127.0.0.1:0").unwrap();
        inner_l.set_nonblocking(true).unwrap();
        let (front, inner) = (endpoint(&inner_l, 1), endpoint(&inner_l, 2));
        let wrong = InterceptEndpoint {
            token: [7; 32],
            ..front
        };
        let (mut client, server_side) = pair();
        client
            .write_all(&wrong.preamble("1.2.3.4:80".parse().unwrap()))
            .unwrap();
        let err = relay(server_side, &front, &inner, &allow()).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData, "{err}");
        assert!(inner_l.accept().is_err(), "inner must not be contacted");
    }

    #[test]
    fn relay_gives_up_on_a_guest_that_sends_nothing() {
        let inner_l = TcpListener::bind("127.0.0.1:0").unwrap();
        let (front, inner) = (endpoint(&inner_l, 1), endpoint(&inner_l, 2));
        let (_client, server_side) = pair();
        let start = std::time::Instant::now();
        let r = relay_with_timeout(
            server_side,
            &front,
            &inner,
            &allow(),
            Duration::from_millis(100),
        );
        assert!(r.is_err());
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn a_preamble_deny_refuses_without_touching_inner() {
        let inner_l = TcpListener::bind("127.0.0.1:0").unwrap();
        inner_l.set_nonblocking(true).unwrap();
        let (front, inner) = (endpoint(&inner_l, 1), endpoint(&inner_l, 2));
        let (decide, seen) = recording(|_| true);
        let dest: SocketAddr = "1.2.3.4:22".parse().unwrap();
        let (mut client, server_side) = pair();
        client.write_all(&front.preamble(dest)).unwrap();
        relay(server_side, &front, &inner, &decide).unwrap();
        let mut verdict = [0u8; 1];
        client.read_exact(&mut verdict).unwrap();
        assert_eq!(verdict[0], 111);
        assert!(inner_l.accept().is_err(), "inner must not be contacted");
        let want = Flow {
            name: None,
            kind: FlowKind::Other,
            ip: dest.ip(),
            port: 22,
        };
        assert_eq!(*seen.lock().unwrap(), vec![want]);
    }

    #[test]
    fn a_name_deny_forwards_nothing() {
        let inner_l = TcpListener::bind("127.0.0.1:0").unwrap();
        let (front, inner) = (endpoint(&inner_l, 1), endpoint(&inner_l, 2));
        let fake = std::thread::spawn(move || {
            let (mut s, _) = inner_l.accept().unwrap();
            inner.read_preamble(&mut s).unwrap();
            s.write_all(&[VERDICT_CONNECTED]).unwrap();
            let mut got = Vec::new();
            let _ = s.read_to_end(&mut got);
            assert!(got.is_empty(), "the interceptor saw {} bytes", got.len());
        });
        let (decide, seen) = recording(|f| f.name.as_deref() == Some("blocked.example"));
        let (mut client, server_side) = pair();
        let r = std::thread::spawn(move || relay(server_side, &front, &inner, &decide));
        client
            .write_all(&front.preamble("1.2.3.4:443".parse().unwrap()))
            .unwrap();
        let mut verdict = [9u8; 1];
        client.read_exact(&mut verdict).unwrap();
        assert_eq!(verdict[0], VERDICT_CONNECTED);
        client
            .write_all(&client_hello(Some("blocked.example")))
            .unwrap();
        let mut rest = Vec::new();
        let _ = client.read_to_end(&mut rest);
        assert!(rest.is_empty());
        r.join().unwrap().unwrap();
        fake.join().unwrap();
        assert_eq!(names(&seen), [None, Some("blocked.example".into())]);
    }

    #[test]
    fn a_split_client_hello_is_read_whole_and_forwarded() {
        let hello = client_hello(Some("api.example.com"));
        let parts: [&[u8]; 3] = [&hello[..3], &hello[3..20], &hello[20..]];
        let seen = guest_sends(443, &parts, Duration::from_millis(50), b"ok");
        assert_eq!(seen[1].name.as_deref(), Some("api.example.com"));
    }

    /// Relays one flow to 1.2.3.4:`port` whose guest sends `parts` (sleeping `pause` before each) to
    /// an interceptor that expects them and answers `reply`, and returns the flows `decide` saw.
    fn guest_sends(port: u16, parts: &[&[u8]], pause: Duration, reply: &'static [u8]) -> Vec<Flow> {
        let inner_l = TcpListener::bind("127.0.0.1:0").unwrap();
        let (front, inner) = (endpoint(&inner_l, 1), endpoint(&inner_l, 2));
        let want = parts.concat();
        let dest = SocketAddr::new(Ipv4Addr::new(1, 2, 3, 4).into(), port);
        let fake = std::thread::spawn(move || {
            let (mut s, _) = inner_l.accept().unwrap();
            assert_eq!(inner.read_preamble(&mut s).unwrap(), dest);
            s.write_all(&[VERDICT_CONNECTED]).unwrap();
            let mut got = vec![0u8; want.len()];
            s.read_exact(&mut got).unwrap();
            assert_eq!(got, want);
            s.write_all(reply).unwrap();
        });
        let (decide, seen) = recording(|_| false);
        let (mut client, server_side) = pair();
        client.set_nodelay(true).unwrap();
        let r = std::thread::spawn(move || relay(server_side, &front, &inner, &decide));
        client.write_all(&front.preamble(dest)).unwrap();
        let mut verdict = [9u8; 1];
        client.read_exact(&mut verdict).unwrap();
        assert_eq!(verdict[0], VERDICT_CONNECTED);
        for part in parts {
            std::thread::sleep(pause);
            client.write_all(part).unwrap();
        }
        let mut got = vec![0u8; reply.len()];
        client.read_exact(&mut got).unwrap();
        assert_eq!(got, reply);
        drop(client);
        fake.join().unwrap();
        r.join().unwrap().unwrap();
        seen.lock().unwrap().clone()
    }

    #[test]
    fn a_delayed_client_hello_is_decided_by_its_sni() {
        let hello = client_hello(Some("gist.github.com"));
        let seen = guest_sends(443, &[&hello], Duration::from_millis(250), b"ok");
        assert_eq!(seen[1].name.as_deref(), Some("gist.github.com"));
        assert_eq!(seen[1].kind, FlowKind::Tls);
    }

    #[test]
    fn an_ssh_client_is_decided_by_address() {
        let start = std::time::Instant::now();
        let seen = guest_sends(
            22,
            &[b"SSH-2.0-x\r\n"],
            Duration::ZERO,
            b"SSH-2.0-server\r\n",
        );
        let kinds: Vec<_> = seen.iter().map(|f| (f.name.clone(), f.kind)).collect();
        assert_eq!(kinds, [(None, FlowKind::Other), (None, FlowKind::Other)]);
        // Decided after the 200 ms idle, not held for the handshake timeout like an HTTP line.
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "{:?}",
            start.elapsed()
        );
    }

    #[test]
    fn request_line_pending_holds_only_for_a_method_prefix() {
        for head in [
            &b""[..],
            b"G",
            b"PA",
            b"GET",
            b"GET ",
            b"OPTIONS * HTTP/1.1",
        ] {
            assert!(request_line_pending(head), "{head:?}");
        }
        for head in [
            &b"S"[..],
            b"SSH-2.0-x",
            b"GETX",
            b"GET / HTTP/1.1\r\n",
            b"\x16\x03",
        ] {
            assert!(!request_line_pending(head), "{head:?}");
        }
    }

    #[test]
    fn a_paused_http_request_line_is_still_named() {
        let rest: &[u8] = b"ET / HTTP/1.1\r\nHost: gist.github.com\r\n\r\n";
        let seen = guest_sends(80, &[b"G", rest], Duration::from_millis(250), b"ok");
        assert_eq!(seen[1].name.as_deref(), Some("gist.github.com"));
        assert_eq!(seen[1].kind, FlowKind::Http);
    }

    #[test]
    fn a_client_hello_with_a_blank_line_split_over_two_writes_is_read_whole() {
        // The ClientHello's random field: a blank line there must not end a TLS read early.
        for blank in [&b"\n\n"[..], b"\r\n\r\n"] {
            let mut hello = client_hello(Some("api.example.com"));
            let end = 11 + blank.len();
            hello[11..end].copy_from_slice(blank);
            let parts: [&[u8]; 2] = [&hello[..end], &hello[end..]];
            let seen = guest_sends(443, &parts, Duration::from_millis(15), b"ok");
            assert_eq!(
                seen[1].name.as_deref(),
                Some("api.example.com"),
                "{blank:?}"
            );
        }
    }

    #[test]
    fn a_guest_trickling_a_request_line_is_cut_off_by_the_total_deadline() {
        let inner_l = TcpListener::bind("127.0.0.1:0").unwrap();
        let (front, inner) = (endpoint(&inner_l, 1), endpoint(&inner_l, 2));
        let fake = std::thread::spawn(move || {
            let (mut s, _) = inner_l.accept().unwrap();
            inner.read_preamble(&mut s).unwrap();
            s.write_all(&[VERDICT_CONNECTED]).unwrap();
            let mut got = Vec::new();
            let _ = s.read_to_end(&mut got);
            got
        });
        // Everything allowed: an unfinished request line must still not be decided or sent on.
        let (decide, seen) = recording(|_| false);
        let (mut client, server_side) = pair();
        client.set_nodelay(true).unwrap();
        let handshake = Duration::from_millis(400);
        let start = std::time::Instant::now();
        let r = std::thread::spawn(move || {
            let r = relay_with_timeout(server_side, &front, &inner, &decide, handshake);
            (r, start.elapsed())
        });
        client
            .write_all(&front.preamble("1.2.3.4:80".parse().unwrap()))
            .unwrap();
        client.read_exact(&mut [0u8; 1]).unwrap();
        client.write_all(b"GET ").unwrap();
        // A byte every 100 ms would keep a per-read timeout alive for the whole 3 s.
        while start.elapsed() < Duration::from_secs(3) {
            std::thread::sleep(Duration::from_millis(100));
            if client.write_all(b"a").is_err() {
                break;
            }
        }
        drop(client);
        let (res, took) = r.join().unwrap();
        let forwarded = fake.join().unwrap();
        assert!(res.is_ok());
        assert!(took < Duration::from_secs(1), "{took:?}");
        assert_eq!(
            seen.lock().unwrap().len(),
            1,
            "only the destination is decided"
        );
        assert!(
            forwarded.is_empty(),
            "{:?}",
            String::from_utf8_lossy(&forwarded)
        );
    }

    #[test]
    fn empty_lines_before_a_request_dont_end_the_read() {
        let req: &[u8] = b"GET / HTTP/1.1\r\nHost: gist.github.com\r\n\r\n";
        let seen = guest_sends(80, &[b"\r\n\r\n", req], Duration::from_millis(50), b"ok");
        assert_eq!(seen[1].name.as_deref(), Some("gist.github.com"));
        assert_eq!(seen[1].kind, FlowKind::Http);
    }

    #[test]
    fn a_silent_guest_is_closed_without_a_second_decide() {
        let inner_l = TcpListener::bind("127.0.0.1:0").unwrap();
        let (front, inner) = (endpoint(&inner_l, 1), endpoint(&inner_l, 2));
        let fake = std::thread::spawn(move || {
            let (mut s, _) = inner_l.accept().unwrap();
            inner.read_preamble(&mut s).unwrap();
            s.write_all(&[VERDICT_CONNECTED]).unwrap();
            let mut got = Vec::new();
            let _ = s.read_to_end(&mut got);
            assert!(got.is_empty(), "the interceptor saw {} bytes", got.len());
        });
        let (decide, seen) = recording(|_| false);
        let (mut client, server_side) = pair();
        let handshake = Duration::from_millis(300);
        let r = std::thread::spawn(move || {
            relay_with_timeout(server_side, &front, &inner, &decide, handshake)
        });
        client
            .write_all(&front.preamble("1.2.3.4:22".parse().unwrap()))
            .unwrap();
        let mut verdict = [9u8; 1];
        client.read_exact(&mut verdict).unwrap();
        assert_eq!(verdict[0], VERDICT_CONNECTED);
        // Bounded, so a relay that splices instead fails the test rather than hanging it.
        client
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut rest = Vec::new();
        let closed = client.read_to_end(&mut rest);
        drop(client);
        r.join().unwrap().unwrap();
        fake.join().unwrap();
        assert!(closed.is_ok() && rest.is_empty(), "{closed:?} {rest:?}");
        assert_eq!(names(&seen), [None]);
    }

    #[test]
    fn the_gateway_is_dialled_as_loopback() {
        let inner_l = TcpListener::bind("127.0.0.1:0").unwrap();
        let (front, inner) = (endpoint(&inner_l, 1), endpoint(&inner_l, 2));
        let fake = std::thread::spawn(move || {
            let (mut s, _) = inner_l.accept().unwrap();
            let dest = inner.read_preamble(&mut s).unwrap();
            s.write_all(&[111]).unwrap();
            dest
        });
        let (decide, seen) = recording(|_| false);
        let (mut client, server_side) = pair();
        client
            .write_all(&front.preamble("100.96.0.1:8080".parse().unwrap()))
            .unwrap();
        relay(server_side, &front, &inner, &decide).unwrap();
        let mut verdict = [9u8; 1];
        client.read_exact(&mut verdict).unwrap();
        assert_eq!(verdict[0], 111);
        let want: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        assert_eq!(fake.join().unwrap(), want);
        // The rules still see the address the guest dialled.
        assert_eq!(seen.lock().unwrap()[0].ip, GATEWAY);
    }
}
