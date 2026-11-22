//! Relaying one intercepted flow from smolvm to the interceptor.

use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpStream};
use std::time::Duration;

use smolvm_protocol::intercept::{InterceptEndpoint, VERDICT_CONNECTED};
use smolvm_protocol::sni::{MAX_CLIENT_HELLO, Peek, peek_client_hello};

use crate::name::flow_name;

/// A flow the relay asks about: the name its first bytes ask for, if any, and its destination.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Flow {
    pub name: Option<String>,
    pub ip: IpAddr,
    pub port: u16,
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
const GATEWAY: IpAddr = IpAddr::V4(Ipv4Addr::new(100, 96, 0, 1));

/// The verdict that refuses a flow: `ECONNREFUSED`, in `connect_verdict`'s errno convention.
const REFUSED: u8 = 111;

/// How long the first-bytes read waits for more after the last bytes arrived.
const FIRST_BYTES_IDLE: Duration = Duration::from_millis(200);

/// How long a flow may take to present its preamble, and the interceptor to answer with a verdict.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

/// Relay one flow: check smolvm's preamble against `front` and `decide` its destination, open a flow
/// to `inner` for it (the gateway dialled as loopback), pass the connect verdict back, read the guest's
/// first bytes and `decide` again with the name they ask for, then forward them and copy bytes both
/// ways until both sides close.
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
    relay_with_timeout(
        guest,
        front,
        inner,
        decide,
        HANDSHAKE_TIMEOUT,
        FIRST_BYTES_IDLE,
    )
}

fn relay_with_timeout(
    mut guest: TcpStream,
    front: &InterceptEndpoint,
    inner: &InterceptEndpoint,
    decide: &Decide,
    handshake: Duration,
    idle: Duration,
) -> std::io::Result<()> {
    guest.set_read_timeout(Some(handshake))?;
    let dest = front.read_preamble(&mut guest)?;
    let flow = |name| Flow {
        name,
        ip: dest.ip(),
        port: dest.port(),
    };
    if decide(&flow(None)) == Decision::Deny {
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

    let first = read_first_bytes(&mut guest, idle)?;
    if decide(&flow(flow_name(&first))) == Decision::Deny {
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

/// Read what the guest sends first: until a whole ClientHello (or bytes that aren't one) or the end of
/// HTTP headers is in, nothing more arrives for `idle`, the guest closes, or `MAX_CLIENT_HELLO` bytes.
fn read_first_bytes(guest: &mut TcpStream, idle: Duration) -> std::io::Result<Vec<u8>> {
    guest.set_read_timeout(Some(idle))?;
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
        // Only TLS-looking bytes end on the ClientHello check: plain HTTP waits for its headers.
        let tls_done = first[0] == 0x16 && peek_client_hello(&first) != Peek::Incomplete;
        if tls_done || first.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    Ok(first)
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
        let dest: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let inner_l = TcpListener::bind("127.0.0.1:0").unwrap();
        let (front, inner) = (endpoint(&inner_l, 1), endpoint(&inner_l, 2));
        let fake = std::thread::spawn(move || {
            let (mut s, _) = inner_l.accept().unwrap();
            assert_eq!(inner.read_preamble(&mut s).unwrap(), dest);
            s.write_all(&[VERDICT_CONNECTED]).unwrap();
            let mut buf = [0u8; 4];
            s.read_exact(&mut buf).unwrap();
            assert_eq!(&buf, b"ping");
            s.write_all(b"pong").unwrap();
        });

        let (mut client, server_side) = pair();
        let r = std::thread::spawn(move || relay(server_side, &front, &inner, &allow()));
        client.write_all(&front.preamble(dest)).unwrap();
        let mut verdict = [9u8; 1];
        client.read_exact(&mut verdict).unwrap();
        assert_eq!(verdict[0], VERDICT_CONNECTED);
        client.write_all(b"ping").unwrap();
        let mut buf = [0u8; 4];
        client.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"pong");
        drop(client);
        fake.join().unwrap();
        r.join().unwrap().unwrap();
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
            FIRST_BYTES_IDLE,
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
        let inner_l = TcpListener::bind("127.0.0.1:0").unwrap();
        let (front, inner) = (endpoint(&inner_l, 1), endpoint(&inner_l, 2));
        let want = hello.clone();
        let fake = std::thread::spawn(move || {
            let (mut s, _) = inner_l.accept().unwrap();
            inner.read_preamble(&mut s).unwrap();
            s.write_all(&[VERDICT_CONNECTED]).unwrap();
            let mut got = vec![0u8; want.len()];
            s.read_exact(&mut got).unwrap();
            assert_eq!(got, want);
            s.write_all(b"ok").unwrap();
        });
        let (decide, seen) = recording(|_| false);
        let (mut client, server_side) = pair();
        client.set_nodelay(true).unwrap();
        let r = std::thread::spawn(move || relay(server_side, &front, &inner, &decide));
        client
            .write_all(&front.preamble("1.2.3.4:443".parse().unwrap()))
            .unwrap();
        let mut verdict = [9u8; 1];
        client.read_exact(&mut verdict).unwrap();
        for part in [&hello[..3], &hello[3..20], &hello[20..]] {
            client.write_all(part).unwrap();
            std::thread::sleep(Duration::from_millis(50));
        }
        let mut ok = [0u8; 2];
        client.read_exact(&mut ok).unwrap();
        assert_eq!(&ok, b"ok");
        drop(client);
        fake.join().unwrap();
        r.join().unwrap().unwrap();
        assert_eq!(names(&seen), [None, Some("api.example.com".into())]);
    }

    #[test]
    fn a_silent_guest_is_decided_without_a_name_and_still_spliced() {
        let inner_l = TcpListener::bind("127.0.0.1:0").unwrap();
        let (front, inner) = (endpoint(&inner_l, 1), endpoint(&inner_l, 2));
        let fake = std::thread::spawn(move || {
            let (mut s, _) = inner_l.accept().unwrap();
            inner.read_preamble(&mut s).unwrap();
            s.write_all(&[VERDICT_CONNECTED]).unwrap();
            s.write_all(b"SSH-2.0-server\r\n").unwrap();
            let mut buf = [0u8; 16];
            s.read_exact(&mut buf).unwrap();
            assert_eq!(&buf, b"SSH-2.0-client\r\n");
        });
        let (decide, seen) = recording(|_| false);
        let (mut client, server_side) = pair();
        let r = std::thread::spawn(move || relay(server_side, &front, &inner, &decide));
        client
            .write_all(&front.preamble("1.2.3.4:22".parse().unwrap()))
            .unwrap();
        let mut verdict = [9u8; 1];
        client.read_exact(&mut verdict).unwrap();
        assert_eq!(verdict[0], VERDICT_CONNECTED);
        let mut banner = [0u8; 16];
        client.read_exact(&mut banner).unwrap();
        assert_eq!(&banner, b"SSH-2.0-server\r\n");
        client.write_all(b"SSH-2.0-client\r\n").unwrap();
        fake.join().unwrap();
        drop(client);
        r.join().unwrap().unwrap();
        assert_eq!(names(&seen), [None, None]);
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
