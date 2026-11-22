//! Relaying one intercepted flow from smolvm to the interceptor.

use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream};
use std::time::Duration;

use smolvm_protocol::intercept::{InterceptEndpoint, VERDICT_CONNECTED};

/// How long a flow may take to present its preamble, and the interceptor to answer with a verdict.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

/// Relay one flow: check smolvm's preamble against `front`, open a flow to `inner` for the same
/// destination, pass the connect verdict back, then copy bytes both ways until both sides close.
///
/// A preamble with the wrong token is an error and the flow is dropped without touching `inner`.
pub fn relay(
    guest: TcpStream,
    front: &InterceptEndpoint,
    inner: &InterceptEndpoint,
) -> std::io::Result<()> {
    relay_with_timeout(guest, front, inner, HANDSHAKE_TIMEOUT)
}

fn relay_with_timeout(
    mut guest: TcpStream,
    front: &InterceptEndpoint,
    inner: &InterceptEndpoint,
    handshake: Duration,
) -> std::io::Result<()> {
    guest.set_read_timeout(Some(handshake))?;
    let dest = front.read_preamble(&mut guest)?;
    let mut upstream = TcpStream::connect(inner.addr)?;
    upstream.write_all(&inner.preamble(dest))?;
    upstream.set_read_timeout(Some(handshake))?;
    let mut verdict = [0u8; 1];
    upstream.read_exact(&mut verdict)?;
    guest.write_all(&verdict)?;
    if verdict[0] != VERDICT_CONNECTED {
        return Ok(());
    }

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{SocketAddr, TcpListener};

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
        let r = std::thread::spawn(move || relay(server_side, &front, &inner));
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
        let err = relay(server_side, &front, &inner).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData, "{err}");
        assert!(inner_l.accept().is_err(), "inner must not be contacted");
    }

    #[test]
    fn relay_gives_up_on_a_guest_that_sends_nothing() {
        let inner_l = TcpListener::bind("127.0.0.1:0").unwrap();
        let (front, inner) = (endpoint(&inner_l, 1), endpoint(&inner_l, 2));
        let (_client, server_side) = pair();
        let start = std::time::Instant::now();
        let r = relay_with_timeout(server_side, &front, &inner, Duration::from_millis(100));
        assert!(r.is_err());
        assert!(start.elapsed() < Duration::from_secs(5));
    }
}
