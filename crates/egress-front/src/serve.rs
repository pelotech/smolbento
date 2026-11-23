//! The accept loop.

use std::net::TcpListener;
use std::sync::Arc;
use std::time::Duration;

use smolvm_credentials::{CredentialResolver, Interceptor, InterceptorConfig};
use smolvm_protocol::intercept::InterceptEndpoint;

use crate::relay::{Decide, relay};

/// Spawn the interceptor, then accept smolvm's per-flow connections on `listener` forever, relaying
/// each on its own thread and letting through only the flows `decide` allows. Accept and relay errors
/// are logged to stderr and ridden out; only an interceptor start-up failure returns.
pub fn serve(
    listener: TcpListener,
    front_token: [u8; 32],
    config: InterceptorConfig,
    resolver: Arc<dyn CredentialResolver>,
    decide: Decide,
) -> anyhow::Result<()> {
    let interceptor = Interceptor::spawn(config, resolver)?;
    let inner = interceptor.endpoint();
    let front = InterceptEndpoint {
        addr: listener.local_addr()?,
        token: front_token,
    };
    loop {
        match listener.accept() {
            Ok((guest, _)) => {
                let decide = decide.clone();
                // `thread::spawn` panics when the OS refuses a thread; that must drop one flow, not
                // the process. The closure, and with it the guest's socket, is dropped on error.
                let spawned = std::thread::Builder::new().spawn(move || {
                    // A bad or dropped flow is that flow's problem only; the log says why.
                    if let Err(e) = relay(guest, &front, &inner, &decide) {
                        eprintln!("egress: a flow was dropped: {e}");
                    }
                });
                if let Err(e) = spawned {
                    eprintln!("egress: a flow was dropped: no thread for it: {e}");
                }
            }
            // A reset before accept, or running out of fds, must not end the service for every flow.
            Err(e) => {
                eprintln!("egress: accept failed: {e}");
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay::Decision;
    use crate::{Action, Case, HostMatch, Methods, PathGlob, Policy, RequestMatch, Rule, broad_ca};
    use smolvm_credentials::{CredentialPolicy, RequestFilter, RequestInfo, StaticResolver};
    use smolvm_protocol::intercept::VERDICT_CONNECTED;
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpStream};

    const HOST: &str = "ruled.test";

    struct Rules(Policy);

    impl RequestFilter for Rules {
        fn check(&self, r: &RequestInfo<'_>) -> Result<(), String> {
            (self
                .0
                .request(r.host, r.port, r.method, r.target, r.headers))
            .map_err(|r| r.reason)
        }
    }

    fn provider() -> Arc<rustls::crypto::CryptoProvider> {
        Arc::new(rustls::crypto::ring::default_provider())
    }

    /// A TLS server for `HOST` that answers every request `200 upstream ok`, and its certificate.
    fn upstream() -> (SocketAddr, String) {
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec![HOST.into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let config = rustls::ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.der().clone()],
                rustls::pki_types::PrivateKeyDer::Pkcs8(key.serialize_der().into()),
            )
            .unwrap();
        let config = Arc::new(config);
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        std::thread::spawn(move || {
            for s in l.incoming() {
                let conn = rustls::ServerConnection::new(config.clone()).unwrap();
                std::thread::spawn(move || {
                    let mut tls = rustls::StreamOwned::new(conn, s.unwrap());
                    let (mut head, mut b) = (Vec::new(), [0u8; 1]);
                    while !head.ends_with(b"\r\n\r\n") {
                        if tls.read(&mut b).unwrap_or(0) == 0 {
                            return;
                        }
                        head.push(b[0]);
                    }
                    let _ = tls.write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\nupstream ok",
                    );
                    tls.conn.send_close_notify();
                    let _ = tls.flush();
                });
            }
        });
        (addr, cert.pem())
    }

    /// Sends `line` to `HOST` at `dest` through the front at `front`, trusting only `ca_pem`.
    fn request(front: &InterceptEndpoint, dest: SocketAddr, ca_pem: &str, line: &str) -> String {
        let mut tcp = TcpStream::connect(front.addr).unwrap();
        tcp.write_all(&front.preamble(dest)).unwrap();
        let mut verdict = [0xffu8; 1];
        tcp.read_exact(&mut verdict).unwrap();
        assert_eq!(verdict[0], VERDICT_CONNECTED);
        let mut roots = rustls::RootCertStore::empty();
        for cert in rustls_pemfile::certs(&mut ca_pem.as_bytes()) {
            roots.add(cert.unwrap()).unwrap();
        }
        let config = rustls::ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let conn =
            rustls::ClientConnection::new(Arc::new(config), HOST.try_into().unwrap()).unwrap();
        let mut tls = rustls::StreamOwned::new(conn, tcp);
        write!(
            tls,
            "{line}\r\nHost: {HOST}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )
        .unwrap();
        let mut out = Vec::new();
        let _ = tls.read_to_end(&mut out);
        String::from_utf8_lossy(&out).into_owned()
    }

    #[test]
    fn a_ruled_host_is_decrypted_and_its_requests_filtered() {
        let (dest, upstream_pem) = upstream();
        let policy = Policy {
            rules: vec![Rule {
                id: Some("r1".into()),
                action: Action::Deny,
                hosts: vec![HostMatch::Exact(HOST.into())],
                port: None,
                request: RequestMatch {
                    methods: Methods::Only(vec!["POST".into()]),
                    paths: vec![PathGlob::parse("/**").unwrap()],
                    query: vec![],
                },
                reason: None,
                case: Case::Insensitive,
            }],
            default: Action::Allow,
        };
        let ca = broad_ca("m").unwrap();
        let ca_pem = ca.certificate_pem().to_string();
        let config = InterceptorConfig {
            machine: "m".into(),
            policy: CredentialPolicy::default(),
            placeholders: Default::default(),
            ca,
            extra_cas: vec![],
            upstream_roots_pem: vec![upstream_pem.into_bytes()],
            terminate_hosts: policy.terminate_hosts(),
            request_filter: Some(Arc::new(Rules(policy))),
        };
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let front = InterceptEndpoint {
            addr: listener.local_addr().unwrap(),
            token: [3; 32],
        };
        let decide: Decide = Arc::new(|_| Decision::Allow);
        std::thread::spawn(move || {
            serve(
                listener,
                [3; 32],
                config,
                Arc::new(StaticResolver::new()),
                decide,
            )
        });

        let refused = request(&front, dest, &ca_pem, "POST /x HTTP/1.1");
        assert!(refused.starts_with("HTTP/1.1 403"), "{refused}");
        assert!(
            refused.ends_with("request denied by policy (rule r1)"),
            "{refused}"
        );
        let passed = request(&front, dest, &ca_pem, "GET /x HTTP/1.1");
        assert!(passed.starts_with("HTTP/1.1 200"), "{passed}");
        assert!(passed.contains("upstream ok"), "{passed}");
    }
}
