//! The accept loop.

use std::net::TcpListener;
use std::sync::Arc;

use smolvm_credentials::{CredentialResolver, Interceptor, InterceptorConfig};
use smolvm_protocol::intercept::InterceptEndpoint;

use crate::relay::relay;

/// Spawn the interceptor, then accept smolvm's per-flow connections on `listener` forever, relaying
/// each on its own thread. Only returns on an interceptor start-up failure.
pub fn serve(
    listener: TcpListener,
    front_token: [u8; 32],
    config: InterceptorConfig,
    resolver: Arc<dyn CredentialResolver>,
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
                std::thread::spawn(move || {
                    // A bad or dropped flow is that flow's problem only.
                    let _ = relay(guest, &front, &inner);
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e.into()),
        }
    }
}
