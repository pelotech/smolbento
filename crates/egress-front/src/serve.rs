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
