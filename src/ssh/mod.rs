//! SSH access to sandboxes: the `~/.ssh/config` block `setup ssh` manages, and the SSH server
//! (`ssh proxy`) that OpenSSH's `ProxyCommand` runs for each connection.

pub mod block;
pub mod server;
