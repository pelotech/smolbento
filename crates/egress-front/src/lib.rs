//! Hosted egress front for smolvm machines. Written to be lifted into smolvm: see the README.

pub use smolvm_credentials::{
    CredentialPolicy, CredentialRequest, CredentialResolver, InterceptorConfig, MachineCa,
    StaticResolver, generate_placeholders,
};
pub use smolvm_protocol::credentials::host_subtree;

mod listener;
mod name;
mod relay;
mod serve;

pub use listener::activated_listener;
pub use name::flow_name;
pub use relay::{Decide, Decision, Flow};
pub use serve::serve;
