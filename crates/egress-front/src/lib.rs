//! Hosted egress front for smolvm machines. Written to be lifted into smolvm: see the README.

pub use smolvm_credentials::{
    CredentialPolicy, CredentialRequest, CredentialResolver, InterceptorConfig, MachineCa,
    StaticResolver, generate_placeholders,
};
pub use smolvm_protocol::credentials::host_subtree;

mod ca;
mod listener;
mod name;
mod relay;
mod rules;
mod serve;

pub use ca::broad_ca;
pub use listener::activated_listener;
pub use relay::{Decide, Decision, Flow};
pub use rules::{
    Action, Case, HostMatch, Inspection, Methods, PathGlob, Policy, QueryMatch, Refusal,
    RequestMatch, Rule, ValueMatch,
};
pub use serve::serve;
