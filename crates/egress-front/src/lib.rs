//! Hosted egress front for smolvm machines. Written to be lifted into smolvm: see the README.

pub use http::HeaderMap;
pub use smolvm_credentials::{
    CredentialPolicy, CredentialRequest, CredentialResolver, InterceptorConfig, MachineCa,
    RequestFilter, RequestInfo, StaticResolver, generate_placeholders,
};
pub use smolvm_protocol::credentials::host_matches;

mod ca;
mod listener;
mod name;
mod relay;
mod rules;
mod serve;

pub use ca::broad_ca;
pub use listener::activated_listener;
pub use relay::{Decide, Decision, Flow, FlowKind};
pub use rules::{
    Action, Case, HostMatch, Inspection, Methods, PathGlob, Policy, QueryMatch, RequestMatch, Rule,
    ValueMatch,
};
pub use serve::serve;
