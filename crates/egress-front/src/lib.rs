//! Hosted egress front for smolvm machines. Written to be lifted into smolvm: see the README.

pub use smolvm_credentials::{
    CredentialBinding, CredentialPolicy, CredentialResolver, Interceptor, InterceptorConfig,
    MachineCa, StaticResolver, generate_placeholders,
};
pub use smolvm_protocol::intercept::InterceptEndpoint;
