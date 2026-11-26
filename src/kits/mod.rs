//! sbx kits: a capability model plus parsers for the kit descriptor formats.

pub mod apply;
pub mod args;
pub mod artifact;
pub mod capability;
pub mod compose;
mod descriptor;
pub mod env_ref;
pub mod guest;
pub mod host_mount;
pub mod load;
pub mod model;
pub mod registry;
pub mod resolve;
pub mod smolfile;
pub mod trust;
pub mod v2;
pub mod v3;
pub mod warn;

/// The namespace of the kit spec's capability types (`com.docker.sandbox/<name>@<version>`).
pub const CAP_NS: &str = "com.docker.sandbox/";

/// The agent user's home in the platform floor; the host can't see the guest's real env.
pub const AGENT_HOME: &str = "/home/agent";

/// Commit of docker/sandbox-kit-spec the parsers and test fixtures were written against.
pub const SPEC_COMMIT: &str = "7c8b7cd53acc7271184b5c66ab0acb9613df56c7";
