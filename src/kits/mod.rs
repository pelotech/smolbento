//! sbx kits: a capability model plus parsers for the kit descriptor formats.

pub mod apply;
pub mod args;
pub mod builder;
pub mod capability;
pub mod compose;
pub mod guest;
pub mod load;
pub mod model;
pub mod registry;
pub mod resolve;
pub mod smolfile;
pub mod trust;
pub mod v2;
pub mod v3;

/// Commit of docker/sandbox-kit-spec the parsers and test fixtures were written against.
pub const SPEC_COMMIT: &str = "198d50b5fd57b216b511fd7200010a3636cb3f01";
