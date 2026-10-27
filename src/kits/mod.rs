//! sbx kits: a capability model plus parsers for the kit descriptor formats.

pub mod model;
pub mod v3;

/// Commit of docker/sandbox-kit-spec the parsers and test fixtures were written against.
pub const SPEC_COMMIT: &str = "198d50b5fd57b216b511fd7200010a3636cb3f01";
