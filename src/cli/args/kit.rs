//! `kit`: inspect, add, validate, sign and verify kits.

use std::path::PathBuf;

use clap::{Args, Subcommand};

use super::OutputArgs;

#[derive(Debug, Subcommand)]
pub enum KitCmd {
    /// Show what a kit provides and requests
    Inspect {
        /// Kit: a registry reference or a local path (./dir, descriptor or Smolfile)
        reference: String,
        #[command(flatten)]
        args: KitArgOpts,
        #[command(flatten)]
        output: OutputArgs,
        /// Skip the source policy check; local kits only, no network
        #[arg(long)]
        offline: bool,
    },
    /// Check a kit without running it
    Validate {
        /// Kit: a registry reference or a local path (./dir, descriptor or Smolfile)
        reference: String,
        #[command(flatten)]
        args: KitArgOpts,
        #[command(flatten)]
        output: OutputArgs,
        /// Skip the source policy check; local kits only, no network
        #[arg(long)]
        offline: bool,
    },
    /// Add a mixin kit to an existing sandbox
    Add {
        /// Sandbox name
        sandbox: String,
        /// Mixin kit: a registry reference or a local path (./dir or descriptor)
        reference: String,
        #[command(flatten)]
        args: KitArgOpts,
        /// Grant the kit's network access without asking
        #[arg(long, short = 'y')]
        yes: bool,
    },
    /// Package a directory as a kit artifact
    Pack {
        /// Kit directory: spec.yaml and an optional files/
        directory: String,
        /// Output file path; must end in .zip (default: <name>.zip)
        #[arg(short, long)]
        output: Option<String>,
    },
    /// Push a kit artifact to an OCI registry
    Push {
        /// Kit directory: spec.yaml and an optional files/
        directory: String,
        /// Where to push it: registry/repo:tag
        reference: String,
        /// Sign the pushed kit and attach the signature as an OCI referrer
        #[arg(long)]
        sign: bool,
        #[command(flatten)]
        signing: SignOpts,
    },
    /// Pull a kit artifact from an OCI registry
    Pull {
        /// Kit: registry/repo:tag or registry/repo@sha256:digest
        reference: String,
        /// Output file path (default: derived from the reference)
        #[arg(short, long)]
        output: Option<String>,
    },
    /// Sign a kit artifact
    Sign {
        /// Kit: registry/repo:tag or registry/repo@sha256:digest
        reference: String,
        #[command(flatten)]
        signing: SignOpts,
    },
    /// Verify a kit artifact's signature
    Verify {
        /// Kit: registry/repo:tag or registry/repo@sha256:digest
        reference: String,
        /// Public key for key-based verification (PEM)
        #[arg(long, conflicts_with_all = ["certificate_identity", "certificate_identity_regexp",
              "certificate_oidc_issuer", "certificate_oidc_issuer_regexp"])]
        key: Option<PathBuf>,
        /// Exact keyless signer identity (certificate SAN)
        #[arg(long, conflicts_with = "certificate_identity_regexp")]
        certificate_identity: Option<String>,
        /// Keyless signer identity regexp (certificate SAN)
        #[arg(long)]
        certificate_identity_regexp: Option<String>,
        /// Exact keyless OIDC issuer
        #[arg(long, conflicts_with = "certificate_oidc_issuer_regexp")]
        certificate_oidc_issuer: Option<String>,
        /// Keyless OIDC issuer regexp
        #[arg(long)]
        certificate_oidc_issuer_regexp: Option<String>,
        /// Do not require a Rekor transparency-log entry (for private keyless signatures)
        #[arg(long)]
        insecure_ignore_tlog: bool,
        #[command(flatten)]
        output: OutputArgs,
    },
}

/// How `kit sign` and `kit push --sign` sign.
#[derive(Debug, Clone, Default, Args)]
pub struct SignOpts {
    /// Private key for key-based signing (PEM); omit for keyless signing
    #[arg(long, conflicts_with_all = ["identity_token", "identity_token_file"])]
    pub key: Option<PathBuf>,
    /// OIDC identity token for keyless signing; defaults to the ambient CI provider, then an
    /// interactive browser login
    #[arg(long, conflicts_with = "identity_token_file")]
    pub identity_token: Option<String>,
    /// File holding the OIDC identity token; keeps it out of the process arguments
    #[arg(long)]
    pub identity_token_file: Option<PathBuf>,
    /// Upload the keyless signature to the Rekor transparency log; set false for private kits
    #[arg(long, default_value_t = true, num_args = 0..=1, default_missing_value = "true",
          require_equals = true, action = clap::ArgAction::Set)]
    pub tlog_upload: bool,
}

/// Kit argument flags, as on `run` and `create`.
#[derive(Debug, Clone, Default, Args)]
pub struct KitArgOpts {
    /// Kit argument: NAME=VALUE, or KIT.NAME=VALUE for one kit (repeatable)
    #[arg(long = "kit-arg", value_name = "NAME=VALUE")]
    pub kit_arg: Vec<String>,
    /// Read kit arguments (NAME=VALUE lines) from a file (repeatable)
    #[arg(long = "kit-args-file", value_name = "FILE")]
    pub kit_args_file: Vec<PathBuf>,
}
