//! End-to-end tests that boot real smolvm VMs. Ignored by default; run with `just e2e`.
//! Machines are small (1 CPU, 1 GiB) so they fit GitHub's private-repo runners.
//! The network policy, secrets, fork and install-phase tests need httpbin.org (not example.com:
//! some resolvers, smolvm's upstream among them, answer NXDOMAIN for it). The bridge tests need
//! the Alpine package mirror. The clone, fork and git-signing tests pull `alpine/git`. The kit
//! tests pull `alpine`, `registry:2`, sbx's
//! `shell` and `claude` agent kits, `sbx/shell` (the builder's image) and BuildKit images from
//! Docker Hub. Every other test runs the built-in agents from stand-in kits, booted with `-t`.
//! Published-kit fixtures go to a `registry:2` machine on a loopback port, pushed with
//! `oci-client`.

mod basics;
mod bridge_agent;
mod common;
mod env;
mod fork_template;
mod git_signing;
mod kits;
mod network;
mod skills;
mod ssh;

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use basics::*;
use common::*;
use network::*;
