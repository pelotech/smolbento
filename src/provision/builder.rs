//! The `_builder` sandbox: builds local v3 kit directories with BuildKit's `docker/sandbox-kit:3`
//! frontend in its own private dockerd, so the host needs no Docker.

use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use anyhow::{Context, Result, bail};

use crate::ctx::Ctx;
use crate::kits::args::ArgValues;
use crate::kits::load::{self, starts_with_syntax};
use crate::kits::model::{Content, Kind, Kit, Source};
use crate::kits::registry_auth;
use crate::kits::resolve::{Plan, resolve};
use crate::provision;
use crate::sandbox::{self, CreateRequest, Recorded, Sandbox, options};
use crate::secrets::{RegistryEntry, SecretsFile, registry_secret};
use crate::smolvm::{Credential, ExecSpec, MachineState, Runner, SmolvmError};
use crate::util;

pub const BUILDER: &str = "_builder";

/// The kit builder's image: sbx's `shell` agent kit, which has Docker with buildx (214 MB, a
/// quarter of sbx's shell-docker-image), booted as a plain image. Pinned by digest; Renovate
/// bumps it.
#[rustfmt::skip] // one line, so Renovate can match it
pub const BUILDER_IMAGE: &str = "docker.io/sbx/shell:latest@sha256:89ed5d63def6bfb2373d408e3ab6ad55aa5c010f884a182a78299fcf85ea42d1";

const MEMORY_MIB: u64 = 4096;

/// How much of a failed build's output the error shows.
const TAIL_LINES: usize = 20;
/// Phrases registries and buildx use for a missing login (matched lowercased).
const AUTH_PHRASES: [&str; 5] = [
    "unauthorized:",
    "authentication required",
    "denied: requested access",
    "pull access denied",
    "401 unauthorized",
];
/// What may precede a bare HTTP 401 status; a bare "401" elsewhere is often a size, a count or a
/// digest (`: 401 bytes`).
const STATUS_PREFIXES: [&str; 2] = ["status: ", "status code "];

/// Whether a lowercased line of buildx output reports a registry login failure.
fn is_auth_failure(lower: &str) -> bool {
    if AUTH_PHRASES.iter().any(|p| lower.contains(p)) {
        return true;
    }
    lower.match_indices("401").any(|(i, _)| {
        let (before, after) = (&lower[..i], &lower[i + 3..]);
        !after.starts_with(|c: char| c.is_ascii_alphanumeric())
            && STATUS_PREFIXES.iter().any(|p| before.ends_with(p))
    })
}

/// Numbers this process's builds, so concurrent builds get their own `/build/<n>`.
static BUILDS: AtomicU32 = AtomicU32::new(0);

/// Mints a pull token: (host, entry, password, repos). `registry_auth::pull_token`, or a fake.
type Minter = fn(&str, &RegistryEntry, &str, &[String]) -> Result<String>;

/// Builds the v3 kit directory `dir` and returns the OCI layout it produced, unpacked into the
/// cache (`<cache>/built/<sha256 of the tar>`).
#[tracing::instrument(name = "kit_build", skip_all, fields(dir = %dir.display()))]
pub fn build<R: Runner>(ctx: &Ctx<R>, dir: &Path) -> Result<PathBuf> {
    build_with(ctx, dir, registry_auth::pull_token)
}

fn build_with<R: Runner>(ctx: &Ctx<R>, dir: &Path, mint: Minter) -> Result<PathBuf> {
    let desc = load::descriptor(dir)?;
    let text = fs::read(dir.join(&desc))
        .with_context(|| format!("reading {}", dir.join(&desc).display()))?;
    let text = String::from_utf8_lossy(&text);
    // Host-wide logins only: the builder is shared by every sandbox.
    let mut registries = SecretsFile::load(&ctx.paths)?.host_registries();
    // smolvm's `--credential` can't carry a port in HOST, and the builder's Docker Hub pulls
    // (the `docker/sandbox-kit` frontend) go to a host no descriptor names.
    registries.retain(|r| !r.host.contains(':') && !registry_auth::is_docker_hub(&r.host));
    registries.sort_by(|a, b| a.host.cmp(&b.host));
    let hosts: Vec<String> = registries.iter().map(|r| r.host.clone()).collect();
    // Bound to the builder but given no token by this build (see `pull_tokens`).
    let unbound: Vec<String> = hosts
        .iter()
        .filter(|h| repos_in(&text, h).is_empty())
        .cloned()
        .collect();
    let cache = ctx.paths.kit_cache();
    fs::create_dir_all(&cache).with_context(|| format!("creating {}", cache.display()))?;
    // In the cache, so the unpacked layout can be renamed into place.
    let tmp = tempfile::Builder::new()
        .prefix(".build-")
        .tempdir_in(&cache)
        .with_context(|| format!("creating a temp dir in {}", cache.display()))?;
    let kit_tar = tmp.path().join("kit.tar");

    // Every setup on the smolvm home shares the builder: another build could delete, recreate or
    // stop it under this one.
    let _builder = crate::config::lock(&ctx.smolvm.home.join(BUILDER))?;
    let found = match sandbox::find(&ctx.vm, BUILDER)? {
        // Its registry bindings are fixed at create: a changed set of logins needs a new one.
        Some(sb) if sb.meta.rec.registries != hosts => {
            ctx.vm
                .delete(&sb.machine)
                .context("removing the kit builder sandbox to bind the stored registry logins")?;
            None
        }
        found => found,
    };
    let (mut sb, was_running) = match found {
        Some(sb) => {
            let running = sb.is_running();
            (sb, running)
        }
        None => (
            docker_plan()
                .and_then(|kits| {
                    provision::create(ctx, &mut request(ctx, &hosts), &[], Some(&kits))
                })
                .context("creating the kit builder sandbox")?,
            false,
        ),
    };
    let result = pull_tokens(ctx, &registries, &text, mint)
        .and_then(|tokens| start(ctx, &mut sb, tokens).context("starting the kit builder sandbox"))
        // A builder that was already up may have lost dockerd since; a start just ran it.
        .and_then(|()| {
            if was_running {
                sandbox::start_engine(&ctx.vm, &sb.machine, "root")
            } else {
                Ok(())
            }
        })
        .and_then(|()| run_build(ctx, &sb.machine, dir, &desc, &kit_tar, &unbound));
    if !was_running
        && sb.is_running()
        && let Err(e) = ctx.vm.stop(&sb.machine)
    {
        crate::warning!("stopping the {BUILDER} sandbox: {e:#}");
    }
    result?;
    unpack(&kit_tar, &cache.join("built"), tmp.path())
}

/// The builder's binding for its `i`th stored registry (sorted by host): smolvm sets the
/// `Authorization` header on requests to HOST to the value of `SBX_REGISTRY_<i>_AUTH`, which a
/// build passes at start as `Bearer <token>`. The guest only sees a placeholder.
pub(crate) fn registry_credential(i: usize, host: &str) -> Credential {
    Credential {
        env_var: registry_env(i),
        hosts: vec![host.to_string()],
        set_header: Some("authorization".into()),
    }
}

fn registry_env(i: usize) -> String {
    format!("SBX_REGISTRY_{i}_AUTH")
}

/// `SBX_REGISTRY_<i>_AUTH=Bearer <token>` for each stored registry the descriptor `text` pulls
/// from, minted now: tokens last minutes and smolvm reads credential values at start only.
/// A stored host the descriptor doesn't name keeps its variable unset; smolvm then answers the
/// builder's requests to it with `502 credential unavailable`, not an anonymous request (see
/// `build_error`).
fn pull_tokens<R: Runner>(
    ctx: &Ctx<R>,
    registries: &[RegistryEntry],
    text: &str,
    mint: Minter,
) -> Result<Vec<(String, String)>> {
    let mut env = Vec::new();
    for (i, entry) in registries.iter().enumerate() {
        let host = &entry.host;
        let repos = repos_in(text, host);
        if repos.is_empty() {
            continue;
        }
        let Some(password) = registry_secret(ctx.store.as_ref(), host)? else {
            bail!(
                "registry secret {host} has no value in {}; set it again with \
                 `bento secret set --registry {host} --password-stdin`",
                ctx.store.describe()
            );
        };
        let token = mint(host, entry, &password, &repos)
            .with_context(|| format!("getting a pull token for {host}"))?;
        env.push((registry_env(i), format!("Bearer {token}")));
    }
    Ok(env)
}

/// The repositories of HOST's image references (`HOST/<repo>[:tag][@digest]`) in `text`,
/// sorted.
fn repos_in(text: &str, host: &str) -> Vec<String> {
    let prefix = format!("{}/", host.to_ascii_lowercase());
    let mut repos: Vec<String> = text
        .to_ascii_lowercase()
        .split(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '=' | ',' | '[' | ']'))
        .filter_map(|word| {
            let word = word.split_once("://").map_or(word, |(_, rest)| rest);
            let rest = word.strip_prefix(&prefix)?;
            let rest = rest.split_once('@').map_or(rest, |(r, _)| r);
            let repo = rest.split_once(':').map_or(rest, |(r, _)| r);
            let valid = repo
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'/'));
            (!repo.is_empty() && valid).then(|| repo.to_string())
        })
        .collect();
    repos.sort();
    repos.dedup();
    repos
}

/// Starts the builder; with `tokens`, fresh (stopping it first), since smolvm reads credential
/// values at start only. The tokens go in `machine start`'s environment only.
fn start<R: Runner>(ctx: &Ctx<R>, sb: &mut Sandbox, tokens: Vec<(String, String)>) -> Result<()> {
    if tokens.is_empty() {
        return provision::ensure_running(ctx, sb);
    }
    if sb.is_running() {
        ctx.vm.stop(&sb.machine)?;
        sb.state = MachineState::Stopped;
    }
    let meta = sb.meta.clone();
    sandbox::ensure_running(&ctx.vm, sb, || {
        let mut plan = provision::start_plan(ctx, &meta)?;
        plan.remove.retain(|v| !tokens.iter().any(|(k, _)| k == v));
        plan.env.extend(tokens);
        Ok(plan)
    })
}

/// The builder's kits: the `shell` agent's image as a plain image, and the shipped docker kit,
/// whose `dockerd@1` has smolbento start the engine on every start of the builder (no startup
/// hook). It runs as root, like every internal sandbox.
fn docker_plan() -> Result<Plan> {
    let workload = Kit {
        content: Content::Image(BUILDER_IMAGE.into()),
        command: Some(vec!["bash".into(), "-l".into()]),
        ..Kit::new("builder", Kind::Workload, Source::Builtin("builder"))
    };
    let docker = load::builtin("docker").expect("the docker kit is shipped")?;
    resolve(workload, vec![docker], &ArgValues::default())
}

/// The builder sandbox: mountless, with a private dockerd, under the global network policy.
fn request<R: Runner>(ctx: &Ctx<R>, registries: &[String]) -> CreateRequest {
    CreateRequest {
        rec: Recorded {
            registries: registries.to_vec(),
            ..Default::default()
        },
        name: BUILDER.into(),
        agent: "shell".into(),
        image: BUILDER_IMAGE.into(),
        cpus: options::host_cpus(),
        memory_mib: MEMORY_MIB,
        created: ctx.now,
        ..Default::default()
    }
}

/// `cmd` in `machine` as root.
fn root(machine: &str, cmd: &[&str]) -> ExecSpec {
    ExecSpec::new(machine, "root", cmd.iter().map(|s| s.to_string()).collect())
}

/// Selects the kit frontend for a descriptor without the syntax line.
const FRONTEND: &str = "BUILDKIT_SYNTAX=docker/sandbox-kit:3";

/// Copies the context in, builds it, copies the OCI tar out, and always removes `/build/<n>`.
fn run_build<R: Runner>(
    ctx: &Ctx<R>,
    machine: &str,
    dir: &Path,
    desc: &str,
    kit_tar: &Path,
    unbound: &[String],
) -> Result<()> {
    let n = format!(
        "/build/{}-{}",
        std::process::id(),
        BUILDS.fetch_add(1, Ordering::Relaxed)
    );
    // A descriptor's syntax line picks the kit frontend. One that sbx takes without it (by its
    // `schemaVersion`) has the build name the frontend instead.
    let frontend_named = fs::read(dir.join(desc)).is_ok_and(|b| starts_with_syntax(&b));
    let exec = |cmd: &[&str]| ctx.vm.exec_captured(&root(machine, cmd));
    let (ctx_dir, guest_kit_tar) = (format!("{n}/ctx"), format!("{n}/kit.tar"));
    let result = (|| {
        exec(&["mkdir", "-p", &n]).context("preparing the build in the builder")?;
        // Like a Docker build context: links stay links instead of pulling in what they point at.
        ctx.vm
            .upload_folder(machine, dir, &ctx_dir)
            .context("copying the kit into the builder")?;
        let (file, output) = (
            format!("{ctx_dir}/{desc}"),
            format!("type=oci,dest={guest_kit_tar}"),
        );
        let mut build = vec!["docker", "buildx", "build"];
        if !frontend_named {
            build.extend(["--build-arg", FRONTEND]);
        }
        build.extend(["-f", &file, "--output", &output, &ctx_dir]);
        exec(&build).map_err(|e| build_error(dir, &e, unbound))?;
        ctx.vm
            .download(machine, &guest_kit_tar, kit_tar)
            .context("copying the built kit out of the builder")
    })();
    if let Err(e) = exec(&["rm", "-rf", &n]) {
        crate::warning!("removing {n} in the {BUILDER} sandbox: {e:#}");
    }
    result
}

/// A failed `docker buildx build`: a stored login it got no token for (`unbound`), a registry
/// login it needed, or the end of its output.
fn build_error(dir: &Path, e: &anyhow::Error, unbound: &[String]) -> anyhow::Error {
    let output = SmolvmError::message_of(e);
    if !unbound.is_empty() && output.contains("credential unavailable") {
        let hosts = unbound.join(", ");
        let (host, refs) = match unbound {
            [h] => (h.as_str(), format!("`{h}/<repo>`")),
            _ => ("HOST", "`HOST/<repo>`".to_string()),
        };
        return anyhow::anyhow!(
            "building {} failed: the build reached {hosts}, which you stored a registry login for, \
             without a token: smolbento gets one only for images the kit's descriptor names as \
             {refs}. Name the image that way in the kit, or remove the login with \
             `bento secret rm --registry {host}`",
            dir.display()
        );
    }
    if output.lines().any(|l| is_auth_failure(&l.to_lowercase())) {
        let host = registry_host(&output);
        let from = host
            .as_ref()
            .map(|h| format!(" from {h}"))
            .unwrap_or_default();
        let host = host.as_deref().unwrap_or("HOST");
        return anyhow::anyhow!(
            "building {} failed: the build pulls{from}, which needs a registry login; store \
             one with `bento secret set --registry {host} --password-stdin`",
            dir.display()
        );
    }
    let tail = crate::sandbox::last_lines(&output, TAIL_LINES);
    anyhow::anyhow!("building {} failed:\n{tail}", dir.display())
}

/// The registry of the first image reference or URL on an auth error line.
fn registry_host(output: &str) -> Option<String> {
    let auth_line = |l: &&str| is_auth_failure(&l.to_lowercase());
    output
        .lines()
        .filter(auth_line)
        .flat_map(str::split_whitespace)
        .find_map(|word| {
            let word = word.split_once("://").map_or(word, |(_, rest)| rest);
            let (host, _) = word.split_once('/')?;
            let host = host.trim_end_matches([':', ',']);
            let hostlike = host.contains('.') || host.contains(':') || host == "localhost";
            let valid = host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':'));
            (hostlike && valid).then(|| host.to_string())
        })
}

/// Unpacks the OCI layout tar into `<built>/<sha256 of the tar>`, unless that exists already.
fn unpack(kit_tar: &Path, built: &Path, tmp: &Path) -> Result<PathBuf> {
    let dest = built.join(
        util::sha256_file(kit_tar).with_context(|| format!("opening {}", kit_tar.display()))?,
    );
    if dest.is_dir() {
        return Ok(dest);
    }
    fs::create_dir_all(built).with_context(|| format!("creating {}", built.display()))?;
    let staging = tmp.join("layout");
    fs::create_dir(&staging)?;
    let mut archive = tar::Archive::new(File::open(kit_tar)?);
    for entry in archive.entries().context("reading the built kit")? {
        let mut entry = entry.context("reading the built kit")?;
        let kind = entry.header().entry_type();
        // An OCI layout is files and directories; anything else isn't buildx's output.
        if !(kind.is_file() || kind.is_dir()) {
            bail!(
                "the built kit has an unexpected {kind:?} entry {}",
                entry.path()?.display()
            );
        }
        // `unpack_in` would skip these silently; buildx never writes them, so the tar is suspect.
        let path = entry.path()?.into_owned();
        if path.is_absolute()
            || path
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            bail!(
                "the built kit has an entry outside its layout: {}",
                path.display()
            );
        }
        entry
            .unpack_in(&staging)
            .context("unpacking the built kit")?;
    }
    if let Err(e) = fs::rename(&staging, &dest)
        && !dest.is_dir()
    {
        return Err(e).with_context(|| format!("moving the built kit to {}", dest.display()));
    }
    Ok(dest)
}

#[cfg(test)]
#[path = "builder_tests.rs"]
mod tests;
