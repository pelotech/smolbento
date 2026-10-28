//! The `_builder` sandbox: builds local v3 kit directories with BuildKit's `docker/sandbox-kit:3`
//! frontend in its own private dockerd, so the host needs no Docker.

use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};

use crate::agents;
use crate::cli::{Ctx, plan};
use crate::kits::args::ArgValues;
use crate::kits::load;
use crate::kits::registry_auth;
use crate::kits::resolve::{Plan, resolve};
use crate::sandbox::{self, CreateRequest, Sandbox, options};
use crate::secrets::{RegistryEntry, SecretsFile, registry_secret};
use crate::smolvm::{Credential, ExecSpec, MachineState, Runner, Smolvm, SmolvmError};

use super::registry::hex;

pub const BUILDER: &str = "_builder";
/// Renovate bumps this (see renovate.json5).
pub const BUILDER_IMAGE: &str = "docker/sandbox-templates:shell-docker-0.10.0";

const MEMORY_MIB: u64 = 4096;
pub(crate) const SYNTAX: &str = "# syntax=docker/sandbox-kit:3";
/// `docker info` tries, a second apart, before dockerd counts as not starting.
const DOCKER_WAIT: u32 = 30;
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
pub fn build<R: Runner>(ctx: &Ctx<R>, dir: &Path) -> Result<PathBuf> {
    build_with(ctx, dir, registry_auth::pull_token)
}

fn build_with<R: Runner>(ctx: &Ctx<R>, dir: &Path, mint: Minter) -> Result<PathBuf> {
    let desc = descriptor(dir)?;
    let text = fs::read(dir.join(&desc))
        .with_context(|| format!("reading {}", dir.join(&desc).display()))?;
    let text = String::from_utf8_lossy(&text);
    let mut registries = SecretsFile::load(&ctx.paths)?.registries;
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
    let (ctx_tar, kit_tar) = (tmp.path().join("ctx.tar"), tmp.path().join("kit.tar"));
    pack(dir, &ctx_tar)?;

    let found = match sandbox::find(&ctx.vm, BUILDER)? {
        // Its registry bindings are fixed at create: a changed set of logins needs a new one.
        Some(sb) if sb.meta.registries != hosts => {
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
                .and_then(|kits| plan::create(ctx, &mut request(ctx, &hosts), &[], Some(&kits)))
                .context("creating the kit builder sandbox")?,
            false,
        ),
    };
    let result = pull_tokens(ctx, &registries, &text, mint)
        .and_then(|tokens| start(ctx, &mut sb, tokens).context("starting the kit builder sandbox"))
        .and_then(|()| wait_for_docker(&ctx.vm, &sb.machine, DOCKER_WAIT, Duration::from_secs(1)))
        .and_then(|()| run_build(ctx, &sb.machine, dir, &desc, &ctx_tar, &kit_tar, &unbound));
    if !was_running
        && sb.is_running()
        && let Err(e) = ctx.vm.stop(&sb.machine)
    {
        eprintln!("warning: stopping the {BUILDER} sandbox: {e:#}");
    }
    result?;
    unpack(&kit_tar, &cache.join("built"), tmp.path())
}

/// The builder's binding for its `i`th stored registry (sorted by host): smolvm sets the
/// `Authorization` header on requests to HOST to the value of `SBX_REGISTRY_<i>_AUTH`, which a
/// build passes at start as `Bearer <token>`. The guest only sees a placeholder.
pub(crate) fn registry_credential(i: usize, host: &str) -> Credential {
    Credential {
        name: format!("reg-{i}"),
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
                 `sbt secret set --registry {host} --password-stdin`",
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
        return plan::ensure_running(ctx, sb);
    }
    if sb.is_running() {
        ctx.vm.stop(&sb.machine)?;
        sb.state = MachineState::Stopped;
    }
    let meta = sb.meta.clone();
    sandbox::ensure_running(&ctx.vm, sb, || {
        let mut plan = plan::start_plan(ctx, &meta)?;
        plan.remove.retain(|v| !tokens.iter().any(|(k, _)| k == v));
        plan.env.extend(tokens);
        Ok(plan)
    })
}

/// The builder's kits: the shell preset with the shipped docker kit, whose startup hook starts
/// dockerd on every start of the builder.
fn docker_plan() -> Result<Plan> {
    let shell = agents::find("shell").expect("the shell preset");
    let docker = load::builtin("docker").expect("the docker kit is shipped")?;
    resolve(
        load::preset_kit(shell, BUILDER_IMAGE),
        vec![docker],
        &ArgValues::default(),
    )
}

/// The builder sandbox: mountless, with a private dockerd, under the global network policy.
fn request<R: Runner>(ctx: &Ctx<R>, registries: &[String]) -> CreateRequest {
    CreateRequest {
        name: BUILDER.into(),
        agent: "shell".into(),
        image: BUILDER_IMAGE.into(),
        cpus: options::host_cpus(),
        memory_mib: MEMORY_MIB,
        docker: true,
        created: ctx.now,
        registries: registries.to_vec(),
        ..Default::default()
    }
}

/// The kit's descriptor file name: the single `*.yaml`/`*.yml` whose first line is the v3 syntax
/// line (upstream names it after the kit, e.g. `claude-mixin.yaml`).
/// Whether a file's first line is the v3 syntax line, after an optional UTF-8 BOM.
pub(crate) fn starts_with_syntax(bytes: &[u8]) -> bool {
    let bytes = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes);
    let first = bytes.split(|b| *b == b'\n').next().unwrap_or_default();
    String::from_utf8_lossy(first).trim_end() == SYNTAX
}

fn descriptor(dir: &Path) -> Result<String> {
    let mut found = Vec::new();
    for entry in fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let path = entry?.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !(name.ends_with(".yaml") || name.ends_with(".yml")) || !path.is_file() {
            continue;
        }
        let bytes = fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
        if starts_with_syntax(&bytes) {
            found.push(name.to_string());
        }
    }
    found.sort();
    match found.len() {
        1 => Ok(found.remove(0)),
        0 => bail!(
            "{} has no kit descriptor: no *.yaml file starts with `{SYNTAX}`",
            dir.display()
        ),
        _ => bail!(
            "{} has several kit descriptors ({}); keep one *.yaml starting with `{SYNTAX}`",
            dir.display(),
            found.join(", ")
        ),
    }
}

/// Tars the kit directory: smolvm's `machine cp` copies files, not directories.
fn pack(dir: &Path, out: &Path) -> Result<()> {
    let mut b = tar::Builder::new(File::create(out)?);
    // Like a Docker build context: links stay links instead of pulling in what they point at.
    b.follow_symlinks(false);
    b.append_dir_all(".", dir)
        .and_then(|()| b.finish())
        .with_context(|| format!("packing {}", dir.display()))
}

/// Waits for the builder's dockerd, which the docker kit's startup hook only launches.
fn wait_for_docker<R: Runner>(
    vm: &Smolvm<R>,
    machine: &str,
    attempts: u32,
    interval: Duration,
) -> Result<()> {
    for i in 0..attempts {
        if i > 0 {
            std::thread::sleep(interval);
        }
        if vm
            .exec_captured(&root(machine, &["docker", "info"]))
            .is_ok()
        {
            return Ok(());
        }
    }
    bail!(
        "dockerd in the {BUILDER} sandbox didn't answer within {}s; see /var/log/dockerd.log in it",
        (interval * attempts).as_secs()
    )
}

fn root(machine: &str, cmd: &[&str]) -> ExecSpec {
    ExecSpec {
        name: machine.into(),
        user: Some("root".into()),
        cmd: cmd.iter().map(|s| s.to_string()).collect(),
        ..Default::default()
    }
}

/// Copies the context in, builds it, copies the OCI tar out, and always removes `/build/<n>`.
fn run_build<R: Runner>(
    ctx: &Ctx<R>,
    machine: &str,
    dir: &Path,
    desc: &str,
    ctx_tar: &Path,
    kit_tar: &Path,
    unbound: &[String],
) -> Result<()> {
    let n = format!(
        "/build/{}-{}",
        std::process::id(),
        BUILDS.fetch_add(1, Ordering::Relaxed)
    );
    let host = |p: &Path| -> Result<String> {
        let s = p.display().to_string();
        // smolvm reads `a:b` as MACHINE:PATH.
        if s.contains(':') {
            bail!("the kit cache path {s} contains ':', which smolvm cp can't copy from");
        }
        Ok(s)
    };
    let exec = |cmd: &[&str]| ctx.vm.exec_captured(&root(machine, cmd));
    let (ctx_dir, guest_ctx_tar, guest_kit_tar) = (
        format!("{n}/ctx"),
        format!("{n}/ctx.tar"),
        format!("{n}/kit.tar"),
    );
    let result = (|| {
        exec(&["mkdir", "-p", &ctx_dir]).context("preparing the build in the builder")?;
        ctx.vm
            .cp(&host(ctx_tar)?, &format!("{machine}:{guest_ctx_tar}"))
            .context("copying the kit into the builder")?;
        exec(&["tar", "-xf", &guest_ctx_tar, "-C", &ctx_dir])
            .context("unpacking the kit in the builder")?;
        exec(&[
            "docker",
            "buildx",
            "build",
            "-f",
            &format!("{ctx_dir}/{desc}"),
            "--output",
            &format!("type=oci,dest={guest_kit_tar}"),
            &ctx_dir,
        ])
        .map_err(|e| build_error(dir, &e, unbound))?;
        ctx.vm
            .cp(&format!("{machine}:{guest_kit_tar}"), &host(kit_tar)?)
            .context("copying the built kit out of the builder")
    })();
    if let Err(e) = exec(&["rm", "-rf", &n]) {
        eprintln!("warning: removing {n} in the {BUILDER} sandbox: {e:#}");
    }
    result
}

/// A failed `docker buildx build`: a stored login it got no token for (`unbound`), a registry
/// login it needed, or the end of its output.
fn build_error(dir: &Path, e: &anyhow::Error, unbound: &[String]) -> anyhow::Error {
    let output = match e.downcast_ref::<SmolvmError>() {
        Some(s) => s.message.clone(),
        None => format!("{e:#}"),
    };
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
             `sbt secret rm --registry {host}`",
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
             one with `sbt secret set --registry {host} --password-stdin`",
            dir.display()
        );
    }
    let lines: Vec<&str> = output.lines().collect();
    let tail = lines[lines.len().saturating_sub(TAIL_LINES)..].join("\n");
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
    let dest = built.join(sha256_file(kit_tar)?);
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

fn sha256_file(path: &Path) -> Result<String> {
    let mut f = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex(&hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;
    use crate::cli::testutil::*;
    use crate::kits::model::Source;
    use crate::kits::registry::{self, fixtures::oci_layout};

    const MIXIN: &str = "# syntax=docker/sandbox-kit:3\nschemaVersion: \"3\"\nkind: mixin\n";

    /// A kit directory with the descriptor `claude-mixin.yaml` and an unrelated yaml file.
    fn kit_dir() -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        fs::write(d.path().join("claude-mixin.yaml"), MIXIN).unwrap();
        fs::write(d.path().join("other.yaml"), "a: 1\n").unwrap();
        fs::create_dir(d.path().join("files")).unwrap();
        fs::write(d.path().join("files/hello.txt"), "hi\n").unwrap();
        d
    }

    /// The tar of an OCI layout holding a kit, as `docker buildx --output type=oci` writes it.
    /// The same bytes on every call: tests compare digests of separately made tars.
    fn kit_tar() -> Vec<u8> {
        let d = tempfile::tempdir().unwrap();
        oci_layout(
            d.path(),
            Some(r#"{"schemaVersion":"3","kind":"mixin","name":"m"}"#),
            &[],
            "{}",
        );
        let mut b = tar::Builder::new(Vec::new());
        // Without this the headers carry the files' mtimes, and a second boundary between two
        // calls changes the digest.
        b.mode(tar::HeaderMode::Deterministic);
        b.append_dir_all(".", d.path()).unwrap();
        b.into_inner().unwrap()
    }

    fn builder_json(state: &str) -> String {
        machine_json(
            "sbx-_builder",
            state,
            &[
                ("sbx.name", "_builder"),
                ("sbx.docker", "true"),
                ("sbx.kits", r#"["builtin:docker"]"#),
            ],
        )
    }

    /// The `/build/<n>` the build used, from its `mkdir`.
    fn build_dir(lines: &[String]) -> String {
        let mkdir = lines
            .iter()
            .find(|l| l.contains("-- mkdir -p /build/"))
            .expect("mkdir");
        let ctx = mkdir.rsplit(' ').next().unwrap();
        ctx.strip_suffix("/ctx").unwrap().to_string()
    }

    #[test]
    fn first_build_creates_starts_builds_copies_back_and_stops() {
        let t = test_env(&[]);
        let fake = t.ctx.vm.runner();
        // `once` replies win over the `ok` until used up: find, plan::create's check, then get.
        fake.ok(&["machine", "status"], &builder_json("created"))
            .once_fail(&["machine", "status"], "NOT_FOUND", "vm not found")
            .once_fail(&["machine", "status"], "NOT_FOUND", "vm not found")
            .download(&kit_tar());
        let kit = kit_dir();
        let out = build(&t.ctx, kit.path()).unwrap();

        let tar = kit_tar();
        let digest = registry::sha256_digest(&tar);
        assert_eq!(
            out,
            t.ctx
                .paths
                .kit_cache()
                .join("built")
                .join(registry::hex_of(&digest).unwrap())
        );
        let k = registry::read_layout(&out, Source::LocalV3(kit.path().into())).unwrap();
        assert_eq!(k.kind, crate::kits::model::Kind::Mixin);

        let lines = fake.call_lines();
        let create = lines
            .iter()
            .position(|l| l.starts_with("machine create -n sbx-_builder"))
            .expect("create");
        let c = &lines[create];
        assert!(c.contains(&format!("--image {BUILDER_IMAGE}")), "{c}");
        assert!(c.contains("--label sbx.name=_builder"), "{c}");
        assert!(c.contains("--label sbx.docker=true"), "{c}");
        // dockerd comes from the shipped docker kit, not the pre-4a `setup` fallback.
        assert!(c.contains(r#"--label sbx.kits=["builtin:docker"]"#), "{c}");
        assert!(
            c.contains("-v /var/lib/docker -v /var/lib/containerd"),
            "{c}"
        );
        assert!(c.contains("--mem 4096"), "{c}");
        assert!(c.contains("--net-backend virtio-net"), "{c}");
        assert!(!c.contains(" -w "), "mountless: {c}");

        let n = build_dir(&lines);
        let rest = lines[create..].to_vec();
        let i = |needle: &str| {
            rest.iter()
                .position(|l| l.contains(needle))
                .unwrap_or_else(|| panic!("{needle} in {rest:#?}"))
        };
        let order = [
            i("machine start -n sbx-_builder"),
            i("usermod -o -u 501 agent"),
            i("sbx-_builder:/etc/smolbento/startup.d/01-docker.sh"),
            i(&format!("-u root -- sh -c {}", sandbox::startup_cmd(None))),
            i("-u root -- docker info"),
            i(&format!("-u root -- mkdir -p {n}/ctx")),
            i(&format!("sbx-_builder:{n}/ctx.tar")),
            i(&format!("-u root -- tar -xf {n}/ctx.tar -C {n}/ctx")),
            i(&format!(
                "-u root -- docker buildx build -f {n}/ctx/claude-mixin.yaml \
                 --output type=oci,dest={n}/kit.tar {n}/ctx"
            )),
            i(&format!("machine cp sbx-_builder:{n}/kit.tar ")),
            i(&format!("-u root -- rm -rf {n}")),
            i("machine stop -n sbx-_builder"),
        ];
        assert!(order.is_sorted(), "{order:?} in {rest:#?}");
        assert!(
            !rest.iter().any(|l| l.contains("pgrep -x dockerd")),
            "dockerd is started once, by the startup runner: {rest:#?}"
        );
        assert!(
            rest.contains(&"machine start -n sbx-_builder".to_string()),
            "not branchable: {rest:#?}"
        );
        assert_eq!(rest.last().unwrap(), "machine stop -n sbx-_builder");
        // The upload is a file: smolvm's cp copies files only.
        let up = &rest[i(&format!("sbx-_builder:{n}/ctx.tar"))];
        assert!(up.starts_with("machine cp /"), "{up}");
        assert!(up.split(' ').nth(2).unwrap().ends_with(".tar"), "{up}");
    }

    #[test]
    fn host_temp_files_are_removed() {
        let t = test_env(&[]);
        let fake = t.ctx.vm.runner();
        fake.ok(&["machine", "status"], &builder_json("running"))
            .download(&kit_tar());
        let kit = kit_dir();
        build(&t.ctx, kit.path()).unwrap();
        let lines = fake.call_lines();
        let up = lines
            .iter()
            .find(|l| l.starts_with("machine cp /"))
            .unwrap();
        let host = up.split(' ').nth(2).unwrap();
        assert!(!Path::new(host).exists(), "temp files are removed: {host}");
    }

    #[test]
    fn a_running_builder_stays_running() {
        let t = test_env(&[]);
        let fake = t.ctx.vm.runner();
        fake.ok(&["machine", "status"], &builder_json("running"))
            .download(&kit_tar());
        let kit = kit_dir();
        build(&t.ctx, kit.path()).unwrap();
        let lines = fake.call_lines();
        assert!(!lines.iter().any(|l| l.starts_with("machine create")));
        assert!(!lines.iter().any(|l| l.starts_with("machine start")));
        assert!(!lines.iter().any(|l| l.starts_with("machine stop")));
        assert!(
            lines.last().unwrap().contains("-- rm -rf /build/"),
            "{lines:#?}"
        );
    }

    #[test]
    fn a_stopped_builder_is_started_and_stopped_again() {
        let t = test_env(&[]);
        let fake = t.ctx.vm.runner();
        fake.ok(&["machine", "status"], &builder_json("stopped"))
            .download(&kit_tar());
        let kit = kit_dir();
        build(&t.ctx, kit.path()).unwrap();
        let lines = fake.call_lines();
        assert!(!lines.iter().any(|l| l.starts_with("machine create")));
        assert!(lines.iter().any(|l| l == "machine start -n sbx-_builder"));
        assert_eq!(lines.last().unwrap(), "machine stop -n sbx-_builder");
    }

    #[test]
    fn a_second_build_of_the_same_output_reuses_the_cache() {
        let t = test_env(&[]);
        let fake = t.ctx.vm.runner();
        fake.ok(&["machine", "status"], &builder_json("running"))
            .download(&kit_tar());
        let kit = kit_dir();
        let first = build(&t.ctx, kit.path()).unwrap();
        fs::write(first.join("marker"), "").unwrap();
        let second = build(&t.ctx, kit.path()).unwrap();
        assert_eq!(first, second);
        assert!(second.join("marker").exists(), "not unpacked again");
    }

    fn failing_build(stderr: &str) -> (TestEnv, String) {
        let t = test_env(&[]);
        let err = failing_build_in(&t, &builder_json("stopped"), stderr);
        (t, err)
    }

    /// A build of `kit_dir()` in the builder `status` describes whose buildx fails with `stderr`.
    fn failing_build_in(t: &TestEnv, status: &str, stderr: &str) -> String {
        let fake = t.ctx.vm.runner();
        fake.ok(&["machine", "status"], status).on(
            &[
                "machine",
                "exec",
                "--name",
                "sbx-_builder",
                "-u",
                "root",
                "--",
                "docker",
                "buildx",
            ],
            crate::smolvm::Output {
                code: 1,
                stdout: String::new(),
                stderr: stderr.into(),
            },
        );
        let kit = kit_dir();
        format!("{:#}", build_with(&t.ctx, kit.path(), no_mint).unwrap_err())
    }

    #[test]
    fn an_unbound_registry_login_names_the_host_and_the_fix() {
        let t = test_env(&[]);
        with_dhi_login(&t);
        let err = failing_build_in(
            &t,
            &dhi_builder_json("stopped"),
            "#3 ERROR: failed to resolve source metadata for dhi.io/debian-base:trixie: \
             unexpected status from GET request to https://dhi.io/token: 502 Bad Gateway: \
             smolvm credentials: credential unavailable\n",
        );
        assert!(
            err.contains(
                "the build reached dhi.io, which you stored a registry login for, without a token"
            ),
            "{err}"
        );
        assert!(err.contains("`dhi.io/<repo>`"), "{err}");
        assert!(err.contains("`sbt secret rm --registry dhi.io`"), "{err}");
        assert!(!err.contains("tok-"), "{err}");
    }

    #[test]
    fn a_failed_build_reports_the_last_20_lines_and_cleans_up() {
        let log: String = (1..=30).map(|i| format!("#{i} step {i}\n")).collect();
        let (t, err) = failing_build(&log);
        assert!(err.contains("building "), "{err}");
        assert!(
            err.contains("#11 step 11") && err.contains("#30 step 30"),
            "{err}"
        );
        assert!(!err.contains("#10 step 10"), "{err}");
        let lines = t.ctx.vm.runner().call_lines();
        let n = build_dir(&lines);
        assert!(lines.iter().any(|l| l.ends_with(&format!("-- rm -rf {n}"))));
        assert_eq!(lines.last().unwrap(), "machine stop -n sbx-_builder");
        assert!(!t.ctx.paths.kit_cache().join("built").exists());
    }

    #[test]
    fn an_auth_failure_points_at_secret_set_registry() {
        let (_t, err) = failing_build(
            "#3 ERROR: failed to resolve source metadata for ghcr.io/acme/base:1: \
             unexpected status from HEAD request to https://ghcr.io/v2/acme/base/manifests/1: \
             401 Unauthorized\n",
        );
        assert!(
            err.contains(
                "failed: the build pulls from ghcr.io, which needs a registry login; store \
                 one with `sbt secret set --registry ghcr.io --password-stdin`"
            ),
            "{err}"
        );
        let (_t, err) = failing_build("ERROR: authentication required\n");
        assert!(
            err.contains(
                "failed: the build pulls, which needs a registry login; store \
                 one with `sbt secret set --registry HOST --password-stdin`"
            ),
            "{err}"
        );
    }

    #[test]
    fn the_descriptor_is_the_one_yaml_with_the_v3_syntax_line() {
        let kit = kit_dir();
        assert_eq!(descriptor(kit.path()).unwrap(), "claude-mixin.yaml");

        let none = tempfile::tempdir().unwrap();
        fs::write(none.path().join("kit.yaml"), "kind: mixin\n").unwrap();
        let err = descriptor(none.path()).unwrap_err().to_string();
        assert!(err.contains(&none.path().display().to_string()), "{err}");
        assert!(err.contains("# syntax=docker/sandbox-kit:3"), "{err}");

        fs::write(kit.path().join("second.yml"), MIXIN).unwrap();
        let err = descriptor(kit.path()).unwrap_err().to_string();
        assert!(err.contains(&kit.path().display().to_string()), "{err}");
        assert!(
            err.contains("claude-mixin.yaml") && err.contains("second.yml"),
            "{err}"
        );
    }

    #[test]
    fn dockerd_that_never_answers_times_out_pointing_at_its_log() {
        let t = test_env(&[]);
        t.ctx.vm.runner().fail(
            &[
                "machine",
                "exec",
                "--name",
                "sbx-_builder",
                "-u",
                "root",
                "--",
                "docker",
                "info",
            ],
            "UNKNOWN",
            "Cannot connect to the Docker daemon",
        );
        let err = wait_for_docker(&t.ctx.vm, "sbx-_builder", 3, Duration::ZERO)
            .unwrap_err()
            .to_string();
        assert!(err.contains("/var/log/dockerd.log"), "{err}");
        assert_eq!(t.ctx.vm.runner().calls().len(), 3);
    }

    #[test]
    fn dockerd_is_waited_for() {
        let t = test_env(&[]);
        let fake = t.ctx.vm.runner();
        fake.once_fail(&["machine", "exec"], "UNKNOWN", "not yet");
        wait_for_docker(&t.ctx.vm, "sbx-_builder", 3, Duration::ZERO).unwrap();
        assert_eq!(fake.calls().len(), 2);
    }

    #[test]
    fn pack_tars_the_kit_dir_keeping_links_as_links() {
        let kit = kit_dir();
        std::os::unix::fs::symlink("/etc/passwd", kit.path().join("link")).unwrap();
        let out = tempfile::tempdir().unwrap();
        let tar_path = out.path().join("ctx.tar");
        pack(kit.path(), &tar_path).unwrap();
        let mut a = tar::Archive::new(File::open(&tar_path).unwrap());
        let mut names = Vec::new();
        for e in a.entries().unwrap() {
            let e = e.unwrap();
            let name = e.path().unwrap().display().to_string();
            if name.ends_with("link") {
                assert!(e.header().entry_type().is_symlink(), "{name}");
            }
            names.push(name);
        }
        for want in ["claude-mixin.yaml", "files/hello.txt", "link"] {
            assert!(
                names.iter().any(|n| n.ends_with(want)),
                "{want} in {names:?}"
            );
        }
    }

    #[test]
    fn unpack_refuses_links_in_the_built_kit() {
        let d = tempfile::tempdir().unwrap();
        let mut b = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Symlink);
        h.set_size(0);
        b.append_link(&mut h, "index.json", "/etc/passwd").unwrap();
        let kit_tar = d.path().join("kit.tar");
        fs::write(&kit_tar, b.into_inner().unwrap()).unwrap();
        let built = d.path().join("built");
        let err = unpack(&kit_tar, &built, d.path()).unwrap_err().to_string();
        assert!(err.contains("Symlink"), "{err}");
        assert!(fs::read_dir(&built).unwrap().next().is_none());
    }

    #[test]
    fn registry_host_takes_the_first_reference_on_an_auth_line() {
        assert_eq!(
            registry_host(
                "#1 resolve docker-image://docker.io/library/alpine:3\n\
                 ERROR: pull access denied: denied: requested access to the resource is denied: \
                 docker-image://registry.example.com:5000/acme/base:1"
            ),
            Some("registry.example.com:5000".into())
        );
        assert_eq!(registry_host("401 Unauthorized at /build/1/ctx"), None);
    }

    #[test]
    fn the_builder_gets_no_secrets() {
        use crate::secrets::{SecretEntry, SecretsFile, Source as SecretSource, scope_for};
        let t = test_env(&[]);
        let entry = SecretEntry {
            service: "github".into(),
            scope: scope_for(None),
            source: SecretSource::Keychain,
        };
        t.ctx.store.set(&entry.account(), "gh-123").unwrap();
        let mut f = SecretsFile::default();
        f.set(entry);
        f.save(&t.ctx.paths).unwrap();
        let fake = t.ctx.vm.runner();
        fake.ok(&["machine", "status"], &builder_json("created"))
            .once_fail(&["machine", "status"], "NOT_FOUND", "vm not found")
            .once_fail(&["machine", "status"], "NOT_FOUND", "vm not found")
            .download(&kit_tar());
        let kit = kit_dir();
        build(&t.ctx, kit.path()).unwrap();
        let lines = fake.call_lines();
        let create = lines
            .iter()
            .find(|l| l.starts_with("machine create -n sbx-_builder"))
            .unwrap();
        assert!(!create.contains("--credential"), "{create}");
        assert!(!create.contains("sbx.secrets"), "{create}");
        assert_eq!(fake.envs(), vec![Vec::<(String, String)>::new()]);
        assert!(
            fake.removed().iter().all(|r| r.is_empty()),
            "{:?}",
            fake.removed()
        );
    }

    /// A stored `dhi.io` login (password `pw`) under the balanced policy, so allow hosts show.
    fn with_dhi_login(t: &TestEnv) {
        use crate::secrets::{RegistryEntry, SecretsFile, registry_account};
        fs::write(t.ctx.paths.policy_file(), "mode = \"balanced\"\n").unwrap();
        t.ctx.store.set(&registry_account("dhi.io"), "pw").unwrap();
        let mut f = SecretsFile::default();
        f.registries.push(RegistryEntry {
            host: "dhi.io".into(),
            username: Some("josmo".into()),
            auth_endpoint: None,
        });
        f.save(&t.ctx.paths).unwrap();
    }

    /// A kit dir whose build starts `FROM dhi.io/debian-base:trixie`.
    fn dhi_kit_dir() -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        fs::write(
            d.path().join("dhi.yaml"),
            format!("{MIXIN}build: |\n  FROM dhi.io/debian-base:trixie AS b\n  FROM scratch\n"),
        )
        .unwrap();
        d
    }

    fn fake_mint(host: &str, entry: &RegistryEntry, pw: &str, repos: &[String]) -> Result<String> {
        assert_eq!((host, entry.host.as_str(), pw), ("dhi.io", "dhi.io", "pw"));
        assert_eq!(repos, ["debian-base"]);
        Ok("tok-123".into())
    }

    fn no_mint(_: &str, _: &RegistryEntry, _: &str, _: &[String]) -> Result<String> {
        panic!("no token is needed")
    }

    fn dhi_builder_json(state: &str) -> String {
        machine_json(
            "sbx-_builder",
            state,
            &[
                ("sbx.name", "_builder"),
                ("sbx.docker", "true"),
                ("sbx.kits", r#"["builtin:docker"]"#),
                ("sbx.registries", "dhi.io"),
                ("sbx.credential-hosts", "dhi.io"),
                ("sbx.credential-env", "SBX_REGISTRY_0_AUTH"),
            ],
        )
    }

    #[test]
    fn the_builder_binds_stored_registry_logins_and_starts_with_a_fresh_token() {
        let t = test_env(&[]);
        with_dhi_login(&t);
        let fake = t.ctx.vm.runner();
        fake.ok(&["machine", "status"], &dhi_builder_json("created"))
            .once_fail(&["machine", "status"], "NOT_FOUND", "vm not found")
            .once_fail(&["machine", "status"], "NOT_FOUND", "vm not found")
            .download(&kit_tar());
        let kit = dhi_kit_dir();
        build_with(&t.ctx, kit.path(), fake_mint).unwrap();

        let lines = fake.call_lines();
        let create = lines
            .iter()
            .find(|l| l.starts_with("machine create -n sbx-_builder"))
            .unwrap();
        assert!(
            create
                .contains("--credential reg-0=SBX_REGISTRY_0_AUTH@dhi.io:set-header=authorization"),
            "{create}"
        );
        assert!(create.contains("--allow-host dhi.io"), "{create}");
        assert!(create.contains("--label sbx.registries=dhi.io"), "{create}");
        // The create's own first start, then a fresh start that carries the token.
        let starts: Vec<usize> = (0..lines.len())
            .filter(|&i| lines[i] == "machine start -n sbx-_builder")
            .collect();
        assert_eq!(starts.len(), 2, "{lines:#?}");
        assert!(
            lines[starts[0]..starts[1]].contains(&"machine stop -n sbx-_builder".to_string()),
            "{lines:#?}"
        );
        let token = (
            "SBX_REGISTRY_0_AUTH".to_string(),
            "Bearer tok-123".to_string(),
        );
        let envs = fake.envs();
        assert!(!envs[0].contains(&token), "{envs:?}");
        assert!(envs[1].contains(&token), "{envs:?}");
        assert!(
            !fake.removed()[1].contains(&token.0),
            "{:?}",
            fake.removed()
        );
        // Later starts unset it, so the host shell's environment can't fill it.
        assert!(fake.removed()[0].contains(&token.0), "{:?}", fake.removed());
        assert!(
            !lines.iter().any(|l| l.contains("tok-123")),
            "never in argv: {lines:#?}"
        );
        assert_eq!(lines.last().unwrap(), "machine stop -n sbx-_builder");
    }

    #[test]
    fn a_running_builder_is_restarted_to_take_a_token() {
        let t = test_env(&[]);
        with_dhi_login(&t);
        let fake = t.ctx.vm.runner();
        fake.ok(&["machine", "status"], &dhi_builder_json("running"))
            .download(&kit_tar());
        let kit = dhi_kit_dir();
        build_with(&t.ctx, kit.path(), fake_mint).unwrap();
        let lines = fake.call_lines();
        assert!(!lines.iter().any(|l| l.starts_with("machine create")));
        let stop = lines
            .iter()
            .position(|l| l == "machine stop -n sbx-_builder");
        let start = lines
            .iter()
            .position(|l| l == "machine start -n sbx-_builder");
        assert!(stop.unwrap() < start.unwrap(), "{lines:#?}");
        assert!(
            fake.envs()[0].contains(&(
                "SBX_REGISTRY_0_AUTH".to_string(),
                "Bearer tok-123".to_string()
            )),
            "{:?}",
            fake.envs()
        );
        // It was running before: it stays running.
        assert!(
            lines.last().unwrap().contains("-- rm -rf /build/"),
            "{lines:#?}"
        );
    }

    #[test]
    fn a_builder_without_the_stored_registries_is_recreated() {
        let t = test_env(&[]);
        with_dhi_login(&t);
        let fake = t.ctx.vm.runner();
        fake.ok(&["machine", "status"], &dhi_builder_json("created"))
            // Later registrations answer first: find gets the old builder, create's check none.
            .once_fail(&["machine", "status"], "NOT_FOUND", "vm not found")
            .once_ok(&["machine", "status"], &builder_json("stopped"))
            .download(&kit_tar());
        let kit = dhi_kit_dir();
        build_with(&t.ctx, kit.path(), fake_mint).unwrap();
        let lines = fake.call_lines();
        let delete = lines
            .iter()
            .position(|l| l == "machine delete -n sbx-_builder -f")
            .expect("delete");
        let create = lines
            .iter()
            .position(|l| l.starts_with("machine create -n sbx-_builder"))
            .expect("create");
        assert!(delete < create, "{lines:#?}");
    }

    #[test]
    fn a_registry_the_kit_doesnt_pull_from_gets_no_token() {
        let t = test_env(&[]);
        with_dhi_login(&t);
        let fake = t.ctx.vm.runner();
        fake.ok(&["machine", "status"], &dhi_builder_json("running"))
            .download(&kit_tar());
        let kit = kit_dir();
        build_with(&t.ctx, kit.path(), no_mint).unwrap();
        let lines = fake.call_lines();
        assert!(!lines.iter().any(|l| l.starts_with("machine stop")));
        assert!(!lines.iter().any(|l| l.starts_with("machine start")));
    }

    #[test]
    fn repos_are_the_hosts_references_without_tag_or_digest() {
        let text = "build: |\n  FROM dhi.io/debian-base:trixie AS b\n  \
                    COPY --from=dhi.io/team/tool@sha256:abcd / /\n  FROM \"DHI.io/node\"\n  \
                    FROM ghcr.io/dhi.io/x\n  RUN echo dhi.io/\n";
        assert_eq!(
            repos_in(text, "dhi.io"),
            ["debian-base", "node", "team/tool"]
        );
        assert!(repos_in(text, "quay.io").is_empty());
    }

    #[test]
    fn a_401_inside_a_digest_or_size_is_not_an_auth_failure() {
        let log = "#5 sha256:4019ab0c401def 12.3MB / 40.1MB\n\
                   #5 transferred 4012 bytes\n\
                   #6 ERROR: process \"/bin/sh -c make\" did not complete successfully: exit code: 2\n";
        let (_t, err) = failing_build(log);
        assert!(!err.contains("registry login"), "{err}");
        assert!(err.contains("transferred 4012 bytes"), "{err}");
        assert!(err.contains("exit code: 2"), "{err}");
    }

    #[test]
    fn the_syntax_line_may_follow_a_bom() {
        assert!(starts_with_syntax(
            b"\xEF\xBB\xBF# syntax=docker/sandbox-kit:3\r\nkind: x\n"
        ));
        assert!(starts_with_syntax(MIXIN.as_bytes()));
        assert!(!starts_with_syntax(
            b"\xEF\xBB\xBFkind: x\n# syntax=docker/sandbox-kit:3\n"
        ));
    }

    #[test]
    fn clear_auth_signals_are_recognised() {
        for line in [
            "unexpected status: 401 Unauthorized",
            "failed with status code 401",
            "HEAD https://r.example/v2/x: 401 Unauthorized",
            "error: unauthorized: authentication required",
            "pull access denied for x",
            "denied: requested access to the resource is denied",
        ] {
            assert!(is_auth_failure(&line.to_lowercase()), "{line}");
        }
        for line in [
            "sha256:aa401bb",
            "transferred 4012 bytes",
            "status: 4010",
            "status: 401b",
            "line 401",
            "copied: 401 bytes",
            "HEAD https://r.example/v2/x: 401 ",
            "layer: 401kb",
        ] {
            assert!(!is_auth_failure(line), "{line}");
        }
    }

    #[test]
    fn unpack_refuses_entries_outside_the_layout() {
        for bad in ["../evil", "/etc/evil"] {
            let d = tempfile::tempdir().unwrap();
            let mut h = tar::Header::new_gnu();
            h.set_entry_type(tar::EntryType::Regular);
            h.set_size(1);
            h.set_mode(0o644);
            let name = &mut h.as_gnu_mut().unwrap().name;
            name[..bad.len()].copy_from_slice(bad.as_bytes());
            h.set_cksum();
            let mut b = tar::Builder::new(Vec::new());
            b.append(&h, &b"x"[..]).unwrap();
            let kit_tar = d.path().join("kit.tar");
            fs::write(&kit_tar, b.into_inner().unwrap()).unwrap();
            let err = unpack(&kit_tar, &d.path().join("built"), d.path())
                .unwrap_err()
                .to_string();
            assert!(err.contains(bad), "{bad}: {err}");
        }
    }
}
