//! The `_builder` sandbox: builds local v3 kit directories with BuildKit's `docker/sandbox-kit:3`
//! frontend in its own private dockerd, so the host needs no Docker.

use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};

use crate::cli::{Ctx, plan};
use crate::sandbox::{self, CreateRequest, options};
use crate::smolvm::{ExecSpec, Runner, Smolvm, SmolvmError};

use super::registry::hex;

pub const BUILDER: &str = "_builder";
/// Renovate bumps this (see renovate.json5).
pub const BUILDER_IMAGE: &str = "docker/sandbox-templates:shell-docker-0.10.0";

const MEMORY_MIB: u64 = 4096;
const SYNTAX: &str = "# syntax=docker/sandbox-kit:3";
/// `docker info` tries, a second apart, before dockerd counts as not starting.
const DOCKER_WAIT: u32 = 30;
/// How much of a failed build's output the error shows.
const TAIL_LINES: usize = 20;
const AUTH_MARKERS: [&str; 4] = [
    "401",
    "unauthorized",
    "authentication required",
    "denied: requested access",
];

/// Numbers this process's builds, so concurrent builds get their own `/build/<n>`.
static BUILDS: AtomicU32 = AtomicU32::new(0);

/// Builds the v3 kit directory `dir` and returns the OCI layout it produced, unpacked into the
/// cache (`<cache>/built/<sha256 of the tar>`).
pub fn build<R: Runner>(ctx: &Ctx<R>, dir: &Path) -> Result<PathBuf> {
    let desc = descriptor(dir)?;
    let cache = ctx.paths.kit_cache();
    fs::create_dir_all(&cache).with_context(|| format!("creating {}", cache.display()))?;
    // In the cache, so the unpacked layout can be renamed into place.
    let tmp = tempfile::Builder::new()
        .prefix(".build-")
        .tempdir_in(&cache)
        .with_context(|| format!("creating a temp dir in {}", cache.display()))?;
    let (ctx_tar, kit_tar) = (tmp.path().join("ctx.tar"), tmp.path().join("kit.tar"));
    pack(dir, &ctx_tar)?;

    let (mut sb, was_running) = match sandbox::find(&ctx.vm, BUILDER)? {
        Some(sb) => {
            let running = sb.is_running();
            (sb, running)
        }
        None => (
            plan::create(ctx, &mut request(ctx), &[])
                .context("creating the kit builder sandbox")?,
            false,
        ),
    };
    let result = plan::ensure_running(ctx, &mut sb)
        .context("starting the kit builder sandbox")
        .and_then(|()| wait_for_docker(&ctx.vm, &sb.machine, DOCKER_WAIT, Duration::from_secs(1)))
        .and_then(|()| run_build(ctx, &sb.machine, dir, &desc, &ctx_tar, &kit_tar));
    if !was_running
        && sb.is_running()
        && let Err(e) = ctx.vm.stop(&sb.machine)
    {
        eprintln!("warning: stopping the {BUILDER} sandbox: {e:#}");
    }
    result?;
    unpack(&kit_tar, &cache.join("built"), tmp.path())
}

/// The builder sandbox: mountless, with a private dockerd, under the global network policy.
fn request<R: Runner>(ctx: &Ctx<R>) -> CreateRequest {
    CreateRequest {
        name: BUILDER.into(),
        agent: "shell".into(),
        image: BUILDER_IMAGE.into(),
        cpus: options::host_cpus(),
        memory_mib: MEMORY_MIB,
        docker: true,
        created: ctx.now,
        ..Default::default()
    }
}

/// The kit's descriptor file name: the single `*.yaml`/`*.yml` whose first line is the v3 syntax
/// line (upstream names it after the kit, e.g. `claude-mixin.yaml`).
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
        let first = bytes.split(|b| *b == b'\n').next().unwrap_or_default();
        if String::from_utf8_lossy(first).trim_end() == SYNTAX {
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

/// Waits for the builder's dockerd, which `machine start` only launches.
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
        .map_err(|e| build_error(dir, &e))?;
        ctx.vm
            .cp(&format!("{machine}:{guest_kit_tar}"), &host(kit_tar)?)
            .context("copying the built kit out of the builder")
    })();
    if let Err(e) = exec(&["rm", "-rf", &n]) {
        eprintln!("warning: removing {n} in the {BUILDER} sandbox: {e:#}");
    }
    result
}

/// A failed `docker buildx build`: a registry login it needed, or the end of its output.
fn build_error(dir: &Path, e: &anyhow::Error) -> anyhow::Error {
    let output = match e.downcast_ref::<SmolvmError>() {
        Some(s) => s.message.clone(),
        None => format!("{e:#}"),
    };
    let lower = output.to_lowercase();
    if AUTH_MARKERS.iter().any(|m| lower.contains(m)) {
        let from = registry_host(&output)
            .map(|h| format!(" from {h}"))
            .unwrap_or_default();
        return anyhow::anyhow!(
            "building {} failed: the build pulls{from}, which needs a registry login; \
             registry login for the builder isn't supported yet",
            dir.display()
        );
    }
    let lines: Vec<&str> = output.lines().collect();
    let tail = lines[lines.len().saturating_sub(TAIL_LINES)..].join("\n");
    anyhow::anyhow!("building {} failed:\n{tail}", dir.display())
}

/// The registry of the first image reference or URL on an auth error line.
fn registry_host(output: &str) -> Option<String> {
    let auth_line = |l: &&str| {
        let l = l.to_lowercase();
        AUTH_MARKERS.iter().any(|m| l.contains(m))
    };
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
    fn kit_tar() -> Vec<u8> {
        let d = tempfile::tempdir().unwrap();
        oci_layout(
            d.path(),
            Some(r#"{"schemaVersion":"3","kind":"mixin","name":"m"}"#),
            &[],
            "{}",
        );
        let mut b = tar::Builder::new(Vec::new());
        b.append_dir_all(".", d.path()).unwrap();
        b.into_inner().unwrap()
    }

    fn builder_json(state: &str) -> String {
        machine_json(
            "sbx-_builder",
            state,
            &[("sbx.name", "_builder"), ("sbx.docker", "true")],
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
            i("-d -- sh -c pgrep -x dockerd"),
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
        let fake = t.ctx.vm.runner();
        fake.ok(&["machine", "status"], &builder_json("stopped"))
            .on(
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
        let err = format!("{:#}", build(&t.ctx, kit.path()).unwrap_err());
        (t, err)
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
    fn an_auth_failure_says_registry_login_is_unsupported() {
        let (_t, err) = failing_build(
            "#3 ERROR: failed to resolve source metadata for ghcr.io/acme/base:1: \
             unexpected status from HEAD request to https://ghcr.io/v2/acme/base/manifests/1: \
             401 Unauthorized\n",
        );
        assert!(
            err.contains(
                "failed: the build pulls from ghcr.io, which needs a registry login; \
                 registry login for the builder isn't supported yet"
            ),
            "{err}"
        );
        let (_t, err) = failing_build("ERROR: authentication required\n");
        assert!(
            err.contains(
                "failed: the build pulls, which needs a registry login; \
                 registry login for the builder isn't supported yet"
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
}
