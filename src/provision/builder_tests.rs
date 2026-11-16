use std::fs;

use super::*;
use crate::kits::model::Source;
use crate::kits::registry::{self, fixtures::oci_layout};
use crate::testutil::*;

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
            (
                "sbx.kits",
                r#"[{"name":"docker","ref":"builtin:docker","provides":["docker@1.0.0"]}]"#,
            ),
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
    let fake = t.runner();
    // The builder is missing until it's created.
    fake.ok(&["machine", "status"], &builder_json("created"))
        .missing_until_created("sbx-_builder")
        .download(&kit_tar());
    let kit = kit_dir();
    let out = build(&t.ctx, kit.path()).unwrap();

    let tar = kit_tar();
    let digest = util::sha256_digest(&tar);
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
    assert!(
        c.contains(
            "--image docker.io/sbx/shell:latest@sha256:\
                 89ed5d63def6bfb2373d408e3ab6ad55aa5c010f884a182a78299fcf85ea42d1"
        ),
        "{c}"
    );
    assert!(c.contains("--label sbx.name=_builder"), "{c}");
    assert!(c.contains("--label sbx.docker=true"), "{c}");
    assert!(c.contains(r#"--label sbx.kits=[{"name":"builder","ref":"builtin:builder"},{"name":"docker","ref":"builtin:docker","provides":["docker@1.0.0"]}]"#), "{c}");
    assert!(
        c.contains("-v /var/lib/docker -v /var/lib/containerd"),
        "{c}"
    );
    assert!(c.contains("--mem 4096"), "{c}");
    assert!(c.contains("--net-backend virtio-net"), "{c}");
    assert!(
        c.contains(" -u root -- sleep infinity"),
        "the builder stays root: {c}"
    );
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
    let fake = t.runner();
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
    let fake = t.runner();
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
    let fake = t.runner();
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
    let fake = t.runner();
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
    let fake = t.runner();
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
    assert!(err.contains("`bento secret rm --registry dhi.io`"), "{err}");
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
    let lines = t.calls();
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
                 one with `bento secret set --registry ghcr.io --password-stdin`"
        ),
        "{err}"
    );
    let (_t, err) = failing_build("ERROR: authentication required\n");
    assert!(
        err.contains(
            "failed: the build pulls, which needs a registry login; store \
                 one with `bento secret set --registry HOST --password-stdin`"
        ),
        "{err}"
    );
}

/// Without the syntax line nothing in the file names the kit frontend, so the build does.
#[test]
fn a_descriptor_without_the_syntax_line_is_built_with_the_frontend_named() {
    let t = test_env(&[]);
    let fake = t.runner();
    fake.ok(&["machine", "status"], &builder_json("running"))
        .download(&kit_tar());
    let kit = tempfile::tempdir().unwrap();
    fs::write(
        kit.path().join("spec.yaml"),
        "schemaVersion: \"3\"\nkind: mixin\n",
    )
    .unwrap();
    build_with(&t.ctx, kit.path(), no_mint).unwrap();
    let lines = fake.call_lines();
    let build = lines.iter().find(|l| l.contains("buildx build")).unwrap();
    assert!(
        build.contains("buildx build --build-arg BUILDKIT_SYNTAX=docker/sandbox-kit:3 -f "),
        "{build}"
    );
    assert!(build.contains("/ctx/spec.yaml "), "{build}");
}

#[test]
fn dockerd_that_never_answers_times_out_pointing_at_its_log() {
    let t = test_env(&[]);
    t.runner().fail(
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
    assert_eq!(t.runner().calls().len(), 3);
}

#[test]
fn dockerd_is_waited_for() {
    let t = test_env(&[]);
    let fake = t.runner();
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
    let fake = t.runner();
    fake.ok(&["machine", "status"], &builder_json("created"))
        .missing_until_created("sbx-_builder")
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

#[test]
fn the_builder_never_gets_host_access() {
    let mut t = test_env(&[]);
    fs::write(t.ctx.paths.policy_file(), "mode = \"deny-all\"\n").unwrap();
    t.sbt(&["policy", "allow", "network", "localhost"]).unwrap();
    let fake = t.runner();
    fake.ok(&["machine", "status"], &builder_json("created"))
        .missing_until_created("sbx-_builder")
        .download(&kit_tar());
    let kit = kit_dir();
    build(&t.ctx, kit.path()).unwrap();
    let lines = fake.call_lines();
    let create = lines
        .iter()
        .find(|l| l.starts_with("machine create -n sbx-_builder"))
        .unwrap();
    assert!(create.contains("--deny-cidr 127.0.0.0/8"), "{create}");
    assert!(!create.contains("sbx.host-access"), "{create}");
    assert!(
        !lines.iter().any(|l| l.contains("100.96.0.1/32")),
        "{lines:#?}"
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
        sandbox: None,
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
            (
                "sbx.kits",
                r#"[{"name":"docker","ref":"builtin:docker","provides":["docker@1.0.0"]}]"#,
            ),
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
    let fake = t.runner();
    fake.ok(&["machine", "status"], &dhi_builder_json("created"))
        .missing_until_created("sbx-_builder")
        .download(&kit_tar());
    let kit = dhi_kit_dir();
    build_with(&t.ctx, kit.path(), fake_mint).unwrap();

    let lines = fake.call_lines();
    let create = lines
        .iter()
        .find(|l| l.starts_with("machine create -n sbx-_builder"))
        .unwrap();
    assert!(
        create.contains("--credential reg-0=SBX_REGISTRY_0_AUTH@dhi.io:set-header=authorization"),
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
    let fake = t.runner();
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
    let fake = t.runner();
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

/// Stored logins the builder can't use (a registry on a port, Docker Hub) are not bound: it
/// builds as if they weren't stored.
fn unbindable_logins_are_not_bound(hosts: &[&str]) {
    use crate::secrets::{RegistryEntry, SecretsFile};
    let t = test_env(&[]);
    let mut f = SecretsFile::default();
    for h in hosts {
        f.registries.push(RegistryEntry {
            host: (*h).into(),
            username: None,
            auth_endpoint: None,
            sandbox: None,
        });
    }
    f.save(&t.ctx.paths).unwrap();
    let fake = t.runner();
    fake.ok(&["machine", "status"], &builder_json("created"))
        .missing_until_created("sbx-_builder")
        .download(&kit_tar());
    let kit = kit_dir();
    build_with(&t.ctx, kit.path(), no_mint).unwrap();
    let lines = fake.call_lines();
    let create = lines
        .iter()
        .find(|l| l.starts_with("machine create -n sbx-_builder"))
        .unwrap();
    assert!(!create.contains("--credential"), "{create}");
    assert!(!create.contains("sbx.registries"), "{create}");
    assert_eq!(fake.envs(), vec![Vec::<(String, String)>::new()]);
}

#[test]
fn a_login_for_a_registry_on_a_port_is_not_bound() {
    unbindable_logins_are_not_bound(&["registry.corp:5000", "localhost:5000"]);
}

#[test]
fn a_docker_hub_login_is_not_bound() {
    unbindable_logins_are_not_bound(&["registry-1.docker.io", "docker.io"]);
}

#[test]
fn a_registry_the_kit_doesnt_pull_from_gets_no_token() {
    let t = test_env(&[]);
    with_dhi_login(&t);
    let fake = t.runner();
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
