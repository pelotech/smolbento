use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use super::*;
use crate::kits::model::{ImageConfig, Kind};

const DESC: &str =
    r#"{"schemaVersion":"3","kind":"workload","version":"1.0.0","provides":["shell"]}"#;

fn src() -> Source {
    Source::Registry("docker.io/acme/kit:1".into())
}

#[test]
fn a_cached_pinned_ref_loads_without_the_registry() {
    let cache = tempfile::tempdir().unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let digest = fixtures::oci_layout(tmp.path(), Some(DESC), &[], "{}");
    fs::create_dir_all(store_dir(cache.path())).unwrap();
    for e in fs::read_dir(store_dir(tmp.path())).unwrap() {
        let data = fs::read(e.unwrap().path()).unwrap();
        put_bytes(cache.path(), &sha256_digest(&data), &data).unwrap();
    }
    let manifest = fs::read(store_dir(tmp.path()).join(hex_of(&digest).unwrap())).unwrap();
    // Nothing listens on 127.0.0.1:1: only the cache can answer.
    let r = "127.0.0.1:1/acme/kit:1";
    build_layout(cache.path(), &manifest, &digest, r).unwrap();
    let k = pull(r, Some(&digest), cache.path(), Logins::none()).unwrap();
    assert_eq!(k.digest.as_deref(), Some(digest.as_str()));
    assert_eq!(k.source, Source::Registry(r.into()));
    // Unpinned, it asks the registry.
    assert!(pull(r, None, cache.path(), Logins::none()).is_err());
}

#[test]
fn start_docker_annotation_is_read() {
    let flagged = tempfile::tempdir().unwrap();
    write_layout(
        flagged.path(),
        Some(DESC),
        &[("com.docker.sandboxes.start-docker", "true")],
        &[],
        "{}",
    )
    .unwrap();
    assert!(read_layout(flagged.path(), src()).unwrap().starts_docker);
    let plain = tempfile::tempdir().unwrap();
    fixtures::oci_layout(plain.path(), Some(DESC), &[], "{}");
    assert!(!read_layout(plain.path(), src()).unwrap().starts_docker);
}

#[test]
fn annotation_becomes_the_descriptor() {
    let d = tempfile::tempdir().unwrap();
    let digest = fixtures::oci_layout(d.path(), Some(DESC), &[b"layer"], "{}");
    let kit = read_layout(d.path(), src()).unwrap();
    assert_eq!(kit.kind, Kind::Workload);
    assert_eq!(kit.provides, vec!["shell@1"]);
    assert_eq!(kit.digest.as_deref(), Some(digest.as_str()));
    assert_eq!(kit.content, Content::Oci(d.path().to_path_buf()));
    assert_eq!(kit.command, None);
}

#[test]
fn missing_annotation_is_not_a_kit() {
    let d = tempfile::tempdir().unwrap();
    fixtures::oci_layout(d.path(), None, &[], "{}");
    let e = read_layout(d.path(), src()).unwrap_err();
    assert!(format!("{e:#}").contains("not a kit"), "{e:#}");
}

#[test]
fn command_is_entrypoint_then_cmd() {
    let d = tempfile::tempdir().unwrap();
    let cfg = r#"{"config":{"Entrypoint":["/bin/agent","--x"],"Cmd":["run"]}}"#;
    fixtures::oci_layout(d.path(), Some(DESC), &[], cfg);
    let kit = read_layout(d.path(), src()).unwrap();
    assert_eq!(
        kit.command,
        Some(vec!["/bin/agent".into(), "--x".into(), "run".into()])
    );
}

#[test]
fn user_and_workdir_come_from_the_image_config() {
    let d = tempfile::tempdir().unwrap();
    let cfg = r#"{"config":{"Cmd":["sh"],"User":"somebody","WorkingDir":"/x"}}"#;
    fixtures::oci_layout(d.path(), Some(DESC), &[], cfg);
    let kit = read_layout(d.path(), src()).unwrap();
    assert_eq!(
        kit.config,
        Some(ImageConfig {
            user: "somebody".into(),
            workdir: "/x".into()
        })
    );
    // Unset fields are empty: root in `/`.
    let d = tempfile::tempdir().unwrap();
    fixtures::oci_layout(d.path(), Some(DESC), &[], "{}");
    let kit = read_layout(d.path(), src()).unwrap();
    assert_eq!(kit.config, Some(ImageConfig::default()));
}

#[test]
fn image_command_reads_a_cached_image_without_the_network() {
    let cache = tempfile::tempdir().unwrap();
    fixtures::cached_image(
        cache.path(),
        "img:1",
        r#"{"config":{"Entrypoint":["/bin/agent"],"Cmd":["run"]}}"#,
    );
    fixtures::cached_image(cache.path(), "bare:1", r#"{"config":{}}"#);
    assert_eq!(
        image_command("img:1", cache.path(), Logins::none()).unwrap(),
        Some(vec!["/bin/agent".to_string(), "run".into()])
    );
    assert_eq!(
        image_command("bare:1", cache.path(), Logins::none()).unwrap(),
        None
    );
}

#[test]
fn local_source_is_kept() {
    let d = tempfile::tempdir().unwrap();
    fixtures::oci_layout(d.path(), Some(DESC), &[], "{}");
    let s = Source::Local(d.path().to_path_buf());
    assert_eq!(read_layout(d.path(), s.clone()).unwrap().source, s);
}

#[test]
fn unsupported_schema_annotation_is_refused() {
    let d = tempfile::tempdir().unwrap();
    let digest = fixtures::oci_layout(d.path(), Some(DESC), &[], "{}");
    let blobs = d.path().join("blobs/sha256");
    let p = blobs.join(hex_of(&digest).unwrap());
    let text = fs::read_to_string(&p)
        .unwrap()
        .replace(r#"schema-version":"3""#, r#"schema-version":"4""#);
    // Re-store under the new digest and point the index at it.
    let new = sha256_digest(text.as_bytes());
    fs::write(blobs.join(hex_of(&new).unwrap()), &text).unwrap();
    let index = json!({"manifests": [{"digest": new}]});
    fs::write(d.path().join("index.json"), index.to_string()).unwrap();
    let e = read_layout(d.path(), src()).unwrap_err();
    assert!(format!("{e:#}").contains("schema version 4"), "{e:#}");
}

#[test]
fn corrupt_manifest_is_refused() {
    let d = tempfile::tempdir().unwrap();
    let digest = fixtures::oci_layout(d.path(), Some(DESC), &[], "{}");
    let p = d.path().join("blobs/sha256").join(hex_of(&digest).unwrap());
    let mut b = fs::read(&p).unwrap();
    b.push(b' ');
    fs::write(&p, b).unwrap();
    let e = read_layout(d.path(), src()).unwrap_err();
    assert!(format!("{e:#}").contains("corrupt"), "{e:#}");
}

#[test]
fn digests_must_be_plain_sha256_hex() {
    assert!(hex_of(&format!("sha256:{}", "a".repeat(64))).is_ok());
    for bad in [
        "sha256:../../etc/passwd",
        "sha512:ab",
        &format!("sha256:{}", "A".repeat(64)),
        "",
    ] {
        assert!(hex_of(bad).is_err(), "{bad}");
    }
}

#[test]
fn layout_hard_links_the_shared_store() {
    let cache = tempfile::tempdir().unwrap();
    let staged = tempfile::tempdir().unwrap();
    let digest = fixtures::oci_layout(
        staged.path(),
        Some(DESC),
        &[b"layer"],
        r#"{"config":{"Cmd":["x"]}}"#,
    );
    // Move the staged blobs into the cache's shared store.
    fs::create_dir_all(store_dir(cache.path())).unwrap();
    for e in fs::read_dir(staged.path().join("blobs/sha256")).unwrap() {
        let e = e.unwrap();
        fs::copy(e.path(), store_dir(cache.path()).join(e.file_name())).unwrap();
    }
    let manifest = fs::read(
        staged
            .path()
            .join("blobs/sha256")
            .join(hex_of(&digest).unwrap()),
    )
    .unwrap();
    let dir = build_layout(cache.path(), &manifest, &digest, "docker.io/acme/kit:1").unwrap();
    assert_eq!(dir, cache.path().join("oci").join(hex_of(&digest).unwrap()));
    assert_eq!(
        fs::read_to_string(dir.join("oci-layout")).unwrap(),
        r#"{"imageLayoutVersion":"1.0.0"}"#
    );
    let index: Value = serde_json::from_slice(&fs::read(dir.join("index.json")).unwrap()).unwrap();
    let m = &index["manifests"][0];
    assert_eq!(m["digest"], json!(digest));
    assert_eq!(
        m["annotations"][REF_NAME_ANNOTATION],
        "docker.io/acme/kit:1"
    );
    assert_eq!(m["annotations"][SCHEMA_ANNOTATION], "3");
    {
        use std::os::unix::fs::MetadataExt;
        let h = hex_of(&digest).unwrap();
        let a = fs::metadata(store_dir(cache.path()).join(h)).unwrap().ino();
        let b = fs::metadata(dir.join("blobs/sha256").join(h))
            .unwrap()
            .ino();
        assert_eq!(a, b);
    }
    let kit = read_layout(&dir, src()).unwrap();
    assert_eq!(kit.command, Some(vec!["x".into()]));
    // Building again over an existing layout is fine.
    build_layout(cache.path(), &manifest, &digest, "docker.io/acme/kit:2").unwrap();
}

#[test]
fn picks_the_host_platform_from_an_index() {
    let a = format!("sha256:{}", "a".repeat(64));
    let b = format!("sha256:{}", "b".repeat(64));
    let index = json!({"manifests": [
        {"digest": a, "platform": {"os": "linux", "architecture": "amd64"}},
        {"digest": b, "platform": {"os": "linux", "architecture": "arm64"}},
        {"digest": "sha256:x", "platform": {"os": "windows", "architecture": "arm64"}},
    ]});
    assert_eq!(pick_platform(&index, "arm64").unwrap(), b);
    assert_eq!(pick_platform(&index, "amd64").unwrap(), a);
    assert!(pick_platform(&index, "riscv64").is_err());
}

fn no_helper(_: &str, _: &str) -> Option<RegistryAuth> {
    None
}

#[test]
fn docker_config_auth_entries() {
    let basic = STANDARD.encode("me:s3cret");
    let cfg = format!(
        r#"{{"auths":{{"ghcr.io":{{"auth":"{basic}"}},
                "https://index.docker.io/v1/":{{"identitytoken":"tok"}}}}}}"#
    );
    match auth_from_config(&cfg, "ghcr.io", &no_helper) {
        Some(RegistryAuth::Basic(u, p)) => {
            assert_eq!((u.as_str(), p.as_str()), ("me", "s3cret"))
        }
        _ => panic!("expected basic auth"),
    }
    assert!(matches!(
        auth_from_config(&cfg, "index.docker.io", &no_helper),
        Some(RegistryAuth::Bearer(t)) if t == "tok"
    ));
    assert!(auth_from_config(&cfg, "quay.io", &no_helper).is_none());
    assert!(auth_from_config("not json", "ghcr.io", &no_helper).is_none());
}

#[test]
fn docker_config_helpers_are_asked_by_name_and_server() {
    let cfg = r#"{"credsStore":"desktop","credHelpers":{"ecr.example.com":"ecr-login"}}"#;
    let ask = |name: &str, server: &str| Some(RegistryAuth::Basic(name.into(), server.into()));
    assert!(matches!(
        auth_from_config(cfg, "ecr.example.com", &ask),
        Some(RegistryAuth::Basic(n, s)) if n == "ecr-login" && s == "ecr.example.com"
    ));
    assert!(matches!(
        auth_from_config(cfg, "index.docker.io", &ask),
        Some(RegistryAuth::Basic(n, s)) if n == "desktop" && s == "https://index.docker.io/v1/"
    ));
}

#[test]
fn client_builds_with_the_ring_provider() {
    let r: Reference = "ghcr.io/a/b".parse().unwrap();
    let _ = new_client(&r);
    let _ = new_client(&r);
    assert!(rustls::crypto::CryptoProvider::get_default().is_some());
}

#[test]
fn only_loopback_registries_allow_plain_http() {
    let protocol = |s: &str| protocol_for(&s.parse::<Reference>().expect(s));
    for (r, host) in [
        ("localhost/kit:1", "localhost"),
        ("localhost:5000/kit:1", "localhost:5000"),
        ("LocalHost:5000/kit", "LocalHost:5000"),
        ("127.0.0.1/kit", "127.0.0.1"),
        ("127.0.0.1:5000/a/kit", "127.0.0.1:5000"),
        ("127.255.0.9:80/kit", "127.255.0.9:80"),
    ] {
        assert_eq!(
            protocol(r),
            ClientProtocol::HttpsExcept(vec![host.to_string()]),
            "{r}"
        );
    }
    for r in [
        "ghcr.io/a/kit",
        "docker.io/library/kit",
        "kit",
        "localhost.evil.com/kit",
        "localhost.evil.com:5000/kit",
        "127.0.0.1.nip.io/kit",
        "128.0.0.1:5000/kit",
    ] {
        assert_eq!(protocol(r), ClientProtocol::Https, "{r}");
    }
    // oci-client 0.18 does not parse IPv6 registries yet; the host check still accepts them.
    assert!(is_loopback("[::1]"));
    assert!(is_loopback("[::1]:5000"));
    assert!(!is_loopback("[::2]:5000"));
    assert!(!is_loopback("localhost:"));
    assert!(!is_loopback("localhost:50x"));
    assert!(!is_loopback("[::1]x"));
}

#[test]
fn only_auth_errors_retry_with_credentials() {
    let auth = anyhow::Error::new(OciDistributionError::UnauthorizedError { url: "u".into() })
        .context("pulling the manifest");
    assert!(is_auth_error(&auth));
    let denied = anyhow::Error::new(OciDistributionError::ServerError {
        code: 403,
        url: "u".into(),
        message: "m".into(),
    });
    assert!(is_auth_error(&denied));
    let other = anyhow::Error::new(OciDistributionError::ServerError {
        code: 500,
        url: "u".into(),
        message: "m".into(),
    });
    assert!(!is_auth_error(&other));
    assert!(!is_auth_error(&anyhow!("boom")));
}

#[test]
fn missing_helper_binary_is_skipped() {
    assert!(credential_helper("definitely-not-installed-xyz", "ghcr.io").is_none());
    assert!(credential_helper("../evil", "ghcr.io").is_none());
}

/// A v2 kit as sbx publishes one (docker.io/sbx/gemini-kit): an OCI artifact whose config is
/// the spec, with one empty layer. `layer` replaces the empty layer.
const GEMINI_SPEC: &str = "schemaVersion: \"2\"\nkind: sandbox\nname: gemini\nversion: \"1.0.0\"\n\
                    sandbox:\n  image: docker.io/sbx/gemini-image:latest\n  entrypoint:\n    - gemini\n  \
                    command:\n    default:\n      - --yolo\n\
                    agentInstructions:\n  filename: GEMINI.md\n";

fn v2_artifact(dir: &Path, layer: Option<(&str, &[u8])>) {
    v2_artifact_with(dir, GEMINI_SPEC, layer)
}

fn v2_artifact_with(dir: &Path, spec: &str, layer: Option<(&str, &[u8])>) {
    let blobs = dir.join("blobs").join("sha256");
    fs::create_dir_all(&blobs).unwrap();
    let put = |data: &[u8]| {
        let d = sha256_digest(data);
        fs::write(blobs.join(hex_of(&d).unwrap()), data).unwrap();
        d
    };
    let config = put(spec.as_bytes());
    let layer = match layer {
        None => json!({"mediaType": "application/vnd.oci.empty.v1+json",
                           "digest": put(b"{}"), "size": 2}),
        Some((media_type, l)) => json!({"mediaType": media_type,
                              "digest": put(l), "size": l.len()}),
    };
    let manifest = json!({
        "schemaVersion": 2,
        "mediaType": OCI_IMAGE_MEDIA_TYPE,
        "artifactType": "application/vnd.docker.sandbox.kit.v2",
        "config": {"mediaType": artifact::V2_SPEC_MEDIA_TYPE, "digest": config, "size": spec.len()},
        "layers": [layer],
        "annotations": {"vnd.docker.sandbox.kit.name": "gemini"},
    });
    let bytes = serde_json::to_vec(&manifest).unwrap();
    let digest = put(&bytes);
    let index = json!({"schemaVersion": 2, "manifests": [
            {"mediaType": OCI_IMAGE_MEDIA_TYPE, "digest": digest, "size": bytes.len()}]});
    fs::write(dir.join("index.json"), index.to_string()).unwrap();
}

#[test]
fn a_published_v2_kit_is_read_from_its_spec() {
    let d = tempfile::tempdir().unwrap();
    v2_artifact(d.path(), None);
    let r = "docker.io/sbx/gemini-kit:latest";
    let kit = read_layout(d.path(), Source::Registry(r.into())).unwrap();
    assert_eq!(kit.name, "gemini");
    assert_eq!(kit.kind, crate::kits::model::Kind::Workload);
    assert_eq!(
        kit.content,
        Content::Image("docker.io/sbx/gemini-image:latest".into())
    );
    assert_eq!(kit.command, Some(vec!["gemini".into(), "--yolo".into()]));
    assert_eq!(kit.source, Source::Registry(r.into()));
    assert_eq!(kit.format(), Some(crate::kits::model::Format::V2));
    assert!(kit.digest.is_some());
}

#[test]
fn a_pinned_reference_names_the_digest() {
    let d = format!("sha256:{}", "a".repeat(64));
    assert_eq!(
        pinned("docker.io/sbx/gemini-kit:latest", &d).unwrap(),
        format!("docker.io/sbx/gemini-kit@{d}")
    );
    assert_eq!(
        pinned("localhost:5000/e2e/k:1", &d).unwrap(),
        format!("localhost:5000/e2e/k@{d}")
    );
    assert!(pinned("localhost:5000/e2e/k:1", "sha256:short").is_err());
}

#[test]
fn the_signature_manifest_matches_sbx() {
    let subject = json!({"mediaType": OCI_IMAGE_MEDIA_TYPE, "digest": "sha256:aa", "size": 824});
    let m = signature_manifest(&subject, "sha256:bb", 712, "2026-11-13T00:00:00Z");
    assert_eq!(
        m,
        json!({
            "schemaVersion": 2,
            "mediaType": OCI_IMAGE_MEDIA_TYPE,
            "artifactType": "application/vnd.docker.sandbox.kit.signature.v1",
            "config": {
                "mediaType": artifact::EMPTY_MEDIA_TYPE,
                "digest": "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
                "size": 2,
                "data": "e30=",
            },
            "layers": [{
                "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
                "digest": "sha256:bb",
                "size": 712,
            }],
            "subject": subject,
            "annotations": {"org.opencontainers.image.created": "2026-11-13T00:00:00Z"},
        })
    );
}

#[test]
fn the_fallback_index_keeps_earlier_referrers() {
    let a = json!({"mediaType": OCI_IMAGE_MEDIA_TYPE, "digest": "sha256:a", "size": 1});
    let b = json!({"mediaType": OCI_IMAGE_MEDIA_TYPE, "digest": "sha256:b", "size": 2});
    let first = add_to_referrers_index(None, a.clone()).unwrap();
    assert_eq!(first["mediaType"], OCI_IMAGE_INDEX_MEDIA_TYPE);
    assert_eq!(first["schemaVersion"], 2);
    assert_eq!(first["manifests"], json!([a.clone()]));
    let both = add_to_referrers_index(Some(first), b.clone()).unwrap();
    assert_eq!(both["manifests"], json!([a.clone(), b]));
    let again = add_to_referrers_index(Some(both.clone()), a.clone()).unwrap();
    assert_eq!(again, both);
    let odd = json!({"schemaVersion": 2, "manifests": "not a list"});
    assert!(add_to_referrers_index(Some(odd), a).is_err());
}

#[test]
fn only_a_v2_kit_artifact_has_a_payload() {
    let files = "sha256:".to_string() + &"a".repeat(64);
    let v2 = json!({"artifactType": artifact::KIT_V2_ARTIFACT,
            "config": {"mediaType": artifact::V2_SPEC_MEDIA_TYPE, "digest": files.clone()},
            "layers": [{"mediaType": TAR_GZ, "digest": files.clone()}]});
    assert_eq!(payload_layer(&v2, "r").unwrap(), Some(files.clone()));
    let empty = json!({"artifactType": artifact::KIT_V2_ARTIFACT,
            "config": {"mediaType": artifact::V2_SPEC_MEDIA_TYPE, "digest": files},
            "layers": [{"mediaType": artifact::EMPTY_MEDIA_TYPE}]});
    assert_eq!(payload_layer(&empty, "r").unwrap(), None);
    let image = json!({"config": {"mediaType": "application/vnd.oci.image.config.v1+json"},
            "annotations": {DESCRIPTOR_ANNOTATION: "{}"}});
    assert_eq!(
        payload_layer(&image, "acme/k:1").unwrap_err().to_string(),
        "acme/k:1 is not a v2 kit artifact"
    );
}

#[test]
fn pull_names_follow_the_reference() {
    assert_eq!(
        pull_name("docker.io/sbx/gemini-kit:latest"),
        "gemini-kit-latest.tar.gz"
    );
    assert_eq!(pull_name("acme/kit"), "kit-latest.tar.gz");
    let hex = "0123456789ab".to_string() + &"c".repeat(52);
    assert_eq!(
        pull_name(&format!("localhost:5000/a/b@sha256:{hex}")),
        "b-0123456789ab.tar.gz"
    );
}

/// A files layer holding `home/agent/<path>` for each `(path, body)`.
fn files_layer(files: &[(&str, &str)]) -> Vec<u8> {
    let d = tempfile::tempdir().unwrap();
    fs::write(
        d.path().join("spec.yaml"),
        "schemaVersion: \"2\"\nkind: mixin\n",
    )
    .unwrap();
    for (path, body) in files {
        let p = d.path().join("files/home").join(path);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, body).unwrap();
    }
    crate::kits::artifact::read_dir(d.path())
        .unwrap()
        .files
        .unwrap()
}

const TAR_GZ: &str = "application/vnd.oci.image.layer.v1.tar+gzip";

#[test]
fn a_published_v2_kit_with_files_is_read() {
    let d = tempfile::tempdir().unwrap();
    let layer = files_layer(&[(".cfg", "hello")]);
    v2_artifact(d.path(), Some((TAR_GZ, &layer)));
    let kit = read_layout(d.path(), Source::Registry("acme/k:1".into())).unwrap();
    assert!(format!("{kit:?}").contains("/home/agent/.cfg"), "{kit:?}");
    assert_eq!(
        fs::read_to_string(d.path().join("files/home/.cfg")).unwrap(),
        "hello"
    );
    // Read again from the unpacked files.
    let again = read_layout(d.path(), Source::Registry("acme/k:1".into())).unwrap();
    assert_eq!(again, kit);
}

#[test]
fn a_crlf_spec_reads_back() {
    let d = tempfile::tempdir().unwrap();
    let spec = "schemaVersion: \"2\"\r\nkind: mixin\r\nname: crlf\r\n";
    v2_artifact_with(d.path(), spec, None);
    let kit = read_layout(d.path(), Source::Registry("acme/k:1".into())).unwrap();
    assert_eq!(kit.name, "crlf");
}

#[test]
fn a_v2_layer_of_another_type_is_refused() {
    let d = tempfile::tempdir().unwrap();
    let media_type = "application/vnd.oci.image.layer.v1.tar";
    v2_artifact(d.path(), Some((media_type, b"some files")));
    let err = read_layout(d.path(), Source::Registry("acme/k:1".into())).unwrap_err();
    assert_eq!(
        err.to_string(),
        format!("acme/k:1 is a v2 kit with a layer of type {media_type}")
    );
}
