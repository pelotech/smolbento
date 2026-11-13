//! Pulls published kits (one OCI image each) into the kit cache as OCI image layouts.
//!
//! Cache: a shared blob store `<cache>/blobs/sha256/<hex>`, and per kit `<cache>/oci/<manifest
//! hex>/` holding `oci-layout`, `index.json` and `blobs/sha256/<hex>` hard-linked into the store,
//! so smolvm can load the directory as it is. `oci-client` is async; the runtime stays in here.

use std::fs;
use std::io::{self, Write};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::{Command, Stdio};
use std::task::{Context as TaskContext, Poll};

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use oci_client::Reference;
use oci_client::RegistryOperation;
use oci_client::client::{Client, ClientConfig, ClientProtocol};
use oci_client::errors::{OciDistributionError, OciErrorCode};
use oci_client::manifest::{
    IMAGE_MANIFEST_LIST_MEDIA_TYPE, IMAGE_MANIFEST_MEDIA_TYPE, OCI_IMAGE_INDEX_MEDIA_TYPE,
    OCI_IMAGE_MEDIA_TYPE,
};
use oci_client::secrets::RegistryAuth;
use reqwest::header::HeaderValue;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWrite;

use crate::kits::model::{Content, ImageConfig, Kit, Source};
use crate::kits::registry_auth::Logins;
use crate::kits::{artifact, trust, v3};
use crate::util::{hex, sha256_digest};

const DESCRIPTOR_ANNOTATION: &str = "vnd.docker.sandbox.kit.descriptor";
const SCHEMA_ANNOTATION: &str = "vnd.docker.sandbox.kit.schema-version";
const REF_NAME_ANNOTATION: &str = "org.opencontainers.image.ref.name";
/// The config of a v2 kit published as an OCI artifact: the kit's spec.yaml.
const V2_SPEC_MEDIA_TYPE: &str = "application/vnd.docker.sandbox.kit.v2.spec+yaml";
const EMPTY_MEDIA_TYPE: &str = "application/vnd.oci.empty.v1+json";
/// A published v2 kit's `files/`, as `home/agent/...`.
const V2_FILES_MEDIA_TYPE: &str = "application/vnd.oci.image.layer.v1.tar+gzip";

/// Fetches REF's manifest and config and its layers into the cache. A manifest without the kit
/// descriptor annotation is a plain image and an error.
pub fn pull(reference: &str, cache: &Path, logins: Logins) -> Result<Kit> {
    let dir = pull_layout(reference, cache, true, logins)?;
    read_layout(&dir, Source::Registry(reference.to_string()))
}

/// Pulls a plain image (no kit annotation required) into an OCI layout; returns its directory.
pub fn pull_image(reference: &str, cache: &Path, logins: Logins) -> Result<PathBuf> {
    pull_layout(reference, cache, false, logins)
}

/// Downloads REF into an OCI layout under the cache and returns its directory. With
/// `require_kit` the kit annotation is checked before any layer is fetched.
fn pull_layout(
    reference: &str,
    cache: &Path,
    require_kit: bool,
    logins: Logins,
) -> Result<PathBuf> {
    let fetched = fetch_ref(reference, cache, require_kit, true, logins)?;
    build_layout(cache, &fetched.manifest, &fetched.digest, reference)
}

/// Fetches REF's manifest and config into the cache's blob store, and its layers with `layers`.
fn fetch_ref(
    reference: &str,
    cache: &Path,
    require_kit: bool,
    layers: bool,
    logins: Logins,
) -> Result<Fetched> {
    // The same normaliser the trust check uses, so both read the ref alike.
    trust::normalise(reference)?;
    let r: Reference = reference
        .parse()
        .with_context(|| format!("invalid kit reference '{reference}'"))?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("starting the registry client")?;
    let client = new_client(&r);
    // A stored registry secret (`sbt secret set --registry`) is used instead of anonymous.
    let stored = logins
        .auth_for(r.registry(), r.repository())
        .with_context(|| format!("logging in to {} with its registry secret", r.registry()))?;
    rt.block_on(async {
        if let Some(auth) = stored {
            return fetch(&client, &r, &auth, cache, require_kit, layers)
                .await
                .with_context(|| format!("pulling {} with its registry secret", r.whole()));
        }
        let anonymous = RegistryAuth::Anonymous;
        let first = fetch(&client, &r, &anonymous, cache, require_kit, layers).await;
        match first {
            Ok(f) => Ok(f),
            // Private images answer anonymous pulls with 401/403; only then try the docker login.
            Err(e) if is_auth_error(&e) => match docker_auth(r.resolve_registry()) {
                Some(auth) => fetch(&client, &r, &auth, cache, require_kit, layers)
                    .await
                    .map_err(|e2| e2.context(format!("{e:#} (anonymous)"))),
                None => Err(e),
            },
            Err(e) => Err(e),
        }
    })
}

/// Pushes a v2 kit to REF (`registry/repo:tag`) and returns the manifest it pushed. Logs in with
/// the stored registry secret (a push-scoped token), else the host's docker login, else
/// anonymously.
pub fn push_v2(reference: &str, payload: &artifact::Payload, logins: Logins) -> Result<Vec<u8>> {
    let r = tagged_reference(reference)?;
    let created = humantime::format_rfc3339_seconds(std::time::SystemTime::now()).to_string();
    let (manifest, blobs) = artifact::manifest(payload, &created);
    with_client(&r, logins, RegistryOperation::Push, async |client| {
        for (d, bytes) in blobs {
            client
                .push_blob(&r, bytes, &d)
                .await
                .with_context(|| format!("pushing blob {d}"))?;
        }
        client
            .push_manifest_raw(
                &r,
                manifest.clone(),
                HeaderValue::from_static(OCI_IMAGE_MEDIA_TYPE),
            )
            .await
            .with_context(|| format!("pushing the manifest of {reference}"))?;
        Ok(())
    })?;
    Ok(manifest)
}

/// Runs F with a client logged in to R\'s registry for OP: with the stored registry secret (a
/// token scoped to OP), else the host\'s docker login, else anonymously.
fn with_client<T>(
    r: &Reference,
    logins: Logins,
    op: RegistryOperation,
    f: impl AsyncFnOnce(&Client) -> Result<T>,
) -> Result<T> {
    let stored = match op {
        RegistryOperation::Push => logins.push_auth(r.registry(), r.repository()),
        RegistryOperation::Pull => logins.auth_for(r.registry(), r.repository()),
    }
    .with_context(|| format!("logging in to {} with its registry secret", r.registry()))?;
    let auth = stored
        .or_else(|| docker_auth(r.resolve_registry()))
        .unwrap_or(RegistryAuth::Anonymous);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("starting the registry client")?;
    let client = new_client(r);
    rt.block_on(async {
        client
            .auth(r, &auth, op)
            .await
            .with_context(|| format!("logging in to {}", r.registry()))?;
        f(&client).await
    })
}

const SIGNATURE_ARTIFACT: &str = "application/vnd.docker.sandbox.kit.signature.v1";
const BUNDLE_MEDIA_TYPE: &str = "application/vnd.dev.sigstore.bundle.v0.3+json";

/// The bytes and digest of the v2 kit manifest REF names, as `kit sign` and `kit verify` read it.
pub fn manifest_of(reference: &str, cache: &Path, logins: Logins) -> Result<(Vec<u8>, String)> {
    let f = fetch_ref(reference, cache, false, false, logins)?;
    payload_layer(&serde_json::from_slice(&f.manifest)?, reference)?;
    Ok((f.manifest, f.digest))
}

/// sbx\'s signature referrer: the bundle as its one layer, the kit manifest as its subject.
fn signature_manifest(
    subject: &Value,
    bundle_digest: &str,
    bundle_len: usize,
    created: &str,
) -> Value {
    json!({
        "schemaVersion": 2,
        "mediaType": OCI_IMAGE_MEDIA_TYPE,
        "artifactType": SIGNATURE_ARTIFACT,
        "config": {
            "mediaType": EMPTY_MEDIA_TYPE,
            "digest": sha256_digest(b"{}"),
            "size": 2,
            "data": STANDARD.encode(b"{}"),
        },
        "layers": [{"mediaType": BUNDLE_MEDIA_TYPE, "digest": bundle_digest, "size": bundle_len}],
        "subject": subject,
        "annotations": {"org.opencontainers.image.created": created},
    })
}

/// The referrers tag-schema index with DESCRIPTOR added (once). An index that isn't one is
/// refused rather than replaced: it holds other referrers.
fn add_to_referrers_index(index: Option<Value>, descriptor: Value) -> Result<Value> {
    let mut index = index.unwrap_or_else(
        || json!({"schemaVersion": 2, "mediaType": OCI_IMAGE_INDEX_MEDIA_TYPE, "manifests": []}),
    );
    let Some(list) = index["manifests"].as_array_mut() else {
        bail!("the referrers index has no manifest list; it was left as it is");
    };
    if !list.iter().any(|m| m["digest"] == descriptor["digest"]) {
        list.push(descriptor);
    }
    Ok(index)
}

/// Whether E means the manifest isn't there, rather than that it couldn't be read.
fn is_not_found(e: &OciDistributionError) -> bool {
    match e {
        OciDistributionError::ImageManifestNotFoundError(_)
        | OciDistributionError::ServerError { code: 404, .. } => true,
        OciDistributionError::RegistryError { envelope, .. } => envelope.errors.iter().any(|x| {
            matches!(
                x.code,
                OciErrorCode::ManifestUnknown | OciErrorCode::NameUnknown
            )
        }),
        _ => false,
    }
}

/// Attaches BUNDLE to the kit MANIFEST at REF as a signature referrer. A registry without the
/// referrers API gets the tag-schema index (`sha256-<hex>`) too.
pub fn push_signature(
    reference: &str,
    manifest: &[u8],
    bundle: &[u8],
    logins: Logins,
) -> Result<()> {
    let r: Reference = reference
        .parse()
        .with_context(|| format!("invalid reference: {reference}"))?;
    let subject_digest = sha256_digest(manifest);
    let media_type = serde_json::from_slice::<Value>(manifest)?["mediaType"]
        .as_str()
        .unwrap_or(OCI_IMAGE_MEDIA_TYPE)
        .to_string();
    let subject =
        json!({"mediaType": media_type, "digest": subject_digest, "size": manifest.len()});
    let created = humantime::format_rfc3339_seconds(std::time::SystemTime::now()).to_string();
    let bundle_digest = sha256_digest(bundle);
    let sig = serde_json::to_vec(&signature_manifest(
        &subject,
        &bundle_digest,
        bundle.len(),
        &created,
    ))?;
    let sig_digest = sha256_digest(&sig);
    let at = |d: &str| Reference::with_digest(r.registry().into(), r.repository().into(), d.into());
    with_client(&r, logins, RegistryOperation::Push, async |client| {
        client
            .push_blob(&r, b"{}".to_vec(), &sha256_digest(b"{}"))
            .await?;
        client
            .push_blob(&r, bundle.to_vec(), &bundle_digest)
            .await?;
        client
            .push_manifest_raw(
                &at(&sig_digest),
                sig.clone(),
                HeaderValue::from_static(OCI_IMAGE_MEDIA_TYPE),
            )
            .await
            .context("pushing the signature")?;
        let listed = client.pull_referrers(&at(&subject_digest), None).await?;
        if listed.manifests.iter().any(|m| m.digest == sig_digest) {
            return Ok(());
        }
        // No referrers API: keep the tag-schema index, as oras (and so sbx) reads it.
        let tag = Reference::with_tag(
            r.registry().into(),
            r.repository().into(),
            subject_digest.replace(':', "-"),
        );
        let accepted = [OCI_IMAGE_INDEX_MEDIA_TYPE];
        let existing = match client
            .pull_manifest_raw(&tag, &RegistryAuth::Anonymous, &accepted)
            .await
        {
            Ok((bytes, _)) => {
                Some(serde_json::from_slice(&bytes).context("reading the referrers index")?)
            }
            Err(e) if is_not_found(&e) => None,
            // Replacing an index that couldn't be read would drop the referrers in it.
            Err(e) => return Err(e).context("reading the referrers index"),
        };
        let descriptor = json!({
            "mediaType": OCI_IMAGE_MEDIA_TYPE,
            "artifactType": SIGNATURE_ARTIFACT,
            "digest": sig_digest,
            "size": sig.len(),
            "annotations": {"org.opencontainers.image.created": created},
        });
        let index = serde_json::to_vec(&add_to_referrers_index(existing, descriptor)?)?;
        client
            .push_manifest_raw(
                &tag,
                index,
                HeaderValue::from_static(OCI_IMAGE_INDEX_MEDIA_TYPE),
            )
            .await
            .context("pushing the referrers index")?;
        Ok(())
    })
}

/// The signature bundles attached to the kit manifest DIGEST at REF.
pub fn signatures_of(reference: &str, digest: &str, logins: Logins) -> Result<Vec<Vec<u8>>> {
    let r: Reference = reference
        .parse()
        .with_context(|| format!("invalid reference: {reference}"))?;
    let at = |d: &str| Reference::with_digest(r.registry().into(), r.repository().into(), d.into());
    with_client(&r, logins, RegistryOperation::Pull, async |client| {
        let index = client
            .pull_referrers(&at(digest), Some(SIGNATURE_ARTIFACT))
            .await?;
        let mut bundles = Vec::new();
        for entry in index.manifests {
            let (bytes, _) = client
                .pull_manifest_raw(
                    &at(&entry.digest),
                    &RegistryAuth::Anonymous,
                    &[OCI_IMAGE_MEDIA_TYPE],
                )
                .await?;
            let m: Value = serde_json::from_slice(&bytes)?;
            if m["artifactType"] != SIGNATURE_ARTIFACT {
                continue;
            }
            for layer in m["layers"].as_array().into_iter().flatten() {
                if layer["mediaType"] != BUNDLE_MEDIA_TYPE {
                    continue;
                }
                let d = layer["digest"]
                    .as_str()
                    .context("a bundle layer has no digest")?;
                let mut out = Vec::new();
                client.pull_blob(&at(digest), d, &mut out).await?;
                if sha256_digest(&out) != d {
                    bail!("signature bundle {d} doesn\'t match its digest");
                }
                bundles.push(out);
            }
        }
        Ok(bundles)
    })
}

/// `kit pull`: the payload of the v2 kit at REF, its files layer (an empty tar.gz when it has
/// none), as sbx saves it.
pub fn fetch_payload(reference: &str, cache: &Path, logins: Logins) -> Result<Vec<u8>> {
    let f = fetch_ref(reference, cache, false, false, logins)?;
    let manifest: Value = serde_json::from_slice(&f.manifest)?;
    let Some(layer) = payload_layer(&manifest, reference)? else {
        return artifact::empty_files_layer();
    };
    fetch_ref(reference, cache, false, true, logins)?;
    let path = blob_path(cache, &layer)?;
    fs::read(&path).with_context(|| format!("reading {}", path.display()))
}

/// The files layer digest of a v2 kit artifact, `None` when it has no files; any other manifest
/// is refused.
fn payload_layer(manifest: &Value, what: &str) -> Result<Option<String>> {
    if manifest["artifactType"] != artifact::KIT_V2_ARTIFACT {
        bail!("{what} is not a v2 kit artifact");
    }
    Ok(v2_spec(manifest, what)?.and_then(|(_, files)| files))
}

/// `kit pull`'s default file name: the repository's last part and the tag (or the digest's
/// first 12 hex digits), `.tar.gz`.
pub fn pull_name(reference: &str) -> String {
    let Ok(r) = reference.parse::<Reference>() else {
        return "kit.tar.gz".into();
    };
    let repo = r.repository().rsplit('/').next().unwrap_or("kit");
    let version: String = match r.digest() {
        Some(d) => d.trim_start_matches("sha256:").chars().take(12).collect(),
        None => r.tag().unwrap_or("latest").into(),
    };
    format!("{repo}-{version}.tar.gz")
}

/// REF parsed for a push, which needs a tag written out (`Reference` would default it to
/// `latest`) and no digest.
pub(crate) fn tagged_reference(reference: &str) -> Result<Reference> {
    let name = reference.rsplit('/').next().unwrap_or_default();
    if reference.contains('@') || !name.contains(':') {
        bail!("invalid reference: {reference} needs a tag (registry/repo:tag)");
    }
    trust::normalise(reference)?;
    reference
        .parse()
        .with_context(|| format!("invalid reference: {reference}"))
}

/// The ring provider is installed once; reqwest's no-provider rustls build needs a default.
/// TLS roots come from the OS verifier (rustls-platform-verifier), not a bundled list.
fn new_client(r: &Reference) -> Client {
    // Err means a provider is already installed, which is fine.
    let _ = rustls::crypto::ring::default_provider().install_default();
    Client::new(ClientConfig {
        protocol: protocol_for(r),
        ..ClientConfig::default()
    })
}

/// Like Docker, a loopback registry (`localhost`, `127.0.0.0/8`, `[::1]`, any port) is spoken to
/// over plain HTTP; every other registry is HTTPS only.
fn protocol_for(r: &Reference) -> ClientProtocol {
    // oci-client matches the exception against `resolve_registry()` verbatim.
    let registry = r.resolve_registry();
    if is_loopback(registry) {
        ClientProtocol::HttpsExcept(vec![registry.to_string()])
    } else {
        ClientProtocol::Https
    }
}

/// REGISTRY is `host[:port]`; the host is compared lowercased, as `trust::normalise` does.
pub(crate) fn is_loopback(registry: &str) -> bool {
    let registry = registry.to_ascii_lowercase();
    let port_ok = |p: &str| p.is_empty() || p.bytes().all(|c| c.is_ascii_digit());
    if let Some(rest) = registry.strip_prefix('[') {
        let Some((host, tail)) = rest.split_once(']') else {
            return false;
        };
        let port = match tail.strip_prefix(':') {
            Some(p) if !p.is_empty() => p,
            Some(_) => return false,
            None if tail.is_empty() => "",
            None => return false,
        };
        return port_ok(port) && host.parse::<Ipv6Addr>().is_ok_and(|ip| ip.is_loopback());
    }
    let (host, port) = match registry.split_once(':') {
        Some((h, p)) if !p.is_empty() => (h, p),
        Some(_) => return false,
        None => (registry.as_str(), ""),
    };
    port_ok(port)
        && (host == "localhost" || host.parse::<Ipv4Addr>().is_ok_and(|ip| ip.is_loopback()))
}

fn is_auth_error(e: &anyhow::Error) -> bool {
    e.chain()
        .any(|c| match c.downcast_ref::<OciDistributionError>() {
            Some(OciDistributionError::AuthenticationFailure(_))
            | Some(OciDistributionError::UnauthorizedError { .. }) => true,
            Some(OciDistributionError::ServerError { code, .. }) => matches!(code, 401 | 403),
            _ => false,
        })
}

struct Fetched {
    manifest: Vec<u8>,
    digest: String,
}

async fn fetch(
    client: &Client,
    r: &Reference,
    auth: &RegistryAuth,
    cache: &Path,
    require_kit: bool,
    layers: bool,
) -> Result<Fetched> {
    let (mut bytes, mut digest) = fetch_manifest(client, r, auth).await?;
    let mut r = r.clone();
    let mut manifest: Value = serde_json::from_slice(&bytes).context("reading the manifest")?;
    if manifest.get("manifests").is_some() {
        // A multi-platform index: the kit annotation lives on the manifest for this host.
        let d = pick_platform(&manifest, host_arch()?)?;
        r = Reference::with_digest(r.registry().into(), r.repository().into(), d);
        (bytes, digest) = fetch_manifest(client, &r, auth).await?;
        manifest = serde_json::from_slice(&bytes).context("reading the manifest")?;
    }
    if require_kit && v2_spec(&manifest, &r.whole())?.is_none() {
        kit_descriptor(&manifest, &r.whole())?;
    }
    let store = store_dir(cache);
    fs::create_dir_all(&store).with_context(|| format!("creating {}", store.display()))?;
    put_bytes(cache, &digest, &bytes)?;
    // The config comes first.
    let blobs = blob_digests(&manifest)?;
    let wanted = if layers { blobs.len() } else { 1 };
    for d in &blobs[..wanted] {
        fetch_blob(client, &r, d, cache).await?;
    }
    Ok(Fetched {
        manifest: bytes,
        digest,
    })
}

async fn fetch_manifest(
    client: &Client,
    r: &Reference,
    auth: &RegistryAuth,
) -> Result<(Vec<u8>, String)> {
    let accept = [
        OCI_IMAGE_MEDIA_TYPE,
        OCI_IMAGE_INDEX_MEDIA_TYPE,
        IMAGE_MANIFEST_MEDIA_TYPE,
        IMAGE_MANIFEST_LIST_MEDIA_TYPE,
    ];
    let (bytes, _) = client
        .pull_manifest_raw(r, auth, &accept)
        .await
        .with_context(|| format!("pulling the manifest of {}", r.whole()))?;
    // Hash the bytes ourselves rather than trust the registry's header.
    let digest = sha256_digest(&bytes);
    if let Some(want) = r.digest()
        && want != digest
    {
        bail!("the registry returned manifest {digest} for {want}");
    }
    Ok((bytes.to_vec(), digest))
}

fn host_arch() -> Result<&'static str> {
    match std::env::consts::ARCH {
        "aarch64" => Ok("arm64"),
        "x86_64" => Ok("amd64"),
        other => bail!("no kit images for architecture {other}"),
    }
}

/// Digest of the `linux/<arch>` manifest in an image index.
fn pick_platform(index: &Value, arch: &str) -> Result<String> {
    let entries = index["manifests"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    for e in entries {
        let p = &e["platform"];
        if p["os"] == "linux" && p["architecture"] == arch {
            let d = e["digest"].as_str().unwrap_or_default();
            hex_of(d)?;
            return Ok(d.to_string());
        }
    }
    bail!("the image has no linux/{arch} manifest")
}

/// Config, then layer digests, of an image manifest.
fn blob_digests(manifest: &Value) -> Result<Vec<String>> {
    let mut out = vec![
        manifest["config"]["digest"]
            .as_str()
            .ok_or_else(|| anyhow!("the manifest has no config"))?
            .to_string(),
    ];
    for l in manifest["layers"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or(&[])
    {
        out.push(
            l["digest"]
                .as_str()
                .ok_or_else(|| anyhow!("a layer has no digest"))?
                .to_string(),
        );
    }
    for d in &out {
        hex_of(d)?;
    }
    Ok(out)
}

/// The descriptor JSON in the manifest annotation.
/// A published v2 kit's spec digest (its config) and files layer digest (`None` for the empty
/// layer), or None for any other manifest.
fn v2_spec(manifest: &Value, what: &str) -> Result<Option<(String, Option<String>)>> {
    if manifest["config"]["mediaType"] != V2_SPEC_MEDIA_TYPE {
        return Ok(None);
    }
    let mut files = None;
    for l in manifest["layers"].as_array().map_or(&[][..], Vec::as_slice) {
        match l["mediaType"].as_str().unwrap_or_default() {
            EMPTY_MEDIA_TYPE => {}
            V2_FILES_MEDIA_TYPE if files.is_none() => {
                files = Some(
                    l["digest"]
                        .as_str()
                        .context("a layer has no digest")?
                        .to_string(),
                );
            }
            other => bail!("{what} is a v2 kit with a layer of type {other}"),
        }
    }
    let digest = manifest["config"]["digest"].as_str();
    Ok(Some((
        digest.context("the manifest has no config")?.to_string(),
        files,
    )))
}

/// Unpacks a v2 kit's files layer into `dir/files` once; later reads reuse it.
fn unpack_v2_files(dir: &Path, layer: &[u8]) -> Result<()> {
    if dir.join("files").is_dir() {
        return Ok(());
    }
    let tmp = tempfile::tempdir_in(dir)?;
    crate::kits::artifact::unpack_files(layer, tmp.path())?;
    match fs::rename(tmp.path().join("files"), dir.join("files")) {
        // Another process unpacked it first.
        Err(_) if dir.join("files").is_dir() => Ok(()),
        r => r.context("unpacking the kit's files"),
    }
}

fn kit_descriptor(manifest: &Value, what: &str) -> Result<String> {
    let ann = &manifest["annotations"];
    let Some(desc) = ann[DESCRIPTOR_ANNOTATION].as_str() else {
        bail!("{what} is not a kit: the image has no {DESCRIPTOR_ANNOTATION} annotation");
    };
    if let Some(v) = ann[SCHEMA_ANNOTATION].as_str()
        && v != "3"
    {
        bail!("{what} has kit schema version {v}; only 3 is supported");
    }
    Ok(desc.to_string())
}

/// `<hex>` of a `sha256:<hex>` digest. Digests become file names, so anything else is refused.
pub(crate) fn hex_of(digest: &str) -> Result<&str> {
    digest
        .strip_prefix("sha256:")
        .filter(|h| h.len() == 64 && h.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')))
        .ok_or_else(|| anyhow!("unsupported digest '{digest}'"))
}

/// Renames a finished temp file to `path`.
pub(crate) fn persist(tmp: tempfile::NamedTempFile, path: &Path) -> Result<()> {
    tmp.persist(path)
        .map_err(|e| e.error)
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

pub(crate) fn store_dir(cache: &Path) -> PathBuf {
    cache.join("blobs").join("sha256")
}

fn blob_path(cache: &Path, digest: &str) -> Result<PathBuf> {
    Ok(store_dir(cache).join(hex_of(digest)?))
}

/// Stores a blob whose digest the caller computed (the manifest).
pub(crate) fn put_bytes(cache: &Path, digest: &str, data: &[u8]) -> Result<()> {
    let path = blob_path(cache, digest)?;
    if path.exists() {
        return Ok(());
    }
    let mut tmp = tempfile::NamedTempFile::new_in(store_dir(cache))?;
    tmp.write_all(data)?;
    persist(tmp, &path)?;
    Ok(())
}

/// Hashes everything written through it, so a blob is verified as it lands.
struct HashingFile {
    file: fs::File,
    hasher: Sha256,
}

impl AsyncWrite for HashingFile {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        // Blocking writes are fine: the runtime has nothing else to run.
        let n = match this.file.write(buf) {
            Ok(n) => n,
            Err(e) => return Poll::Ready(Err(e)),
        };
        this.hasher.update(&buf[..n]);
        Poll::Ready(Ok(n))
    }

    fn poll_flush(mut self: Pin<&mut Self>, _: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(self.file.flush())
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// Downloads a blob into the store unless it is already there. It lands in a temp file in the
/// store and is renamed only once its sha256 matches.
async fn fetch_blob(client: &Client, r: &Reference, digest: &str, cache: &Path) -> Result<()> {
    let path = blob_path(cache, digest)?;
    if path.exists() {
        return Ok(());
    }
    let tmp = tempfile::NamedTempFile::new_in(store_dir(cache))?;
    let mut out = HashingFile {
        file: tmp.reopen()?,
        hasher: Sha256::new(),
    };
    client
        .pull_blob(r, digest, &mut out)
        .await
        .with_context(|| format!("pulling blob {digest}"))?;
    let got = format!("sha256:{}", hex(&out.hasher.finalize()));
    if got != digest {
        bail!("blob {digest} downloaded as {got}");
    }
    persist(tmp, &path)?;
    Ok(())
}

/// Assembles `<cache>/oci/<manifest hex>/` from blobs already in the store.
fn build_layout(cache: &Path, manifest: &[u8], digest: &str, reference: &str) -> Result<PathBuf> {
    let hexd = hex_of(digest)?;
    let value: Value = serde_json::from_slice(manifest)?;
    let dir = cache.join("oci").join(hexd);
    let blobs = dir.join("blobs").join("sha256");
    fs::create_dir_all(&blobs).with_context(|| format!("creating {}", blobs.display()))?;
    let mut all = vec![digest.to_string()];
    all.extend(blob_digests(&value)?);
    for d in &all {
        let dst = blobs.join(hex_of(d)?);
        if dst.exists() {
            continue;
        }
        let src = blob_path(cache, d)?;
        // Hard links keep one copy per blob; copy when the store is on another device, via a
        // temp file so an interrupted copy never leaves a short blob under its digest.
        if fs::hard_link(&src, &dst).is_err() {
            let tmp = tempfile::NamedTempFile::new_in(&blobs)?;
            fs::copy(&src, tmp.path()).with_context(|| format!("copying {}", src.display()))?;
            tmp.as_file().sync_all()?;
            persist(tmp, &dst)?;
        }
    }
    fs::write(dir.join("oci-layout"), r#"{"imageLayoutVersion":"1.0.0"}"#)?;
    let mut annotations = value["annotations"]
        .as_object()
        .cloned()
        .unwrap_or_default();
    annotations.insert(REF_NAME_ANNOTATION.into(), json!(reference));
    let index = json!({
        "schemaVersion": 2,
        "manifests": [{
            "mediaType": value["mediaType"].as_str().unwrap_or(OCI_IMAGE_MEDIA_TYPE),
            "digest": digest,
            "size": manifest.len(),
            "annotations": annotations,
        }],
    });
    let tmp = tempfile::NamedTempFile::new_in(&dir)?;
    fs::write(tmp.path(), serde_json::to_vec(&index)?)?;
    let target = dir.join("index.json");
    persist(tmp, &target)?;
    Ok(dir)
}

/// Reads a kit from an OCI layout directory: the descriptor from the manifest annotation, the
/// command, user and working directory from the image config. Also used for local builds, with their own `source`.
pub fn read_layout(dir: &Path, source: Source) -> Result<Kit> {
    let what = match &source {
        Source::Registry(r) | Source::Preset(r) => r.clone(),
        Source::Builtin(n) => format!("builtin:{n}"),
        Source::LocalV3(p) | Source::LocalV2(p) | Source::Smolfile(p) => p.display().to_string(),
    };
    let read = |p: PathBuf| fs::read(&p).with_context(|| format!("reading {}", p.display()));
    let index: Value = serde_json::from_slice(&read(dir.join("index.json"))?)
        .context("reading the layout's index.json")?;
    let digest = index["manifests"][0]["digest"]
        .as_str()
        .ok_or_else(|| anyhow!("the layout in {} has no manifest", dir.display()))?
        .to_string();
    let blobs = dir.join("blobs").join("sha256");
    let bytes = read(blobs.join(hex_of(&digest)?))?;
    if sha256_digest(&bytes) != digest {
        bail!("manifest {digest} in {} is corrupt", dir.display());
    }
    let manifest: Value = serde_json::from_slice(&bytes).context("reading the manifest")?;
    if let Some((spec, files)) = v2_spec(&manifest, &what)? {
        if let Some(files) = files {
            let layer = read(blobs.join(hex_of(&files)?))?;
            if sha256_digest(&layer) != files {
                bail!("layer {files} in {} is corrupt", dir.display());
            }
            unpack_v2_files(dir, &layer).with_context(|| format!("reading the v2 kit {what}"))?;
        }
        let yaml = String::from_utf8(read(blobs.join(hex_of(&spec)?))?)
            .context("reading the v2 kit's spec")?;
        let mut kit = crate::kits::v2::parse(&yaml, dir)
            .with_context(|| format!("reading the v2 kit {what}"))?;
        // Its image is named in the spec (`Content::Image`) and pulled when a sandbox is made.
        kit.source = source;
        kit.digest = Some(digest);
        return Ok(kit);
    }
    let descriptor = kit_descriptor(&manifest, &what)?;
    let mut kit = v3::parse_json(&descriptor, source)?;
    let config_digest = manifest["config"]["digest"]
        .as_str()
        .ok_or_else(|| anyhow!("the manifest has no config"))?;
    let config: Value = serde_json::from_slice(&read(blobs.join(hex_of(config_digest)?))?)
        .context("reading the image config")?;
    kit.command = command_of(&config);
    let text = |k: &str| config["config"][k].as_str().unwrap_or_default().to_string();
    kit.config = Some(ImageConfig {
        user: text("User"),
        workdir: text("WorkingDir"),
    });
    kit.digest = Some(digest);
    kit.content = Content::Oci(dir.to_path_buf());
    Ok(kit)
}

/// Entrypoint+Cmd of a plain image's config, for a v2 workload that declares no command. An image
/// already in the cache (`pull_image`) answers offline; otherwise only its manifest and config
/// are fetched.
pub fn image_command(reference: &str, cache: &Path, logins: Logins) -> Result<Option<Vec<String>>> {
    Ok(command_of(&image_config(reference, cache, logins)?))
}

/// The image's `KEY=VALUE` environment, read as `image_command` reads its command.
pub fn image_env(reference: &str, cache: &Path, logins: Logins) -> Result<Vec<String>> {
    Ok(env_of(&image_config(reference, cache, logins)?))
}

/// The `Env` of an image config.
pub(crate) fn env_of(config: &Value) -> Vec<String> {
    let env = config["config"]["Env"]
        .as_array()
        .map_or(&[][..], Vec::as_slice);
    env.iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect()
}

/// An image's config: from the cache when a layout for `reference` is there, else its manifest
/// and config are fetched.
fn image_config(reference: &str, cache: &Path, logins: Logins) -> Result<Value> {
    let blobs = store_dir(cache);
    let read_json = |p: PathBuf| -> Result<Value> {
        let bytes = fs::read(&p).with_context(|| format!("reading {}", p.display()))?;
        serde_json::from_slice(&bytes).with_context(|| format!("reading {}", p.display()))
    };
    let manifest_digest = match cached_manifest(reference, cache) {
        Some(d) => d,
        None => {
            fetch_ref(reference, cache, false, false, logins)
                .with_context(|| format!("reading the image config of {reference}"))?
                .digest
        }
    };
    let manifest = read_json(blobs.join(hex_of(&manifest_digest)?))?;
    let config_digest = manifest["config"]["digest"]
        .as_str()
        .ok_or_else(|| anyhow!("the manifest of {reference} has no config"))?;
    read_json(blobs.join(hex_of(config_digest)?))
}

/// The manifest digest of a layout in the cache made for `reference`.
fn cached_manifest(reference: &str, cache: &Path) -> Option<String> {
    fs::read_dir(cache.join("oci")).ok()?.find_map(|e| {
        let index: Value =
            serde_json::from_slice(&fs::read(e.ok()?.path().join("index.json")).ok()?).ok()?;
        let m = &index["manifests"][0];
        (m["annotations"][REF_NAME_ANNOTATION].as_str() == Some(reference))
            .then(|| m["digest"].as_str().map(String::from))
            .flatten()
    })
}

/// An image config's Entrypoint then Cmd; `None` when both are empty.
fn command_of(config: &Value) -> Option<Vec<String>> {
    let words = |k: &str| -> Vec<String> {
        config["config"][k]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default()
    };
    let mut command = words("Entrypoint");
    command.extend(words("Cmd"));
    (!command.is_empty()).then_some(command)
}

fn docker_config_dir() -> Option<PathBuf> {
    std::env::var_os("DOCKER_CONFIG")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".docker")))
}

/// Credentials from the host's docker login, if any. Read-only; values are never logged.
fn docker_auth(host: &str) -> Option<RegistryAuth> {
    let text = fs::read_to_string(docker_config_dir()?.join("config.json")).ok()?;
    auth_from_config(&text, host, &credential_helper)
}

/// Docker Hub's entry is keyed by its legacy URL.
fn config_keys(host: &str) -> Vec<String> {
    if host == "index.docker.io" || host == "docker.io" {
        return vec![
            "https://index.docker.io/v1/".into(),
            "index.docker.io".into(),
        ];
    }
    vec![
        host.to_string(),
        format!("https://{host}"),
        format!("https://{host}/"),
    ]
}

fn auth_from_config(
    text: &str,
    host: &str,
    helper: &dyn Fn(&str, &str) -> Option<RegistryAuth>,
) -> Option<RegistryAuth> {
    let cfg: Value = serde_json::from_str(text).ok()?;
    let keys = config_keys(host);
    for k in &keys {
        let e = &cfg["auths"][k.as_str()];
        if let Some(t) = e["identitytoken"].as_str().filter(|t| !t.is_empty()) {
            return Some(RegistryAuth::Bearer(t.to_string()));
        }
        if let Some(a) = e["auth"].as_str().filter(|a| !a.is_empty()) {
            let raw = String::from_utf8(STANDARD.decode(a.trim()).ok()?).ok()?;
            let (user, pass) = raw.split_once(':')?;
            return Some(RegistryAuth::Basic(user.into(), pass.into()));
        }
    }
    let name = keys
        .iter()
        .find_map(|k| cfg["credHelpers"][k.as_str()].as_str())
        .or_else(|| cfg["credsStore"].as_str())?;
    // Docker Hub helpers are asked by its legacy URL, other registries by host.
    let server = keys.first().map(String::as_str).unwrap_or(host);
    helper(name, server)
}

/// Runs `docker-credential-<name> get`, only when that binary is on PATH.
fn credential_helper(name: &str, server: &str) -> Option<RegistryAuth> {
    if name.is_empty() || name.contains(['/', '\\']) {
        return None;
    }
    let bin = format!("docker-credential-{name}");
    let path = std::env::var_os("PATH")?;
    if !std::env::split_paths(&path).any(|d| d.join(&bin).is_file()) {
        return None;
    }
    let mut child = Command::new(&bin)
        .arg("get")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    child.stdin.take()?.write_all(server.as_bytes()).ok()?;
    let out = child.wait_with_output().ok()?;
    if !out.status.success() {
        return None;
    }
    let v: Value = serde_json::from_slice(&out.stdout).ok()?;
    let user = v["Username"].as_str()?;
    let secret = v["Secret"].as_str()?;
    // Helpers return identity tokens under this sentinel user name.
    if user == "<token>" {
        Some(RegistryAuth::Bearer(secret.into()))
    } else {
        Some(RegistryAuth::Basic(user.into(), secret.into()))
    }
}

#[cfg(test)]
pub(crate) mod fixtures {
    use super::*;

    /// A plain image (no kit annotation) in the kit cache as `reference`, as `pull_image` leaves
    /// it; returns its layout directory.
    pub fn cached_image(cache: &Path, reference: &str, config_json: &str) -> PathBuf {
        let tmp = tempfile::tempdir().unwrap();
        let digest = oci_layout(tmp.path(), None, &[], config_json);
        fs::create_dir_all(store_dir(cache)).unwrap();
        for e in fs::read_dir(store_dir(tmp.path())).unwrap() {
            let data = fs::read(e.unwrap().path()).unwrap();
            put_bytes(cache, &sha256_digest(&data), &data).unwrap();
        }
        let manifest = fs::read(store_dir(tmp.path()).join(hex_of(&digest).unwrap())).unwrap();
        build_layout(cache, &manifest, &digest, reference).unwrap()
    }

    /// Writes a one-manifest OCI layout into `dir`; returns the manifest digest.
    pub fn oci_layout(
        dir: &Path,
        annotation_json: Option<&str>,
        layers: &[&[u8]],
        config_json: &str,
    ) -> String {
        let blobs = dir.join("blobs").join("sha256");
        fs::create_dir_all(&blobs).unwrap();
        let put = |data: &[u8]| {
            let d = sha256_digest(data);
            fs::write(blobs.join(hex_of(&d).unwrap()), data).unwrap();
            d
        };
        let config = put(config_json.as_bytes());
        let layer_descs: Vec<Value> = layers
            .iter()
            .map(|l| {
                json!({"mediaType": "application/vnd.oci.image.layer.v1.tar",
                            "digest": put(l), "size": l.len()})
            })
            .collect();
        let mut manifest = json!({
            "schemaVersion": 2,
            "mediaType": OCI_IMAGE_MEDIA_TYPE,
            "config": {"mediaType": "application/vnd.oci.image.config.v1+json",
                       "digest": config, "size": config_json.len()},
            "layers": layer_descs,
        });
        if let Some(a) = annotation_json {
            manifest["annotations"] = json!({DESCRIPTOR_ANNOTATION: a, SCHEMA_ANNOTATION: "3"});
        }
        let bytes = serde_json::to_vec(&manifest).unwrap();
        let digest = put(&bytes);
        fs::write(dir.join("oci-layout"), r#"{"imageLayoutVersion":"1.0.0"}"#).unwrap();
        let index = json!({"schemaVersion": 2, "manifests": [
            {"mediaType": OCI_IMAGE_MEDIA_TYPE, "digest": digest, "size": bytes.len()}]});
        fs::write(dir.join("index.json"), index.to_string()).unwrap();
        digest
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kits::model::{ImageConfig, Kind};

    const DESC: &str =
        r#"{"schemaVersion":"3","kind":"workload","version":"1.0.0","provides":["shell"]}"#;

    fn src() -> Source {
        Source::Registry("docker.io/acme/kit:1".into())
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
        let s = Source::LocalV3(d.path().to_path_buf());
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
        let index: Value =
            serde_json::from_slice(&fs::read(dir.join("index.json")).unwrap()).unwrap();
        let m = &index["manifests"][0];
        assert_eq!(m["digest"], json!(digest));
        assert_eq!(
            m["annotations"][REF_NAME_ANNOTATION],
            "docker.io/acme/kit:1"
        );
        assert_eq!(m["annotations"][SCHEMA_ANNOTATION], "3");
        #[cfg(unix)]
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
            "config": {"mediaType": V2_SPEC_MEDIA_TYPE, "digest": config, "size": spec.len()},
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
    fn the_signature_manifest_matches_sbx() {
        let subject =
            json!({"mediaType": OCI_IMAGE_MEDIA_TYPE, "digest": "sha256:aa", "size": 824});
        let m = signature_manifest(&subject, "sha256:bb", 712, "2026-11-13T00:00:00Z");
        assert_eq!(
            m,
            json!({
                "schemaVersion": 2,
                "mediaType": OCI_IMAGE_MEDIA_TYPE,
                "artifactType": "application/vnd.docker.sandbox.kit.signature.v1",
                "config": {
                    "mediaType": EMPTY_MEDIA_TYPE,
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
            "config": {"mediaType": V2_SPEC_MEDIA_TYPE, "digest": files.clone()},
            "layers": [{"mediaType": TAR_GZ, "digest": files.clone()}]});
        assert_eq!(payload_layer(&v2, "r").unwrap(), Some(files.clone()));
        let empty = json!({"artifactType": artifact::KIT_V2_ARTIFACT,
            "config": {"mediaType": V2_SPEC_MEDIA_TYPE, "digest": files},
            "layers": [{"mediaType": EMPTY_MEDIA_TYPE}]});
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
}
