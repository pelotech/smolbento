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
use std::task::{Context as TaskContext, Poll};

use anyhow::{Context, Result, anyhow, bail};
use oci_client::Reference;
use oci_client::RegistryOperation;
use oci_client::client::{Client, ClientConfig, ClientProtocol};
use oci_client::errors::OciDistributionError;
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
use crate::util::{block_on, hex, sha256_digest};

mod docker_auth;
mod signature;

use docker_auth::*;
pub use signature::*;

/// The manifest types a pull accepts: an image or an index, OCI or Docker.
const MANIFEST_TYPES: [&str; 4] = [
    OCI_IMAGE_MEDIA_TYPE,
    OCI_IMAGE_INDEX_MEDIA_TYPE,
    IMAGE_MANIFEST_MEDIA_TYPE,
    IMAGE_MANIFEST_LIST_MEDIA_TYPE,
];
const DESCRIPTOR_ANNOTATION: &str = "vnd.docker.sandbox.kit.descriptor";
const SCHEMA_ANNOTATION: &str = "vnd.docker.sandbox.kit.schema-version";
const REF_NAME_ANNOTATION: &str = "org.opencontainers.image.ref.name";
/// sbx's published kits set it to `"true"` when the image's Docker engine should start.
const START_DOCKER_ANNOTATION: &str = "com.docker.sandboxes.start-docker";

/// Fetches REF's manifest and config and its layers into the cache. A manifest without the kit
/// descriptor annotation is a plain image and an error. A DIGEST (one a signature check
/// verified) pins the fetch to that manifest; the kit's source is still REF.
pub fn pull(reference: &str, digest: Option<&str>, cache: &Path, logins: Logins) -> Result<Kit> {
    if let Some(kit) = cached(reference, digest, cache)? {
        return Ok(kit);
    }
    let pinned = digest.map(|d| pinned(reference, d)).transpose()?;
    let dir = pull_layout(pinned.as_deref().unwrap_or(reference), cache, true, logins)?;
    read_layout(&dir, Source::Registry(reference.to_string()))
}

/// A pinned kit already in the cache, read with no registry call; `None` when unpinned or not
/// cached. Layouts are named by manifest digest only, so the same content pulled from another
/// repository answers too: identical bytes, recorded here under `reference`.
pub fn cached(reference: &str, digest: Option<&str>, cache: &Path) -> Result<Option<Kit>> {
    let Some(d) = digest else {
        return Ok(None);
    };
    let dir = cache.join("oci").join(hex_of(d)?);
    if !dir.join("index.json").is_file() {
        return Ok(None);
    }
    read_layout(&dir, Source::Registry(reference.to_string())).map(Some)
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
    let r = parse_ref(reference)?;
    let client = new_client(&r);
    // A stored registry secret (`bento secret set --registry`) is used instead of anonymous.
    let stored = logins
        .auth_for(r.registry(), r.repository())
        .with_context(|| format!("logging in to {} with its registry secret", r.registry()))?;
    block_on("registry client", async {
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

/// Runs F with a client logged in to R's registry for OP: with the stored registry secret (a
/// token scoped to OP), else the host's docker login, else anonymously.
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
    let client = new_client(r);
    block_on("registry client", async {
        client
            .auth(r, &auth, op)
            .await
            .with_context(|| format!("logging in to {}", r.registry()))?;
        f(&client).await
    })
}

/// The manifest a signature on REF covers, as `kit sign` and `kit verify` read it: the one REF
/// resolves to (an index stays an index, as `kit.requireSignature` checks it), and a plain
/// manifest must be a v2 kit artifact.
pub fn kit_manifest(reference: &str, logins: Logins) -> Result<(Vec<u8>, String)> {
    let (bytes, digest) = top_manifest(reference, logins)?;
    let m: Value = serde_json::from_slice(&bytes)?;
    if m.get("manifests").is_none() {
        payload_layer(&m, reference)?;
    }
    Ok((bytes, digest))
}

/// REF pinned to DIGEST (`registry/repo@sha256:…`), so a pull gets exactly what was verified.
fn pinned(reference: &str, digest: &str) -> Result<String> {
    let r = parse_ref(reference)?;
    hex_of(digest)?;
    Ok(format!("{}/{}@{digest}", r.registry(), r.repository()))
}

fn parse_ref(reference: &str) -> Result<Reference> {
    reference
        .parse()
        .with_context(|| format!("invalid kit reference '{reference}'"))
}

/// The bytes and digest of the manifest REF resolves to, an index left as it is: what a
/// signature on REF covers.
pub fn top_manifest(reference: &str, logins: Logins) -> Result<(Vec<u8>, String)> {
    let r = parse_ref(reference)?;
    with_client(&r, logins, RegistryOperation::Pull, async |client| {
        let (bytes, digest) = client
            .pull_manifest_raw(&r, &RegistryAuth::Anonymous, &MANIFEST_TYPES)
            .await
            .with_context(|| format!("pulling the manifest of {reference}"))?;
        Ok((bytes.to_vec(), digest))
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
    parse_ref(reference)
}

/// The ring provider is installed once; reqwest's no-provider rustls build needs a default.
/// TLS roots come from the OS verifier (rustls-platform-verifier), not a bundled list.
fn new_client(r: &Reference) -> Client {
    // Built before `block_on` installs it. Err means a provider is already installed.
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
    let (bytes, _) = client
        .pull_manifest_raw(r, auth, &MANIFEST_TYPES)
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
pub(crate) fn blob_digests(manifest: &Value) -> Result<Vec<String>> {
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

/// A published v2 kit's spec digest (its config) and files layer digest (`None` for the empty
/// layer), or None for any other manifest.
fn v2_spec(manifest: &Value, what: &str) -> Result<Option<(String, Option<String>)>> {
    if manifest["config"]["mediaType"] != artifact::V2_SPEC_MEDIA_TYPE {
        return Ok(None);
    }
    let mut files = None;
    for l in manifest["layers"].as_array().map_or(&[][..], Vec::as_slice) {
        match l["mediaType"].as_str().unwrap_or_default() {
            artifact::EMPTY_MEDIA_TYPE => {}
            artifact::V2_FILES_MEDIA_TYPE if files.is_none() => {
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

/// The descriptor JSON in the manifest annotation.
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

/// The `blobs/sha256` directory of the cache's store or of a layout.
pub(crate) fn store_dir(cache: &Path) -> PathBuf {
    cache.join("blobs").join("sha256")
}

/// The path of blob DIGEST under `store_dir`.
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
    let blobs = store_dir(&dir);
    fs::create_dir_all(&blobs).with_context(|| format!("creating {}", blobs.display()))?;
    let mut all = vec![digest.to_string()];
    all.extend(blob_digests(&value)?);
    for d in &all {
        let dst = blob_path(&dir, d)?;
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

/// An OCI image layout directory (or the cache's store) and the one manifest it names.
pub(crate) struct Layout {
    pub dir: PathBuf,
    pub digest: String,
    pub manifest: Value,
}

impl Layout {
    /// Reads `index.json` and the manifest it names.
    pub fn read(dir: &Path) -> Result<Self> {
        let index: Value = serde_json::from_slice(&read_file(&dir.join("index.json"))?)
            .context("reading the layout's index.json")?;
        let digest = index["manifests"][0]["digest"]
            .as_str()
            .ok_or_else(|| anyhow!("the layout in {} has no manifest", dir.display()))?;
        Self::at(dir, digest)
    }

    /// Reads manifest DIGEST from `dir/blobs/sha256`, refusing bytes that don't match it.
    pub fn at(dir: &Path, digest: &str) -> Result<Self> {
        let bytes = read_file(&blob_path(dir, digest)?)?;
        if sha256_digest(&bytes) != digest {
            bail!("manifest {digest} in {} is corrupt", dir.display());
        }
        Ok(Self {
            dir: dir.to_path_buf(),
            digest: digest.to_string(),
            manifest: serde_json::from_slice(&bytes).context("reading the manifest")?,
        })
    }

    /// The path of blob DIGEST in this layout.
    pub fn blob(&self, digest: &str) -> Result<PathBuf> {
        blob_path(&self.dir, digest)
    }

    /// The manifest's layer descriptors.
    pub fn layers(&self) -> &[Value] {
        self.manifest["layers"].as_array().map_or(&[], |v| v)
    }

    /// The image config as JSON, read only when asked (a v2 kit's config is YAML).
    pub fn config(&self) -> Result<Value> {
        let digest = self.manifest["config"]["digest"]
            .as_str()
            .ok_or_else(|| anyhow!("the manifest has no config"))?;
        serde_json::from_slice(&read_file(&self.blob(digest)?)?).context("reading the image config")
    }
}

/// Reads a file, naming it in the error.
fn read_file(p: &Path) -> Result<Vec<u8>> {
    fs::read(p).with_context(|| format!("reading {}", p.display()))
}

/// Reads a kit from an OCI layout directory: the descriptor from the manifest annotation, the
/// command, user and working directory from the image config. Also used for local builds, with their own `source`.
pub fn read_layout(dir: &Path, source: Source) -> Result<Kit> {
    let what = match &source {
        Source::Registry(r) | Source::Agent(r) => r.clone(),
        Source::Builtin(n) => format!("builtin:{n}"),
        Source::LocalV3(p) | Source::LocalV2(p) | Source::Smolfile(p) => p.display().to_string(),
    };
    let l = Layout::read(dir)?;
    if let Some((spec, files)) = v2_spec(&l.manifest, &what)? {
        if let Some(files) = files {
            let layer = read_file(&l.blob(&files)?)?;
            if sha256_digest(&layer) != files {
                bail!("layer {files} in {} is corrupt", dir.display());
            }
            unpack_v2_files(dir, &layer).with_context(|| format!("reading the v2 kit {what}"))?;
        }
        let yaml =
            String::from_utf8(read_file(&l.blob(&spec)?)?).context("reading the v2 kit's spec")?;
        let mut kit = crate::kits::v2::parse(&yaml, dir)
            .with_context(|| format!("reading the v2 kit {what}"))?;
        // Its image is named in the spec (`Content::Image`) and pulled when a sandbox is made.
        kit.source = source;
        kit.digest = Some(l.digest);
        return Ok(kit);
    }
    let descriptor = kit_descriptor(&l.manifest, &what)?;
    let mut kit = v3::parse(&descriptor, source)?;
    let config = l.config()?;
    kit.command = command_of(&config);
    let text = |k: &str| config["config"][k].as_str().unwrap_or_default().to_string();
    kit.config = Some(ImageConfig {
        user: text("User"),
        workdir: text("WorkingDir"),
    });
    kit.starts_docker = l.manifest["annotations"][START_DOCKER_ANNOTATION].as_str() == Some("true");
    kit.digest = Some(l.digest);
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
    let manifest_digest = match cached_manifest(reference, cache) {
        Some(d) => d,
        None => {
            fetch_ref(reference, cache, false, false, logins)
                .with_context(|| format!("reading the image config of {reference}"))?
                .digest
        }
    };
    Layout::at(cache, &manifest_digest)?.config()
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

/// Writes a one-manifest OCI layout into `dir`, with the kit descriptor `annotation_json` and
/// `extra` manifest annotations; returns the manifest digest. For tests and the agent stand-ins.
pub(crate) fn write_layout(
    dir: &Path,
    annotation_json: Option<&str>,
    extra: &[(&str, &str)],
    layers: &[&[u8]],
    config_json: &str,
) -> io::Result<String> {
    let blobs = store_dir(dir);
    fs::create_dir_all(&blobs)?;
    let put = |data: &[u8]| -> io::Result<String> {
        let d = sha256_digest(data);
        fs::write(blobs.join(d.trim_start_matches("sha256:")), data)?;
        Ok(d)
    };
    let mut layer_descs = Vec::new();
    for l in layers {
        layer_descs.push(
            json!({"mediaType": "application/vnd.oci.image.layer.v1.tar",
                                "digest": put(l)?, "size": l.len()}),
        );
    }
    let mut manifest = json!({
        "schemaVersion": 2,
        "mediaType": OCI_IMAGE_MEDIA_TYPE,
        "config": {"mediaType": "application/vnd.oci.image.config.v1+json",
                   "digest": put(config_json.as_bytes())?, "size": config_json.len()},
        "layers": layer_descs,
    });
    if let Some(a) = annotation_json {
        manifest["annotations"] = json!({DESCRIPTOR_ANNOTATION: a, SCHEMA_ANNOTATION: "3"});
    }
    for (k, v) in extra {
        manifest["annotations"][*k] = json!(v);
    }
    let bytes = manifest.to_string();
    let digest = put(bytes.as_bytes())?;
    fs::write(dir.join("oci-layout"), r#"{"imageLayoutVersion":"1.0.0"}"#)?;
    let index = json!({"schemaVersion": 2, "manifests": [
        {"mediaType": OCI_IMAGE_MEDIA_TYPE, "digest": digest, "size": bytes.len()}]});
    fs::write(dir.join("index.json"), index.to_string())?;
    Ok(digest)
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

    /// `write_layout` with only the descriptor annotation, for tests.
    pub fn oci_layout(
        dir: &Path,
        annotation_json: Option<&str>,
        layers: &[&[u8]],
        config_json: &str,
    ) -> String {
        write_layout(dir, annotation_json, &[], layers, config_json).unwrap()
    }
}

#[cfg(test)]
#[path = "registry_tests.rs"]
mod tests;
