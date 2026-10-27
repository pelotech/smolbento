//! Pulls published kits (one OCI image each) into the kit cache as OCI image layouts.
//!
//! Cache: a shared blob store `<cache>/blobs/sha256/<hex>`, and per kit `<cache>/oci/<manifest
//! hex>/` holding `oci-layout`, `index.json` and `blobs/sha256/<hex>` hard-linked into the store,
//! so smolvm can load the directory as it is. `oci-client` is async; the runtime stays in here.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::{Command, Stdio};
use std::task::{Context as TaskContext, Poll};

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use oci_client::Reference;
use oci_client::client::{Client, ClientConfig};
use oci_client::errors::OciDistributionError;
use oci_client::manifest::{
    IMAGE_MANIFEST_LIST_MEDIA_TYPE, IMAGE_MANIFEST_MEDIA_TYPE, OCI_IMAGE_INDEX_MEDIA_TYPE,
    OCI_IMAGE_MEDIA_TYPE,
};
use oci_client::secrets::RegistryAuth;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWrite;

use crate::kits::model::{Content, Kit, Source};
use crate::kits::{trust, v3};

const DESCRIPTOR_ANNOTATION: &str = "vnd.docker.sandbox.kit.descriptor";
const SCHEMA_ANNOTATION: &str = "vnd.docker.sandbox.kit.schema-version";
const REF_NAME_ANNOTATION: &str = "org.opencontainers.image.ref.name";

/// Fetches REF's manifest and config and its layers into the cache. A manifest without the kit
/// descriptor annotation is a plain image and an error.
pub fn pull(reference: &str, cache: &Path) -> Result<Kit> {
    pull_kit(reference, None, cache)
}

/// Same, pinned to a manifest digest; used again when a cache entry is missing.
pub fn pull_digest(reference: &str, digest: &str, cache: &Path) -> Result<Kit> {
    hex_of(digest)?;
    pull_kit(reference, Some(digest), cache)
}

/// Pulls a plain image (no kit annotation required) into an OCI layout; returns its directory.
pub fn pull_image(reference: &str, cache: &Path) -> Result<PathBuf> {
    pull_layout(reference, None, cache, false)
}

fn pull_kit(reference: &str, pin: Option<&str>, cache: &Path) -> Result<Kit> {
    let dir = pull_layout(reference, pin, cache, true)?;
    read_layout(&dir, Source::Registry(reference.to_string()))
}

/// Downloads REF into an OCI layout under the cache and returns its directory. With
/// `require_kit` the kit annotation is checked before any layer is fetched.
fn pull_layout(
    reference: &str,
    pin: Option<&str>,
    cache: &Path,
    require_kit: bool,
) -> Result<PathBuf> {
    // The same normaliser the trust check uses, so both read the ref alike.
    trust::normalise(reference)?;
    let mut r: Reference = reference
        .parse()
        .with_context(|| format!("invalid kit reference '{reference}'"))?;
    if let Some(d) = pin {
        r = Reference::with_digest(r.registry().into(), r.repository().into(), d.into());
    }
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("starting the registry client")?;
    let client = new_client();
    let fetched = rt.block_on(async {
        let first = fetch(&client, &r, &RegistryAuth::Anonymous, cache, require_kit).await;
        match first {
            Ok(f) => Ok(f),
            // Private images answer anonymous pulls with 401/403; only then try the docker login.
            Err(e) if is_auth_error(&e) => match docker_auth(r.resolve_registry()) {
                Some(auth) => fetch(&client, &r, &auth, cache, require_kit)
                    .await
                    .map_err(|e2| e2.context(format!("{e:#} (anonymous)"))),
                None => Err(e),
            },
            Err(e) => Err(e),
        }
    })?;
    build_layout(cache, &fetched.manifest, &fetched.digest, reference)
}

/// The ring provider is installed once; reqwest's no-provider rustls build needs a default.
/// TLS roots come from the OS verifier (rustls-platform-verifier), not a bundled list.
fn new_client() -> Client {
    // Err means a provider is already installed, which is fine.
    let _ = rustls::crypto::ring::default_provider().install_default();
    Client::new(ClientConfig::default())
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
    if require_kit {
        kit_descriptor(&manifest, &r.whole())?;
    }
    let store = store_dir(cache);
    fs::create_dir_all(&store).with_context(|| format!("creating {}", store.display()))?;
    put_bytes(cache, &digest, &bytes)?;
    for d in blob_digests(&manifest)? {
        fetch_blob(client, &r, &d, cache).await?;
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

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub(crate) fn sha256_digest(data: &[u8]) -> String {
    format!("sha256:{}", hex(&Sha256::digest(data)))
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
    tmp.persist(&path)
        .map_err(|e| e.error)
        .with_context(|| format!("writing {}", path.display()))?;
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
    tmp.persist(&path)
        .map_err(|e| e.error)
        .with_context(|| format!("writing {}", path.display()))?;
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
        // Hard links keep one copy per blob; copy when the store is on another device.
        if fs::hard_link(&src, &dst).is_err() {
            fs::copy(&src, &dst).with_context(|| format!("copying {}", src.display()))?;
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
    tmp.persist(&target)
        .map_err(|e| e.error)
        .with_context(|| format!("writing {}", target.display()))?;
    Ok(dir)
}

/// Reads a kit from an OCI layout directory: the descriptor from the manifest annotation, the
/// command from the image config. Also used for local builds, with their own `source`.
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
    let descriptor = kit_descriptor(&manifest, &what)?;
    let mut kit = v3::parse_json(&descriptor, source)?;
    let config_digest = manifest["config"]["digest"]
        .as_str()
        .ok_or_else(|| anyhow!("the manifest has no config"))?;
    let config: Value = serde_json::from_slice(&read(blobs.join(hex_of(config_digest)?))?)
        .context("reading the image config")?;
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
    kit.command = (!command.is_empty()).then_some(command);
    kit.digest = Some(digest);
    kit.content = Content::Oci(dir.to_path_buf());
    Ok(kit)
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
    use crate::kits::model::Kind;

    const DESC: &str = r#"{"schemaVersion":"3","kind":"workload","provides":["shell"]}"#;

    fn src() -> Source {
        Source::Registry("docker.io/acme/kit:1".into())
    }

    #[test]
    fn annotation_becomes_the_descriptor() {
        let d = tempfile::tempdir().unwrap();
        let digest = fixtures::oci_layout(d.path(), Some(DESC), &[b"layer"], "{}");
        let kit = read_layout(d.path(), src()).unwrap();
        assert_eq!(kit.kind, Kind::Workload);
        assert_eq!(kit.provides, vec!["shell"]);
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
        let _ = new_client();
        let _ = new_client();
        assert!(rustls::crypto::CryptoProvider::get_default().is_some());
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
}
