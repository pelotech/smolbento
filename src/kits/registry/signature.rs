//! Kit signatures in a registry: sbx's signature referrers, pushed and listed.

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use oci_client::Reference;
use oci_client::RegistryOperation;
use oci_client::errors::{OciDistributionError, OciErrorCode};
use oci_client::manifest::{OCI_IMAGE_INDEX_MEDIA_TYPE, OCI_IMAGE_MEDIA_TYPE};
use oci_client::secrets::RegistryAuth;
use reqwest::header::HeaderValue;
use serde_json::{Value, json};

use crate::kits::registry::auth::Logins;
use crate::util::sha256_digest;

use super::{parse_ref, with_client};
use crate::kits::artifact::EMPTY_MEDIA_TYPE;

pub(super) const SIGNATURE_ARTIFACT: &str = "application/vnd.docker.sandbox.kit.signature.v1";
pub(super) const BUNDLE_MEDIA_TYPE: &str = "application/vnd.dev.sigstore.bundle.v0.3+json";

/// sbx's signature referrer: the bundle as its one layer, the kit manifest as its subject.
pub(super) fn signature_manifest(
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
pub(super) fn add_to_referrers_index(index: Option<Value>, descriptor: Value) -> Result<Value> {
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
pub(super) fn is_not_found(e: &OciDistributionError) -> bool {
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
    let r = parse_ref(reference)?;
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
    let r = parse_ref(reference)?;
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
                    bail!("signature bundle {d} doesn't match its digest");
                }
                bundles.push(out);
            }
        }
        Ok(bundles)
    })
}
