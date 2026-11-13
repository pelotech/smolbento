//! `kit.requireSignature` and `kit.trustedSigners`: with the requirement on, a kit loads only when
//! one of the trusted signers signed it, as in sbx 0.53. smolbento's presets and shipped kits
//! are exempt; `--offline` skips the check, as sbx documents.

use std::path::Path;

use anyhow::{Result, anyhow, bail};
use serde::Deserialize;

use crate::config::Settings;
use crate::kits::registry;
use crate::kits::registry_auth::Logins;
use crate::kits::signing::{self, Match, Policy};

/// sbx's refusal, with DETAIL saying what was wrong.
fn refused(reference: &str, detail: &str) -> anyhow::Error {
    anyhow!(
        "kit \"{reference}\" cannot be installed \u{2014} kit.requireSignature=true and no trusted \
         signature was found: kit signature required by policy: {detail}; sign it with a trusted \
         signer and re-push; if administrator policy permits, add the signer to the trusted \
         signers or disable the requirement; otherwise ask your administrator to update the \
         policy\n\
         try: sbt kit sign --help\n \
         or: sbt settings set kit.trustedSigners <signers>\n \
         or: sbt settings set kit.requireSignature false"
    )
}

/// A local kit (directory or Smolfile at PATH) when signatures are required: refused, as
/// smolbento can't check a directory's `kit.sig.bundle` yet.
pub fn refuse_local(reference: &str, path: &Path) -> anyhow::Error {
    let dir = if path.is_dir() {
        path
    } else {
        path.parent().unwrap_or(path)
    };
    let detail = if dir.join("kit.sig.bundle").exists() {
        format!("{reference}: verifying a local kit's kit.sig.bundle isn't supported yet")
    } else {
        format!("{reference} is not signed")
    };
    refused(reference, &detail)
}

/// A registry kit when signatures are required: one of its signatures must verify for a trusted
/// signer. Prints sbx's success line and returns the manifest digest that verified, for the
/// caller to pull, so what loads is what was verified.
pub fn verify_registry(reference: &str, settings: &Settings, logins: Logins) -> Result<String> {
    let signers = parse(
        &settings.value("kit.trustedSigners")?,
        settings.bool("kit.ignoreTransparencyLog")?,
    )?;
    if signers.is_empty() {
        let detail = "no trusted signers are configured; set kit.trustedSigners, or disable \
                      kit.requireSignature";
        return Err(refused(reference, detail));
    }
    let cosign = signing::cosign()?;
    let (manifest, digest) = registry::top_manifest(reference, logins)?;
    let bundles = registry::signatures_of(reference, &digest, logins)?;
    if bundles.is_empty() {
        return Err(refused(reference, &format!("{reference} is not signed")));
    }
    let signer = signing::verify_any(&cosign, &manifest, &bundles, &signers)
        .map_err(|e| refused(reference, &format!("{reference}: {e:#}")))?;
    eprintln!(
        "  \u{2713} {reference} \u{2014} signature verified ({})",
        shown(signer)
    );
    Ok(digest)
}

/// The signer that matched, as the success line names it.
fn shown(p: &Policy) -> String {
    match p {
        Policy::Key(k) => format!("key {}", k.display()),
        Policy::Keyless {
            identity, issuer, ..
        } => format!("{} via {}", identity.as_str(), issuer.as_str()),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Entry {
    key: Option<std::path::PathBuf>,
    identity: Option<String>,
    identity_regexp: Option<String>,
    issuer: Option<String>,
    issuer_regexp: Option<String>,
}

/// `kit.trustedSigners`: `{"key": PATH}` entries and keyless `issuer`/`identity` entries (exact
/// or `…Regexp`), as verification policies; keyless ones skip Rekor when IGNORE_TLOG
/// (`kit.ignoreTransparencyLog`). Also checked by `sbt settings set`.
pub fn parse(raw: &str, ignore_tlog: bool) -> Result<Vec<Policy>> {
    let entries: Vec<Entry> = serde_json::from_str(raw).map_err(|e| {
        anyhow::anyhow!("kit.trustedSigners must be a JSON array of signer objects: {e}")
    })?;
    entries
        .into_iter()
        .map(|e| policy(e, ignore_tlog))
        .collect()
}

fn policy(e: Entry, ignore_tlog: bool) -> Result<Policy> {
    let pick = |exact: Option<String>, regexp: Option<String>| {
        exact.map(Match::Exact).or(regexp.map(Match::Regexp))
    };
    let identity = pick(e.identity, e.identity_regexp);
    let issuer = pick(e.issuer, e.issuer_regexp);
    if let Some(key) = e.key {
        if identity.is_some() || issuer.is_some() {
            bail!(r#"a trusted signer is either {{"key": …}} or keyless, not both"#);
        }
        return Ok(Policy::Key(key));
    }
    let Some(identity) = identity else {
        bail!(r#"keyless signer must set "identity" or "identityRegexp""#);
    };
    let Some(issuer) = issuer else {
        bail!(r#"keyless signer must set "issuer" or "issuerRegexp""#);
    };
    Ok(Policy::Keyless {
        identity,
        issuer,
        ignore_tlog,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_trusts_docker_employees() {
        let p = parse(
            r#"[{"identityRegexp":"^.*@docker\\.com$","issuer":"https://accounts.google.com"}]"#,
            false,
        )
        .unwrap();
        assert_eq!(
            p,
            [Policy::Keyless {
                identity: Match::Regexp("^.*@docker\\.com$".into()),
                issuer: Match::Exact("https://accounts.google.com".into()),
                ignore_tlog: false,
            }]
        );
    }

    #[test]
    fn keys_and_keyless_entries_mix() {
        let p = parse(
            r#"[{"key":"/k.pub"},{"identity":"me@x.io","issuerRegexp":"^https://iss"}]"#,
            true,
        )
        .unwrap();
        assert_eq!(
            p,
            [
                Policy::Key("/k.pub".into()),
                Policy::Keyless {
                    identity: Match::Exact("me@x.io".into()),
                    issuer: Match::Regexp("^https://iss".into()),
                    ignore_tlog: true,
                }
            ]
        );
        assert_eq!(parse("[]", false).unwrap(), []);
    }

    #[test]
    fn bad_entries_are_named() {
        let err = |raw: &str| parse(raw, false).unwrap_err().to_string();
        assert_eq!(
            err(r#"[{"issuer":"https://i"}]"#),
            r#"keyless signer must set "identity" or "identityRegexp""#
        );
        assert_eq!(
            err(r#"[{"identity":"me"}]"#),
            r#"keyless signer must set "issuer" or "issuerRegexp""#
        );
        assert_eq!(
            err(r#"[{"key":"/k","identity":"me","issuer":"i"}]"#),
            r#"a trusted signer is either {"key": …} or keyless, not both"#
        );
        assert!(err(r#"[{"key":"/k","colour":"blue"}]"#).contains("colour"));
        assert!(err(r#"{"key":"/k"}"#).contains("JSON array"));
    }
}
