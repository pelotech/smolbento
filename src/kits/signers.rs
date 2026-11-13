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

/// A local kit (directory or Smolfile at PATH) under the requirement: refused, as smolbento
/// can't check a directory's `kit.sig.bundle` yet.
pub fn check_local(reference: &str, path: &Path, settings: &Settings) -> Result<()> {
    if !settings.bool("kit.requireSignature")? {
        return Ok(());
    }
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
    Err(refused(reference, &detail))
}

/// A registry kit under the requirement: one of its signatures must verify for a trusted signer.
/// Returns sbx's line for stderr when one does, `None` when signatures aren't required.
pub fn check_registry(
    reference: &str,
    settings: &Settings,
    logins: Logins,
) -> Result<Option<String>> {
    if !settings.bool("kit.requireSignature")? {
        return Ok(None);
    }
    let mut signers = parse(&settings.value("kit.trustedSigners")?)?;
    if signers.is_empty() {
        let detail = "no trusted signers are configured; set kit.trustedSigners, or disable \
                      kit.requireSignature";
        return Err(refused(reference, detail));
    }
    let ignore = settings.bool("kit.ignoreTransparencyLog")?;
    for s in &mut signers {
        if let Policy::Keyless { ignore_tlog, .. } = s {
            *ignore_tlog = ignore;
        }
    }
    let cosign = signing::cosign()?;
    let (manifest, digest) = registry::top_manifest(reference, logins)?;
    let bundles = registry::signatures_of(reference, &digest, logins)?;
    let mut last = None;
    for signer in &signers {
        for b in &bundles {
            match signing::verify_blob(&cosign, &manifest, b, signer) {
                Ok(()) => {
                    return Ok(Some(format!(
                        "  \u{2713} {reference} \u{2014} signature verified ({})",
                        shown(signer)
                    )));
                }
                Err(e) => last = Some(e),
            }
        }
    }
    let detail = match last {
        Some(e) => format!("{reference}: {e:#}"),
        None => format!("{reference} is not signed"),
    };
    Err(refused(reference, &detail))
}

/// The signer that matched, as the success line names it.
fn shown(p: &Policy) -> String {
    let m = |m: &Match| match m {
        Match::Exact(v) | Match::Regexp(v) => v.clone(),
    };
    match p {
        Policy::Key(k) => format!("key {}", k.display()),
        Policy::Keyless {
            identity, issuer, ..
        } => format!("{} via {}", m(identity), m(issuer)),
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
/// or `…Regexp`), as verification policies. Also checked by `sbt settings set`.
pub fn parse(raw: &str) -> Result<Vec<Policy>> {
    let entries: Vec<Entry> = serde_json::from_str(raw).map_err(|e| {
        anyhow::anyhow!("kit.trustedSigners must be a JSON array of signer objects: {e}")
    })?;
    entries.into_iter().map(policy).collect()
}

fn policy(e: Entry) -> Result<Policy> {
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
        ignore_tlog: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_trusts_docker_employees() {
        let p = parse(
            r#"[{"identityRegexp":"^.*@docker\\.com$","issuer":"https://accounts.google.com"}]"#,
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
        let p = parse(r#"[{"key":"/k.pub"},{"identity":"me@x.io","issuerRegexp":"^https://iss"}]"#)
            .unwrap();
        assert_eq!(
            p,
            [
                Policy::Key("/k.pub".into()),
                Policy::Keyless {
                    identity: Match::Exact("me@x.io".into()),
                    issuer: Match::Regexp("^https://iss".into()),
                    ignore_tlog: false,
                }
            ]
        );
        assert_eq!(parse("[]").unwrap(), []);
    }

    #[test]
    fn bad_entries_are_named() {
        let err = |raw: &str| parse(raw).unwrap_err().to_string();
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
