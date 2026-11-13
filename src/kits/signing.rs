//! Kit signatures, made and checked by `cosign` over a kit manifest's bytes, in the Sigstore
//! bundle format sbx 0.53 writes (a `messageSignature` over the manifest).
//!
//! sbx's `--key` is an unencrypted PEM key, which cosign doesn't read: it is imported into a
//! private temp directory first. A key-based signature stays off the public transparency log, as
//! in sbx. An identity token never reaches cosign's argv: a value is passed as a file path.

use std::fs;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, anyhow, bail};

const MISSING: &str = "kit signing needs cosign on PATH; install it from \
                       https://docs.sigstore.dev/cosign/system_config/installation/";

/// An OIDC identity token for keyless signing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Token {
    Value(String),
    File(PathBuf),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Signer {
    /// An unencrypted PEM private key.
    Key(PathBuf),
    /// Fulcio and Rekor; without a token cosign finds one in CI or opens a browser.
    Keyless { token: Option<Token> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Match {
    Exact(String),
    Regexp(String),
}

impl Match {
    /// The value or pattern, without saying which.
    pub fn as_str(&self) -> &str {
        match self {
            Match::Exact(v) | Match::Regexp(v) => v,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Policy {
    /// A PEM public key.
    Key(PathBuf),
    Keyless {
        identity: Match,
        issuer: Match,
        ignore_tlog: bool,
    },
}

/// The cosign to run: `$SMOLBENTO_COSIGN`, else `cosign` on PATH.
pub fn cosign() -> Result<PathBuf> {
    if let Some(p) = std::env::var_os("SMOLBENTO_COSIGN") {
        return Ok(p.into());
    }
    std::env::var_os("PATH")
        .iter()
        .flat_map(std::env::split_paths)
        .map(|d| d.join("cosign"))
        .find(|p| p.is_file())
        .context(MISSING)
}

/// Signs BLOB and returns the bundle.
pub fn sign_blob(cosign: &Path, blob: &[u8], signer: &Signer) -> Result<Vec<u8>> {
    let tmp = tempfile::tempdir()?;
    let dir = tmp.path();
    let (blob_path, bundle_path) = (dir.join("blob"), dir.join("bundle"));
    fs::write(&blob_path, blob)?;
    let mut sign = Command::new(cosign);
    sign.args(["sign-blob", "--yes", "--new-bundle-format"]);
    match signer {
        Signer::Key(key) => {
            // An empty password, in the environment: the imported key is only a format change.
            let mut import = Command::new(cosign);
            import
                .args(["import-key-pair", "--key"])
                .arg(key)
                .args(["--output-key-prefix", "import"])
                .current_dir(dir)
                .env("COSIGN_PASSWORD", "")
                .stdin(Stdio::null())
                .stderr(Stdio::piped());
            run(&mut import, "importing the signing key")?;
            sign.arg("--key")
                .arg(dir.join("import.key"))
                .args(["--use-signing-config=false", "--tlog-upload=false"])
                .env("COSIGN_PASSWORD", "");
        }
        Signer::Keyless { token } => match token {
            Some(Token::File(f)) => {
                sign.arg("--identity-token").arg(f);
            }
            Some(Token::Value(v)) => {
                let f = dir.join("token");
                fs::write(&f, v)?;
                fs::set_permissions(&f, fs::Permissions::from_mode(0o600))?;
                sign.arg("--identity-token").arg(f);
            }
            None => {}
        },
    }
    sign.arg("--bundle").arg(&bundle_path).arg(&blob_path);
    // A keyless login may ask in the terminal or open a browser.
    sign.stdin(Stdio::inherit()).stderr(Stdio::inherit());
    run(&mut sign, "signing the kit")?;
    fs::read(&bundle_path).context("reading the signature bundle cosign wrote")
}

/// Checks BUNDLE against BLOB under POLICY.
pub fn verify_blob(cosign: &Path, blob: &[u8], bundle: &[u8], policy: &Policy) -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let (blob_path, bundle_path) = (tmp.path().join("blob"), tmp.path().join("bundle"));
    fs::write(&blob_path, blob)?;
    fs::write(&bundle_path, bundle)?;
    let mut verify = Command::new(cosign);
    verify.args(["verify-blob", "--bundle"]).arg(&bundle_path);
    let flag = |name: &str, m: &Match| match m {
        Match::Exact(v) => [format!("--{name}"), v.clone()],
        Match::Regexp(v) => [format!("--{name}-regexp"), v.clone()],
    };
    match policy {
        // A key-based signature has no transparency log entry, as sbx makes it.
        Policy::Key(key) => {
            verify.arg("--key").arg(key).arg("--insecure-ignore-tlog");
        }
        Policy::Keyless {
            identity,
            issuer,
            ignore_tlog,
        } => {
            verify.args(flag("certificate-identity", identity));
            verify.args(flag("certificate-oidc-issuer", issuer));
            if *ignore_tlog {
                verify.arg("--insecure-ignore-tlog");
            }
        }
    }
    verify.arg(&blob_path);
    let out = verify
        .stdin(Stdio::null())
        .output()
        .with_context(|| format!("running {}", cosign.display()))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let reason = stderr
            .lines()
            .rev()
            .map(str::trim)
            .find(|l| !l.is_empty())
            .unwrap_or("cosign verify-blob failed");
        let reason = reason
            .trim_start_matches("Error: ")
            .trim_start_matches("error during command execution: ");
        bail!("kit signature verification failed: {reason}");
    }
    Ok(())
}

/// The first of POLICIES that one of BUNDLES verifies BLOB for; else the last verification
/// failure, or `kit is not signed` when there is nothing to try.
pub fn verify_any<'p>(
    cosign: &Path,
    blob: &[u8],
    bundles: &[Vec<u8>],
    policies: &'p [Policy],
) -> Result<&'p Policy> {
    let mut last = anyhow!("kit is not signed");
    for policy in policies {
        for b in bundles {
            match verify_blob(cosign, blob, b, policy) {
                Ok(()) => return Ok(policy),
                Err(e) => last = e,
            }
        }
    }
    Err(last)
}

/// Runs a cosign command whose stdout isn't needed; its stderr is shown on failure.
fn run(cmd: &mut Command, what: &str) -> Result<()> {
    let program = cmd.get_program().to_owned();
    let mut child = cmd
        .stdout(Stdio::null())
        .spawn()
        .with_context(|| format!("{what}: running {}", Path::new(&program).display()))?;
    let mut stderr = String::new();
    if let Some(mut e) = child.stderr.take() {
        e.read_to_string(&mut stderr)?;
    }
    let status = child.wait()?;
    if !status.success() {
        bail!(
            "{what}: cosign failed ({status}){}",
            match stderr.trim() {
                "" => String::new(),
                e => format!(": {e}"),
            }
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fake cosign that logs each call's argv (one per line) and `COSIGN_PASSWORD`, writes
    /// `import.key` for `import-key-pair` and a bundle for `sign-blob`, and fails `verify-blob`
    /// when `FAIL_VERIFY` exists or the bundle reads `bad`.
    fn fake() -> (tempfile::TempDir, PathBuf) {
        let d = tempfile::tempdir().unwrap();
        let log = d.path().join("log");
        let script = d.path().join("cosign");
        fs::write(
            &script,
            format!(
                r#"#!/bin/sh
echo "argv: $*" >> {log}
echo "password: ${{COSIGN_PASSWORD-unset}}" >> {log}
case "$1" in
  import-key-pair) echo key > import.key ;;
  sign-blob)
    while [ $# -gt 0 ]; do
      case "$1" in
        --bundle) shift; echo '{{"bundle":true}}' > "$1" ;;
        --identity-token) shift; echo "token: $(cat "$1")" >> {log} ;;
      esac
      shift
    done ;;
  verify-blob)
    if [ -e {fail} ] || grep -q bad "$3"; then
      echo "Error: failed to verify signature: bad" >&2; exit 1
    fi ;;
esac
"#,
                log = log.display(),
                fail = d.path().join("FAIL_VERIFY").display(),
            ),
        )
        .unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        (d, script)
    }

    fn log(d: &tempfile::TempDir) -> String {
        fs::read_to_string(d.path().join("log")).unwrap()
    }

    #[test]
    fn key_signing_imports_the_key_and_skips_rekor() {
        let (d, cosign) = fake();
        let bundle = sign_blob(&cosign, b"manifest", &Signer::Key("/keys/k.pem".into())).unwrap();
        assert_eq!(bundle, b"{\"bundle\":true}\n");
        let log = log(&d);
        let calls: Vec<&str> = log.lines().filter(|l| l.starts_with("argv")).collect();
        assert_eq!(calls.len(), 2, "{log}");
        assert_eq!(
            calls[0],
            "argv: import-key-pair --key /keys/k.pem --output-key-prefix import"
        );
        assert!(
            calls[1].starts_with("argv: sign-blob --yes --new-bundle-format --key "),
            "{log}"
        );
        assert!(calls[1].contains("/import.key --use-signing-config=false --tlog-upload=false"));
        assert!(
            log.lines()
                .filter(|l| l.starts_with("password"))
                .all(|l| l == "password: ")
        );
    }

    #[test]
    fn a_token_value_goes_by_file() {
        let (d, cosign) = fake();
        let token = Some(Token::Value("s3cret-token".into()));
        sign_blob(&cosign, b"m", &Signer::Keyless { token }).unwrap();
        let log = log(&d);
        let argv = log.lines().find(|l| l.starts_with("argv")).unwrap();
        assert!(argv.contains("--identity-token /"), "{log}");
        assert!(!argv.contains("s3cret-token"), "{log}");
        assert!(log.contains("token: s3cret-token"), "{log}");
        assert!(!argv.contains("--key"), "{log}");
        assert!(!argv.contains("tlog-upload"), "{log}");
    }

    #[test]
    fn verify_passes_identity_or_key_flags() {
        let (d, cosign) = fake();
        verify_blob(&cosign, b"m", b"{}", &Policy::Key("/k.pub".into())).unwrap();
        let policy = Policy::Keyless {
            identity: Match::Regexp("^me@".into()),
            issuer: Match::Exact("https://iss".into()),
            ignore_tlog: false,
        };
        verify_blob(&cosign, b"m", b"{}", &policy).unwrap();
        let log = log(&d);
        let calls: Vec<&str> = log.lines().filter(|l| l.starts_with("argv")).collect();
        assert!(calls[0].contains("verify-blob --bundle "), "{log}");
        assert!(
            calls[0].contains("--key /k.pub --insecure-ignore-tlog"),
            "{log}"
        );
        assert!(
            calls[1].contains(
                "--certificate-identity-regexp ^me@ --certificate-oidc-issuer https://iss"
            ),
            "{log}"
        );
        assert!(!calls[1].contains("insecure"), "{log}");
    }

    #[test]
    fn a_failed_verify_carries_cosigns_reason() {
        let (d, cosign) = fake();
        fs::write(d.path().join("FAIL_VERIFY"), "").unwrap();
        let e = verify_blob(&cosign, b"m", b"{}", &Policy::Key("/k.pub".into())).unwrap_err();
        assert_eq!(
            e.to_string(),
            "kit signature verification failed: failed to verify signature: bad"
        );
    }

    #[test]
    fn any_bundle_verifying_for_any_policy_is_enough() {
        let (_d, cosign) = fake();
        let policies = [Policy::Key("/a.pub".into()), Policy::Key("/b.pub".into())];
        let bundles = [b"bad".to_vec(), b"good".to_vec()];
        let p = verify_any(&cosign, b"m", &bundles, &policies).unwrap();
        assert_eq!(p, &policies[0]);
        let e = verify_any(&cosign, b"m", &bundles[..1], &policies).unwrap_err();
        assert_eq!(
            e.to_string(),
            "kit signature verification failed: failed to verify signature: bad"
        );
        let e = verify_any(&cosign, b"m", &[], &policies).unwrap_err();
        assert_eq!(e.to_string(), "kit is not signed");
    }

    #[test]
    fn a_missing_cosign_is_named() {
        let e = sign_blob(
            Path::new("/nonexistent/cosign"),
            b"m",
            &Signer::Key("k".into()),
        )
        .unwrap_err();
        assert!(format!("{e:#}").contains("/nonexistent/cosign"), "{e:#}");
    }
}
