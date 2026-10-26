//! Turns a secret's source into its value, at sandbox start.

use std::process::Command;

use anyhow::{Context, Result, bail};

use super::store::SecretStore;
use super::{SecretEntry, Source};

fn output(program: &str, args: &[&str]) -> Result<String> {
    let out = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("running {program}"))?;
    if !out.status.success() {
        bail!(
            "{program} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .trim_end_matches(['\n', '\r'])
        .to_string())
}

/// The `aws` argv that reads a Secrets Manager secret, for any partition.
fn aws_args(arn: &str) -> Result<Vec<String>> {
    let parts: Vec<&str> = arn.split(':').collect();
    if parts.len() < 6 || parts[2] != "secretsmanager" || parts[3].is_empty() {
        bail!("unsupported reference '{arn}' (use op://… or an AWS Secrets Manager ARN)");
    }
    Ok([
        "secretsmanager",
        "get-secret-value",
        "--region",
        parts[3],
        "--secret-id",
        arn,
        "--query",
        "SecretString",
        "--output",
        "text",
    ]
    .map(String::from)
    .to_vec())
}

pub fn resolve(entry: &SecretEntry, store: &dyn SecretStore) -> Result<String> {
    let value = match &entry.source {
        Source::Keychain => store.get(&entry.account())?.with_context(|| {
            format!(
                "no stored value for {} ({})",
                entry.service,
                store.describe()
            )
        })?,
        Source::Ref { reference } if reference.starts_with("op://") => {
            output("op", &["read", reference])?
        }
        Source::Ref { reference } if reference.starts_with("arn:") => {
            let args = aws_args(reference)?;
            output("aws", &args.iter().map(String::as_str).collect::<Vec<_>>())?
        }
        Source::Ref { reference } => {
            bail!("unsupported reference '{reference}' (use op://… or an AWS Secrets Manager ARN)")
        }
        Source::Command { command } => output("sh", &["-c", command])?,
    };
    if value.is_empty() {
        bail!("the {} secret resolved to an empty value", entry.service);
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::store::MemoryStore;
    use crate::secrets::{SecretEntry, Source};

    fn e(source: Source) -> SecretEntry {
        SecretEntry {
            service: "github".into(),
            scope: "global".into(),
            source,
        }
    }

    #[test]
    fn aws_args_take_the_region_from_the_arn() {
        for (arn, region) in [
            (
                "arn:aws:secretsmanager:us-east-1:123:secret:x-AbC",
                "us-east-1",
            ),
            (
                "arn:aws-us-gov:secretsmanager:us-gov-west-1:123:secret:x",
                "us-gov-west-1",
            ),
        ] {
            let a = aws_args(arn).unwrap();
            let i = a.iter().position(|x| x == "--region").unwrap();
            assert_eq!(a[i + 1], region);
            assert!(a.contains(&arn.to_string()));
        }
        for bad in [
            "arn:aws:s3:::bucket",
            "arn:aws:secretsmanager::1:secret:x",
            "arn:aws:secretsmanager",
        ] {
            assert!(aws_args(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn keychain_command_and_errors() {
        let store = MemoryStore::default();
        store.set("global/github", "from-store").unwrap();
        assert_eq!(resolve(&e(Source::Keychain), &store).unwrap(), "from-store");
        let v = resolve(
            &e(Source::Command {
                command: "printf 'tok-1\\n'".into(),
            }),
            &store,
        )
        .unwrap();
        assert_eq!(v, "tok-1");
        let err = resolve(
            &e(Source::Command {
                command: "echo nope >&2; exit 3".into(),
            }),
            &store,
        )
        .unwrap_err();
        assert!(err.to_string().contains("nope"), "{err}");
        assert!(
            resolve(
                &e(Source::Command {
                    command: "true".into()
                }),
                &store
            )
            .is_err(),
            "empty value"
        );
        assert!(
            resolve(
                &e(Source::Ref {
                    reference: "vault://x".into()
                }),
                &store
            )
            .is_err()
        );
        assert!(resolve(&e(Source::Keychain), &MemoryStore::default()).is_err());
    }
}
