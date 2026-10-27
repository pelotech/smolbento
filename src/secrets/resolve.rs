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
            first_line(&String::from_utf8_lossy(&out.stderr))
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .trim_end_matches(['\n', '\r'])
        .to_string())
}

/// The first non-empty line of a command's stderr, at most 200 characters: enough to say what
/// went wrong without copying everything a command printed (maybe a token) into an error.
fn first_line(stderr: &str) -> String {
    const MAX: usize = 200;
    let line = stderr
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("");
    match line.char_indices().nth(MAX) {
        Some((cut, _)) => format!("{}…", &line[..cut]),
        None => line.to_string(),
    }
}

/// The command that reads a reference: `op read` for `op://…`, or `aws secretsmanager` for a
/// Secrets Manager ARN of any partition. Also how `secret set --ref` validates one.
pub(crate) fn ref_command(reference: &str) -> Result<(&'static str, Vec<String>)> {
    if reference.starts_with("op://") {
        return Ok(("op", vec!["read".into(), reference.into()]));
    }
    let parts: Vec<&str> = reference.split(':').collect();
    if parts.len() < 6
        || parts[0] != "arn"
        || parts[1].is_empty()
        || parts[2] != "secretsmanager"
        || parts[3].is_empty()
    {
        bail!("unsupported reference (use op://… or an AWS Secrets Manager ARN)");
    }
    let args = [
        "secretsmanager",
        "get-secret-value",
        "--region",
        parts[3],
        "--secret-id",
        reference,
        "--query",
        "SecretString",
        "--output",
        "text",
    ];
    Ok(("aws", args.map(String::from).to_vec()))
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
        Source::Ref { reference } => {
            let (program, args) = ref_command(reference)?;
            output(
                program,
                &args.iter().map(String::as_str).collect::<Vec<_>>(),
            )?
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
    fn ref_commands_take_the_region_from_the_arn() {
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
            let (program, a) = ref_command(arn).unwrap();
            assert_eq!(program, "aws");
            let i = a.iter().position(|x| x == "--region").unwrap();
            assert_eq!(a[i + 1], region);
            assert!(a.contains(&arn.to_string()));
        }
        for bad in [
            "arn:aws:s3:::bucket",
            "arn:aws:secretsmanager::1:secret:x",
            "arn::secretsmanager:us-east-1:1:secret:x",
            "arn:aws:secretsmanager",
            "nra:aws:secretsmanager:us-east-1:1:secret:x",
            "vault://x",
        ] {
            assert!(ref_command(bad).is_err(), "{bad}");
        }
        assert_eq!(
            ref_command("op://P/c/credential").unwrap(),
            (
                "op",
                vec!["read".to_string(), "op://P/c/credential".to_string()]
            )
        );
    }

    #[test]
    fn a_failing_command_shows_only_the_start_of_its_stderr() {
        let store = MemoryStore::default();
        let err = |command: &str| {
            resolve(
                &e(Source::Command {
                    command: command.into(),
                }),
                &store,
            )
            .unwrap_err()
            .to_string()
        };
        let msg = err("printf 'bad thing\\ntoken-on-line-2\\n' >&2; exit 1");
        assert!(
            msg.contains("bad thing") && !msg.contains("token-on-line-2"),
            "{msg}"
        );
        let msg = err("i=0; while [ $i -lt 300 ]; do printf é; i=$((i+1)); done >&2; exit 1");
        assert!(msg.ends_with('…'), "{msg}");
        assert_eq!(msg.chars().filter(|c| *c == 'é').count(), 200, "{msg}");
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
