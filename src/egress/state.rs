//! A hosted sandbox's on-disk egress state: its CA and front token.

use super::{Binding, Label};
use crate::config::{Paths, Symlink, write_atomic};
use crate::sandbox::{name, options::free_port};
use crate::smolvm::Credential;
use anyhow::{Context, Result, bail};
use egress_front::{CredentialPolicy, MachineCa, generate_placeholders, host_subtree};
use std::collections::BTreeSet;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prepared {
    pub label: Label,
    /// The CA's guest-facing half, mounted at `/run/smol/credentials`; `None` without credentials.
    pub ca_guest_dir: Option<PathBuf>,
}

pub fn prepare(paths: &Paths, sandbox: &str, creds: &[Credential]) -> Result<Prepared> {
    let dir = paths.egress(sandbox);
    // A leftover from an earlier create must not leak a stale CA or token.
    forget(paths, sandbox)?;
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;

    let hosts: BTreeSet<String> = creds
        .iter()
        .flat_map(|c| &c.hosts)
        .map(|h| host_subtree(h).to_string())
        .collect();
    let mut hosts: Vec<String> = hosts.into_iter().collect();
    if hosts.is_empty() {
        // A CA needs a permitted host; `invalid` never resolves, so this one can sign for nothing real.
        hosts.push("invalid".into());
    }
    let machine = name::machine_name(sandbox);
    let ca = MachineCa::generate(&machine, &hosts)?;
    ca.save(&dir.join("ca"))?;

    let tok: [u8; 32] = rand::random();
    let tok = crate::util::hex(&tok);
    write_atomic(
        &dir.join("token"),
        tok.as_bytes(),
        Some(0o600),
        Symlink::Replace,
    )?;

    let mut label = Label {
        port: free_port()?,
        bindings: creds
            .iter()
            .map(|c| Binding {
                name: Credential::binding(&c.env_var),
                env: c.env_var.clone(),
                hosts: c.hosts.clone(),
                set_header: c.set_header.clone(),
                placeholder: String::new(),
            })
            .collect(),
    };
    let placeholders = generate_placeholders(&policy(&label));
    for b in &mut label.bindings {
        b.placeholder = placeholders[&b.name].clone();
    }
    Ok(Prepared {
        label,
        // Nothing is terminated without a binding, so the guest needs no CA.
        ca_guest_dir: (!creds.is_empty()).then(|| MachineCa::guest_dir(&dir.join("ca"))),
    })
}

/// A fork's egress state: a copy of its parent's CA and token, which the copied guest memory already
/// trusts and holds, and the parent's label (its placeholders) on a port of its own. Nothing is left
/// under the fork's name on failure.
pub fn copy_for_fork(
    paths: &Paths,
    parent: &str,
    fork: &str,
    parent_label: &Label,
) -> Result<Label> {
    let (from, to) = (paths.egress(parent), paths.egress(fork));
    if !MachineCa::exists(&from.join("ca")) {
        bail!("{parent} has no CA in {}; recreate it", from.display());
    }
    forget(paths, fork)?;
    let copied = (|| {
        std::fs::create_dir_all(&to).with_context(|| format!("creating {}", to.display()))?;
        std::fs::set_permissions(&to, std::fs::Permissions::from_mode(0o700))?;
        // The CA and token only: the parent's egress.log stays its own.
        std::fs::create_dir(to.join("ca"))?;
        crate::skills::store::copy_tree(&from.join("ca"), &to.join("ca"))?;
        // `fs::copy` keeps the 0600 mode.
        std::fs::copy(from.join("token"), to.join("token")).context("copying the token")?;
        Ok(Label {
            port: free_port()?,
            ..parent_label.clone()
        })
    })();
    if copied.is_err() {
        let _ = forget(paths, fork);
    }
    copied
}

pub fn token(paths: &Paths, sandbox: &str) -> Result<String> {
    let path = paths.egress(sandbox).join("token");
    Ok(std::fs::read_to_string(&path)
        .with_context(|| format!("reading {}", path.display()))?
        .trim()
        .to_string())
}

pub fn load_ca(paths: &Paths, sandbox: &str) -> Result<MachineCa> {
    MachineCa::load(
        &paths.egress(sandbox).join("ca"),
        &name::machine_name(sandbox),
    )
}

pub fn forget(paths: &Paths, sandbox: &str) -> Result<()> {
    match std::fs::remove_dir_all(paths.egress(sandbox)) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.into()),
        _ => Ok(()),
    }
}

/// One binding per label entry, with the default methods.
pub fn policy(label: &Label) -> CredentialPolicy {
    let credentials = label
        .bindings
        .iter()
        .map(|b| {
            serde_json::from_value(serde_json::json!({
                "name": b.name,
                "environment_variable": b.env,
                "allowed_hosts": b.hosts,
                "set_header": b.set_header,
            }))
            .expect("binding fields are valid")
        })
        .collect();
    CredentialPolicy { credentials }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn paths(dir: &std::path::Path) -> Paths {
        let e: BTreeMap<String, String> = [
            ("SMOLBENTO_CONFIG_DIR", "/c"),
            ("SMOLBENTO_CACHE_DIR", "/k"),
            ("SMOLBENTO_DATA_DIR", dir.to_str().unwrap()),
        ]
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .into();
        Paths::from_env(&e).unwrap()
    }

    fn cred(env: &str, host: &str, header: Option<&str>) -> Credential {
        Credential {
            env_var: env.into(),
            hosts: vec![host.into()],
            set_header: header.map(String::from),
        }
    }

    fn mode(p: &std::path::Path) -> u32 {
        std::fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn prepare_writes_a_private_ca_and_token() {
        let d = tempfile::tempdir().unwrap();
        let p = paths(d.path());
        let got = prepare(&p, "w", &[cred("GH_TOKEN", "*.github.com", None)]).unwrap();
        let dir = p.egress("w");
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(&dir.join("token")), 0o600);
        let t = token(&p, "w").unwrap();
        assert_eq!(t.len(), 64);
        assert!(t.bytes().all(|b| b.is_ascii_hexdigit()));
        assert!(load_ca(&p, "w").unwrap().permits("api.github.com"));
        assert!(got.ca_guest_dir.unwrap().starts_with(&dir));
        assert!(got.label.port > 0);
    }

    #[test]
    fn prepare_without_credentials_constrains_the_ca_to_invalid() {
        let d = tempfile::tempdir().unwrap();
        let p = paths(d.path());
        let got = prepare(&p, "w", &[]).unwrap();
        assert!(got.label.bindings.is_empty());
        assert_eq!(got.ca_guest_dir, None);
        assert_eq!(token(&p, "w").unwrap().len(), 64);
        let ca = load_ca(&p, "w").unwrap();
        assert!(ca.permits("invalid"));
        assert!(!ca.permits("example.com"));
    }

    #[test]
    fn prepare_labels_each_credential_with_a_placeholder() {
        let d = tempfile::tempdir().unwrap();
        let p = paths(d.path());
        let creds = [
            cred("GH_TOKEN", "api.github.com", None),
            cred("NPM_TOKEN", "registry.npmjs.org", Some("Authorization")),
        ];
        let b = prepare(&p, "w", &creds).unwrap().label.bindings;
        assert_eq!(b[0].name, "gh_token");
        assert_eq!(b[0].env, "GH_TOKEN");
        assert_eq!(b[0].hosts, ["api.github.com"]);
        assert_eq!(b[1].set_header.as_deref(), Some("Authorization"));
        assert!(!b[0].placeholder.is_empty() && b[0].placeholder != b[1].placeholder);
        assert_eq!(
            policy(&Label {
                port: 1,
                bindings: b
            })
            .credentials
            .len(),
            2
        );
    }

    #[test]
    fn copy_for_fork_keeps_the_ca_and_token_and_takes_a_new_port() {
        let d = tempfile::tempdir().unwrap();
        let p = paths(d.path());
        let parent = prepare(&p, "a", &[cred("GH_TOKEN", "api.github.com", None)])
            .unwrap()
            .label;
        // A stale fork directory is replaced, not merged.
        std::fs::create_dir_all(p.egress("b")).unwrap();
        std::fs::write(p.egress("b").join("stale"), "x").unwrap();
        let got = copy_for_fork(&p, "a", "b", &parent).unwrap();
        assert_eq!(got.bindings, parent.bindings);
        assert!(got.port > 0);
        assert_eq!(token(&p, "b").unwrap(), token(&p, "a").unwrap());
        let (a, b) = (load_ca(&p, "a").unwrap(), load_ca(&p, "b").unwrap());
        assert_eq!(a.certificate_pem(), b.certificate_pem());
        assert!(b.permits("api.github.com"));
        let dir = p.egress("b");
        assert!(!dir.join("stale").exists());
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(&dir.join("token")), 0o600);
        assert_eq!(mode(&dir.join("ca").join("ca.key")), 0o600);
        assert!(p.egress("a").join("token").exists(), "the parent's stays");
    }

    #[test]
    fn copy_for_fork_without_the_parent_dir_fails_and_leaves_nothing() {
        let d = tempfile::tempdir().unwrap();
        let p = paths(d.path());
        let label = Label {
            port: 1,
            bindings: vec![],
        };
        assert!(copy_for_fork(&p, "a", "b", &label).is_err());
        assert!(!p.egress("b").exists());
    }

    #[test]
    fn forget_removes_the_state_and_tolerates_none() {
        let d = tempfile::tempdir().unwrap();
        let p = paths(d.path());
        forget(&p, "w").unwrap();
        prepare(&p, "w", &[cred("A", "a.com", None)]).unwrap();
        forget(&p, "w").unwrap();
        assert!(!p.egress("w").exists());
    }
}
