//! A hosted sandbox's on-disk egress state: its CA and front token.

use super::{Binding, Label};
use crate::config::{Paths, Symlink, write_atomic};
use crate::sandbox::{name, options::free_port};
use crate::smolvm::Credential;
use anyhow::{Context, Result};
use egress_front::{CredentialPolicy, MachineCa, generate_placeholders};
use std::collections::BTreeSet;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prepared {
    pub label: Label,
    /// The CA's guest-facing half, mounted at `/run/smol/credentials`.
    pub ca_guest_dir: PathBuf,
}

pub fn prepare(paths: &Paths, sandbox: &str, creds: &[Credential]) -> Result<Prepared> {
    let dir = paths.egress(sandbox);
    // A leftover from an earlier create must not leak a stale CA or token.
    forget(paths, sandbox)?;
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;

    // smolvm permits a CA for a wildcard's parent domain (`host_subtree`).
    let hosts: BTreeSet<String> = creds
        .iter()
        .flat_map(|c| &c.hosts)
        .map(|h| h.strip_prefix("*.").unwrap_or(h).to_string())
        .collect();
    let hosts: Vec<String> = hosts.into_iter().collect();
    let machine = name::machine_name(sandbox);
    let ca = MachineCa::generate(&machine, &hosts)?;
    ca.save(&dir.join("ca"))?;

    let tok: [u8; 32] = rand::random();
    let tok: String = tok.iter().map(|b| format!("{b:02x}")).collect();
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
        ca_guest_dir: MachineCa::guest_dir(&dir.join("ca")),
    })
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
        assert!(got.ca_guest_dir.starts_with(&dir));
        assert!(got.label.port > 0);
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
    fn forget_removes_the_state_and_tolerates_none() {
        let d = tempfile::tempdir().unwrap();
        let p = paths(d.path());
        forget(&p, "w").unwrap();
        prepare(&p, "w", &[cred("A", "a.com", None)]).unwrap();
        forget(&p, "w").unwrap();
        assert!(!p.egress("w").exists());
    }
}
