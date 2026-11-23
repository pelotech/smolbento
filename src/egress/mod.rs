//! Hosted egress: bento runs the interceptor that swaps a sandbox's credentials.

pub mod filter;
pub mod request_rules;
pub mod rules;
pub mod serve;
mod state;
pub use state::{Prepared, copy_for_fork, forget, load_ca, per_request, policy, prepare, token};

use crate::config::Settings;
use crate::sandbox::name;
use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

/// What a hosted-egress sandbox needs at start (`sbx.egress`, JSON). Never holds secret values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Label {
    pub port: u16,
    pub bindings: Vec<Binding>,
}

/// One credential the interceptor swaps; `name` is `Credential::binding`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Binding {
    pub name: String,
    pub env: String,
    pub hosts: Vec<String>,
    pub set_header: Option<String>,
    pub placeholder: String,
}

impl Label {
    pub fn to_label(&self) -> String {
        serde_json::to_string(self).expect("egress label serializes")
    }

    /// `None` for a garbled label, which a start refuses (`egress_unreadable`).
    pub fn from_label(s: &str) -> Option<Label> {
        serde_json::from_str(s).ok()
    }
}

/// Whether `sandbox` gets hosted egress: `network.egress` is `hosted` and it isn't internal.
pub fn hosted(settings: &Settings, sandbox: &str) -> Result<bool> {
    Ok(parse(&settings.value("network.egress")?)? && !name::is_internal(sandbox))
}

/// `true` for `hosted`.
pub fn parse(value: &str) -> Result<bool> {
    match value {
        "smolvm" => Ok(false),
        "hosted" => Ok(true),
        _ => bail!("invalid network.egress {value:?}: use smolvm or hosted"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Paths;
    use std::collections::BTreeMap;

    fn settings(egress: Option<&str>) -> Settings {
        let dir = tempfile::tempdir().unwrap();
        let mut e: BTreeMap<String, String> = [
            ("SMOLBENTO_CONFIG_DIR", dir.path().to_str().unwrap()),
            ("SMOLBENTO_CACHE_DIR", "/k"),
            ("SMOLBENTO_DATA_DIR", "/d"),
        ]
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .into();
        if let Some(v) = egress {
            e.insert("SMOLBENTO_NETWORK_EGRESS".into(), v.into());
        }
        let paths = Paths::from_env(&e).unwrap();
        Settings::load(&paths, e).0
    }

    #[test]
    fn hosted_is_the_default() {
        assert!(hosted(&settings(None), "w").unwrap());
        assert!(!hosted(&settings(None), "_builder").unwrap());
    }

    #[test]
    fn egress_setting_accepts_smolvm_and_hosted_only() {
        assert!(!hosted(&settings(Some("smolvm")), "w").unwrap());
        assert!(hosted(&settings(Some("hosted")), "w").unwrap());
        let e = hosted(&settings(Some("bogus")), "w").unwrap_err();
        assert!(e.to_string().contains("smolvm or hosted"), "{e}");
        let mut s = settings(None);
        assert!(s.set("network.egress", "bogus").is_err());
        s.set("network.egress", "hosted").unwrap();
    }

    #[test]
    fn the_builder_is_never_hosted() {
        let s = settings(Some("hosted"));
        assert!(!hosted(&s, "_builder").unwrap());
        assert!(hosted(&s, "work").unwrap());
    }
}
