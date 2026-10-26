use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// A machine's lifecycle state as smolvm reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum MachineState {
    Created,
    Running,
    Stopped,
    #[serde(other)]
    Other,
}

/// One machine from `smolvm machine ls --json` or `machine status --json`. Unknown fields are ignored.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct Machine {
    pub name: String,
    pub state: MachineState,
    #[serde(default)]
    pub image: Option<String>,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
    /// Unix seconds.
    #[serde(default)]
    pub created_at: i64,
    /// Only `machine status --json` reports these.
    #[serde(default)]
    pub published_ports: Vec<PublishedPort>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub struct PublishedPort {
    pub host: u16,
    pub guest: u16,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ls_json() {
        let machines: Vec<Machine> =
            serde_json::from_str(include_str!("../../tests/fixtures/smolvm/ls.json")).unwrap();
        assert_eq!(machines.len(), 2);
        assert_eq!(machines[0].name, "sbx-claude-myrepo");
        assert_eq!(machines[0].state, MachineState::Running);
        assert_eq!(machines[0].labels["sbx.name"], "claude-myrepo");
        assert_eq!(machines[1].state, MachineState::Stopped);
        assert!(machines[1].labels.is_empty());
    }

    #[test]
    fn parses_status_json_with_ports() {
        let m: Machine =
            serde_json::from_str(include_str!("../../tests/fixtures/smolvm/status.json")).unwrap();
        assert_eq!(
            m.published_ports,
            vec![PublishedPort {
                host: 18080,
                guest: 80
            }]
        );
    }

    #[test]
    fn unknown_state_is_other() {
        let m: Machine = serde_json::from_str(r#"{"name":"x","state":"paused"}"#).unwrap();
        assert_eq!(m.state, MachineState::Other);
    }
}
