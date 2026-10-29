//! SSH agent forwarding (`ssh-agent@1`): the grant a kit set asks for, the `sbx.ssh-agent` label
//! that records it, and whether the host has an agent to back it.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use crate::config::Settings;

/// The merged `ssh-agent@1` grant of a kit set, per phase; `None` = that phase isn't granted.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AgentGrant {
    pub install: Option<PhaseGrant>,
    pub runtime: Option<PhaseGrant>,
}

/// One phase of an `AgentGrant`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhaseGrant {
    /// `None`: unrestricted (signs anything); else the namespaces it may sign.
    pub sign: Option<Vec<String>>,
    /// A required entry asked for it: with no agent to back it, the create is refused.
    pub required: bool,
    /// The kit messages name: the first required entry's, else the first kit entry's. `None` for
    /// a built-in agent's implicit grant alone, which drops silently.
    pub kit: Option<String>,
}

impl AgentGrant {
    pub fn is_empty(&self) -> bool {
        self.install.is_none() && self.runtime.is_none()
    }

    /// The label for what's left once phases without an agent are dropped (`settle`).
    fn label(&self) -> Option<AgentLabel> {
        let access = |p: &Option<PhaseGrant>| {
            p.as_ref().map(|p| Access {
                sign: p.sign.clone(),
            })
        };
        let l = AgentLabel {
            install: access(&self.install),
            runtime: access(&self.runtime),
        };
        (!l.is_empty()).then_some(l)
    }
}

/// The `sbx.ssh-agent` label: what each phase granted at create may sign,
/// `{"runtime":{"sign":null},"install":{"sign":["git"]}}` (`null` = unrestricted).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentLabel {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime: Option<Access>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub install: Option<Access>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Access {
    /// `None`: unrestricted; else the namespaces the filter admits.
    pub sign: Option<Vec<String>>,
}

impl AgentLabel {
    pub fn is_empty(&self) -> bool {
        self.install.is_none() && self.runtime.is_none()
    }

    pub fn to_label(&self) -> String {
        serde_json::to_string(self).expect("the label serializes")
    }

    /// `None` for a garbled label: the sandbox gets no agent.
    pub fn from_label(s: &str) -> Option<AgentLabel> {
        serde_json::from_str::<AgentLabel>(s)
            .ok()
            .filter(|l| !l.is_empty())
    }
}

/// Why there's no backing agent for a sandbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unavailable {
    Unset,
    Missing(PathBuf),
    Disabled,
}

impl fmt::Display for Unavailable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Unavailable::Unset => write!(f, "SSH_AUTH_SOCK is unset"),
            Unavailable::Missing(p) => write!(f, "{} doesn't exist", p.display()),
            Unavailable::Disabled => write!(f, "ssh.agentForwardingEnabled is false"),
        }
    }
}

/// The host agent sandboxes relay to: `socket_path` (`ssh.agentSocketPath`) when set, else
/// `auth_sock` (the process's `SSH_AUTH_SOCK`); it must exist, and `enabled`
/// (`ssh.agentForwardingEnabled`) must be on.
pub fn backing_agent(
    enabled: bool,
    socket_path: &str,
    auth_sock: Option<&str>,
) -> Result<PathBuf, Unavailable> {
    if !enabled {
        return Err(Unavailable::Disabled);
    }
    let path = match (socket_path, auth_sock) {
        ("", None | Some("")) => return Err(Unavailable::Unset),
        ("", Some(s)) => s,
        (p, _) => p,
    };
    let path = Path::new(path);
    if !path.exists() {
        return Err(Unavailable::Missing(path.to_path_buf()));
    }
    Ok(path.to_path_buf())
}

/// `backing_agent` from the settings and the process environment `env`.
pub fn host_agent(
    settings: &Settings,
    env: &BTreeMap<String, String>,
) -> Result<Result<PathBuf, Unavailable>> {
    Ok(backing_agent(
        settings.bool("ssh.agentForwardingEnabled")?,
        &settings.value("ssh.agentSocketPath")?,
        env.get("SSH_AUTH_SOCK").map(String::as_str),
    ))
}

/// Applies availability to a grant at create: with an agent every phase stays; without one a
/// required phase refuses the create (`kit K: ssh-agent@1 needs an SSH agent, but <reason>`), and
/// an optional one is dropped, with a note for stderr when a kit asked for it. Returns the
/// label to record (`None`: no agent at all) and the notes.
pub fn settle(
    grant: &AgentGrant,
    backing: &Result<PathBuf, Unavailable>,
) -> Result<(Option<AgentLabel>, Vec<String>)> {
    let Err(why) = backing else {
        return Ok((grant.label(), vec![]));
    };
    let mut notes = Vec::new();
    for (name, phase) in [("install", &grant.install), ("runtime", &grant.runtime)] {
        let Some(p) = phase else { continue };
        let kit = p.kit.as_deref().unwrap_or("?");
        if p.required {
            bail!("kit {kit}: ssh-agent@1 needs an SSH agent, but {why}");
        }
        if p.kit.is_some() {
            notes.push(format!(
                "kit {kit}: no SSH agent for the {name} phase ({why}); continuing without one"
            ));
        }
    }
    Ok((None, notes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn phase(sign: Option<&[&str]>, required: bool, kit: Option<&str>) -> PhaseGrant {
        PhaseGrant {
            sign: sign.map(|s| s.iter().map(|x| x.to_string()).collect()),
            required,
            kit: kit.map(Into::into),
        }
    }

    #[test]
    fn the_backing_agent_is_the_setting_else_ssh_auth_sock_and_must_exist() {
        let tmp = tempfile::tempdir().unwrap();
        let sock = tmp.path().join("agent.sock");
        std::fs::write(&sock, "").unwrap();
        let s = sock.to_str().unwrap();
        let missing = tmp.path().join("gone.sock");
        let m = missing.to_str().unwrap();

        assert_eq!(backing_agent(true, "", Some(s)), Ok(sock.clone()));
        assert_eq!(backing_agent(true, s, Some(m)), Ok(sock.clone()));
        assert_eq!(backing_agent(true, "", None), Err(Unavailable::Unset));
        assert_eq!(backing_agent(true, "", Some("")), Err(Unavailable::Unset));
        assert_eq!(
            backing_agent(true, m, Some(s)),
            Err(Unavailable::Missing(missing.clone()))
        );
        assert_eq!(backing_agent(false, s, Some(s)), Err(Unavailable::Disabled));

        assert_eq!(Unavailable::Unset.to_string(), "SSH_AUTH_SOCK is unset");
        assert_eq!(
            Unavailable::Missing("/x/a.sock".into()).to_string(),
            "/x/a.sock doesn't exist"
        );
        assert_eq!(
            Unavailable::Disabled.to_string(),
            "ssh.agentForwardingEnabled is false"
        );
    }

    #[test]
    fn host_agent_reads_the_settings_and_env() {
        let t = crate::cli::testutil::test_env(&[("SMOLBENTO_SSH_AGENT_FORWARDING", "false")]);
        let env = BTreeMap::from([("SSH_AUTH_SOCK".to_string(), "/nonexistent".to_string())]);
        assert_eq!(
            host_agent(&t.ctx.settings, &env).unwrap(),
            Err(Unavailable::Disabled)
        );
        let t = crate::cli::testutil::test_env(&[("SMOLBENTO_SSH_AGENT_SOCKET", "/nope.sock")]);
        assert_eq!(
            host_agent(&t.ctx.settings, &env).unwrap(),
            Err(Unavailable::Missing("/nope.sock".into()))
        );
    }

    #[test]
    fn an_available_agent_keeps_every_phase() {
        let g = AgentGrant {
            install: Some(phase(Some(&["git"]), true, Some("k"))),
            runtime: Some(phase(None, false, None)),
        };
        let (label, notes) = settle(&g, &Ok("/a.sock".into())).unwrap();
        assert_eq!(
            label.unwrap().to_label(),
            r#"{"runtime":{"sign":null},"install":{"sign":["git"]}}"#
        );
        assert!(notes.is_empty());
        let (label, _) = settle(&AgentGrant::default(), &Ok("/a.sock".into())).unwrap();
        assert_eq!(label, None);
    }

    #[test]
    fn no_agent_refuses_a_required_phase_and_drops_optional_ones() {
        let req = AgentGrant {
            runtime: Some(phase(Some(&["git"]), true, Some("signer"))),
            ..Default::default()
        };
        for (why, reason) in [
            (Unavailable::Unset, "SSH_AUTH_SOCK is unset"),
            (
                Unavailable::Missing("/a.sock".into()),
                "/a.sock doesn't exist",
            ),
            (Unavailable::Disabled, "ssh.agentForwardingEnabled is false"),
        ] {
            let e = settle(&req, &Err(why)).unwrap_err();
            assert_eq!(
                e.to_string(),
                format!("kit signer: ssh-agent@1 needs an SSH agent, but {reason}")
            );
        }

        let opt = AgentGrant {
            install: Some(phase(None, false, Some("k"))),
            runtime: Some(phase(None, false, None)),
        };
        let (label, notes) = settle(&opt, &Err(Unavailable::Unset)).unwrap();
        assert_eq!(label, None);
        // Only the kit's entry gets a note; the built-in agent's implicit grant drops silently.
        assert_eq!(
            notes,
            [
                "kit k: no SSH agent for the install phase (SSH_AUTH_SOCK is unset); continuing \
                 without one"
            ]
        );
    }

    #[test]
    fn the_label_round_trips_and_garbage_is_no_agent() {
        let l = AgentLabel {
            runtime: Some(Access {
                sign: Some(vec!["git".into()]),
            }),
            install: None,
        };
        assert_eq!(l.to_label(), r#"{"runtime":{"sign":["git"]}}"#);
        assert_eq!(AgentLabel::from_label(&l.to_label()), Some(l));
        let unrestricted = AgentLabel::from_label(r#"{"install":{"sign":null}}"#).unwrap();
        assert_eq!(unrestricted.install, Some(Access { sign: None }));
        assert_eq!(AgentLabel::from_label("{}"), None);
        assert_eq!(AgentLabel::from_label("nope"), None);
    }
}
