//! Agent skills: the shared store (`sbt skills`) and how sandboxes see it (`--skills`, kit
//! `agent-skills@1`/`agent-skill@1`). Spec: Phase 5c.

pub mod import;
pub mod repo;
pub mod store;

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

/// sbx's skill name rule: a portable directory name that can't leave its parent.
pub fn valid_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    name.len() <= 255
        && bytes.next().is_some_and(|b| b.is_ascii_alphanumeric())
        && bytes.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// How a sandbox shares the store (`--skills`, `skills.defaultMode`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Off,
    #[default]
    Readonly,
    Readwrite,
}

impl Mode {
    pub fn parse(s: &str) -> Result<Mode> {
        Ok(match s {
            "off" => Mode::Off,
            "readonly" => Mode::Readonly,
            "readwrite" => Mode::Readwrite,
            _ => bail!("invalid skills mode {s:?}: use off, readonly or readwrite"),
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Off => "off",
            Mode::Readonly => "readonly",
            Mode::Readwrite => "readwrite",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skill_names() {
        for ok in ["pdf", "a", "Front-end_2.x", &"a".repeat(255)] {
            assert!(valid_name(ok), "{ok}");
        }
        for bad in [
            "",
            ".tmp-x",
            "-x",
            "_x",
            "a/b",
            "..",
            "a b",
            &"a".repeat(256),
        ] {
            assert!(!valid_name(bad), "{bad}");
        }
    }

    #[test]
    fn modes_parse() {
        assert_eq!(Mode::parse("readonly").unwrap(), Mode::Readonly);
        assert_eq!(Mode::parse("readwrite").unwrap(), Mode::Readwrite);
        assert_eq!(Mode::parse("off").unwrap(), Mode::Off);
        let e = Mode::parse("rw").unwrap_err().to_string();
        assert!(e.contains("off, readonly or readwrite"), "{e}");
    }
}
