use serde::Deserialize;

use super::Output;

/// An error smolvm reported with `--error-format json`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("smolvm: {message}")]
pub struct SmolvmError {
    pub code: String,
    pub message: String,
}

#[derive(Deserialize)]
struct Envelope {
    error: Body,
}

#[derive(Deserialize)]
struct Body {
    code: String,
    message: String,
}

impl SmolvmError {
    /// The JSON error smolvm printed on stderr, if any.
    pub fn from_json(out: &Output) -> Option<Self> {
        let Envelope { error } = out
            .stderr
            .lines()
            .rev()
            .find_map(|line| serde_json::from_str::<Envelope>(line.trim()).ok())?;
        Some(Self {
            code: error.code,
            message: error.message,
        })
    }

    /// Reads the JSON error smolvm prints on stderr, falling back to the raw text.
    pub fn from_output(out: &Output) -> Self {
        match Self::from_json(out) {
            Some(e) => e,
            None => {
                let text = out.stderr.trim();
                Self {
                    code: "UNKNOWN".into(),
                    message: if text.is_empty() {
                        format!("exited with status {}", out.code)
                    } else {
                        text.to_string()
                    },
                }
            }
        }
    }

    /// What the user can do about it, for the codes that have an answer (see
    /// docs/troubleshooting.md).
    pub fn hint(&self) -> Option<&'static str> {
        match self.code.as_str() {
            "KVM_UNAVAILABLE" => Some(
                "KVM isn't available: enable virtualization, load the KVM module and add your \
                 user to the `kvm` group (`sbt diagnose` checks /dev/kvm)",
            ),
            "HYPERVISOR_UNAVAILABLE" => Some(
                "the hypervisor isn't available: run `sbt diagnose`; on macOS the smolvm binary \
                 needs the hypervisor entitlement (reinstall smolvm)",
            ),
            "STORAGE_ERROR" => {
                Some("check free disk space; `sbt rm` removes sandboxes you no longer need")
            }
            _ => None,
        }
    }

    /// smolvm 1.32.2 reports a missing machine as `CONFIG_ERROR` ("machine 'x' not found"), not
    /// `NOT_FOUND`, so a `CONFIG_ERROR` naming a missing machine counts too.
    pub fn is_not_found(&self) -> bool {
        self.code == "NOT_FOUND"
            || (self.code == "CONFIG_ERROR"
                && self.message.contains("machine '")
                && self.message.ends_with("' not found"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hints_for_the_codes_a_user_can_act_on() {
        let with = |code: &str| SmolvmError {
            code: code.into(),
            message: "m".into(),
        };
        assert!(with("KVM_UNAVAILABLE").hint().unwrap().contains("kvm"));
        assert!(
            with("HYPERVISOR_UNAVAILABLE")
                .hint()
                .unwrap()
                .contains("sbt diagnose")
        );
        assert!(with("STORAGE_ERROR").hint().unwrap().contains("disk space"));
        assert_eq!(with("SMOLVM_ERROR").hint(), None);
        assert_eq!(with("NOT_FOUND").hint(), None);
    }

    #[test]
    fn missing_machine_reported_as_config_error_is_not_found() {
        let err = SmolvmError::from_output(&out(
            r#"{"error":{"code":"CONFIG_ERROR","message":"config operation failed: machine status: machine 'x' not found"}}"#,
        ));
        assert!(err.is_not_found());
    }

    #[test]
    fn other_config_errors_are_not_not_found() {
        let err = SmolvmError::from_output(&out(
            r#"{"error":{"code":"CONFIG_ERROR","message":"config operation failed: image 'x' not found"}}"#,
        ));
        assert!(!err.is_not_found());
        let err = SmolvmError::from_output(&out(
            r#"{"error":{"code":"SMOLVM_ERROR","message":"machine 'x' not found"}}"#,
        ));
        assert!(!err.is_not_found());
    }

    fn out(stderr: &str) -> Output {
        Output {
            code: 1,
            stdout: String::new(),
            stderr: stderr.into(),
        }
    }

    #[test]
    fn parses_json_error() {
        let err = SmolvmError::from_output(&out(
            r#"{"error":{"code":"NOT_FOUND","message":"vm not found: does-not-exist"}}"#,
        ));
        assert_eq!(err.code, "NOT_FOUND");
        assert_eq!(err.message, "vm not found: does-not-exist");
        assert!(err.is_not_found());
    }

    #[test]
    fn json_error_after_other_lines() {
        let err = SmolvmError::from_output(&out(
            "Starting...\n{\"error\":{\"code\":\"SMOLVM_ERROR\",\"message\":\"boom\"}}\n",
        ));
        assert_eq!(err.code, "SMOLVM_ERROR");
        assert!(!err.is_not_found());
    }

    #[test]
    fn falls_back_to_text_or_status() {
        assert_eq!(
            SmolvmError::from_output(&out("plain failure")).message,
            "plain failure"
        );
        assert_eq!(
            SmolvmError::from_output(&out("")).message,
            "exited with status 1"
        );
    }
}
