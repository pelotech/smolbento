//! smolvm's image pull progress, as `machine start` prints it to stderr (`pull_with_progress_as`
//! in smolvm's `src/cli/mod.rs`): `Pulling image X... [====>   ] NN%`, redrawn with `\r`, then
//! `... 100% — syncing...` and `... done.`.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PullProgress {
    Percent(u8),
    Syncing,
}

/// `NN%` or `syncing`, the detail shown under the image step.
impl fmt::Display for PullProgress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Percent(n) => write!(f, "{n}%"),
            Self::Syncing => f.write_str("syncing"),
        }
    }
}

/// Parses one piece of smolvm's stderr (split on `\r` and `\n`); `None` for anything else.
pub fn pull_progress(line: &str) -> Option<PullProgress> {
    let rest = line.strip_prefix("Pulling image ")?;
    if rest.ends_with("% — syncing...") {
        return Some(PullProgress::Syncing);
    }
    let (_, percent) = rest.rsplit_once("] ")?;
    let n: u8 = percent.strip_suffix('%')?.parse().ok()?;
    (n <= 100).then_some(PullProgress::Percent(n))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_smolvm_pull_lines() {
        let cases = [
            ("Pulling image alpine:3.20...", None),
            (
                "Pulling image alpine:3.20... [==>                 ] 10%",
                Some(PullProgress::Percent(10)),
            ),
            (
                "Pulling image ghcr.io/a/b:1... [====================] 100%",
                Some(PullProgress::Percent(100)),
            ),
            (
                "Pulling image alpine:3.20... [====================] 100% — syncing...",
                Some(PullProgress::Syncing),
            ),
            (
                "Pulling image alpine:3.20... done.                    ",
                None,
            ),
            ("Pulling image alpine:3.20... [] 101%", None),
            (r#"{"error":{"code":"X","message":"10%"}}"#, None),
            ("", None),
        ];
        for (line, want) in cases {
            assert_eq!(pull_progress(line), want, "{line:?}");
        }
    }

    #[test]
    fn displays_as_the_step_detail() {
        assert_eq!(PullProgress::Percent(42).to_string(), "42%");
        assert_eq!(PullProgress::Syncing.to_string(), "syncing");
    }
}
