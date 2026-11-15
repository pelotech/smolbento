//! Kit compatibility warnings: the optional parts of a kit smolbento skips or ignores (an
//! unsupported capability, an optional credential, a v2 field). Off unless `kit.showWarnings` or
//! `-D`: the kit works without them, so they only matter when checking a kit or debugging.
//!
//! Decided once per command, like `-D`, because they're raised deep in kit parsing and binding,
//! where no context reaches.

use std::sync::atomic::{AtomicBool, Ordering};

use crate::config::Settings;

static SHOWN: AtomicBool = AtomicBool::new(false);

/// Whether this command shows them: `-D`, or the setting.
pub fn wanted(settings: &Settings, debug: bool) -> bool {
    debug || settings.bool("kit.showWarnings").unwrap_or(false)
}

/// Shows (or hides) them for the rest of this command.
pub fn show(on: bool) {
    SHOWN.store(on, Ordering::Relaxed);
}

/// Prints `line` (a whole `warning: kit …` line) to stderr when they're shown.
pub fn warn(line: impl std::fmt::Display) {
    if SHOWN.load(Ordering::Relaxed) {
        eprintln!("{line}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;

    #[test]
    fn shown_with_the_setting_or_debug_only() {
        let t = test_env(&[]);
        assert!(!wanted(&t.ctx.settings, false));
        assert!(wanted(&t.ctx.settings, true));
        let t = test_env(&[("SMOLBENTO_KIT_SHOW_WARNINGS", "true")]);
        assert!(wanted(&t.ctx.settings, false));
    }
}
