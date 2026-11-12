//! The first start of a `--clone` sandbox: cloning the host repo inside the VM.

use anyhow::Result;

use super::Sandbox;
use crate::smolvm::{ExecSpec, Runner, Smolvm, SmolvmError};
use crate::util::sh_quote;
use crate::workspace::clone::{SOURCE_MOUNT, WorktreeHead};

/// The first start of a clone sandbox clones the host repo inside the VM (as sbx).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloneStep {
    /// Where the clone goes: a guest-only volume at the host repo's path.
    pub dir: String,
    /// Only for a linked worktree, whose source HEAD is the main worktree's.
    pub head: Option<WorktreeHead>,
    /// Host remotes to copy (local ones and credentials already left out).
    pub remotes: Vec<(String, String)>,
}

impl CloneStep {
    /// The clone dir and its `.git`, quoted for `sh -c`.
    fn quoted(&self) -> (String, String) {
        (sh_quote(&self.dir), sh_quote(&format!("{}/.git", self.dir)))
    }
}

/// As root: the volume is root-owned and may hold `lost+found`, which `git clone` won't clone into.
pub(super) fn clone_prep_cmd(step: &CloneStep) -> String {
    let (d, git) = step.quoted();
    let lf = sh_quote(&format!("{}/lost+found", step.dir));
    format!("[ -d {git} ] && exit 0; rmdir {lf} 2>/dev/null; chown agent {d}")
}

/// As `agent`: sbx's clone command (skipped once cloned), then its remote copy, which runs on
/// every start so a failed add is retried and host remote changes arrive (as sbx's setup script).
/// A detached worktree's commit is checked out after the clone (a local clone copies every object,
/// so commits made while detached are there too). If that checkout still fails, the clone keeps
/// its default HEAD, with a warning, rather than failing every start. Only a hex commit id takes
/// that path: it's echoed unquoted inside the warning.
pub(super) fn clone_cmd(step: &CloneStep) -> String {
    let (d, git) = step.quoted();
    let clone = format!("git -c safe.directory={SOURCE_MOUNT} clone -q");
    let clone = match &step.head {
        Some(WorktreeHead::Branch(b)) => {
            format!("{clone} --branch {} {SOURCE_MOUNT} {d}", sh_quote(b))
        }
        Some(WorktreeHead::Detached(c)) if c.bytes().all(|b| b.is_ascii_hexdigit()) => format!(
            "{{ {clone} --no-checkout {SOURCE_MOUNT} {d} || exit 1; \
             git -C {d} checkout -q --detach {q} -- 2>/dev/null || {{ \
             git -C {d} reset -q --hard || {{ rm -rf {git}; exit 1; }}; \
             echo \"warning: commit {short} isn't in the clone; the agent starts \
             from $(git -C {d} symbolic-ref -q --short HEAD || echo HEAD) instead\" >&2; }}; }}",
            q = sh_quote(c),
            short = c.get(..12).unwrap_or(c),
        ),
        _ => format!("{clone} {SOURCE_MOUNT} {d}"),
    };
    let mut s = format!("set -e; [ -d {git} ] || {clone}; cd {d}");
    for (n, u) in &step.remotes {
        let (n, u) = (sh_quote(n), sh_quote(u));
        s.push_str(&format!(
            "; git remote set-url -- {n} {u} 2>/dev/null || git remote add -- {n} {u}"
        ));
    }
    s
}

/// Returns the guest's `warning:` lines for the caller to print: the detached-commit fallback's,
/// and any git prints itself (worth seeing too). The rest of git's stderr stays quiet.
pub(super) fn run_clone<R: Runner>(
    vm: &Smolvm<R>,
    sb: &Sandbox,
    step: &CloneStep,
) -> Result<Vec<String>> {
    let mut warnings = Vec::new();
    for (user, cmd) in [("root", clone_prep_cmd(step)), ("agent", clone_cmd(step))] {
        let out = vm
            .exec_captured(&ExecSpec::sh(&sb.machine, user, cmd))
            .map_err(|e| {
                // git's first error line, not the whole stderr.
                let text = match e.downcast_ref::<SmolvmError>() {
                    Some(s) => s.message.clone(),
                    None => format!("{e:#}"),
                };
                let line = text
                    .lines()
                    .find(|l| !l.trim().is_empty())
                    .unwrap_or("failed");
                anyhow::anyhow!("cloning the repo in the sandbox: {}", line.trim())
            })?;
        warnings.extend(
            out.stderr
                .lines()
                .filter(|l| l.starts_with("warning: "))
                .map(String::from),
        );
    }
    Ok(warnings)
}
