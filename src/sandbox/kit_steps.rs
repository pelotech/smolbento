//! Running a kit's install and startup steps in the guest.

use anyhow::{Context, Result, anyhow};

use super::{Event, Sandbox};
use crate::kits::apply::{InstallStep, KitSteps};
use crate::kits::guest;
use crate::smolvm::{ExecSpec, Runner, Smolvm, SmolvmError};
use crate::util::sh_quote;

/// Where `apply_kit_steps` failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KitPhase {
    /// An install hook (hooks that ran may have changed the guest).
    Install,
    /// The caller's step between the hooks and the files.
    AfterInstall,
    /// Files, agent context, startup scripts or the kits record.
    Write,
}

/// Applies kit steps to a running sandbox, for a create's first start and for `kit add`: install
/// hooks, then `after_install` (dropping the install-phase rules), then files, agent context, the
/// `startup.d` scripts, the startup runner and the kits record (written whole). `on` hears
/// `Install` for each kit: before its first install hook, and after the hooks for kits with none.
pub fn apply_kit_steps<R: Runner>(
    vm: &Smolvm<R>,
    sb: &Sandbox,
    steps: &KitSteps,
    after_install: impl FnOnce() -> Result<()>,
    on: &mut dyn FnMut(Event),
) -> std::result::Result<(), (KitPhase, anyhow::Error)> {
    let mut run = Steps { vm, sb, n: 0 };
    let mut told: Vec<&str> = Vec::new();
    for step in &steps.install {
        if let Some(kit) = step.kit.as_deref()
            && !told.contains(&kit)
        {
            on(Event::Install(kit));
            told.push(kit);
        }
        for line in run.install(step).map_err(|e| (KitPhase::Install, e))? {
            eprintln!("{line}");
        }
    }
    // The kits record's first column is each kit's name.
    for kit in steps
        .kits_record
        .lines()
        .filter_map(|l| l.split('\t').next())
    {
        if !told.contains(&kit) {
            on(Event::Install(kit));
            told.push(kit);
        }
    }
    after_install().map_err(|e| (KitPhase::AfterInstall, e))?;
    let mut write = || -> Result<()> {
        for script in &steps.files {
            run.run("root", script).context("writing kit files")?;
        }
        for script in &steps.context {
            run.run("root", script).context("writing agent context")?;
        }
        let mut files: Vec<(String, &str, &str)> = steps
            .startup_d
            .iter()
            .map(|(name, body)| {
                (
                    format!("{}/{name}", guest::STARTUP_DIR),
                    body.as_str(),
                    "644",
                )
            })
            .collect();
        files.push((guest::STARTUP_PATH.into(), guest::STARTUP_RUNNER, "755"));
        files.push((guest::KITS_FILE.into(), &steps.kits_record, "644"));
        put_files(vm, sb, &files).context("writing the kits' startup scripts")
    };
    write().map_err(|e| (KitPhase::Write, e))
}

/// Larger scripts are copied in rather than passed as `sh -c` argv, well under Linux's 128 KiB
/// limit per argument.
pub(super) const INLINE_MAX: usize = 64 * 1024;
pub(super) const STEP_DIR: &str = "/run/smolbento";

/// Runs guest scripts, numbering the ones copied in.
pub(super) struct Steps<'a, R: Runner> {
    pub(super) vm: &'a Smolvm<R>,
    pub(super) sb: &'a Sandbox,
    pub(super) n: usize,
}

impl<R: Runner> Steps<'_, R> {
    /// The exec for `script`, and the guest path it was copied to (if it was).
    pub(super) fn spec(&mut self, user: &str, script: &str) -> Result<(ExecSpec, Option<String>)> {
        let (cmd, copied) = if script.len() > INLINE_MAX {
            self.n += 1;
            let path = format!("{STEP_DIR}/step-{}.sh", self.n);
            put_files(self.vm, self.sb, &[(path.clone(), script, "644")])?;
            (vec!["sh".into(), path.clone()], Some(path))
        } else {
            (vec!["sh".into(), "-c".into(), script.into()], None)
        };
        let spec = ExecSpec {
            name: self.sb.machine.clone(),
            user: Some(user.into()),
            cmd,
            ..Default::default()
        };
        Ok((spec, copied))
    }

    /// Removes a copied-in script once it ran, as root (`/run/smolbento` is root's). Best effort:
    /// the step's own result is what matters.
    pub(super) fn remove(&self, copied: Option<String>) {
        if let Some(path) = copied {
            let _ = self.vm.exec_captured(&ExecSpec {
                name: self.sb.machine.clone(),
                user: Some("root".into()),
                cmd: vec!["rm".into(), "-f".into(), path],
                ..Default::default()
            });
        }
    }

    pub(super) fn run(&mut self, user: &str, script: &str) -> Result<()> {
        let (spec, copied) = self.spec(user, script)?;
        let result = self.vm.exec_captured(&spec);
        self.remove(copied);
        result?;
        Ok(())
    }

    /// An install step; a failure names it and carries the end of its output. A successful
    /// smolbento step (`kit: None`) returns its stderr lines for the user: the bundled skills
    /// step warns there about an optional skill it skipped. Kit hooks' output stays quiet.
    pub(super) fn install(&mut self, step: &InstallStep) -> Result<Vec<String>> {
        let (spec, copied) = self.spec(step.user.as_deref().unwrap_or("root"), &step.script)?;
        let out = self.vm.exec_output(&spec);
        self.remove(copied);
        let out = out.with_context(|| format!("{} failed", step.label))?;
        if out.code == 0 {
            if !step.relay_stderr {
                return Ok(Vec::new());
            }
            return Ok(out
                .stderr
                .lines()
                .map(str::trim_end)
                .filter(|l| !l.is_empty())
                .map(String::from)
                .collect());
        }
        let text = if out.stderr.trim().is_empty() {
            out.stdout.clone()
        } else {
            SmolvmError::from_output(&out).message
        };
        let tail = last_lines(&text, 20);
        if tail.is_empty() {
            anyhow::bail!("{} failed (exit {})", step.label, out.code);
        }
        anyhow::bail!("{} failed:\n{tail}", step.label)
    }
}

/// Writes `(guest path, content, mode)` files as root via host temp files and `machine cp`
/// (which copies single files only).
pub(super) fn put_files<R: Runner>(
    vm: &Smolvm<R>,
    sb: &Sandbox,
    files: &[(String, &str, &str)],
) -> Result<()> {
    let root = |script: String| vm.exec_captured(&ExecSpec::sh(&sb.machine, "root", script));
    let mut dirs: Vec<String> = files
        .iter()
        .filter_map(|(p, _, _)| std::path::Path::new(p).parent())
        .map(|d| sh_quote(&d.display().to_string()))
        .collect();
    dirs.sort();
    dirs.dedup();
    root(format!("mkdir -p {}", dirs.join(" ")))?;
    let tmp = tempfile::tempdir().context("creating a temp dir")?;
    for (i, (path, content, _)) in files.iter().enumerate() {
        let host = tmp.path().join(i.to_string());
        std::fs::write(&host, content).with_context(|| format!("writing {}", host.display()))?;
        vm.cp(
            &host.display().to_string(),
            &format!("{}:{path}", sb.machine),
        )
        .with_context(|| format!("copying {path} into the sandbox"))?;
    }
    let chmod: Vec<String> = files
        .iter()
        .map(|(p, _, mode)| format!("chmod {mode} {}", sh_quote(p)))
        .collect();
    root(chmod.join(" && "))?;
    Ok(())
}

/// The last `n` lines of `text`.
pub(super) fn last_lines(text: &str, n: usize) -> String {
    let lines: Vec<&str> = text.trim_end().lines().collect();
    lines[lines.len().saturating_sub(n)..].join("\n")
}

/// The startup runner's command, as root; `script` limits it to one kit's `startup.d` script. A
/// no-op without kits.
pub fn startup_cmd(script: Option<&str>) -> String {
    let script = script
        .map(|s| format!(" {}", sh_quote(s)))
        .unwrap_or_default();
    format!(
        "[ -x {p} ] || exit 0; exec {p}{script}",
        p = guest::STARTUP_PATH
    )
}

/// Runs the kits' startup hooks (or one kit's `script`) as sbx does on every start: one pass in
/// kit order that waits for each blocking hook and starts each background one detached at its
/// position. A failed blocking hook is an error with sbx's text (its output is in the guest's
/// startup log).
pub fn run_startup<R: Runner>(vm: &Smolvm<R>, sb: &Sandbox, script: Option<&str>) -> Result<()> {
    let what = "running the kits' startup hooks";
    let out = vm
        .exec_output(&ExecSpec::sh(&sb.machine, "root", startup_cmd(script)))
        .context(what)?;
    if out.code != 0 {
        // The runner writes only to its log; a smolvm error envelope means smolvm failed. Any
        // other stderr comes from the guest, so the start gets sbx's text.
        if let Some(e) = SmolvmError::from_json(&out) {
            return Err(anyhow!(e.message).context(what));
        }
        anyhow::bail!("kit startup exited with code {}", out.code);
    }
    Ok(())
}
