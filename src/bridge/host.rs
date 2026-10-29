//! The host commands behind the bridge (browser, clipboard) and when a session serves it.

use std::collections::BTreeMap;
use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};

use super::relay::Relays;
use super::server::{self, Handlers, Relay, Server};
use crate::config::Settings;
use crate::sandbox::Sandbox;
use crate::smolvm::{ProcessRunner, Runner};

/// Internal test overrides: a program run with the URL as its argument / the text on stdin.
const OPEN_CMD: &str = "SMOLBENTO_OPEN_CMD";
const COPY_CMD: &str = "SMOLBENTO_COPY_CMD";

/// Whether the host can open a browser: not over SSH, unless (on Linux) a display is forwarded.
/// sbx sets `SBX_NO_DISPLAY` in the same case.
pub fn has_display(env: &BTreeMap<String, String>, linux: bool) -> bool {
    let set = |k: &str| env.get(k).is_some_and(|v| !v.is_empty());
    !set("SSH_CONNECTION") || (linux && (set("DISPLAY") || set("WAYLAND_DISPLAY")))
}

/// Handlers that run the host's browser and clipboard commands, or the env overrides, and relay
/// login callbacks into `machine` with the `smolvm` binary.
pub fn handlers(
    env: &BTreeMap<String, String>,
    browser_enabled: bool,
    smolvm: &str,
    machine: &str,
) -> Handlers {
    let open_cmd = env.get(OPEN_CMD).cloned();
    let copy_cmd = env.get(COPY_CMD).cloned();
    Handlers {
        browser_enabled,
        open: Box::new(move |url| open_url(open_cmd.as_deref(), url)),
        copy: Box::new(move |text| copy_text(copy_cmd.as_deref(), text)),
        relay: relay(smolvm, machine),
    }
}

/// Starts the login callback relays; they stop when the handlers are dropped (the server stops).
fn relay(smolvm: &str, machine: &str) -> Relay {
    let runner = ProcessRunner::new(smolvm);
    let relays = Mutex::new(Relays::new(Box::new(move |args| runner.run(args)), machine));
    Box::new(move |port| {
        if let Some(warning) = relays.lock().ok().and_then(|mut r| r.start(port)) {
            eprintln!("{warning}");
        }
    })
}

/// Serves the sandbox's bridge for an attached session (`run`, `exec -it`) until the result is
/// dropped. `None` when the sandbox has no bridge, the host has no display, or another session
/// already serves it. Problems only warn: the session goes on and the shims fall back.
pub fn attach(env: &BTreeMap<String, String>, settings: &Settings, sb: &Sandbox) -> Option<Server> {
    if !sb.meta.bridge || !has_display(env, cfg!(target_os = "linux")) {
        return None;
    }
    let browser = settings.bool("browser.enabled").unwrap_or_else(|e| {
        eprintln!("warning: not opening URLs from the sandbox: {e:#}");
        false
    });
    let smolvm = settings
        .value("smolvm.path")
        .unwrap_or_else(|_| "smolvm".into());
    let h = handlers(env, browser, &smolvm, &sb.machine);
    server::serve(&super::host_socket(sb.name()), h).unwrap_or_else(|e| {
        eprintln!(
            "warning: {}: no browser and clipboard bridge: {e:#}",
            sb.name()
        );
        None
    })
}

fn open_url(cmd: Option<&str>, url: &str) -> Result<()> {
    let program = cmd.unwrap_or(if cfg!(target_os = "macos") {
        "open"
    } else {
        "xdg-open"
    });
    launch(program, &[url], OPEN_GRACE)
}

/// How long an opener has to fail before its URL counts as opened.
const OPEN_GRACE: Duration = Duration::from_secs(2);

/// Starts an opener: an exit within `grace` decides; one still running after it is left to run.
/// `xdg-open` can run the browser itself in the foreground, so it is never killed.
fn launch(program: &str, args: &[&str], grace: Duration) -> Result<()> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| format!("running {program}"))?;
    let until = Instant::now() + grace;
    while Instant::now() < until {
        if let Some(status) = child.try_wait()? {
            if !status.success() {
                bail!("{program} failed ({status})");
            }
            return Ok(());
        }
        thread::sleep(Duration::from_millis(20));
    }
    // Reaped when it exits, so it leaves no zombie.
    thread::spawn(move || child.wait());
    Ok(())
}

/// `pbcopy` on macOS; on Linux the first of `wl-copy`, `xclip`, `xsel` that works.
fn copy_text(cmd: Option<&str>, text: &[u8]) -> Result<()> {
    let candidates: &[(&str, &[&str])] = match cmd {
        Some(c) => &[(c, &[])],
        None if cfg!(target_os = "macos") => &[("pbcopy", &[])],
        None => &[
            ("wl-copy", &[]),
            ("xclip", &["-selection", "clipboard"]),
            ("xsel", &["-b", "-i"]),
        ],
    };
    let mut last = None;
    for (program, args) in candidates {
        match run(program, args, Some(text)) {
            Ok(()) => return Ok(()),
            Err(e) => last = Some(e),
        }
    }
    Err(last.unwrap_or_else(|| anyhow::anyhow!("no clipboard command")))
}

/// Runs a host command with nothing reaching the attached terminal; `input` goes to its stdin.
fn run(program: &str, args: &[&str], input: Option<&[u8]>) -> Result<()> {
    run_within(program, args, input, CMD_TIMEOUT)
}

/// How long a copier may run: requests are handled one at a time.
const CMD_TIMEOUT: Duration = Duration::from_secs(10);

/// `run`, killing the command after `timeout`.
fn run_within(program: &str, args: &[&str], input: Option<&[u8]>, timeout: Duration) -> Result<()> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| format!("running {program}"))?;
    if let (Some(input), Some(mut stdin)) = (input, child.stdin.take()) {
        // Its own thread: a command that never reads mustn't block us past the timeout. It ends
        // when the command does (the pipe breaks).
        let input = input.to_vec();
        thread::spawn(move || stdin.write_all(&input));
    }
    let until = Instant::now() + timeout;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= until {
            let _ = child.kill();
            let _ = child.wait();
            bail!("{program} didn't finish within {}s", timeout.as_secs());
        }
        thread::sleep(Duration::from_millis(20));
    };
    if !status.success() {
        bail!("{program} failed ({status})");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};

    fn env(vars: &[(&str, &str)]) -> BTreeMap<String, String> {
        vars.iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn no_display_over_ssh_unless_linux_forwards_one() {
        let ssh = ("SSH_CONNECTION", "10.0.0.1 22 10.0.0.2 22");
        for linux in [true, false] {
            assert!(has_display(&env(&[]), linux));
            assert!(has_display(&env(&[("DISPLAY", ":0")]), linux));
            assert!(!has_display(&env(&[ssh]), linux));
            assert!(has_display(&env(&[("SSH_CONNECTION", "")]), linux));
        }
        assert!(has_display(&env(&[ssh, ("DISPLAY", "localhost:10")]), true));
        assert!(has_display(
            &env(&[ssh, ("WAYLAND_DISPLAY", "wayland-0")]),
            true
        ));
        assert!(!has_display(&env(&[ssh, ("DISPLAY", "")]), true));
        // macOS opens a browser on the Mac's own screen, which an SSH user isn't at.
        assert!(!has_display(&env(&[ssh, ("DISPLAY", ":0")]), false));
    }

    /// A script that records its argv and stdin under `dir`, exiting with `code`.
    fn recorder(dir: &Path, code: i32) -> PathBuf {
        let script = dir.join("cmd");
        let out = dir.join("out");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}.args'\ncat > '{}.stdin'\nexit {code}\n",
                out.display(),
                out.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        script
    }

    fn test_handlers(vars: &[(&str, &str)], browser: bool) -> Handlers {
        handlers(&env(vars), browser, "/nonexistent/smolvm", "sbx-test")
    }

    fn read(dir: &Path, what: &str) -> String {
        std::fs::read_to_string(dir.join(format!("out.{what}"))).unwrap()
    }

    #[test]
    fn the_overrides_get_the_url_and_the_text() {
        let dir = tempfile::tempdir().unwrap();
        let cmd = recorder(dir.path(), 0).display().to_string();
        let h = test_handlers(&[(OPEN_CMD, &cmd), (COPY_CMD, &cmd)], true);
        (h.open)("https://example.com/?a=b c").unwrap();
        assert_eq!(read(dir.path(), "args"), "https://example.com/?a=b c\n");
        assert_eq!(read(dir.path(), "stdin"), "");
        (h.copy)(b"two\nlines\n").unwrap();
        assert_eq!(read(dir.path(), "args"), "\n");
        assert_eq!(read(dir.path(), "stdin"), "two\nlines\n");
    }

    #[test]
    fn a_failing_or_missing_command_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let cmd = recorder(dir.path(), 3).display().to_string();
        let h = test_handlers(&[(OPEN_CMD, &cmd), (COPY_CMD, &cmd)], true);
        assert!((h.open)("https://x").is_err());
        assert!((h.copy)(b"x").is_err());
        let missing = dir.path().join("missing").display().to_string();
        let h = test_handlers(&[(OPEN_CMD, &missing), (COPY_CMD, &missing)], true);
        let err = (h.open)("https://x").unwrap_err();
        assert!(format!("{err:#}").contains("running"), "{err:#}");
        assert!((h.copy)(b"x").is_err());
    }

    #[test]
    fn handlers_carry_the_browser_setting() {
        assert!(test_handlers(&[], true).browser_enabled);
        assert!(!test_handlers(&[], false).browser_enabled);
    }

    #[test]
    fn a_hung_command_is_killed_at_the_timeout() {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("hang");
        // Never reads its stdin and never exits on its own.
        std::fs::write(&script, "#!/bin/sh\nexec sleep 30\n").unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let program = script.display().to_string();
        let started = Instant::now();
        let big = vec![b'x'; 1 << 20];
        let err = run_within(&program, &[], Some(&big), Duration::from_millis(300)).unwrap_err();
        assert!(err.to_string().contains("didn't finish"), "{err:#}");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "{:?}",
            started.elapsed()
        );
    }

    #[test]
    fn an_opener_still_running_after_the_grace_is_left_running() {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("browser");
        let pid_file = dir.path().join("pid");
        // A browser in the foreground: never exits on its own.
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\necho $$ > '{}'\nexec sleep 30\n",
                pid_file.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let program = script.display().to_string();
        let started = Instant::now();
        launch(&program, &["https://x"], Duration::from_millis(300)).unwrap();
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "{:?}",
            started.elapsed()
        );
        let pid = std::fs::read_to_string(&pid_file)
            .unwrap()
            .trim()
            .to_string();
        let alive = || {
            Command::new("kill")
                .args(["-0", &pid])
                .status()
                .unwrap()
                .success()
        };
        thread::sleep(Duration::from_millis(200));
        assert!(alive(), "the opener was killed");
        Command::new("kill").arg(&pid).status().unwrap();
    }

    #[test]
    fn an_opener_that_fails_early_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let cmd = recorder(dir.path(), 1).display().to_string();
        let started = Instant::now();
        assert!(launch(&cmd, &["https://x"], OPEN_GRACE).is_err());
        assert!(started.elapsed() < OPEN_GRACE, "{:?}", started.elapsed());
        let ok = recorder(dir.path(), 0).display().to_string();
        assert!(launch(&ok, &["https://x"], OPEN_GRACE).is_ok());
    }
}
