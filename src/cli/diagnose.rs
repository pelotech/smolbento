//! diagnose: checks smolvm, its home and host tools, the hypervisor and the config file.

use anyhow::Result;
use std::io::Write;
use std::path::PathBuf;

use super::{Ctx, DiagnoseArgs, DiagnoseFormat, Format};
use crate::smolvm::Runner;

pub fn run<R: Runner>(ctx: &mut Ctx<R>, a: &DiagnoseArgs) -> Result<i32> {
    // Refused before any check runs: nothing is ever sent anywhere.
    super::refuse_as(
        &[(a.upload, "--upload")],
        "isn't supported: smolbento has no support service to upload a report to",
    )?;
    // Named for `--json`, as sbx names its checks.
    let mut named = vec![
        ("smolvm", smolvm_check(ctx)),
        ("smolvm.home", home_check(ctx)),
    ];
    #[cfg(target_os = "macos")]
    named.push(("mkfs.ext4", mkfs_check(&mkfs_dirs(&ctx.env))));
    #[cfg(target_os = "linux")]
    named.push(("libbz2", libbz2_check(&lib_dirs())));
    #[cfg(target_os = "linux")]
    named.push(("kvm", kvm_check()));
    #[cfg(target_os = "macos")]
    named.push((
        "hypervisor entitlement",
        entitlement_check(&ctx.smolvm.bin.display().to_string(), &ctx.env),
    ));
    named.push(("config", config_check(ctx)));
    named.extend(services_check(ctx).map(|c| ("host services", c)));
    let checks: Vec<(bool, String)> = named.iter().map(|(_, c)| c.clone()).collect();
    let (text, code) = report(&checks);
    let doc = structured(&named);
    // `--json` wins over `--format`, which defaults to a table.
    let format = if a.json {
        Some(Format::Json)
    } else {
        a.format.map_or(Some(Format::Table), DiagnoseFormat::shared)
    };
    let text = match format {
        Some(f) => f.structured(&doc)?.unwrap_or(text),
        None => github_issue(&doc)?,
    };
    write!(&ctx.out, "{text}")?;
    Ok(code)
}

#[derive(serde::Serialize)]
struct Check<'a> {
    #[serde(skip)]
    ok: bool,
    name: &'a str,
    status: &'static str,
    message: &'a str,
    detail: &'static str,
    hint: &'static str,
}

/// How many checks ended in each of sbx's states; smolbento's checks only pass or fail.
#[derive(serde::Serialize)]
struct Summary {
    pass: usize,
    warn: usize,
    fail: usize,
    skip: usize,
}

/// sbx's `diagnose --json` shape: `{version, checks: [{name, status, message, detail, hint}],
/// summary}`.
#[derive(serde::Serialize)]
struct Doc<'a> {
    version: &'static str,
    checks: Vec<Check<'a>>,
    summary: Summary,
}

fn structured<'a>(named: &'a [(&'a str, (bool, String))]) -> Doc<'a> {
    let checks: Vec<Check> = named
        .iter()
        .map(|(name, (ok, message))| Check {
            ok: *ok,
            name,
            status: if *ok { "pass" } else { "fail" },
            message,
            detail: "",
            hint: "",
        })
        .collect();
    let pass = checks.iter().filter(|c| c.ok).count();
    Doc {
        version: "1.0",
        summary: Summary {
            pass,
            warn: 0,
            fail: checks.len() - pass,
            skip: 0,
        },
        checks,
    }
}

/// sbx's `--format github-issue`: Markdown to paste into an issue, with the JSON folded away.
/// OS and architecture are named as sbx (Go) names them.
fn github_issue(doc: &Doc) -> Result<String> {
    let os = match std::env::consts::OS {
        "macos" => "darwin",
        os => os,
    };
    let arch = match std::env::consts::ARCH {
        "aarch64" => "arm64",
        "x86_64" => "amd64",
        arch => arch,
    };
    let mut out = format!(
        "### bento diagnose report\n\n**OS:** {os}\n**Arch:** {arch}\n\
         **smolbento Version:** v{}\n\n\
         | Check | Status | Message |\n|-------|--------|---------|\n",
        env!("CARGO_PKG_VERSION")
    );
    for c in &doc.checks {
        let mark = if c.ok { "✓" } else { "✗" };
        // A `|` or a line break in a message would end the cell.
        let message = c.message.replace('|', "\\|").replace('\n', " ");
        out.push_str(&format!("| {} | {mark} | {message} |\n", c.name));
    }
    out.push_str(&format!(
        "\n<details>\n<summary>Full JSON output</summary>\n\n```json\n{}\n```\n\n</details>\n",
        serde_json::to_string_pretty(doc)?
    ));
    Ok(out)
}

pub fn report(checks: &[(bool, String)]) -> (String, i32) {
    let text = checks
        .iter()
        .map(|(ok, msg)| format!("{} {msg}\n", if *ok { "ok  " } else { "FAIL" }))
        .collect();
    let code = if checks.iter().all(|(ok, _)| *ok) {
        0
    } else {
        1
    };
    (text, code)
}

/// The smolvm `bento` runs: the pinned release (or not downloaded yet), or the explicit
/// `smolvm.path`, whose version is only noted when it differs from the pin.
pub fn smolvm_check<R: Runner>(ctx: &Ctx<R>) -> (bool, String) {
    let pinned = &crate::smolvm::pin::pin().version;
    let cmd = &ctx.smolvm;
    if cmd.managed && !cmd.bin.is_file() {
        return (
            true,
            format!(
                "smolvm {pinned} (pinned) isn't downloaded yet: the first command that needs it \
                 downloads it, or run `bento smolvm --version`"
            ),
        );
    }
    let v = match ctx.vm.version() {
        Ok(v) => v,
        Err(e) => return (false, format!("smolvm: {e:#}")),
    };
    let msg = if cmd.managed {
        format!("smolvm {v} (pinned, {})", cmd.bin.display())
    } else if &v == pinned {
        format!("smolvm {v} ({}, from smolvm.path)", cmd.bin.display())
    } else {
        format!(
            "smolvm {v} ({}, from smolvm.path; smolbento is tested with {pinned})",
            cmd.bin.display()
        )
    };
    (true, msg)
}

/// `smolvm.home`, and on macOS how long its longest socket path is against the limit.
fn home_check<R: Runner>(ctx: &Ctx<R>) -> (bool, String) {
    let home = &ctx.smolvm.home;
    if !cfg!(target_os = "macos") {
        return (true, format!("smolvm.home {}", home.display()));
    }
    match crate::smolvm::locate::socket_room(home) {
        Ok(n) => (
            true,
            format!(
                "smolvm.home {} (longest socket path {n} of {} bytes)",
                home.display(),
                crate::smolvm::locate::MACOS_SOCKET_LIMIT
            ),
        ),
        Err(e) => (false, format!("{e:#}")),
    }
}

/// Finds `name` in `dirs`. Missing, it's a failure unless `required` is false (then a note), with
/// `hint` saying what to do.
fn tool_check(name: &str, dirs: &[PathBuf], required: bool, hint: &str) -> (bool, String) {
    match dirs.iter().map(|d| d.join(name)).find(|p| p.exists()) {
        Some(p) => (true, format!("{name} {}", p.display())),
        None => (!required, format!("{name} not found: {hint}")),
    }
}

/// macOS: where smolvm looks for `mkfs.ext4` (PATH, then Homebrew's e2fsprogs).
#[cfg(target_os = "macos")]
fn mkfs_dirs(env: &std::collections::BTreeMap<String, String>) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = env
        .get("PATH")
        .map(|p| std::env::split_paths(p).collect())
        .unwrap_or_default();
    dirs.extend(
        [
            "/opt/homebrew/opt/e2fsprogs/sbin",
            "/usr/local/opt/e2fsprogs/sbin",
            "/opt/homebrew/sbin",
        ]
        .map(PathBuf::from),
    );
    dirs
}

/// `mkfs.ext4`: smolvm needs it only for disks larger than its templates, so it's a note.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn mkfs_check(dirs: &[PathBuf]) -> (bool, String) {
    tool_check(
        "mkfs.ext4",
        dirs,
        false,
        "disks larger than smolvm's templates need it (brew install e2fsprogs)",
    )
}

/// Linux: where the system's libraries are.
#[cfg(target_os = "linux")]
fn lib_dirs() -> Vec<PathBuf> {
    [
        "/lib",
        "/usr/lib",
        "/lib64",
        "/usr/lib64",
        "/lib/x86_64-linux-gnu",
        "/usr/lib/x86_64-linux-gnu",
        "/lib/aarch64-linux-gnu",
        "/usr/lib/aarch64-linux-gnu",
    ]
    .map(PathBuf::from)
    .to_vec()
}

/// `libbz2.so.1`: the downloaded smolvm needs the system's.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn libbz2_check(dirs: &[PathBuf]) -> (bool, String) {
    tool_check(
        "libbz2.so.1",
        dirs,
        true,
        "smolvm needs it (install your distribution's bzip2 library)",
    )
}

fn config_check<R: Runner>(ctx: &Ctx<R>) -> (bool, String) {
    let path = ctx.paths.config_file();
    match &ctx.config_error {
        Some(err) => (false, format!("config {}: {err}", path.display())),
        None => (true, format!("config {}", path.display())),
    }
}

/// Units whose sandbox smolvm no longer has (deleted with `smolvm machine delete`).
fn services_check<R: Runner>(ctx: &Ctx<R>) -> Option<(bool, String)> {
    let orphans = crate::provision::orphan_services(ctx);
    (!orphans.is_empty()).then(|| {
        (
            false,
            format!(
                "host services left by removed sandboxes: {}; `{} prune` removes them",
                orphans.join(", "),
                ctx.program
            ),
        )
    })
}

#[cfg(target_os = "linux")]
fn kvm_check() -> (bool, String) {
    match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/kvm")
    {
        Ok(_) => (true, "/dev/kvm is accessible".into()),
        Err(e) => (
            false,
            format!("/dev/kvm: {e}; enable KVM and add your user to the kvm group"),
        ),
    }
}

/// smolvm needs `com.apple.security.hypervisor`; Homebrew installs a wrapper script next to the
/// signed `smolvm-bin`.
#[cfg(target_os = "macos")]
fn entitlement_check(
    smolvm: &str,
    env: &std::collections::BTreeMap<String, String>,
) -> (bool, String) {
    use std::path::{Path, PathBuf};

    let found: Option<PathBuf> = if smolvm.contains('/') {
        Some(PathBuf::from(smolvm))
    } else {
        crate::util::find_on_path(env.get("PATH"), smolvm)
    };
    let Some(path) = found.and_then(|p| p.canonicalize().ok()) else {
        return (false, format!("{smolvm} not found on PATH"));
    };
    let bin = path.with_file_name("smolvm-bin");
    let bin = if bin.is_file() { bin } else { path };
    let out = std::process::Command::new("codesign")
        .args(["-d", "--entitlements", "-", "--xml"])
        .arg(Path::new(&bin))
        .output();
    match out {
        Ok(o) if String::from_utf8_lossy(&o.stdout).contains("com.apple.security.hypervisor") => (
            true,
            format!("{} has the hypervisor entitlement", bin.display()),
        ),
        Ok(_) => (
            false,
            format!(
                "{} lacks com.apple.security.hypervisor; reinstall smolvm",
                bin.display()
            ),
        ),
        Err(e) => (false, format!("codesign: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;

    #[test]
    fn report_formats_and_fails_on_any_failure() {
        let (text, code) = report(&[(true, "a".into()), (false, "b".into())]);
        assert_eq!(text, "ok   a\nFAIL b\n");
        assert_eq!(code, 1);
        assert_eq!(report(&[(true, "a".into())]).1, 0);
    }

    #[test]
    fn invalid_config_fails_the_config_check() {
        let mut t = test_env(&[]);
        let file = t.ctx.paths.config_file().display().to_string();
        assert_eq!(config_check(&t.ctx), (true, format!("config {file}")));
        break_config(&mut t);
        let (ok, msg) = config_check(&t.ctx);
        assert!(!ok);
        assert!(
            msg.starts_with(&format!("config {file}: TOML parse error")),
            "{msg}"
        );
        assert_eq!(t.sbt(&["diagnose"]).unwrap(), 1);
    }

    fn pinned() -> &'static str {
        &crate::smolvm::pin::pin().version
    }

    #[test]
    fn an_explicit_smolvm_is_named_and_a_differing_version_noted() {
        let t = test_env(&[]);
        // test_env's smolvm is explicit, at the pinned version.
        t.runner()
            .ok(&["--version"], &format!("smolvm {}\n", pinned()));
        assert_eq!(
            smolvm_check(&t.ctx),
            (
                true,
                format!(
                    "smolvm {} (/nonexistent/smolvm, from smolvm.path)",
                    pinned()
                )
            )
        );
        // No floor: an explicit smolvm is the user's; a different version is only noted.
        t.runner().ok(&["--version"], "smolvm 1.0.0\n");
        assert_eq!(
            smolvm_check(&t.ctx),
            (
                true,
                format!(
                    "smolvm 1.0.0 (/nonexistent/smolvm, from smolvm.path; smolbento is tested \
                     with {})",
                    pinned()
                )
            )
        );
    }

    #[test]
    fn a_managed_smolvm_not_yet_downloaded_says_when_it_will_be() {
        let mut t = test_env(&[]);
        t.use_managed_smolvm();
        let (ok, msg) = smolvm_check(&t.ctx);
        assert!(ok);
        assert_eq!(
            msg,
            format!(
                "smolvm {} (pinned) isn't downloaded yet: the first command that needs it \
                 downloads it, or run `bento smolvm --version`",
                pinned()
            )
        );
    }

    #[test]
    fn json_has_sbxs_shape() {
        let mut t = test_env(&[]);
        t.sbt(&["diagnose", "--json"]).ok();
        let out = t.stdout();
        assert!(
            out.starts_with("{\n  \"version\": \"1.0\",\n  \"checks\": ["),
            "{out}"
        );
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        let first = &v["checks"][0];
        assert_eq!(first["name"], "smolvm");
        assert!(["pass", "fail"].contains(&first["status"].as_str().unwrap()));
        for key in ["message", "detail", "hint"] {
            assert!(first[key].is_string(), "{key}");
        }
    }

    #[test]
    fn github_issue_is_sbxs_report_with_the_json_folded() {
        let named = [
            ("smolvm", (true, "smolvm 1.35.1 (pinned)".to_string())),
            ("config", (false, "config a|b: bad".to_string())),
        ];
        let out = github_issue(&structured(&named)).unwrap();
        let (head, rest) = out.split_once("| Check |").unwrap();
        let mut lines = head.lines();
        assert_eq!(lines.next(), Some("### bento diagnose report"));
        assert_eq!(lines.next(), Some(""));
        assert!(lines.next().unwrap().starts_with("**OS:** "));
        assert!(lines.next().unwrap().starts_with("**Arch:** "));
        assert_eq!(
            lines.next().unwrap(),
            format!("**smolbento Version:** v{}", env!("CARGO_PKG_VERSION"))
        );
        assert_eq!(
            rest,
            r#" Status | Message |
|-------|--------|---------|
| smolvm | ✓ | smolvm 1.35.1 (pinned) |
| config | ✗ | config a\|b: bad |

<details>
<summary>Full JSON output</summary>

```json
{
  "version": "1.0",
  "checks": [
    {
      "name": "smolvm",
      "status": "pass",
      "message": "smolvm 1.35.1 (pinned)",
      "detail": "",
      "hint": ""
    },
    {
      "name": "config",
      "status": "fail",
      "message": "config a|b: bad",
      "detail": "",
      "hint": ""
    }
  ],
  "summary": {
    "pass": 1,
    "warn": 0,
    "fail": 1,
    "skip": 0
  }
}
```

</details>
"#
        );
    }

    #[test]
    fn format_github_issue_keeps_the_exit_code() {
        let mut t = test_env(&[]);
        break_config(&mut t);
        assert_eq!(t.sbt(&["diagnose", "--format", "github-issue"]).unwrap(), 1);
        let out = t.stdout();
        assert!(
            out.starts_with("### bento diagnose report\n\n**OS:** "),
            "{out}"
        );
        assert!(out.ends_with("```\n\n</details>\n"), "{out}");
    }

    #[test]
    fn upload_is_refused_before_anything_runs() {
        let mut t = test_env(&[]);
        let err = t.sbt(&["diagnose", "--upload"]).unwrap_err();
        assert_eq!(super::super::exit_code(&err), 2);
        assert_eq!(
            err.to_string(),
            "--upload isn't supported: smolbento has no support service to upload a report to"
        );
        assert_eq!(t.stdout(), "");
        assert!(t.calls().is_empty());
    }

    #[test]
    fn home_is_reported_with_its_socket_room_on_macos() {
        let t = test_env(&[("HOME", "/Users/jhill")]);
        let (ok, msg) = home_check(&t.ctx);
        assert!(ok);
        if cfg!(target_os = "macos") {
            assert_eq!(
                msg,
                "smolvm.home /Users/jhill/.smolbento (longest socket path 84 of 103 bytes)"
            );
        } else {
            assert_eq!(msg, "smolvm.home /Users/jhill/.smolbento");
        }
    }

    #[test]
    fn host_tools_are_found_or_explained() {
        let dir = tempfile::tempdir().unwrap();
        let dirs = [dir.path().to_path_buf()];
        assert_eq!(
            mkfs_check(&dirs),
            (
                true,
                "mkfs.ext4 not found: disks larger than smolvm's templates need it (brew install \
                 e2fsprogs)"
                    .to_string()
            )
        );
        std::fs::write(dir.path().join("mkfs.ext4"), "").unwrap();
        assert_eq!(
            mkfs_check(&dirs),
            (
                true,
                format!("mkfs.ext4 {}", dir.path().join("mkfs.ext4").display())
            )
        );
        assert_eq!(
            libbz2_check(&dirs),
            (
                false,
                "libbz2.so.1 not found: smolvm needs it (install your distribution's bzip2 \
                 library)"
                    .to_string()
            )
        );
        std::fs::write(dir.path().join("libbz2.so.1"), "").unwrap();
        assert!(libbz2_check(&dirs).0);
    }
}
