//! Guest shell scripts for kit steps. Every value is single-quoted with `sh_quote`.

use std::path::Path;

use crate::kits::model::{FileReq, Hook, HookCmd};
use crate::sandbox::sh_quote;

pub const STARTUP_PATH: &str = "/etc/smolbento/startup";
pub const STARTUP_DIR: &str = "/etc/smolbento/startup.d";
pub const KITS_FILE: &str = "/etc/smolbento/kits";
pub const STARTUP_LOG: &str = "/var/log/sbx-kit-startup.log";

/// The kits' startup runner, as root on every start (`/etc/smolbento/startup [script…]`): one
/// pass over the `startup.d` scripts (or the ones named), in kit order, like sbx's dispatcher.
/// Blocking hooks run to completion and the first failure ends the pass with its exit code;
/// background hooks are started detached at their position.
pub const STARTUP_RUNNER: &str = r#"#!/bin/sh
# Written by smolbento: runs the kits' startup hooks, in order, on every start.
[ $# -gt 0 ] || set -- /etc/smolbento/startup.d/*.sh
exec >>/var/log/sbx-kit-startup.log 2>&1 </dev/null
echo "=== dispatcher run $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
cd /
for f; do
  [ -f "$f" ] || continue
  sh "$f" || { rc=$?; echo "kit startup exited with code $rc"; exit $rc; }
done
"#;

/// A portable env var name, safe to expand unquoted in a script.
pub fn is_env_name(v: &str) -> bool {
    let mut c = v.chars();
    c.next()
        .is_some_and(|f| f.is_ascii_alphabetic() || f == '_')
        && c.all(|x| x.is_ascii_alphanumeric() || x == '_')
}

/// CA settings smolvm gives the guest (its TLS-terminating proxy's bundle, for bound credentials).
/// Hooks keep them so install hooks can reach hosts that have a credential bound.
pub const CA_ENV: &[&str] = &[
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "CURL_CA_BUNDLE",
    "REQUESTS_CA_BUNDLE",
    "GIT_SSL_CAINFO",
    "NODE_EXTRA_CA_CERTS",
    "DENO_CERT",
];

/// A hook with only `PATH`, `HOME`, the `CA_ENV` vars that are set in the guest and its declared
/// env vars. The caller runs it from `/` as the hook's user (`exec -u`, or `as_user` in a startup
/// script).
pub fn hook_script(h: &Hook) -> String {
    let mut s = String::from(r#"env -i PATH="$PATH" HOME="$HOME""#);
    // `${V+V="$V"}` expands to one word when V is set (even empty) and to nothing when unset, so
    // an unset CA var stays unset rather than becoming an empty value.
    for v in CA_ENV {
        s.push_str(&format!(r#" ${{{v}+{v}="${v}"}}"#));
    }
    // apply refuses other names; skipping them here keeps the script well-formed regardless.
    for v in h.env.iter().filter(|v| is_env_name(v)) {
        s.push_str(&format!(r#" {v}="${v}""#));
    }
    match &h.command {
        HookCmd::Shell(c) => s.push_str(&format!(" sh -c {}", sh_quote(c))),
        HookCmd::Argv(argv) => {
            for a in argv {
                s.push(' ');
                s.push_str(&sh_quote(a));
            }
        }
    }
    s
}

/// `script` as `user` from a root shell. `runuser` where the image has it (util-linux), else `su`.
pub fn as_user(user: Option<&str>, script: &str) -> String {
    match user {
        None | Some("root") | Some("0") => script.to_string(),
        Some(u) => {
            let (u, q) = (sh_quote(u), sh_quote(script));
            format!(
                "if command -v runuser >/dev/null 2>&1; then runuser -u {u} -- sh -c {q}; \
                 else su -s /bin/sh {u} -c {q}; fi"
            )
        }
    }
}

/// A kit's `startup.d` script: its startup hooks in order. A blocking hook runs to completion and
/// logs `ok <script> hook N`; a failure exits with its code. A background hook is started in its
/// own session (`setsid`, else `nohup`), so it outlives the runner's exec, and logs
/// `started <script> hook N`; its failure is only logged.
pub fn startup_script(kit: &str, hooks: &[&Hook]) -> String {
    // The kit name only appears quoted.
    let mut s = String::from("#!/bin/sh\n# Kit startup hooks (written by smolbento).\ncd /\n");
    if hooks.iter().any(|h| h.background) {
        s.push_str("d=nohup; command -v setsid >/dev/null 2>&1 && d=setsid\n");
    }
    for (i, h) in hooks.iter().enumerate() {
        let run = as_user(h.user.as_deref(), &hook_script(h));
        let n = i + 1;
        let failed = sh_quote(&format!("smolbento: kit {kit} startup hook {n} failed"));
        if h.background {
            let body = sh_quote(&format!(
                "if {{ {run}; }}; then :; else echo {failed} \"(exit $?)\"; fi"
            ));
            s.push_str(&format!(
                "$d sh -c {body} &\necho \"started $0 hook {n}\"\n"
            ));
        } else {
            s.push_str(&format!(
                "if {{ {run}; }}; then echo \"ok $0 hook {n}\"; \
                 else rc=$?; echo {failed} \"(exit $rc)\"; exit $rc; fi\n"
            ));
        }
    }
    s
}

/// Mounts tmpfs volumes (lost on stop, so this runs on every start, first: `00-volumes.sh`). A
/// failed mount is logged, not fatal. `(path, mode)`.
pub fn tmpfs_script(volumes: &[(String, Option<String>)]) -> String {
    let mut s =
        String::from("#!/bin/sh\n# tmpfs volumes of the sandbox's kits (written by smolbento).\n");
    for (path, mode) in volumes {
        let p = sh_quote(path);
        // /proc/mounts escapes a space, tab, newline and backslash in a path as octal.
        let escaped: String = path
            .chars()
            .map(|c| match c {
                ' ' => "\\040".to_string(),
                '\t' => "\\011".to_string(),
                '\n' => "\\012".to_string(),
                '\\' => "\\134".to_string(),
                c => c.to_string(),
            })
            .collect();
        let mounted = sh_quote(&format!(" {escaped} tmpfs "));
        let opts = mode
            .as_ref()
            .map(|m| format!("-o mode={} ", sh_quote(m)))
            .unwrap_or_default();
        s.push_str(&format!(
            "mkdir -p {p} && {{ grep -qsF {mounted} /proc/mounts || mount -t tmpfs {opts}tmpfs {p}; }} \
             || echo {} \"(exit $?)\"\n",
            sh_quote(&format!("smolbento: mounting tmpfs {path} failed"))
        ));
    }
    s
}

/// Sets the guest's system git identity (`git-identity@1`), as root.
pub fn git_identity_script(name: &str, email: &str) -> String {
    format!(
        "git config --system user.name {} && git config --system user.email {}",
        sh_quote(name),
        sh_quote(email)
    )
}

const AGENT_HOME: &str = "/home/agent";

/// Sets `$o` to `agent` when the image has that user, else leaves it empty (no chown).
const OWNER: &str = "o=; id agent >/dev/null 2>&1 && o=agent";

/// Creates the missing parent directories of `path`. Those under the agent's home go to `$o`;
/// elsewhere they stay root's.
fn mkdirs(path: &str) -> String {
    let mut dirs: Vec<&Path> = Path::new(path)
        .parent()
        .map(|p| {
            p.ancestors()
                .filter(|a| a.parent().is_some() && !a.as_os_str().is_empty())
                .collect()
        })
        .unwrap_or_default();
    dirs.reverse();
    dirs.iter()
        .map(|d| {
            let q = sh_quote(&d.display().to_string());
            if d.starts_with(AGENT_HOME) && *d != Path::new(AGENT_HOME) {
                format!("[ -d {q} ] || {{ mkdir {q}; [ -z \"$o\" ] || chown \"$o\" {q}; }}\n")
            } else {
                format!("[ -d {q} ] || mkdir {q}\n")
            }
        })
        .collect()
}

/// Writes a kit file as root, then gives it to `agent`. Left alone when it exists and
/// `overwrite` is off.
pub fn file_script(f: &FileReq) -> String {
    let p = sh_quote(&f.path);
    let mut s = String::from("set -e\n");
    if !f.overwrite {
        s.push_str(&format!("[ -e {p} ] && exit 0\n"));
    }
    s.push_str(OWNER);
    s.push('\n');
    s.push_str(&mkdirs(&f.path));
    s.push_str(&format!("printf %s {} > {p}\n", sh_quote(&f.content)));
    if let Some(m) = &f.mode {
        s.push_str(&format!("chmod {} {p}\n", sh_quote(m)));
    }
    s.push_str(&format!("[ -z \"$o\" ] || chown \"$o\" {p}\n"));
    s
}

/// Replaces kit `kit`'s managed section in `file` with `body`, or appends it; text outside the
/// markers stays. `body` is inline text or `file:<in-image path>` (copied with `cat`).
pub fn context_script(file: &str, kit: &str, body: &str) -> String {
    context_script_parts(file, kit, &[body])
}

/// `context_script` with several bodies, one blank line apart (one section per kit and file).
pub fn context_script_parts(file: &str, kit: &str, bodies: &[&str]) -> String {
    let begin = sh_quote(&format!("<!-- smolbento:kit:{kit} -->"));
    let end = sh_quote(&format!("<!-- /smolbento:kit:{kit} -->"));
    let mut section = format!("printf '%s\\n' {begin}\n");
    for (i, b) in bodies.iter().enumerate() {
        if i > 0 {
            section.push_str("echo\n");
        }
        match b.strip_prefix("file:") {
            // `awk 1` ends the copy with a newline even when the file doesn't.
            Some(path) => section.push_str(&format!("awk 1 {}\n", sh_quote(path))),
            None => section.push_str(&format!(
                "printf '%s\\n' {}\n",
                sh_quote(b.trim_end_matches('\n'))
            )),
        }
    }
    section.push_str(&format!("printf '%s\\n' {end}\n"));
    let f = sh_quote(file);
    format!(
        "set -e\n{OWNER}\n{mkdirs}s=$(mktemp); t=$(mktemp)\n{{\n{section}}} > \"$s\"\n\
         new=; [ -e {f} ] || {{ : > {f}; new=1; }}\n\
         awk -v b={begin} -v e={end} -v s=\"$s\" '\n\
         function put(  l) {{ while ((getline l < s) > 0) print l; close(s); done = 1 }}\n\
         $0 == b {{ if (!done) put(); skip = 1; next }}\n\
         skip {{ if ($0 == e) skip = 0; next }}\n\
         {{ print }}\n\
         END {{ if (!done) {{ if (NR) print \"\"; put() }} }}' {f} > \"$t\"\n\
         cat \"$t\" > {f}\nrm -f \"$s\" \"$t\"\n\
         [ -z \"$new\" ] || [ -z \"$o\" ] || chown \"$o\" {f}\n",
        mkdirs = mkdirs(file),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kits::model::HookCmd;
    use std::process::Command;

    fn hook(cmd: HookCmd, env: &[&str]) -> Hook {
        Hook {
            command: cmd,
            user: None,
            env: env.iter().map(|s| s.to_string()).collect(),
            background: false,
        }
    }

    /// The CA pass-through `hook_script` puts after `HOME`.
    const CA: &str = concat!(
        r#" ${SSL_CERT_FILE+SSL_CERT_FILE="$SSL_CERT_FILE"}"#,
        r#" ${SSL_CERT_DIR+SSL_CERT_DIR="$SSL_CERT_DIR"}"#,
        r#" ${CURL_CA_BUNDLE+CURL_CA_BUNDLE="$CURL_CA_BUNDLE"}"#,
        r#" ${REQUESTS_CA_BUNDLE+REQUESTS_CA_BUNDLE="$REQUESTS_CA_BUNDLE"}"#,
        r#" ${GIT_SSL_CAINFO+GIT_SSL_CAINFO="$GIT_SSL_CAINFO"}"#,
        r#" ${NODE_EXTRA_CA_CERTS+NODE_EXTRA_CA_CERTS="$NODE_EXTRA_CA_CERTS"}"#,
        r#" ${DENO_CERT+DENO_CERT="$DENO_CERT"}"#,
    );

    fn sh(script: &str) -> std::process::Output {
        Command::new("sh").arg("-c").arg(script).output().unwrap()
    }

    #[test]
    fn a_mounted_tmpfs_with_a_space_in_its_path_is_seen() {
        let d = tempfile::tempdir().unwrap();
        let mounts = d.path().join("mounts");
        let script = tmpfs_script(&[("/data/my cache".into(), None)])
            .replace("/proc/mounts", &mounts.display().to_string())
            .replace("mkdir -p", "true")
            .replace("mount -t", "echo MOUNT");
        std::fs::write(&mounts, "tmpfs /data/my\\040cache tmpfs rw 0 0\n").unwrap();
        let out = String::from_utf8(sh(&script).stdout).unwrap();
        assert!(!out.contains("MOUNT"), "{out}");
        std::fs::write(&mounts, "tmpfs /data/my tmpfs rw 0 0\n").unwrap();
        let out = String::from_utf8(sh(&script).stdout).unwrap();
        assert!(out.contains("MOUNT"), "{out}");
    }

    #[test]
    fn hook_script_passes_only_declared_env() {
        let h = hook(HookCmd::Shell("echo hi".into()), &["FOO"]);
        assert_eq!(
            hook_script(&h),
            format!(r#"env -i PATH="$PATH" HOME="$HOME"{CA} FOO="$FOO" sh -c 'echo hi'"#)
        );
        let h = hook(HookCmd::Argv(vec!["echo".into(), "it's".into()]), &[]);
        assert_eq!(
            hook_script(&h),
            format!(r#"env -i PATH="$PATH" HOME="$HOME"{CA} 'echo' 'it'\''s'"#)
        );
    }

    #[test]
    fn hook_script_keeps_ca_vars_only_when_set() {
        let h = hook(
            HookCmd::Shell(
                "echo \"${SSL_CERT_FILE-unset}|${CURL_CA_BUNDLE-unset}|${DENO_CERT-unset}|${BAR-unset}\""
                    .into(),
            ),
            &[],
        );
        let out = Command::new("sh")
            .arg("-c")
            .arg(hook_script(&h))
            .env("SSL_CERT_FILE", "/run/smolvm/ca bundle.pem")
            .env("DENO_CERT", "")
            .env_remove("CURL_CA_BUNDLE")
            .env("BAR", "b")
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
        assert_eq!(
            String::from_utf8_lossy(&out.stdout),
            "/run/smolvm/ca bundle.pem|unset||unset\n"
        );
    }

    #[test]
    fn hook_script_runs_with_a_clean_env() {
        let h = hook(
            HookCmd::Shell("echo \"$FOO|${BAR:-unset}\"".into()),
            &["FOO"],
        );
        let out = Command::new("sh")
            .arg("-c")
            .arg(hook_script(&h))
            .env("FOO", "f")
            .env("BAR", "b")
            .output()
            .unwrap();
        assert_eq!(String::from_utf8_lossy(&out.stdout), "f|unset\n");
    }

    #[test]
    fn file_script_writes_and_honours_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a/b/f.txt").display().to_string();
        let mut f = FileReq {
            path: path.clone(),
            content: "one 'quoted' $HOME\n".into(),
            mode: Some("0600".into()),
            overwrite: false,
        };
        assert!(sh(&file_script(&f)).status.success());
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "one 'quoted' $HOME\n"
        );
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);

        f.content = "two".into();
        assert!(sh(&file_script(&f)).status.success());
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "one 'quoted' $HOME\n"
        );
        f.overwrite = true;
        assert!(sh(&file_script(&f)).status.success());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "two");
    }

    #[test]
    fn context_script_twice_leaves_one_section_below_user_text() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("CLAUDE.md");
        std::fs::write(&file, "# mine\nkeep me\n").unwrap();
        let f = file.display().to_string();
        let out = sh(&context_script(&f, "acme", "first body"));
        assert!(out.status.success(), "{out:?}");
        let out = sh(&context_script(&f, "acme", "second 'body'"));
        assert!(out.status.success(), "{out:?}");
        assert_eq!(
            std::fs::read_to_string(&file).unwrap(),
            "# mine\nkeep me\n\n<!-- smolbento:kit:acme -->\nsecond 'body'\n\
             <!-- /smolbento:kit:acme -->\n"
        );
    }

    #[test]
    fn context_script_creates_the_file_and_copies_an_in_image_file() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("ctx.md");
        std::fs::write(&src, "from image").unwrap();
        let file = dir.path().join("new/AGENTS.md");
        let f = file.display().to_string();
        let body = format!("file:{}", src.display());
        let out = sh(&context_script(&f, "k", &body));
        assert!(out.status.success(), "{out:?}");
        assert_eq!(
            std::fs::read_to_string(&file).unwrap(),
            "<!-- smolbento:kit:k -->\nfrom image\n<!-- /smolbento:kit:k -->\n"
        );
    }

    #[test]
    fn only_dirs_under_the_agent_home_are_given_to_agent() {
        let f = FileReq {
            path: "/home/agent/.config/x/f".into(),
            content: "c".into(),
            mode: None,
            overwrite: true,
        };
        let s = file_script(&f);
        assert!(s.contains("[ -d '/home/agent/.config' ] || { mkdir '/home/agent/.config'; [ -z \"$o\" ] || chown \"$o\" '/home/agent/.config'; }"), "{s}");
        assert!(s.contains("[ -d '/home' ] || mkdir '/home'\n"), "{s}");
        assert!(
            s.contains("[ -d '/home/agent' ] || mkdir '/home/agent'\n"),
            "{s}"
        );
        let s = file_script(&FileReq {
            path: "/etc/kit/conf".into(),
            ..f
        });
        assert!(s.contains("[ -d '/etc/kit' ] || mkdir '/etc/kit'\n"), "{s}");
        assert!(s.contains("chown \"$o\" '/etc/kit/conf'"), "{s}");
        assert!(!s.contains("chown \"$o\" '/etc/kit'\n"), "{s}");
    }

    #[test]
    fn startup_scripts_only_quote_the_kit_name() {
        let h = hook(HookCmd::Shell("true".into()), &[]);
        let s = startup_script("k", &[&h]);
        assert!(
            !s.lines()
                .any(|l| l.starts_with('#') && l.contains('k') && l.contains("kit k")),
            "{s}"
        );
        assert!(
            s.contains("'smolbento: kit k startup hook 1 failed'"),
            "{s}"
        );
    }

    /// A temp `startup.d` and log, and the runner pointed at them.
    struct Startup {
        d: tempfile::TempDir,
        runner: String,
    }

    impl Startup {
        /// `(file, kit, hooks)` scripts in `startup.d`.
        fn new(scripts: &[(&str, &str, Vec<&Hook>)]) -> Self {
            let d = tempfile::tempdir().unwrap();
            let dir = d.path().join("startup.d");
            std::fs::create_dir(&dir).unwrap();
            for (file, kit, hooks) in scripts {
                std::fs::write(dir.join(file), startup_script(kit, hooks)).unwrap();
            }
            let runner = STARTUP_RUNNER
                .replace(STARTUP_DIR, &dir.display().to_string())
                .replace(STARTUP_LOG, &d.path().join("log").display().to_string());
            Startup { d, runner }
        }

        fn path(&self, name: &str) -> String {
            self.d.path().join(name).display().to_string()
        }

        /// Runs the runner with `args` and returns its exit code.
        fn run(&self, args: &[&str]) -> Option<i32> {
            Command::new("sh")
                .arg("-c")
                .arg(&self.runner)
                .arg("startup")
                .args(args)
                .status()
                .unwrap()
                .code()
        }

        fn log(&self) -> String {
            std::fs::read_to_string(self.d.path().join("log")).unwrap_or_default()
        }

        /// The log once it contains `text` (polled for up to 2 s).
        fn log_with(&self, text: &str) -> String {
            for _ in 0..100 {
                if self.log().contains(text) {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            self.log()
        }
    }

    fn shell(cmd: &str) -> Hook {
        hook(HookCmd::Shell(cmd.into()), &[])
    }

    fn background(cmd: &str) -> Hook {
        Hook {
            background: true,
            ..shell(cmd)
        }
    }

    #[test]
    fn the_runner_runs_hooks_in_kit_order_and_stops_at_a_failure() {
        let (first, bad, third) = (
            shell("echo first"),
            shell("echo second; exit 3"),
            shell("echo third"),
        );
        let s = Startup::new(&[
            ("01-a.sh", "a", vec![&first]),
            ("02-b.sh", "b", vec![&bad]),
            ("03-c.sh", "c", vec![&third]),
        ]);
        assert_eq!(s.run(&[]), Some(3));
        let log = s.log();
        let dir = s.path("startup.d");
        assert!(log.starts_with("=== dispatcher run "), "{log}");
        assert!(
            log.contains(&format!("first\nok {dir}/01-a.sh hook 1\nsecond\n")),
            "{log}"
        );
        assert!(
            log.contains(
                "smolbento: kit b startup hook 1 failed (exit 3)\nkit startup exited with code 3\n"
            ),
            "{log}"
        );
        assert!(!log.contains("third"), "nothing after the failure: {log}");
    }

    /// sbx's order: a background hook starts at its position and the pass goes on, so a later
    /// kit's blocking hook can wait for it.
    #[test]
    fn a_later_blocking_hook_can_wait_for_an_earlier_background_hook() {
        let d = tempfile::tempdir().unwrap();
        let ready = d.path().join("ready").display().to_string();
        let service = background(&format!("sleep 0.3; touch '{ready}'; sleep 1"));
        let wait = shell(&format!(
            "i=0; while [ ! -e '{ready}' ]; do i=$((i+1)); [ $i -le 50 ] || exit 9; sleep 0.1; done"
        ));
        let s = Startup::new(&[
            ("01-svc.sh", "svc", vec![&service]),
            ("02-use.sh", "use", vec![&wait]),
        ]);
        let started = std::time::Instant::now();
        assert_eq!(s.run(&[]), Some(0), "{}", s.log());
        assert!(
            started.elapsed() < std::time::Duration::from_secs(1),
            "the runner didn't wait for the background hook to exit"
        );
        let log = s.log();
        let dir = s.path("startup.d");
        let svc = log.find(&format!("started {dir}/01-svc.sh hook 1\n"));
        let use_ = log.find(&format!("ok {dir}/02-use.sh hook 1\n"));
        assert!(svc.is_some() && use_.is_some() && svc < use_, "{log}");
    }

    #[test]
    fn the_runner_runs_only_the_scripts_it_is_given() {
        let (first, third) = (shell("echo first"), shell("echo third"));
        let s = Startup::new(&[
            ("01-a.sh", "a", vec![&first]),
            ("03-c.sh", "c", vec![&third]),
        ]);
        let c = format!("{}/03-c.sh", s.path("startup.d"));
        assert_eq!(s.run(&[&c]), Some(0));
        let log = s.log();
        assert!(log.contains(&format!("third\nok {c} hook 1\n")), "{log}");
        assert!(!log.contains("first"), "{log}");
    }

    #[test]
    fn a_failing_background_hook_is_only_logged() {
        let (bad, after) = (background("exit 4"), shell("echo after"));
        let s = Startup::new(&[("01-k.sh", "k", vec![&bad, &after])]);
        assert_eq!(s.run(&[]), Some(0));
        let log = s.log_with("(exit 4)");
        assert!(
            log.contains("smolbento: kit k startup hook 1 failed (exit 4)\n"),
            "{log}"
        );
        assert!(log.contains("after\n"), "{log}");
    }

    #[test]
    fn a_kits_startup_script_keeps_its_hooks_in_order() {
        let (a, b, c) = (shell("echo a"), background("echo b"), shell("echo c"));
        let s = startup_script("k", &[&a, &b, &c]);
        let at = |t: &str| s.find(t).unwrap_or_else(|| panic!("{t} in {s}"));
        assert!(
            at("'echo a'") < at("hook 1\"")
                && at("hook 1\"") < at("echo b")
                && at("echo b") < at("started $0 hook 2")
                && at("started $0 hook 2") < at("'echo c'"),
            "{s}"
        );
        assert!(s.contains("$d sh -c "), "{s}");
    }
}
