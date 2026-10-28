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
# Some images have no /var/log.
log=/var/log/sbx-kit-startup.log
mkdir -p "${log%/*}"
exec >>"$log" 2>&1 </dev/null
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

/// What sbx keeps in a v3 install hook's `env -i`, before the `CA_ENV` vars.
const CLEAN_ENV: &[&str] = &[
    "PATH",
    "HOME",
    "USER",
    "TERM",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "http_proxy",
    "https_proxy",
    "NO_PROXY",
    "no_proxy",
];

/// A hook's command line, run as the hook's user (`exec -u`, or `as_user` in a startup script).
/// A `clean_env` hook (v3 install) gets sbx's `env -i` with only the `CLEAN_ENV` and `CA_ENV` vars
/// that are set in the guest and its declared env vars; any other hook inherits the container's
/// environment, as in sbx.
pub fn hook_script(h: &Hook) -> String {
    let mut s = String::new();
    if h.clean_env {
        s.push_str("env -i");
        // `${V+V="$V"}` expands to one word when V is set (even empty) and to nothing when unset,
        // so an unset var stays unset rather than becoming an empty value.
        for v in CLEAN_ENV.iter().chain(CA_ENV) {
            s.push_str(&format!(r#" ${{{v}+{v}="${v}"}}"#));
        }
        // apply refuses other names; skipping them here keeps the script well-formed regardless.
        for v in h.env.iter().filter(|v| is_env_name(v)) {
            s.push_str(&format!(r#" {v}="${v}""#));
        }
        s.push(' ');
    }
    match &h.command {
        HookCmd::Shell(c) => s.push_str(&format!("sh -c {}", sh_quote(c))),
        HookCmd::Argv(argv) => {
            let words: Vec<String> = argv.iter().map(|a| sh_quote(a)).collect();
            s.push_str(&words.join(" "));
        }
    }
    s
}

/// `script` as `user` from a root shell. `runuser` where the image has it (util-linux), else `su`.
/// A numeric user runs as the account with that uid (`agent` has moved off uid 1000 to the host's
/// uid, so a uid alone can't name it); a uid with no account runs through `setpriv`, if present.
/// Exactly `1000` is sbx's image `agent` (uid 1000 there), so it runs as `agent` when the guest
/// has that account, whatever uid it holds now.
pub fn as_user(user: Option<&str>, script: &str) -> String {
    as_user_in(user, script, "/etc/passwd")
}

/// `as_user` against `passwd` (tests use a temp file).
fn as_user_in(user: Option<&str>, script: &str, passwd: &str) -> String {
    let q = sh_quote(script);
    let by_name = |u: &str| {
        format!(
            "if command -v runuser >/dev/null 2>&1; then runuser -u {u} -- sh -c {q}; \
             else su -s /bin/sh {u} -c {q}; fi"
        )
    };
    match user {
        None | Some("root") | Some("0") => script.to_string(),
        Some(u) if !u.is_empty() && u.bytes().all(|b| b.is_ascii_digit()) => {
            let missing = sh_quote(&format!(
                "smolbento: no account has uid {u}, and no setpriv"
            ));
            let numeric = format!(
                "if _sbu=$(awk -F: -v u={u} '$3 == u {{ print $1; exit }}' {passwd}) \
                 && [ -n \"$_sbu\" ]; then {run}; \
                 elif command -v setpriv >/dev/null 2>&1; then \
                 setpriv --reuid {u} --regid {u} --clear-groups sh -c {q}; \
                 else echo {missing} >&2; false; fi",
                passwd = sh_quote(passwd),
                run = by_name("\"$_sbu\""),
            );
            if u == "1000" {
                format!(
                    "if awk -F: '$1 == \"agent\" {{ f = 1 }} END {{ exit !f }}' {passwd}; \
                     then {agent}; else {numeric}; fi",
                    passwd = sh_quote(passwd),
                    agent = by_name("agent"),
                )
            } else {
                numeric
            }
        }
        Some(u) => by_name(&sh_quote(u)),
    }
}

/// A kit's `startup.d` script: its startup hooks in order. A blocking hook runs to completion and
/// logs `ok <script> hook N`; a failure exits with its code. A background hook is started detached
/// and logs `ok <script> hook N` at once, as sbx does; its failure is only logged. With `setsid` it
/// gets its own session, so it outlives the runner's exec on a normal finish; the `nohup` fallback
/// stays in the runner's process group, so a kill of that group takes it too.
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
            s.push_str(&format!("$d sh -c {body} &\necho \"ok $0 hook {n}\"\n"));
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

/// The directory, next to the agent file, holding one `<kit>.md` per mixin with agent context.
pub const KITS_CONTEXT_DIR: &str = "kits-agent-context";
/// The markers around sbx's kits index in the agent file.
pub const KITS_SECTION_START: &str = "<!-- sbx:kits-section start -->";
pub const KITS_SECTION_END: &str = "<!-- sbx:kits-section end -->";

/// Shell commands printing `bodies` one blank line apart. A body is inline text or
/// `file:<in-image path>` (copied with `awk 1`, which ends it with a newline).
fn print_bodies(bodies: &[&str]) -> String {
    let mut s = String::new();
    for (i, b) in bodies.iter().enumerate() {
        if i > 0 {
            s.push_str("echo\n");
        }
        match b.strip_prefix("file:") {
            Some(path) => s.push_str(&format!("awk 1 {}\n", sh_quote(path))),
            None => s.push_str(&format!(
                "printf '%s\\n' {}\n",
                sh_quote(b.trim_end_matches('\n'))
            )),
        }
    }
    s
}

/// Appends `bodies` to the agent file `file`, one blank line apart, with no markers (a workload
/// kit's own agent context, written once at create).
pub fn append_context_script(file: &str, bodies: &[&str]) -> String {
    let f = sh_quote(file);
    format!(
        "set -e\n{OWNER}\n{mkdirs}new=; [ -e {f} ] || new=1\n\
         if [ -s {f} ]; then {{ [ -z \"$(tail -c 1 {f})\" ] || echo; echo; }} >> {f}; fi\n\
         {{\n{body}}} >> {f}\n\
         [ -z \"$new\" ] || [ -z \"$o\" ] || chown \"$o\" {f}\n",
        mkdirs = mkdirs(file),
        body = print_bodies(bodies),
    )
}

/// Writes a mixin's agent context to its own file `path`, replacing it; the file and its
/// directory go to `agent`.
pub fn kit_context_script(path: &str, bodies: &[&str]) -> String {
    let p = sh_quote(path);
    let dir = Path::new(path)
        .parent()
        .map_or_else(|| "/".to_string(), |d| d.display().to_string());
    format!(
        "set -e\n{OWNER}\n{mkdirs}{{\n{body}}} > {p}\n[ -z \"$o\" ] || chown \"$o\" {d} {p}\n",
        mkdirs = mkdirs(path),
        body = print_bodies(bodies),
        d = sh_quote(&dir),
    )
}

/// Puts one `- **<kit>** — See <path>.` line per entry in sbx's kits index block of `file`,
/// rewriting the block in place (a kit's old line is replaced) or appending it; text outside
/// the block stays.
pub fn kits_index_script(file: &str, entries: &[(String, String)]) -> String {
    let lines: Vec<String> = entries
        .iter()
        .map(|(kit, path)| sh_quote(&format!("- **{kit}** — See {path}.")))
        .collect();
    let f = sh_quote(file);
    format!(
        "set -e\n{OWNER}\n{mkdirs}s=$(mktemp); t=$(mktemp)\nprintf '%s\\n' {lines} > \"$s\"\n\
         new=; [ -e {f} ] || {{ : > {f}; new=1; }}\n\
         awk -v b={start} -v e={end} -v s=\"$s\" '\n\
         function key(l,  i) {{ i = index(substr(l, 5), \"**\"); return i ? substr(l, 1, i + 5) : l }}\n\
         function put(  i) {{ print b; print \"## Kits\"; for (i = 1; i <= m; i++) print keep[i];\n\
           for (i = 1; i <= n; i++) print add[i]; print e; done = 1 }}\n\
         BEGIN {{ while ((getline l < s) > 0) {{ add[++n] = l; new_kit[key(l)] = 1 }} close(s) }}\n\
         $0 == b {{ inb = 1; next }}\n\
         inb && $0 == e {{ inb = 0; if (!done) put(); next }}\n\
         inb {{ if ($0 != \"## Kits\" && $0 != \"\" && !(key($0) in new_kit)) keep[++m] = $0; next }}\n\
         {{ print }}\n\
         END {{ if (!done) {{ if (NR && !inb) print \"\"; put() }} }}' {f} > \"$t\"\n\
         cat \"$t\" > {f}\nrm -f \"$s\" \"$t\"\n\
         [ -z \"$new\" ] || [ -z \"$o\" ] || chown \"$o\" {f}\n",
        mkdirs = mkdirs(file),
        lines = lines.join(" "),
        start = sh_quote(KITS_SECTION_START),
        end = sh_quote(KITS_SECTION_END),
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
            clean_env: true,
        }
    }

    /// The baseline `hook_script` gives a v3 install hook: each var only when set.
    const BASE: &str = concat!(
        r#"env -i ${PATH+PATH="$PATH"} ${HOME+HOME="$HOME"} ${USER+USER="$USER"}"#,
        r#" ${TERM+TERM="$TERM"}"#,
        r#" ${HTTP_PROXY+HTTP_PROXY="$HTTP_PROXY"} ${HTTPS_PROXY+HTTPS_PROXY="$HTTPS_PROXY"}"#,
        r#" ${http_proxy+http_proxy="$http_proxy"} ${https_proxy+https_proxy="$https_proxy"}"#,
        r#" ${NO_PROXY+NO_PROXY="$NO_PROXY"} ${no_proxy+no_proxy="$no_proxy"}"#,
        r#" ${SSL_CERT_FILE+SSL_CERT_FILE="$SSL_CERT_FILE"}"#,
        r#" ${SSL_CERT_DIR+SSL_CERT_DIR="$SSL_CERT_DIR"}"#,
        r#" ${CURL_CA_BUNDLE+CURL_CA_BUNDLE="$CURL_CA_BUNDLE"}"#,
        r#" ${REQUESTS_CA_BUNDLE+REQUESTS_CA_BUNDLE="$REQUESTS_CA_BUNDLE"}"#,
        r#" ${GIT_SSL_CAINFO+GIT_SSL_CAINFO="$GIT_SSL_CAINFO"}"#,
        r#" ${NODE_EXTRA_CA_CERTS+NODE_EXTRA_CA_CERTS="$NODE_EXTRA_CA_CERTS"}"#,
        r#" ${DENO_CERT+DENO_CERT="$DENO_CERT"}"#,
    );

    /// A hook with the full container environment (v3 startup, all v2 hooks).
    fn full_env(cmd: HookCmd) -> Hook {
        Hook {
            clean_env: false,
            ..hook(cmd, &[])
        }
    }

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
            format!(r#"{BASE} FOO="$FOO" sh -c 'echo hi'"#)
        );
        let h = hook(HookCmd::Argv(vec!["echo".into(), "it's".into()]), &[]);
        assert_eq!(hook_script(&h), format!(r#"{BASE} 'echo' 'it'\''s'"#));
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

    /// sbx's v3 install hooks keep the proxy vars too, and an unset one stays unset.
    #[test]
    fn a_v3_install_hook_keeps_set_proxy_and_ca_vars_and_drops_the_rest() {
        let h = hook(
            HookCmd::Shell(
                "echo \"$HTTPS_PROXY|$no_proxy|$SSL_CERT_FILE|$TERM|${USER-unset}|\
                 ${http_proxy-unset}|${BAR-unset}|$FOO\""
                    .into(),
            ),
            &["FOO"],
        );
        let out = Command::new("sh")
            .arg("-c")
            .arg(hook_script(&h))
            .env("HTTPS_PROXY", "http://proxy:3128")
            .env("no_proxy", "localhost")
            .env("SSL_CERT_FILE", "/ca.pem")
            .env("TERM", "xterm")
            .env_remove("USER")
            .env_remove("http_proxy")
            .env("BAR", "b")
            .env("FOO", "f")
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
        assert_eq!(
            String::from_utf8_lossy(&out.stdout),
            "http://proxy:3128|localhost|/ca.pem|xterm|unset|unset|unset|f\n"
        );
    }

    #[test]
    fn a_full_env_hook_runs_as_written() {
        assert_eq!(
            hook_script(&full_env(HookCmd::Shell("echo hi".into()))),
            "sh -c 'echo hi'"
        );
        assert_eq!(
            hook_script(&full_env(HookCmd::Argv(vec!["echo".into(), "it's".into()]))),
            r#"'echo' 'it'\''s'"#
        );
    }

    /// v3 startup hooks and all v2 hooks see the container's environment, as in sbx.
    #[test]
    fn a_full_env_hook_sees_any_container_var() {
        for cmd in [
            HookCmd::Shell("echo \"$BAR\"".into()),
            HookCmd::Argv(vec!["sh".into(), "-c".into(), "echo \"$BAR\"".into()]),
        ] {
            let out = Command::new("sh")
                .arg("-c")
                .arg(hook_script(&full_env(cmd)))
                .env("BAR", "from the container")
                .output()
                .unwrap();
            assert_eq!(String::from_utf8_lossy(&out.stdout), "from the container\n");
        }
    }

    #[test]
    fn the_runner_gives_full_env_startup_hooks_the_container_env() {
        let h = full_env(HookCmd::Shell("echo \"bar=$BAR\"".into()));
        let s = Startup::new(&[("01-k.sh", "k", vec![&h])]);
        let status = Command::new("sh")
            .arg("-c")
            .arg(&s.runner)
            .arg("startup")
            .env("BAR", "b")
            .status()
            .unwrap();
        assert!(status.success());
        assert!(s.log().contains("bar=b\n"), "{}", s.log());
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

    fn entry(kit: &str, path: &str) -> (String, String) {
        (kit.to_string(), path.to_string())
    }

    #[test]
    fn the_kits_index_is_rewritten_in_place_and_keeps_other_text() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("CLAUDE.md");
        std::fs::write(&file, "# mine\nkeep me").unwrap();
        let f = file.display().to_string();
        let out = sh(&kits_index_script(
            &f,
            &[entry("a", "/p/kits-agent-context/a.md")],
        ));
        assert!(out.status.success(), "{out:?}");
        std::fs::write(
            &file,
            std::fs::read_to_string(&file).unwrap() + "\n# after\n",
        )
        .unwrap();
        // `kit add`: the new kit joins the one block, in place; a rerun changes nothing.
        let add = kits_index_script(&f, &[entry("b", "/p/kits-agent-context/b.md")]);
        for _ in 0..2 {
            let out = sh(&add);
            assert!(out.status.success(), "{out:?}");
            assert_eq!(
                std::fs::read_to_string(&file).unwrap(),
                "# mine\nkeep me\n\n<!-- sbx:kits-section start -->\n## Kits\n\
                 - **a** — See /p/kits-agent-context/a.md.\n\
                 - **b** — See /p/kits-agent-context/b.md.\n\
                 <!-- sbx:kits-section end -->\n\n# after\n"
            );
        }
        // A kit's line is replaced, not repeated; `ab` isn't `a`.
        let out = sh(&kits_index_script(
            &f,
            &[entry("a", "/q/a 'x'.md"), entry("ab", "/p/ab.md")],
        ));
        assert!(out.status.success(), "{out:?}");
        let text = std::fs::read_to_string(&file).unwrap();
        assert_eq!(text.matches("- **a** ").count(), 1, "{text}");
        assert!(text.contains("- **a** — See /q/a 'x'.md.\n"), "{text}");
        assert!(text.contains("- **b** — See"), "{text}");
        assert!(text.contains("- **ab** — See /p/ab.md.\n"), "{text}");
        assert_eq!(text.matches("sbx:kits-section start").count(), 1, "{text}");
    }

    #[test]
    fn the_kits_index_creates_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("new/AGENTS.md");
        let f = file.display().to_string();
        let out = sh(&kits_index_script(
            &f,
            &[entry("a", "/p/a.md"), entry("b", "/p/b.md")],
        ));
        assert!(out.status.success(), "{out:?}");
        assert_eq!(
            std::fs::read_to_string(&file).unwrap(),
            "<!-- sbx:kits-section start -->\n## Kits\n- **a** — See /p/a.md.\n\
             - **b** — See /p/b.md.\n<!-- sbx:kits-section end -->\n"
        );
    }

    #[test]
    fn workload_context_is_appended_without_markers() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("ctx.md");
        std::fs::write(&src, "from image").unwrap();
        let file = dir.path().join("AGENTS.md");
        std::fs::write(&file, "# preamble").unwrap();
        let f = file.display().to_string();
        let body = format!("file:{}", src.display());
        let out = sh(&append_context_script(&f, &["use 'x'\n", &body]));
        assert!(out.status.success(), "{out:?}");
        assert_eq!(
            std::fs::read_to_string(&file).unwrap(),
            "# preamble\n\nuse 'x'\n\nfrom image\n"
        );
        // A new file starts with the body.
        let file = dir.path().join("sub/CLAUDE.md");
        let out = sh(&append_context_script(
            &file.display().to_string(),
            &["only"],
        ));
        assert!(out.status.success(), "{out:?}");
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "only\n");
    }

    #[test]
    fn a_kit_context_file_is_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("kits-agent-context/k.md");
        let f = file.display().to_string();
        for body in ["first", "second 'body'"] {
            let out = sh(&kit_context_script(&f, &[body, "more"]));
            assert!(out.status.success(), "{out:?}");
        }
        assert_eq!(
            std::fs::read_to_string(&file).unwrap(),
            "second 'body'\n\nmore\n"
        );
        let s = kit_context_script("/p/kits-agent-context/k.md", &["x"]);
        assert!(
            s.contains("chown \"$o\" '/p/kits-agent-context'"),
            "the directory goes to agent: {s}"
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

    /// A temp dir holding `passwd` with `acct` at uid 4321, and a `bin` of fake `runuser` and
    /// `setpriv` that report how they were called and run the script.
    fn fake_guest() -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(
            d.path().join("passwd"),
            "root:x:0:0::/root:/bin/sh\nacct:x:4321:4321::/home/acct:/bin/sh\n",
        )
        .unwrap();
        let bin = d.path().join("bin");
        std::fs::create_dir(&bin).unwrap();
        let fake = |name: &str, body: &str| {
            use std::os::unix::fs::PermissionsExt;
            let p = bin.join(name);
            std::fs::write(&p, format!("#!/bin/sh\n{body}")).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        };
        // `runuser -u NAME -- sh -c S`; `setpriv --reuid U --regid G --clear-groups sh -c S`.
        fake("runuser", "echo \"runuser $2\"; shift 3; exec \"$@\"\n");
        fake(
            "setpriv",
            "echo \"setpriv $2 $4 $5\"; shift 5; exec \"$@\"\n",
        );
        d
    }

    /// `as_user_in` against the fake guest, with `path` as `PATH`.
    fn run_as(d: &tempfile::TempDir, user: &str, path: &str) -> std::process::Output {
        let passwd = d.path().join("passwd").display().to_string();
        Command::new("/bin/sh")
            .arg("-c")
            .arg(as_user_in(Some(user), "echo ran", &passwd))
            .env("PATH", path)
            .output()
            .unwrap()
    }

    fn fake_path(d: &tempfile::TempDir) -> String {
        format!(
            "{}:{}",
            d.path().join("bin").display(),
            std::env::var("PATH").unwrap()
        )
    }

    #[test]
    fn a_numeric_user_runs_as_its_account() {
        let d = fake_guest();
        let out = run_as(&d, "4321", &fake_path(&d));
        assert!(out.status.success(), "{out:?}");
        assert_eq!(String::from_utf8_lossy(&out.stdout), "runuser acct\nran\n");
    }

    #[test]
    fn user_1000_runs_as_agent_when_the_guest_has_one() {
        let d = fake_guest();
        std::fs::write(
            d.path().join("passwd"),
            "root:x:0:0::/root:/bin/sh\nagent:x:4321:4321::/home/agent:/bin/sh\n\
             ubuntu:x:1000:1000::/home/ubuntu:/bin/sh\n",
        )
        .unwrap();
        let out = run_as(&d, "1000", &fake_path(&d));
        assert!(out.status.success(), "{out:?}");
        assert_eq!(String::from_utf8_lossy(&out.stdout), "runuser agent\nran\n");
    }

    #[test]
    fn user_1000_without_an_agent_account_resolves_numerically() {
        let d = fake_guest();
        std::fs::write(
            d.path().join("passwd"),
            "root:x:0:0::/root:/bin/sh\nubuntu:x:1000:1000::/home/ubuntu:/bin/sh\n",
        )
        .unwrap();
        let out = run_as(&d, "1000", &fake_path(&d));
        assert_eq!(
            String::from_utf8_lossy(&out.stdout),
            "runuser ubuntu\nran\n"
        );
        std::fs::write(d.path().join("passwd"), "root:x:0:0::/root:/bin/sh\n").unwrap();
        let out = run_as(&d, "1000", &fake_path(&d));
        assert_eq!(
            String::from_utf8_lossy(&out.stdout),
            "setpriv 1000 1000 --clear-groups\nran\n"
        );
    }

    #[test]
    fn a_named_user_is_passed_by_name() {
        let d = fake_guest();
        let out = run_as(&d, "agent", &fake_path(&d));
        assert_eq!(String::from_utf8_lossy(&out.stdout), "runuser agent\nran\n");
    }

    #[test]
    fn a_uid_without_an_account_runs_through_setpriv() {
        let d = fake_guest();
        let out = run_as(&d, "777", &fake_path(&d));
        assert!(out.status.success(), "{out:?}");
        assert_eq!(
            String::from_utf8_lossy(&out.stdout),
            "setpriv 777 777 --clear-groups\nran\n"
        );
    }

    #[test]
    fn a_uid_without_an_account_or_setpriv_fails_clearly() {
        let d = fake_guest();
        // Only awk on the PATH.
        let awk = String::from_utf8(sh("command -v awk").stdout).unwrap();
        let only = d.path().join("only");
        std::fs::create_dir(&only).unwrap();
        std::os::unix::fs::symlink(awk.trim(), only.join("awk")).unwrap();
        let out = run_as(&d, "777", &only.display().to_string());
        assert!(!out.status.success());
        assert!(out.stdout.is_empty(), "{out:?}");
        assert_eq!(
            String::from_utf8_lossy(&out.stderr),
            "smolbento: no account has uid 777, and no setpriv\n"
        );
    }

    #[test]
    fn root_needs_no_switch() {
        for u in ["root", "0"] {
            assert_eq!(as_user(Some(u), "echo ran"), "echo ran");
        }
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
        let svc = log.find(&format!("ok {dir}/01-svc.sh hook 1\n"));
        let use_ = log.find(&format!("ok {dir}/02-use.sh hook 1\n"));
        assert!(svc.is_some() && use_.is_some() && svc < use_, "{log}");
    }

    /// An image without `/var/log` still runs its hooks.
    #[test]
    fn the_runner_creates_its_log_directory() {
        let h = shell("echo hi");
        let s = Startup::new(&[("01-k.sh", "k", vec![&h])]);
        let log = s.path("var/log/sbx-kit-startup.log");
        let runner = s.runner.replace(&s.path("log"), &log);
        let status = Command::new("sh").arg("-c").arg(&runner).status().unwrap();
        assert!(status.success());
        assert!(std::fs::read_to_string(&log).unwrap().contains("hi\n"));
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
                && at("echo b") < at("ok $0 hook 2")
                && at("ok $0 hook 2") < at("'echo c'"),
            "{s}"
        );
        assert!(s.contains("$d sh -c "), "{s}");
    }
}
