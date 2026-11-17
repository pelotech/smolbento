//! Guest shell scripts for kit steps. Every value is single-quoted with `sh_quote`.

use std::path::Path;

use crate::kits::model::{FileReq, Hook, HookCmd};
use crate::util::sh_quote;

pub const STARTUP_PATH: &str = "/etc/smolbento/startup";
pub const STARTUP_DIR: &str = "/etc/smolbento/startup.d";
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
/// A numeric user runs as the account with that uid (`runuser` and `su` take names); a uid with
/// no account runs through `setpriv`, if present.
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
            format!(
                "if _sbu=$(awk -F: -v u={u} '$3 == u {{ print $1; exit }}' {passwd}) \
                 && [ -n \"$_sbu\" ]; then {run}; \
                 elif command -v setpriv >/dev/null 2>&1; then \
                 setpriv --reuid {u} --regid {u} --clear-groups sh -c {q}; \
                 else echo {missing} >&2; false; fi",
                passwd = sh_quote(passwd),
                run = by_name("\"$_sbu\""),
            )
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
    s.push_str(&format!("{} > {p}\n", printf_bytes(&f.content)));
    if let Some(m) = &f.mode {
        s.push_str(&format!("chmod {} {p}\n", sh_quote(m)));
    }
    s.push_str(&format!("[ -z \"$o\" ] || chown \"$o\" {p}\n"));
    s
}

/// A `printf` command printing `bytes` exactly. Text goes through `%s`; anything else (NUL,
/// invalid UTF-8) is spelled as octal escapes, which plain POSIX `printf` understands.
fn printf_bytes(bytes: &[u8]) -> String {
    match std::str::from_utf8(bytes) {
        Ok(text) if !text.contains('\0') => format!("printf %s {}", sh_quote(text)),
        _ => {
            let escaped: String = bytes.iter().map(|b| format!("\\{b:03o}")).collect();
            format!("printf '{escaped}'")
        }
    }
}

/// The directory, next to the agent file, holding one `<kit>.md` per mixin with agent context.
pub const KITS_CONTEXT_DIR: &str = "kits-agent-context";
/// The markers around the kits section of the agent file: sbx's index of per-kit files
/// (`agent-context@1`), or the kits' text itself (`@2`).
pub const KITS_SECTION_START: &str = "<!-- sbx:kits-section start -->";
pub const KITS_SECTION_END: &str = "<!-- sbx:kits-section end -->";

/// The line before a kit's text in the kits section of the agent file.
fn kit_marker(kit: &str) -> String {
    format!("<!-- sbx:kit {kit} -->")
}

/// Rewrites the kits section of `file` with `awk` program `rules`, appending the section when
/// the file has none; text outside it stays. The program gets the markers as `b` and `e`, and
/// `lines` (the new entries) in the file `s`. It prints the section from a `put()` it defines
/// (setting `done`), having read the old section's lines through its own `inb` rule.
fn section_script(file: &str, lines: &[String], rules: &str) -> String {
    let lines: Vec<String> = lines.iter().map(|l| sh_quote(l)).collect();
    let f = sh_quote(file);
    format!(
        "set -e\n{OWNER}\n{mkdirs}s=$(mktemp); t=$(mktemp)\nprintf '%s\\n' {lines} > \"$s\"\n\
         new=; [ -e {f} ] || {{ : > {f}; new=1; }}\n\
         awk -v b={start} -v e={end} -v s=\"$s\" '\n\
         {rules}\
         $0 == b {{ inb = 1; drop = 0; next }}\n\
         inb && $0 == e {{ inb = 0; if (!done) put(); next }}\n\
         inb {{ old(); next }}\n\
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

/// Puts each kit's text itself in the kits section of `file` (`agent-context@2`): `(kit, its
/// bodies)` in order, under a line naming the kit. A kit already there gets its new text; the
/// other kits' text stays. Bodies are joined with two newlines, untrimmed, as the spec says. A
/// section marker in kit text is written as `&lt;!-- sbx:`, so a kit can't end the section or
/// pass its text off as another kit's.
pub fn inline_context_script(file: &str, kits: &[(&str, Vec<&str>)]) -> String {
    let mut lines: Vec<String> = Vec::new();
    for (i, (kit, bodies)) in kits.iter().enumerate() {
        if i > 0 {
            lines.push(String::new());
        }
        lines.push(kit_marker(kit));
        let text = bodies.join("\n\n").replace("<!-- sbx:", "&lt;!-- sbx:");
        lines.extend(text.trim_end_matches('\n').split('\n').map(String::from));
    }
    section_script(
        file,
        &lines,
        "function kit(l) { return substr(l, 1, 13) == \"<!-- sbx:kit \" }\n\
         function put(  i) { while (m && keep[m] == \"\") m--; print b;\n\
           for (i = 1; i <= m; i++) print keep[i]; if (m) print \"\";\n\
           for (i = 1; i <= n; i++) print add[i]; print e; done = 1 }\n\
         function old() { if (kit($0)) drop = ($0 in new_kit); if (!drop) keep[++m] = $0 }\n\
         BEGIN { while ((getline l < s) > 0) { add[++n] = l; if (kit(l)) new_kit[l] = 1 } close(s) }\n",
    )
}

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

/// Puts one `- **<kit>** — See <path>.` line per entry in sbx's kits index (`agent-context@1`),
/// the kits section of `file`; a kit's old line is replaced.
pub fn kits_index_script(file: &str, entries: &[(String, String)]) -> String {
    let lines: Vec<String> = entries
        .iter()
        .map(|(kit, path)| format!("- **{kit}** — See {path}."))
        .collect();
    section_script(
        file,
        &lines,
        "function key(l,  i) { i = index(substr(l, 5), \"**\"); return i ? substr(l, 1, i + 5) : l }\n\
         function put(  i) { print b; print \"## Kits\"; for (i = 1; i <= m; i++) print keep[i];\n\
           for (i = 1; i <= n; i++) print add[i]; print e; done = 1 }\n\
         function old() { if ($0 != \"## Kits\" && $0 != \"\" && !(key($0) in new_kit)) keep[++m] = $0 }\n\
         BEGIN { while ((getline l < s) > 0) { add[++n] = l; new_kit[key(l)] = 1 } close(s) }\n",
    )
}

#[cfg(test)]
#[path = "guest_tests.rs"]
mod tests;
