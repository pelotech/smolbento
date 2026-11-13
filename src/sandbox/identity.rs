//! Matching the guest's users to the host user, and the guest's `/etc/hosts`.

use anyhow::{Context, Result};

use super::Sandbox;
use crate::policy::compile::HOST_GATEWAY;
use crate::smolvm::{ExecSpec, Runner, Smolvm, SmolvmError};
use crate::util::sh_quote;

/// Gives the image's `agent` user the host user's uid and its primary group the host gid.
/// virtiofs passes host uids through, so without this uid 1000 can't write a workspace owned by,
/// say, uid 501 (verified on smolvm 1.32.2). Idempotent; skipped for images without an `agent`
/// user.
pub fn identity_cmd(uid: u32, gid: u32) -> String {
    format!(
        "id -u agent >/dev/null 2>&1 || exit 0; {group}[ \"$(id -u agent)\" = {uid} ] || usermod -o -u {uid} agent",
        group = group_cmd("agent", gid),
    )
}

/// Gives `user`'s primary group the host gid. On Linux, virtiofs creates files as the caller's
/// uid and gid, and the unprivileged VMM can't take on another gid, so any other gid gets EPERM
/// even in a workspace the uid owns. Root's group stays 0; images without `groupmod` (busybox)
/// are left alone. `user` is a shell word.
pub(super) fn group_cmd(user: &str, gid: u32) -> String {
    format!(
        "g=$(id -g {user}); [ \"$g\" = 0 ] || [ \"$g\" = {gid} ] || \
         ! command -v groupmod >/dev/null 2>&1 || groupmod -o -g {gid} \"$(id -gn {user})\" || exit; "
    )
}

/// Names the host `host.docker.internal` in the guest, as sbx does: the guest gateway reaches the
/// host's loopback for sandboxes with host access (`policy::compile::HOST_GATEWAY`). Idempotent.
/// What a start does for an environment file's settings: take `/dev/fuse` away
/// (`sandboxOptions.fuse: false`) and bind each of `read_only` over itself read-only (sbx mounts
/// an environment's files read-only unless `writableEnvFiles`). None when there's nothing to do.
/// Both last until the next start; root in the guest can undo them, as in sbx.
pub fn lockdown_cmd(no_fuse: bool, read_only: &[String]) -> Option<String> {
    let mut lines: Vec<String> = Vec::new();
    if no_fuse {
        lines.push("rm -f /dev/fuse".into());
    }
    for f in read_only {
        let f = crate::util::sh_quote(f);
        lines.push(format!(
            "[ ! -f {f} ] || {{ mount --bind {f} {f} && mount -o remount,bind,ro {f}; }}"
        ));
    }
    (!lines.is_empty()).then(|| lines.join("\n"))
}

pub fn hosts_cmd() -> String {
    hosts_script("/etc/hosts")
}

/// `hosts_cmd` against the hosts file at `file` (tests use a temp file). The leading newline keeps
/// the line apart when the file doesn't end in one.
pub(super) fn hosts_script(file: &str) -> String {
    format!(
        "grep -q ' host.docker.internal$' {file} || \
         printf '\\n%s\\n' '{HOST_GATEWAY} host.docker.internal' >> {file}"
    )
}

/// Where a start records the account a v3 workload's image user resolved to, so a numeric
/// `USER` still names it after its uid moved to the host's (or `agent`'s move took it).
pub const IMAGE_USER_FILE: &str = "/etc/smolbento/image-user";

/// `identity_cmd` for a v3 workload's image user (`sbx.user`: `name`, `uid` or either with
/// `:group`). Run before `identity_cmd`, so a `USER 1000` image still finds `agent` there.
pub fn image_user_cmd(user: &str, uid: u32, gid: u32) -> String {
    image_user_script(user, uid, gid, "/etc")
}

/// `image_user_cmd` against the passwd file and record under `etc` (tests use a temp dir). The
/// first start resolves the user (a uid through `passwd`) and records the account; later starts
/// read the record. Root keeps uid 0. Exits `UNMAPPED` when there's no account or no `usermod`.
pub(super) fn image_user_script(user: &str, uid: u32, gid: u32, etc: &str) -> String {
    let token = user.split(':').next().unwrap_or(user);
    format!(
        "f={file}; n=; [ -r \"$f\" ] && read -r n < \"$f\"; \
         if [ -z \"$n\" ]; then n={token}; case \"$n\" in *[!0-9]*) ;; \
         *) n=$(awk -F: -v u=\"$n\" '$3 == u {{ print $1; exit }}' {passwd});; esac; \
         [ -n \"$n\" ] && mkdir -p {dir} && echo \"$n\" > \"$f\"; fi; \
         [ -n \"$n\" ] && u=$(id -u \"$n\" 2>/dev/null) || exit {UNMAPPED}; \
         [ \"$u\" = 0 ] && exit 0; {group}[ \"$u\" = {uid} ] && exit 0; \
         command -v usermod >/dev/null 2>&1 || exit {UNMAPPED}; usermod -o -u {uid} \"$n\"",
        group = group_cmd("\"$n\"", gid),
        file = sh_quote(&format!("{etc}/smolbento/image-user")),
        dir = sh_quote(&format!("{etc}/smolbento")),
        passwd = sh_quote(&format!("{etc}/passwd")),
        token = sh_quote(token),
    )
}

/// The user `run` and `exec` use for a v3 workload: `sbx.user`, except that a non-root uid is
/// replaced by the account the start recorded for it (keeping any `:group`). Without a record
/// (the uid has no passwd entry; the start warned) the raw uid.
pub fn launch_user<R: Runner>(vm: &Smolvm<R>, sb: &Sandbox) -> Option<String> {
    let spec = sb.meta.user.clone()?;
    let (user, group) = match spec.split_once(':') {
        Some((u, g)) => (u, Some(g)),
        None => (spec.as_str(), None),
    };
    if user.is_empty() || !user.bytes().all(|b| b.is_ascii_digit()) || user.parse() == Ok(0u32) {
        return Some(spec);
    }
    // The guest wrote the record, so it only counts as a plain account name.
    let Some(name) = read_guest_file(vm, sb, IMAGE_USER_FILE).filter(|n| is_account_name(n)) else {
        return Some(spec);
    };
    Some(match group {
        Some(g) => format!("{name}:{g}"),
        None => name,
    })
}

/// A POSIX-style account name: `[A-Za-z_][A-Za-z0-9_.-]*` with an optional trailing `$`, at
/// most 32 characters. Nothing that `-u` could read as a flag, a group or more than one word.
pub(super) fn is_account_name(name: &str) -> bool {
    let body = name.strip_suffix('$').unwrap_or(name);
    let mut bytes = body.bytes();
    name.len() <= 32
        && bytes
            .next()
            .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        && bytes.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

/// A small guest file's first line via `machine cp` (no guest shell needed); `None` when it's
/// missing or empty.
pub(super) fn read_guest_file<R: Runner>(
    vm: &Smolvm<R>,
    sb: &Sandbox,
    path: &str,
) -> Option<String> {
    let dir = tempfile::tempdir().ok()?;
    let local = dir.path().join("file");
    vm.cp(
        &format!("{}:{path}", sb.machine),
        &local.display().to_string(),
    )
    .ok()?;
    let text = std::fs::read_to_string(&local).ok()?;
    let line = text.lines().next()?.trim();
    (!line.is_empty()).then(|| line.to_string())
}

/// `image_user_cmd`'s exit code when it can't map the user.
pub(super) const UNMAPPED: i32 = 3;

/// Runs `image_user_cmd` as root. Returns the warning for a user it couldn't map: the agent then
/// runs with the image's uid, which may not be able to write the host workspace.
pub fn map_image_user<R: Runner>(
    vm: &Smolvm<R>,
    sb: &Sandbox,
    user: &str,
    uid: u32,
    gid: u32,
) -> Result<Option<String>> {
    let out = vm.exec_output(&ExecSpec::sh(
        &sb.machine,
        "root",
        image_user_cmd(user, uid, gid),
    ))?;
    match out.code {
        0 => Ok(None),
        UNMAPPED => Ok(Some(format!(
            "warning: {}: couldn't map the image user {user} to your uid; the workspace may not \
             be writable",
            sb.name()
        ))),
        _ => Err(anyhow::anyhow!(SmolvmError::from_output(&out).message))
            .context("matching the sandbox's image user to your host uid"),
    }
}
