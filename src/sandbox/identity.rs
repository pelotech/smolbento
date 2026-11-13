//! What a start does inside the guest besides running the agent: `/etc/hosts` and lockdown.

use crate::policy::compile::HOST_GATEWAY;

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

/// Names the host `host.docker.internal` in the guest, as sbx does: the guest gateway reaches the
/// host's loopback for sandboxes with host access (`policy::compile::HOST_GATEWAY`). Idempotent.
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
