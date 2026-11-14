//! WORKAROUND(smolvm 1.35.0 idmap): smolvm 1.35.0 mounts `-v` host directories unmapped, so the
//! session user can't write its workspace (1.34.2 to 1.34.4 map them to the workload user). After
//! each start, the script below binds each writable host directory onto itself with that mapping,
//! as smolvm would. A directory smolvm already mapped is skipped, so with a fixed smolvm it does
//! nothing. Remove this file, its call in `setup` and the tests marked with the same tag once a
//! fixed smolvm is the minimum.

use super::Meta;
use crate::util::sh_quote;

/// The root script that maps `meta`'s writable workspaces and kit host mounts to its session
/// user; `None` when there is nothing to map (no mounts, or a root session user). It exits
/// non-zero when a directory couldn't be mapped: busybox `mount` refuses `X-mount.idmap`, and
/// util-linux before 2.39 ignores it and binds unmapped, so the owner is checked and such a bind
/// undone.
pub fn script(meta: &Meta) -> Option<String> {
    let (user, group) = match meta.session_user().split_once(':') {
        Some((u, g)) => (u, Some(g)),
        None => (meta.session_user(), None),
    };
    if user == "0" || user == "root" {
        return None;
    }
    let paths: Vec<String> = meta
        .workspaces
        .iter()
        .filter(|w| !w.ends_with(":ro"))
        .chain(meta.host_mounts.keys())
        .map(|p| sh_quote(p))
        .collect();
    if paths.is_empty() {
        return None;
    }
    let gid = match group {
        Some(g) if g.chars().all(|c| c.is_ascii_digit()) => g.to_string(),
        Some(g) => format!("$(getent group {} | cut -d: -f3)", sh_quote(g)),
        None => format!("$(id -g {})", sh_quote(user)),
    };
    Some(format!(
        "u=$(id -u {user}) && g={gid} && [ -n \"$g\" ] || exit 1; rc=0; \
         for p in {paths}; do [ -d \"$p\" ] || continue; \
         o=$(stat -c %u \"$p\"); og=$(stat -c %g \"$p\"); \
         if [ \"$o\" = 0 ] || [ \"$o\" = \"$u\" ]; then continue; fi; \
         mount --bind -o X-mount.idmap=\"u:$o:$u:1 g:$og:$g:1\" \"$p\" \"$p\" || {{ rc=1; continue; }}; \
         [ \"$(stat -c %u \"$p\")\" = \"$u\" ] || {{ umount \"$p\"; rc=1; }}; \
         done; exit $rc",
        user = sh_quote(user),
        paths = paths.join(" "),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn meta(user: Option<&str>, workspaces: &[&str], host_mounts: &[(&str, &str)]) -> Meta {
        Meta {
            user: user.map(String::from),
            workspaces: workspaces.iter().map(|w| w.to_string()).collect(),
            host_mounts: host_mounts
                .iter()
                .map(|(g, h)| (g.to_string(), h.to_string()))
                .collect::<BTreeMap<_, _>>(),
            ..Default::default()
        }
    }

    #[test]
    fn maps_writable_workspaces_and_kit_host_mounts_to_the_session_user() {
        let s = script(&meta(
            None,
            &["/w/a", "/w/ro:ro"],
            &[("/home/agent/.cache/x", "/h/x")],
        ))
        .unwrap();
        assert!(
            s.starts_with("u=$(id -u 'agent') && g=$(id -g 'agent')"),
            "{s}"
        );
        assert!(
            s.contains("for p in '/w/a' '/home/agent/.cache/x'; do"),
            "read-only workspaces stay as they are: {s}"
        );
        assert!(
            s.contains("mount --bind -o X-mount.idmap=\"u:$o:$u:1 g:$og:$g:1\" \"$p\" \"$p\""),
            "{s}"
        );
        assert!(
            s.contains("[ \"$o\" = 0 ] || [ \"$o\" = \"$u\" ]"),
            "skips root-owned and already mapped: {s}"
        );
        assert!(
            s.contains("[ \"$(stat -c %u \"$p\")\" = \"$u\" ] || { umount \"$p\"; rc=1; }"),
            "an old mount that ignored the idmap is undone and reported: {s}"
        );
    }

    #[test]
    fn an_image_user_with_a_group_uses_that_group() {
        let numeric = script(&meta(Some("somebody:1001"), &["/w"], &[])).unwrap();
        assert!(
            numeric.starts_with("u=$(id -u 'somebody') && g=1001 "),
            "{numeric}"
        );
        let named = script(&meta(Some("somebody:staff"), &["/w"], &[])).unwrap();
        assert!(
            named.contains("g=$(getent group 'staff' | cut -d: -f3)"),
            "{named}"
        );
    }

    #[test]
    fn nothing_to_map_for_root_or_without_mounts() {
        assert_eq!(script(&meta(Some("0"), &["/w"], &[])), None);
        assert_eq!(script(&meta(Some("root"), &["/w"], &[])), None);
        assert_eq!(script(&meta(None, &[], &[])), None);
        assert_eq!(script(&meta(None, &["/w:ro"], &[])), None);
    }
}
