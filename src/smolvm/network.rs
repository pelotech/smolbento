//! How a machine reaches the network, as smolvm flags.

use std::collections::BTreeSet;

/// Always allowed in a restricted list: smolvm treats `--net` with no entries as open, and agents
/// talk to servers on their own loopback.
pub const LOOPBACK: [&str; 2] = ["127.0.0.0/8", "::1/128"];

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum NetworkSpec {
    /// Any destination.
    #[default]
    Open,
    /// Only what the list allows.
    Restricted(AllowList),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AllowList {
    hosts: Vec<String>,
    patterns: Vec<String>,
    cidrs: Vec<String>,
}

fn sorted(items: impl IntoIterator<Item = String>) -> Vec<String> {
    items
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

impl AllowList {
    /// Sorted and de-duplicated, with loopback always included.
    pub fn new(
        hosts: impl IntoIterator<Item = String>,
        patterns: impl IntoIterator<Item = String>,
        cidrs: impl IntoIterator<Item = String>,
    ) -> AllowList {
        AllowList {
            hosts: sorted(hosts),
            patterns: sorted(patterns),
            cidrs: sorted(cidrs.into_iter().chain(LOOPBACK.map(String::from))),
        }
    }

    pub fn hosts(&self) -> &[String] {
        &self.hosts
    }

    pub fn patterns(&self) -> &[String] {
        &self.patterns
    }

    pub fn cidrs(&self) -> &[String] {
        &self.cidrs
    }

    fn flags(&self) -> Vec<String> {
        let mut a = Vec::new();
        for (flag, items) in [
            ("--allow-host", &self.hosts),
            ("--allow-host-pattern", &self.patterns),
            ("--allow-cidr", &self.cidrs),
        ] {
            for item in items {
                a.push(flag.to_string());
                a.push(item.clone());
            }
        }
        a
    }
}

impl NetworkSpec {
    /// Flags for `machine create`. virtio-net is what lets smolvm change the allow list and
    /// published ports on a running machine.
    pub fn create_args(&self) -> Vec<String> {
        match self {
            NetworkSpec::Open => ["--net", "--net-backend", "virtio-net"]
                .map(String::from)
                .to_vec(),
            NetworkSpec::Restricted(list) => {
                let mut a = vec!["--net-backend".to_string(), "virtio-net".to_string()];
                a.extend(list.flags());
                a
            }
        }
    }

    /// Flags for each `machine update` call, in order: the whole list is replaced, never patched.
    /// One call, except for a list without hosts (see `NO_HOSTS_PLACEHOLDER`).
    pub fn update_calls(&self) -> Vec<Vec<String>> {
        match self {
            NetworkSpec::Open => vec![vec!["--net".into(), "--reset-allow-list".into()]],
            NetworkSpec::Restricted(list) if list.hosts.is_empty() && list.patterns.is_empty() => {
                let mut first = vec![
                    "--reset-allow-list".to_string(),
                    "--allow-host-pattern".to_string(),
                    NO_HOSTS_PLACEHOLDER.to_string(),
                ];
                first.extend(list.flags());
                vec![
                    first,
                    vec![
                        "--remove-allow-host".to_string(),
                        NO_HOSTS_PLACEHOLDER.to_string(),
                    ],
                ]
            }
            NetworkSpec::Restricted(list) => {
                let mut a = vec!["--reset-allow-list".to_string()];
                a.extend(list.flags());
                vec![a]
            }
        }
    }
}

/// Workaround for smolvm 1.32.3: a running machine's live allow list without hosts turns DNS
/// filtering off, and the IPs it learned from earlier allowed DNS answers stay allowed until
/// their TTL (up to an hour). So a host removed by `--reset-allow-list` that leaves only CIDRs
/// stays reachable by name and IP until a restart; `--remove-allow-host` of the last host does
/// the same. Repro: create with `--net-backend virtio-net --allow-host-pattern example.com
/// --allow-cidr 127.0.0.0/8`, start, `wget https://example.com`, then `machine update
/// --reset-allow-list --allow-cidr 127.0.0.0/8`: `wget` still works by name and by IP.
///
/// A list with at least one host is applied correctly (learned IPs of names it no longer allows
/// are dropped), so an emptied list is sent as two calls: reset to this never-resolving name
/// (`.invalid`, RFC 2606) plus the CIDRs, which revokes the learned IPs; then remove it, which
/// leaves exactly the CIDRs, as a fresh start with that list would have.
pub const NO_HOSTS_PLACEHOLDER: &str = "smolbento.invalid";

#[cfg(test)]
mod tests {
    use super::*;

    fn calls_of(n: &NetworkSpec) -> Vec<String> {
        n.update_calls().iter().map(|c| c.join(" ")).collect()
    }

    fn s(items: &[&str]) -> Vec<String> {
        items.iter().map(|i| i.to_string()).collect()
    }

    #[test]
    fn allow_list_sorts_dedupes_and_keeps_loopback() {
        let l = AllowList::new(
            s(&["b.com", "a.com", "a.com"]),
            s(&["*.x.com"]),
            s(&["10.0.0.0/8"]),
        );
        assert_eq!(l.hosts(), s(&["a.com", "b.com"]));
        assert_eq!(l.cidrs(), s(&["10.0.0.0/8", "127.0.0.0/8", "::1/128"]));
        let empty = AllowList::new(vec![], vec![], vec![]);
        assert_eq!(empty.cidrs(), s(&["127.0.0.0/8", "::1/128"]));
    }

    #[test]
    fn create_and_update_args() {
        assert_eq!(
            NetworkSpec::Open.create_args().join(" "),
            "--net --net-backend virtio-net"
        );
        let calls = calls_of;
        assert_eq!(calls(&NetworkSpec::Open), ["--net --reset-allow-list"]);
        let r = NetworkSpec::Restricted(AllowList::new(s(&["a.com"]), s(&["*.x.com"]), vec![]));
        assert_eq!(
            r.create_args().join(" "),
            "--net-backend virtio-net --allow-host a.com --allow-host-pattern *.x.com \
             --allow-cidr 127.0.0.0/8 --allow-cidr ::1/128"
        );
        assert_eq!(
            calls(&r),
            [
                "--reset-allow-list --allow-host a.com --allow-host-pattern *.x.com \
              --allow-cidr 127.0.0.0/8 --allow-cidr ::1/128"
            ]
        );
        // One pattern is enough for smolvm to apply the list live.
        let r = NetworkSpec::Restricted(AllowList::new(vec![], s(&["a.com"]), vec![]));
        assert_eq!(calls(&r).len(), 1);
    }

    #[test]
    fn a_list_without_hosts_is_reset_through_a_placeholder() {
        let r = NetworkSpec::Restricted(AllowList::new(vec![], vec![], s(&["10.0.0.0/8"])));
        assert_eq!(
            calls_of(&r),
            [
                "--reset-allow-list --allow-host-pattern smolbento.invalid \
                 --allow-cidr 10.0.0.0/8 --allow-cidr 127.0.0.0/8 --allow-cidr ::1/128",
                "--remove-allow-host smolbento.invalid",
            ]
        );
        assert_eq!(
            r.create_args().join(" "),
            "--net-backend virtio-net --allow-cidr 10.0.0.0/8 --allow-cidr 127.0.0.0/8 \
             --allow-cidr ::1/128"
        );
    }
}
