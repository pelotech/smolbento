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

    /// Flags for `machine update`: the whole list is replaced, never patched.
    pub fn update_args(&self) -> Vec<String> {
        match self {
            NetworkSpec::Open => vec!["--net".into(), "--reset-allow-list".into()],
            NetworkSpec::Restricted(list) => {
                let mut a = vec!["--reset-allow-list".to_string()];
                a.extend(list.flags());
                a
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(
            NetworkSpec::Open.update_args().join(" "),
            "--net --reset-allow-list"
        );
        let r = NetworkSpec::Restricted(AllowList::new(s(&["a.com"]), s(&["*.x.com"]), vec![]));
        assert_eq!(
            r.create_args().join(" "),
            "--net-backend virtio-net --allow-host a.com --allow-host-pattern *.x.com \
             --allow-cidr 127.0.0.0/8 --allow-cidr ::1/128"
        );
        assert_eq!(
            r.update_args().join(" "),
            "--reset-allow-list --allow-host a.com --allow-host-pattern *.x.com \
             --allow-cidr 127.0.0.0/8 --allow-cidr ::1/128"
        );
    }
}
