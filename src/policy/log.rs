//! smolvm's egress events as sbx's `policy log` rows, and the approvals derived from them.

use std::collections::BTreeMap;

use serde::Serialize;

use super::Policy;
use crate::smolvm::EgressEvent;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LogRow {
    pub sandbox: String,
    pub host: String,
    pub count: usize,
    pub last_seen: String,
    /// The oldest of the events read: when an approval for it was first wanted.
    #[serde(skip)]
    pub first_seen: String,
}

/// One row per sandbox and blocked host, newest first.
pub fn rows(events: &[(String, Vec<EgressEvent>)]) -> Vec<LogRow> {
    let mut grouped: BTreeMap<(String, String), LogRow> = BTreeMap::new();
    for (sandbox, list) in events {
        for e in list {
            let row = grouped
                .entry((sandbox.clone(), e.dest.clone()))
                .or_insert_with(|| LogRow {
                    sandbox: sandbox.clone(),
                    host: e.dest.clone(),
                    count: 0,
                    last_seen: String::new(),
                    first_seen: e.timestamp.clone(),
                });
            row.count += 1;
            // smolvm's timestamps are ISO-8601 UTC (`2026-10-26T14:37:58Z`), so they sort as text.
            if e.timestamp > row.last_seen {
                row.last_seen = e.timestamp.clone();
            }
            if e.timestamp < row.first_seen {
                row.first_seen = e.timestamp.clone();
            }
        }
    }
    let mut out: Vec<LogRow> = grouped.into_values().collect();
    out.sort_by(|a, b| b.last_seen.cmp(&a.last_seen).then(a.host.cmp(&b.host)));
    out
}

/// Blocked hosts no rule mentions yet (in that sandbox's scope): sbx's approval queue. Log hosts
/// carry no port, so a rule's port is ignored: a rule naming the host on any port handles it.
/// A dismissed host stays out until it is blocked again.
pub fn pending<'a>(policy: &Policy, rows: &'a [LogRow]) -> Vec<&'a LogRow> {
    rows.iter()
        .filter(|row| {
            let dismissed = policy
                .dismissed
                .get(&row.sandbox)
                .and_then(|hosts| hosts.get(&row.host))
                .is_some_and(|at| row.last_seen <= *at);
            !dismissed
                && !policy.rules_for(Some(&row.sandbox)).any(|(r, _)| {
                    r.parsed().any(|mut res| {
                        res.port = None;
                        res.matches(&row.host)
                    })
                })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{Decision, Policy};

    fn ev(ts: &str, dest: &str) -> EgressEvent {
        EgressEvent {
            timestamp: ts.into(),
            operation: "resolve".into(),
            dest: dest.into(),
        }
    }

    #[test]
    fn rows_group_and_sort_newest_first() {
        let events = vec![(
            "s1".to_string(),
            vec![
                ev("2026-10-26T10:00:00Z", "a.com"),
                ev("2026-10-26T11:00:00Z", "b.com"),
                ev("2026-10-26T12:00:00Z", "a.com"),
            ],
        )];
        let rows = rows(&events);
        assert_eq!(rows.len(), 2);
        assert_eq!(
            (
                rows[0].host.as_str(),
                rows[0].count,
                rows[0].last_seen.as_str()
            ),
            ("a.com", 2, "2026-10-26T12:00:00Z")
        );
        assert_eq!(rows[1].host, "b.com");
    }

    #[test]
    fn pending_skips_hosts_with_rules() {
        let mut p = Policy::default();
        p.add_rule(None, Decision::Deny, "b.com", "added", None, None)
            .unwrap();
        let events = vec![("s1".to_string(), vec![ev("t1", "a.com"), ev("t2", "b.com")])];
        let rows = rows(&events);
        let pending: Vec<&str> = pending(&p, &rows).iter().map(|r| r.host.as_str()).collect();
        assert_eq!(pending, vec!["a.com"]);
    }

    #[test]
    fn a_dismissed_host_is_pending_again_once_blocked_later() {
        let mut p = Policy::default();
        p.dismissed
            .entry("s1".into())
            .or_default()
            .insert("a.com".into(), "t2".into());
        let hosts = |p: &Policy, events: Vec<EgressEvent>| -> Vec<String> {
            let rows = rows(&[("s1".to_string(), events)]);
            pending(p, &rows).iter().map(|r| r.host.clone()).collect()
        };
        assert_eq!(
            hosts(&p, vec![ev("t1", "a.com"), ev("t2", "a.com")]),
            [""; 0]
        );
        assert_eq!(
            hosts(&p, vec![ev("t1", "a.com"), ev("t3", "a.com")]),
            ["a.com"]
        );
        // Another sandbox's dismissal doesn't count.
        let other = rows(&[("s2".to_string(), vec![ev("t1", "a.com")])]);
        assert_eq!(pending(&p, &other).len(), 1);
        assert_eq!(other[0].first_seen, "t1");
    }

    #[test]
    fn a_rule_with_a_port_still_handles_its_host() {
        // Egress log hosts carry no port.
        let mut p = Policy::default();
        p.add_rule(None, Decision::Allow, "a.com:80", "added", None, None)
            .unwrap();
        let events = vec![("s1".to_string(), vec![ev("t1", "a.com"), ev("t2", "b.com")])];
        let rows = rows(&events);
        let pending: Vec<&str> = pending(&p, &rows).iter().map(|r| r.host.as_str()).collect();
        assert_eq!(pending, vec!["b.com"]);
    }
}
