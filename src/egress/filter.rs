//! Request rules on a hosted sandbox's flows: the policy source the connection decision and the
//! interceptor's request filter share, the connection step for ruled hosts, and the restart when
//! the set of ruled hosts changes.

use super::request_rules::request_policy;
use crate::config::Paths;
use crate::policy::compile::HOST_GATEWAY;
use egress_front::{
    Action, Case, Decision, Flow, FlowKind, HeaderMap, HostMatch, Inspection, Methods, PathGlob,
    Policy, RequestFilter, RequestInfo, RequestMatch, Rule, host_matches,
};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::SystemTime;

/// What `policy.toml` was when last read: its modification time and length, `None` when it can't be
/// stat'ed.
type Stamp = Option<(SystemTime, u64)>;

/// One sandbox's request policy, rebuilt from `policy.toml` only when the file's stamp changes, so
/// asking costs a `stat`.
pub struct PolicySource {
    paths: Paths,
    sandbox: String,
    credential_hosts: Vec<String>,
    state: Mutex<Loaded>,
}

struct Loaded {
    stamp: Stamp,
    policy: Arc<Policy>,
    /// The policy's `terminate_hosts`; `None` while `policy.toml` can't be used.
    ruled: Option<Vec<String>>,
    /// The last ruled hosts that could be read, which an unusable file refuses.
    last_ruled: Vec<String>,
}

impl PolicySource {
    pub fn new(paths: &Paths, sandbox: &str, credential_hosts: Vec<String>) -> PolicySource {
        let source = PolicySource {
            paths: paths.clone(),
            sandbox: sandbox.to_string(),
            credential_hosts,
            state: Mutex::new(Loaded {
                stamp: None,
                policy: Arc::new(refuse(&[])),
                ruled: None,
                last_ruled: Vec::new(),
            }),
        };
        source.reload(stamp(&source.paths));
        source
    }

    /// The current request policy. When `policy.toml` can't be read or mapped, a policy that refuses
    /// every request on the hosts that were ruled and the credential hosts, with reason
    /// `policy.toml unreadable`.
    pub fn current(&self) -> Arc<Policy> {
        self.refresh().0
    }

    /// The hosts the current rules name, in `terminate_hosts` form; `None` while `policy.toml` can't
    /// be used.
    pub fn ruled_hosts(&self) -> Option<Vec<String>> {
        self.refresh().1
    }

    fn refresh(&self) -> (Arc<Policy>, Option<Vec<String>>) {
        let now = stamp(&self.paths);
        {
            let s = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            if s.stamp == now {
                return (s.policy.clone(), s.ruled.clone());
            }
        }
        self.reload(now)
    }

    /// Reads and maps the file outside the lock; a racing reload just reads it too.
    fn reload(&self, now: Stamp) -> (Arc<Policy>, Option<Vec<String>>) {
        let last = (self.state.lock().unwrap_or_else(PoisonError::into_inner))
            .last_ruled
            .clone();
        let built = crate::policy::Policy::load(&self.paths)
            .map_err(|e| format!("{e:#}"))
            .map(|p| request_policy(&p, &self.sandbox, &self.credential_hosts));
        let (policy, ruled) = match built {
            Ok(p) => {
                let ruled = p.terminate_hosts();
                (Arc::new(p), Some(ruled))
            }
            Err(e) => {
                // The detail goes to the unit's log only: a 403 never shows the policy's content.
                eprintln!("egress: policy.toml unreadable, refusing requests on ruled hosts: {e}");
                let hosts: Vec<String> =
                    last.iter().chain(&self.credential_hosts).cloned().collect();
                (Arc::new(refuse(&hosts)), None)
            }
        };
        let mut s = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        s.stamp = now;
        s.policy = policy.clone();
        s.ruled = ruled.clone();
        if let Some(r) = &ruled {
            s.last_ruled = r.clone();
        }
        (policy, ruled)
    }
}

fn stamp(paths: &Paths) -> Stamp {
    let m = std::fs::metadata(paths.policy_file()).ok()?;
    Some((m.modified().ok()?, m.len()))
}

/// A policy that refuses every request on `hosts` (`terminate_hosts` patterns).
fn refuse(hosts: &[String]) -> Policy {
    let hosts: Vec<HostMatch> = hosts
        .iter()
        .map(|h| match h.strip_prefix("*.") {
            Some(domain) => HostMatch::Subdomains {
                domain: domain.to_string(),
                any_depth: true,
            },
            None => HostMatch::Exact(h.clone()),
        })
        .collect();
    let rules = (!hosts.is_empty()).then(|| Rule {
        id: None,
        action: Action::Deny,
        hosts,
        port: None,
        request: RequestMatch {
            methods: Methods::Any,
            paths: vec![PathGlob::parse("/**").expect("/** parses")],
            query: vec![],
        },
        reason: Some("policy.toml unreadable".into()),
        case: Case::Insensitive,
    });
    Policy {
        rules: rules.into_iter().collect(),
        default: Action::Allow,
    }
}

/// The interceptor's request filter: the current rules, judged with no file read beyond a `stat`.
pub struct Filter(pub Arc<PolicySource>);

impl Filter {
    fn judge(
        &self,
        host: &str,
        port: u16,
        method: &str,
        target: &str,
        headers: &HeaderMap,
    ) -> Result<(), String> {
        // The hook has already resolved dot segments and `\`, so the target goes as it is.
        (self
            .0
            .current()
            .request(host, port, method, target, headers))
        .map_err(|r| r.reason)
    }
}

impl RequestFilter for Filter {
    fn check(&self, r: &RequestInfo<'_>) -> Result<(), String> {
        self.judge(r.host, r.port, r.method, r.target, r.headers)
    }
}

/// The request-rule step of a flow's decision, after Phase 3's allowed it; `None` when no request
/// rule names its host. `terminated` is what the interceptor decrypts.
pub fn connection(
    policy: &Policy,
    flow: &Flow,
    terminated: &[String],
) -> Option<(Decision, String)> {
    // The gateway is the host's `localhost`, whatever name the guest gives it, and never decrypted.
    let gateway = flow.ip.to_string() == HOST_GATEWAY;
    let host = if gateway {
        "localhost"
    } else {
        flow.name.as_deref()?
    };
    let Inspection::Inspect { uninspectable } = policy.inspection(host, flow.port) else {
        return None;
    };
    Some(match flow.kind {
        FlowKind::Http => (
            Decision::Deny,
            "plain HTTP to a host with request rules".into(),
        ),
        FlowKind::Tls if !gateway && terminated.iter().any(|p| host_matches(p, host)) => {
            (Decision::Allow, "decrypted for request rules".into())
        }
        // A CA from before request rules, the gateway, or a host ruled since the process started:
        // refused, as 0.37.0 refused the host.
        FlowKind::Tls => (
            Decision::Deny,
            "TLS to a ruled host that isn't decrypted".into(),
        ),
        FlowKind::Other => match uninspectable {
            Action::Allow => (Decision::Allow, "request rules only deny".into()),
            Action::Deny => (
                Decision::Deny,
                "request rules apply and this flow can't be read".into(),
            ),
        },
    })
}

/// Ends the process once when the ruled hosts differ from those it started with, so its unit starts
/// it again with the new set: the interceptor's `terminate_hosts` is fixed for its lifetime.
pub struct Restart {
    started: Vec<String>,
    fired: AtomicBool,
    exit: Box<dyn Fn() + Send + Sync>,
}

impl Restart {
    pub fn new(started: Vec<String>, exit: Box<dyn Fn() + Send + Sync>) -> Restart {
        Restart {
            started,
            fired: AtomicBool::new(false),
            exit,
        }
    }

    /// `now` is `None` while `policy.toml` can't be used, which keeps the running set.
    pub fn check(&self, now: Option<&[String]>) {
        if now.is_some_and(|n| n != self.started) && !self.fired.swap(true, Ordering::SeqCst) {
            eprintln!("egress: request-rule hosts changed; restarting");
            (self.exit)();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::test_paths;
    use crate::policy::{self, Decision as D};
    use std::sync::atomic::AtomicUsize;
    use std::time::Duration;

    const SB: &str = "sb";

    fn flow(name: &str, kind: FlowKind) -> Flow {
        Flow {
            name: Some(name.into()),
            kind,
            ip: "192.0.2.1".parse().unwrap(),
            port: 443,
        }
    }

    /// A policy with a bounded allow on `a.com` and a bounded deny on `d.com`.
    /// Deny-all, so no connection rule makes a bounded allow moot.
    fn deny_all() -> policy::Policy {
        policy::Policy {
            mode: Some(policy::Mode::DenyAll),
            ..Default::default()
        }
    }

    fn rules() -> Policy {
        let mut p = deny_all();
        add(&mut p, D::Allow, "a.com", "GET");
        add(&mut p, D::Deny, "d.com", "POST");
        request_policy(&p, SB, &[])
    }

    fn add(p: &mut policy::Policy, d: D, host: &str, method: &str) {
        p.insert_rule(Some(SB), d, host, "added", Some(method.into()), None, None)
            .unwrap();
    }

    /// Saves `p` with a modification time later than any before it.
    fn save(paths: &Paths, p: &policy::Policy, tick: u64) {
        p.save(paths).unwrap();
        bump(paths, tick);
    }

    fn bump(paths: &Paths, tick: u64) {
        let f = std::fs::File::options()
            .write(true)
            .open(paths.policy_file())
            .unwrap();
        f.set_modified(SystemTime::now() + Duration::from_secs(tick))
            .unwrap();
    }

    fn judge(f: &Filter, host: &str, method: &str) -> Result<(), String> {
        f.judge(host, 443, method, "/x", &HeaderMap::new())
    }

    #[test]
    fn plain_http_to_a_ruled_host_is_refused() {
        let p = rules();
        for host in ["a.com", "d.com"] {
            let (d, why) = connection(&p, &flow(host, FlowKind::Http), &[]).unwrap();
            assert_eq!(d, Decision::Deny, "{host}");
            assert_eq!(why, "plain HTTP to a host with request rules");
        }
        assert_eq!(
            connection(&p, &flow("other.com", FlowKind::Http), &[]),
            None
        );
    }

    #[test]
    fn tls_to_a_ruled_host_is_allowed_for_interception() {
        let p = rules();
        let terminated = p.terminate_hosts();
        let d = |host| {
            connection(&p, &flow(host, FlowKind::Tls), &terminated)
                .unwrap()
                .0
        };
        assert_eq!(d("a.com"), Decision::Allow);
        assert_eq!(d("d.com"), Decision::Allow);
        // The gateway is never decrypted.
        let gw = Flow {
            ip: HOST_GATEWAY.parse().unwrap(),
            ..flow("localhost", FlowKind::Tls)
        };
        let mut lp = deny_all();
        add(&mut lp, D::Allow, "localhost", "GET");
        let lp = request_policy(&lp, SB, &[]);
        assert_eq!(
            connection(&lp, &gw, &lp.terminate_hosts()).unwrap().0,
            Decision::Deny
        );
    }

    #[test]
    fn tls_to_a_ruled_host_outside_terminated_is_denied() {
        let p = rules();
        // A CA from before request rules, or a host ruled since the process started: refused, as
        // 0.37.0 refused the host, even with only bounded denies.
        for host in ["a.com", "d.com"] {
            let (d, why) = connection(&p, &flow(host, FlowKind::Tls), &[]).unwrap();
            assert_eq!(d, Decision::Deny, "{host}");
            assert_eq!(why, "TLS to a ruled host that isn't decrypted");
        }
        // The gateway, with only a bounded deny on `localhost`.
        let mut lp = deny_all();
        add(&mut lp, D::Deny, "localhost", "POST");
        let lp = request_policy(&lp, SB, &[]);
        let gw = Flow {
            ip: HOST_GATEWAY.parse().unwrap(),
            ..flow("localhost", FlowKind::Tls)
        };
        assert_eq!(
            connection(&lp, &gw, &lp.terminate_hosts()).unwrap().0,
            Decision::Deny
        );
    }

    #[test]
    fn ssh_to_a_ruled_host_still_follows_uninspectable() {
        let p = rules();
        // Not decrypted either way: a host with only denies passes it, one with an allow refuses it.
        for terminated in [vec![], p.terminate_hosts()] {
            let d = |host| {
                connection(&p, &flow(host, FlowKind::Other), &terminated)
                    .unwrap()
                    .0
            };
            assert_eq!(d("d.com"), Decision::Allow);
            assert_eq!(d("a.com"), Decision::Deny);
        }
    }

    #[test]
    fn an_unparseable_request_rule_doesnt_disable_the_others() {
        let (_d, paths) = test_paths();
        let mut p = deny_all();
        p.allow(Some(SB), "**");
        add(&mut p, D::Deny, "d.com", "POST");
        // Stored by 0.37.0, which didn't check `--path`; `PathGlob` refuses the empty segment.
        p.insert_rule(
            Some(SB),
            D::Deny,
            "api.x.com",
            "added",
            Some("POST".into()),
            Some("/admin/".into()),
            None,
        )
        .unwrap();
        save(&paths, &p, 1);
        // A fresh process: it knows no ruled hosts from before.
        let source = Arc::new(PolicySource::new(&paths, SB, vec![]));
        let f = Filter(source.clone());
        assert!(judge(&f, "d.com", "POST").is_err());
        assert_eq!(judge(&f, "d.com", "GET"), Ok(()));
        let ruled = source.ruled_hosts().unwrap();
        assert_eq!(ruled, ["d.com"]);
        // The bad deny keeps 0.37.0's meaning: its whole host is denied.
        let rules = super::super::rules::Rules::new(&paths, SB, false, vec![]);
        let to = |host: &str| Flow {
            name: Some(host.into()),
            kind: FlowKind::Tls,
            ip: "192.0.2.1".parse().unwrap(),
            port: 443,
        };
        assert_eq!(rules.decide(&to("api.x.com")).0, Decision::Deny);
        assert_eq!(rules.decide(&to("d.com")).0, Decision::Allow);
    }

    #[test]
    fn uninspectable_follows_the_rules() {
        let p = rules();
        let d = |host| connection(&p, &flow(host, FlowKind::Other), &p.terminate_hosts());
        // A host with an allow refuses what it can't read; one with only denies passes it.
        assert_eq!(d("a.com").unwrap().0, Decision::Deny);
        assert_eq!(d("d.com").unwrap().0, Decision::Allow);
        assert_eq!(d("other.com"), None);
        // A flow decided from its destination alone, with no name yet, is left to Phase 3.
        let nameless = Flow {
            name: None,
            ..flow("a.com", FlowKind::Other)
        };
        assert_eq!(connection(&p, &nameless, &p.terminate_hosts()), None);
    }

    #[test]
    fn the_filter_refuses_with_the_rule_reason() {
        let (_d, paths) = test_paths();
        let mut p = policy::Policy::default();
        add(&mut p, D::Deny, "d.com", "POST");
        save(&paths, &p, 1);
        let f = Filter(Arc::new(PolicySource::new(&paths, SB, vec![])));
        let err = judge(&f, "d.com", "POST").unwrap_err();
        assert!(err.starts_with("request denied by policy (rule "), "{err}");
        assert_eq!(judge(&f, "d.com", "GET"), Ok(()));
        assert_eq!(judge(&f, "other.com", "POST"), Ok(()));
    }

    #[test]
    fn the_filter_sees_a_policy_change_without_a_new_connection() {
        let (_d, paths) = test_paths();
        let mut p = policy::Policy::default();
        add(&mut p, D::Deny, "d.com", "PUT");
        save(&paths, &p, 1);
        let f = Filter(Arc::new(PolicySource::new(&paths, SB, vec![])));
        assert_eq!(judge(&f, "d.com", "POST"), Ok(()));
        add(&mut p, D::Deny, "d.com", "POST");
        save(&paths, &p, 2);
        assert!(judge(&f, "d.com", "POST").is_err());
    }

    #[test]
    fn an_unreadable_policy_refuses_requests() {
        let (_d, paths) = test_paths();
        let mut p = policy::Policy::default();
        add(&mut p, D::Deny, "d.com", "POST");
        save(&paths, &p, 1);
        let source = Arc::new(PolicySource::new(&paths, SB, vec!["cred.com".into()]));
        let f = Filter(source.clone());
        assert_eq!(source.ruled_hosts(), Some(vec!["d.com".to_string()]));

        std::fs::write(paths.policy_file(), "mode = [not toml").unwrap();
        bump(&paths, 2);
        for host in ["d.com", "cred.com"] {
            let err = judge(&f, host, "GET").unwrap_err();
            assert!(err.starts_with("policy.toml unreadable"), "{host}: {err}");
        }
        assert_eq!(
            judge(&f, "other.com", "GET"),
            Ok(()),
            "hosts with no rules keep working"
        );
        assert_eq!(source.ruled_hosts(), None, "keeps the running set");

        save(&paths, &p, 3);
        assert_eq!(
            judge(&f, "d.com", "GET"),
            Ok(()),
            "recovers on the next valid write"
        );
        assert!(judge(&f, "d.com", "POST").is_err());
    }

    #[test]
    fn a_changed_terminate_set_restarts_once() {
        let exits = Arc::new(AtomicUsize::new(0));
        let counter = exits.clone();
        let r = Restart::new(
            vec!["a.com".into()],
            Box::new(move || {
                counter.fetch_add(1, Ordering::SeqCst);
            }),
        );
        r.check(Some(&["a.com".to_string()]));
        r.check(None);
        assert_eq!(exits.load(Ordering::SeqCst), 0);
        let changed = ["a.com".to_string(), "b.com".to_string()];
        r.check(Some(&changed));
        r.check(Some(&changed));
        r.check(Some(&[]));
        assert_eq!(exits.load(Ordering::SeqCst), 1);
    }
}
