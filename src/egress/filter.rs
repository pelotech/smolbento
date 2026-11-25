//! Request rules on a hosted sandbox's flows: the policy source the connection decision and the
//! interceptor's request filter share, the connection step for ruled hosts, and the restart when
//! the set of ruled hosts changes.

use super::request_rules::request_policy;
use crate::config::Paths;
use crate::policy::compile::HOST_GATEWAY;
use egress_front::{
    Action, Decision, Flow, FlowKind, HeaderMap, Inspection, Policy, RequestFilter, RequestInfo,
    host_matches,
};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::SystemTime;

/// What `policy.toml` was when last read: its modification time, length, device and inode (a save
/// renames a new file into place, so even a same-length save in one mtime tick changes it); `None`
/// when it can't be stat'ed, which is never taken as unchanged.
type Stamp = Option<(SystemTime, u64, u64, u64)>;

/// One sandbox's `policy.toml` and request policy, re-read only when the file's stamp changes, so
/// asking costs a `stat`.
pub struct PolicySource {
    paths: Paths,
    pub(super) sandbox: String,
    state: Mutex<Loaded>,
}

#[derive(Clone)]
struct Loaded {
    stamp: Stamp,
    /// `policy.toml` as read, or why it can't be.
    file: Result<Arc<crate::policy::Policy>, String>,
    policy: Arc<Policy>,
    /// The policy's `terminate_hosts`; `None` while `policy.toml` can't be used.
    ruled: Option<Vec<String>>,
}

impl PolicySource {
    pub fn new(paths: &Paths, sandbox: &str) -> PolicySource {
        PolicySource {
            paths: paths.clone(),
            sandbox: sandbox.to_string(),
            state: Mutex::new(load(paths, sandbox, stamp(paths))),
        }
    }

    /// The current request policy. When `policy.toml` can't be read or mapped, one that refuses
    /// every request: the filter sees decrypted hosts only, the ruled and credential hosts.
    pub fn current(&self) -> Arc<Policy> {
        self.refresh().policy
    }

    /// The current `policy.toml`, or why it can't be read.
    pub fn file(&self) -> Result<Arc<crate::policy::Policy>, String> {
        self.refresh().file
    }

    /// The hosts the current rules name, in `terminate_hosts` form; `None` while `policy.toml` can't
    /// be used.
    pub fn ruled_hosts(&self) -> Option<Vec<String>> {
        self.refresh().ruled
    }

    fn refresh(&self) -> Loaded {
        let now = stamp(&self.paths);
        {
            let s = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            if now.is_some() && s.stamp == now {
                return s.clone();
            }
        }
        // Read and mapped outside the lock; a racing refresh just reads it too.
        let loaded = load(&self.paths, &self.sandbox, now);
        *self.state.lock().unwrap_or_else(PoisonError::into_inner) = loaded.clone();
        loaded
    }
}

/// `policy.toml` and `sandbox`'s request policy from it, as of `now`.
fn load(paths: &Paths, sandbox: &str, now: Stamp) -> Loaded {
    let file = crate::policy::Policy::load(paths)
        .map(Arc::new)
        .map_err(|e| format!("{e:#}"));
    let (policy, ruled) = match &file {
        Ok(p) => {
            let p = request_policy(p, sandbox);
            let ruled = p.terminate_hosts();
            (Arc::new(p), Some(ruled))
        }
        Err(e) => {
            // The detail goes to the unit's log only: a 403 never shows the policy's content.
            eprintln!("egress: policy.toml unreadable, refusing requests on ruled hosts: {e}");
            (Arc::new(REFUSE), None)
        }
    };
    Loaded {
        stamp: now,
        file,
        policy,
        ruled,
    }
}

/// Refuses every request.
const REFUSE: Policy = Policy {
    rules: vec![],
    default: Action::Deny,
};

fn stamp(paths: &Paths) -> Stamp {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::metadata(paths.policy_file()).ok()?;
    Some((m.modified().ok()?, m.len(), m.dev(), m.ino()))
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
        let result = (self.0.current()).request(host, port, method, target, headers);
        // The rule id only: the target, its headers and a miss's refusal (which quotes the path)
        // can carry a token.
        let rule = result.as_ref().err().and_then(|e| {
            e.strip_prefix("request denied by policy (rule ")
                .and_then(|rest| rest.split_once(')'))
                .map(|(id, _)| id)
        });
        tracing::debug!(host = ?host, port, method = ?method, denied = result.is_err(), rule, "egress request");
        result
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
        // The gateway, or a host ruled since the process started: refused.
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
        request_policy(&p, SB)
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
        // The gateway is never decrypted, with a bounded allow or only a bounded deny.
        let gw = Flow {
            ip: HOST_GATEWAY.parse().unwrap(),
            ..flow("localhost", FlowKind::Tls)
        };
        for d in [D::Allow, D::Deny] {
            let mut lp = deny_all();
            add(&mut lp, d, "localhost", "GET");
            let lp = request_policy(&lp, SB);
            assert_eq!(
                connection(&lp, &gw, &lp.terminate_hosts()).unwrap().0,
                Decision::Deny
            );
        }
    }

    #[test]
    fn tls_to_a_ruled_host_outside_terminated_is_denied() {
        let p = rules();
        // A host ruled since the process started: refused, even with only bounded denies.
        for host in ["a.com", "d.com"] {
            let (d, why) = connection(&p, &flow(host, FlowKind::Tls), &[]).unwrap();
            assert_eq!(d, Decision::Deny, "{host}");
            assert_eq!(why, "TLS to a ruled host that isn't decrypted");
        }
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
        let f = Filter(Arc::new(PolicySource::new(&paths, SB)));
        let err = judge(&f, "d.com", "POST").unwrap_err();
        assert!(err.starts_with("request denied by policy (rule "), "{err}");
        assert_eq!(judge(&f, "d.com", "GET"), Ok(()));
        assert_eq!(judge(&f, "other.com", "POST"), Ok(()));
    }

    #[test]
    fn the_request_log_names_the_rule_but_never_the_path() {
        let (_d, paths) = test_paths();
        let mut p = deny_all();
        add(&mut p, D::Allow, "a.com", "GET");
        add(&mut p, D::Deny, "d.com", "POST");
        save(&paths, &p, 1);
        let f = Filter(Arc::new(PolicySource::new(&paths, SB)));
        // A path that looks like a refusal's rule id can't smuggle itself in either.
        let token = "bot123:SECRET(rule SECRET2)";
        let (results, log) = crate::log::logged("debug", || {
            [("a.com", "POST"), ("d.com", "POST")].map(|(host, method)| {
                f.judge(host, 443, method, &format!("/{token}/x"), &HeaderMap::new())
            })
        });
        assert!(results.iter().all(Result::is_err), "{results:?}");
        assert!(log.contains("denied=true"), "{log}");
        assert!(log.contains("rule="), "{log}");
        assert!(!log.contains("SECRET"), "{log}");
    }

    #[test]
    fn the_filter_sees_a_policy_change_without_a_new_connection() {
        let (_d, paths) = test_paths();
        let mut p = policy::Policy::default();
        add(&mut p, D::Deny, "d.com", "PUT");
        save(&paths, &p, 1);
        let f = Filter(Arc::new(PolicySource::new(&paths, SB)));
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
        let source = Arc::new(PolicySource::new(&paths, SB));
        let f = Filter(source.clone());
        assert_eq!(source.ruled_hosts(), Some(vec!["d.com".to_string()]));

        std::fs::write(paths.policy_file(), "mode = [not toml").unwrap();
        bump(&paths, 2);
        for host in ["d.com", "cred.com"] {
            assert!(judge(&f, host, "GET").is_err(), "{host}");
        }
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
