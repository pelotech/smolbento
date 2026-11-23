//! `policy.toml`'s request-qualified rules (`--method/--path/--query`, sbx semantics) as an
//! `egress_front` request policy. Connection rules stay with `policy::compile::decide`.

use egress_front::{
    Action, Case, HostMatch, Methods, PathGlob, Policy, QueryMatch, RequestMatch, Rule, ValueMatch,
};

use crate::policy::rules::{Pattern, Resource};
use crate::policy::{self, Decision, compile};

/// The request rules that apply to `sandbox`: its active global, per-sandbox and kit rules with a
/// method, path or query, one crate rule per resource. Connection defaults stay in `decide`, so a
/// host no rule names is allowed. As in sbx, a bounded allow on a host that connection rules alone
/// already admit (`moot`) is dropped; bounded denies never are. A resource the crate can't take
/// is skipped and acts on its whole host instead (`compile::per_request`).
pub fn request_policy(
    policy: &policy::Policy,
    sandbox: &str,
    credential_hosts: &[String],
) -> Policy {
    // Connection rules only, and no glob allows: a glob can match the `*` probe label (`?.x.com`)
    // without admitting every subdomain, and a doubtful admit must keep the bounded allow.
    let mut plain = policy.clone();
    let lists = std::iter::once(&mut plain.rules)
        .chain(plain.sandboxes.values_mut().map(|sp| &mut sp.rules));
    for list in lists {
        list.retain(|r| !r.is_request());
        for r in list.iter_mut().filter(|r| r.decision == Decision::Allow) {
            r.resources.retain(|x| {
                !Resource::parse(x).is_ok_and(|x| matches!(x.pattern, Pattern::Glob { .. }))
            });
        }
        list.retain(|r| !r.resources.is_empty());
    }
    let admits = |target: &str| {
        let host_access = compile::host_access(&plain, sandbox);
        compile::decide(&plain, sandbox, credential_hosts, host_access, target).allowed
    };
    let spare = spare_port(policy);
    let mut rules = Vec::new();
    for (r, _) in compile::active(policy, Some(sandbox), &[]).filter(|(r, _)| r.is_request()) {
        for res in r.parsed() {
            let rule = match map(r, &res) {
                Ok(rule) => rule,
                Err(e) => {
                    // A rule the filter can't take acts on its whole host (`compile::per_request`).
                    eprintln!(
                        "egress: rule {} on {}: {e}; it acts on the whole host",
                        r.id, res.raw
                    );
                    continue;
                }
            };
            if r.decision == Decision::Allow && moot(&admits, &rule.hosts[0], res.port, spare) {
                continue;
            }
            rules.push(rule);
        }
    }
    Policy {
        rules,
        default: Action::Allow,
    }
}

/// The crate rule for one resource of a request rule, or why the crate can't take it.
fn map(r: &policy::Rule, res: &Resource) -> Result<Rule, String> {
    let rule = Rule {
        id: Some(r.id.clone()),
        action: action(r.decision),
        hosts: vec![host(r.decision, res)?],
        port: res.port,
        request: request(r.method.as_deref(), r.path.as_deref(), r.query.as_deref())?,
        reason: None,
        // Kits follow the kit spec; `bento policy` follows sbx.
        case: if r.created_via.starts_with(policy::KIT_VIA) {
            Case::Sensitive
        } else {
            Case::Insensitive
        },
    };
    let mut one = Policy {
        rules: vec![rule],
        default: Action::Allow,
    };
    one.validate()?;
    Ok(one.rules.remove(0))
}

/// The host, in `terminate_hosts` form, that one resource of a request rule maps to; `None` when
/// the crate can't take it.
pub fn mapped_host(r: &policy::Rule, res: &Resource) -> Option<String> {
    let one = Policy {
        rules: vec![map(r, res).ok()?],
        default: Action::Allow,
    };
    one.terminate_hosts().pop()
}

/// Whether connection rules alone admit every host and port a bounded allow on `host` names. A
/// `*` label stands for any subdomain: only a rule over all of them admits it.
fn moot(admits: &impl Fn(&str) -> bool, host: &HostMatch, port: Option<u16>, spare: u16) -> bool {
    let names = match host {
        HostMatch::Exact(n) => vec![n.clone()],
        HostMatch::Subdomains { domain, any_depth } => {
            let mut v = vec![format!("*.{domain}")];
            if *any_depth {
                v.push(format!("*.*.{domain}"));
            }
            v
        }
        HostMatch::Any => return false,
    };
    // A rule without a port names every port: admitted on 443 and on a port no rule names.
    let ports = port.map_or_else(|| vec![443, spare], |p| vec![p]);
    names
        .iter()
        .all(|n| ports.iter().all(|p| admits(&format!("{n}:{p}"))))
}

/// The first port no rule or preset names, so admitting it means admitting every unnamed port.
fn spare_port(policy: &policy::Policy) -> u16 {
    let named: std::collections::BTreeSet<u16> = (policy.all_rules())
        .flat_map(|(r, _)| r.parsed())
        .chain(policy::presets::balanced())
        .filter_map(|r| r.port)
        .collect();
    (1..=u16::MAX).find(|p| !named.contains(p)).unwrap_or(443)
}

/// Whether a rule with these qualifiers can be enforced per request: `policy allow|deny` refuses
/// one that can't.
pub fn check(
    decision: Decision,
    resources: &[Resource],
    method: Option<&str>,
    path: Option<&str>,
    query: Option<&str>,
) -> Result<(), String> {
    request(method, path, query)?;
    resources
        .iter()
        .try_for_each(|r| host(decision, r).map(drop))
}

fn action(d: Decision) -> Action {
    match d {
        Decision::Allow => Action::Allow,
        Decision::Deny => Action::Deny,
    }
}

/// The interceptor decrypts named hosts only. A glob deny widens to its parent's subdomains (a
/// wider deny is safe); a glob allow would widen what it allows, so it's refused.
fn host(decision: Decision, r: &Resource) -> Result<HostMatch, String> {
    match &r.pattern {
        Pattern::Exact(h) => Ok(HostMatch::Exact(h.clone())),
        Pattern::OneLabel(d) => Ok(HostMatch::Subdomains {
            domain: d.clone(),
            any_depth: false,
        }),
        Pattern::Subdomains(d) => Ok(HostMatch::Subdomains {
            domain: d.clone(),
            any_depth: true,
        }),
        Pattern::Glob { parent, .. } if decision == Decision::Deny => Ok(HostMatch::Subdomains {
            domain: parent.clone(),
            any_depth: true,
        }),
        Pattern::Glob { .. } => Err(format!(
            "a request rule can't allow the host glob '{}'; name the host, or use *.x or **.x",
            r.raw
        )),
        Pattern::Everything | Pattern::Cidr { .. } => Err("request rules need a named host".into()),
    }
}

/// `--method` (a comma list or `ANY`), `--path` (default `/**`) and `--query` as a request match.
fn request(
    method: Option<&str>,
    path: Option<&str>,
    query: Option<&str>,
) -> Result<RequestMatch, String> {
    let methods = match method.and_then(policy::normalise_methods) {
        None => Methods::Any,
        Some(m) if m.split(',').any(|x| x == "ANY") => Methods::Any,
        Some(m) => Methods::Only(m.split(',').map(String::from).collect()),
    };
    let paths = vec![PathGlob::parse(path.unwrap_or("/**")).map_err(|e| format!("--path: {e}"))?];
    let query = (query.into_iter().flat_map(|q| q.split(',')))
        .map(str::trim)
        .filter(|q| !q.is_empty())
        .map(query_match)
        .collect::<Result<_, _>>()?;
    Ok(RequestMatch {
        methods,
        paths,
        query,
    })
}

/// sbx's `--query` forms: `name=value`, `name=prefix*`, `name=*suffix`, `name=*`.
fn query_match(q: &str) -> Result<QueryMatch, String> {
    let bad = || format!("--query '{q}': use name=value, name=prefix*, name=*suffix or name=*");
    let (name, v) = q.split_once('=').ok_or_else(bad)?;
    if name.is_empty() || name.contains('*') {
        return Err(bad());
    }
    let value = match (v.strip_prefix('*'), v.strip_suffix('*')) {
        _ if v == "*" => ValueMatch::Any,
        (Some(s), _) if !s.contains('*') => ValueMatch::Suffix(s.into()),
        (_, Some(p)) if !p.contains('*') => ValueMatch::Prefix(p.into()),
        _ if !v.contains('*') => ValueMatch::Exact(v.into()),
        _ => return Err(bad()),
    };
    Ok(QueryMatch {
        name: name.into(),
        value,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{Mode, rules::parse_list};
    use http::HeaderMap;

    fn deny_all() -> policy::Policy {
        policy::Policy {
            mode: Some(Mode::DenyAll),
            ..Default::default()
        }
    }

    fn add(
        p: &mut policy::Policy,
        d: Decision,
        res: &str,
        via: &str,
        method: Option<&str>,
        path: Option<&str>,
        query: Option<&str>,
    ) -> String {
        p.insert_rule(
            Some("s1"),
            d,
            res,
            via,
            method.map(Into::into),
            path.map(Into::into),
            query.map(Into::into),
        )
        .unwrap()
        .0
    }

    fn one(method: Option<&str>, path: Option<&str>, query: Option<&str>) -> Rule {
        let mut p = deny_all();
        add(
            &mut p,
            Decision::Deny,
            "h.com",
            "added",
            method,
            path,
            query,
        );
        let mut got = request_policy(&p, "s1", &[]).rules;
        assert_eq!(got.len(), 1);
        got.remove(0)
    }

    #[test]
    fn every_sbx_form_maps() {
        let only = |ms: &[&str]| Methods::Only(ms.iter().map(|m| (*m).to_string()).collect());
        let q = |name: &str, value: ValueMatch| QueryMatch {
            name: name.into(),
            value,
        };
        let glob = |p: &str| vec![PathGlob::parse(p).unwrap()];
        for (method, path, query, want) in [
            (
                Some("post"),
                None,
                None,
                RequestMatch {
                    methods: only(&["POST"]),
                    paths: glob("/**"),
                    query: vec![],
                },
            ),
            (
                Some("GET,head"),
                Some("/v1/**"),
                None,
                RequestMatch {
                    methods: only(&["GET", "HEAD"]),
                    paths: glob("/v1/**"),
                    query: vec![],
                },
            ),
            (
                Some("ANY"),
                Some("/a/*"),
                None,
                RequestMatch {
                    methods: Methods::Any,
                    paths: glob("/a/*"),
                    query: vec![],
                },
            ),
            (
                None,
                None,
                Some("tag=prod,v=1.*,s=*-rc,x=*"),
                RequestMatch {
                    methods: Methods::Any,
                    paths: glob("/**"),
                    query: vec![
                        q("tag", ValueMatch::Exact("prod".into())),
                        q("v", ValueMatch::Prefix("1.".into())),
                        q("s", ValueMatch::Suffix("-rc".into())),
                        q("x", ValueMatch::Any),
                    ],
                },
            ),
        ] {
            assert_eq!(
                one(method, path, query).request,
                want,
                "{method:?} {path:?} {query:?}"
            );
        }
        // Hosts and ports.
        let mut p = deny_all();
        let id = add(
            &mut p,
            Decision::Allow,
            "a.com:8443,*.b.com,**.c.com",
            "added",
            Some("GET"),
            None,
            None,
        );
        let got = request_policy(&p, "s1", &[]).rules;
        let hosts: Vec<_> = got.iter().map(|r| (r.hosts.clone(), r.port)).collect();
        assert_eq!(
            hosts,
            [
                (vec![HostMatch::Exact("a.com".into())], Some(8443)),
                (
                    vec![HostMatch::Subdomains {
                        domain: "b.com".into(),
                        any_depth: false
                    }],
                    None
                ),
                (
                    vec![HostMatch::Subdomains {
                        domain: "c.com".into(),
                        any_depth: true
                    }],
                    None
                ),
            ]
        );
        assert!(got.iter().all(|r| r.id.as_deref() == Some(id.as_str())
            && r.action == Action::Allow
            && r.case == Case::Insensitive));
        // Bad query forms are refused.
        for bad in ["x", "=v", "a*=v", "x=a*b", "x=*a*"] {
            assert!(request(None, None, Some(bad)).is_err(), "{bad}");
        }
    }

    #[test]
    fn connection_rules_dont_map_and_the_default_allows() {
        let mut p = deny_all();
        add(&mut p, Decision::Deny, "h.com", "added", None, None, None);
        add(&mut p, Decision::Allow, "a.com", "added", None, None, None);
        let got = request_policy(&p, "s1", &[]);
        assert!(got.rules.is_empty());
        assert_eq!(got.default, Action::Allow);
    }

    #[test]
    fn a_stored_method_deny_becomes_request_level() {
        let mut p = deny_all();
        add(
            &mut p,
            Decision::Deny,
            "h.com",
            "added",
            Some("POST"),
            None,
            None,
        );
        add(&mut p, Decision::Allow, "h.com", "added", None, None, None);
        assert!(compile::decide(&p, "s1", &[], false, "h.com:443").allowed);
        let rp = request_policy(&p, "s1", &[]);
        let h = HeaderMap::new();
        assert!(rp.request("h.com", 443, "POST", "/", &h).is_err());
        assert!(rp.request("h.com", 443, "GET", "/", &h).is_ok());
    }

    #[test]
    fn kit_rules_are_case_sensitive() {
        let mut p = deny_all();
        add(
            &mut p,
            Decision::Deny,
            "h.com",
            "kit:k",
            Some("GET"),
            Some("/A"),
            None,
        );
        add(
            &mut p,
            Decision::Deny,
            "h.com",
            "added",
            Some("GET"),
            Some("/B"),
            None,
        );
        let cases: Vec<_> = (request_policy(&p, "s1", &[]).rules.iter())
            .map(|r| r.case)
            .collect();
        assert_eq!(cases, [Case::Sensitive, Case::Insensitive]);
    }

    #[test]
    fn a_glob_host_widens_on_deny_and_is_refused_on_allow() {
        let crl = parse_list("crl*.x.com").unwrap();
        assert!(check(Decision::Deny, &crl, Some("POST"), None, None).is_ok());
        assert!(
            check(Decision::Allow, &crl, Some("GET"), None, None)
                .unwrap_err()
                .contains("host glob")
        );
        let mut p = deny_all();
        add(
            &mut p,
            Decision::Deny,
            "crl*.x.com",
            "added",
            Some("POST"),
            None,
            None,
        );
        // Stored by an older version: skipped, not fatal.
        add(
            &mut p,
            Decision::Allow,
            "crl*.y.com",
            "added",
            Some("GET"),
            None,
            None,
        );
        let got = request_policy(&p, "s1", &[]).rules;
        assert_eq!(got.len(), 1);
        assert_eq!(
            got[0].hosts,
            [HostMatch::Subdomains {
                domain: "x.com".into(),
                any_depth: true
            }]
        );
    }

    #[test]
    fn an_unparseable_request_rule_doesnt_disable_the_others() {
        let mut p = deny_all();
        add(
            &mut p,
            Decision::Deny,
            "api.x.com",
            "added",
            None,
            Some("/admin/"),
            None,
        );
        add(
            &mut p,
            Decision::Allow,
            "a.com",
            "added",
            Some("GET"),
            Some("//x"),
            None,
        );
        add(
            &mut p,
            Decision::Deny,
            "h.com",
            "added",
            Some("POST"),
            None,
            None,
        );
        let got = request_policy(&p, "s1", &[]).rules;
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].hosts, [HostMatch::Exact("h.com".into())]);
        let r = |res: &str| {
            (compile::active(&p, Some("s1"), &[]).map(|(r, _)| r))
                .find(|r| r.resources == [res])
                .unwrap()
        };
        let res = |s: &str| Resource::parse(s).unwrap();
        assert_eq!(mapped_host(r("api.x.com"), &res("api.x.com")), None);
        assert_eq!(mapped_host(r("h.com"), &res("h.com")), Some("h.com".into()));
    }

    #[test]
    fn request_rules_need_a_named_host() {
        for res in ["**", "10.0.0.0/8", "1.2.3.4"] {
            let err = check(
                Decision::Deny,
                &parse_list(res).unwrap(),
                Some("POST"),
                None,
                None,
            );
            assert_eq!(err.unwrap_err(), "request rules need a named host", "{res}");
        }
        // A stored one is skipped, and never fails the rest.
        let mut p = deny_all();
        add(
            &mut p,
            Decision::Deny,
            "**",
            "added",
            Some("POST"),
            None,
            None,
        );
        add(
            &mut p,
            Decision::Deny,
            "h.com",
            "added",
            Some("POST"),
            None,
            None,
        );
        assert_eq!(request_policy(&p, "s1", &[]).rules.len(), 1);
    }

    fn post_passes(p: &policy::Policy, creds: &[String], host: &str) -> bool {
        request_policy(p, "s1", creds)
            .request(host, 443, "POST", "/", &HeaderMap::new())
            .is_ok()
    }

    #[test]
    fn an_unbounded_allow_makes_a_bounded_allow_moot() {
        let mut p = deny_all();
        add(&mut p, Decision::Allow, "h.com", "added", None, None, None);
        add(
            &mut p,
            Decision::Allow,
            "h.com",
            "added",
            Some("GET"),
            None,
            None,
        );
        assert!(request_policy(&p, "s1", &[]).rules.is_empty());
        assert!(post_passes(&p, &[], "h.com"));
        // An allow of one port leaves the others to the bounded allow.
        let mut p = deny_all();
        add(
            &mut p,
            Decision::Allow,
            "h.com:443",
            "added",
            None,
            None,
            None,
        );
        add(
            &mut p,
            Decision::Allow,
            "h.com",
            "added",
            Some("GET"),
            None,
            None,
        );
        assert!(!post_passes(&p, &[], "h.com"));
        // One subdomain doesn't cover them all.
        let mut p = deny_all();
        add(
            &mut p,
            Decision::Allow,
            "a.x.com",
            "added",
            None,
            None,
            None,
        );
        add(
            &mut p,
            Decision::Allow,
            "*.x.com",
            "added",
            Some("GET"),
            None,
            None,
        );
        assert!(!post_passes(&p, &[], "b.x.com"));
        add(
            &mut p,
            Decision::Allow,
            "*.x.com",
            "added",
            None,
            None,
            None,
        );
        assert!(post_passes(&p, &[], "b.x.com"));
        // A credential host is admitted before any rule.
        let mut p = deny_all();
        add(
            &mut p,
            Decision::Allow,
            "h.com",
            "added",
            Some("GET"),
            None,
            None,
        );
        assert!(!post_passes(&p, &[], "h.com"));
        assert!(post_passes(&p, &["h.com".into()], "h.com"));
    }

    #[test]
    fn a_preset_host_makes_a_bounded_allow_moot() {
        let mut p = policy::Policy {
            mode: Some(Mode::Balanced),
            ..Default::default()
        };
        add(
            &mut p,
            Decision::Allow,
            "api.anthropic.com",
            "added",
            Some("GET"),
            None,
            None,
        );
        assert!(post_passes(&p, &[], "api.anthropic.com"));
    }

    #[test]
    fn allow_all_makes_bounded_allows_moot() {
        let mut p = policy::Policy {
            mode: Some(Mode::AllowAll),
            ..Default::default()
        };
        add(
            &mut p,
            Decision::Allow,
            "h.com",
            "added",
            Some("GET"),
            None,
            None,
        );
        assert!(post_passes(&p, &[], "h.com"));
    }

    #[test]
    fn a_bounded_deny_still_maps_beside_an_unbounded_allow() {
        let mut p = policy::Policy {
            mode: Some(Mode::AllowAll),
            ..Default::default()
        };
        add(&mut p, Decision::Allow, "h.com", "added", None, None, None);
        add(
            &mut p,
            Decision::Deny,
            "h.com",
            "added",
            Some("POST"),
            None,
            None,
        );
        assert!(!post_passes(&p, &[], "h.com"));
    }

    #[test]
    fn a_glob_allow_never_makes_a_subdomain_bounded_allow_moot() {
        let mut p = deny_all();
        add(
            &mut p,
            Decision::Allow,
            "?.x.com",
            "added",
            None,
            None,
            None,
        );
        add(
            &mut p,
            Decision::Allow,
            "*.x.com",
            "added",
            Some("GET"),
            None,
            None,
        );
        assert!(!post_passes(&p, &[], "api.x.com"));
    }
}
