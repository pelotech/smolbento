//! `policy.toml`'s request-qualified rules (`--method/--path/--query`, sbx semantics) as an
//! `egress_front` request policy. Connection rules stay with `policy::compile::decide`.

use egress_front::{
    Action, Case, HostMatch, Methods, PathGlob, Policy, QueryMatch, RequestMatch, Rule, ValueMatch,
};

use crate::policy::rules::{Pattern, Resource};
use crate::policy::{self, Decision, compile};

/// The request rules that apply to `sandbox`: its active global, per-sandbox and kit rules with a
/// method, path or query, one crate rule per resource. Connection defaults stay in `decide`, so a
/// host no rule names is allowed.
pub fn request_policy(policy: &policy::Policy, sandbox: &str) -> Result<Policy, String> {
    let mut rules = Vec::new();
    for (r, _) in compile::active(policy, Some(sandbox), &[]).filter(|(r, _)| r.is_request()) {
        let request = request(r.method.as_deref(), r.path.as_deref(), r.query.as_deref())
            .map_err(|e| format!("rule {}: {e}", r.id))?;
        for res in r.parsed() {
            // A host `policy allow` refuses now but an older version stored: unenforced, as in
            // 0.37.0, rather than failing every other rule.
            let Ok(host) = host(r.decision, &res) else {
                continue;
            };
            rules.push(Rule {
                id: Some(r.id.clone()),
                action: action(r.decision),
                hosts: vec![host],
                port: res.port,
                request: request.clone(),
                reason: None,
                // Kits follow the kit spec; `bento policy` follows sbx.
                case: if r.created_via.starts_with(policy::KIT_VIA) {
                    Case::Sensitive
                } else {
                    Case::Insensitive
                },
            });
        }
    }
    let p = Policy {
        rules,
        default: Action::Allow,
    };
    p.validate()?;
    Ok(p)
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
        let mut got = request_policy(&p, "s1").unwrap().rules;
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
        let got = request_policy(&p, "s1").unwrap().rules;
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
        let got = request_policy(&p, "s1").unwrap();
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
        let rp = request_policy(&p, "s1").unwrap();
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
        let cases: Vec<_> = (request_policy(&p, "s1").unwrap().rules.iter())
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
        let got = request_policy(&p, "s1").unwrap().rules;
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
        assert_eq!(request_policy(&p, "s1").unwrap().rules.len(), 1);
    }
}
