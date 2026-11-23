use super::*;
use http::HeaderMap;

fn rule(action: Action, host: &str, methods: &[&str], paths: &[&str]) -> Rule {
    Rule {
        id: None,
        action,
        hosts: vec![HostMatch::Exact(host.into())],
        port: None,
        request: RequestMatch {
            methods: if methods.is_empty() {
                Methods::Any
            } else {
                Methods::Only(methods.iter().map(|m| (*m).into()).collect())
            },
            paths: paths.iter().map(|p| PathGlob::parse(p).unwrap()).collect(),
            query: vec![],
        },
        reason: None,
        case: Case::Insensitive,
    }
}

fn allow(host: &str, methods: &[&str], paths: &[&str]) -> Rule {
    rule(Action::Allow, host, methods, paths)
}

fn deny(host: &str, methods: &[&str], paths: &[&str]) -> Rule {
    rule(Action::Deny, host, methods, paths)
}

fn policy(rules: Vec<Rule>) -> Policy {
    let p = Policy {
        rules,
        default: Action::Allow,
    };
    p.validate().unwrap();
    p
}

fn check(p: &Policy, method: &str, target: &str) -> Result<(), String> {
    check_with(p, method, target, &HeaderMap::new())
}

fn check_with(p: &Policy, method: &str, target: &str, headers: &HeaderMap) -> Result<(), String> {
    p.request("h", 443, method, target, headers)
        .map_err(|r| r.reason)
}

fn query(name: &str, value: ValueMatch) -> QueryMatch {
    QueryMatch {
        name: name.into(),
        value,
    }
}

#[test]
fn method_rules_match_their_methods() {
    let p = policy(vec![allow("h", &["GET", "HEAD"], &["/**"])]);
    assert!(check(&p, "GET", "/x").is_ok());
    assert!(check(&p, "HEAD", "/x").is_ok());
    assert!(check(&p, "POST", "/x").is_err());

    let p = policy(vec![deny("h", &["POST"], &["/**"])]);
    assert!(check(&p, "GET", "/x").is_ok());
    assert!(check(&p, "POST", "/x").is_err());
}

#[test]
fn star_matches_one_segment_and_inside_a_segment() {
    let p = policy(vec![allow("h", &[], &["/v*/x", "/a/*/c"])]);
    assert!(check(&p, "GET", "/v1/x").is_ok());
    assert!(check(&p, "GET", "/v/x").is_ok());
    assert!(check(&p, "GET", "/v1/y/x").is_err());
    assert!(check(&p, "GET", "/a/b/c").is_ok());
    assert!(
        check(&p, "GET", "/a/c").is_err(),
        "a whole-segment * needs a segment"
    );
    assert!(check(&p, "GET", "/a/b/b/c").is_err());
}

#[test]
fn double_star_matches_zero_or_more_segments() {
    let p = policy(vec![allow("h", &[], &["/a/**"])]);
    assert!(check(&p, "GET", "/a").is_ok());
    assert!(check(&p, "GET", "/a/b/c").is_ok());
    assert!(check(&p, "GET", "/ab").is_err());
    assert!(check(&p, "GET", "/").is_err());

    let p = policy(vec![allow("h", &[], &["/**/hooks"])]);
    assert!(check(&p, "GET", "/hooks").is_ok());
    assert!(check(&p, "GET", "/r/o/hooks").is_ok());
    assert!(check(&p, "GET", "/r/o/hooks/1").is_err());
}

#[test]
fn query_any_value_and_prefix_and_suffix() {
    let mut r = allow("h", &[], &["/**"]);
    r.request.query = vec![
        query("a", ValueMatch::Any),
        query("v", ValueMatch::Prefix("1.".into())),
        query("f", ValueMatch::Suffix(".json".into())),
        query("t", ValueMatch::Exact("prod".into())),
    ];
    let p = policy(vec![r]);
    assert!(check(&p, "GET", "/?a&v=1.2&f=x.json&t=prod").is_ok());
    assert!(check(&p, "GET", "/?a=anything&v=1.&f=.json&t=PROD").is_ok());
    assert!(
        check(&p, "GET", "/?v=1.2&f=x.json&t=prod").is_err(),
        "a is required"
    );
    assert!(check(&p, "GET", "/?a&v=2.1&f=x.json&t=prod").is_err());
    assert!(check(&p, "GET", "/?a&v=1.2&f=x.yaml&t=prod").is_err());
    assert!(check(&p, "GET", "/?a&v=1.2&f=x.json&t=prod2").is_err());
    assert!(
        check(&p, "GET", "/?a&v=1%2E2&f=x.json&t=pr%6fd").is_ok(),
        "values are decoded"
    );
}

#[test]
fn repeated_query_params_allow_only_if_every_value_matches_and_deny_if_any_does() {
    let mut r = allow("h", &[], &["/**"]);
    r.request.query = vec![query("t", ValueMatch::Exact("prod".into()))];
    let p = policy(vec![r]);
    assert!(check(&p, "GET", "/?t=prod&t=prod").is_ok());
    assert!(check(&p, "GET", "/?t=prod&t=dev").is_err());
    assert!(
        check(&p, "GET", "/?t=prod;t=dev").is_err(),
        "`;` separates too"
    );
    assert!(
        check(&p, "GET", "/?t=prod;x").is_err(),
        "`&`-only reading sees t=prod;x"
    );

    let mut r = deny("h", &[], &["/**"]);
    r.request.query = vec![query("t", ValueMatch::Exact("dev".into()))];
    let p = policy(vec![r]);
    assert!(check(&p, "GET", "/?t=prod").is_ok());
    assert!(check(&p, "GET", "/?t=prod&t=dev").is_err());
    assert!(check(&p, "GET", "/?t=prod;t=dev").is_err());
    assert!(check(&p, "GET", "/?t=d+ev").is_ok());
}

#[test]
fn deny_beats_allow() {
    let mut d = deny("h", &[], &["/repos/*/*/hooks/**"]);
    d.reason = Some("webhooks are blocked".into());
    d.id = Some("r7".into());
    // Order never matters.
    for rules in [
        vec![allow("h", &[], &["/repos/**"]), d.clone()],
        vec![d.clone(), allow("h", &[], &["/repos/**"])],
    ] {
        let p = policy(rules);
        assert!(check(&p, "GET", "/repos/o/r/issues").is_ok());
        assert_eq!(
            check(&p, "POST", "/repos/o/r/hooks").unwrap_err(),
            "webhooks are blocked (rule r7)"
        );
    }
}

#[test]
fn a_host_with_bounded_allows_refuses_the_rest() {
    let p = policy(vec![allow("h", &["GET"], &["/x"])]);
    assert_eq!(
        check(&p, "DELETE", "/x").unwrap_err(),
        "no rule allows DELETE /x on h"
    );
    assert_eq!(
        check(&p, "GET", "/y").unwrap_err(),
        "no rule allows GET /y on h"
    );
    // Another host, or a host only denies name, falls to the default.
    assert!(
        p.request("other", 443, "DELETE", "/x", &HeaderMap::new())
            .is_ok()
    );
    let strict = Policy {
        rules: vec![],
        default: Action::Deny,
    };
    assert!(
        strict
            .request("other", 443, "GET", "/", &HeaderMap::new())
            .is_err()
    );
}

#[test]
fn confused_paths_never_reach_a_denied_path() {
    let p = policy(vec![
        allow("h", &[], &["/**"]),
        deny("h", &[], &["/admin/**"]),
    ]);
    for target in [
        "/admin",
        "/admin;x=1",
        "//admin",
        "/%61dmin",
        "/ADMIN/users",
        "/public/..;/admin",
        "/a/%2e%2e/admin",
        "/admin;x/b",
        "/./admin/",
        "/admin/?x",
    ] {
        assert!(check(&p, "GET", target).is_err(), "{target} reached /admin");
    }
    assert!(check(&p, "GET", "/administrator").is_ok());
    assert!(check(&p, "GET", "/public/admin").is_ok());
}

#[test]
fn ambiguous_targets_are_refused() {
    let p = policy(vec![allow("h", &[], &["/**"])]);
    for target in [
        "/a%2Fb", "/a%2fb", "/a%5cb", "/a%5Cb", "/%252e", "/%c0%af", "/a%00", "/%u002e", "/a%",
        "/a%zz", "/a%+f", "/a\tb", "a", "*",
    ] {
        assert_eq!(
            check(&p, "GET", target).unwrap_err(),
            "ambiguous request target",
            "{target}"
        );
    }
    // A host no rule names isn't judged, so its encoded slashes pass.
    assert!(
        p.request("other", 443, "GET", "/g%2Fp", &HeaderMap::new())
            .is_ok()
    );
}

#[test]
fn an_override_header_counts_as_the_method() {
    let p = policy(vec![
        allow("h", &["GET"], &["/**"]),
        deny("h", &["DELETE"], &["/"]),
    ]);
    for name in [
        "x-http-method-override",
        "X-HTTP-Method",
        "x-method-override",
    ] {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            "DELETE".parse().unwrap(),
        );
        assert!(check_with(&p, "GET", "/", &headers).is_err(), "{name}");
        // A deny alone fires on any view.
        let deny_only = policy(vec![deny("h", &["DELETE"], &["/"])]);
        assert!(
            check_with(&deny_only, "GET", "/", &headers).is_err(),
            "{name}, deny only"
        );
        assert!(check(&deny_only, "GET", "/").is_ok());
    }
    // An allow needs every view: a GET-only host refuses a GET that says it's a PUT.
    let mut headers = HeaderMap::new();
    headers.insert("x-http-method-override", "PUT".parse().unwrap());
    assert!(check_with(&p, "GET", "/x", &headers).is_err());
    headers.insert("x-http-method-override", "get, PUT".parse().unwrap());
    assert!(check_with(&p, "GET", "/x", &headers).is_err());
    headers.insert("x-http-method-override", "get".parse().unwrap());
    assert!(check_with(&p, "GET", "/x", &headers).is_ok());
}

#[test]
fn case_is_per_rule() {
    let mut sensitive = deny("h", &[], &["/Admin/**"]);
    sensitive.case = Case::Sensitive;
    let p = policy(vec![sensitive]);
    assert!(check(&p, "GET", "/Admin").is_err());
    assert!(check(&p, "GET", "/admin").is_ok());

    let p = policy(vec![deny("h", &[], &["/Admin/**"])]);
    assert!(check(&p, "GET", "/admin").is_err());
    assert!(check(&p, "GET", "/ADMIN").is_err());

    let mut q = allow("h", &[], &["/**"]);
    q.case = Case::Sensitive;
    q.request.query = vec![query("T", ValueMatch::Exact("Prod".into()))];
    let p = policy(vec![q]);
    assert!(check(&p, "GET", "/?T=Prod").is_ok());
    assert!(check(&p, "GET", "/?t=Prod").is_err());
    assert!(check(&p, "GET", "/?T=prod").is_err());
}

#[test]
fn inspection_by_rule_kind() {
    let mut on_22 = allow("ssh.h", &[], &["/**"]);
    on_22.port = Some(22);
    let mut sub = deny("x", &[], &["/**"]);
    sub.hosts = vec![HostMatch::Subdomains {
        domain: "d.com".into(),
        any_depth: false,
    }];
    let p = policy(vec![
        allow("a", &["GET"], &["/**"]),
        deny("a", &[], &["/x"]),
        deny("b", &[], &["/x"]),
        on_22,
        sub,
    ]);
    let inspect = |uninspectable| Inspection::Inspect { uninspectable };
    assert_eq!(p.inspection("a", 443), inspect(Action::Deny));
    assert_eq!(
        p.inspection("A.", 22),
        inspect(Action::Deny),
        "case and a trailing dot"
    );
    assert_eq!(p.inspection("b", 443), inspect(Action::Allow));
    assert_eq!(p.inspection("c", 443), Inspection::None);
    assert_eq!(p.inspection("ssh.h", 22), inspect(Action::Deny));
    assert_eq!(p.inspection("ssh.h", 443), Inspection::None);
    assert_eq!(p.inspection("api.d.com", 443), inspect(Action::Allow));
    assert_eq!(
        p.inspection("d.com", 443),
        Inspection::None,
        "never the apex"
    );
    assert_eq!(
        p.inspection("a.b.d.com", 443),
        Inspection::None,
        "one label"
    );
}

#[test]
fn terminate_hosts_forms() {
    let mut r = deny("Api.Example.com.", &[], &["/**"]);
    r.hosts.extend([
        HostMatch::Subdomains {
            domain: "one.com".into(),
            any_depth: false,
        },
        HostMatch::Subdomains {
            domain: "deep.com".into(),
            any_depth: true,
        },
        HostMatch::Exact("api.example.com".into()),
    ]);
    let p = policy(vec![r]);
    assert_eq!(
        p.terminate_hosts(),
        ["*.deep.com", "*.one.com", "api.example.com"]
    );

    let mut deep = deny("x", &[], &["/**"]);
    deep.hosts = vec![HostMatch::Subdomains {
        domain: "deep.com".into(),
        any_depth: true,
    }];
    let p = policy(vec![deep]);
    assert_eq!(
        p.inspection("a.b.deep.com", 443),
        Inspection::Inspect {
            uninspectable: Action::Allow
        }
    );
    assert_eq!(
        p.inspection("deep.com", 443),
        Inspection::None,
        "never the apex"
    );
}

#[test]
fn validate_refuses_rule_paths_that_never_match() {
    for path in [
        "/a//b", "/a/../b", "/a/./b", "/a?x", "a", "", "/a/", "/a#b", "/a;b", "/a%2fb", "/a\\b",
        "/a**", "/a\tb",
    ] {
        assert!(PathGlob::parse(path).is_err(), "{path}");
    }
    for path in ["/", "/**", "/a/*/b", "/v*", "/**/x"] {
        assert!(PathGlob::parse(path).is_ok(), "{path}");
    }
    let mut no_hosts = allow("h", &[], &["/**"]);
    no_hosts.hosts.clear();
    let mut no_paths = allow("h", &[], &[]);
    no_paths.request.paths.clear();
    let mut no_methods = allow("h", &[], &["/**"]);
    no_methods.request.methods = Methods::Only(vec![]);
    let mut every_host = allow("h", &[], &["/**"]);
    every_host.hosts = vec![HostMatch::Any];
    for r in [no_hosts, no_paths, no_methods, every_host] {
        assert!(
            Policy {
                rules: vec![r],
                default: Action::Allow
            }
            .validate()
            .is_err()
        );
    }
}
