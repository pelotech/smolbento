//! Request rules (`--method/--path/--query`, `network-policy@2` methods and paths) on hosted
//! sandboxes: the egress process decrypts ruled hosts and judges each request. Every rule is
//! scoped to the test's sandbox: other tests reach httpbin.org at the same time.

use super::*;
use crate::bridge_agent::unit_files;

/// This test's Alpine sandbox with curl, created under `allow-all` (apk needs the
/// network). `deny_all` then switches it to `deny-all`, where a bounded allow isn't moot.
fn sandbox(e: &E2e, deny_all: bool) {
    e.create_alpine_with("apk add -q curl");
    if deny_all {
        e.ok(&["policy", "init", "deny-all"]);
    }
}

/// `bento policy allow|deny network --sandbox <sandbox> ARGS`: the new rule's id.
fn rule(e: &E2e, decision: &str, args: &[&str]) -> String {
    let head = ["policy", decision, "network", "--sandbox", e.name.as_str()];
    let out = e.ok(&[&head[..], args].concat());
    // `allow rule r-1234abcd: HOST`
    let id = out.split_whitespace().nth(2).expect("a rule id");
    id.trim_end_matches(':').to_string()
}

/// `curl ARGS` in the sandbox: the status code (`000` with no answer) and the body.
fn curl(e: &E2e, args: &str) -> (String, String) {
    let out = out_text(&e.sh(
        &e.name,
        &format!("curl -s -m 15 -w '\\n%{{http_code}}' {args}"),
    ));
    let (body, code) = out.rsplit_once('\n').unwrap_or(("", &out));
    (code.trim().to_string(), body.to_string())
}

fn status(e: &E2e, args: &str) -> String {
    curl(e, args).0
}

/// The pid of the sandbox's egress process, once a connection has started it.
fn egress(e: &E2e) -> Option<u32> {
    let units = unit_files(e, &e.name);
    let unit = units
        .iter()
        .find(|u| u.to_string_lossy().contains("egress"))?;
    egress_pid(unit)
}

/// `GET /get` on `host` until it answers 200: the first request after a new ruled host ends the
/// egress process, and launchd may hold its relaunch for up to 10 s.
fn wait_for_get(e: &E2e, host: &str) -> bool {
    wait_until(25, || {
        status(e, &format!("https://{host}/get -o /dev/null")) == "200"
    })
}

/// `wait_for_get`'s wait for any answer from `url`, for a host whose GET isn't allowed.
fn wait_for_answer(e: &E2e, url: &str) -> bool {
    wait_until(25, || status(e, &format!("{url} -o /dev/null")) != "000")
}

#[test]
#[ignore = "boots real VMs and needs httpbin.org; run with `just e2e`"]
pub(crate) fn hosted_request_rule_refuses_post() {
    let e = E2e::new("rqpost");
    sandbox(&e, true);
    rule(&e, "allow", &["httpbin.org", "--method", "GET"]);
    let deny = rule(&e, "deny", &["httpbin.org", "--method", "DELETE"]);
    assert!(wait_for_get(&e, "httpbin.org"), "GET is allowed");
    // A decrypted host is HTTP/1.1 only.
    let v = out_text(&e.sh(
        &e.name,
        "curl -s -m 15 -o /dev/null -w '%{http_version}' https://httpbin.org/get",
    ));
    assert_eq!(v, "1.1");
    let (code, body) = curl(&e, "-X POST https://httpbin.org/post");
    assert_eq!(code, "403", "{body}");
    assert!(
        body.contains("no rule allows POST /post on httpbin.org"),
        "{body}"
    );
    let (code, body) = curl(&e, "-X DELETE https://httpbin.org/delete");
    assert_eq!(code, "403", "{body}");
    assert!(body.contains(&deny), "the refusal names the rule: {body}");
    // Plain HTTP to a ruled host can't be judged per request: refused.
    assert_eq!(status(&e, "http://httpbin.org/get -o /dev/null"), "000");
    let log = egress_log(&e, &e.name);
    assert!(
        log.contains("deny httpbin.org:80: plain HTTP to a host with request rules"),
        "{log}"
    );
}

#[test]
#[ignore = "boots real VMs and needs httpbin.org; run with `just e2e`"]
pub(crate) fn hosted_credential_host_still_swaps() {
    let e = E2e::new("rqcred");
    e.own_httpbin_secret("TOK", BASIC_SECRET);
    sandbox(&e, false);
    let deny = rule(&e, "deny", &["httpbin.org", "--method", "POST"]);
    assert!(wait_for_answer(&e, "https://httpbin.org/get"));
    assert!(
        basic_auth_ok(&e, &e.name, "TOK", "real-secret-xyz"),
        "the secret is swapped"
    );
    let (code, body) = curl(&e, "-X POST https://httpbin.org/post");
    assert_eq!(code, "403", "{body}");
    assert!(body.contains(&deny), "{body}");
    // A host with no rule and no secret is spliced, not decrypted: HTTP/2 is negotiated.
    let v = out_text(&e.sh(
        &e.name,
        "curl -s -m 15 -o /dev/null -w '%{http_version}' https://www.wikipedia.org/",
    ));
    assert_eq!(v, "2");
    let log = egress_log(&e, &e.name);
    assert!(!log.contains("wikipedia"), "{log}");
}

#[test]
#[ignore = "boots real VMs and needs httpbin.org; run with `just e2e`"]
pub(crate) fn hosted_request_rule_applies_live() {
    let e = E2e::new("rqlive");
    sandbox(&e, true);
    let before = egress(&e).expect("apk's downloads started the egress process");
    let boot = root_out(&e.name, "cat /proc/sys/kernel/random/boot_id");
    assert_eq!(status(&e, "https://httpbin.org/get -o /dev/null"), "000");
    rule(&e, "allow", &["httpbin.org", "--method", "GET"]);
    assert!(
        wait_for_get(&e, "httpbin.org"),
        "the unit starts the egress process again"
    );
    assert_eq!(
        status(&e, "-X POST https://httpbin.org/post -o /dev/null"),
        "403"
    );
    let after = egress(&e).expect("the egress process runs again");
    assert_ne!(
        before, after,
        "a new ruled host restarts the egress process"
    );
    let log = egress_log(&e, &e.name);
    assert!(
        log.contains("request-rule hosts changed; restarting"),
        "{log}"
    );
    assert_eq!(
        root_out(&e.name, "cat /proc/sys/kernel/random/boot_id"),
        boot,
        "the sandbox wasn't restarted"
    );
}

/// A declaration-only mixin in `reg` (no build) whose `network-policy@2` allows `host` for GET only.
fn get_only_kit(reg: &Registry, repo: &str, host: &str) -> String {
    let caps = serde_json::json!([{
        "type": "com.docker.sandbox/network-policy@2",
        "config": {"runtime": {"allow": [{"hosts": [host], "methods": ["GET"]}]}},
    }]);
    let provides = format!("{repo}@1.0.0");
    reg.push(
        repo,
        Image::empty(),
        descriptor("mixin", &[&provides], caps),
    )
}

/// tck: network-policy@2/bounded-host-refused-outside-rules, network-policy@2/refusal-is-403
#[test]
#[ignore = "boots real VMs and needs httpbin.org and postman-echo.com; run with `just e2e`"]
pub(crate) fn hosted_kit_request_rules_are_enforced() {
    let e = E2e::new("rqkit");
    let reg = Registry::start(&e);
    let kit = get_only_kit(&reg, "rq-get", "httpbin.org");
    e.create_with_kits(&[&kit]);
    guest_root(&e.name, "apk add -q curl");
    e.ok(&["policy", "init", "deny-all"]);
    // `kit add` changes smolvm's allow list live, which a machine booted under allow-all has none of.
    e.ok(&["stop", &e.name]);
    e.ok(&["start", &e.name]);
    assert!(wait_for_get(&e, "httpbin.org"), "the kit allows GET");
    let (code, body) = curl(&e, "-X POST https://httpbin.org/post");
    assert_eq!(code, "403", "{body}");

    // `kit add` on the running sandbox: its rules on another host apply once the egress process
    // restarts.
    let added = get_only_kit(&reg, "rq-added", "postman-echo.com");
    e.ok(&["kit", "add", &e.name, &added, "--yes"]);
    assert!(
        wait_for_get(&e, "postman-echo.com"),
        "the added kit allows GET"
    );
    let (code, body) = curl(&e, "-X POST https://postman-echo.com/post");
    assert_eq!(code, "403", "{body}");
}
