//! Kit-to-kit capabilities: `provides`, `requires`, `integrates` and `conflicts` entries, parsed
//! and matched as SPEC-v3 §5 says (pinned in `super::SPEC_COMMIT`; a port of the spec's Go
//! `spec/version.go`). Versions are dotted segments compared per segment, not semver. Every
//! message here is the spec frontend's or resolver's text as sbx prints it (checklist #27,
//! without sbx's outer `resolve kits:` prefix), so the composition errors live in one place.

use std::cmp::Ordering;
use std::fmt;
use std::sync::LazyLock;

use regex_lite::Regex;

/// Bare names normalize into this namespace: `gh` and `com.docker.kit/gh` are one capability.
pub const DEFAULT_NAMESPACE: &str = "com.docker.kit";

static NAME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z0-9]([a-z0-9+.-]{0,62}[a-z0-9+])?$").unwrap());
static NAMESPACE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[a-z0-9.-]+$").unwrap());
static LABEL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$").unwrap());
static VERSION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[0-9]+(\.[0-9A-Za-z-]+)*$").unwrap());
static ARG_REF: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\$\{\{\s*kit\.args\.([A-Za-z_][A-Za-z0-9_]*)\s*\}\}").unwrap());

/// Single-label namespaces the spec defines (for derived provides); authors may not use others.
const RESERVED: [&str; 2] = ["deb", "apk"];
const MAX_NAMESPACE: usize = 253;
/// Appended to a version, the smallest version above it (`>` becomes `>=` of it).
const SUCCESSOR: &str = ".-";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provide {
    /// Normalized.
    pub name: String,
    pub version: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Ge,
    Gt,
    Le,
    Lt,
    Eq,
}

impl fmt::Display for Op {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Op::Ge => ">=",
            Op::Gt => ">",
            Op::Le => "<=",
            Op::Lt => "<",
            Op::Eq => "=",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Constraint {
    pub op: Op,
    pub version: String,
}

/// A `requires` or `integrates` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Require {
    /// Normalized.
    pub name: String,
    /// All must hold; empty when unconstrained.
    pub constraints: Vec<Constraint>,
}

pub fn normalize(name: &str) -> String {
    if name.contains('/') {
        name.to_string()
    } else {
        format!("{DEFAULT_NAMESPACE}/{name}")
    }
}

/// The short form of a normalized name.
pub fn display(name: &str) -> &str {
    name.strip_prefix(DEFAULT_NAMESPACE)
        .and_then(|n| n.strip_prefix('/'))
        .unwrap_or(name)
}

/// Whether `s` holds a `${{ kit.args.NAME }}` reference.
pub fn has_arg_ref(s: &str) -> bool {
    ARG_REF.is_match(s)
}

fn name_error(name: &str) -> Option<String> {
    let invalid = || Some(format!("invalid capability name {name:?}"));
    let Some((ns, base)) = name.split_once('/') else {
        return if NAME.is_match(name) { None } else { invalid() };
    };
    if ns.is_empty() || !NAMESPACE.is_match(ns) || !NAME.is_match(base) {
        return invalid();
    }
    if ns.len() > MAX_NAMESPACE {
        return Some(format!(
            "namespace in {base:?} is {} characters, and no domain is longer than {MAX_NAMESPACE}",
            ns.len()
        ));
    }
    let labels: Vec<&str> = ns.split('.').collect();
    if let Some(l) = labels.iter().find(|l| !LABEL.is_match(l)) {
        return Some(format!(
            "namespace {ns:?} in {name:?} is not reverse-DNS: {l:?} is not a label a domain can \
             carry"
        ));
    }
    if labels.len() < 2 && !RESERVED.contains(&ns) {
        return Some(format!(
            "namespace {ns:?} in {name:?} is a single label, which this specification reserves; \
             a namespace of your own is reverse-DNS, as in com.example/{base}"
        ));
    }
    None
}

fn parse_version(v: &str) -> Result<String, String> {
    let v = v.trim();
    if VERSION.is_match(v) {
        Ok(v.to_string())
    } else {
        Err(format!("invalid version {v:?}"))
    }
}

/// A version-shaped string (no `v` prefix).
pub fn is_version(v: &str) -> bool {
    parse_version(v).is_ok()
}

/// `name` or `name@version`.
pub fn parse_provide(s: &str) -> Result<Provide, String> {
    let wrap = |e: String| format!("provides entry {s:?}: {e}");
    let t = s.trim();
    let (name, version) = match t.split_once('@') {
        Some((n, v)) => (n, Some(v)),
        None => (t, None),
    };
    if let Some(e) = name_error(name) {
        return Err(wrap(e));
    }
    let version = version.map(parse_version).transpose().map_err(wrap)?;
    Ok(Provide {
        name: normalize(name),
        version,
    })
}

/// `name`, or `name <op> version` with further `, <op> version` constraints.
pub fn parse_require(s: &str) -> Result<Require, String> {
    let t = s.trim();
    let wrap = |e: String| format!("requires entry {t:?}: {e}");
    let (name, rest) = match t.find(['>', '<', '=']) {
        Some(i) => (t[..i].trim(), t[i..].trim()),
        None => (t, ""),
    };
    if name.is_empty() && !rest.is_empty() {
        return Err(wrap("missing capability name".into()));
    }
    if let Some(e) = name_error(name) {
        return Err(wrap(e));
    }
    let constraints = if rest.is_empty() {
        vec![]
    } else {
        parse_constraints(rest).map_err(wrap)?
    };
    Ok(Require {
        name: normalize(name),
        constraints,
    })
}

fn cut_op(s: &str) -> Result<(Op, &str), String> {
    let s = s.trim();
    let ops = [
        (">=", Op::Ge),
        ("<=", Op::Le),
        (">", Op::Gt),
        ("<", Op::Lt),
        ("=", Op::Eq),
    ];
    ops.iter()
        .find_map(|(p, op)| s.strip_prefix(p).map(|r| (*op, r.trim())))
        .ok_or_else(|| format!("expected version operator, got {s:?}"))
}

fn parse_constraints(mut s: &str) -> Result<Vec<Constraint>, String> {
    let mut out = Vec::new();
    while !s.is_empty() {
        let (op, after) = cut_op(s)?;
        let (version, next) = match after.split_once(',') {
            Some((v, n)) => (v.trim(), Some(n.trim())),
            None => (after.trim(), None),
        };
        if version.is_empty() {
            return Err(format!("constraint \"{op}\": missing version"));
        }
        let version = parse_version(version).map_err(|e| format!("constraint \"{op}\": {e}"))?;
        out.push(Constraint { op, version });
        match next {
            None => break,
            Some("") => return Err("trailing comma in constraints".into()),
            Some(n) => s = n,
        }
    }
    if out.is_empty() {
        return Err("empty constraints".into());
    }
    check_satisfiable(&out)?;
    Ok(out)
}

/// Refuses conflicting pins and inverted or exclusively touching bounds.
fn check_satisfiable(cs: &[Constraint]) -> Result<(), String> {
    let mut pin: Option<&str> = None;
    for c in cs.iter().filter(|c| c.op == Op::Eq) {
        if let Some(p) = pin
            && compare(p, &c.version) != Ordering::Equal
        {
            return Err(format!(
                "unsatisfiable constraints: = {p} and = {}",
                c.version
            ));
        }
        pin = Some(&c.version);
    }
    if let Some(p) = pin {
        if let Some(c) = cs.iter().find(|c| !holds(p, c)) {
            return Err(format!(
                "unsatisfiable constraints: = {p} conflicts with {} {}",
                c.op, c.version
            ));
        }
        return Ok(());
    }
    let (mut lo, mut lo_exc) = ("0".to_string(), false);
    let mut hi: Option<(String, bool)> = None;
    for c in cs {
        match c.op {
            Op::Ge | Op::Gt => {
                let exc = c.op == Op::Gt;
                let cmp = compare(&c.version, &lo);
                if cmp == Ordering::Greater || (cmp == Ordering::Equal && exc && !lo_exc) {
                    (lo, lo_exc) = (c.version.clone(), exc);
                }
            }
            Op::Le | Op::Lt => {
                let exc = c.op == Op::Lt;
                let replace = hi.as_ref().is_none_or(|(v, e)| {
                    let cmp = compare(&c.version, v);
                    cmp == Ordering::Less || (cmp == Ordering::Equal && exc && !e)
                });
                if replace {
                    hi = Some((c.version.clone(), exc));
                }
            }
            Op::Eq => {}
        }
    }
    let Some((hi, hi_exc)) = hi else {
        return Ok(());
    };
    let effective = if lo_exc {
        format!("{lo}{SUCCESSOR}")
    } else {
        lo.clone()
    };
    let cmp = compare(&effective, &hi);
    if cmp == Ordering::Greater || (cmp == Ordering::Equal && hi_exc) {
        let lo_op = if lo_exc { Op::Gt } else { Op::Ge };
        let hi_op = if hi_exc { Op::Lt } else { Op::Le };
        return Err(format!(
            "unsatisfiable constraints: {lo_op} {lo} and {hi_op} {hi}"
        ));
    }
    Ok(())
}

fn holds(version: &str, c: &Constraint) -> bool {
    let cmp = compare(version, &c.version);
    match c.op {
        Op::Ge => cmp != Ordering::Less,
        Op::Gt => cmp == Ordering::Greater,
        Op::Le => cmp != Ordering::Greater,
        Op::Lt => cmp == Ordering::Less,
        Op::Eq => cmp == Ordering::Equal,
    }
}

/// Per segment: numeric segments numerically, others (and a missing one, as empty) by bytes.
pub fn compare(a: &str, b: &str) -> Ordering {
    let split = |v: &str| -> Vec<String> {
        let v = v.trim();
        if v.is_empty() {
            vec![]
        } else {
            v.split('.').map(String::from).collect()
        }
    };
    let (a, b) = (split(a), split(b));
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit());
    for i in 0..a.len().max(b.len()) {
        let x = a.get(i).map_or("", String::as_str);
        let y = b.get(i).map_or("", String::as_str);
        let cmp = if digits(x) && digits(y) {
            let (x, y) = (x.trim_start_matches('0'), y.trim_start_matches('0'));
            x.len().cmp(&y.len()).then_with(|| x.cmp(y))
        } else {
            x.cmp(y)
        };
        if cmp != Ordering::Equal {
            return cmp;
        }
    }
    Ordering::Equal
}

/// Names match and the provided version holds every constraint; an unversioned provide meets
/// only an unconstrained require.
pub fn satisfies(p: &Provide, r: &Require) -> bool {
    if p.name != r.name {
        return false;
    }
    if r.constraints.is_empty() {
        return true;
    }
    p.version
        .as_deref()
        .is_some_and(|v| r.constraints.iter().all(|c| holds(v, c)))
}

/// The version a consumption reference carries: a version-shaped tag (a leading `v` stripped),
/// or a `git+…#ref=` that is one. Local paths, digests and other tags carry none.
pub fn version_from_reference(reference: &str) -> Option<String> {
    let tag = if reference.starts_with("git+") {
        let (_, fragment) = reference.split_once('#')?;
        fragment
            .split('&')
            .find_map(|kv| kv.strip_prefix("ref="))?
            .to_string()
    } else {
        let r = reference.split('@').next().unwrap_or_default();
        let colon = r.rfind(':')?;
        if r.rfind('/').is_some_and(|slash| colon <= slash) {
            return None;
        }
        r[colon + 1..].to_string()
    };
    let v = tag.strip_prefix('v').unwrap_or(&tag);
    is_version(v).then(|| v.to_string())
}

/// A provides entry meeting `r`: what a stand-in for the rest of the set offers when a mixin is
/// checked on its own. `r`'s constraints are satisfiable (parsing refuses others), so one of
/// `0`, a bound, or the version just above a bound holds them all.
pub fn witness(r: &Require) -> String {
    let name = display(&r.name);
    if r.constraints.is_empty() {
        return name.to_string();
    }
    std::iter::once("0".to_string())
        .chain(
            r.constraints
                .iter()
                .flat_map(|c| [c.version.clone(), format!("{}{SUCCESSOR}", c.version)]),
        )
        .find(|v| r.constraints.iter().all(|c| holds(v, c)))
        .map_or_else(|| name.to_string(), |v| format!("{name}@{v}"))
}

/// Checks a v3 descriptor's entries like the spec's validator (`validateCapabilityNames`), one
/// `field[i]: …` line per problem. Arg references are allowed in `provides` only.
pub fn validate(
    provides: &[String],
    requires: &[String],
    integrates: &[String],
    conflicts: &[String],
) -> Vec<String> {
    let mut errs = Vec::new();
    for (i, s) in provides.iter().enumerate() {
        if !has_arg_ref(s)
            && let Err(e) = parse_provide(s)
        {
            errs.push(format!("provides[{i}]: {e}"));
        }
    }
    for (field, list) in [("requires", requires), ("integrates", integrates)] {
        for (i, s) in list.iter().enumerate() {
            if has_arg_ref(s) {
                errs.push(format!(
                    "{field}[{i}]: {field} entry {s:?}: arg references are not allowed in {field}"
                ));
            } else if let Err(e) = parse_require(s) {
                // The spec's parser says `requires entry` for an integrates entry too.
                errs.push(format!("{field}[{i}]: {e}"));
            }
        }
    }
    for (i, s) in conflicts.iter().enumerate() {
        if has_arg_ref(s) {
            errs.push(format!(
                "conflicts[{i}]: conflicts entry {s:?}: arg references are not allowed in conflicts"
            ));
        } else if let Some(e) = name_error(s) {
            errs.push(format!("conflicts[{i}]: conflicts entry {s:?}: {e}"));
        }
    }
    errs
}

/// The spec frontend's refusal of an unversioned `provides` entry.
pub fn unversioned(i: usize, s: &str) -> String {
    format!(
        "provides[{i}]: provides entry {s:?} has no version: add @<version> here or a top-level \
         version: field (a version-shaped image tag can override it at consumption, but a \
         published kit must carry one)"
    )
}

/// One offer in a resolver message: `name@version (from kit)`.
pub fn describe(p: &Provide, kit: &str) -> String {
    match &p.version {
        Some(v) => format!("{}@{v} (from {kit})", display(&p.name)),
        None => format!("{} (unversioned, from {kit})", display(&p.name)),
    }
}

pub fn unmet(kit: &str, entry: &str, name: &str) -> String {
    format!(
        "{kit} requires {entry:?} but nothing in the set provides it; add a kit that provides \
         {name}"
    )
}

pub fn unmet_version(kit: &str, entry: &str, offered: &[String]) -> String {
    format!(
        "{kit} requires {entry:?} but the set only offers {}",
        offered.join(", ")
    )
}

/// `offers` are `(kit, version)`.
pub fn duplicate(name: &str, offers: &[(&str, Option<&str>)]) -> String {
    let offers: Vec<String> = offers
        .iter()
        .map(|(k, v)| format!("{k} ({})", v.unwrap_or("unversioned")))
        .collect();
    format!(
        "capability {name:?} is provided by more than one kit: {}; one name has one owner, so \
         drop the redundant kit",
        offers.join(", ")
    )
}

pub fn integrates_violated(kit: &str, entry: &str, offered: &[String]) -> String {
    format!(
        "{kit} integrates with {entry:?} but the set only offers {}; upgrade the provider or drop \
         it from the set",
        offered.join(", ")
    )
}

pub fn conflict(kit: &str, entry: &str, provider: &str) -> String {
    format!("{kit} conflicts with {entry:?}, which {provider} provides; the two cannot compose")
}

/// sbx's resolver report: one `  - ` line per problem under its heading. Kits are named by
/// reference as typed (`Kit::label`).
pub fn incoherent(problems: &[String]) -> String {
    let mut out = String::from("resolve: the kit set is not coherent:");
    for p in problems {
        out.push_str("\n  - ");
        out.push_str(p);
    }
    out
}

pub const NO_WORKLOAD: &str =
    "no workload kit in the set; every composition needs exactly one kind: workload base";

pub fn cycle(kits: &[&str]) -> String {
    format!("resolve: dependency cycle among {}", kits.join(", "))
}

pub fn listed_twice(kit: &str) -> String {
    format!("kit {kit} is listed more than once")
}

/// Whether a `provides` entry names `name` (any version, either spelling).
pub fn provides_name(entry: &str, name: &str) -> bool {
    parse_provide(entry).is_ok_and(|p| p.name == normalize(name))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(s: &str) -> Require {
        parse_require(s).unwrap()
    }
    fn prov(s: &str) -> Provide {
        parse_provide(s).unwrap()
    }

    #[test]
    fn names_normalize_into_the_default_namespace() {
        assert_eq!(prov("gh@2.98.0").name, "com.docker.kit/gh");
        assert_eq!(prov("com.docker.kit/gh").name, "com.docker.kit/gh");
        assert_eq!(prov("com.example/gh").name, "com.example/gh");
        assert_eq!(display("com.docker.kit/gh"), "gh");
        assert_eq!(display("com.example/gh"), "com.example/gh");
        assert_eq!(prov("libstdc++6@1").name, "com.docker.kit/libstdc++6");
        assert_eq!(prov("deb/bash@5.2").name, "deb/bash");
    }

    #[test]
    fn bad_names_and_versions_are_refused_with_the_spec_texts() {
        let e = |s: &str| parse_provide(s).unwrap_err();
        assert_eq!(
            e("gh-"),
            "provides entry \"gh-\": invalid capability name \"gh-\""
        );
        assert_eq!(e("gh@"), "provides entry \"gh@\": invalid version \"\"");
        assert_eq!(
            e("gh@1..2"),
            "provides entry \"gh@1..2\": invalid version \"1..2\""
        );
        assert_eq!(
            e("com..example/gh@1"),
            "provides entry \"com..example/gh@1\": namespace \"com..example\" in \
             \"com..example/gh\" is not reverse-DNS: \"\" is not a label a domain can carry"
        );
        let r = |s: &str| parse_require(s).unwrap_err();
        assert_eq!(
            r(">= 1"),
            "requires entry \">= 1\": missing capability name"
        );
        assert_eq!(
            r("x >="),
            "requires entry \"x >=\": constraint \">=\": missing version"
        );
        assert_eq!(
            r("x >= 1,"),
            "requires entry \"x >= 1,\": trailing comma in constraints"
        );
        assert_eq!(
            r("x >= 1, ~2"),
            "requires entry \"x >= 1, ~2\": expected version operator, got \"~2\""
        );
        assert_eq!(
            r("x = 1, = 2"),
            "requires entry \"x = 1, = 2\": unsatisfiable constraints: = 1 and = 2"
        );
        assert_eq!(
            r("x = 1, > 1"),
            "requires entry \"x = 1, > 1\": unsatisfiable constraints: = 1 conflicts with > 1"
        );
        assert_eq!(
            r("x > 1, <= 1"),
            "requires entry \"x > 1, <= 1\": unsatisfiable constraints: > 1 and <= 1"
        );
        assert_eq!(
            r("x < 0"),
            "requires entry \"x < 0\": unsatisfiable constraints: >= 0 and < 0"
        );
        assert!(parse_require("x >= 1, <= 1").is_ok());
        assert_eq!(
            req("node >= 20.0.0, < 21.0.0").constraints,
            [
                Constraint {
                    op: Op::Ge,
                    version: "20.0.0".into()
                },
                Constraint {
                    op: Op::Lt,
                    version: "21.0.0".into()
                },
            ]
        );
    }

    #[test]
    fn versions_compare_per_segment() {
        use Ordering::*;
        assert_eq!(compare("1.10", "1.9"), Greater);
        assert_eq!(compare("01.2", "1.2"), Equal);
        assert_eq!(compare("1.0", "1.0.0"), Less);
        assert_eq!(compare("1.0.rc1", "1.0.rc2"), Less);
        assert_eq!(compare("1.0.-", "1.0.0"), Less);
        assert_eq!(compare("2", "10"), Less);
    }

    #[test]
    fn satisfies_holds_every_constraint() {
        let r = req("node >= 20, < 21");
        assert!(satisfies(&prov("node@20.11.1"), &r));
        assert!(!satisfies(&prov("node@21"), &r));
        assert!(!satisfies(&prov("node"), &r));
        assert!(satisfies(&prov("node"), &req("node")));
        assert!(!satisfies(&prov("com.example/node@20"), &r));
        assert!(satisfies(
            &prov("node@20"),
            &req("com.docker.kit/node = 20")
        ));
    }

    #[test]
    fn references_carry_versions_from_tags_and_git_refs() {
        let v = |s: &str| version_from_reference(s);
        assert_eq!(v("reg.io/kits/hello:1.0.3").as_deref(), Some("1.0.3"));
        assert_eq!(v("docker.io/acme/k:v2@sha256:00").as_deref(), Some("2"));
        assert_eq!(v("acme/k:latest"), None);
        assert_eq!(v("localhost:5000/k"), None);
        assert_eq!(v("./kit"), None);
        assert_eq!(
            v("git+https://github.com/o/r.git#ref=v2.1.0&dir=k").as_deref(),
            Some("2.1.0")
        );
        assert_eq!(v("git+https://github.com/o/r.git#ref=main"), None);
    }

    #[test]
    fn a_witness_meets_its_require() {
        for s in [
            "x",
            "x >= 1.2",
            "x > 1.2",
            "x < 3",
            "x = 4.1",
            "x > 1, < 1.0.1",
            "com.example/x >= 2",
        ] {
            let r = req(s);
            assert!(satisfies(&prov(&witness(&r)), &r), "{s}: {}", witness(&r));
        }
        assert_eq!(witness(&req("x")), "x");
        assert_eq!(witness(&req("x >= 1.2")), "x@1.2");
    }

    #[test]
    fn provides_name_ignores_version_and_spelling() {
        assert!(provides_name("docker@1.0.0", "docker"));
        assert!(provides_name("com.docker.kit/docker", "docker"));
        assert!(!provides_name("com.example/docker@1", "docker"));
    }
}
