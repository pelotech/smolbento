//! A request-rule language: which HTTP requests to a host are allowed, by method, path and query.
//!
//! Rules add up and order never matters: a deny that matches wins over any allow. The guest is taken to be
//! adversarial, so where a request can be read more than one way (method override headers, a path with
//! or without `;params`, repeated or `;`-separated query parameters), a deny fires if any reading matches, and an allow needs every reading
//! to match. A target is judged by a canonical view and never rewritten.

mod path;

use http::HeaderMap;
pub use path::PathGlob;
use path::View;

/// A set of request rules, and what happens to a request on a host none of them names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    pub rules: Vec<Rule>,
    pub default: Action,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Allow,
    Deny,
}

/// One rule over the HTTP requests it matches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    /// Named in a refusal.
    pub id: Option<String>,
    pub action: Action,
    pub host: HostMatch,
    /// `None` matches every port.
    pub port: Option<u16>,
    pub request: RequestMatch,
    /// How paths and query names and values compare. Methods always compare ASCII-case-insensitively.
    pub case: Case,
}

/// Hosts compare ASCII-case-insensitively, with one trailing dot ignored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostMatch {
    Exact(String),
    /// Subdomains of `domain`, never `domain` itself: one label deep, or any depth.
    Subdomains {
        domain: String,
        any_depth: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestMatch {
    pub methods: Methods,
    /// Non-empty; any one matches. Every path is `/**`.
    pub paths: Vec<PathGlob>,
    /// All must match; empty matches any query.
    pub query: Vec<QueryMatch>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Methods {
    Any,
    /// Non-empty uppercase tokens.
    Only(Vec<String>),
}

/// A query parameter by its (decoded) name, and what its value must be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryMatch {
    pub name: String,
    pub value: ValueMatch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValueMatch {
    /// Present, with any value or none.
    Any,
    Exact(String),
    Prefix(String),
    Suffix(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Case {
    Insensitive,
    Sensitive,
}

/// Whether request rules apply to a connection, and what to do with it if its requests can't be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Inspection {
    None,
    Inspect { uninspectable: Action },
}

/// Why a request is refused: a deny rule's id, or a generic miss. Nothing else of the policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub reason: String,
}

/// Headers whose values are read as the request's method too.
const METHOD_OVERRIDES: [&str; 3] = [
    "x-http-method-override",
    "x-http-method",
    "x-method-override",
];

impl Policy {
    /// Refuses a policy with a rule that could never match.
    pub fn validate(&self) -> Result<(), String> {
        for (i, r) in self.rules.iter().enumerate() {
            let at = |why: &str| {
                Err(format!(
                    "rule {}: {why}",
                    r.id.as_deref().map_or(i.to_string(), str::to_owned)
                ))
            };
            if let HostMatch::Exact(n) | HostMatch::Subdomains { domain: n, .. } = &r.host
                && (n.is_empty() || n.contains('*'))
            {
                return at("a host is empty or holds *");
            }
            if r.request.paths.is_empty() {
                return at("it names no path");
            }
            if let Methods::Only(ms) = &r.request.methods
                && (ms.is_empty()
                    || ms.iter().any(|m| {
                        m.is_empty()
                            || !m
                                .bytes()
                                .all(|b| b.is_ascii_graphic() && !b.is_ascii_lowercase())
                    }))
            {
                return at("methods must be non-empty uppercase tokens");
            }
            if r.request.query.iter().any(|q| q.name.is_empty()) {
                return at("a query parameter has no name");
            }
        }
        Ok(())
    }

    /// Whether request rules apply to a connection to `host:port`. A host with an allow refuses what it
    /// can't inspect (an allow refuses everything it doesn't match); one with only denies passes it.
    pub fn inspection(&self, host: &str, port: u16) -> Inspection {
        let host = normal(host);
        let mut named = false;
        for r in self.rules.iter().filter(|r| r.applies(&host, port)) {
            if r.action == Action::Allow {
                return Inspection::Inspect {
                    uninspectable: Action::Deny,
                };
            }
            named = true;
        }
        if named {
            Inspection::Inspect {
                uninspectable: Action::Allow,
            }
        } else {
            Inspection::None
        }
    }

    /// Judges a request on `host:port`. `target` is its path and query as sent.
    pub fn request(
        &self,
        host: &str,
        port: u16,
        method: &str,
        target: &str,
        headers: &HeaderMap,
    ) -> Result<(), Refusal> {
        let host = normal(host);
        let ruled: Vec<&Rule> = self
            .rules
            .iter()
            .filter(|r| r.applies(&host, port))
            .collect();
        // A host no rule names isn't judged, so its encoded slashes (say, GitLab project paths) still pass.
        if ruled.is_empty() && self.default == Action::Allow {
            return Ok(());
        }
        let view = View::parse(target).ok_or_else(|| Refusal {
            reason: "ambiguous request target".into(),
        })?;
        let methods = method_views(method, headers);
        if let Some(r) = ruled
            .iter()
            .find(|r| r.action == Action::Deny && r.matches(&methods, &view, false))
        {
            return Err(r.refusal());
        }
        let mut allows = ruled
            .iter()
            .filter(|r| r.action == Action::Allow)
            .peekable();
        let unbounded = allows.peek().is_none() && self.default == Action::Allow;
        if unbounded || allows.any(|r| r.matches(&methods, &view, true)) {
            return Ok(());
        }
        Err(Refusal {
            reason: format!("no rule allows {method} {} on {host}", view.path()),
        })
    }

    /// The hosts an interceptor must terminate for these rules, in its `terminate_hosts` form, sorted.
    ///
    /// The interceptor matches `*.d` like a credential host pattern (`smolvm_protocol::credentials::
    /// host_matches`): any subdomain of `d` at any depth, never `d` itself. So both `Subdomains` forms map
    /// to `*.d`, and no apex is listed, since neither form matches it. A one-label rule terminates deeper
    /// hosts too; their requests fall to the default, as no rule names them.
    pub fn terminate_hosts(&self) -> Vec<String> {
        let mut hosts: Vec<String> = (self.rules.iter().map(|r| &r.host))
            .map(|h| match h {
                HostMatch::Exact(n) => normal(n),
                HostMatch::Subdomains { domain, .. } => format!("*.{}", normal(domain)),
            })
            .collect();
        hosts.sort();
        hosts.dedup();
        hosts
    }
}

impl Rule {
    fn applies(&self, host: &str, port: u16) -> bool {
        self.port.is_none_or(|p| p == port) && self.host.matches(host)
    }

    /// Whether the request matches: on any reading (`every: false`, for a deny) or on every reading.
    fn matches(&self, methods: &[String], view: &View, every: bool) -> bool {
        let ci = self.case == Case::Insensitive;
        let m = &self.request;
        let method_ok = match &m.methods {
            Methods::Any => true,
            Methods::Only(ms) => {
                let hit = |v: &String| ms.iter().any(|m| m.eq_ignore_ascii_case(v));
                if every {
                    methods.iter().all(hit)
                } else {
                    methods.iter().any(hit)
                }
            }
        };
        let query_ok =
            |params: &Vec<(Vec<u8>, Vec<u8>)>| m.query.iter().all(|q| q.matches(params, ci, every));
        method_ok
            && {
                let path_ok = |segs: &Vec<String>| m.paths.iter().any(|g| g.matches(segs, ci));
                if every {
                    view.paths.iter().all(path_ok)
                } else {
                    view.paths.iter().any(path_ok)
                }
            }
            && if every {
                view.readings.iter().all(query_ok)
            } else {
                view.readings.iter().any(query_ok)
            }
    }

    fn refusal(&self) -> Refusal {
        let reason = match &self.id {
            Some(id) => format!("request denied by policy (rule {id})"),
            None => "request denied by policy".into(),
        };
        Refusal { reason }
    }
}

impl HostMatch {
    /// `host` is already [`normal`].
    fn matches(&self, host: &str) -> bool {
        match self {
            HostMatch::Exact(n) => normal(n) == host,
            HostMatch::Subdomains { domain, any_depth } => host
                .strip_suffix(&normal(domain))
                .and_then(|sub| sub.strip_suffix('.'))
                .is_some_and(|sub| !sub.is_empty() && (*any_depth || !sub.contains('.'))),
        }
    }
}

impl QueryMatch {
    /// Any value of the parameter matching (`every: false`), or every value, and at least one.
    fn matches(&self, params: &[(Vec<u8>, Vec<u8>)], ci: bool, every: bool) -> bool {
        let same = |a: &[u8], b: &[u8]| {
            a.len() == b.len() && a.iter().zip(b).all(|(x, y)| path::eq(*x, *y, ci))
        };
        let mut values = params
            .iter()
            .filter(|(k, _)| same(k, self.name.as_bytes()))
            .map(|(_, v)| v.as_slice())
            .peekable();
        let ok = |v: &[u8]| match &self.value {
            ValueMatch::Any => true,
            ValueMatch::Exact(x) => same(v, x.as_bytes()),
            ValueMatch::Prefix(x) => v.len() >= x.len() && same(&v[..x.len()], x.as_bytes()),
            ValueMatch::Suffix(x) => {
                v.len() >= x.len() && same(&v[v.len() - x.len()..], x.as_bytes())
            }
        };
        if every {
            values.peek().is_some() && values.all(ok)
        } else {
            values.any(ok)
        }
    }
}

/// Lowercase, without one trailing dot.
fn normal(host: &str) -> String {
    host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase()
}

/// The method, and each comma-separated value of a method override header.
fn method_views(method: &str, headers: &HeaderMap) -> Vec<String> {
    let mut views = vec![method.to_owned()];
    for name in METHOD_OVERRIDES {
        for v in headers.get_all(name) {
            let v = String::from_utf8_lossy(v.as_bytes());
            views.extend(
                v.split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned),
            );
        }
    }
    views
}

#[cfg(test)]
mod tests;
