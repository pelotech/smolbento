//! sbx network rule resources: parsing, sbx-style matching, and translation to smolvm's allow
//! list (which is coarser: see `note`).

use std::net::IpAddr;

use anyhow::{Result, anyhow, bail};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pattern {
    /// `**`: everything.
    Everything,
    /// `api.example.com`
    Exact(String),
    /// `**.example.com`: subdomains at any depth.
    Subdomains(String),
    /// `*.example.com`: exactly one more label.
    OneLabel(String),
    /// Other wildcards (`crl*.digicert.com`, `?`, `[..]`). `parent` is the fixed part after the
    /// first dot.
    Glob { pattern: String, parent: String },
    /// An address or CIDR range.
    Cidr { addr: IpAddr, prefix: u8 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resource {
    pub raw: String,
    pub pattern: Pattern,
    pub port: Option<u16>,
}

/// What a resource becomes in smolvm's allow list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Allow {
    Everything,
    /// A `--allow-host-pattern`: an exact host or `*.domain` (any depth, not the apex).
    Pattern(String),
    Cidr(String),
}

/// Parses sbx's comma-separated resource list.
pub fn parse_list(list: &str) -> Result<Vec<Resource>> {
    let items: Vec<&str> = list
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    if items.is_empty() {
        bail!("no resources given");
    }
    items.into_iter().map(Resource::parse).collect()
}

fn has_glob(s: &str) -> bool {
    s.contains(['*', '?', '['])
}

impl Resource {
    pub fn parse(raw: &str) -> Result<Resource> {
        let raw = raw.trim();
        if raw == "*" {
            bail!("a bare `*` isn't a valid rule; use `**` to allow everything");
        }
        if raw == "**" {
            return Ok(Resource {
                raw: raw.into(),
                pattern: Pattern::Everything,
                port: None,
            });
        }
        let (host, port) = split_port(raw)?;
        let host = host.to_ascii_lowercase();
        if host.is_empty() {
            bail!("empty host in '{raw}'");
        }
        let pattern = if let Some((addr, prefix)) = parse_cidr(&host)? {
            Pattern::Cidr { addr, prefix }
        } else if let Some(rest) = host.strip_prefix("**.")
            && !has_glob(rest)
        {
            check_host(rest, raw)?;
            Pattern::Subdomains(rest.into())
        } else if let Some(rest) = host.strip_prefix("*.")
            && !has_glob(rest)
        {
            check_host(rest, raw)?;
            Pattern::OneLabel(rest.into())
        } else if has_glob(&host) {
            match host.split_once('.') {
                Some((label, parent)) if !parent.is_empty() && !has_glob(parent) => {
                    check_host(parent, raw)?;
                    if !label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-*?[]!".contains(&b))
                    {
                        bail!(
                            "invalid host in '{raw}': a wildcard label takes letters, digits, '-' \
                             and the wildcards * ? [..]"
                        );
                    }
                    check_classes(label, raw)?;
                    Pattern::Glob {
                        pattern: host.clone(),
                        parent: parent.into(),
                    }
                }
                _ => bail!(
                    "can't use '{raw}': a wildcard must be followed by a fixed domain, like `crl*.digicert.com`"
                ),
            }
        } else {
            check_host(&host, raw)?;
            Pattern::Exact(host)
        };
        Ok(Resource {
            raw: raw.into(),
            pattern,
            port,
        })
    }

    /// sbx semantics, used by `policy check`, approvals and deny subtraction. A rule without a
    /// port matches every port. A rule with a port matches only that port; a target without one
    /// is an HTTPS request (`policy check network api.x.com`), so it counts as port 443.
    pub fn matches(&self, target: &str) -> bool {
        let target = target.trim().to_ascii_lowercase();
        let (host, port) = split_port(&target).unwrap_or((target.as_str(), None));
        if self.port.is_some_and(|p| p != port.unwrap_or(443)) {
            return false;
        }
        match &self.pattern {
            Pattern::Everything => true,
            Pattern::Exact(h) => host == h,
            Pattern::Subdomains(d) => host
                .strip_suffix(d.as_str())
                .is_some_and(|p| p.len() > 1 && p.ends_with('.')),
            Pattern::OneLabel(d) => host
                .strip_suffix(d.as_str())
                .and_then(|p| p.strip_suffix('.'))
                .is_some_and(|label| !label.is_empty() && !label.contains('.')),
            Pattern::Glob { pattern, .. } => glob(pattern.as_bytes(), host.as_bytes()),
            Pattern::Cidr { addr, prefix } => host
                .parse::<IpAddr>()
                .is_ok_and(|ip| in_cidr(ip, *addr, *prefix)),
        }
    }

    /// Never `--allow-host`: smolvm resolves those names at create and fails when one has no
    /// address record (blob.core.windows.net), while patterns resolve at start, warning only.
    pub fn to_allow(&self) -> Allow {
        match &self.pattern {
            Pattern::Everything => Allow::Everything,
            Pattern::Exact(h) => Allow::Pattern(h.clone()),
            Pattern::Subdomains(d) => Allow::Pattern(format!("*.{d}")),
            Pattern::OneLabel(d) => Allow::Pattern(format!("*.{d}")),
            Pattern::Glob { parent, .. } => Allow::Pattern(format!("*.{parent}")),
            Pattern::Cidr { addr, prefix } => Allow::Cidr(format!("{addr}/{prefix}")),
        }
    }

    /// The resource as written, without its port (`[::1]:22` -> `::1`).
    pub fn without_port(&self) -> String {
        split_port(&self.raw).map_or_else(|_| self.raw.clone(), |(h, _)| h.to_string())
    }

    /// How smolvm enforces this more loosely than sbx would, if it does. smolvm can't limit a
    /// host to some ports: an allow opens every port, and a deny with a port isn't applied (denying
    /// the whole host would block the ports it leaves open), except that it cancels an allow with
    /// exactly the same text.
    pub fn note(&self, deny: bool) -> Option<String> {
        let mut notes = Vec::new();
        match self.port {
            Some(p) if deny => {
                return Some(format!(
                    "port {p} not enforced (deny not applied, except that it cancels an allow \
                     of exactly {})",
                    self.raw
                ));
            }
            Some(p) => notes.push(format!("port {p} not enforced (all ports allowed)")),
            None => {}
        }
        if let Pattern::Glob { parent, .. } = &self.pattern {
            notes.push(format!("widened to *.{parent}"));
        }
        (!notes.is_empty()).then(|| notes.join("; "))
    }
}

/// Every `[` in a wildcard label opens a non-empty class closed by `]`.
fn check_classes(label: &str, raw: &str) -> Result<()> {
    let mut rest = label;
    while let Some(i) = rest.find('[') {
        let Some(len) = rest[i + 1..].find(']') else {
            bail!("missing ']' in '{raw}': a `[` starts a character class like `[ab]`");
        };
        let class = &rest[i + 1..i + 1 + len];
        if class.is_empty() || class == "!" {
            bail!("empty character class in '{raw}'");
        }
        rest = &rest[i + 2 + len..];
    }
    Ok(())
}

/// The hostname rules smolvm's `--allow-host-pattern` enforces (`encode_strict` in
/// smolvm-protocol's host_pattern.rs): one optional trailing dot, at most 253 characters, labels of
/// 1 to 63 ASCII letters, digits and '-', with no '-' at either end of a label.
pub(crate) fn check_host(host: &str, raw: &str) -> Result<()> {
    let host = host.strip_suffix('.').unwrap_or(host);
    let valid = !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        });
    if !valid {
        bail!(
            "invalid host in '{raw}': use dot-separated labels of letters, digits and '-' \
             (1-63 characters each, not starting or ending with '-'; 253 in all)"
        );
    }
    Ok(())
}

pub(crate) fn split_port(s: &str) -> Result<(&str, Option<u16>)> {
    // `[::1]:443` is a bracketed IPv6 address; `[ab]pi.x.com` is a glob class, not a bracket.
    if let Some(rest) = s.strip_prefix('[')
        && rest.split(']').next().is_some_and(|a| a.contains(':'))
    {
        let (addr, after) = rest
            .split_once(']')
            .ok_or_else(|| anyhow!("missing ']' in '{s}'"))?;
        return match after.strip_prefix(':') {
            Some(p) => Ok((addr, Some(parse_port(p, s)?))),
            None if after.is_empty() => Ok((addr, None)),
            None => bail!("unexpected '{after}' after ']' in '{s}'"),
        };
    }
    match s.rsplit_once(':') {
        // Several colons without brackets: a bare IPv6 address or range.
        Some((h, p)) if !h.contains(':') => Ok((h, Some(parse_port(p, s)?))),
        _ => Ok((s, None)),
    }
}

fn parse_port(p: &str, s: &str) -> Result<u16> {
    p.parse::<u16>()
        .ok()
        .filter(|p| *p > 0)
        .ok_or_else(|| anyhow!("invalid port in '{s}'"))
}

fn parse_cidr(s: &str) -> Result<Option<(IpAddr, u8)>> {
    let (addr, prefix) = match s.split_once('/') {
        Some((a, p)) => (a, Some(p)),
        None => (s, None),
    };
    let Ok(addr) = addr.parse::<IpAddr>() else {
        return if prefix.is_some() {
            Err(anyhow!("invalid CIDR '{s}'"))
        } else {
            Ok(None)
        };
    };
    let max = if addr.is_ipv4() { 32 } else { 128 };
    let prefix = match prefix {
        Some(p) => p
            .parse::<u8>()
            .ok()
            .filter(|p| *p <= max)
            .ok_or_else(|| anyhow!("invalid prefix in '{s}'"))?,
        None => max,
    };
    Ok(Some((addr, prefix)))
}

fn in_cidr(ip: IpAddr, net: IpAddr, prefix: u8) -> bool {
    match (ip, net) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            u32::from(a) & mask == u32::from(b) & mask
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            u128::from(a) & mask == u128::from(b) & mask
        }
        _ => false,
    }
}

/// `*` and `?` stay within one label (they never match '.'); `[abc]`, `[!abc]` and `[a-z]` classes.
fn glob(p: &[u8], s: &[u8]) -> bool {
    match p.first() {
        None => s.is_empty(),
        Some(b'*') => (0..=s.len())
            .take_while(|&i| i == 0 || s[i - 1] != b'.')
            .any(|i| glob(&p[1..], &s[i..])),
        Some(b'?') => s.first().is_some_and(|&c| c != b'.') && glob(&p[1..], &s[1..]),
        Some(b'[') => {
            let Some(end) = p.iter().position(|&c| c == b']') else {
                return false;
            };
            let (class, rest) = (&p[1..end], &p[end + 1..]);
            let (negate, class) = match class.first() {
                Some(b'!') => (true, &class[1..]),
                _ => (false, class),
            };
            let Some(&c) = s.first() else {
                return false;
            };
            c != b'.' && class_matches(class, c) != negate && glob(rest, &s[1..])
        }
        Some(&c) => s.first() == Some(&c) && glob(&p[1..], &s[1..]),
    }
}

fn class_matches(class: &[u8], c: u8) -> bool {
    let mut i = 0;
    while i < class.len() {
        if i + 2 < class.len() && class[i + 1] == b'-' {
            if (class[i]..=class[i + 2]).contains(&c) {
                return true;
            }
            i += 3;
        } else {
            if class[i] == c {
                return true;
            }
            i += 1;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(s: &str) -> Resource {
        Resource::parse(s).unwrap()
    }

    #[test]
    fn parses_shapes() {
        assert_eq!(r("**").pattern, Pattern::Everything);
        assert_eq!(
            r("API.Example.com").pattern,
            Pattern::Exact("api.example.com".into())
        );
        assert_eq!(
            r("**.example.com").pattern,
            Pattern::Subdomains("example.com".into())
        );
        assert_eq!(
            r("*.example.com").pattern,
            Pattern::OneLabel("example.com".into())
        );
        assert_eq!(
            r("crl*.digicert.com:80").pattern,
            Pattern::Glob {
                pattern: "crl*.digicert.com".into(),
                parent: "digicert.com".into()
            }
        );
        assert_eq!(r("crl*.digicert.com:80").port, Some(80));
        assert_eq!(r("10.0.0.0/8").to_allow(), Allow::Cidr("10.0.0.0/8".into()));
        assert_eq!(
            r("192.168.1.5").to_allow(),
            Allow::Cidr("192.168.1.5/32".into())
        );
        assert_eq!(r("[::1]:443").to_allow(), Allow::Cidr("::1/128".into()));
        assert_eq!(r("fd00::/8").to_allow(), Allow::Cidr("fd00::/8".into()));
    }

    #[test]
    fn rejects_bad_input() {
        assert!(
            Resource::parse("*")
                .unwrap_err()
                .to_string()
                .contains("`**`")
        );
        assert!(Resource::parse("host:99999").is_err());
        assert!(Resource::parse("10.0.0.0/33").is_err());
        assert!(Resource::parse("abc*").is_err());
        assert!(parse_list(" , ").is_err());
        assert_eq!(parse_list("a.com, *.b.com").unwrap().len(), 2);
    }

    #[test]
    fn host_names_are_checked_the_way_smolvm_checks_them() {
        let long_label = "a".repeat(64);
        let longest = [
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61),
        ]
        .join(".");
        for good in [
            "api.x.com",
            "x-1.example.com",
            "localhost",
            "example.com.",
            "**.x.com",
            "*.x.com",
            "crl*.digicert.com",
            "[ab]pi.x-y.com",
            "ocsp?.globalsign.com",
            longest.as_str(),
        ] {
            assert!(Resource::parse(good).is_ok(), "{good}");
        }
        let too_long = format!("{longest}d");
        let label = format!("{long_label}.com");
        for bad in [
            "bad_host.com",
            "-a.com",
            "a-.com",
            "a..com",
            "**.x_y.com",
            "*.-x.com",
            "crl*.digi_cert.com",
            "cr_l*.digicert.com",
            "https://x.com",
            "x.com/path",
            too_long.as_str(),
            label.as_str(),
        ] {
            let err = Resource::parse(bad).unwrap_err().to_string();
            assert!(err.contains(bad), "{bad}: {err}");
        }
    }

    #[test]
    fn sbx_matching() {
        assert!(r("api.x.com").matches("API.x.com"));
        assert!(!r("api.x.com").matches("y.api.x.com"));
        assert!(r("**.x.com").matches("a.b.x.com"));
        assert!(!r("**.x.com").matches("x.com"));
        assert!(r("*.x.com").matches("a.x.com"));
        assert!(!r("*.x.com").matches("a.b.x.com"));
        assert!(r("crl*.digicert.com").matches("crl3.digicert.com"));
        assert!(!r("crl*.digicert.com").matches("ocsp.digicert.com"));
        assert!(r("ocsp?.globalsign.com").matches("ocsp2.globalsign.com"));
        assert!(r("[ab]pi.x.com").matches("bpi.x.com"));
        assert!(!r("[!ab]pi.x.com").matches("api.x.com"));
        assert!(r("10.0.0.0/8").matches("10.2.3.4"));
        assert!(!r("10.0.0.0/8").matches("11.0.0.1"));
        assert!(r("**").matches("anything.example"));
        assert!(r("api.x.com:443").matches("api.x.com:443"));
    }

    #[test]
    fn port_scoped_rules_match_only_their_port() {
        assert!(r("api.x.com:8080").matches("api.x.com:8080"));
        assert!(!r("api.x.com:8080").matches("api.x.com:9090"));
        assert!(
            !r("api.x.com:8080").matches("api.x.com"),
            "a portless target means port 443"
        );
        assert!(r("api.x.com:443").matches("api.x.com"));
        assert!(
            r("api.x.com").matches("api.x.com:8080"),
            "no port: any port"
        );
        assert!(r("10.0.0.0/8:22").matches("10.1.2.3:22"));
        assert!(!r("10.0.0.0/8:22").matches("10.1.2.3:80"));
        assert!(r("[::1]:443").matches("::1"));
        assert!(!r("[::1]:22").matches("[::1]:443"));
    }

    #[test]
    fn unterminated_brackets_are_rejected() {
        for bad in ["[ab.x.com", "a[b.x.com", "[!a.x.com", "[::1", "[::1:443"] {
            let err = Resource::parse(bad).unwrap_err().to_string();
            assert!(err.contains("missing ']'"), "{bad}: {err}");
        }
        assert!(Resource::parse("[]a.x.com").is_err());
        assert!(Resource::parse("[!]a.x.com").is_err());
        assert!(Resource::parse("[ab]c[0-9].x.com").is_ok());
    }

    #[test]
    fn translation_to_smolvm() {
        // Patterns, not `--allow-host`: smolvm resolves `--allow-host` names at create and fails on
        // one with no address record (blob.core.windows.net, statsig.anthropic.com).
        assert_eq!(
            r("api.x.com").to_allow(),
            Allow::Pattern("api.x.com".into())
        );
        assert_eq!(r("**.x.com").to_allow(), Allow::Pattern("*.x.com".into()));
        assert_eq!(r("*.x.com").to_allow(), Allow::Pattern("*.x.com".into()));
        assert_eq!(
            r("crl*.digicert.com").to_allow(),
            Allow::Pattern("*.digicert.com".into())
        );
        assert_eq!(r("**").to_allow(), Allow::Everything);
    }

    #[test]
    fn notes_for_looser_enforcement() {
        assert_eq!(r("a.com").note(false), None);
        assert!(
            r("a.com:8443")
                .note(false)
                .unwrap()
                .contains("all ports allowed")
        );
        assert_eq!(
            r("a.com:8443").note(true).unwrap(),
            "port 8443 not enforced (deny not applied, except that it cancels an allow of \
             exactly a.com:8443)"
        );
        assert!(
            r("crl*.digicert.com")
                .note(false)
                .unwrap()
                .contains("*.digicert.com")
        );
    }
}
