//! The canonical view a request target is judged by, and the path globs rules match it with.

/// A `/`-segment path glob. `*` matches a run of characters inside one segment (alone, it is one whole
/// segment); `**`, only as a whole segment, matches zero or more segments, so `/a/**` matches `/a`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathGlob(Vec<Seg>);

#[derive(Debug, Clone, PartialEq, Eq)]
enum Seg {
    Many,
    One(String),
}

impl PathGlob {
    /// Parses a glob, refusing any that a canonical path could never match: it must start with `/`, and
    /// may not hold `%`, `?`, `#`, `;`, `\`, a control character, an empty, `.` or `..` segment, or a
    /// `**` that isn't a whole segment.
    pub fn parse(s: &str) -> Result<PathGlob, String> {
        let bad = |why: &str| Err(format!("path {s:?} never matches: {why}"));
        let Some(rest) = s.strip_prefix('/') else {
            return bad("it doesn't start with /");
        };
        if s.chars().any(|c| "%?#;\\".contains(c) || c.is_control()) {
            return bad("it holds %, ?, #, ;, \\ or a control character");
        }
        if rest.is_empty() {
            return Ok(PathGlob(vec![]));
        }
        let mut segs = Vec::new();
        for seg in rest.split('/') {
            segs.push(match seg {
                "" | "." | ".." => return bad("empty, . and .. segments are merged or resolved"),
                "**" => Seg::Many,
                s if s.contains("**") => return bad("** must be a whole segment"),
                s => Seg::One(s.to_owned()),
            });
        }
        Ok(PathGlob(segs))
    }

    pub(super) fn matches(&self, path: &[String], ci: bool) -> bool {
        glob(
            &self.0,
            path,
            |g| *g == Seg::Many,
            |g, seg| match g {
                Seg::One(p) => glob(
                    p.as_bytes(),
                    seg.as_bytes(),
                    |b| *b == b'*',
                    |a, b| eq(*a, *b, ci),
                ),
                Seg::Many => false,
            },
        )
    }
}

pub(super) fn eq(a: u8, b: u8, ci: bool) -> bool {
    if ci {
        a.eq_ignore_ascii_case(&b)
    } else {
        a == b
    }
}

/// Wildcard match where a star element matches any run of items: greedy with one backtrack point, so
/// O(pattern × input) on a guest-chosen input.
fn glob<P, S>(
    pat: &[P],
    s: &[S],
    is_star: impl Fn(&P) -> bool,
    one: impl Fn(&P, &S) -> bool,
) -> bool {
    let (mut p, mut i, mut star) = (0, 0, None);
    while i < s.len() {
        if p < pat.len() && is_star(&pat[p]) {
            star = Some((p, i));
            p += 1;
        } else if p < pat.len() && one(&pat[p], &s[i]) {
            p += 1;
            i += 1;
        } else if let Some((sp, si)) = star {
            star = Some((sp, si + 1));
            p = sp + 1;
            i = si + 1;
        } else {
            return false;
        }
    }
    pat[p..].iter().all(is_star)
}

/// A request target as judged: canonical path segments, and the query read two ways (split on `&` and
/// `;`, and on `&` only). It never changes what is forwarded.
pub(super) struct View {
    pub segments: Vec<String>,
    pub readings: Vec<Vec<(Vec<u8>, Vec<u8>)>>,
}

impl View {
    /// `None` for an ambiguous target: one that isn't origin-form, or whose path holds an encoded `/` or
    /// `\`, a `%` that isn't one valid escape (double encoding, `%u`), invalid UTF-8 or a control character.
    pub fn parse(target: &str) -> Option<View> {
        let (path, query) = target.split_once('?').unwrap_or((target, ""));
        let path = path.strip_prefix('/')?;
        let raw = path.as_bytes();
        let mut bytes = Vec::with_capacity(raw.len());
        let mut i = 0;
        while i < raw.len() {
            if raw[i] == b'%' {
                let d = hex(raw.get(i + 1..i + 3)?)?;
                if d == b'/' || d == b'\\' {
                    return None;
                }
                bytes.push(d);
                i += 3;
            } else {
                bytes.push(raw[i]);
                i += 1;
            }
        }
        let path = String::from_utf8(bytes).ok()?;
        if path
            .chars()
            .any(|c| c == '%' || c == '\\' || c.is_control())
        {
            return None;
        }
        let mut segments: Vec<String> = Vec::new();
        for seg in path
            .split('/')
            .map(|s| s.split(';').next().unwrap_or_default())
        {
            match seg {
                "" | "." => {}
                ".." => {
                    segments.pop();
                }
                s => segments.push(s.to_owned()),
            }
        }
        let mut readings = vec![params(query, &['&', ';'])];
        if query.contains(';') {
            readings.push(params(query, &['&']));
        }
        Some(View { segments, readings })
    }

    pub fn path(&self) -> String {
        format!("/{}", self.segments.join("/"))
    }
}

/// Query parameters split on `seps`, each name and value `application/x-www-form-urlencoded` decoded.
fn params(query: &str, seps: &[char]) -> Vec<(Vec<u8>, Vec<u8>)> {
    query
        .split(seps)
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            (form_decode(k), form_decode(v))
        })
        .collect()
}

fn form_decode(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match (b[i], b.get(i + 1..i + 3).and_then(hex)) {
            (b'%', Some(d)) => {
                out.push(d);
                i += 3;
                continue;
            }
            (b'+', _) => out.push(b' '),
            (c, _) => out.push(c),
        }
        i += 1;
    }
    out
}

/// The byte a two-digit hex escape stands for. (`from_str_radix` would take a sign, as in `%+f`.)
fn hex(h: &[u8]) -> Option<u8> {
    let d = |c: u8| char::from(c).to_digit(16);
    match h {
        [a, b] => u8::try_from(d(*a)? * 16 + d(*b)?).ok(),
        _ => None,
    }
}
