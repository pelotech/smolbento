//! Registry credentials on the host: mints short-lived pull tokens from a stored login, and picks
//! the stored login for smolbento's own kit pulls. The login and tokens never reach argv, logs,
//! errors or URLs; Basic goes in the `Authorization` header only.

use std::time::Duration;

use anyhow::{Context, Result, bail};
use oci_client::secrets::RegistryAuth;
use reqwest::header::WWW_AUTHENTICATE;
use reqwest::redirect::Policy;
use reqwest::{StatusCode, Url};
use serde_json::Value;

use crate::kits::registry::is_loopback;
use crate::secrets::store::SecretStore;
use crate::secrets::{RegistryEntry, registry_secret};

/// Docker Hub's names; its token server is `auth.docker.io`.
const DOCKER_HUB: [&str; 3] = ["docker.io", "index.docker.io", "registry-1.docker.io"];

fn is_docker_hub(host: &str) -> bool {
    DOCKER_HUB.contains(&host)
}

/// Docker Hub's API answers on `registry-1.docker.io`.
fn api_host(host: &str) -> &str {
    if is_docker_hub(host) {
        "registry-1.docker.io"
    } else {
        host
    }
}

/// A token-only login (no `--username`) authenticates as `token`: token servers that take a
/// personal access token (ghcr.io, GitLab, Gitea) ignore the user name. Registries that check it
/// (Docker Hub, dhi.io, Quay robots) need `--username`. Docker's `<token>` sentinel is not used:
/// it means an OAuth refresh token, a different flow (`POST /token`, which dhi.io refuses).
fn username(entry: &RegistryEntry) -> &str {
    entry.username.as_deref().unwrap_or("token")
}

/// A Bearer token for pulling REPOS from HOST (a stored registry host), minted with the stored
/// login: realm discovery on `/v2/`, the trust rule, then a scoped GET with Basic.
pub fn pull_token(
    host: &str,
    entry: &RegistryEntry,
    password: &str,
    repos: &[String],
) -> Result<String> {
    match mint(host, entry, password, repos)? {
        Some(token) => Ok(token),
        None => {
            bail!("registry {host} does not hand out pull tokens (no Bearer challenge on /v2/)")
        }
    }
}

/// `pull_token`, with `None` when `/v2/` asks for no Bearer token (no auth, or Basic itself).
/// Sync: runs its own runtime, so it must not be called from inside one.
pub(crate) fn mint(
    host: &str,
    entry: &RegistryEntry,
    password: &str,
    repos: &[String],
) -> Result<Option<String>> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("starting the registry client")?
        .block_on(mint_async(host, entry, password, repos))
}

async fn mint_async(
    host: &str,
    entry: &RegistryEntry,
    password: &str,
    repos: &[String],
) -> Result<Option<String>> {
    // Same TLS setup as `registry::new_client`. Err means a provider is already installed.
    let _ = rustls::crypto::ring::default_provider().install_default();
    // No redirects: the login must only reach the realm the trust rule checked.
    let client = reqwest::Client::builder()
        .redirect(Policy::none())
        .connect_timeout(Duration::from_secs(30))
        .timeout(Duration::from_secs(60))
        .build()
        .context("starting the registry client")?;
    let api = api_host(host);
    // Loopback registries are plain HTTP, as for kit pulls (`registry::protocol_for`).
    let scheme = if is_loopback(api) { "http" } else { "https" };
    let res = client
        .get(format!("{scheme}://{api}/v2/"))
        .send()
        .await
        .with_context(|| format!("asking registry {host} where to log in"))?;
    // Every challenge, across header lines: a Bearer one may follow Basic (RFC 7235).
    let header = res
        .headers()
        .get_all(WWW_AUTHENTICATE)
        .iter()
        .map(|h| String::from_utf8_lossy(h.as_bytes()).into_owned())
        .collect::<Vec<_>>()
        .join(", ");
    let Some((realm, service)) = parse_challenge(&header) else {
        // Fail closed: oci-client would send Basic to any Bearer realm it finds.
        if header.to_ascii_lowercase().contains("bearer") {
            bail!(
                "registry {host} asks for a Bearer token but gives no realm smolbento can read; \
                 the login was not sent"
            );
        }
        return Ok(None);
    };
    if !trusted_realm(host, &realm, entry.auth_endpoint.as_deref()) {
        bail!(
            "registry {host} asks for credentials at {realm}; trust it with \
             --registry-auth-endpoint {realm}"
        );
    }
    let mut url = Url::parse(&realm).with_context(|| format!("registry {host}'s realm"))?;
    {
        let mut q = url.query_pairs_mut();
        if let Some(s) = &service {
            q.append_pair("service", s);
        }
        for r in repos {
            q.append_pair("scope", &format!("repository:{r}:pull"));
        }
    }
    // The login goes in the Authorization header only; the URL carries no credential.
    let res = client
        .get(url)
        .basic_auth(username(entry), Some(password))
        .send()
        .await
        .with_context(|| format!("getting a pull token from {realm}"))?;
    let status = res.status();
    if status != StatusCode::OK {
        // The body is not shown: some servers echo what they were sent.
        bail!("registry {host} refused the stored login at {realm} (HTTP {status})");
    }
    let body = res
        .bytes()
        .await
        .with_context(|| format!("reading the pull token from {realm}"))?;
    let v: Value = serde_json::from_slice(&body)
        .map_err(|_| anyhow::anyhow!("registry {host} sent a pull token that isn't JSON"))?;
    match ["token", "access_token"]
        .iter()
        .find_map(|k| v[*k].as_str().filter(|t| !t.is_empty()))
    {
        Some(t) => Ok(Some(t.to_string())),
        None => bail!("registry {host} sent no pull token"),
    }
}

/// The first Bearer challenge's (realm, service) in a `WWW-Authenticate` value, which may list
/// several challenges (`Basic realm="r", Bearer realm="…"`). `None` without one with a realm.
pub fn parse_challenge(header: &str) -> Option<(String, Option<String>)> {
    challenges(header)
        .into_iter()
        .filter(|(scheme, _)| scheme == "bearer")
        .find_map(|(_, params)| {
            let get = |k: &str| params.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
            Some((get("realm")?, get("service")))
        })
}

/// RFC 7235 challenges as (lowercased scheme, [(lowercased name, value)]). Challenges and their
/// params are all comma-separated: an item that starts with a bare token is a new challenge.
fn challenges(header: &str) -> Vec<(String, Vec<(String, String)>)> {
    let mut out: Vec<(String, Vec<(String, String)>)> = Vec::new();
    for item in split_commas(header) {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        let end = item
            .find(|c: char| c.is_whitespace() || c == '=')
            .unwrap_or(item.len());
        let (first, rest) = item.split_at(end);
        let param = if rest.trim_start().starts_with('=') {
            item
        } else {
            out.push((first.to_ascii_lowercase(), Vec::new()));
            rest.trim()
        };
        if let Some((k, v)) = param.split_once('=')
            && let Some((_, params)) = out.last_mut()
        {
            params.push((k.trim().to_ascii_lowercase(), unquote(v.trim())));
        }
    }
    out
}

/// Splits at commas outside quoted strings.
fn split_commas(s: &str) -> Vec<String> {
    let (mut items, mut cur, mut quoted, mut escaped) = (Vec::new(), String::new(), false, false);
    for c in s.chars() {
        match c {
            _ if escaped => escaped = false,
            '\\' if quoted => escaped = true,
            '"' => quoted = !quoted,
            ',' if !quoted => {
                items.push(std::mem::take(&mut cur));
                continue;
            }
            _ => {}
        }
        cur.push(c);
    }
    items.push(cur);
    items
}

fn unquote(v: &str) -> String {
    let Some(inner) = v.strip_prefix('"') else {
        return v.to_string();
    };
    let mut out = String::new();
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => out.extend(chars.next()),
            '"' => break,
            c => out.push(c),
        }
    }
    out
}

/// Whether HOST's login may be sent to REALM: https only, and the realm is HOST itself,
/// `auth.docker.io` for Docker Hub, or exactly HOST's `--registry-auth-endpoint`. A loopback
/// HOST, which kit pulls already speak plain HTTP to, may use an http realm on its own address.
pub fn trusted_realm(host: &str, realm: &str, auth_endpoint: Option<&str>) -> bool {
    let Ok(url) = Url::parse(realm) else {
        return false;
    };
    let Some(realm_host) = url.host_str() else {
        return false;
    };
    if !url.username().is_empty() || url.password().is_some() {
        return false;
    }
    let host = host.to_ascii_lowercase();
    // `Url` lowercases the host and drops the scheme's default port.
    let authority = match url.port() {
        Some(p) => format!("{realm_host}:{p}"),
        None => realm_host.to_string(),
    };
    match url.scheme() {
        "https" => {}
        "http" => return is_loopback(&host) && authority == host,
        _ => return false,
    }
    auth_endpoint == Some(realm)
        || authority == host
        || (is_docker_hub(&host) && authority == "auth.docker.io")
}

/// The stored login for REGISTRY (a reference's registry) as Basic, with its entry.
pub(crate) fn stored_login(
    registries: &[RegistryEntry],
    store: &dyn SecretStore,
    registry: &str,
) -> Result<Option<(RegistryEntry, RegistryAuth)>> {
    let registry = registry.to_ascii_lowercase();
    let Some(entry) = registries
        .iter()
        .find(|e| e.host == registry || (is_docker_hub(&e.host) && is_docker_hub(&registry)))
    else {
        return Ok(None);
    };
    let host = &entry.host;
    let Some(password) = registry_secret(store, host)? else {
        bail!(
            "registry secret {host} has no value in {}; set it again with \
             `sbt secret set --registry {host} --password-stdin`",
            store.describe()
        );
    };
    let user = username(entry).to_string();
    Ok(Some((entry.clone(), RegistryAuth::Basic(user, password))))
}

/// The stored registry logins kit pulls may use, injected by the caller (from `Ctx`).
#[derive(Clone, Copy)]
pub struct Logins<'a> {
    registries: &'a [RegistryEntry],
    store: Option<&'a dyn SecretStore>,
}

impl<'a> Logins<'a> {
    pub fn new(registries: &'a [RegistryEntry], store: &'a dyn SecretStore) -> Logins<'a> {
        Logins {
            registries,
            store: Some(store),
        }
    }

    /// No stored logins: anonymous and docker-login pulls only.
    pub fn none() -> Logins<'static> {
        Logins {
            registries: &[],
            store: None,
        }
    }

    /// The auth for pulling REPO from REGISTRY with its stored login: a minted Bearer token, or,
    /// only when `/v2/` has no Bearer challenge, the Basic login itself (oci-client then sends
    /// it to that registry only). `None` without a stored login. Sync; call outside a runtime.
    pub(crate) fn auth_for(&self, registry: &str, repo: &str) -> Result<Option<RegistryAuth>> {
        let Some(store) = self.store else {
            return Ok(None);
        };
        let Some((entry, RegistryAuth::Basic(user, password))) =
            stored_login(self.registries, store, registry)?
        else {
            return Ok(None);
        };
        Ok(Some(
            match mint(&entry.host, &entry, &password, &[repo.to_string()])? {
                Some(token) => RegistryAuth::Bearer(token),
                None => RegistryAuth::Basic(user, password),
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::registry_account;
    use crate::secrets::store::MemoryStore;
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;

    fn entry(host: &str, user: Option<&str>, endpoint: Option<&str>) -> RegistryEntry {
        RegistryEntry {
            host: host.into(),
            username: user.map(String::from),
            auth_endpoint: endpoint.map(String::from),
        }
    }

    #[test]
    fn challenge_parsing() {
        assert_eq!(
            parse_challenge(r#"Bearer realm="https://dhi.io/token",service="registry.docker.io""#),
            Some((
                "https://dhi.io/token".into(),
                Some("registry.docker.io".into())
            ))
        );
        // Scheme is case-insensitive; quoted commas and escapes; extra params ignored.
        assert_eq!(
            parse_challenge(
                r#"bearer service="a\"b", scope="repository:x:pull,push" ,realm="https://ghcr.io/token""#
            ),
            Some(("https://ghcr.io/token".into(), Some("a\"b".into())))
        );
        assert_eq!(
            parse_challenge(r#"Bearer realm=https://r.example/t"#),
            Some(("https://r.example/t".into(), None))
        );
        // RFC 7235 lists several challenges in one header; the Bearer one is found wherever it is.
        assert_eq!(
            parse_challenge(
                r#"Basic realm="x, y", Bearer realm="https://r.example/t",service="s", Other"#
            ),
            Some(("https://r.example/t".into(), Some("s".into())))
        );
        assert_eq!(
            parse_challenge("Bearer\trealm=\"https://r.example/t\""),
            Some(("https://r.example/t".into(), None))
        );
        assert_eq!(
            parse_challenge(r#"Basic realm="a", BEARER  realm = "https://r.example/t""#),
            Some(("https://r.example/t".into(), None))
        );
        // A Basic param named like a Bearer one doesn't count.
        assert_eq!(
            parse_challenge(r#"Basic realm="https://x/t", Bearer"#),
            None
        );
        assert_eq!(parse_challenge(r#"Basic realm="Registry Realm""#), None);
        assert_eq!(parse_challenge(r#"Bearer service="x""#), None);
        assert_eq!(parse_challenge(""), None);
    }

    #[test]
    fn trust_rule() {
        // Same host.
        assert!(trusted_realm("dhi.io", "https://dhi.io/token", None));
        assert!(trusted_realm("ghcr.io", "https://GHCR.io/token?x=1", None));
        // Docker Hub's auth host.
        for h in ["docker.io", "registry-1.docker.io", "index.docker.io"] {
            assert!(
                trusted_realm(h, "https://auth.docker.io/token", None),
                "{h}"
            );
        }
        assert!(!trusted_realm(
            "dhi.io",
            "https://auth.docker.io/token",
            None
        ));
        // Another host only when named exactly.
        assert!(!trusted_realm(
            "quay.io",
            "https://auth.example.com/t",
            None
        ));
        assert!(trusted_realm(
            "quay.io",
            "https://auth.example.com/t",
            Some("https://auth.example.com/t")
        ));
        assert!(!trusted_realm(
            "quay.io",
            "https://auth.example.com/t2",
            Some("https://auth.example.com/t")
        ));
        // https only, even on the same host or a named endpoint.
        assert!(!trusted_realm("dhi.io", "http://dhi.io/token", None));
        assert!(!trusted_realm(
            "quay.io",
            "http://auth.example.com/t",
            Some("http://auth.example.com/t")
        ));
        // Host lookalikes, other ports, userinfo.
        assert!(!trusted_realm(
            "dhi.io",
            "https://dhi.io.evil.com/token",
            None
        ));
        assert!(!trusted_realm("dhi.io", "https://dhi.io:8443/token", None));
        assert!(!trusted_realm("dhi.io", "https://u:p@dhi.io/token", None));
        assert!(!trusted_realm("dhi.io", "not a url", None));
        // A loopback registry, already spoken to over plain HTTP, may answer on its own address.
        assert!(trusted_realm(
            "127.0.0.1:5000",
            "http://127.0.0.1:5000/t",
            None
        ));
        assert!(trusted_realm(
            "localhost:5000",
            "http://localhost:5000/t",
            None
        ));
        assert!(!trusted_realm(
            "127.0.0.1:5000",
            "http://127.0.0.1:5001/t",
            None
        ));
        assert!(!trusted_realm(
            "127.0.0.1:5000",
            "http://localhost:5000/t",
            None
        ));
    }

    /// Serves one response per connection (`Connection: close`) and hands back each request.
    fn serve(responses: Vec<Box<dyn Fn(u16) -> String + Send>>) -> (u16, mpsc::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            for respond in responses {
                let Ok((mut s, _)) = listener.accept() else {
                    return;
                };
                let mut req = String::new();
                let mut r = BufReader::new(s.try_clone().unwrap());
                loop {
                    let mut line = String::new();
                    if r.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                        break;
                    }
                    req.push_str(&line);
                }
                let _ = tx.send(req);
                let _ = s.write_all(respond(port).as_bytes());
            }
        });
        (port, rx)
    }

    fn challenge(realm_host: &'static str) -> Box<dyn Fn(u16) -> String + Send> {
        Box::new(move |port| {
            format!(
                "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Bearer realm=\"http://{realm_host}:{port}/token\",service=\"reg.test\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
        })
    }

    fn json(status: &'static str, body: &'static str) -> Box<dyn Fn(u16) -> String + Send> {
        Box::new(move |_| {
            format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
        })
    }

    #[test]
    fn mints_a_scoped_token_with_basic() {
        let (port, rx) = serve(vec![
            challenge("127.0.0.1"),
            json("200 OK", r#"{"token":"minted"}"#),
        ]);
        let host = format!("127.0.0.1:{port}");
        let repos = vec!["debian-base".to_string(), "a/b".to_string()];
        let t = pull_token(&host, &entry(&host, Some("josmo"), None), "s3cret", &repos).unwrap();
        assert_eq!(t, "minted");
        let v2 = rx.recv().unwrap();
        assert!(v2.starts_with("GET /v2/ "), "{v2}");
        assert!(!v2.to_ascii_lowercase().contains("authorization"), "{v2}");
        let tok = rx.recv().unwrap();
        let first = tok.lines().next().unwrap();
        assert!(first.starts_with("GET /token?"), "{first}");
        assert!(first.contains("service=reg.test"), "{first}");
        assert!(
            first.contains("scope=repository%3Adebian-base%3Apull"),
            "{first}"
        );
        assert!(first.contains("scope=repository%3Aa%2Fb%3Apull"), "{first}");
        assert!(!first.contains("s3cret"), "{first}");
        // base64("josmo:s3cret")
        assert!(
            tok.lines()
                .any(|l| l.eq_ignore_ascii_case("authorization: Basic am9zbW86czNjcmV0")),
            "{tok}"
        );
    }

    #[test]
    fn token_only_login_uses_the_token_user_and_access_token() {
        let (port, rx) = serve(vec![
            challenge("127.0.0.1"),
            json("200 OK", r#"{"access_token":"at"}"#),
        ]);
        let host = format!("127.0.0.1:{port}");
        let t = pull_token(&host, &entry(&host, None, None), "pat", &["r".into()]).unwrap();
        assert_eq!(t, "at");
        rx.recv().unwrap();
        // base64("token:pat")
        assert!(rx.recv().unwrap().contains("Basic dG9rZW46cGF0"));
    }

    #[test]
    fn untrusted_realm_is_refused_before_sending_the_login() {
        let (port, rx) = serve(vec![
            challenge("localhost"),
            json("200 OK", r#"{"token":"x"}"#),
        ]);
        let host = format!("127.0.0.1:{port}");
        let e = pull_token(
            &host,
            &entry(&host, Some("u"), None),
            "s3cret",
            &["r".into()],
        )
        .unwrap_err();
        assert_eq!(
            format!("{e:#}"),
            format!(
                "registry {host} asks for credentials at http://localhost:{port}/token; trust it \
                 with --registry-auth-endpoint http://localhost:{port}/token"
            )
        );
        rx.recv().unwrap();
        assert!(rx.try_recv().is_err(), "the token endpoint was called");
    }

    #[test]
    fn refused_login_error_has_no_secret() {
        let (port, _rx) = serve(vec![
            challenge("127.0.0.1"),
            json("401 Unauthorized", r#"{"details":"s3cret is wrong"}"#),
        ]);
        let host = format!("127.0.0.1:{port}");
        let e = pull_token(
            &host,
            &entry(&host, Some("u"), None),
            "s3cret",
            &["r".into()],
        )
        .unwrap_err();
        let text = format!("{e:#}");
        assert!(text.contains("401"), "{text}");
        assert!(!text.contains("s3cret"), "{text}");
    }

    #[test]
    fn stored_login_matches_the_reference_registry() {
        let store = MemoryStore::default();
        store.set(&registry_account("ghcr.io"), "pat").unwrap();
        store.set(&registry_account("docker.io"), "hub").unwrap();
        let regs = vec![
            entry("ghcr.io", None, None),
            entry("docker.io", Some("josmo"), None),
            entry("quay.io", None, None),
        ];
        let basic = |r: &str| match stored_login(&regs, &store, r).unwrap() {
            Some((e, RegistryAuth::Basic(u, p))) => Some((e.host, u, p)),
            Some(_) => panic!("not Basic"),
            None => None,
        };
        assert_eq!(
            basic("GHCR.io"),
            Some(("ghcr.io".into(), "token".into(), "pat".into()))
        );
        for r in ["docker.io", "index.docker.io", "registry-1.docker.io"] {
            assert_eq!(
                basic(r),
                Some(("docker.io".into(), "josmo".into(), "hub".into())),
                "{r}"
            );
        }
        assert_eq!(basic("example.com"), None);
        // An entry whose value is gone from the store is an error, not a silent anonymous pull.
        let e = stored_login(&regs, &store, "quay.io").unwrap_err();
        assert!(
            format!("{e:#}").contains("sbt secret set --registry quay.io"),
            "{e:#}"
        );
    }

    fn raw(status: &'static str, header: &'static str) -> Box<dyn Fn(u16) -> String + Send> {
        Box::new(move |port| {
            let header = header.replace("{port}", &port.to_string());
            format!("HTTP/1.1 {status}\r\n{header}Content-Length: 0\r\nConnection: close\r\n\r\n")
        })
    }

    /// What `Logins` hands oci-client for a stored login on a fake registry at 127.0.0.1.
    fn kit_auth(
        responses: Vec<Box<dyn Fn(u16) -> String + Send>>,
    ) -> (Result<Option<RegistryAuth>>, Vec<String>) {
        let (port, rx) = serve(responses);
        let host = format!("127.0.0.1:{port}");
        let store = MemoryStore::default();
        store.set(&registry_account(&host), "s3cret").unwrap();
        let regs = vec![entry(&host, Some("u"), None)];
        let auth = Logins::new(&regs, &store).auth_for(&host, "kits/a");
        (auth, rx.try_iter().collect())
    }

    #[test]
    fn kit_pull_uses_a_minted_bearer_token() {
        let (auth, reqs) = kit_auth(vec![
            challenge("127.0.0.1"),
            json("200 OK", r#"{"token":"minted"}"#),
        ]);
        assert!(matches!(auth.unwrap(), Some(RegistryAuth::Bearer(t)) if t == "minted"));
        assert!(
            reqs[1].contains("scope=repository%3Akits%2Fa%3Apull"),
            "{}",
            reqs[1]
        );
    }

    #[test]
    fn kit_pull_sends_basic_only_without_a_bearer_challenge() {
        for resp in [
            raw("200 OK", ""),
            raw(
                "401 Unauthorized",
                "WWW-Authenticate: Basic realm=\"Registry Realm\"\r\n",
            ),
        ] {
            let (auth, reqs) = kit_auth(vec![resp]);
            assert!(
                matches!(auth.unwrap(), Some(RegistryAuth::Basic(u, p)) if u == "u" && p == "s3cret")
            );
            assert_eq!(reqs.len(), 1);
        }
    }

    #[test]
    fn a_bearer_challenge_after_basic_is_still_checked() {
        let (auth, reqs) = kit_auth(vec![raw(
            "401 Unauthorized",
            "WWW-Authenticate: Basic realm=\"x\", Bearer realm=\"http://localhost:{port}/token\"\r\n",
        )]);
        let e = auth.unwrap_err();
        assert!(
            format!("{e:#}").contains("--registry-auth-endpoint http://localhost:"),
            "{e:#}"
        );
        assert_eq!(reqs.len(), 1);
        // The same with the challenges in two header lines.
        let (auth, _) = kit_auth(vec![raw(
            "401 Unauthorized",
            "WWW-Authenticate: Basic realm=\"x\"\r\nWWW-Authenticate: Bearer realm=\"http://localhost:{port}/token\"\r\n",
        )]);
        assert!(auth.is_err());
    }

    #[test]
    fn a_bearer_challenge_without_a_realm_fails_closed() {
        for header in [
            "WWW-Authenticate: Bearer service=\"x\"\r\n",
            "WWW-Authenticate: Basic realm=\"x\", Bearer\r\n",
        ] {
            let (auth, reqs) = kit_auth(vec![raw("401 Unauthorized", header)]);
            let e = auth.unwrap_err();
            assert!(format!("{e:#}").contains("no realm"), "{e:#}");
            assert!(!format!("{e:#}").contains("s3cret"));
            assert_eq!(reqs.len(), 1);
        }
    }

    #[test]
    fn no_stored_login_means_no_auth_and_no_request() {
        let store = MemoryStore::default();
        assert!(
            Logins::new(&[], &store)
                .auth_for("ghcr.io", "a")
                .unwrap()
                .is_none()
        );
        assert!(Logins::none().auth_for("ghcr.io", "a").unwrap().is_none());
    }
}
