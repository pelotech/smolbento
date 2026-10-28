//! Registry credentials on the host: mints short-lived pull tokens from a stored login, and picks
//! the stored login for smolbento's own kit pulls. The login and tokens never reach argv, logs,
//! errors or URLs; Basic goes in the `Authorization` header only.

use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use oci_client::secrets::RegistryAuth;
use reqwest::header::WWW_AUTHENTICATE;
use reqwest::redirect::Policy;
use reqwest::{StatusCode, Url};
use serde_json::Value;

use crate::config::Paths;
use crate::kits::registry::is_loopback;
use crate::secrets::store::{self, SecretStore};
use crate::secrets::{RegistryEntry, SecretsFile, registry_secret};

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
    let Some((realm, service)) = res
        .headers()
        .get(WWW_AUTHENTICATE)
        .and_then(|h| h.to_str().ok())
        .and_then(parse_challenge)
    else {
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

/// `Bearer realm="…",service="…"` → (realm, service). Other schemes (Basic) → `None`.
pub fn parse_challenge(header: &str) -> Option<(String, Option<String>)> {
    let (scheme, rest) = header.trim().split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let (mut realm, mut service) = (None, None);
    let mut chars = rest.chars().peekable();
    loop {
        while chars.next_if(|c| *c == ',' || c.is_whitespace()).is_some() {}
        let mut key = String::new();
        while let Some(c) = chars.next_if(|c| *c != '=' && *c != ',') {
            key.push(c);
        }
        if key.is_empty() && chars.peek().is_none() {
            break;
        }
        if chars.next_if_eq(&'=').is_none() {
            continue;
        }
        while chars.next_if(|c| *c == ' ').is_some() {}
        let mut value = String::new();
        if chars.next_if_eq(&'"').is_some() {
            while let Some(c) = chars.next() {
                match c {
                    '\\' => value.extend(chars.next()),
                    '"' => break,
                    c => value.push(c),
                }
            }
        } else {
            while let Some(c) = chars.next_if(|c| *c != ',') {
                value.push(c);
            }
            value = value.trim().to_string();
        }
        match key.trim().to_ascii_lowercase().as_str() {
            "realm" => realm = Some(value),
            "service" => service = Some(value),
            _ => {}
        }
    }
    Some((realm?, service))
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

/// The pull auth for a kit pull from REPO on REGISTRY, from the user's stored registry secret:
/// a minted Bearer token, or the Basic login itself for a registry that takes Basic on `/v2/`
/// (sent only to that registry). `None` without a stored secret. Kit pulls have no `Ctx`, so
/// the secrets file and store come from the environment, as `main` builds them.
pub(crate) fn kit_pull_auth(registry: &str, repo: &str) -> Result<Option<RegistryAuth>> {
    let env: BTreeMap<String, String> = std::env::vars().collect();
    let paths = Paths::from_env(&env)?;
    let file = SecretsFile::load(&paths)?;
    if file.registries.is_empty() {
        return Ok(None);
    }
    let store = store::platform(&paths, &env);
    let Some((entry, RegistryAuth::Basic(user, password))) =
        stored_login(&file.registries, &*store, registry)?
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
}
