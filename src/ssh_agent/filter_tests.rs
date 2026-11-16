use super::*;
use std::sync::Mutex;

fn s(b: &[u8]) -> Vec<u8> {
    [&(b.len() as u32).to_be_bytes()[..], b].concat()
}

fn sign(data: &[u8]) -> Vec<u8> {
    [
        &[SIGN_REQUEST][..],
        &s(&crate::ssh_agent::known_hosts::testkeys::key(99)
            .public_key()
            .to_bytes()
            .unwrap()),
        &s(data),
        &0u32.to_be_bytes(),
    ]
    .concat()
}

fn sshsig(namespace: &[u8]) -> Vec<u8> {
    [SSHSIG, &s(namespace), &s(b""), &s(b"sha512"), &s(b"hash")].concat()
}

fn extension(name: &[u8]) -> Vec<u8> {
    [&[EXTENSION][..], &s(name), b"rest"].concat()
}

/// `verdict` with a fresh connection and no `known_hosts`: for what needs neither.
fn verdict(access: &Access, msg: &[u8]) -> Verdict {
    super::verdict(access, &mut Conn::default(), &|| None, msg)
}

fn all() -> Access {
    Access {
        sign: None,
        authenticate: vec![],
    }
}

fn only(namespaces: &[&str]) -> Access {
    Access {
        sign: Some(namespaces.iter().map(|n| n.to_string()).collect()),
        authenticate: vec![],
    }
}

#[test]
fn identities_and_session_binding_are_relayed_other_messages_fail() {
    for access in [all(), only(&["git"])] {
        assert_eq!(verdict(&access, &[REQUEST_IDENTITIES]), Verdict::Relay);
        assert_eq!(verdict(&access, &extension(SESSION_BIND)), Verdict::Relay);
        for name in [&b"query"[..], b"session-bind@openssh.co", b"x@example.com"] {
            assert_eq!(verdict(&access, &extension(name)), Verdict::Fail);
        }
        // Add, remove, remove all, lock, unlock, add smartcard, constrained add, …
        for kind in [17, 18, 19, 20, 21, 22, 23, 25, 26, 1, 0, 255] {
            assert_eq!(
                verdict(&access, &[kind, 0, 0, 0, 0]),
                Verdict::Fail,
                "{kind}"
            );
        }
    }
}

#[test]
fn an_unrestricted_grant_signs_anything() {
    assert_eq!(verdict(&all(), &sign(b"login data")), Verdict::Relay);
    assert_eq!(verdict(&all(), &sign(&sshsig(b"file"))), Verdict::Relay);
}

#[test]
fn a_sign_list_admits_only_its_sshsig_namespaces() {
    let git = only(&["git", "file"]);
    assert_eq!(verdict(&git, &sign(&sshsig(b"git"))), Verdict::Relay);
    assert_eq!(verdict(&git, &sign(&sshsig(b"file"))), Verdict::Relay);
    // Unlisted, a prefix of a listed one, a listed one with more after it.
    for ns in [&b"email"[..], b"gi", b"gitx", b""] {
        assert_eq!(verdict(&git, &sign(&sshsig(ns))), Verdict::Fail);
    }
    // Not SSHSIG: a login's session data, or the namespace without the preamble.
    assert_eq!(verdict(&git, &sign(b"\0\0\0\x20session")), Verdict::Fail);
    assert_eq!(verdict(&git, &sign(&s(b"git"))), Verdict::Fail);
    assert_eq!(verdict(&git, &sign(b"sshsig")), Verdict::Fail);
    // Truncated after the preamble or inside the namespace.
    assert_eq!(verdict(&git, &sign(b"SSHSIG")), Verdict::Fail);
    assert_eq!(verdict(&git, &sign(b"SSHSIG\0\0\0\x03gi")), Verdict::Fail);
    // Just the namespace is enough to decide.
    assert_eq!(verdict(&git, &sign(b"SSHSIG\0\0\0\x03git")), Verdict::Relay);
}

#[test]
fn malformed_requests_close_the_connection() {
    for access in [all(), only(&["git"])] {
        let truncated = [&[SIGN_REQUEST][..], &s(b"key"), b"\0\0\x01\0data"].concat();
        let no_flags = [&[SIGN_REQUEST][..], &s(b"key"), &s(&sshsig(b"git"))].concat();
        let extra = [&sign(&sshsig(b"git"))[..], b"x"].concat();
        for msg in [vec![SIGN_REQUEST], truncated, no_flags, extra] {
            assert_eq!(verdict(&access, &msg), Verdict::Close, "{msg:?}");
        }
        assert_eq!(verdict(&access, &[EXTENSION, 0, 0, 1]), Verdict::Close);
        assert_eq!(verdict(&access, &[]), Verdict::Close);
    }
}

use crate::ssh_agent::known_hosts::testkeys::{key, line};
use signature::Signer;
use ssh_key::PrivateKey;

const SESSION: &[u8] = b"0123456789abcdef0123456789abcdef";

fn wire_sig(k: &PrivateKey, data: &[u8]) -> Vec<u8> {
    let sig: Signature = k.try_sign(data).unwrap();
    Vec::try_from(sig).unwrap()
}

/// A `session-bind@openssh.com` request: `host` signs `session`.
fn bind(host: &PrivateKey, session: &[u8], forwarding: bool) -> Vec<u8> {
    bind_signed_by(host, host, session, forwarding)
}

fn bind_signed_by(host: &PrivateKey, signer: &PrivateKey, session: &[u8], fwd: bool) -> Vec<u8> {
    [
        &[EXTENSION][..],
        &s(SESSION_BIND),
        &s(&host.public_key().to_bytes().unwrap()),
        &s(session),
        &s(&wire_sig(signer, session)),
        &[u8::from(fwd)],
    ]
    .concat()
}

/// The signed data of a login with `user_key` as `user`.
fn login_data(session: &[u8], user: &str, method: &[u8], hostkey: Option<&PrivateKey>) -> Vec<u8> {
    login_data_flag(session, user, method, hostkey, 1)
}

fn login_data_flag(
    session: &[u8],
    user: &str,
    method: &[u8],
    hostkey: Option<&PrivateKey>,
    flag: u8,
) -> Vec<u8> {
    let user_key = key(99).public_key().to_bytes().unwrap();
    let mut d = [
        &s(session)[..],
        &[USERAUTH_REQUEST],
        &s(user.as_bytes()),
        &s(b"ssh-connection"),
        &s(method),
        &[flag],
        &s(b"ssh-ed25519"),
        &s(&user_key),
    ]
    .concat();
    if let Some(h) = hostkey {
        d.extend(s(&h.public_key().to_bytes().unwrap()));
    }
    d
}

fn logins(entries: &[&str]) -> Access {
    Access {
        sign: Some(vec!["git".into()]),
        authenticate: entries.iter().map(|e| e.to_string()).collect(),
    }
}

fn known(hosts: &[(&str, u8)]) -> String {
    hosts
        .iter()
        .map(|(h, n)| format!("{h} {}\n", line(*n)))
        .collect()
}

/// Asks, on one connection, a sequence of messages and returns the last verdict.
fn run(access: &Access, kh: &str, msgs: &[Vec<u8>]) -> Verdict {
    let mut conn = Conn::default();
    let text = kh.to_string();
    let mut last = Verdict::Close;
    for m in msgs {
        last = super::verdict(access, &mut conn, &|| Some(text.clone()), m);
    }
    last
}

const PK: &[u8] = PUBLICKEY;

#[test]
fn a_login_needs_a_verified_binding_to_a_listed_server() {
    let gh = key(1);
    let a = logins(&["github.com"]);
    let kh = known(&[("github.com", 1)]);
    let login = sign(&login_data(SESSION, "git", PK, None));
    let ok = [bind(&gh, SESSION, false), login.clone()];
    assert_eq!(run(&a, &kh, &ok), Verdict::Relay);

    // No binding at all.
    assert_eq!(run(&a, &kh, std::slice::from_ref(&login)), Verdict::Fail);
    // A binding another connection carried.
    let mut other = Conn::default();
    super::verdict(&a, &mut other, &|| None, &bind(&gh, SESSION, false));
    assert_eq!(
        super::verdict(&a, &mut Conn::default(), &|| Some(kh.clone()), &login),
        Verdict::Fail
    );
    // A binding whose signature is by another key, or over other data.
    let forged = bind_signed_by(&gh, &key(2), SESSION, false);
    assert_eq!(run(&a, &kh, &[forged, login.clone()]), Verdict::Fail);
    let mut tampered = bind(&gh, SESSION, false);
    let at = tampered.len() - 3;
    tampered[at] ^= 1;
    assert_eq!(run(&a, &kh, &[tampered, login.clone()]), Verdict::Fail);
    // A forwarding binding never counts.
    assert_eq!(
        run(&a, &kh, &[bind(&gh, SESSION, true), login.clone()]),
        Verdict::Fail
    );
    // A binding for another session.
    assert_eq!(
        run(
            &a,
            &kh,
            &[bind(&gh, b"another session id", false), login.clone()]
        ),
        Verdict::Fail
    );
}

#[test]
fn the_binding_s_host_key_must_be_a_listed_servers_known_key() {
    let gh = key(1);
    let b = bind(&gh, SESSION, false);
    let login = sign(&login_data(SESSION, "git", PK, None));
    let msgs = [b.clone(), login.clone()];
    // Not named in authenticate, or named only as another host.
    assert_eq!(
        run(
            &logins(&["gitlab.com"]),
            &known(&[("github.com", 1)]),
            &msgs
        ),
        Verdict::Fail
    );
    // The file doesn't list the key for that name (another key, another host), or revokes it.
    let a = logins(&["github.com"]);
    assert_eq!(run(&a, &known(&[("github.com", 2)]), &msgs), Verdict::Fail);
    assert_eq!(run(&a, &known(&[("gitlab.com", 1)]), &msgs), Verdict::Fail);
    let revoked = format!("github.com {}\n@revoked * {}\n", line(1), line(1));
    assert_eq!(run(&a, &revoked, &msgs), Verdict::Fail);
    assert_eq!(run(&a, "", &msgs), Verdict::Fail);
    // An unreadable file is no keys.
    let mut conn = Conn::default();
    super::verdict(&a, &mut conn, &|| None, &b);
    assert_eq!(
        super::verdict(&a, &mut conn, &|| None, &login),
        Verdict::Fail
    );
    // One of several listed servers, with the server's key among several.
    let many = logins(&["gitlab.com", "github.com"]);
    let kh = known(&[("github.com", 7), ("github.com", 1)]);
    assert_eq!(run(&many, &kh, &msgs), Verdict::Relay);
}

#[test]
fn a_login_must_sign_with_the_key_it_names_and_an_algorithm_that_key_makes() {
    let gh = key(1);
    let a = logins(&["github.com"]);
    let kh = known(&[("github.com", 1)]);
    let data = login_data(SESSION, "git", PK, None);
    let bound = bind(&gh, SESSION, false);
    let with_key = |k: &[u8]| [&[SIGN_REQUEST][..], &s(k), &s(&data), &0u32.to_be_bytes()].concat();
    let other = key(98).public_key().to_bytes().unwrap();
    assert_eq!(
        run(&a, &kh, &[bound.clone(), with_key(&other)]),
        Verdict::Fail
    );
    // An algorithm the key doesn't make.
    let wrong_alg = {
        let mut d = login_data(SESSION, "git", PK, None);
        let pos = d.windows(11).position(|w| w == b"ssh-ed25519").unwrap();
        d[pos..pos + 11].copy_from_slice(b"ssh-ed25518");
        d
    };
    assert_eq!(
        run(&a, &kh, &[bound.clone(), sign(&wrong_alg)]),
        Verdict::Fail
    );
    assert!(algorithm_fits(b"rsa-sha2-512", &s(b"ssh-rsa")));
    assert!(algorithm_fits(
        b"rsa-sha2-256-cert-v01@openssh.com",
        &s(b"ssh-rsa-cert-v01@openssh.com")
    ));
    assert!(!algorithm_fits(b"ssh-rsa", &s(b"ssh-ed25519")));
    assert!(!algorithm_fits(b"ssh-ed25519", b"\x00"));
}

#[test]
fn a_user_entry_admits_only_that_user() {
    let gh = key(1);
    let kh = known(&[("github.com", 1)]);
    let b = bind(&gh, SESSION, false);
    let as_user = |u: &str| sign(&login_data(SESSION, u, PK, None));
    let a = logins(&["git@github.com"]);
    assert_eq!(run(&a, &kh, &[b.clone(), as_user("git")]), Verdict::Relay);
    for u in ["root", "gi", "git2", "", "GIT"] {
        assert_eq!(run(&a, &kh, &[b.clone(), as_user(u)]), Verdict::Fail, "{u}");
    }
    // A bare host admits any user; another entry for the host can admit another one.
    assert_eq!(
        run(&logins(&["github.com"]), &kh, &[b.clone(), as_user("root")]),
        Verdict::Relay
    );
    let two = logins(&["git@github.com", "root@github.com"]);
    assert_eq!(run(&two, &kh, &[b, as_user("root")]), Verdict::Relay);
}

#[test]
fn the_hostbound_method_must_name_the_bindings_host_key() {
    let (gh, evil) = (key(1), key(2));
    let kh = known(&[("github.com", 1)]);
    let a = logins(&["github.com"]);
    let b = bind(&gh, SESSION, false);
    let hb = |h: &PrivateKey| sign(&login_data(SESSION, "git", HOSTBOUND, Some(h)));
    assert_eq!(run(&a, &kh, &[b.clone(), hb(&gh)]), Verdict::Relay);
    assert_eq!(run(&a, &kh, &[b.clone(), hb(&evil)]), Verdict::Fail);
    // The hostbound method without its host key, and the plain one with a stray one.
    let bare = sign(&login_data(SESSION, "git", HOSTBOUND, None));
    assert_eq!(run(&a, &kh, &[b.clone(), bare]), Verdict::Fail);
    let stray = sign(&login_data(SESSION, "git", PK, Some(&gh)));
    assert_eq!(run(&a, &kh, &[b, stray]), Verdict::Fail);
}

#[test]
fn other_login_data_is_refused() {
    let gh = key(1);
    let kh = known(&[("github.com", 1)]);
    let a = logins(&["github.com"]);
    let b = bind(&gh, SESSION, false);
    let good = login_data(SESSION, "git", PK, None);
    let refused = |data: Vec<u8>| run(&a, &kh, &[b.clone(), sign(&data)]);
    assert_eq!(refused(good.clone()), Verdict::Relay);
    // Other methods, a missing-signature flag, trailing bytes, truncations, garbage.
    for m in [
        &b"hostbased"[..],
        b"password",
        b"none",
        b"keyboard-interactive",
        b"",
    ] {
        assert_eq!(refused(login_data(SESSION, "git", m, None)), Verdict::Fail);
    }
    let no_sig = login_data_flag(SESSION, "git", PK, None, 0);
    assert_eq!(refused(no_sig), Verdict::Fail);
    assert_eq!(refused([&good[..], b"x"].concat()), Verdict::Fail);
    for cut in 0..good.len() {
        assert_eq!(refused(good[..cut].to_vec()), Verdict::Fail, "{cut}");
    }
    let mut wrong_type = good.clone();
    wrong_type[SESSION.len() + 4] = 51;
    assert_eq!(refused(wrong_type), Verdict::Fail);
    assert_eq!(refused(b"garbage".to_vec()), Verdict::Fail);
    assert_eq!(refused(vec![]), Verdict::Fail);
    // Certificate-signed data and other bytes are neither SSHSIG nor a login.
    assert_eq!(refused(b"\0\0\0\x05ca-signed cert".to_vec()), Verdict::Fail);
}

#[test]
fn a_grant_without_logins_never_admits_one_and_sshsig_is_unchanged() {
    let gh = key(1);
    let kh = known(&[("github.com", 1)]);
    let b = bind(&gh, SESSION, false);
    let login = sign(&login_data(SESSION, "git", PK, None));
    assert_eq!(
        run(&only(&["git"]), &kh, &[b.clone(), login.clone()]),
        Verdict::Fail
    );
    let a = logins(&["github.com"]);
    assert_eq!(
        run(&a, &kh, &[b.clone(), sign(&sshsig(b"git"))]),
        Verdict::Relay
    );
    assert_eq!(
        run(&a, &kh, &[b.clone(), sign(&sshsig(b"file"))]),
        Verdict::Fail
    );
    // A logins-only grant (empty sign list) signs no SSHSIG.
    let only_logins = Access {
        sign: Some(vec![]),
        authenticate: a.authenticate.clone(),
    };
    assert_eq!(
        run(&only_logins, &kh, &[b.clone(), sign(&sshsig(b"git"))]),
        Verdict::Fail
    );
    assert_eq!(run(&only_logins, &kh, &[b, login]), Verdict::Relay);
    // An unrestricted grant relays logins without bindings.
    assert_eq!(
        run(&all(), "", &[sign(&login_data(SESSION, "x", PK, None))]),
        Verdict::Relay
    );
}

#[test]
fn a_malformed_binding_fails_under_a_grant_with_logins_and_relays_otherwise() {
    let a = logins(&["github.com"]);
    assert_eq!(run(&a, "", &[extension(SESSION_BIND)]), Verdict::Fail);
    let good = bind(&key(1), SESSION, false);
    assert_eq!(run(&a, "", std::slice::from_ref(&good)), Verdict::Relay);
    assert_eq!(run(&a, "", &[[&good[..], b"x"].concat()]), Verdict::Fail);
    assert_eq!(
        run(&a, "", &[good[..good.len() - 1].to_vec()]),
        Verdict::Fail
    );
    assert_eq!(
        run(&only(&["git"]), "", &[extension(SESSION_BIND)]),
        Verdict::Relay
    );
}

#[test]
fn rsa_and_ecdsa_host_keys_bind() {
    let fixtures = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/ssh_agent/fixtures");
    for name in ["rsa2048", "ecdsa_p256"] {
        let host = PrivateKey::read_openssh_file(fixtures.join(name)).unwrap();
        let kh = format!("github.com {}\n", host.public_key().to_openssh().unwrap());
        let a = logins(&["github.com"]);
        let login = sign(&login_data(SESSION, "git", PK, None));
        let msgs = [bind(&host, SESSION, false), login.clone()];
        assert_eq!(run(&a, &kh, &msgs), Verdict::Relay, "{name}");
        let wrong = [bind_signed_by(&host, &key(1), SESSION, false), login];
        assert_eq!(run(&a, &kh, &wrong), Verdict::Fail, "{name}");
    }
}

/// A fake host agent on a Unix socket under /tmp (never the developer's): answers every
/// message with its type plus one, and records what it received.
struct FakeAgent {
    dir: tempfile::TempDir,
    seen: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl FakeAgent {
    fn start() -> FakeAgent {
        let dir = short_dir();
        let listener = UnixListener::bind(dir.path().join("host.sock")).unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let s = seen.clone();
        thread::spawn(move || {
            for conn in listener.incoming() {
                let Ok(mut conn) = conn else { return };
                let s = s.clone();
                thread::spawn(move || {
                    let stop = AtomicBool::new(false);
                    while let Some(msg) = read_message(&conn, IDLE, &stop) {
                        s.lock().unwrap().push(msg.clone());
                        // The reply to an extension (a session binding) is `SSH_AGENT_SUCCESS`.
                        let reply = if msg[0] == EXTENSION {
                            vec![6]
                        } else {
                            vec![msg[0] + 1, b'k']
                        };
                        conn.write_all(&[&(reply.len() as u32).to_be_bytes()[..], &reply].concat())
                            .unwrap();
                    }
                });
            }
        });
        FakeAgent { dir, seen }
    }

    fn path(&self) -> PathBuf {
        self.dir.path().join("host.sock")
    }

    fn seen(&self) -> Vec<Vec<u8>> {
        self.seen.lock().unwrap().clone()
    }
}

/// macOS caps socket paths near 104 bytes: keep them under /tmp. Private, as a socket's
/// directory must be.
fn short_dir() -> tempfile::TempDir {
    use std::os::unix::fs::PermissionsExt;
    tempfile::Builder::new()
        .prefix("sbt")
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir_in("/tmp")
        .unwrap()
}

struct Served {
    _config: tempfile::TempDir,
    paths: Paths,
    dir: tempfile::TempDir,
    server: Option<Server>,
}

impl Served {
    fn socket(&self) -> PathBuf {
        self.dir.path().join("agent.sock")
    }

    fn connect(&self) -> UnixStream {
        let c = UnixStream::connect(self.socket()).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        c
    }
}

fn serve_with(access: Access, agent: &FakeAgent, env: &[(&str, &str)]) -> Served {
    let (config, paths) = crate::config::test_paths();
    let mut map = BTreeMap::from([(
        "SSH_AUTH_SOCK".to_string(),
        agent.path().display().to_string(),
    )]);
    map.extend(env.iter().map(|(k, v)| (k.to_string(), v.to_string())));
    let dir = short_dir();
    let backing = Backing {
        paths: paths.clone(),
        env: map,
    };
    let server = serve(&dir.path().join("agent.sock"), access, backing)
        .unwrap()
        .unwrap();
    Served {
        _config: config,
        paths,
        dir,
        server: Some(server),
    }
}

/// Sends `msg` framed and returns the framed answer's message, `None` when the connection
/// closed instead.
fn ask(c: &mut UnixStream, msg: &[u8]) -> Option<Vec<u8>> {
    write_message(c, msg).ok()?;
    read_reply(c)
}

fn read_reply(c: &mut UnixStream) -> Option<Vec<u8>> {
    let mut len = [0; 4];
    c.read_exact(&mut len).ok()?;
    let mut msg = vec![0; u32::from_be_bytes(len) as usize];
    c.read_exact(&mut msg).ok()?;
    Some(msg)
}

/// The other end closed it (not a read timeout).
fn closed(c: &mut UnixStream) -> bool {
    let mut b = [0; 1];
    match c.read(&mut b) {
        Ok(n) => n == 0,
        Err(e) => e.kind() == std::io::ErrorKind::ConnectionReset,
    }
}

#[test]
fn relays_admitted_requests_and_answers_the_rest_itself() {
    let agent = FakeAgent::start();
    let served = serve_with(only(&["git"]), &agent, &[]);
    let mut c = served.connect();
    assert_eq!(ask(&mut c, &[REQUEST_IDENTITIES]).unwrap(), [12, b'k']);
    assert_eq!(ask(&mut c, &sign(&sshsig(b"git"))).unwrap(), [14, b'k']);
    assert_eq!(ask(&mut c, &sign(&sshsig(b"file"))).unwrap(), [FAILURE]);
    assert_eq!(ask(&mut c, &sign(b"login")).unwrap(), [FAILURE]);
    assert_eq!(ask(&mut c, &[19]).unwrap(), [FAILURE], "remove all");
    assert_eq!(ask(&mut c, &extension(SESSION_BIND)).unwrap(), [6]);
    assert_eq!(ask(&mut c, &extension(b"query")).unwrap(), [FAILURE]);
    // Only the admitted ones reached the host agent, unchanged.
    assert_eq!(
        agent.seen(),
        vec![
            vec![REQUEST_IDENTITIES],
            sign(&sshsig(b"git")),
            extension(SESSION_BIND)
        ]
    );
}

#[test]
fn a_login_is_relayed_only_with_a_binding_from_this_connection_and_the_known_hosts_file() {
    let agent = FakeAgent::start();
    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir(home.path().join(".ssh")).unwrap();
    let hosts = home.path().join(".ssh/known_hosts");
    let env = [("HOME", home.path().to_str().unwrap())];
    let served = serve_with(logins(&["github.com"]), &agent, &env);
    let b = bind(&key(1), SESSION, false);
    let login = sign(&login_data(SESSION, "git", PK, None));

    // The default `~/.ssh/known_hosts` is missing: no keys, no login.
    let mut c = served.connect();
    assert_eq!(ask(&mut c, &b).unwrap(), [6]);
    assert_eq!(ask(&mut c, &login).unwrap(), [FAILURE]);
    // Edits apply to the next login on the same connection.
    std::fs::write(&hosts, known(&[("github.com", 1)])).unwrap();
    assert_eq!(ask(&mut c, &login).unwrap(), [14, b'k']);
    // Another connection has no binding.
    let mut other = served.connect();
    assert_eq!(ask(&mut other, &login).unwrap(), [FAILURE]);
    assert_eq!(agent.seen(), vec![b, login]);

    // The setting names another file.
    let other_file = home.path().join("hosts2");
    std::fs::write(&other_file, known(&[("github.com", 2)])).unwrap();
    let env = [
        ("HOME", home.path().to_str().unwrap()),
        (
            "SMOLBENTO_SSH_KNOWN_HOSTS_FILE",
            other_file.to_str().unwrap(),
        ),
    ];
    let served = serve_with(logins(&["github.com"]), &agent, &env);
    let mut c = served.connect();
    ask(&mut c, &bind(&key(1), SESSION, false)).unwrap();
    let again = sign(&login_data(SESSION, "git", PK, None));
    assert_eq!(ask(&mut c, &again).unwrap(), [FAILURE]);
}

#[test]
fn oversize_or_malformed_messages_close_the_connection() {
    let agent = FakeAgent::start();
    let served = serve_with(all(), &agent, &[]);
    let mut c = served.connect();
    c.write_all(&((MAX_MESSAGE + 1) as u32).to_be_bytes())
        .unwrap();
    assert!(closed(&mut c));
    let mut c = served.connect();
    c.write_all(&0u32.to_be_bytes()).unwrap();
    assert!(closed(&mut c));
    let mut c = served.connect();
    assert_eq!(ask(&mut c, &[SIGN_REQUEST, 0, 0, 0, 9]), None);
    // A message at the cap is fine.
    let mut c = served.connect();
    let big = [&[REQUEST_IDENTITIES][..], &vec![0; MAX_MESSAGE - 1]].concat();
    assert_eq!(ask(&mut c, &big).unwrap(), [12, b'k']);
    assert_eq!(agent.seen(), vec![big]);
}

#[test]
fn forwarding_turned_off_refuses_new_connections_but_not_open_ones() {
    let agent = FakeAgent::start();
    let served = serve_with(all(), &agent, &[]);
    let mut open = served.connect();
    assert!(ask(&mut open, &[REQUEST_IDENTITIES]).is_some());
    let (mut settings, _) = Settings::load(&served.paths, BTreeMap::new());
    settings.set("ssh.agentForwardingEnabled", "false").unwrap();
    let mut new = served.connect();
    assert_eq!(ask(&mut new, &[REQUEST_IDENTITIES]), None);
    assert!(ask(&mut open, &[REQUEST_IDENTITIES]).is_some());
    settings.set("ssh.agentForwardingEnabled", "true").unwrap();
    let mut again = served.connect();
    assert!(ask(&mut again, &[REQUEST_IDENTITIES]).is_some());
}

#[test]
fn one_connection_on_any_socket_is_relayed_as_a_unit_serves_it() {
    let agent = FakeAgent::start();
    let (_config, paths) = crate::config::test_paths();
    let backing = |sock: &str| Backing {
        paths: paths.clone(),
        env: BTreeMap::from([("SSH_AUTH_SOCK".to_string(), sock.to_string())]),
    };
    let (mut client, server) = UnixStream::pair().unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let b = backing(agent.path().to_str().unwrap());
    let t = thread::spawn(move || serve_connection(&server, &only(&["git"]), &b));
    assert_eq!(ask(&mut client, &[REQUEST_IDENTITIES]).unwrap(), [12, b'k']);
    assert_eq!(
        ask(&mut client, &sign(&sshsig(b"file"))).unwrap(),
        [FAILURE]
    );
    drop(client);
    t.join().unwrap();
    assert_eq!(agent.seen(), vec![vec![REQUEST_IDENTITIES]]);
    // With no host agent the connection is closed.
    let (mut client, server) = UnixStream::pair().unwrap();
    let b = backing("/tmp/sbt-no-such-agent.sock");
    serve_connection(&server, &all(), &b);
    drop(server);
    assert_eq!(ask(&mut client, &[REQUEST_IDENTITIES]), None);
}

#[test]
fn no_host_agent_refuses_connections() {
    let agent = FakeAgent::start();
    for env in [
        [("SMOLBENTO_SSH_AGENT_FORWARDING", "false")],
        [("SSH_AUTH_SOCK", "/tmp/sbt-no-such-agent.sock")],
        [("SMOLBENTO_SSH_AGENT_FORWARDING", "maybe")],
    ] {
        let served = serve_with(all(), &agent, &env);
        let mut c = served.connect();
        assert_eq!(ask(&mut c, &[REQUEST_IDENTITIES]), None, "{env:?}");
    }
    assert!(agent.seen().is_empty());
}

#[test]
fn at_most_eight_connections_at_once() {
    let agent = FakeAgent::start();
    let served = serve_with(all(), &agent, &[]);
    let mut open: Vec<UnixStream> = (0..MAX_CONNECTIONS).map(|_| served.connect()).collect();
    for c in &mut open {
        assert!(ask(c, &[REQUEST_IDENTITIES]).is_some());
    }
    let mut ninth = served.connect();
    assert_eq!(ask(&mut ninth, &[REQUEST_IDENTITIES]), None);
    // A closed one frees its place.
    drop(open.pop());
    let mut c = (0..100)
        .find_map(|_| {
            thread::sleep(POLL);
            let mut c = served.connect();
            ask(&mut c, &[REQUEST_IDENTITIES]).map(|_| c)
        })
        .expect("a place frees up");
    assert!(ask(&mut c, &[REQUEST_IDENTITIES]).is_some());
}

#[test]
fn dropping_the_server_stops_serving_and_closes_connections() {
    let agent = FakeAgent::start();
    let mut served = serve_with(all(), &agent, &[]);
    let mut c = served.connect();
    assert!(ask(&mut c, &[REQUEST_IDENTITIES]).is_some());
    served.server.take();
    assert!(!served.socket().exists());
    assert!(UnixStream::connect(served.socket()).is_err());
    assert_eq!(ask(&mut c, &[REQUEST_IDENTITIES]), None);
    assert_eq!(agent.seen().len(), 1);
}

#[test]
fn another_session_serving_it_is_left_alone() {
    let agent = FakeAgent::start();
    let served = serve_with(all(), &agent, &[]);
    let backing = Backing {
        paths: served.paths.clone(),
        env: BTreeMap::new(),
    };
    assert!(serve(&served.socket(), all(), backing).unwrap().is_none());
    let mut c = served.connect();
    assert!(ask(&mut c, &[REQUEST_IDENTITIES]).is_some());
}
