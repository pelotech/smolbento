//! The SSH agent filter (`ssh-agent@1`): serves a sandbox's agent socket while a granted phase
//! runs, and relays to the host agent only listing keys, admitted signatures and session binding.
//! Nothing about keys or what is signed is logged.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::Result;
use signature::Verifier;
use ssh_key::public::KeyData;
use ssh_key::{PublicKey, Signature};

use super::known_hosts::host_keys;
use super::{self as agent, Access};
use crate::bridge::listener::{self, DEADLINE, Deadline, POLL, Server};
use crate::config::{Paths, Settings};
use crate::sandbox::Sandbox;

const FAILURE: u8 = 5;
/// `SSH_MSG_USERAUTH_REQUEST` (RFC 4252 section 7), the byte after the session id in a login's
/// signed data.
const USERAUTH_REQUEST: u8 = 50;
const PUBLICKEY: &[u8] = b"publickey";
const HOSTBOUND: &[u8] = b"publickey-hostbound-v00@openssh.com";
/// Verified bindings kept per connection; the oldest go first.
const MAX_BINDINGS: usize = 16;
/// The largest `known_hosts` file read.
const MAX_KNOWN_HOSTS: u64 = 16 << 20;
const REQUEST_IDENTITIES: u8 = 11;
const SIGN_REQUEST: u8 = 13;
const EXTENSION: u8 = 27;
const SESSION_BIND: &[u8] = b"session-bind@openssh.com";
/// The preamble of a namespaced signature's data (`ssh-keygen -Y sign`, PROTOCOL.sshsig).
const SSHSIG: &[u8] = b"SSHSIG";

/// A message (either way) above this closes the connection.
const MAX_MESSAGE: usize = 256 << 10;
/// Guest connections served at once; more are closed when they arrive.
const MAX_CONNECTIONS: usize = 8;
/// How long a connection may sit between requests: ssh keeps one open for its whole session.
const IDLE: Duration = Duration::from_secs(600);
/// How long the host agent may take to answer; it may ask the user to confirm a signature.
const AGENT_DEADLINE: Duration = Duration::from_secs(120);

/// Where a new guest connection finds the host agent. The settings are read again for each
/// connection, so turning `ssh.agentForwardingEnabled` off blocks new connections at once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Backing {
    paths: Paths,
    env: BTreeMap<String, String>,
}

impl Backing {
    /// Keeps only the env vars the host agent lookup reads, so the rest of the process env (which
    /// may hold secrets) is never carried in a plan, or printed with it.
    pub fn new(paths: &Paths, env: &BTreeMap<String, String>) -> Self {
        const KEPT: [&str; 5] = [
            "SSH_AUTH_SOCK",
            "SMOLBENTO_SSH_AGENT_SOCKET",
            "SMOLBENTO_SSH_AGENT_FORWARDING",
            "SMOLBENTO_SSH_KNOWN_HOSTS_FILE",
            "HOME",
        ];
        Backing {
            paths: paths.clone(),
            env: env
                .iter()
                .filter(|(k, _)| KEPT.contains(&k.as_str()))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        }
    }

    /// The host agent for a new connection; `None` refuses it: forwarding is off, there's no
    /// agent, or the settings can't be read.
    fn agent(&self) -> Option<PathBuf> {
        let (settings, error) = Settings::load(&self.paths, self.env.clone());
        if error.is_some() {
            return None;
        }
        agent::host_agent(&settings, &self.env).ok()?.ok()
    }

    /// The text of the host's `known_hosts` file (`ssh.knownHostsFile`), read afresh each time so
    /// edits apply to the next login. `None` (no keys, so no login) when it can't be read.
    fn known_hosts(&self) -> Option<String> {
        let (settings, error) = Settings::load(&self.paths, self.env.clone());
        if error.is_some() {
            return None;
        }
        let path = settings.value("ssh.knownHostsFile").ok()?;
        let path = match path.strip_prefix("~/") {
            Some(rest) => Path::new(self.env.get("HOME")?).join(rest),
            None => PathBuf::from(path),
        };
        let file = std::fs::File::open(path).ok()?;
        let mut text = String::new();
        file.take(MAX_KNOWN_HOSTS).read_to_string(&mut text).ok()?;
        Some(text)
    }
}

/// Serves the sandbox's runtime grant during a session (`run`, `exec`) until the result is
/// dropped. `None` when it has no runtime grant or another session already serves it; problems
/// only warn, and the guest's agent connections then fail.
pub fn attach(env: &BTreeMap<String, String>, paths: &Paths, sb: &Sandbox) -> Option<Server> {
    let access = sb.meta.ssh_agent.as_ref()?.runtime.clone()?;
    serve_for(sb.name(), access, Backing::new(paths, env))
}

/// Serves `access` on the sandbox `name`'s agent socket; problems only warn.
pub fn serve_for(name: &str, access: Access, backing: Backing) -> Option<Server> {
    serve(&crate::bridge::agent_socket(name), access, backing).unwrap_or_else(|e| {
        eprintln!("warning: {name}: no SSH agent: {e:#}");
        None
    })
}

/// Serves `path` until the returned `Server` is dropped, with the bridge's bind rules: `None`
/// when another session serves it, a stale socket is replaced, the directory must be ours.
fn serve(path: &Path, access: Access, backing: Backing) -> Result<Option<Server>> {
    listener::spawn(path, move |listener, stop| {
        accept_loop(listener, &stop, &access, &backing);
    })
}

/// Each guest connection gets its own thread and its own connection to the host agent, made at
/// accept time; at most `MAX_CONNECTIONS` at once.
fn accept_loop(listener: &UnixListener, stop: &Arc<AtomicBool>, access: &Access, b: &Backing) {
    let open = Arc::new(AtomicUsize::new(0));
    while !stop.load(Ordering::Relaxed) {
        let Ok((guest, _)) = listener.accept() else {
            thread::sleep(POLL);
            continue;
        };
        // Only this thread adds, so the check holds. A refused connection is closed (dropped).
        if open.load(Ordering::Relaxed) >= MAX_CONNECTIONS {
            continue;
        }
        let Some(host) = b.agent().and_then(|p| UnixStream::connect(p).ok()) else {
            continue;
        };
        open.fetch_add(1, Ordering::Relaxed);
        let (open, stop, access, b) = (open.clone(), stop.clone(), access.clone(), b.clone());
        thread::spawn(move || {
            relay(&guest, &host, &access, &b, &stop);
            open.fetch_sub(1, Ordering::Relaxed);
        });
    }
}

/// Relays one guest connection's requests, one at a time, until either side closes, a message is
/// malformed or too large, a deadline passes or the server stops.
fn relay(
    guest: &UnixStream,
    host: &UnixStream,
    access: &Access,
    backing: &Backing,
    stop: &AtomicBool,
) {
    // Accepted sockets inherit non-blocking mode on some systems.
    let blocking = |s: &UnixStream| {
        s.set_nonblocking(false)
            .and_then(|()| s.set_write_timeout(Some(DEADLINE)))
    };
    if blocking(guest).is_err() || blocking(host).is_err() {
        return;
    }
    let mut conn = Conn::default();
    while let Some(msg) = read_message(guest, IDLE, stop) {
        let reply = match verdict(access, &mut conn, &|| backing.known_hosts(), &msg) {
            Verdict::Relay => {
                if write_message(host, &msg).is_err() {
                    return;
                }
                match read_message(host, AGENT_DEADLINE, stop) {
                    Some(reply) => reply,
                    None => return,
                }
            }
            Verdict::Fail => vec![FAILURE],
            Verdict::Close => return,
        };
        if write_message(guest, &reply).is_err() {
            return;
        }
    }
}

/// One message (type byte and payload) without its length. The first byte may take `wait`, the
/// rest `DEADLINE`. `None` on a close, a timeout, a stop, or an empty or oversize message.
fn read_message(s: &UnixStream, wait: Duration, stop: &AtomicBool) -> Option<Vec<u8>> {
    let within = |d: Duration| Deadline {
        stream: s,
        until: Instant::now() + d,
        stop,
    };
    let mut len = [0; 4];
    within(wait).read_exact(&mut len[..1]).ok()?;
    within(DEADLINE).read_exact(&mut len[1..]).ok()?;
    let len = u32::from_be_bytes(len) as usize;
    if len == 0 || len > MAX_MESSAGE {
        return None;
    }
    let mut msg = vec![0; len];
    within(DEADLINE).read_exact(&mut msg).ok()?;
    Some(msg)
}

fn write_message(mut s: &UnixStream, msg: &[u8]) -> std::io::Result<()> {
    let len = u32::try_from(msg.len()).map_err(std::io::Error::other)?;
    s.write_all(&[&len.to_be_bytes()[..], msg].concat())
}

#[derive(Debug, PartialEq)]
enum Verdict {
    /// Send it to the host agent and its answer back.
    Relay,
    /// Answer `SSH_AGENT_FAILURE` without relaying it.
    Fail,
    /// Malformed: close the connection.
    Close,
}

/// A session binding this connection carried that checked out: the server's host key and the
/// session it signed.
#[derive(Debug, Clone, PartialEq)]
struct Binding {
    session_id: Vec<u8>,
    host_key: KeyData,
}

/// What one guest connection has told the agent so far.
#[derive(Debug, Default)]
struct Conn {
    /// Verified, non-forwarding bindings, newest last.
    bindings: Vec<Binding>,
}

/// What to do with one guest message (type byte and payload, never empty). `known_hosts` reads
/// the host's file only when a login needs it.
fn verdict(
    access: &Access,
    conn: &mut Conn,
    known_hosts: &dyn Fn() -> Option<String>,
    msg: &[u8],
) -> Verdict {
    let Some((&kind, payload)) = msg.split_first() else {
        return Verdict::Close;
    };
    match kind {
        REQUEST_IDENTITIES => Verdict::Relay,
        SIGN_REQUEST => match sign_data(payload) {
            None => Verdict::Close,
            Some(data)
                if admitted(access, data) || login_admitted(access, conn, known_hosts, data) =>
            {
                Verdict::Relay
            }
            Some(_) => Verdict::Fail,
        },
        EXTENSION => match string(payload) {
            None => Verdict::Close,
            Some((name, rest)) if name == SESSION_BIND => {
                // Bindings matter only to a grant with logins; others relay them as before.
                if access.authenticate.is_empty() {
                    return Verdict::Relay;
                }
                match binding(rest) {
                    // Remembered when verified and not for a forwarded agent. The host agent
                    // still gets it and answers as it would, so its own limits apply.
                    Some((b, forwarding)) => {
                        if !forwarding {
                            conn.bindings.push(b);
                            if conn.bindings.len() > MAX_BINDINGS {
                                conn.bindings.remove(0);
                            }
                        }
                        Verdict::Relay
                    }
                    None => Verdict::Fail,
                }
            }
            Some(_) => Verdict::Fail,
        },
        _ => Verdict::Fail,
    }
}

/// An unrestricted grant signs anything; a `sign` list only namespaced signatures (`SSHSIG`) in
/// one of its namespaces. Logins and other data don't start with `SSHSIG`.
fn admitted(access: &Access, data: &[u8]) -> bool {
    let Some(namespaces) = &access.sign else {
        return true;
    };
    data.strip_prefix(SSHSIG)
        .and_then(string)
        .is_some_and(|(ns, _)| namespaces.iter().any(|n| n.as_bytes() == ns))
}

/// A `session-bind@openssh.com` body after the extension name (`string hostkey, string
/// session_id, string signature, bool is_forwarding`, PROTOCOL.agent): the binding when the host
/// key's signature over the session id verifies, and whether it is for a forwarded agent. `None`
/// for anything malformed or unverifiable.
fn binding(body: &[u8]) -> Option<(Binding, bool)> {
    let (key, rest) = string(body)?;
    let (session_id, rest) = string(rest)?;
    let (sig, rest) = string(rest)?;
    let [forwarding] = rest else { return None };
    let host_key = PublicKey::from_bytes(key).ok()?.key_data().clone();
    let sig = Signature::try_from(sig).ok()?;
    host_key.verify(session_id, &sig).ok()?;
    Some((
        Binding {
            session_id: session_id.to_vec(),
            host_key,
        },
        *forwarding != 0,
    ))
}

/// A login signature (RFC 4252 section 7 data) the grant admits, by the spec's rules: a binding
/// this connection verified for the data's session id, whose host key is one `known_hosts` lists
/// for a server in `authenticate` (an entry naming a user needs that user), and for the hostbound
/// method the data's host key is the binding's. Anything unparseable or unknown is refused.
fn login_admitted(
    access: &Access,
    conn: &Conn,
    known_hosts: &dyn Fn() -> Option<String>,
    data: &[u8],
) -> bool {
    if access.sign.is_none() || access.authenticate.is_empty() {
        return false;
    }
    let Some(login) = login(data) else {
        return false;
    };
    let bound: Vec<&Binding> = conn
        .bindings
        .iter()
        .filter(|b| b.session_id == login.session_id)
        .filter(|b| login.host_key.as_ref().is_none_or(|k| *k == b.host_key))
        .collect();
    if bound.is_empty() {
        return false;
    }
    let Some(text) = known_hosts() else {
        return false;
    };
    access.authenticate.iter().any(|dest| {
        dest.user
            .as_ref()
            .is_none_or(|u| u.as_bytes() == login.user)
            && host_keys(&text, &dest.host)
                .iter()
                .any(|k| bound.iter().any(|b| b.host_key == *k))
    })
}

/// The parts of a login's signed data the rules look at.
struct Login<'a> {
    session_id: &'a [u8],
    user: &'a [u8],
    /// The host key in the data, for the hostbound method.
    host_key: Option<KeyData>,
}

/// Parses `string session_id, byte 50, string user, string service, string method, bool true,
/// string algorithm, string key` and, for the hostbound method, `string hostkey`, with nothing
/// after. `None` for other methods and anything else.
fn login(data: &[u8]) -> Option<Login<'_>> {
    let (session_id, rest) = string(data)?;
    let (&kind, rest) = rest.split_first()?;
    if kind != USERAUTH_REQUEST {
        return None;
    }
    let (user, rest) = string(rest)?;
    let (_service, rest) = string(rest)?;
    let (method, rest) = string(rest)?;
    let (&has_signature, rest) = rest.split_first()?;
    let (_algorithm, rest) = string(rest)?;
    let (_key, rest) = string(rest)?;
    if has_signature != 1 {
        return None;
    }
    let host_key = match method {
        m if m == PUBLICKEY && rest.is_empty() => None,
        m if m == HOSTBOUND => {
            let (host_key, rest) = string(rest)?;
            if !rest.is_empty() {
                return None;
            }
            Some(PublicKey::from_bytes(host_key).ok()?.key_data().clone())
        }
        _ => return None,
    };
    Some(Login {
        session_id,
        user,
        host_key,
    })
}

/// A sign request's data: `string key_blob, string data, uint32 flags`.
fn sign_data(payload: &[u8]) -> Option<&[u8]> {
    let (_key, rest) = string(payload)?;
    let (data, rest) = string(rest)?;
    (rest.len() == 4).then_some(data)
}

/// The SSH string (`uint32` length, bytes) at the start of `b`, and what follows it.
fn string(b: &[u8]) -> Option<(&[u8], &[u8])> {
    let (len, rest) = b.split_first_chunk::<4>()?;
    let len = u32::from_be_bytes(*len) as usize;
    (rest.len() >= len).then(|| rest.split_at(len))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn s(b: &[u8]) -> Vec<u8> {
        [&(b.len() as u32).to_be_bytes()[..], b].concat()
    }

    fn sign(data: &[u8]) -> Vec<u8> {
        [
            &[SIGN_REQUEST][..],
            &s(b"key"),
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

    use crate::ssh_agent::Dest;
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

    fn bind_signed_by(
        host: &PrivateKey,
        signer: &PrivateKey,
        session: &[u8],
        fwd: bool,
    ) -> Vec<u8> {
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
    fn login_data(
        session: &[u8],
        user: &str,
        method: &[u8],
        hostkey: Option<&PrivateKey>,
    ) -> Vec<u8> {
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
            authenticate: entries.iter().map(|e| Dest::parse(e)).collect(),
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
        let fixtures =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/ssh_agent/fixtures");
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
                            conn.write_all(
                                &[&(reply.len() as u32).to_be_bytes()[..], &reply].concat(),
                            )
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
}
