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
use crate::bridge::listener::{self, DEADLINE, Deadline, POLL, Server, Stream};
use crate::config::{Paths, Settings};
use crate::host_service::MAX_CONNECTIONS;
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

    /// The settings as they are now; `None` when they can't be read.
    fn settings(&self) -> Option<Settings> {
        let (settings, error) = Settings::load(&self.paths, self.env.clone());
        error.is_none().then_some(settings)
    }

    /// The host agent for a new connection; `None` refuses it: forwarding is off, there's no
    /// agent, or the settings can't be read.
    fn agent(&self) -> Option<PathBuf> {
        agent::host_agent(&self.settings()?, &self.env).ok()?.ok()
    }

    /// The text of the host's `known_hosts` file (`ssh.knownHostsFile`), read afresh each time so
    /// edits apply to the next login. `None` (no keys, so no login) when it can't be read.
    fn known_hosts(&self) -> Option<String> {
        let path = self.settings()?.value("ssh.knownHostsFile").ok()?;
        let path = crate::util::expand_home(&path, &self.env)
            .ok()?
            .unwrap_or_else(|| path.into());
        let file = std::fs::File::open(path).ok()?;
        let mut text = String::new();
        file.take(MAX_KNOWN_HOSTS).read_to_string(&mut text).ok()?;
        Some(text)
    }
}

/// Serves the sandbox's runtime grant during a session (`run`, `exec`) until the result is
/// dropped. `None` when it has no runtime grant, a unit serves it (`sbx.service`) or another
/// session already serves it; problems only warn, and the guest's agent connections then fail.
pub fn attach(env: &BTreeMap<String, String>, paths: &Paths, sb: &Sandbox) -> Option<Server> {
    if sb.meta.service {
        return None;
    }
    let access = sb.meta.ssh_agent.as_ref()?.runtime.clone()?;
    serve_for(
        sb.name(),
        &crate::bridge::agent_socket(sb.name()),
        access,
        Backing::new(paths, env),
    )
}

/// Serves the one guest connection `guest`, as a unit's `_serve agent` does: relays it to the
/// host agent with the grant's filter until either side closes. A connection with no host agent
/// (forwarding off, none running) is closed.
pub fn serve_connection(guest: &UnixStream, access: &Access, backing: &Backing) {
    let Some(host) = backing.agent().and_then(|p| UnixStream::connect(p).ok()) else {
        return;
    };
    relay(guest, &host, access, backing, &AtomicBool::new(false));
}

/// Serves `access` on the sandbox `name`'s agent socket; problems only warn.
pub fn serve_for(name: &str, socket: &Path, access: Access, backing: Backing) -> Option<Server> {
    serve(socket, access, backing).unwrap_or_else(|e| {
        crate::warning!("{name}: no SSH agent: {e:#}");
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
    if guest.blocking().is_err() || host.blocking().is_err() {
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
    /// Once a connection carries a forwarding binding, it stays forwarded: later non-forwarding
    /// bindings and login signatures are refused even against host agents that don't enforce this.
    forwarded: bool,
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
            Some((key, data))
                if admitted(access, data)
                    || login_admitted(access, conn, known_hosts, key, data) =>
            {
                Verdict::Relay
            }
            Some(_) => Verdict::Fail,
        },
        EXTENSION => match string(payload) {
            None => Verdict::Close,
            Some((name, rest)) if name == SESSION_BIND => {
                // Bindings matter only to a grant with logins; others relay them.
                if access.authenticate.is_empty() {
                    return Verdict::Relay;
                }
                match binding(rest) {
                    // Remembered when verified and not for a forwarded agent. Once forwarding is
                    // observed on a connection, latch it and drop prior bindings so a compromised
                    // forwarded host can't downgrade against non-OpenSSH host agents.
                    Some((b, forwarding)) => {
                        if forwarding {
                            conn.forwarded = true;
                            conn.bindings.clear();
                            Verdict::Relay
                        } else if conn.forwarded {
                            Verdict::Fail
                        } else {
                            conn.bindings.push(b);
                            if conn.bindings.len() > MAX_BINDINGS {
                                conn.bindings.remove(0);
                            }
                            Verdict::Relay
                        }
                    }
                    None => Verdict::Fail,
                }
            }
            Some(_) => Verdict::Fail,
        },
        _ => Verdict::Fail,
    }
}

/// An unrestricted grant signs anything; a `sign` list only well-formed `PROTOCOL.sshsig`
/// payloads (`"SSHSIG"`, namespace, reserved, hash_algorithm, hash, with nothing trailing) in one
/// of its namespaces. Logins and other data don't start with `SSHSIG`.
fn admitted(access: &Access, data: &[u8]) -> bool {
    let Some(namespaces) = &access.sign else {
        return true;
    };
    let Some(rest) = data.strip_prefix(SSHSIG) else {
        return false;
    };
    let Some((ns, rest)) = string(rest) else {
        return false;
    };
    let Some((_reserved, rest)) = string(rest) else {
        return false;
    };
    let Some((hash_alg, rest)) = string(rest) else {
        return false;
    };
    let Some((hash, rest)) = string(rest) else {
        return false;
    };
    rest.is_empty()
        && !hash_alg.is_empty()
        && !hash.is_empty()
        && namespaces.iter().any(|n| n.as_bytes() == ns)
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
    key: &[u8],
    data: &[u8],
) -> bool {
    if conn.forwarded || access.sign.is_none() || access.authenticate.is_empty() {
        return false;
    }
    let Some(login) = login(key, data) else {
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
        // `user@host` or `host`, as the kit parser validated it.
        let (user, host) = dest
            .split_once('@')
            .map_or((None, dest.as_str()), |(u, h)| (Some(u), h));
        user.is_none_or(|u| u.as_bytes() == login.user)
            && host_keys(&text, host)
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
/// after. The key in the data must be the key the request signs with, and the algorithm must be
/// one that key makes. `None` for other methods and anything else.
fn login<'a>(request_key: &[u8], data: &'a [u8]) -> Option<Login<'a>> {
    let (session_id, rest) = string(data)?;
    let (&kind, rest) = rest.split_first()?;
    if kind != USERAUTH_REQUEST {
        return None;
    }
    let (user, rest) = string(rest)?;
    let (service, rest) = string(rest)?;
    if service != b"ssh-connection" {
        return None;
    }
    let (method, rest) = string(rest)?;
    let (&has_signature, rest) = rest.split_first()?;
    let (algorithm, rest) = string(rest)?;
    let (key, rest) = string(rest)?;
    if has_signature != 1 || key != request_key || !algorithm_fits(algorithm, key) {
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

/// Whether `algorithm` is one the public key blob `key` signs with: its own type name, and for
/// RSA also the SHA-2 variants (certificates likewise with their suffix).
fn algorithm_fits(algorithm: &[u8], key: &[u8]) -> bool {
    let Some((key_type, _)) = string(key) else {
        return false;
    };
    if algorithm == key_type {
        return true;
    }
    let cert = b"-cert-v01@openssh.com";
    let (base, suffix): (&[u8], &[u8]) = match key_type.strip_suffix(&cert[..]) {
        Some(base) => (base, &cert[..]),
        None => (key_type, b""),
    };
    base == b"ssh-rsa"
        && [&b"rsa-sha2-256"[..], b"rsa-sha2-512"]
            .iter()
            .any(|a| algorithm == [a, suffix].concat())
}

/// A sign request's key blob and data: `string key_blob, string data, uint32 flags`.
fn sign_data(payload: &[u8]) -> Option<(&[u8], &[u8])> {
    let (key, rest) = string(payload)?;
    let (data, rest) = string(rest)?;
    (rest.len() == 4).then_some((key, data))
}

/// The SSH string (`uint32` length, bytes) at the start of `b`, and what follows it.
fn string(b: &[u8]) -> Option<(&[u8], &[u8])> {
    let (len, rest) = b.split_first_chunk::<4>()?;
    let len = u32::from_be_bytes(*len) as usize;
    (rest.len() >= len).then(|| rest.split_at(len))
}

#[cfg(test)]
#[path = "filter_tests.rs"]
mod tests;
