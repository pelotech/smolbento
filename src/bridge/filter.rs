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

use super::agent::{self, Access};
use super::server::{self, DEADLINE, Deadline, POLL, Server};
use crate::config::{Paths, Settings};
use crate::sandbox::Sandbox;

const FAILURE: u8 = 5;
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
        const KEPT: [&str; 3] = [
            "SSH_AUTH_SOCK",
            "SMOLBENTO_SSH_AGENT_SOCKET",
            "SMOLBENTO_SSH_AGENT_FORWARDING",
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
}

/// Serves the sandbox's runtime grant during a session (`run`, `exec`) until the result is
/// dropped. `None` when it has no runtime grant or another session already serves it; problems
/// only warn, and the guest's agent connections then fail.
pub fn attach(paths: &Paths, env: &BTreeMap<String, String>, sb: &Sandbox) -> Option<Server> {
    let access = sb.meta.ssh_agent.as_ref()?.runtime.clone()?;
    serve_for(sb.name(), access, Backing::new(paths, env))
}

/// Serves `access` on the sandbox `name`'s agent socket; problems only warn.
pub fn serve_for(name: &str, access: Access, backing: Backing) -> Option<Server> {
    serve(&super::agent_socket(name), access, backing).unwrap_or_else(|e| {
        eprintln!("warning: {name}: no SSH agent: {e:#}");
        None
    })
}

/// Serves `path` until the returned `Server` is dropped, with the bridge's bind rules: `None`
/// when another session serves it, a stale socket is replaced, the directory must be ours.
pub fn serve(path: &Path, access: Access, backing: Backing) -> Result<Option<Server>> {
    server::spawn(path, move |listener, stop| {
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
        let (open, stop, access) = (open.clone(), stop.clone(), access.clone());
        thread::spawn(move || {
            relay(&guest, &host, &access, &stop);
            open.fetch_sub(1, Ordering::Relaxed);
        });
    }
}

/// Relays one guest connection's requests, one at a time, until either side closes, a message is
/// malformed or too large, a deadline passes or the server stops.
fn relay(guest: &UnixStream, host: &UnixStream, access: &Access, stop: &AtomicBool) {
    // Accepted sockets inherit non-blocking mode on some systems.
    let blocking = |s: &UnixStream| {
        s.set_nonblocking(false)
            .and_then(|()| s.set_write_timeout(Some(DEADLINE)))
    };
    if blocking(guest).is_err() || blocking(host).is_err() {
        return;
    }
    while let Some(msg) = read_message(guest, IDLE, stop) {
        let reply = match verdict(access, &msg) {
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

/// What to do with one guest message (type byte and payload, never empty).
fn verdict(access: &Access, msg: &[u8]) -> Verdict {
    let Some((&kind, payload)) = msg.split_first() else {
        return Verdict::Close;
    };
    match kind {
        REQUEST_IDENTITIES => Verdict::Relay,
        SIGN_REQUEST => match sign_data(payload) {
            None => Verdict::Close,
            Some(data) if admitted(access, data) => Verdict::Relay,
            Some(_) => Verdict::Fail,
        },
        EXTENSION => match string(payload) {
            None => Verdict::Close,
            Some((name, _)) if name == SESSION_BIND => Verdict::Relay,
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

    fn all() -> Access {
        Access { sign: None }
    }

    fn only(namespaces: &[&str]) -> Access {
        Access {
            sign: Some(namespaces.iter().map(|n| n.to_string()).collect()),
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
                            let reply = [msg[0] + 1, b'k'];
                            conn.write_all(&[&2u32.to_be_bytes()[..], &reply].concat())
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

    /// macOS caps socket paths near 104 bytes: keep them under /tmp.
    fn short_dir() -> tempfile::TempDir {
        tempfile::Builder::new()
            .prefix("sbt")
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
        assert_eq!(ask(&mut c, &extension(SESSION_BIND)).unwrap(), [28, b'k']);
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
