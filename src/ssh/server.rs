//! The SSH server `ssh proxy` runs on stdin/stdout for one connection. There is no network
//! listener: OpenSSH's `ProxyCommand` starts this process as a child, so only the local user can
//! reach it, and it accepts the `none` method only. Sessions run `smolvm machine exec` in the
//! sandbox; nothing about their data is logged.

use std::collections::{BTreeMap, HashMap};
use std::io::{Read, Write};
use std::net::IpAddr;
use std::sync::Arc;

use russh::server::{Auth, Config, Handle, Handler, Msg, Session};
use russh::{Channel, ChannelId, MethodKind};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;

use crate::sandbox::env::session_env;
use crate::smolvm::{ExecSpec, Proc, ProcCtl, ProcessSpawner, Pty};

/// Concurrent channels (sessions and forwards) per connection. The client is the local user, but
/// each channel is a process.
const MAX_CHANNELS: usize = 64;

/// What the server connects clients to.
pub struct Target {
    pub spawner: ProcessSpawner,
    /// The smolvm machine name.
    pub machine: String,
    /// The session user (`Meta::session_user`).
    pub user: String,
    pub workdir: String,
    /// Whether the sandbox has the browser bridge (`BROWSER` for sessions).
    pub bridge: bool,
    /// This process's environment, for `session_env`.
    pub host_env: BTreeMap<String, String>,
}

/// Serves one SSH connection on `stream` until the client goes away.
pub async fn serve<S>(stream: S, target: Target) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // A fresh key per connection: the transport is a pipe to our own child process, so there is
    // no host to impersonate and nothing to remember.
    let key = russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519)?;
    let config = Config {
        methods: [MethodKind::None][..].into(),
        keys: vec![key],
        // A tunnel can sit idle; the connection ends when `ssh` closes the pipe.
        inactivity_timeout: None,
        ..Config::default()
    };
    let conn = Conn {
        target: Arc::new(target),
        chans: HashMap::new(),
    };
    let session = russh::server::run_stream(Arc::new(config), stream, conn).await?;
    // The client closing the pipe is how a connection normally ends.
    let _ = session.await;
    Ok(())
}

/// The guest command for a session: the session user's login shell (`-l`), or that shell running
/// `command` (`-c`), as sshd does. Falls back to `/bin/sh` when the passwd entry has no shell.
pub fn shell_command(command: Option<&str>) -> Vec<String> {
    const FIND: &str =
        r#"s=$(getent passwd "$(id -un)" 2>/dev/null | cut -d: -f7); [ -x "$s" ] || s=/bin/sh; "#;
    let sh = |s: String| vec!["sh".to_string(), "-c".into(), s];
    match command {
        None => sh(format!("{FIND}exec \"$s\" -l")),
        Some(c) => {
            let mut v = sh(format!("{FIND}exec \"$s\" -c \"$1\""));
            v.extend(["sh".into(), c.into()]);
            v
        }
    }
}

/// Where a `direct-tcpip` request may go: the sandbox's own loopback (`localhost`, `127.0.0.0/8`,
/// `::1`), nothing else. Returns the address to connect to in the guest.
pub fn forward_address(host: &str, port: u32) -> Option<(IpAddr, u16)> {
    let port = u16::try_from(port).ok().filter(|&p| p != 0)?;
    let addr = if host.eq_ignore_ascii_case("localhost") {
        IpAddr::from([127, 0, 0, 1])
    } else {
        host.parse::<IpAddr>().ok().filter(IpAddr::is_loopback)?
    };
    Some((addr, port))
}

/// The guest command that connects its stdin and stdout to `addr:port`: `nc` if there is one, else
/// bash's `/dev/tcp`, else it says so and exits 127. `addr` and `port` are parsed values, so
/// nothing in them is shell syntax.
pub fn forward_command((addr, port): (IpAddr, u16)) -> Vec<String> {
    let script = format!(
        "if command -v nc >/dev/null 2>&1; then exec nc {addr} {port}; \
elif command -v bash >/dev/null 2>&1; then exec bash -c \
'exec 3<>/dev/tcp/{addr}/{port} || exit 1; cat <&3 & r=$!; cat <&0 >&3 & w=$!; wait $r; kill $w 2>/dev/null; exit 0'; \
else exit {NO_FORWARD_TOOLS}; fi"
    );
    vec!["sh".into(), "-c".into(), script]
}

/// The exit code of a forward command when the guest has neither `nc` nor bash.
const NO_FORWARD_TOOLS: i32 = 127;

struct PtyReq {
    term: String,
    size: Pty,
}

#[derive(Default)]
struct Chan {
    pty: Option<PtyReq>,
    run: Option<Running>,
}

struct Running {
    /// Bytes for the process's stdin; dropped on the client's EOF.
    stdin: Option<mpsc::Sender<Vec<u8>>>,
    ctl: Arc<ProcCtl>,
    pty: bool,
}

struct Conn {
    target: Arc<Target>,
    chans: HashMap<ChannelId, Chan>,
}

impl Drop for Conn {
    fn drop(&mut self) {
        for run in self.chans.values().filter_map(|c| c.run.as_ref()) {
            run.ctl.kill();
        }
    }
}

fn size(cols: u32, rows: u32) -> Pty {
    let clamp = |n: u32| u16::try_from(n).unwrap_or(u16::MAX).max(1);
    Pty {
        cols: clamp(cols),
        rows: clamp(rows),
    }
}

impl Conn {
    /// Runs `command` (the login shell when `None`) for the session channel `ch`.
    fn start_session(
        &mut self,
        ch: ChannelId,
        command: Option<&str>,
        handle: Handle,
    ) -> Result<(), String> {
        let t = &self.target;
        let chan = self.chans.get_mut(&ch).ok_or("no such channel")?;
        if chan.run.is_some() {
            return Err("this channel already runs a command".into());
        }
        let tty = chan.pty.is_some();
        let mut env = Vec::new();
        if let Some(p) = &chan.pty {
            env.push(("TERM".to_string(), p.term.clone()));
        }
        session_env(&t.host_env, tty, t.bridge, &mut env);
        let spec = ExecSpec {
            name: t.machine.clone(),
            user: Some(t.user.clone()),
            workdir: Some(t.workdir.clone()),
            env,
            interactive: true,
            tty,
            detach: false,
            // `-i` streams the output as it is written.
            stream: false,
            cmd: shell_command(command),
        };
        let proc = t
            .spawner
            .spawn(&spec.to_args(), chan.pty.as_ref().map(|p| p.size))
            .map_err(|e| format!("{e:#}"))?;
        chan.run = Some(relay(proc, handle, ch, tty, Kind::Session));
        Ok(())
    }
}

/// What a relayed process is for.
#[derive(Clone, Copy)]
enum Kind {
    Session,
    /// A forward to this guest address; the guest's stderr is never passed on, and a failure is
    /// reported on our own stderr in fixed words.
    Forward(IpAddr, u16),
}

enum Ev {
    Out(Vec<u8>),
    Err(Vec<u8>),
    Exit(i32),
}

/// Relays between `proc` and channel `ch`: threads read its output (blocking pipes) into one
/// ordered queue that a task writes to the channel, followed by the exit status, EOF and close.
fn relay(proc: Proc, handle: Handle, ch: ChannelId, pty: bool, kind: Kind) -> Running {
    let Proc {
        stdin,
        stdout,
        stderr,
        ctl,
        wait,
    } = proc;
    let (in_tx, in_rx) = mpsc::channel::<Vec<u8>>(64);
    std::thread::spawn(move || {
        let (mut w, mut rx) = (stdin, in_rx);
        while let Some(bytes) = rx.blocking_recv() {
            if w.write_all(&bytes).and_then(|()| w.flush()).is_err() {
                break;
            }
        }
    });
    let (tx, mut rx) = mpsc::channel::<Ev>(32);
    let pump = |mut r: Box<dyn Read + Send>, tx: mpsc::Sender<Ev>, wrap: fn(Vec<u8>) -> Ev| {
        std::thread::spawn(move || {
            let mut buf = [0u8; 16 * 1024];
            while let Ok(n) = r.read(&mut buf) {
                if n == 0 || tx.blocking_send(wrap(buf[..n].to_vec())).is_err() {
                    break;
                }
            }
        })
    };
    let mut pumps = vec![pump(stdout, tx.clone(), Ev::Out)];
    pumps.extend(stderr.map(|e| pump(e, tx.clone(), Ev::Err)));
    std::thread::spawn(move || {
        let code = wait().unwrap_or(255);
        for p in pumps {
            let _ = p.join();
        }
        let _ = tx.blocking_send(Ev::Exit(code));
    });
    let killer = ctl.clone();
    tokio::spawn(async move {
        let (mut open, mut sent) = (true, false);
        while let Some(ev) = rx.recv().await {
            // Once the client is gone keep draining, so the pump threads can finish.
            match (ev, kind) {
                (Ev::Out(b), _) if open => {
                    sent = true;
                    open = handle.data(ch, b).await.is_ok();
                }
                (Ev::Err(b), Kind::Session) if open => {
                    open = handle.extended_data(ch, 1, b).await.is_ok();
                }
                (Ev::Exit(code), kind) => {
                    if !open {
                        break;
                    }
                    match kind {
                        Kind::Session => {
                            let status = u32::try_from(code).unwrap_or(255);
                            let _ = handle.exit_status_request(ch, status).await;
                        }
                        Kind::Forward(addr, port) if code != 0 && !sent => {
                            if code == NO_FORWARD_TOOLS {
                                eprintln!(
                                    "bento: can't forward to {addr}:{port}: the sandbox has neither nc nor bash"
                                );
                            } else {
                                eprintln!(
                                    "bento: can't forward to {addr}:{port}: the connection failed in the sandbox"
                                );
                            }
                        }
                        Kind::Forward(..) => {}
                    }
                    let _ = handle.eof(ch).await;
                    let _ = handle.close(ch).await;
                    break;
                }
                _ => {}
            }
            if !open {
                killer.kill();
            }
        }
    });
    Running {
        stdin: Some(in_tx),
        ctl,
        pty,
    }
}

impl Handler for Conn {
    type Error = russh::Error;

    async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: russh::server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if self.chans.len() >= MAX_CHANNELS {
            reply
                .reject(russh::ChannelOpenFailure::ResourceShortage)
                .await;
            return Ok(());
        }
        self.chans.insert(channel.id(), Chan::default());
        reply.accept().await;
        Ok(())
    }

    /// Local port forwarding, to the sandbox's loopback only.
    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: russh::server::ChannelOpenHandle,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        use russh::ChannelOpenFailure::{
            AdministrativelyProhibited, ConnectFailed, ResourceShortage,
        };
        let Some(to) = forward_address(host_to_connect, port_to_connect) else {
            reply.reject(AdministrativelyProhibited).await;
            return Ok(());
        };
        if self.chans.len() >= MAX_CHANNELS {
            reply.reject(ResourceShortage).await;
            return Ok(());
        }
        let t = &self.target;
        let spec = ExecSpec {
            name: t.machine.clone(),
            user: Some(t.user.clone()),
            workdir: Some(t.workdir.clone()),
            interactive: true,
            cmd: forward_command(to),
            ..ExecSpec::default()
        };
        match t.spawner.spawn(&spec.to_args(), None) {
            Ok(proc) => {
                let run = relay(
                    proc,
                    session.handle(),
                    channel.id(),
                    false,
                    Kind::Forward(to.0, to.1),
                );
                self.chans.insert(
                    channel.id(),
                    Chan {
                        pty: None,
                        run: Some(run),
                    },
                );
                reply.accept().await;
            }
            Err(e) => {
                eprintln!("bento: can't forward to {}:{}: {e:#}", to.0, to.1);
                reply.reject(ConnectFailed).await;
            }
        }
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        match self.chans.get_mut(&channel) {
            Some(c) if c.run.is_none() => {
                c.pty = Some(PtyReq {
                    term: term.to_string(),
                    size: size(col_width, row_height),
                });
                session.channel_success(channel)?;
            }
            _ => session.channel_failure(channel)?,
        }
        Ok(())
    }

    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(c) = self.chans.get_mut(&channel) {
            let new = size(col_width, row_height);
            if let Some(p) = &mut c.pty {
                p.size = new;
            }
            if let Some(r) = c.run.as_ref().filter(|r| r.pty) {
                r.ctl.resize(new);
            }
        }
        Ok(())
    }

    /// Acknowledged and ignored, as sbx does: the session environment is smolbento's.
    async fn env_request(
        &mut self,
        channel: ChannelId,
        _name: &str,
        _value: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.run(channel, None, session)
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        match std::str::from_utf8(data) {
            Ok(cmd) => self.run(channel, Some(cmd), session),
            Err(_) => Ok(session.channel_failure(channel)?),
        }
    }

    /// SFTP and the rest: refused.
    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        _name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_failure(channel)?;
        Ok(())
    }

    async fn x11_request(
        &mut self,
        channel: ChannelId,
        _single_connection: bool,
        _protocol: &str,
        _cookie: &str,
        _screen: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_failure(channel)?;
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let tx = self
            .chans
            .get(&channel)
            .and_then(|c| c.run.as_ref())
            .and_then(|r| r.stdin.clone());
        if let Some(tx) = tx {
            let _ = tx.send(data.to_vec()).await;
        }
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        // On a terminal, Ctrl-D is data; there is no end of input to deliver.
        if let Some(r) = self.chans.get_mut(&channel).and_then(|c| c.run.as_mut())
            && !r.pty
        {
            r.stdin = None;
        }
        Ok(())
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(r) = self.chans.remove(&channel).and_then(|c| c.run) {
            r.ctl.kill();
        }
        Ok(())
    }
}

impl Conn {
    fn run(
        &mut self,
        channel: ChannelId,
        command: Option<&str>,
        session: &mut Session,
    ) -> Result<(), russh::Error> {
        match self.start_session(channel, command, session.handle()) {
            Ok(()) => session.channel_success(channel),
            Err(e) => {
                // The client sees a failed request; the reason goes to our stderr, which
                // `ssh` shows.
                eprintln!("bento: {e}");
                session.channel_failure(channel)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{forward_address, shell_command};

    #[test]
    fn forwards_go_to_guest_loopback_only() {
        let ok = |h: &str, p| forward_address(h, p).map(|(a, p)| format!("{a}:{p}"));
        assert_eq!(ok("localhost", 80).as_deref(), Some("127.0.0.1:80"));
        assert_eq!(ok("LocalHost", 80).as_deref(), Some("127.0.0.1:80"));
        assert_eq!(ok("127.0.0.1", 8080).as_deref(), Some("127.0.0.1:8080"));
        assert_eq!(ok("127.9.9.9", 1).as_deref(), Some("127.9.9.9:1"));
        assert_eq!(ok("::1", 65535).as_deref(), Some("::1:65535"));
        for (host, port) in [
            ("10.0.0.1", 80),
            ("192.168.1.1", 80),
            ("0.0.0.0", 80),
            ("169.254.169.254", 80),
            ("example.com", 80),
            ("localhost.example.com", 80),
            ("::ffff:127.0.0.1", 80),
            ("::", 80),
            ("127.0.0.1; id", 80),
            ("127.1", 80),
            ("", 80),
            ("127.0.0.1", 0),
            ("127.0.0.1", 65536),
        ] {
            assert!(forward_address(host, port).is_none(), "{host}:{port}");
        }
    }

    #[test]
    fn shell_commands_pass_the_command_as_an_argument_not_as_script() {
        let c = shell_command(Some("echo 'hi'; id"));
        assert_eq!(&c[3..], ["sh", "echo 'hi'; id"]);
        assert!(!c[2].contains("echo"));
        assert!(shell_command(None)[2].ends_with("exec \"$s\" -l"));
    }
}
