//! `ssh proxy HOST`: what the `ProxyCommand` of `setup ssh` runs. stdout is the SSH protocol, so
//! nothing else may write to it.

use anyhow::{Context, Result, bail};

use super::{Ctx, SshCmd};
use crate::bridge;
use crate::ctx::Out;
use crate::provision;
use crate::sandbox;
use crate::smolvm::Runner;
use crate::ssh::server::{self, Target};

pub fn run<R: Runner>(ctx: &mut Ctx<R>, cmd: SshCmd) -> Result<i32> {
    let SshCmd::Proxy { host } = cmd;
    proxy(
        ctx,
        &host,
        tokio::io::join(tokio::io::stdin(), tokio::io::stdout()),
    )
}

/// The sandbox a host name means: `NAME.sbx`.
pub fn sandbox_of(host: &str) -> Result<&str> {
    let name = host
        .len()
        .checked_sub(".sbx".len())
        .filter(|&n| host.is_char_boundary(n) && host[n..].eq_ignore_ascii_case(".sbx"))
        .map(|n| &host[..n])
        .filter(|n| !n.is_empty());
    name.with_context(|| format!("'{host}' is not a sandbox host name (use NAME.sbx)"))
}

pub(crate) fn proxy<R, S>(ctx: &mut Ctx<R>, host: &str, stream: S) -> Result<i32>
where
    R: Runner,
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    // Whatever starting the sandbox prints must not reach the protocol stream.
    ctx.out = Out::Buffer(Default::default());
    let name = sandbox_of(host)?;
    let Some(mut sb) = sandbox::find(&ctx.vm, name)? else {
        bail!(
            "sandbox '{name}' not found; create the sandbox first (`{} create ... --name {name}`)",
            ctx.program
        );
    };
    provision::ensure_running(ctx, &mut sb)?;
    let spawner = ctx
        .vm
        .spawner()?
        .context("this smolvm runner can't serve SSH sessions")?;
    // Served for the connection's life, as for an attached session.
    let _bridge = bridge::attach(&ctx.env, &ctx.settings, &ctx.smolvm, &sb);
    let _agent = crate::ssh_agent::filter::attach(&ctx.env, &ctx.paths, &sb);
    let target = Target {
        spawner,
        machine: sb.machine.clone(),
        user: sb.meta.rec.session_user().to_string(),
        workdir: sb.workdir(),
        bridge: sb.meta.bridge,
        host_env: ctx.env.clone(),
    };
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let result = rt.block_on(server::serve(stream, target));
    // A blocking read of stdin may still be pending; don't wait for it.
    rt.shutdown_background();
    result?;
    Ok(0)
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::sync::Arc;

    use russh::client::{self, Handle};
    use russh::{Channel, ChannelMsg};

    use super::sandbox_of;
    use crate::testutil::*;

    #[test]
    fn host_names() {
        assert_eq!(sandbox_of("claude-proj.sbx").unwrap(), "claude-proj");
        assert_eq!(sandbox_of("my.app.SBX").unwrap(), "my.app");
        for bad in [".sbx", "proj", "proj.sbx.example.com", "sbx", ""] {
            assert!(sandbox_of(bad).is_err(), "{bad}");
        }
    }

    pub(crate) struct Client;

    impl client::Handler for Client {
        type Error = russh::Error;

        async fn check_server_key(
            &mut self,
            _key: &russh::keys::PublicKeyOrCertificate,
        ) -> Result<bool, Self::Error> {
            Ok(true)
        }
    }

    /// Runs `ssh proxy HOST` on this thread against a russh client (authenticated with `none`)
    /// running `f` on another; the proxy ends when the client drops its handle.
    pub(super) fn drive<F, Fut, T>(t: &mut TestEnv, host: &str, f: F) -> T
    where
        F: FnOnce(Handle<Client>) -> Fut + Send + 'static,
        Fut: Future<Output = T>,
        T: Send + 'static,
    {
        drive_as(t, host, true, f)
    }

    /// `drive`, optionally without the `none` authentication.
    pub(super) fn drive_as<F, Fut, T>(t: &mut TestEnv, host: &str, auth: bool, f: F) -> T
    where
        F: FnOnce(Handle<Client>) -> Fut + Send + 'static,
        Fut: Future<Output = T>,
        T: Send + 'static,
    {
        let (a, b) = tokio::io::duplex(64 * 1024);
        let client = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                let mut h = client::connect_stream(Arc::new(client::Config::default()), b, Client)
                    .await
                    .unwrap();
                assert!(!auth || h.authenticate_none("anyone").await.unwrap().success());
                tokio::time::timeout(std::time::Duration::from_secs(20), f(h))
                    .await
                    .expect("the client timed out")
            })
        });
        super::proxy(&mut t.ctx, host, a).unwrap();
        client.join().unwrap()
    }

    /// Everything a channel sends until it closes: (stdout, stderr, exit status, replies).
    pub(super) async fn collect(ch: &mut Channel<client::Msg>) -> (Vec<u8>, Vec<u8>, Option<u32>) {
        let (mut out, mut err, mut code) = (Vec::new(), Vec::new(), None);
        while let Some(m) = ch.wait().await {
            match m {
                ChannelMsg::Data { data } => out.extend_from_slice(&data),
                ChannelMsg::ExtendedData { data, .. } => err.extend_from_slice(&data),
                ChannelMsg::ExitStatus { exit_status } => code = Some(exit_status),
                ChannelMsg::Close => break,
                _ => {}
            }
        }
        (out, err, code)
    }

    /// A fake `smolvm` that records its arguments (one line per call) in `log`, drops everything up
    /// to and including the first `--`, and runs the rest on this host. `path`, when given, is the
    /// `PATH` the guest command sees.
    struct FakeSmolvm {
        dir: tempfile::TempDir,
    }

    impl FakeSmolvm {
        fn install(t: &TestEnv, path: Option<&str>) -> FakeSmolvm {
            use std::os::unix::fs::PermissionsExt;
            let dir = tempfile::tempdir().unwrap();
            let bin = dir.path().join("smolvm");
            let export = path
                .map(|p| format!("PATH='{p}'; export PATH\n"))
                .unwrap_or_default();
            let log = dir.path().join("argv");
            let script = format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\n{export}\
while [ \"$1\" != \"--\" ]; do shift; done\nshift\nexec \"$@\"\n",
                log.display()
            );
            std::fs::write(&bin, script).unwrap();
            std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
            t.runner().set_spawn_bin(&bin);
            FakeSmolvm { dir }
        }

        /// The arguments of each call so far.
        fn calls(&self) -> Vec<String> {
            std::fs::read_to_string(self.dir.path().join("argv"))
                .unwrap_or_default()
                .lines()
                .map(str::to_string)
                .collect()
        }
    }

    /// Symlinks to the named host programs in a new directory, for a `PATH` with only those.
    fn tools(names: &[&str]) -> (tempfile::TempDir, String) {
        let dir = tempfile::tempdir().unwrap();
        for n in names {
            let found = std::env::split_paths(&std::env::var_os("PATH").unwrap())
                .map(|d| d.join(n))
                .find(|p| p.is_file())
                .unwrap_or_else(|| panic!("{n} not installed"));
            std::os::unix::fs::symlink(found, dir.path().join(n)).unwrap();
        }
        let path = dir.path().display().to_string();
        (dir, path)
    }

    /// Reads from `ch` until the output holds `marker`; everything read so far.
    async fn read_until(ch: &mut Channel<client::Msg>, marker: &str) -> String {
        let mut seen = String::new();
        while !seen.contains(marker) {
            match ch.wait().await {
                Some(ChannelMsg::Data { data }) => seen.push_str(&String::from_utf8_lossy(&data)),
                Some(_) => {}
                None => panic!("channel ended before {marker:?}: {seen:?}"),
            }
        }
        seen
    }

    /// The next reply to a request on `ch`.
    async fn reply(ch: &mut Channel<client::Msg>) -> ChannelMsg {
        loop {
            match ch.wait().await {
                Some(m @ (ChannelMsg::Success | ChannelMsg::Failure)) => return m,
                Some(_) => {}
                None => panic!("channel ended without a reply"),
            }
        }
    }

    #[test]
    fn exec_returns_output_stderr_and_exit_status_as_the_session_user() {
        let mut t = test_env(&[]);
        t.running_proj();
        let fake = FakeSmolvm::install(&t, None);
        let got = drive(&mut t, "claude-proj.sbx", |h| async move {
            let mut ch = h.channel_open_session().await.unwrap();
            // sbx ignores env requests; so do we, and says yes.
            ch.set_env(true, "FOO", "bar").await.unwrap();
            assert!(matches!(reply(&mut ch).await, ChannelMsg::Success));
            ch.exec(true, "echo hi \"[$FOO]\"; echo to-err >&2; exit 3")
                .await
                .unwrap();
            assert!(matches!(reply(&mut ch).await, ChannelMsg::Success));
            collect(&mut ch).await
        });
        assert_eq!(got, (b"hi []\n".to_vec(), b"to-err\n".to_vec(), Some(3)));
        let calls = fake.calls();
        assert_eq!(calls.len(), 1);
        let line = &calls[0];
        assert!(
            line.starts_with("machine exec --name sbx-claude-proj -u agent -w /w/proj -i -- sh -c"),
            "{line}"
        );
        assert!(!line.contains("-e FOO") && !line.contains(" -t"), "{line}");
    }

    #[test]
    fn stdin_reaches_the_command_and_its_end_ends_it() {
        let mut t = test_env(&[]);
        t.running_proj();
        let _fake = FakeSmolvm::install(&t, None);
        let got = drive(&mut t, "claude-proj.sbx", |h| async move {
            let mut ch = h.channel_open_session().await.unwrap();
            ch.exec(true, "cat").await.unwrap();
            assert!(matches!(reply(&mut ch).await, ChannelMsg::Success));
            ch.data_bytes(&b"piped in"[..]).await.unwrap();
            ch.eof().await.unwrap();
            collect(&mut ch).await
        });
        assert_eq!(got, (b"piped in".to_vec(), Vec::new(), Some(0)));
    }

    #[test]
    fn a_shell_on_a_pty_follows_window_changes_and_returns_its_exit_status() {
        let mut t = test_env(&[("TZ", "Asia/Kolkata")]);
        t.running_proj();
        let fake = FakeSmolvm::install(&t, None);
        let (first, second, tty, code) = drive(&mut t, "claude-proj.sbx", |h| async move {
            let mut ch = h.channel_open_session().await.unwrap();
            ch.request_pty(true, "xterm-256color", 100, 30, 0, 0, &[])
                .await
                .unwrap();
            assert!(matches!(reply(&mut ch).await, ChannelMsg::Success));
            ch.request_shell(true).await.unwrap();
            assert!(matches!(reply(&mut ch).await, ChannelMsg::Success));
            // The markers are computed, so the echo of the typed line doesn't match them.
            ch.data_bytes(&b"stty size; echo A$((20+22))\r"[..])
                .await
                .unwrap();
            let first = read_until(&mut ch, "A42").await;
            ch.window_change(120, 40, 0, 0).await.unwrap();
            ch.data_bytes(&b"stty size; echo B$((20+22))\r"[..])
                .await
                .unwrap();
            let second = read_until(&mut ch, "B42").await;
            ch.data_bytes(&b"test -t 0 && echo C$((20+22)); exit 5\r"[..])
                .await
                .unwrap();
            let (rest, _, code) = collect(&mut ch).await;
            (
                first,
                second,
                String::from_utf8_lossy(&rest).into_owned(),
                code,
            )
        });
        assert!(first.contains("30 100"), "{first:?}");
        assert!(second.contains("40 120"), "{second:?}");
        assert!(tty.contains("C42"), "{tty:?}");
        assert_eq!(code, Some(5));
        let line = &fake.calls()[0];
        assert!(
            line.contains(" -w /w/proj -e TERM=xterm-256color -e TZ=Asia/Kolkata -i -t -- sh -c "),
            "{line}"
        );
        assert!(line.ends_with("exec \"$s\" -l"), "{line}");
    }

    #[test]
    fn subsystems_x11_and_remote_forwarding_are_refused() {
        let mut t = test_env(&[]);
        t.running_proj();
        let fake = FakeSmolvm::install(&t, None);
        let (sftp, x11, forward) = drive(&mut t, "claude-proj.sbx", |h| async move {
            let mut ch = h.channel_open_session().await.unwrap();
            ch.request_subsystem(true, "sftp").await.unwrap();
            let sftp = reply(&mut ch).await;
            ch.request_x11(true, false, "MIT-MAGIC-COOKIE-1", "00", 0)
                .await
                .unwrap();
            let x11 = reply(&mut ch).await;
            let forward = h.tcpip_forward("127.0.0.1", 0).await;
            (sftp, x11, forward.is_err())
        });
        assert!(matches!(sftp, ChannelMsg::Failure));
        assert!(matches!(x11, ChannelMsg::Failure));
        assert!(forward);
        assert!(fake.calls().is_empty());
    }

    #[test]
    fn a_second_command_on_one_channel_is_refused() {
        let mut t = test_env(&[]);
        t.running_proj();
        let _fake = FakeSmolvm::install(&t, None);
        let (second, out) = drive(&mut t, "claude-proj.sbx", |h| async move {
            let mut ch = h.channel_open_session().await.unwrap();
            ch.exec(true, "cat").await.unwrap();
            assert!(matches!(reply(&mut ch).await, ChannelMsg::Success));
            ch.exec(true, "echo second").await.unwrap();
            let second = reply(&mut ch).await;
            ch.eof().await.unwrap();
            (second, collect(&mut ch).await.0)
        });
        assert!(matches!(second, ChannelMsg::Failure));
        assert!(out.is_empty());
    }

    #[test]
    fn at_most_64_channels_are_open_at_once() {
        let mut t = test_env(&[]);
        t.running_proj();
        let _fake = FakeSmolvm::install(&t, None);
        let (first_64, the_65th) = drive(&mut t, "claude-proj.sbx", |h| async move {
            let mut open = Vec::new();
            for _ in 0..64 {
                open.push(h.channel_open_session().await);
            }
            let extra = h.channel_open_session().await.is_ok();
            (open.iter().all(Result::is_ok), extra)
        });
        assert!(first_64);
        assert!(!the_65th);
    }

    /// A local server that sends "hello ", reads 5 bytes, sends them back and closes. Returns its port.
    fn echo_server() -> u16 {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            if let Ok((mut s, _)) = listener.accept() {
                let _ = s.write_all(b"hello ");
                let mut buf = [0u8; 5];
                if s.read_exact(&mut buf).is_ok() {
                    let _ = s.write_all(&buf);
                }
            }
        });
        port
    }

    /// Forwards to `echo_server` through the proxy, with `path` as the guest's PATH; what comes
    /// back, and the calls made.
    fn forward(path: Option<&str>) -> (Vec<u8>, Vec<String>) {
        let mut t = test_env(&[]);
        t.running_proj();
        let fake = FakeSmolvm::install(&t, path);
        let port = echo_server();
        let out = drive(&mut t, "claude-proj.sbx", move |h| async move {
            let mut ch = h
                .channel_open_direct_tcpip("localhost", u32::from(port), "127.0.0.1", 1)
                .await
                .unwrap();
            ch.data_bytes(&b"world"[..]).await.unwrap();
            ch.eof().await.unwrap();
            let (out, _, code) = collect(&mut ch).await;
            // A forward has no exit status.
            assert_eq!(code, None);
            out
        });
        (out, fake.calls())
    }

    #[test]
    fn local_forwards_use_nc_in_the_guest() {
        let (_nc, path) = tools(&["sh", "nc"]);
        let (out, calls) = forward(Some(&path));
        assert_eq!(out, b"hello world");
        assert_eq!(calls.len(), 1);
        assert!(
            calls[0].starts_with(
                "machine exec --name sbx-claude-proj -u agent -w /w/proj -i -- sh -c "
            ),
            "{calls:?}"
        );
        assert!(calls[0].contains("exec nc 127.0.0.1 "), "{calls:?}");
    }

    #[test]
    fn local_forwards_fall_back_to_bash_dev_tcp() {
        let (_d, path) = tools(&["sh", "bash", "cat"]);
        assert_eq!(forward(Some(&path)).0, b"hello world");
    }

    #[test]
    fn a_forward_fails_when_the_guest_has_neither_nc_nor_bash() {
        let (_d, path) = tools(&["sh", "cat"]);
        assert_eq!(forward(Some(&path)).0, b"");
    }

    #[test]
    fn forwards_to_anything_but_guest_loopback_are_refused_and_start_nothing() {
        let mut t = test_env(&[]);
        t.running_proj();
        let fake = FakeSmolvm::install(&t, None);
        let refused = drive(&mut t, "claude-proj.sbx", |h| async move {
            let mut refused = Vec::new();
            for (host, port) in [("10.0.0.5", 80), ("example.com", 80), ("0.0.0.0", 80)] {
                refused.push(
                    h.channel_open_direct_tcpip(host, port, "127.0.0.1", 1)
                        .await
                        .is_err(),
                );
            }
            refused
        });
        assert_eq!(refused, [true, true, true]);
        assert!(fake.calls().is_empty());
    }

    #[test]
    fn only_auth_none_is_accepted() {
        let mut t = test_env(&[]);
        t.running_proj();
        let _fake = FakeSmolvm::install(&t, None);
        let ok = drive_as(&mut t, "claude-proj.sbx", false, |mut h| async move {
            let password = h.authenticate_password("agent", "x").await.unwrap();
            let none = h.authenticate_none("agent").await.unwrap();
            (password.success(), none.success())
        });
        assert_eq!(ok, (false, true));
    }

    #[test]
    fn a_stopped_sandbox_is_started_and_a_missing_one_is_an_error() {
        let mut t = test_env(&[]);
        t.machine("sbx-claude-proj", "stopped", &[("sbx.name", "claude-proj")]);
        let _fake = FakeSmolvm::install(&t, None);
        drive(&mut t, "claude-proj.sbx", |_| async {});
        assert!(
            t.calls()
                .contains(&"machine start -n sbx-claude-proj --branchable".to_string())
        );
        let mut t = test_env(&[]);
        t.no_machine();
        let (a, _b) = tokio::io::duplex(1024);
        let err = super::proxy(&mut t.ctx, "nope.sbx", a)
            .unwrap_err()
            .to_string();
        assert!(err.contains("create the sandbox first"), "{err}");
        assert!(t.stdout().is_empty());
    }
}
