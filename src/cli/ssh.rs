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
        .spawner()
        .context("this smolvm runner can't serve SSH sessions")?;
    // Served for the connection's life, as for an attached session.
    let _bridge = bridge::attach(&ctx.env, &ctx.settings, &sb);
    let _agent = crate::ssh_agent::filter::attach(&ctx.env, &ctx.paths, &sb);
    let target = Target {
        spawner,
        machine: sb.machine.clone(),
        user: sb.meta.session_user().to_string(),
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
    use crate::smolvm::fake::Script;
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

    fn running(t: &TestEnv) {
        t.sandbox("claude-proj", "running", &[("sbx.workspace", "/w/proj")]);
    }

    #[test]
    fn exec_returns_output_and_exit_status_as_the_session_user() {
        let mut t = test_env(&[]);
        running(&t);
        t.runner().spawns().on(
            "echo hi",
            Script {
                stdout: b"hi\n".to_vec(),
                stderr: b"warn\n".to_vec(),
                code: 3,
                ..Script::default()
            },
        );
        let got = drive(&mut t, "claude-proj.sbx", |h| async move {
            let mut ch = h.channel_open_session().await.unwrap();
            // sbx ignores env requests; so do we, and says yes.
            ch.set_env(true, "FOO", "bar").await.unwrap();
            assert!(matches!(ch.wait().await, Some(ChannelMsg::Success)));
            ch.exec(true, "echo hi").await.unwrap();
            assert!(matches!(ch.wait().await, Some(ChannelMsg::Success)));
            collect(&mut ch).await
        });
        assert_eq!(got, (b"hi\n".to_vec(), b"warn\n".to_vec(), Some(3)));
        let spawned = t.runner().spawns().spawned();
        let line = spawned[0].args.join(" ");
        assert!(
            line.starts_with("machine exec --name sbx-claude-proj -u agent -w /w/proj -i -- sh -c"),
            "{line}"
        );
        assert!(line.ends_with(" sh echo hi"), "{line}");
        assert!(!line.contains("FOO") && !line.contains(" -t "), "{line}");
        assert_eq!(spawned[0].pty, None);
    }

    #[test]
    fn a_shell_on_a_pty_is_the_login_shell_and_follows_window_changes() {
        let mut t = test_env(&[("TZ", "Asia/Kolkata")]);
        running(&t);
        t.runner().spawns().on(
            "-l",
            Script {
                stdout: b"$ ".to_vec(),
                echo: true,
                exit_on: Some(b"exit\r".to_vec()),
                ..Script::default()
            },
        );
        let (out, code) = drive(&mut t, "claude-proj.sbx", |h| async move {
            let mut ch = h.channel_open_session().await.unwrap();
            ch.request_pty(true, "xterm-256color", 100, 30, 0, 0, &[])
                .await
                .unwrap();
            assert!(matches!(ch.wait().await, Some(ChannelMsg::Success)));
            ch.request_shell(true).await.unwrap();
            assert!(matches!(ch.wait().await, Some(ChannelMsg::Success)));
            ch.data_bytes(&b"ls\r"[..]).await.unwrap();
            ch.window_change(120, 40, 0, 0).await.unwrap();
            let mut seen = Vec::new();
            while !String::from_utf8_lossy(&seen).contains("ls\r") {
                if let Some(ChannelMsg::Data { data }) = ch.wait().await {
                    seen.extend_from_slice(&data);
                }
            }
            // The shell exits on `exit`; the fake sees it on stdin.
            ch.data_bytes(&b"exit\r"[..]).await.unwrap();
            let (rest, _, code) = collect(&mut ch).await;
            seen.extend(rest);
            (seen, code)
        });
        assert!(String::from_utf8_lossy(&out).starts_with("$ "));
        assert_eq!(code, Some(0));
        let spawned = t.runner().spawns().spawned();
        let line = spawned[0].args.join(" ");
        assert!(
            line.contains(" -w /w/proj -e TERM=xterm-256color -e TZ=Asia/Kolkata -i -t -- sh -c ")
        );
        assert!(line.ends_with("exec \"$s\" -l"), "{line}");
        let size = |cols, rows| crate::smolvm::Pty { cols, rows };
        assert_eq!(spawned[0].pty, Some(size(100, 30)));
        assert_eq!(*spawned[0].resizes.lock().unwrap(), vec![size(120, 40)]);
        assert_eq!(*spawned[0].stdin.lock().unwrap(), b"ls\rexit\r");
    }

    #[test]
    fn subsystems_x11_and_remote_forwarding_are_refused() {
        let mut t = test_env(&[]);
        running(&t);
        let (sftp, forward) = drive(&mut t, "claude-proj.sbx", |h| async move {
            let mut ch = h.channel_open_session().await.unwrap();
            ch.request_subsystem(true, "sftp").await.unwrap();
            let sftp = ch.wait().await;
            let forward = h.tcpip_forward("127.0.0.1", 0).await;
            (sftp, forward.is_err())
        });
        assert!(matches!(sftp, Some(ChannelMsg::Failure)));
        assert!(forward);
        assert!(t.runner().spawns().spawned().is_empty());
    }

    #[test]
    fn only_auth_none_is_accepted() {
        let mut t = test_env(&[]);
        running(&t);
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
