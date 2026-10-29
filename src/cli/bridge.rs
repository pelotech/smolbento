//! `_bridge NAME`: serves a sandbox's browser and clipboard bridge until killed, as `run` and
//! `exec -it` do while attached. For e2e tests, which can't drive an interactive session.

use anyhow::{Context, Result, bail};

use super::Ctx;
use crate::bridge::{self, Server};
use crate::sandbox;
use crate::smolvm::Runner;

pub fn run<R: Runner>(ctx: &mut Ctx<R>, name: &str) -> Result<i32> {
    let _server = serve(ctx, name)?;
    loop {
        std::thread::park();
    }
}

/// Unlike an attached session, this serves whatever the display and fails rather than warns.
fn serve<R: Runner>(ctx: &Ctx<R>, name: &str) -> Result<Server> {
    let sb = sandbox::get(&ctx.vm, name)?;
    if !sb.meta.bridge {
        bail!("sandbox '{name}' has no browser and clipboard bridge (sandboxes get one at create)");
    }
    let handlers = bridge::handlers(
        &ctx.env,
        ctx.settings.bool("browser.enabled")?,
        &ctx.settings.value("smolvm.path")?,
        &sb,
    );
    bridge::serve(&bridge::host_socket(sb.name()), handlers)?
        .with_context(|| format!("another session already serves sandbox '{name}'s bridge"))
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    use super::super::testutil::*;
    use crate::bridge::host_socket;

    #[test]
    fn serves_a_labelled_sandbox() {
        let t = test_env(&[]);
        let (name, _) = bridge_probe(&t, "cmd", true);
        let server = super::serve(&t.ctx, &name).unwrap();
        let mut s = UnixStream::connect(host_socket(&name)).unwrap();
        s.write_all(b"POST /nope HTTP/1.1\r\n\r\n").unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).unwrap();
        assert!(out.starts_with("HTTP/1.1 404 "), "{out}");
        // A second one leaves it to the first.
        let err = super::serve(&t.ctx, &name).err().expect("refused");
        assert!(err.to_string().contains("already serves"), "{err:#}");
        drop(server);
    }

    #[test]
    fn refuses_a_sandbox_without_the_bridge() {
        let t = test_env(&[]);
        let (name, _) = bridge_probe(&t, "cmd", false);
        let err = super::serve(&t.ctx, &name).err().expect("refused");
        assert!(
            err.to_string().contains("no browser and clipboard bridge"),
            "{err:#}"
        );
        assert!(!host_socket(&name).exists());
    }

    #[test]
    fn is_hidden_and_needs_smolvm() {
        use clap::CommandFactory;
        let cmd = super::super::Cli::command();
        let sub = cmd.find_subcommand("_bridge").expect("exists");
        assert!(sub.is_hide_set());
        let mut t = test_env(&[]);
        t.ctx.vm.runner().fail(&["--version"], "E", "no smolvm");
        assert!(sbt(&mut t.ctx, &["_bridge", "x"]).is_err());
    }
}
