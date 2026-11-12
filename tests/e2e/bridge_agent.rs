use super::*;

/// A `smolbento _bridge NAME` in the background, as `run` and `exec -it` serve it while attached.
/// Killed on drop, so a failing test doesn't leave it running.
pub(crate) struct Bridge {
    pub(crate) child: std::process::Child,
    pub(crate) socket: PathBuf,
}

impl Bridge {
    pub(crate) fn start(e: &E2e, opener: &Path, copier: &Path) -> Bridge {
        let child = e
            .env(Command::new(env!("CARGO_BIN_EXE_smolbento")).args(["_bridge", &e.name]))
            .env("SMOLBENTO_OPEN_CMD", opener)
            .env("SMOLBENTO_COPY_CMD", copier)
            .spawn()
            .unwrap();
        let socket = smolbento::bridge::host_socket(&e.name);
        assert!(wait_until(10, || socket.exists()), "_bridge didn't serve");
        Bridge { child, socket }
    }
}

impl Drop for Bridge {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.socket);
    }
}

/// An executable `sh` script.
pub(crate) fn sh_script(path: &Path, body: &str) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// `GET path` on the host's `127.0.0.1:port`; the whole response.
pub(crate) fn host_get(port: u16, path: &str) -> std::io::Result<String> {
    use std::io::{Read, Write};
    let mut s = std::net::TcpStream::connect(("127.0.0.1", port))?;
    s.set_read_timeout(Some(std::time::Duration::from_secs(30)))?;
    write!(
        s,
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"
    )?;
    let mut out = String::new();
    s.read_to_string(&mut out)?;
    Ok(out)
}

/// The browser and clipboard bridge while "attached": https URLs reach the host opener, other
/// URLs and a stopped bridge print the fallback, copies reach the host clipboard, and a login
/// redirect to `http://127.0.0.1:PORT` relays the host's callback to a guest loopback listener.
/// The host commands are scripts that record what they get; no browser or clipboard is touched.
#[test]
#[ignore = "boots real VMs and needs the Alpine package mirror; run with `just e2e`"]
pub(crate) fn bridge_opens_urls_copies_text_and_relays_login_callbacks() {
    let e = E2e::new("brg");
    e.create_alpine_with("apk add -q curl busybox-extras");
    let dir = e.dir.path();
    let (opened, copied) = (dir.join("opened"), dir.join("copied"));
    let (opener, copier) = (dir.join("open.sh"), dir.join("copy.sh"));
    sh_script(
        &opener,
        &format!("printf '%s\\n' \"$1\" >> '{}'", opened.display()),
    );
    sh_script(&copier, &format!("cat > '{}'", copied.display()));
    let guest = |script: &str| e.ok(&["exec", &e.name, "sh", "-c", script]);
    let read = |p: &Path| std::fs::read_to_string(p).unwrap_or_default();

    let bridge = Bridge::start(&e, &opener, &copier);
    assert_eq!(guest("xdg-open https://example.invalid/x"), "");
    assert_eq!(read(&opened), "https://example.invalid/x\n");
    assert_eq!(
        guest("xdg-open http://example.invalid/y"),
        "Open this URL in your browser: http://example.invalid/y\n",
        "only https URLs open"
    );
    guest("printf hi | wl-copy");
    assert_eq!(read(&copied), "hi");

    // A login whose redirect_uri is the guest's loopback callback server: the host's
    // 127.0.0.1:PORT relays to it. PORT is free on the host; the guest's is its own.
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    guest_root(
        &e.name,
        &format!(
            "mkdir -p /tmp/www && echo callback-ok > /tmp/www/cb && \
             busybox-extras httpd -p 127.0.0.1:{port} -h /tmp/www"
        ),
    );
    let login = format!(
        "https://login.example.invalid/auth?client_id=c&redirect_uri=http%3A%2F%2F127.0.0.1%3A{port}%2Fcb"
    );
    assert_eq!(guest(&format!("xdg-open '{login}'")), "");
    let answer = host_get(port, "/cb?code=abc").unwrap();
    assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
    assert!(answer.contains("callback-ok"), "{answer}");

    // Nobody attached: the shims fall back and the relay is gone.
    drop(bridge);
    assert_eq!(
        guest("xdg-open https://example.invalid/z"),
        "Open this URL in your browser: https://example.invalid/z\n"
    );
    assert_eq!(read(&opened).lines().count(), 2, "nothing more opened");
    assert!(host_get(port, "/cb").is_err(), "the relay stopped");
}

/// A throwaway `ssh-agent` on a short socket under /tmp holding one throwaway ed25519 key, so the
/// SSH tests never talk to your agent. Killed on drop.
pub(crate) struct ThrowawayAgent {
    pub(crate) child: std::process::Child,
    pub(crate) socket: PathBuf,
    /// The key's comment, as `ssh-add -l` prints it.
    pub(crate) comment: String,
}

impl ThrowawayAgent {
    pub(crate) fn start(e: &E2e, n: u32) -> ThrowawayAgent {
        let socket = PathBuf::from(format!("/tmp/sbt-e2e-{}-{n}.sock", std::process::id()));
        let _ = std::fs::remove_file(&socket);
        let child = Command::new("ssh-agent")
            .arg("-D")
            .arg("-a")
            .arg(&socket)
            .env_remove("SSH_AUTH_SOCK")
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let mut agent = ThrowawayAgent {
            child,
            socket,
            comment: format!("sbt-e2e-throwaway-{}-{n}", std::process::id()),
        };
        // Its socket must exist before anything talks to an agent; otherwise stop here.
        let up = wait_until(10, || agent.socket.exists());
        assert!(
            up && agent.child.try_wait().unwrap().is_none(),
            "the throwaway ssh-agent didn't start on {}",
            agent.socket.display()
        );
        let key = e.dir.path().join(format!("id_ed25519_{n}"));
        let keygen = Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-C", &agent.comment, "-f"])
            .arg(&key)
            .output()
            .unwrap();
        assert!(keygen.status.success(), "ssh-keygen: {keygen:?}");
        let add = agent.ssh_add(&[key.to_str().unwrap()]);
        assert!(add.status.success(), "ssh-add: {add:?}");
        assert!(agent.has_key(), "the throwaway agent holds its key");
        agent
    }

    /// `ssh-add args` against this agent only.
    pub(crate) fn ssh_add(&self, args: &[&str]) -> Output {
        Command::new("ssh-add")
            .args(args)
            .env("SSH_AUTH_SOCK", &self.socket)
            .output()
            .unwrap()
    }

    pub(crate) fn has_key(&self) -> bool {
        String::from_utf8_lossy(&self.ssh_add(&["-l"]).stdout).contains(&self.comment)
    }

    /// Points every `sbt` call of `e` at this agent.
    pub(crate) fn serve_to(&self, e: &mut E2e) {
        e.vars
            .push(("SSH_AUTH_SOCK", self.socket.to_str().unwrap().into()));
    }
}

impl Drop for ThrowawayAgent {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.socket);
    }
}

/// Signs a file in the guest with the agent's key (`ssh-keygen -Y sign`) in namespace `ns`.
pub(crate) fn guest_sign(e: &E2e, sb: &str, ns: &str) -> Output {
    let script = format!(
        "set -e; cd /tmp; ssh-add -L > e2e-key.pub; echo hi > e2e-{ns}; \
         ssh-keygen -Y sign -f e2e-key.pub -n {ns} e2e-{ns}; test -s e2e-{ns}.sig"
    );
    e.sbt(&["exec", sb, "sh", "-c", &script])
}

/// sbx's built-in `shell` agent forwards your SSH agent filtered: the sandbox lists keys and signs,
/// but can't remove them.
#[test]
#[ignore = "boots real VMs and needs the Alpine package mirror; run with `just e2e`"]
pub(crate) fn built_in_agent_lists_and_signs_but_cannot_remove_keys() {
    let mut e = E2e::new("sshagent");
    let agent = ThrowawayAgent::start(&e, 1);
    agent.serve_to(&mut e);
    e.create_alpine_with("apk add -q openssh-client openssh-keygen");

    let sock = e.ok(&["exec", &e.name, "sh", "-c", "echo $SSH_AUTH_SOCK"]);
    assert_eq!(sock, "/run/ssh-agent.sock\n");
    let keys = e.ok(&["exec", &e.name, "ssh-add", "-l"]);
    assert!(keys.contains(&agent.comment), "{keys}");
    let signed = guest_sign(&e, &e.name, "file");
    assert!(signed.status.success(), "sign -n file: {signed:?}");

    let remove = e.sbt(&["exec", &e.name, "ssh-add", "-D"]);
    assert!(
        !remove.status.success(),
        "ssh-add -D is refused: {remove:?}"
    );
    assert!(agent.has_key(), "the key is still in the agent");
}

/// Kit grants: a `sign: [git]` mixin signs only git signatures; an install-only grant reaches the
/// install hooks that declare `SSH_AUTH_SOCK` but not the workload; a v3 workload without a grant
/// gets no agent.
#[test]
#[ignore = "boots real VMs and pulls alpine; run with `just e2e`"]
pub(crate) fn kit_ssh_agent_grants_limit_signing_and_phases() {
    let mut e = E2e::new("sshkit");
    let agent = ThrowawayAgent::start(&e, 2);
    agent.serve_to(&mut e);
    let reg = Registry::start(&e);
    let workload = reg.push(
        "ssh-workload",
        Image::alpine(),
        descriptor(
            "workload",
            &[],
            serde_json::json!([
                {"type": "com.docker.sandbox/sbx@1"},
                {"type": "com.docker.sandbox/lifecycle@1",
                 "config": {"install": [
                     {"command": add_agent_hook(), "user": "0"},
                     {"command": "apk add -q openssh-client openssh-keygen", "user": "0"},
                 ]}},
            ]),
        ),
    );
    let git_only = reg.push(
        "ssh-git",
        Image::empty(),
        descriptor(
            "mixin",
            &["e2e-ssh-git"],
            serde_json::json!([
                {"type": "com.docker.sandbox/ssh-agent@1",
                 "config": {"phase": "runtime", "unrestricted": false, "sign": ["git"]}},
            ]),
        ),
    );
    let install_only = reg.push(
        "ssh-install",
        Image::empty(),
        descriptor(
            "mixin",
            &["e2e-ssh-install"],
            serde_json::json!([
                {"type": "com.docker.sandbox/ssh-agent@1", "config": {"phase": "install"}},
                {"type": "com.docker.sandbox/lifecycle@1",
                 "config": {"install": [
                     {"command": "apk add -q openssh-client && ssh-add -l > /etc/e2e-install-keys",
                      "user": "0", "env": ["SSH_AUTH_SOCK"]},
                 ]}},
            ]),
        ),
    );
    let ws = e.workspace();
    let create = |name: &str, mixin: Option<&str>| {
        let mut args = vec!["create"];
        if let Some(m) = mixin {
            args.extend(["--kit", m]);
        }
        args.extend([
            &workload,
            ws.to_str().unwrap(),
            "--name",
            name,
            "--cpus",
            "1",
            "-m",
            "1g",
        ]);
        e.ok(&args);
    };
    let (git, inst) = (format!("{}-git", e.name), format!("{}-inst", e.name));
    let _cleanup = Forks(vec![git.clone(), inst.clone()]);
    let env = "echo ${SSH_AUTH_SOCK-unset}";

    create(&git, Some(&git_only));
    let signed = guest_sign(&e, &git, "git");
    assert!(signed.status.success(), "sign -n git: {signed:?}");
    let refused = guest_sign(&e, &git, "file");
    assert!(!refused.status.success(), "sign -n file is refused");

    create(&inst, Some(&install_only));
    let during = root_out(&inst, "cat /etc/e2e-install-keys");
    assert!(
        during.contains(&agent.comment),
        "install hooks list keys: {during}"
    );
    assert_eq!(
        e.ok(&["exec", &inst, "sh", "-c", env]),
        "unset\n",
        "not at runtime"
    );

    create(&e.name, None);
    let none = format!("{env}; test -e /run/ssh-agent.sock && echo socket || true");
    assert_eq!(
        e.ok(&["exec", &e.name, "sh", "-c", &none]),
        "unset\n",
        "no grant, no agent"
    );
    assert!(agent.has_key(), "the key is still in the agent");
}
