//! The `git-signing` kit's key-picking script, run on the host with a stand-in `ssh-add` and `gh`
//! (never your SSH agent, your `gh` or your git config).

use smolbento::kits::load::builtin;
use smolbento::kits::model::CapBody;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const FIRST: &str = "ssh-ed25519 AAAAfirst first@host";
const SECOND: &str = "ssh-ed25519 AAAAsecond second@host";

/// A repository, a home and a `PATH` with stand-in tools, all under one temp dir.
struct Sandbox {
    dir: tempfile::TempDir,
    /// Held so the agent socket exists.
    _socket: UnixListener,
    /// `ssh-add -L`'s output and exit status.
    keys: String,
    ssh_add_status: i32,
    /// What `gh api user/ssh_signing_keys` prints; `None` makes `gh` fail.
    github: Option<String>,
    agent: bool,
}

impl Sandbox {
    fn new() -> Sandbox {
        let dir = tempfile::tempdir().unwrap();
        for d in ["bin", "home", "repo", "etc"] {
            std::fs::create_dir(dir.path().join(d)).unwrap();
        }
        let s = Sandbox {
            _socket: UnixListener::bind(dir.path().join("agent.sock")).unwrap(),
            dir,
            keys: format!("{FIRST}\n{SECOND}\n"),
            ssh_add_status: 0,
            github: None,
            agent: true,
        };
        s.tool(
            "ssh-add",
            r#"printf %s "$FAKE_KEYS"; exit "$FAKE_SSH_ADD_STATUS""#,
        );
        s.tool(
            "gh",
            r#"echo "$*" >> "$FAKE_GH_CALLS"; [ -n "${FAKE_GH+set}" ] || exit 1; printf %s "$FAKE_GH""#,
        );
        std::fs::write(
            s.path("gitconfig"),
            "[user]\n\tname = Test\n\temail = me@example.com\n",
        )
        .unwrap();
        assert!(s.git(&["init", "-q"]).status.success());
        s
    }

    fn path(&self, rel: &str) -> PathBuf {
        self.dir.path().join(rel)
    }

    fn tool(&self, name: &str, body: &str) {
        let path = self.path("bin").join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// `cmd` in the repository, seeing only this sandbox's tools, home and git config.
    fn env<'a>(&self, cmd: &'a mut Command) -> &'a mut Command {
        let path = format!(
            "{}:{}",
            self.path("bin").display(),
            std::env::var("PATH").unwrap()
        );
        cmd.current_dir(self.path("repo"))
            .env_clear()
            .env("PATH", path)
            .env("HOME", self.path("home"))
            .env("GIT_CONFIG_GLOBAL", self.path("gitconfig"))
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("FAKE_KEYS", &self.keys)
            .env("FAKE_SSH_ADD_STATUS", self.ssh_add_status.to_string())
            .env("FAKE_GH_CALLS", self.path("gh-calls"));
        if let Some(listed) = &self.github {
            cmd.env("FAKE_GH", listed);
        }
        if self.agent {
            cmd.env("SSH_AUTH_SOCK", self.path("agent.sock"));
        }
        cmd
    }

    fn git(&self, args: &[&str]) -> Output {
        self.env(Command::new("git").args(args)).output().unwrap()
    }

    fn github_remote(&self) {
        let add = self.git(&["remote", "add", "origin", "git@github.com:acme/widgets.git"]);
        assert!(add.status.success(), "{add:?}");
    }

    fn pin(&self, key: &str) {
        std::fs::write(self.path("etc/key"), format!("{key}\n")).unwrap();
    }

    /// Runs the kit's script, reading its files from this sandbox's `etc` instead of
    /// `/etc/git-signing`.
    fn pick(&self) -> Output {
        let script = self.path("pick-key");
        let text = pick_key().replace("/etc/git-signing", self.path("etc").to_str().unwrap());
        std::fs::write(&script, text).unwrap();
        self.env(Command::new("sh").arg(&script)).output().unwrap()
    }

    fn picked(&self) -> String {
        let out = self.pick();
        assert!(out.status.success(), "{out:?}");
        String::from_utf8(out.stdout).unwrap()
    }

    fn refusal(&self) -> String {
        let out = self.pick();
        assert!(!out.status.success(), "{out:?}");
        assert_eq!(String::from_utf8_lossy(&out.stdout), "", "no key on stdout");
        String::from_utf8(out.stderr).unwrap()
    }

    fn gh_calls(&self) -> usize {
        std::fs::read_to_string(self.path("gh-calls")).map_or(0, |c| c.lines().count())
    }

    fn allowed_signers(&self) -> String {
        read(&self.path("home/.config/git-signing/allowed_signers"))
    }
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

/// The script the shipped kit installs as `/etc/git-signing/pick-key`.
fn pick_key() -> String {
    let kit = builtin("git-signing").unwrap().unwrap();
    let files = kit.caps.iter().find_map(|c| match &c.body {
        CapBody::Lifecycle(l) => Some(&l.files),
        _ => None,
    });
    let file = files
        .unwrap()
        .iter()
        .find(|f| f.path == "/etc/git-signing/pick-key")
        .expect("the kit writes /etc/git-signing/pick-key");
    assert_eq!(file.mode.as_deref(), Some("0755"));
    String::from_utf8(file.content.clone()).unwrap()
}

#[test]
fn the_first_agent_key_signs_by_default_and_is_recorded_for_the_committer() {
    let s = Sandbox::new();
    assert_eq!(s.picked(), "key::ssh-ed25519 AAAAfirst\n");
    assert_eq!(
        s.allowed_signers(),
        "me@example.com namespaces=\"git\" ssh-ed25519 AAAAfirst\n"
    );
    s.picked();
    assert_eq!(s.allowed_signers().lines().count(), 1, "recorded once");
    assert_eq!(s.gh_calls(), 0, "no GitHub remote, so GitHub isn't asked");
}

#[test]
fn a_pinned_key_signs_whatever_the_agent_lists_first() {
    let s = Sandbox::new();
    s.github_remote();
    s.pin("ssh-ed25519 AAAAsecond");
    assert_eq!(s.picked(), "key::ssh-ed25519 AAAAsecond\n");
    assert_eq!(s.gh_calls(), 0, "a pinned key needs no lookup");
}

#[test]
fn a_pinned_key_the_agent_lacks_is_refused_by_name() {
    let s = Sandbox::new();
    s.pin("ssh-ed25519 AAAAother");
    let err = s.refusal();
    assert!(err.contains("signingKey"), "{err}");
    assert!(err.contains("AAAAother"), "{err}");
}

#[test]
fn a_github_remote_prefers_the_key_github_lists_for_signing() {
    let mut s = Sandbox::new();
    s.github_remote();
    s.github = Some("ssh-ed25519 AAAAsecond\n".into());
    assert_eq!(s.picked(), "key::ssh-ed25519 AAAAsecond\n");
    assert_eq!(s.picked(), "key::ssh-ed25519 AAAAsecond\n");
    assert_eq!(s.gh_calls(), 1, "GitHub's answer is kept for a few minutes");
}

#[test]
fn without_a_github_answer_the_first_key_signs() {
    let mut s = Sandbox::new();
    s.github_remote();
    // `gh` fails: not logged in, or the host is blocked.
    assert_eq!(s.picked(), "key::ssh-ed25519 AAAAfirst\n");
    // GitHub lists a key the agent doesn't hold.
    s.github = Some("ssh-ed25519 AAAAelsewhere\n".into());
    assert_eq!(s.picked(), "key::ssh-ed25519 AAAAfirst\n");
}

#[test]
fn each_missing_piece_is_named_with_what_to_run() {
    let mut s = Sandbox::new();
    s.agent = false;
    let err = s.refusal();
    assert!(err.starts_with("git-signing: "), "{err}");
    assert!(err.contains("SSH_AUTH_SOCK is unset"), "{err}");
    assert!(err.contains("bento "), "{err}");
    assert!(
        err.contains("user.signingKey"),
        "says git's own line misleads: {err}"
    );

    s.agent = true;
    s.keys = String::new();
    s.ssh_add_status = 1;
    let err = s.refusal();
    assert!(err.contains("holds no keys"), "{err}");
    assert!(err.contains("ssh-add"), "{err}");

    s.ssh_add_status = 2;
    let err = s.refusal();
    assert!(err.contains("isn't answering"), "{err}");
    assert!(err.contains("bento diagnose"), "{err}");
}
