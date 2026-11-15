//! The shipped `git-signing` kit in real sandboxes, signing through a throwaway host SSH agent.

use super::bridge_agent::{ThrowawayAgent, guest_sign};
use super::*;

/// `alpine/git` (git and OpenSSH, which the kit's steps need from the first start) with an
/// `agent` account, as an image that idles in a shell.
fn git_image() -> Image {
    let base = Image::pull("alpine/git");
    let copy = Image {
        layers: base.layers.clone(),
        config: base.config.clone(),
    };
    let mut image = copy.with_agent_account(&base);
    image.config["config"]["Entrypoint"] = serde_json::Value::Null;
    image.config["config"]["Cmd"] = serde_json::json!(["/bin/sh"]);
    image
}

/// Makes the test's workspace a repository with a git identity of its own (what `git-identity@1`
/// reads, whatever yours is) and, with `remote`, an `origin`.
fn workspace_repo(e: &E2e, remote: bool) {
    e.git_ok(&["init", "-q"]);
    e.git_ok(&["config", "user.name", "E2E Signer"]);
    e.git_ok(&["config", "user.email", "signer@example.com"]);
    if remote {
        e.git_ok(&[
            "remote",
            "add",
            "origin",
            "https://git.example.invalid/e2e.git",
        ]);
    }
}

/// The built-in `shell` agent on `git_image`, with the kit.
fn create_shell(e: &E2e) {
    let archive = e.dir.path().join("git-image.tar");
    git_image().save_oci(&archive);
    let ws = e.workspace();
    let mut args = vec!["create", "shell", ws.to_str().unwrap(), "--name", &e.name];
    args.extend(["-t", archive.to_str().unwrap(), "--kit", "git-signing"]);
    args.extend(["--cpus", "1", "-m", "1g"]);
    e.ok(&args);
}

/// `script` in the sandbox's workspace, as the session user.
fn in_workspace(e: &E2e, sb: &str, script: &str) -> Output {
    let script = format!("cd \"$WORKSPACE_DIR\" && {script}");
    e.sbt(&["exec", sb, "sh", "-c", &script])
}

const COMMIT: &str = "git commit -q --allow-empty -m signed";
/// The last commit's signature check: `G` for a good one, `N` for none; then the verifier's text.
const VERIFY: &str = "git log -1 --format=%G? && git log -1 --show-signature";

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// A commit in a built-in agent's sandbox is signed with the agent's key, and the sandbox can
/// verify it.
#[test]
#[ignore = "boots real VMs and pulls alpine/git; run with `just e2e`"]
pub(crate) fn git_signing_signs_and_verifies_under_a_built_in_agent() {
    let mut e = E2e::new("gsbuiltin");
    let agent = ThrowawayAgent::start(&e, 11);
    agent.serve_to(&mut e);
    workspace_repo(&e, true);
    create_shell(&e);

    let out = in_workspace(&e, &e.name, &format!("{COMMIT} && {VERIFY}"));
    let said = text(&out);
    assert!(out.status.success(), "{said}");
    assert!(said.starts_with("G\n"), "{said}");
    assert!(
        said.contains("Good \"git\" signature for signer@example.com"),
        "{said}"
    );

    // A plain tag stays a plain tag (no message asked for); `-s` signs one.
    let tags = "git tag plain && git tag -s -m release signed && git tag -v signed";
    let out = in_workspace(&e, &e.name, &format!("GIT_EDITOR=false {tags}"));
    let said = text(&out);
    assert!(out.status.success(), "{said}");
    assert!(said.contains("Good \"git\" signature"), "{said}");
    assert!(agent.has_key(), "the key is still in the agent");
}

/// A workload kit gets no SSH agent of its own; with the kit it signs commits, and the agent
/// refuses any other kind of signature (so no SSH logins).
#[test]
#[ignore = "boots real VMs and pulls alpine/git; run with `just e2e`"]
pub(crate) fn git_signing_gives_a_workload_agent_git_signatures_only() {
    let mut e = E2e::new("gsworkload");
    let agent = ThrowawayAgent::start(&e, 12);
    agent.serve_to(&mut e);
    workspace_repo(&e, true);
    let reg = Registry::start(&e);
    let mut image = git_image();
    image.config["config"]["User"] = "agent".into();
    let workload = reg.push(
        "git-workload",
        image,
        descriptor(
            "workload",
            &[],
            serde_json::json!([{"type": "com.docker.sandbox/sbx@1"}]),
        ),
    );
    let ws = e.workspace();
    e.ok(&[
        "create",
        "--kit",
        "git-signing",
        &workload,
        ws.to_str().unwrap(),
        "--name",
        &e.name,
        "--cpus",
        "1",
        "-m",
        "1g",
    ]);

    let out = in_workspace(&e, &e.name, &format!("{COMMIT} && {VERIFY}"));
    let said = text(&out);
    assert!(out.status.success(), "{said}");
    assert!(said.starts_with("G\n"), "{said}");

    let other = guest_sign(&e, &e.name, "file");
    assert!(!other.status.success(), "only git signatures: {other:?}");
}

/// With no SSH agent on the host the sandbox is still created. A repository without a remote
/// commits unsigned; one with a remote refuses the commit and says why.
#[test]
#[ignore = "boots real VMs and pulls alpine/git; run with `just e2e`"]
pub(crate) fn git_signing_without_an_agent_signs_nothing_and_says_why() {
    let e = E2e::new("gsnoagent");
    workspace_repo(&e, true);
    create_shell(&e);

    let scratch = format!("git init -q /tmp/scratch && cd /tmp/scratch && {COMMIT} && {VERIFY}");
    let out = in_workspace(&e, &e.name, &scratch);
    let said = text(&out);
    assert!(out.status.success(), "{said}");
    assert!(said.starts_with("N\n"), "unsigned: {said}");

    let out = in_workspace(&e, &e.name, COMMIT);
    let said = text(&out);
    assert!(!out.status.success(), "{said}");
    assert!(
        said.contains("git-signing: no SSH agent reaches this sandbox"),
        "{said}"
    );
}
