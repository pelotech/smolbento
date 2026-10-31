//! fork: copy-on-write copies of a running sandbox (smolvm `machine branch`), for parallel attempts
//! or as an undo point. smolbento-only (sbx has no fork).

use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};

use super::{Ctx, ForkArgs, plan};
use crate::policy::Policy;
use crate::sandbox::{self, Sandbox, labels, name};
use crate::smolvm::{Runner, SmolvmError};
use crate::workspace::clone;

/// Prints each copy's name as it's made.
pub fn run<R: Runner>(ctx: &mut Ctx<R>, a: &ForkArgs) -> Result<i32> {
    if !ctx.settings.bool("fork.enabled")? {
        bail!("fork is turned off (fork.enabled=false)");
    }
    let mut parent = sandbox::get(&ctx.vm, &a.sandbox)?;
    check_forkable(&parent)?;
    let names = match &a.name {
        Some(n) => {
            name::validate(n)?;
            if sandbox::find(&ctx.vm, n)?.is_some() {
                bail!("sandbox '{n}' already exists");
            }
            vec![n.clone()]
        }
        None => free_names(ctx, parent.name(), a.count)?,
    };
    if let Some(repo) = &parent.meta.clone_repo {
        for n in &names {
            clone::check_remote_free(Path::new(repo), n)?;
        }
    }
    // One secrets resolution (one Touch ID) for the parent's start, if needed, and every copy.
    let start = plan::start_plan(ctx, &parent.meta)?;
    sandbox::ensure_running(&ctx.vm, &mut parent, || Ok(start.clone()))?;
    for n in &names {
        fork_one(ctx, &parent, n, &start.env, &start.remove)
            .with_context(|| format!("forking {} as {n}", parent.name()))?;
        writeln!(&ctx.out, "{n}")?;
    }
    Ok(0)
}

/// Only sandboxes whose workspace lives in the VM: a host folder would be shared with the copies.
fn check_forkable(sb: &Sandbox) -> Result<()> {
    if sb.meta.fork_of.is_some() {
        bail!("forking a fork isn't supported yet");
    }
    if sb.meta.writable_host_folder() {
        bail!("fork needs a sandbox with no writable host folder; create it with --clone");
    }
    Ok(())
}

/// The lowest free `<parent>-fork-<n>` names.
fn free_names<R: Runner>(ctx: &Ctx<R>, parent: &str, count: u32) -> Result<Vec<String>> {
    let mut out = Vec::new();
    let mut n = 1;
    while out.len() < count as usize {
        let candidate = format!("{parent}-fork-{n}");
        if sandbox::find(&ctx.vm, &candidate)?.is_none() {
            name::validate(&candidate)
                .map_err(|e| anyhow!("{e}; use --name to choose a shorter one"))?;
            out.push(candidate);
        }
        n += 1;
    }
    Ok(out)
}

/// Drops stale state under the fork's name and copies the parent's policy entry, then adds the
/// clone remote and branches; on failure, undoes what it did in reverse (a failed undo only warns).
fn fork_one<R: Runner>(
    ctx: &Ctx<R>,
    parent: &Sandbox,
    fork: &str,
    env: &[(String, String)],
    remove: &[String],
) -> Result<()> {
    // The name is free, so anything stored under it is stale (say, a machine deleted with raw
    // smolvm): drop its secrets, keychain values included, and policy entry.
    super::secret::forget_sandbox(ctx, fork, true)?;
    let mut policy = Policy::load(&ctx.paths)?;
    policy.copy_sandbox(parent.name(), fork);
    policy.save(&ctx.paths)?;
    let result = add_remote_and_branch(ctx, parent, fork, env, remove);
    if result.is_err()
        && let Err(e) = super::secret::forget_sandbox(ctx, fork, false)
    {
        eprintln!("warning: removing {fork}'s policy entry: {e:#}");
    }
    result
}

fn add_remote_and_branch<R: Runner>(
    ctx: &Ctx<R>,
    parent: &Sandbox,
    fork: &str,
    env: &[(String, String)],
    remove: &[String],
) -> Result<()> {
    let repo = parent.meta.clone_repo.as_deref().map(Path::new);
    let added = match repo {
        Some(r) => clone::add_remote(r, fork)?,
        None => false,
    };
    let mut labels = vec![
        (labels::NAME.to_string(), fork.to_string()),
        (labels::FORK_OF.to_string(), parent.name().to_string()),
        // A child inherits its source's labels; a fork's age is its own.
        (labels::CREATED.to_string(), ctx.now.to_string()),
        // The copy keeps the parent's bridge socket path, but a session serves each sandbox at
        // its own (`bridge::host_socket`): a fork gets no shims at starts, though its processes
        // can still reach the parent's socket while the parent is attached.
        (labels::BRIDGE.to_string(), "false".to_string()),
    ];
    // Nor an SSH agent: an empty label reads as none (smolvm can't remove an inherited one).
    // Like the bridge, the copy's mount still points at the parent's socket.
    if parent.meta.ssh_agent.is_some() {
        labels.push((labels::SSH_AGENT.to_string(), String::new()));
    }
    // The child inherits the parent's create-time -e values: give it its own identity.
    let vars = [
        ("SANDBOX_NAME".to_string(), fork.to_string()),
        ("SANDBOX_VM_ID".to_string(), fork.to_string()),
        ("SANDBOX_ID".to_string(), sandbox::env::new_uuid()?),
    ];
    let result = ctx
        .vm
        .branch(
            &parent.machine,
            &name::machine_name(fork),
            &labels,
            &vars,
            env,
            remove,
        )
        .map_err(|e| branch_hint(e, parent.name()));
    if result.is_err()
        && added
        && let Some(r) = repo
        && let Err(e) = clone::remove_remote(r, fork)
    {
        eprintln!("warning: removing the sandbox-{fork} remote: {e:#}");
    }
    result
}

/// smolvm's not-branchable and backing-chain errors (`src/agent/fork.rs` in smolvm), in sbt terms.
fn branch_hint(e: anyhow::Error, parent: &str) -> anyhow::Error {
    let Some(message) = e.downcast_ref::<SmolvmError>().map(|s| s.message.as_str()) else {
        return e;
    };
    if message.contains("was not started as branchable") {
        return anyhow!(
            "{parent} was started without fork support; restart it once \
             (`sbt stop {parent} && sbt start {parent}`) to enable fork"
        );
    }
    if message.contains("qcow2 backing layers") || message.contains("safe backing depth") {
        return e.context("smolvm limits how deep a chain of copies can get");
    }
    e
}

#[cfg(test)]
mod tests {
    use super::super::testutil::*;
    use crate::policy::Policy;
    use crate::secrets::{SecretEntry, SecretsFile, Source, scope_for};
    use crate::smolvm::SmolvmError;

    const NOT_BRANCHABLE: &str = "agent operation failed: fork: machine 'sbx-a' was not started \
        as branchable, so it has no copy-on-write memory to branch from. Restart it with \
        `smolvm machine start --name sbx-a --branchable`; branchability is decided at start time \
        and cannot be turned on for an already-running machine.";
    const CHAIN_DEPTH: &str = "agent operation failed: fork-continue: /m/sbx-a/disk.qcow2 already \
        has 32 qcow2 backing layers; the safe limit is 32. Stop and pack this machine into a new \
        root before creating another live fork";

    /// Every machine but `machine` is missing; `machine` is sandbox `a` with `extra` labels.
    fn parent(t: &TestEnv, state: &str, extra: &[(&str, &str)]) {
        let mut labels = vec![("sbx.name", "a"), ("sbx.created", "999000")];
        labels.extend_from_slice(extra);
        let fake = t.runner();
        fake.fail(&["machine", "status"], "NOT_FOUND", "machine not found");
        fake.ok(
            &["machine", "status", "-n", "sbx-a"],
            &machine_json("sbx-a", state, &labels),
        );
    }

    fn exists(t: &TestEnv, name: &str) {
        let machine = format!("sbx-{name}");
        t.runner().ok(
            &["machine", "status", "-n", &machine],
            &machine_json(&machine, "running", &[("sbx.name", name)]),
        );
    }

    fn branches(t: &TestEnv) -> Vec<String> {
        t.calls()
            .into_iter()
            .filter(|c| c.starts_with("machine branch"))
            .map(|c| normalize_id(&c))
            .collect()
    }

    /// The fresh SANDBOX_ID replaced by `ID`.
    fn normalize_id(line: &str) -> String {
        let at = line.find("SANDBOX_ID=").expect("a SANDBOX_ID") + "SANDBOX_ID=".len();
        assert_eq!(line.len() - at, 36, "{line}");
        format!("{}ID", &line[..at])
    }

    fn branch(fork: &str) -> String {
        format!(
            "machine branch --from sbx-a -n sbx-{fork} --label sbx.name={fork} \
             --label sbx.fork-of=a --label sbx.created=1000000 --label sbx.bridge=false \
             -e SANDBOX_NAME={fork} -e SANDBOX_VM_ID={fork} -e SANDBOX_ID=ID"
        )
    }

    fn deny_rule_policy(t: &TestEnv) {
        set_policy(
            t,
            "mode = \"allow-all\"\n[[sandboxes.a.rules]]\nid = \"r-1\"\ndecision = \"deny\"\n\
             resources = [\"a.com\"]\n",
        );
    }

    fn remote(repo: &std::path::Path, name: &str, key: &str) -> String {
        git_config(repo, &format!("remote.sandbox-{name}.{key}"))
    }

    fn clone_labels(repo: &std::path::Path) -> (String, String) {
        let r = repo.display().to_string();
        let ws = serde_json::to_string(&[&r]).unwrap();
        (r, ws)
    }

    #[test]
    fn forks_a_clone_sandbox() {
        let mut t = test_env(&[]);
        let (_d, repo) = temp_repo();
        let (r, ws) = clone_labels(&repo);
        parent(
            &t,
            "running",
            &[
                ("sbx.clone", "true"),
                ("sbx.workspace", &r),
                ("sbx.workspaces", &ws),
            ],
        );
        assert_eq!(t.sbt(&["fork", "a"]).unwrap(), 0);
        assert_eq!(branches(&t), vec![branch("a-fork-1")]);
        assert_eq!(remote(&repo, "a-fork-1", "url"), "file:///sbt/a-fork-1");
        assert_eq!(
            remote(&repo, "a-fork-1", "uploadpack"),
            "smolbento _upload-pack a-fork-1"
        );
        assert_eq!(remote(&repo, "a-fork-1", "tagOpt"), "--no-tags");
    }

    /// smolvm copies the machine's mounts and labels: the branch argv leaves them alone.
    #[test]
    fn a_fork_of_a_sandbox_with_host_mounts_leaves_the_branch_argv_alone() {
        let mut t = test_env(&[]);
        parent(
            &t,
            "running",
            &[("sbx.host-mounts", r#"{"/home/agent/x":"/data/x"}"#)],
        );
        assert_eq!(t.sbt(&["fork", "a"]).unwrap(), 0);
        assert_eq!(branches(&t), vec![branch("a-fork-1")]);
    }

    /// A fork gets no SSH agent: an empty `sbx.ssh-agent` replaces the inherited grant.
    #[test]
    fn a_fork_drops_the_ssh_agent_grant() {
        let mut t = test_env(&[]);
        parent(
            &t,
            "running",
            &[("sbx.ssh-agent", r#"{"runtime":{"sign":null}}"#)],
        );
        assert_eq!(t.sbt(&["fork", "a"]).unwrap(), 0);
        let b = branch("a-fork-1");
        let (head, vars) = b.split_at(b.find(" -e ").unwrap());
        assert_eq!(
            branches(&t),
            vec![format!("{head} --label sbx.ssh-agent={vars}")]
        );
    }

    #[test]
    fn default_names_skip_taken_ones() {
        let mut t = test_env(&[]);
        parent(&t, "running", &[]);
        exists(&t, "a-fork-1");
        t.sbt(&["fork", "a"]).unwrap();
        assert_eq!(branches(&t), vec![branch("a-fork-2")]);

        let mut t = test_env(&[]);
        parent(&t, "running", &[]);
        exists(&t, "a-fork-1");
        t.sbt(&["fork", "a", "--count", "2"]).unwrap();
        assert_eq!(branches(&t), vec![branch("a-fork-2"), branch("a-fork-3")]);
        assert_eq!(t.stdout(), "a-fork-2\na-fork-3\n");
    }

    #[test]
    fn name_names_the_copy() {
        let mut t = test_env(&[]);
        parent(&t, "running", &[]);
        t.sbt(&["fork", "a", "--name", "try.2"]).unwrap();
        assert_eq!(t.stdout(), "try.2\n");
        assert_eq!(
            branches(&t),
            vec![
                "machine branch --from sbx-a -n sbx-try_2 --label sbx.name=try.2 \
                 --label sbx.fork-of=a --label sbx.created=1000000 --label sbx.bridge=false \
                 -e SANDBOX_NAME=try.2 -e SANDBOX_VM_ID=try.2 -e SANDBOX_ID=ID"
            ]
        );
    }

    #[test]
    fn secrets_go_in_the_branch_env() {
        let mut t = test_env(&[]);
        let entry = SecretEntry {
            service: "github".into(),
            scope: scope_for(None),
            source: Source::Keychain,
        };
        t.ctx.store.set(&entry.account(), "gh-123").unwrap();
        let mut f = SecretsFile::default();
        f.set(entry);
        f.save(&t.ctx.paths).unwrap();
        parent(
            &t,
            "running",
            &[
                ("sbx.secrets", "github"),
                ("sbx.credential-env", "GH_TOKEN,GITHUB_TOKEN,OLD_TOKEN"),
            ],
        );
        t.sbt(&["fork", "a"]).unwrap();
        let fake = t.runner();
        let env = fake.envs().last().unwrap().clone();
        assert!(env.contains(&("GH_TOKEN".to_string(), "gh-123".to_string())));
        assert_eq!(fake.removed().last().unwrap(), &vec!["OLD_TOKEN"]);
        assert!(fake.call_lines().iter().all(|c| !c.contains("gh-123")));
        assert_eq!(branches(&t), vec![branch("a-fork-1")]);
    }

    #[test]
    fn fork_enabled_false_refuses() {
        let mut t = test_env(&[("SMOLBENTO_FORK", "false")]);
        parent(&t, "running", &[]);
        let err = t.sbt_err(&["fork", "a"]);
        assert_eq!(err, "fork is turned off (fork.enabled=false)");
        let calls = t.calls();
        assert!(calls.iter().all(|c| !c.starts_with("machine")), "{calls:?}");
    }

    #[test]
    fn stale_policy_and_secrets_for_the_name_are_dropped() {
        let mut t = test_env(&[]);
        set_policy(
            &t,
            "mode = \"allow-all\"\n[[sandboxes.a-fork-1.rules]]\nid = \"r-1\"\n\
             decision = \"deny\"\nresources = [\"stale.com\"]\n",
        );
        let mut f = SecretsFile::default();
        for scope in ["a", "a-fork-1"] {
            let entry = SecretEntry {
                service: "github".into(),
                scope: scope_for(Some(scope)),
                source: Source::Keychain,
            };
            t.ctx.store.set(&entry.account(), scope).unwrap();
            f.set(entry);
        }
        f.save(&t.ctx.paths).unwrap();
        parent(&t, "running", &[("sbx.secrets", "github")]);
        t.sbt(&["fork", "a"]).unwrap();
        let p = Policy::load(&t.ctx.paths).unwrap();
        assert!(!p.sandboxes.contains_key("a-fork-1"), "{:?}", p.sandboxes);
        let f = SecretsFile::load(&t.ctx.paths).unwrap();
        let scopes: Vec<_> = f.secrets.iter().map(|e| e.scope.as_str()).collect();
        assert_eq!(scopes, vec!["sandbox:a"]);
        assert_eq!(t.ctx.store.get("sandbox:a-fork-1/github").unwrap(), None);
        // The fork's next start falls back to the parent's secret.
        assert_eq!(
            f.entry_for("a-fork-1", Some("a"), "github").unwrap().scope,
            "sandbox:a"
        );
    }

    #[test]
    fn copies_the_parent_policy_entry() {
        let mut t = test_env(&[]);
        deny_rule_policy(&t);
        parent(&t, "running", &[]);
        t.sbt(&["fork", "a"]).unwrap();
        let p = Policy::load(&t.ctx.paths).unwrap();
        let rules = &p.sandboxes["a-fork-1"].rules;
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].resources, vec!["a.com"]);
        assert_eq!(p.sandboxes["a"].rules.len(), 1);
    }

    /// Parent labels, sbt args, and the expected error.
    type Refusal<'a> = (&'a [(&'a str, &'a str)], &'a [&'a str], &'a str);

    #[test]
    fn refusals_make_no_branch() {
        let cases: [Refusal; 4] = [
            (
                &[("sbx.workspace", "/w/p"), ("sbx.workspaces", "[\"/w/p\"]")],
                &["fork", "a"],
                "fork needs a sandbox with no writable host folder; create it with --clone",
            ),
            (
                &[("sbx.workspaces", "[\"/w/docs:ro\",\"/w/out\"]")],
                &["fork", "a"],
                "create it with --clone",
            ),
            (
                &[("sbx.fork-of", "x")],
                &["fork", "a"],
                "forking a fork isn't supported yet",
            ),
            (
                &[],
                &["fork", "a", "--name", "taken"],
                "sandbox 'taken' already exists",
            ),
        ];
        for (labels, args, msg) in cases {
            let mut t = test_env(&[]);
            parent(&t, "stopped", labels);
            exists(&t, "taken");
            let err = t.sbt(args).unwrap_err();
            assert!(format!("{err:#}").contains(msg), "{args:?}: {err:#}");
            assert!(branches(&t).is_empty(), "{args:?}");
            assert!(
                t.calls().iter().all(|c| !c.starts_with("machine start")),
                "{args:?}"
            );
        }
    }

    #[test]
    fn a_too_long_default_name_points_at_name() {
        let mut t = test_env(&[]);
        let long = "a".repeat(120);
        let machine = format!("sbx-{long}");
        let fake = t.runner();
        fake.fail(&["machine", "status"], "NOT_FOUND", "machine not found");
        fake.ok(
            &["machine", "status", "-n", &machine],
            &machine_json(&machine, "running", &[("sbx.name", &long)]),
        );
        let err = t.sbt_err(&["fork", &long]);
        assert!(
            err.contains("is too long (maximum 124 characters)"),
            "{err}"
        );
        assert!(
            err.ends_with("; use --name to choose a shorter one"),
            "{err}"
        );
        assert!(branches(&t).is_empty());
    }

    #[test]
    fn count_and_name_are_exclusive() {
        for args in [
            &["fork", "a", "--count", "1", "--name", "x"][..],
            &["fork", "a", "--count", "2", "--name", "x"][..],
            &["fork", "a", "--count", "0"][..],
        ] {
            let mut t = test_env(&[]);
            parent(&t, "running", &[]);
            assert!(t.sbt(args).is_err(), "{args:?}");
            assert!(t.runner().calls().is_empty(), "{args:?}");
        }
    }

    #[test]
    fn a_foreign_remote_is_refused() {
        let mut t = test_env(&[]);
        let (_d, repo) = temp_repo();
        let (r, ws) = clone_labels(&repo);
        git(
            &repo,
            &[
                "remote",
                "add",
                "sandbox-a-fork-1",
                "https://example.com/x.git",
            ],
        );
        parent(
            &t,
            "running",
            &[
                ("sbx.clone", "true"),
                ("sbx.workspace", &r),
                ("sbx.workspaces", &ws),
            ],
        );
        let err = t.sbt(&["fork", "a"]).unwrap_err();
        assert!(err.to_string().contains("already has a remote"), "{err:#}");
        assert!(branches(&t).is_empty());
    }

    #[test]
    fn a_read_only_extra_workspace_is_fine() {
        let mut t = test_env(&[]);
        let (_d, repo) = temp_repo();
        let (r, _) = clone_labels(&repo);
        let ws = serde_json::to_string(&[r.clone(), "/w/docs:ro".into()]).unwrap();
        parent(
            &t,
            "running",
            &[
                ("sbx.clone", "true"),
                ("sbx.workspace", &r),
                ("sbx.workspaces", &ws),
            ],
        );
        t.sbt(&["fork", "a"]).unwrap();
        assert_eq!(branches(&t), vec![branch("a-fork-1")]);

        let mut t = test_env(&[]);
        parent(&t, "running", &[("sbx.workspaces", "[\"/w/docs:ro\"]")]);
        t.sbt(&["fork", "a"]).unwrap();
        assert_eq!(branches(&t), vec![branch("a-fork-1")]);
    }

    #[test]
    fn starts_a_stopped_parent() {
        let mut t = test_env(&[]);
        parent(&t, "stopped", &[]);
        t.sbt(&["fork", "a"]).unwrap();
        let calls = t.calls();
        let start = calls
            .iter()
            .position(|c| c == "machine start -n sbx-a --branchable")
            .expect("started");
        let fork = calls
            .iter()
            .position(|c| c.starts_with("machine branch"))
            .expect("branched");
        assert!(start < fork, "{calls:?}");
    }

    #[test]
    fn not_branchable_gets_the_restart_hint() {
        let mut t = test_env(&[]);
        parent(&t, "running", &[]);
        t.runner()
            .fail(&["machine", "branch"], "SMOLVM_ERROR", NOT_BRANCHABLE);
        let err = format!("{:#}", t.sbt(&["fork", "a"]).unwrap_err());
        assert!(
            err.contains(
                "a was started without fork support; restart it once \
                 (`sbt stop a && sbt start a`) to enable fork"
            ),
            "{err}"
        );
    }

    #[test]
    fn chain_depth_gets_the_limit_hint() {
        let mut t = test_env(&[]);
        parent(&t, "running", &[]);
        t.runner()
            .fail(&["machine", "branch"], "CONFLICT", CHAIN_DEPTH);
        let err = format!("{:#}", t.sbt(&["fork", "a"]).unwrap_err());
        assert!(
            err.contains("smolvm limits how deep a chain of copies can get: smolvm: "),
            "{err}"
        );
        assert!(err.contains("the safe limit is 32"), "{err}");
        // The original error stays in the chain.
        assert!(
            t.sbt(&["fork", "a"])
                .unwrap_err()
                .chain()
                .any(|c| c.downcast_ref::<SmolvmError>().is_some())
        );
    }

    #[test]
    fn other_branch_errors_pass_through() {
        let mut t = test_env(&[]);
        parent(&t, "running", &[]);
        t.runner()
            .fail(&["machine", "branch"], "SMOLVM_ERROR", "boom");
        let err = format!("{:#}", t.sbt(&["fork", "a"]).unwrap_err());
        assert_eq!(err, "forking a as a-fork-1: smolvm: boom");
    }

    #[test]
    fn a_failed_branch_rolls_back() {
        let mut t = test_env(&[]);
        deny_rule_policy(&t);
        let (_d, repo) = temp_repo();
        let (r, ws) = clone_labels(&repo);
        let clone = [
            ("sbx.clone", "true"),
            ("sbx.workspace", r.as_str()),
            ("sbx.workspaces", ws.as_str()),
        ];
        parent(&t, "running", &clone);
        t.runner()
            .fail(&["machine", "branch"], "SMOLVM_ERROR", "boom");
        t.sbt(&["fork", "a"]).unwrap_err();
        let p = Policy::load(&t.ctx.paths).unwrap();
        assert!(!p.sandboxes.contains_key("a-fork-1"));
        assert!(p.sandboxes.contains_key("a"));
        assert_eq!(remote(&repo, "a-fork-1", "url"), "");

        // The second of two fails: the first stays.
        let mut t = test_env(&[]);
        deny_rule_policy(&t);
        parent(&t, "running", &clone);
        t.runner().fail(
            &["machine", "branch", "--from", "sbx-a", "-n", "sbx-a-fork-2"],
            "SMOLVM_ERROR",
            "boom",
        );
        let err = format!("{:#}", t.sbt(&["fork", "a", "--count", "2"]).unwrap_err());
        assert!(err.contains("forking a as a-fork-2"), "{err}");
        assert_eq!(branches(&t), vec![branch("a-fork-1"), branch("a-fork-2")]);
        let p = Policy::load(&t.ctx.paths).unwrap();
        assert!(p.sandboxes.contains_key("a-fork-1"));
        assert!(!p.sandboxes.contains_key("a-fork-2"));
        assert_eq!(remote(&repo, "a-fork-1", "url"), "file:///sbt/a-fork-1");
        assert_eq!(remote(&repo, "a-fork-2", "url"), "");
    }
}
