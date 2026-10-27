//! fork: copy-on-write copies of a running sandbox (smolvm `machine branch`), for parallel attempts
//! or as an undo point. smolbento-only (sbx has no fork).

use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};

use super::{Ctx, ForkArgs, plan};
use crate::policy::Policy;
use crate::sandbox::{self, Sandbox, labels, name};
use crate::smolvm::{Runner, SmolvmError};
use crate::workspace::clone;

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
        println!("{n}");
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
            name::validate(&candidate)?;
            out.push(candidate);
        }
        n += 1;
    }
    Ok(out)
}

/// Copies the parent's policy entry and adds the clone remote, then branches; a failed branch
/// undoes both (a failed undo only warns).
fn fork_one<R: Runner>(
    ctx: &Ctx<R>,
    parent: &Sandbox,
    fork: &str,
    env: &[(String, String)],
    remove: &[String],
) -> Result<()> {
    let mut policy = Policy::load(&ctx.paths)?;
    // The name is free, so an entry under it is stale (say, a machine deleted with raw smolvm).
    policy.forget_sandbox(fork);
    policy.copy_sandbox(parent.name(), fork);
    policy.save(&ctx.paths)?;
    let repo = parent.meta.clone_repo.as_deref().map(Path::new);
    let added_remote = match repo {
        Some(r) => clone::add_remote(r, fork),
        None => Ok(false),
    };
    let result = added_remote.and_then(|added| {
        let labels = [
            (labels::NAME.to_string(), fork.to_string()),
            (labels::FORK_OF.to_string(), parent.name().to_string()),
            // A child inherits its source's labels; a fork's age is its own.
            (labels::CREATED.to_string(), ctx.now.to_string()),
        ];
        ctx.vm
            .branch(
                &parent.machine,
                &name::machine_name(fork),
                &labels,
                env,
                remove,
            )
            .map_err(|e| branch_hint(e, parent.name()))
            .inspect_err(|_| {
                if let (Some(r), true) = (repo, added)
                    && let Err(e) = clone::remove_remote(r, fork)
                {
                    eprintln!("warning: removing the sandbox-{fork} remote: {e:#}");
                }
            })
    });
    if result.is_err() {
        // Nothing was created: undo the policy copy made for it.
        let undo = || -> Result<()> {
            let mut p = Policy::load(&ctx.paths)?;
            p.forget_sandbox(fork);
            p.save(&ctx.paths)
        };
        if let Err(e) = undo() {
            eprintln!("warning: removing {fork}'s policy entry: {e:#}");
        }
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
            "{parent} was started before fork support; restart it once \
             (`sbt stop {parent} && sbt start {parent}`) to enable fork"
        );
    }
    if message.contains("qcow2 backing layers") || message.contains("safe backing depth") {
        return anyhow!("{e}; a sandbox can be forked about 30 times");
    }
    e
}

#[cfg(test)]
mod tests {
    use super::super::testutil::*;
    use crate::policy::Policy;
    use crate::secrets::{SecretEntry, SecretsFile, Source, scope_for};

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
        let fake = t.ctx.vm.runner();
        fake.fail(&["machine", "status"], "NOT_FOUND", "machine not found");
        fake.ok(
            &["machine", "status", "-n", "sbx-a"],
            &machine_json("sbx-a", state, &labels),
        );
    }

    fn exists(t: &TestEnv, name: &str) {
        let machine = format!("sbx-{name}");
        t.ctx.vm.runner().ok(
            &["machine", "status", "-n", &machine],
            &machine_json(&machine, "running", &[("sbx.name", name)]),
        );
    }

    fn branches(t: &TestEnv) -> Vec<String> {
        t.ctx
            .vm
            .runner()
            .call_lines()
            .into_iter()
            .filter(|c| c.starts_with("machine branch"))
            .collect()
    }

    fn branch(fork: &str) -> String {
        format!(
            "machine branch --from sbx-a -n sbx-{fork} --label sbx.name={fork} \
             --label sbx.fork-of=a --label sbx.created=1000000"
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
        assert_eq!(sbt(&mut t.ctx, &["fork", "a"]).unwrap(), 0);
        assert_eq!(branches(&t), vec![branch("a-fork-1")]);
        assert_eq!(remote(&repo, "a-fork-1", "url"), "file:///sbt/a-fork-1");
        assert_eq!(
            remote(&repo, "a-fork-1", "uploadpack"),
            "smolbento _upload-pack a-fork-1"
        );
        assert_eq!(remote(&repo, "a-fork-1", "tagOpt"), "--no-tags");
    }

    #[test]
    fn default_names_skip_taken_ones() {
        let mut t = test_env(&[]);
        parent(&t, "running", &[]);
        exists(&t, "a-fork-1");
        sbt(&mut t.ctx, &["fork", "a"]).unwrap();
        assert_eq!(branches(&t), vec![branch("a-fork-2")]);

        let mut t = test_env(&[]);
        parent(&t, "running", &[]);
        exists(&t, "a-fork-1");
        sbt(&mut t.ctx, &["fork", "a", "--count", "2"]).unwrap();
        assert_eq!(branches(&t), vec![branch("a-fork-2"), branch("a-fork-3")]);
    }

    #[test]
    fn name_names_the_copy() {
        let mut t = test_env(&[]);
        parent(&t, "running", &[]);
        sbt(&mut t.ctx, &["fork", "a", "--name", "try.2"]).unwrap();
        assert_eq!(
            branches(&t),
            vec![
                "machine branch --from sbx-a -n sbx-try_2 --label sbx.name=try.2 \
                 --label sbx.fork-of=a --label sbx.created=1000000"
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
        sbt(&mut t.ctx, &["fork", "a"]).unwrap();
        let fake = t.ctx.vm.runner();
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
        let err = sbt(&mut t.ctx, &["fork", "a"]).unwrap_err().to_string();
        assert_eq!(err, "fork is turned off (fork.enabled=false)");
        let calls = t.ctx.vm.runner().call_lines();
        assert!(calls.iter().all(|c| !c.starts_with("machine")), "{calls:?}");
    }

    #[test]
    fn a_stale_policy_entry_for_the_name_is_dropped() {
        let mut t = test_env(&[]);
        set_policy(
            &t,
            "mode = \"allow-all\"\n[[sandboxes.a-fork-1.rules]]\nid = \"r-1\"\n\
             decision = \"deny\"\nresources = [\"stale.com\"]\n",
        );
        parent(&t, "running", &[]);
        sbt(&mut t.ctx, &["fork", "a"]).unwrap();
        let p = Policy::load(&t.ctx.paths).unwrap();
        assert!(!p.sandboxes.contains_key("a-fork-1"), "{:?}", p.sandboxes);
    }

    #[test]
    fn copies_the_parent_policy_entry() {
        let mut t = test_env(&[]);
        deny_rule_policy(&t);
        parent(&t, "running", &[]);
        sbt(&mut t.ctx, &["fork", "a"]).unwrap();
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
            let err = sbt(&mut t.ctx, args).unwrap_err();
            assert!(format!("{err:#}").contains(msg), "{args:?}: {err:#}");
            assert!(branches(&t).is_empty(), "{args:?}");
            assert!(
                t.ctx
                    .vm
                    .runner()
                    .call_lines()
                    .iter()
                    .all(|c| !c.starts_with("machine start")),
                "{args:?}"
            );
        }
    }

    #[test]
    fn count_and_name_are_exclusive() {
        for args in [
            &["fork", "a", "--count", "2", "--name", "x"][..],
            &["fork", "a", "--count", "0"][..],
        ] {
            let mut t = test_env(&[]);
            parent(&t, "running", &[]);
            assert!(sbt(&mut t.ctx, args).is_err(), "{args:?}");
            assert!(t.ctx.vm.runner().calls().is_empty(), "{args:?}");
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
        let err = sbt(&mut t.ctx, &["fork", "a"]).unwrap_err();
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
        sbt(&mut t.ctx, &["fork", "a"]).unwrap();
        assert_eq!(branches(&t), vec![branch("a-fork-1")]);

        let mut t = test_env(&[]);
        parent(&t, "running", &[("sbx.workspaces", "[\"/w/docs:ro\"]")]);
        sbt(&mut t.ctx, &["fork", "a"]).unwrap();
        assert_eq!(branches(&t), vec![branch("a-fork-1")]);
    }

    #[test]
    fn starts_a_stopped_parent() {
        let mut t = test_env(&[]);
        parent(&t, "stopped", &[]);
        sbt(&mut t.ctx, &["fork", "a"]).unwrap();
        let calls = t.ctx.vm.runner().call_lines();
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
        t.ctx
            .vm
            .runner()
            .fail(&["machine", "branch"], "SMOLVM_ERROR", NOT_BRANCHABLE);
        let err = format!("{:#}", sbt(&mut t.ctx, &["fork", "a"]).unwrap_err());
        assert!(
            err.contains(
                "a was started before fork support; restart it once \
                 (`sbt stop a && sbt start a`) to enable fork"
            ),
            "{err}"
        );
    }

    #[test]
    fn chain_depth_gets_the_limit_hint() {
        let mut t = test_env(&[]);
        parent(&t, "running", &[]);
        t.ctx
            .vm
            .runner()
            .fail(&["machine", "branch"], "CONFLICT", CHAIN_DEPTH);
        let err = format!("{:#}", sbt(&mut t.ctx, &["fork", "a"]).unwrap_err());
        assert!(err.contains("the safe limit is 32"), "{err}");
        assert!(
            err.contains("a sandbox can be forked about 30 times"),
            "{err}"
        );
    }

    #[test]
    fn other_branch_errors_pass_through() {
        let mut t = test_env(&[]);
        parent(&t, "running", &[]);
        t.ctx
            .vm
            .runner()
            .fail(&["machine", "branch"], "SMOLVM_ERROR", "boom");
        let err = format!("{:#}", sbt(&mut t.ctx, &["fork", "a"]).unwrap_err());
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
        t.ctx
            .vm
            .runner()
            .fail(&["machine", "branch"], "SMOLVM_ERROR", "boom");
        sbt(&mut t.ctx, &["fork", "a"]).unwrap_err();
        let p = Policy::load(&t.ctx.paths).unwrap();
        assert!(!p.sandboxes.contains_key("a-fork-1"));
        assert!(p.sandboxes.contains_key("a"));
        assert_eq!(remote(&repo, "a-fork-1", "url"), "");

        // The second of two fails: the first stays.
        let mut t = test_env(&[]);
        deny_rule_policy(&t);
        parent(&t, "running", &clone);
        t.ctx.vm.runner().fail(
            &["machine", "branch", "--from", "sbx-a", "-n", "sbx-a-fork-2"],
            "SMOLVM_ERROR",
            "boom",
        );
        let err = format!(
            "{:#}",
            sbt(&mut t.ctx, &["fork", "a", "--count", "2"]).unwrap_err()
        );
        assert!(err.contains("forking a as a-fork-2"), "{err}");
        assert_eq!(branches(&t), vec![branch("a-fork-1"), branch("a-fork-2")]);
        let p = Policy::load(&t.ctx.paths).unwrap();
        assert!(p.sandboxes.contains_key("a-fork-1"));
        assert!(!p.sandboxes.contains_key("a-fork-2"));
        assert_eq!(remote(&repo, "a-fork-1", "url"), "file:///sbt/a-fork-1");
        assert_eq!(remote(&repo, "a-fork-2", "url"), "");
    }
}
