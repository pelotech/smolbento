//! run: create the sandbox if needed, start it, attach to the agent, and stop it when the last
//! session ends (unless it was started with -d).

use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result, bail};

use super::lifecycle::{has_kit_flags, kit_plan, kit_target, resolve_clone};
use super::plan;
use super::{Ctx, RunArgs, Unsupported};
use crate::agents;
use crate::sandbox::{self, Sandbox, session};
use crate::smolvm::{ExecSpec, Runner, SmolvmError};
use crate::workspace::clone;

/// Flag checks that need no smolvm; `dispatch` runs them before its smolvm gate.
pub fn check_args(a: &RunArgs) -> Result<()> {
    a.opts.check_supported()?;
    if a.new {
        return Err(Unsupported("--new is a Docker Cloud option".into()).into());
    }
    if a.detach_keys.is_some() {
        return Err(Unsupported("--detach-keys is not supported".into()).into());
    }
    if a.rm && a.detach {
        bail!("--rm can't be combined with -d");
    }
    Ok(())
}

pub fn run<R: Runner>(ctx: &mut Ctx<R>, a: &RunArgs) -> Result<i32> {
    super::lifecycle::check_kit_args(&a.targets, &a.opts)?;
    let existing = match &a.opts.name {
        Some(n) => sandbox::find(&ctx.vm, n)?,
        None => None,
    };
    let kits_ignored = |sb: &Sandbox| {
        if let Some(w) = ignored_kits_warning(a, sb.name()) {
            eprintln!("{w}");
        }
    };
    let (mut sb, created) = match existing {
        Some(sb) => {
            kits_ignored(&sb);
            (sb, false)
        }
        None => {
            if a.targets.is_empty() {
                bail!(
                    "specify an agent (e.g. `sbt run claude`) or the --name of an existing sandbox"
                );
            }
            // The name first: attaching to an existing sandbox loads no kits.
            let (mut req, workload) = kit_target(ctx, &a.targets, &a.opts, true)?;
            match sandbox::find(&ctx.vm, &req.name)? {
                Some(sb) => {
                    kits_ignored(&sb);
                    (sb, false)
                }
                None => {
                    let kits = workload
                        .map(|w| kit_plan(ctx, &mut req, w, &a.opts))
                        .transpose()?;
                    resolve_clone(&mut req, &a.opts)?;
                    (
                        plan::create(ctx, &mut req, &a.opts.deny_network, kits.as_ref())?,
                        true,
                    )
                }
            }
        }
    };
    if !a.opts.deny_network.is_empty() && !created {
        eprintln!(
            "warning: --deny-network only adds rules when a sandbox is created; {} already exists \
             (use `sbt policy deny network --sandbox {}`)",
            sb.name(),
            sb.name()
        );
    }
    plan::ensure_running(ctx, &mut sb)?;

    let sessions = ctx.paths.sessions();
    if a.detach {
        session::mark_detached(&sessions, sb.name())?;
        writeln!(&ctx.out, "{}", sb.name())?;
        return Ok(0);
    }

    // A workload kit's command, else the preset's.
    let command: Vec<String> = match &sb.meta.command {
        Some(c) => c.clone(),
        None => agents::find(&sb.meta.agent)
            .with_context(|| {
                format!(
                    "sandbox '{}' has no known agent ('{}')",
                    sb.name(),
                    sb.meta.agent
                )
            })?
            .command
            .iter()
            .map(|s| s.to_string())
            .collect(),
    };
    let mut spec = ExecSpec {
        name: sb.machine.clone(),
        user: Some("agent".into()),
        workdir: Some(sb.workdir()),
        interactive: true,
        tty: ctx.stdin_tty,
        cmd: agents::command_with_args(&command, &a.agent_args),
        ..Default::default()
    };
    sandbox::env::session_tz(&ctx.env, spec.tty, &mut spec.env);
    // A v3 workload runs as its image user, through bash so the image's BASH_ENV is sourced.
    let image_user = sandbox::launch_user(&ctx.vm, &sb);
    if let Some(user) = &image_user {
        spec.user = Some(user.clone());
        spec.cmd = [BASH, "-c", "exec -- \"$@\"", "bash"]
            .into_iter()
            .map(String::from)
            .chain(spec.cmd)
            .collect();
    }
    let code = {
        let _session = session::Session::register(&sessions, sb.name())?;
        if image_user.is_some() && !has_bash(ctx, &sb)? {
            // sbx's error for such an image, and the code its agent exits with.
            eprintln!("executable file '{BASH}' not found");
            127
        } else {
            ctx.vm.exec(&spec)?
        }
    };

    // Fetch before `--rm` deletes the sandbox, and while it still runs for `_upload-pack`.
    if fetch_on_exit(ctx, &sb)
        && let Some(repo) = &sb.meta.clone_repo
        && let Err(e) = clone::fetch(Path::new(repo), sb.name())
    {
        eprintln!("warning: fetching the agent's commits: {e:#}");
    }

    // The agent's exit code is the result; failing to clean up after it only warrants a warning.
    if a.rm {
        match ctx.vm.delete(&sb.machine) {
            Ok(()) => session::clear(&sessions, sb.name()),
            Err(e) => eprintln!("warning: removing sandbox {}: {e:#}", sb.name()),
        }
    } else if !sb.meta.long_running
        && session::idle(&sessions, sb.name())
        && let Err(e) = ctx.vm.stop(&sb.machine)
    {
        eprintln!("warning: stopping sandbox {}: {e:#}", sb.name());
    }
    Ok(code)
}

const BASH: &str = "/bin/bash";

/// Whether the guest can run `/bin/bash`, which a v3 workload's agent is launched through.
/// Runs bash itself, so the image needs no `/bin/sh` for the check. An error smolvm reports (the
/// machine gone, say) is that error, not a missing bash.
fn has_bash<R: Runner>(ctx: &Ctx<R>, sb: &Sandbox) -> Result<bool> {
    let out = ctx.vm.exec_output(&ExecSpec {
        name: sb.machine.clone(),
        cmd: vec![BASH.into(), "-c".into(), ":".into()],
        ..Default::default()
    })?;
    if out.code == 0 {
        return Ok(true);
    }
    match SmolvmError::from_json(&out) {
        Some(e) => Err(e.into()),
        None => Ok(false),
    }
}

/// The warning for kits given to `run` of a sandbox that already exists: kit flags, or a workload
/// kit as the target.
fn ignored_kits_warning(a: &RunArgs, name: &str) -> Option<String> {
    let kit_target = a.targets.first().is_some_and(|t| agents::find(t).is_none());
    (has_kit_flags(&a.opts) || kit_target).then(|| {
        format!("warning: kits only apply when a sandbox is created; {name} already exists")
    })
}

/// A bad setting value only skips the fetch: the stop or `--rm` and the agent's status still apply.
fn fetch_on_exit<R: Runner>(ctx: &Ctx<R>, sb: &Sandbox) -> bool {
    sb.meta.clone_repo.is_some()
        && ctx
            .settings
            .bool("clone.fetch-on-exit")
            .unwrap_or_else(|e| {
                eprintln!("warning: not fetching the agent's commits: {e:#}");
                false
            })
}

#[cfg(test)]
mod tests {
    use super::super::testutil::*;
    use crate::sandbox::session;

    fn created(t: &TestEnv, state: &str) {
        let ws = t.ctx.cwd.display().to_string();
        t.ctx.vm.runner().ok(
            &["machine", "status"],
            &machine_json(
                "sbx-claude-proj",
                state,
                &[
                    ("sbx.name", "claude-proj"),
                    ("sbx.agent", "claude"),
                    ("sbx.workspace", ws.as_str()),
                ],
            ),
        );
    }

    #[test]
    fn clone_is_ignored_when_run_attaches_to_an_existing_sandbox() {
        let mut t = test_env(&[]);
        created(&t, "running");
        t.ctx.vm.runner().interactive_exit(0);
        // cwd is not a git repo, yet --clone must not matter for an existing sandbox.
        sbt(&mut t.ctx, &["run", "claude", "--clone"]).unwrap();
        assert!(
            !t.ctx
                .vm
                .runner()
                .call_lines()
                .iter()
                .any(|l| l.contains("machine create"))
        );
    }

    #[test]
    fn creates_attaches_and_stops_after_the_last_session() {
        let mut t = test_env(&[]);
        created(&t, "created");
        // run looks the name up, then plan::create checks again before creating.
        t.ctx
            .vm
            .runner()
            .once_fail(&["machine", "status"], "NOT_FOUND", "vm not found");
        t.ctx
            .vm
            .runner()
            .once_fail(&["machine", "status"], "NOT_FOUND", "vm not found");
        t.ctx.vm.runner().interactive_exit(0);
        assert_eq!(
            sbt(
                &mut t.ctx,
                &["run", "claude", "--cpus", "1", "-m", "1g", "--", "-c"]
            )
            .unwrap(),
            0
        );

        let ws = t.ctx.cwd.display().to_string();
        assert_eq!(
            t.ctx.vm.runner().interactive_calls()[0].join(" "),
            format!(
                "machine exec --name sbx-claude-proj -u agent -w {ws} -i -- claude --dangerously-skip-permissions -c"
            )
        );
        let lines = t.ctx.vm.runner().call_lines();
        assert!(
            lines
                .iter()
                .any(|l| l.starts_with("machine create -n sbx-claude-proj"))
        );
        assert!(
            lines.iter().any(|l| l.ends_with("usermod -o -u 501 agent")),
            "the agent takes ctx.uid: {lines:?}"
        );
        assert_eq!(lines.last().unwrap(), "machine stop -n sbx-claude-proj");
        assert_eq!(
            session::live_sessions(&t.ctx.paths.sessions(), "claude-proj"),
            0
        );
    }

    #[test]
    fn a_failed_create_does_not_leave_deny_rules_behind() {
        let mut t = test_env(&[]);
        let fake = t.ctx.vm.runner();
        fake.fail(&["machine", "status"], "NOT_FOUND", "vm not found");
        fake.fail(&["machine", "create"], "CREATE_FAILED", "no space left");
        assert!(sbt(&mut t.ctx, &["run", "claude", "--deny-network", "evil.com"]).is_err());
        let p = crate::policy::Policy::load(&t.ctx.paths).unwrap();
        assert!(p.sandboxes.is_empty(), "{p:?}");
    }

    #[test]
    fn deny_network_adds_sandbox_deny_rules_at_create() {
        let mut t = test_env(&[]);
        created(&t, "created");
        // run looks the name up, then plan::create checks again before creating.
        for _ in 0..2 {
            t.ctx
                .vm
                .runner()
                .once_fail(&["machine", "status"], "NOT_FOUND", "vm not found");
        }
        t.ctx.vm.runner().interactive_exit(0);
        sbt(
            &mut t.ctx,
            &[
                "run",
                "claude",
                "--deny-network",
                "a.example,b.example",
                "--deny-network",
                "c.example",
            ],
        )
        .unwrap();
        let p = crate::policy::Policy::load(&t.ctx.paths).unwrap();
        let rules: Vec<Vec<String>> = p.sandboxes["claude-proj"]
            .rules
            .iter()
            .map(|r| {
                assert_eq!(r.decision, crate::policy::Decision::Deny);
                r.resources.clone()
            })
            .collect();
        assert_eq!(
            rules,
            vec![
                vec!["a.example".to_string()],
                vec!["b.example".to_string()],
                vec!["c.example".to_string()]
            ]
        );
        assert!(p.rules.is_empty());
    }

    #[test]
    fn running_an_existing_sandbox_records_nothing_and_starting_it_needs_a_policy() {
        let mut t = test_env(&[]);
        std::fs::remove_file(t.ctx.paths.policy_file()).unwrap();
        created(&t, "running");
        t.ctx.vm.runner().interactive_exit(0);
        assert_eq!(
            sbt(&mut t.ctx, &["run", "claude", "--deny-network", "evil.com"]).unwrap(),
            0
        );
        assert!(!t.ctx.paths.policy_file().exists());
        let lines = t.ctx.vm.runner().call_lines();
        assert!(!lines.iter().any(|l| l.contains("create")), "{lines:?}");

        // A stopped one has to start, and every start needs a policy.
        let mut t = test_env(&[]);
        std::fs::remove_file(t.ctx.paths.policy_file()).unwrap();
        created(&t, "stopped");
        let err = sbt(&mut t.ctx, &["run", "claude", "--deny-network", "evil.com"])
            .unwrap_err()
            .to_string();
        assert!(err.contains("sbt policy init"), "{err}");
        assert!(!t.ctx.paths.policy_file().exists());
        let lines = t.ctx.vm.runner().call_lines();
        assert!(
            !lines
                .iter()
                .any(|l| l.contains("create") || l.contains("start")),
            "{lines:?}"
        );
    }

    #[test]
    fn reattaches_by_name_and_returns_the_agent_status() {
        let mut t = test_env(&[]);
        created(&t, "running");
        t.ctx.vm.runner().interactive_exit(42);
        assert_eq!(
            sbt(&mut t.ctx, &["run", "--name", "claude-proj"]).unwrap(),
            42
        );
        assert!(
            !t.ctx
                .vm
                .runner()
                .call_lines()
                .iter()
                .any(|l| l.contains("create"))
        );
    }

    #[test]
    fn detach_leaves_it_running_and_later_runs_keep_it() {
        let mut t = test_env(&[]);
        created(&t, "running");
        sbt(&mut t.ctx, &["run", "-d", "--name", "claude-proj"]).unwrap();
        assert!(t.ctx.vm.runner().interactive_calls().is_empty());
        sbt(&mut t.ctx, &["run", "--name", "claude-proj"]).unwrap();
        assert!(
            !t.ctx
                .vm
                .runner()
                .call_lines()
                .iter()
                .any(|l| l.contains("stop"))
        );
    }

    #[test]
    fn rm_deletes_after_exit() {
        let mut t = test_env(&[]);
        created(&t, "running");
        sbt(&mut t.ctx, &["run", "--rm", "--name", "claude-proj"]).unwrap();
        assert_eq!(
            t.ctx.vm.runner().call_lines().last().unwrap(),
            "machine delete -n sbx-claude-proj -f"
        );
    }

    #[test]
    fn cleanup_failures_warn_and_keep_the_agent_status() {
        let mut t = test_env(&[]);
        created(&t, "running");
        t.ctx.vm.runner().interactive_exit(7);
        t.ctx
            .vm
            .runner()
            .fail(&["machine", "stop"], "SMOLVM_ERROR", "boom");
        assert_eq!(
            sbt(&mut t.ctx, &["run", "--name", "claude-proj"]).unwrap(),
            7
        );
        t.ctx
            .vm
            .runner()
            .fail(&["machine", "delete"], "SMOLVM_ERROR", "boom");
        assert_eq!(
            sbt(&mut t.ctx, &["run", "--rm", "--name", "claude-proj"]).unwrap(),
            7
        );
    }

    #[test]
    fn unsupported_flags_exit_2_even_without_a_usable_smolvm() {
        let mut t = test_env(&[]);
        t.ctx.vm.runner().ok(&["--version"], "smolvm 1.0.0\n");
        for args in [
            &["run", "claude", "--skills", "off"][..],
            &["create", "claude", "--skills", "off"][..],
            &["run", "claude", "--new"][..],
        ] {
            let err = sbt(&mut t.ctx, args).unwrap_err();
            assert_eq!(super::super::exit_code(&err), 2, "{args:?}: {err}");
        }
        assert!(t.ctx.vm.runner().calls().is_empty());
    }

    #[test]
    fn argument_errors() {
        let mut t = test_env(&[]);
        assert!(
            sbt(&mut t.ctx, &["run"])
                .unwrap_err()
                .to_string()
                .contains("specify an agent")
        );
        assert!(
            sbt(&mut t.ctx, &["run", "-d", "--rm", "claude"])
                .unwrap_err()
                .to_string()
                .contains("--rm")
        );
    }

    fn clone_sandbox(t: &TestEnv, ws: &std::path::Path) {
        t.ctx.vm.runner().ok(
            &["machine", "status"],
            &machine_json(
                "sbx-claude-proj",
                "running",
                &[
                    ("sbx.name", "claude-proj"),
                    ("sbx.agent", "claude"),
                    ("sbx.workspace", &ws.display().to_string()),
                    ("sbx.clone", "true"),
                ],
            ),
        );
    }

    #[test]
    fn a_failed_fetch_warns_and_keeps_the_agent_status_and_the_stop() {
        let mut t = test_env(&[]);
        // The remote's upload-pack records that the fetch ran, then fails it.
        let (_keep, repo) = temp_repo();
        let marker = repo.parent().unwrap().join("fetch-ran");
        git(
            &repo,
            &[
                "remote",
                "add",
                "sandbox-claude-proj",
                "file:///sbt/claude-proj",
            ],
        );
        git(
            &repo,
            &[
                "config",
                "remote.sandbox-claude-proj.uploadpack",
                &format!("touch '{}'; exit 1 #", marker.display()),
            ],
        );
        clone_sandbox(&t, &repo);
        t.ctx.vm.runner().interactive_exit(5);
        assert_eq!(
            sbt(&mut t.ctx, &["run", "--name", "claude-proj"]).unwrap(),
            5
        );
        assert!(marker.exists(), "the fetch was never attempted");
        assert_eq!(
            t.ctx.vm.runner().call_lines().last().unwrap(),
            "machine stop -n sbx-claude-proj"
        );
    }

    #[test]
    fn fetch_on_exit_needs_a_clone_and_the_setting() {
        let (_keep, repo) = temp_repo();
        for (env, clone, want) in [
            (&[][..], true, true),
            (
                &[("SMOLBENTO_CLONE_FETCH_ON_EXIT", "false")][..],
                true,
                false,
            ),
            (&[][..], false, false),
        ] {
            let t = test_env(env);
            if clone {
                clone_sandbox(&t, &repo);
            } else {
                created(&t, "running");
            }
            let sb = crate::sandbox::find(&t.ctx.vm, "claude-proj")
                .unwrap()
                .unwrap();
            assert_eq!(super::fetch_on_exit(&t.ctx, &sb), want);
        }
    }

    fn kit_sandbox(t: &TestEnv, long_running: bool) {
        let ws = t.ctx.cwd.display().to_string();
        let mut labels = vec![
            ("sbx.name", "toolbox-proj"),
            ("sbx.agent", "toolbox"),
            ("sbx.workspace", ws.as_str()),
            ("sbx.command", r#"["/bin/agent","--x"]"#),
        ];
        if long_running {
            labels.push(("sbx.long-running", "true"));
        }
        t.ctx.vm.runner().ok(
            &["machine", "status"],
            &machine_json("sbx-toolbox-proj", "running", &labels),
        );
        t.ctx.vm.runner().interactive_exit(0);
    }

    #[test]
    fn run_launches_a_kit_sandboxs_command() {
        let mut t = test_env(&[]);
        kit_sandbox(&t, false);
        sbt(
            &mut t.ctx,
            &["run", "--name", "toolbox-proj", "--", "--y", "z"],
        )
        .unwrap();
        let ws = t.ctx.cwd.display().to_string();
        assert_eq!(
            t.ctx.vm.runner().interactive_calls()[0].join(" "),
            format!(
                "machine exec --name sbx-toolbox-proj -u agent -w {ws} -i -- /bin/agent --x --y z"
            )
        );
        assert_eq!(
            t.ctx.vm.runner().call_lines().last().unwrap(),
            "machine stop -n sbx-toolbox-proj"
        );
    }

    /// A v3 workload kit's sandbox: its image user is recorded.
    fn image_user_sandbox(t: &TestEnv) {
        let ws = t.ctx.cwd.display().to_string();
        t.ctx.vm.runner().ok(
            &["machine", "status"],
            &machine_json(
                "sbx-toolbox-proj",
                "running",
                &[
                    ("sbx.name", "toolbox-proj"),
                    ("sbx.agent", "toolbox"),
                    ("sbx.workspace", ws.as_str()),
                    ("sbx.command", r#"["/bin/agent","--x"]"#),
                    ("sbx.user", "somebody"),
                ],
            ),
        );
        t.ctx.vm.runner().interactive_exit(0);
    }

    #[test]
    fn run_launches_a_v3_workload_as_its_image_user_under_bash() {
        let mut t = test_env(&[]);
        image_user_sandbox(&t);
        sbt(
            &mut t.ctx,
            &["run", "--name", "toolbox-proj", "--", "--y", "z"],
        )
        .unwrap();
        let ws = t.ctx.cwd.display().to_string();
        assert_eq!(
            t.ctx.vm.runner().interactive_calls()[0].join(" "),
            format!(
                "machine exec --name sbx-toolbox-proj -u somebody -w {ws} -i -- \
                 /bin/bash -c exec -- \"$@\" bash /bin/agent --x --y z"
            )
        );
        assert!(
            t.ctx
                .vm
                .runner()
                .call_lines()
                .contains(&"machine exec --name sbx-toolbox-proj -- /bin/bash -c :".into())
        );
    }

    #[test]
    fn run_launches_a_numeric_image_user_as_its_mapped_account() {
        let mut t = test_env(&[]);
        let ws = t.ctx.cwd.display().to_string();
        t.ctx.vm.runner().ok(
            &["machine", "status"],
            &machine_json(
                "sbx-toolbox-proj",
                "running",
                &[
                    ("sbx.name", "toolbox-proj"),
                    ("sbx.agent", "toolbox"),
                    ("sbx.workspace", ws.as_str()),
                    ("sbx.command", r#"["/bin/agent"]"#),
                    ("sbx.user", "1000"),
                ],
            ),
        );
        t.ctx.vm.runner().interactive_exit(0);
        // The start recorded uid 1000's account (`agent`, since moved to the host uid).
        t.ctx.vm.runner().download(b"agent\n");
        sbt(&mut t.ctx, &["run", "--name", "toolbox-proj"]).unwrap();
        assert_eq!(
            t.ctx.vm.runner().interactive_calls()[0].join(" "),
            format!(
                "machine exec --name sbx-toolbox-proj -u agent -w {ws} -i -- \
                 /bin/bash -c exec -- \"$@\" bash /bin/agent"
            )
        );
    }

    #[test]
    fn run_without_bash_in_the_image_fails_like_sbx() {
        let mut t = test_env(&[]);
        image_user_sandbox(&t);
        t.ctx.vm.runner().on(
            &[
                "machine",
                "exec",
                "--name",
                "sbx-toolbox-proj",
                "--",
                "/bin/bash",
            ],
            crate::smolvm::Output {
                code: 1,
                ..Default::default()
            },
        );
        let code = sbt(&mut t.ctx, &["run", "--name", "toolbox-proj"]).unwrap();
        assert_eq!(code, 127);
        assert!(t.ctx.vm.runner().interactive_calls().is_empty());
        assert_eq!(
            t.ctx.vm.runner().call_lines().last().unwrap(),
            "machine stop -n sbx-toolbox-proj"
        );
    }

    #[test]
    fn a_smolvm_error_from_the_bash_probe_is_not_a_missing_bash() {
        let mut t = test_env(&[]);
        image_user_sandbox(&t);
        t.ctx.vm.runner().fail(
            &[
                "machine",
                "exec",
                "--name",
                "sbx-toolbox-proj",
                "--",
                "/bin/bash",
            ],
            "AGENT_ERROR",
            "the guest agent is not responding",
        );
        let err = sbt(&mut t.ctx, &["run", "--name", "toolbox-proj"]).unwrap_err();
        assert!(
            format!("{err:#}").contains("the guest agent is not responding"),
            "{err:#}"
        );
        assert!(t.ctx.vm.runner().interactive_calls().is_empty());
    }

    #[test]
    fn attaching_to_an_existing_sandbox_loads_no_kits() {
        let mut t = test_env(&[("SMOLBENTO_KIT_ALLOW_LOCAL_KITS", "true")]);
        created(&t, "running");
        t.ctx.vm.runner().interactive_exit(0);
        // Loading either would fail: the path doesn't exist.
        sbt(
            &mut t.ctx,
            &[
                "run",
                "claude",
                "--kit",
                "./no-such-kit",
                "--kit-arg",
                "a=1",
            ],
        )
        .unwrap();
        assert_eq!(t.ctx.vm.runner().interactive_calls().len(), 1);
        assert!(
            !t.ctx
                .vm
                .runner()
                .call_lines()
                .iter()
                .any(|l| l.contains("_builder") || l.starts_with("machine create"))
        );
    }

    #[test]
    fn attaching_with_a_workload_kit_target_loads_nothing() {
        for (kit, sandbox) in [
            ("./kit", "kit-proj"),
            ("localhost:1/acme/my-kit:1", "my-kit-proj"),
        ] {
            let mut t = test_env(&[
                ("SMOLBENTO_KIT_ALLOW_LOCAL_KITS", "true"),
                ("SMOLBENTO_KIT_ALLOWED_SOURCES", r#"["localhost:1/"]"#),
            ]);
            let dir = t.ctx.cwd.join("kit");
            std::fs::create_dir(&dir).unwrap();
            std::fs::write(
                dir.join("k.yaml"),
                "# syntax=docker/sandbox-kit:3\nschemaVersion: \"3\"\nkind: workload\n",
            )
            .unwrap();
            let ws = t.ctx.cwd.display().to_string();
            t.ctx.vm.runner().ok(
                &["machine", "status"],
                &machine_json(
                    &format!("sbx-{sandbox}"),
                    "running",
                    &[
                        ("sbx.name", sandbox),
                        ("sbx.agent", "kit"),
                        ("sbx.workspace", ws.as_str()),
                        ("sbx.command", r#"["/bin/agent"]"#),
                    ],
                ),
            );
            t.ctx.vm.runner().interactive_exit(0);
            // A build would ask smolvm for `_builder`; a pull of localhost:1 would fail.
            sbt(&mut t.ctx, &["run", kit, "."]).unwrap();
            let lines = t.ctx.vm.runner().call_lines();
            assert!(
                !lines
                    .iter()
                    .any(|l| l.contains("_builder") || l.starts_with("machine create")),
                "{lines:?}"
            );
            assert_eq!(t.ctx.vm.runner().interactive_calls().len(), 1, "{kit}");
        }
    }

    #[test]
    fn kit_flags_on_an_existing_sandbox_are_warned_about() {
        use clap::Parser;
        let warning = |args: &[&str]| {
            let cli = super::super::Cli::try_parse_from(
                std::iter::once("sbt").chain(args.iter().copied()),
            )
            .unwrap();
            let Some(super::super::Cmd::Run(a)) = cli.command else {
                panic!("run");
            };
            super::ignored_kits_warning(&a, "s1")
        };
        let want = Some(
            "warning: kits only apply when a sandbox is created; s1 already exists".to_string(),
        );
        assert_eq!(warning(&["run", "--name", "s1", "--kit", "./k"]), want);
        assert_eq!(
            warning(&["run", "--name", "s1", "--kit", "./k", "--kit-arg", "a=1"]),
            want
        );
        assert_eq!(warning(&["run", "./k", "."]), want);
        assert_eq!(warning(&["run", "--name", "s1"]), None);
        assert_eq!(warning(&["run", "claude", "."]), None);
    }

    #[test]
    fn kit_args_without_a_kit_always_fail() {
        let want = "kit arguments were supplied but no kits were referenced";
        let mut t = test_env(&[]);
        created(&t, "running");
        t.ctx.vm.runner().interactive_exit(0);
        for args in [
            vec!["run", "claude", "--kit-arg", "a=1"],
            vec!["run", "--name", "claude-proj", "--kit-arg", "a=1"],
            vec!["run", "--name", "claude-proj", "--kit-args-file", "f"],
        ] {
            let err = sbt(&mut t.ctx, &args).unwrap_err();
            assert_eq!(format!("{err:#}"), want, "{args:?}");
        }
        assert!(t.ctx.vm.runner().interactive_calls().is_empty());

        let mut t = test_env(&[]);
        t.ctx
            .vm
            .runner()
            .fail(&["machine", "status"], "NOT_FOUND", "vm not found");
        let err = sbt(&mut t.ctx, &["run", "claude", "--kit-arg", "a=1"]).unwrap_err();
        assert_eq!(format!("{err:#}"), want);
        assert!(
            !t.ctx
                .vm
                .runner()
                .call_lines()
                .iter()
                .any(|l| l.starts_with("machine create")),
        );
    }

    #[test]
    fn existing_name_with_kit_flags_attaches_without_loading() {
        let mut t = test_env(&[("SMOLBENTO_KIT_ALLOW_LOCAL_KITS", "true")]);
        created(&t, "running");
        t.ctx.vm.runner().interactive_exit(0);
        sbt(
            &mut t.ctx,
            &["run", "--name", "claude-proj", "--kit", "./no-such-kit"],
        )
        .unwrap();
        assert_eq!(t.ctx.vm.runner().interactive_calls().len(), 1);
    }

    #[test]
    fn a_long_running_sandbox_keeps_running_after_the_last_session() {
        let mut t = test_env(&[]);
        kit_sandbox(&t, true);
        sbt(&mut t.ctx, &["run", "--name", "toolbox-proj"]).unwrap();
        assert!(
            !t.ctx
                .vm
                .runner()
                .call_lines()
                .iter()
                .any(|l| l.starts_with("machine stop"))
        );
    }

    #[test]
    fn a_bad_fetch_setting_skips_the_fetch_but_not_the_rm() {
        let mut t = test_env(&[("SMOLBENTO_CLONE_FETCH_ON_EXIT", "yes")]);
        let (_keep, repo) = temp_repo();
        clone_sandbox(&t, &repo);
        t.ctx.vm.runner().interactive_exit(3);
        assert_eq!(
            sbt(&mut t.ctx, &["run", "--rm", "--name", "claude-proj"]).unwrap(),
            3
        );
        assert_eq!(
            t.ctx.vm.runner().call_lines().last().unwrap(),
            "machine delete -n sbx-claude-proj -f"
        );
    }
}
