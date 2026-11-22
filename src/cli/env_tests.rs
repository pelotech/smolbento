use super::super::{Cli, Cmd, EnvCmd, exit_code};
use crate::secrets::{SecretEntry, SecretsFile, Source};
use crate::testutil::*;
use clap::Parser;

const FILE: &str = "schemaVersion: \"1\"\nagent: claude\nworkspace: .\n\
        sandboxOptions:\n  cpus: 2\n  memory: 4g\nenv:\n  X: one\nports:\n  - sandbox: 80\n    host: 8080\n";

/// A test env with HOME set and `text` as `<cwd>/sbxenv.yaml`.
fn with_file(text: &str) -> TestEnv {
    let mut t = test_env(&[]);
    let home = t.ctx.cwd.parent().unwrap().display().to_string();
    t.ctx.env.insert("HOME".into(), home);
    std::fs::write(t.ctx.cwd.join("sbxenv.yaml"), text).unwrap();
    t
}

/// Call lines with what differs between test envs masked: fresh UUIDs (SANDBOX_ID) and
/// temp directories.
fn lines(t: &TestEnv) -> Vec<String> {
    let uuid =
        regex_lite::Regex::new("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
            .unwrap();
    let tmp = regex_lite::Regex::new(r"/[^ :]*/\.tmp[A-Za-z0-9]+").unwrap();
    t.calls()
        .iter()
        .map(|l| {
            tmp.replace_all(&uuid.replace_all(l, "UUID"), "TMP")
                .into_owned()
        })
        .collect()
}

fn creates(t: &TestEnv) -> Vec<String> {
    lines(t)
        .into_iter()
        .filter(|l| l.starts_with("machine create"))
        .collect()
}

fn scoped(t: &TestEnv) -> Vec<SecretEntry> {
    SecretsFile::load(&t.ctx.paths)
        .unwrap()
        .secrets
        .into_iter()
        .filter(|e| e.scope == "sandbox:claude-proj")
        .collect()
}

fn stored(t: &TestEnv, service: &str) -> Option<String> {
    t.ctx
        .store
        .get(&format!("sandbox:claude-proj/{service}"))
        .unwrap()
}

#[test]
fn create_force_runs_what_sbt_create_runs() {
    let mut env = with_file(FILE);
    env.project_creatable();
    sbt(&mut env.ctx, &["env", "create", "--force"]).unwrap();
    let out = env.stdout();
    assert!(
        out.starts_with("ENVIRONMENT\n  Name:  claude-proj\n"),
        "{out}"
    );
    assert!(
        out.ends_with(
            "  ✓ Created sandbox claude-proj\n        try: bento run --name claude-proj\n"
        ),
        "{out}"
    );
    assert!(!out.contains("PROVISION"), "{out}");

    let mut plain = with_file(FILE);
    plain.project_creatable();
    let ws = plain.ctx.cwd.display().to_string();
    sbt(
        &mut plain.ctx,
        &[
            "create",
            "claude",
            &ws,
            "--name",
            "claude-proj",
            "--cpus",
            "2",
            "-m",
            "4g",
            "-e",
            "X=one",
            "-p",
            "8080:80/tcp",
        ],
    )
    .unwrap();
    let mut env_lines = lines(&env);
    // env create looks the name up once more, for its own "already exists" error.
    let lookup = env_lines
        .iter()
        .position(|l| l.starts_with("machine status"))
        .unwrap();
    env_lines.remove(lookup);
    // It also keeps the file read-only in the sandbox, as sbx does (the label; starts apply it).
    // (`lines` shows temporary directories as TMP.)
    let label = " --label sbx.read-only-files=[\"TMP/proj/sbxenv.yaml\"]";
    let create = env_lines
        .iter()
        .position(|l| l.starts_with("machine create"))
        .unwrap();
    assert!(env_lines[create].contains(label), "{}", env_lines[create]);
    env_lines[create] = env_lines[create].replace(label, "");
    assert_eq!(env_lines, lines(&plain));
}

#[test]
fn create_binds_the_mounts_of_the_file() {
    let mut t = with_file(
        "schemaVersion: \"1\"\nagent: shell\nkits:\n  - ./hm\nmounts:\n  /home/agent/.hm: ./data\n",
    );
    t.ctx
        .env
        .insert("SMOLBENTO_KIT_ALLOW_LOCAL_KITS".into(), "true".into());
    let ws = t.ctx.cwd.display().to_string();
    t.machine(
        "sbx-shell-proj",
        "created",
        &[
            ("sbx.name", "shell-proj"),
            ("sbx.agent", "shell"),
            ("sbx.workspace", ws.as_str()),
        ],
    );
    t.runner().missing_until_created("sbx-shell-proj");
    v3_kit(
        &t,
        "hm",
        r#"{"schemaVersion":"3","kind":"mixin","name":"hm","capabilities":[
                {"type":"com.docker.sandbox/host-mount@1","config":{"path":"/home/agent/.hm"}}]}"#,
        &[],
    );
    std::fs::create_dir(t.ctx.cwd.join("data")).unwrap();
    t.sbt(&["env", "create", "--force"]).unwrap();
    let create = creates(&t).remove(0);
    assert!(
        create.contains(" -v TMP/proj/data:/home/agent/.hm "),
        "{create}"
    );
}

#[test]
fn create_provisions_scoped_secrets_before_the_create() {
    let mut t = with_file(&format!(
        "{FILE}secrets:\n  github:\n    value: ghp_dummy\n"
    ));
    t.project_creatable();
    t.sbt(&["env", "create", "-f"]).unwrap();
    let out = t.stdout();
    assert!(
        out.contains("\nPROVISION\n  Scope:  claude-proj\n  ✓ github — secret · literal\n"),
        "{out}"
    );
    assert!(!out.contains("ghp_dummy"), "{out}");
    assert_eq!(scoped(&t)[0].source, Source::Keychain);
    assert_eq!(stored(&t, "github").as_deref(), Some("ghp_dummy"));
    let create = &creates(&t)[0];
    assert!(create.contains("github"), "the create binds it: {create}");
    assert!(!create.contains("ghp_dummy"), "{create}");
}

#[test]
fn without_force_or_a_terminal_nothing_happens() {
    let mut t = with_file(&format!(
        "{FILE}secrets:\n  github:\n    value: ghp_dummy\n"
    ));
    t.project_creatable();
    let file = t.ctx.cwd.join("sbxenv.yaml").display().to_string();
    for cmd in ["create", "run"] {
        let err = t.sbt_err(&["env", cmd]);
        assert_eq!(
            err,
            format!(
                "{file} changes things outside the sandbox that have not been approved; \
                     approve them by running this in a terminal, or approve this invocation with \
                     --force (-f)\n  try: bento env {cmd} --force"
            )
        );
    }
    assert!(t.stdout().starts_with("ENVIRONMENT\n"));
    assert!(creates(&t).is_empty());
    assert!(
        lines(&t)
            .iter()
            .all(|l| l == "--version" || l.starts_with("machine status")),
        "{:?}",
        lines(&t)
    );
    assert!(scoped(&t).is_empty());
}

#[test]
fn the_force_hint_repeats_the_original_arguments() {
    let mut t = with_file(FILE);
    let text = format!("{FILE}args:\n  v:\n    default: a\n");
    std::fs::write(t.ctx.cwd.join("my env.yaml"), text).unwrap();
    t.creatable("box", &[]);
    let err = t.sbt_err(&[
        "env",
        "create",
        "my env.yaml",
        "--name",
        "box",
        "--env-arg",
        "v=x y",
    ]);
    assert!(
        err.ends_with(
            "\n  try: bento env create 'my env.yaml' --name box --env-arg 'v=x y' --force"
        ),
        "{err}"
    );
}

#[test]
fn create_of_an_existing_sandbox_fails() {
    let mut t = with_file(FILE);
    t.project("running");
    let err = t.sbt_err(&["env", "create", "-f"]);
    assert_eq!(
        err,
        "sandbox \"claude-proj\" already exists; attach to it with `bento env run`, or remove it \
             with `bento env rm` and create it again"
    );
    assert!(creates(&t).is_empty());
}

#[test]
fn a_failed_create_leaves_the_secret() {
    let mut t = with_file(&format!(
        "{FILE}secrets:\n  github:\n    value: ghp_dummy\n"
    ));
    t.project_creatable();
    t.runner()
        .fail(&["machine", "create"], "CREATE_FAILED", "no space left");
    assert!(t.sbt(&["env", "create", "-f"]).is_err());
    assert_eq!(scoped(&t).len(), 1);
    assert_eq!(stored(&t, "github").as_deref(), Some("ghp_dummy"));
}

#[test]
fn snapshot_stores_the_resolved_value_as_a_literal() {
    let mut t = with_file(&format!(
        "{FILE}secrets:\n  github:\n    command: printf snap\n    snapshot: true\n"
    ));
    t.project_creatable();
    t.sbt(&["env", "create", "-f"]).unwrap();
    assert!(t.stdout().contains("  ✓ github — secret · literal\n"));
    assert_eq!(scoped(&t)[0].source, Source::Keychain);
    assert_eq!(stored(&t, "github").as_deref(), Some("snap"));
}

#[test]
fn sources_are_verified_unless_no_verify() {
    let mut t = with_file(&format!(
        "{FILE}secrets:\n  github:\n    command: \"false\"\n"
    ));
    t.project_creatable();
    let err = t.sbt_err(&["env", "create", "-f"]);
    assert!(err.starts_with("secret \"github\": "), "{err}");
    assert!(scoped(&t).is_empty());
    assert!(creates(&t).is_empty());

    let mut t = with_file(&format!(
        "{FILE}secrets:\n  github:\n    command: \"false\"\n    noVerify: true\n"
    ));
    t.project_creatable();
    t.sbt(&["env", "create", "-f"]).unwrap();
    assert!(t.stdout().contains("  ✓ github — secret · command\n"));
    assert_eq!(
        scoped(&t)[0].source,
        Source::Command {
            command: "false".into()
        }
    );
    assert_eq!(stored(&t, "github"), None);
}

#[test]
fn run_of_an_existing_sandbox_attaches_with_the_files_env() {
    let mut t = with_file(&FILE.replace("X: one", "X: two"));
    t.project("running");
    t.runner().interactive_exit(0);
    assert_eq!(t.sbt(&["env", "run", "-f"]).unwrap(), 0);
    let exec = t.runner().interactive_calls()[0].join(" ");
    assert!(exec.contains("-e X=two"), "{exec}");
    assert!(creates(&t).is_empty());
    assert!(scoped(&t).is_empty());
}

#[test]
fn run_of_a_new_sandbox_creates_it_and_detaches() {
    let mut t = with_file(FILE);
    // env run looks the name up, and the create once more; the attach finds it.
    t.project_creatable();
    assert_eq!(t.sbt(&["env", "run", "-d", "-f"]).unwrap(), 0);
    assert_eq!(creates(&t).len(), 1);
    assert!(t.stdout().ends_with("claude-proj\n"));
    assert!(t.runner().interactive_calls().is_empty());
}

/// `claude-proj`, created, is the one sandbox smolvm lists.
fn listed(t: &TestEnv) {
    t.sandboxes(&[("claude-proj", "created", &[("sbx.agent", "claude")])]);
}

#[test]
fn exec_splits_paths_from_the_command_at_dashes() {
    let mut t = with_file(FILE);
    t.project("running");
    t.runner().interactive_exit(3);
    let file = t.ctx.cwd.join("sbxenv.yaml").display().to_string();
    let code = t.sbt(&["env", "exec", &file, "--", "npm", "test"]).unwrap();
    assert_eq!(code, 3);
    let call = t.runner().interactive_calls()[0].join(" ");
    assert!(call.ends_with("-- npm test"), "{call}");
    assert!(call.contains("--name sbx-claude-proj"), "{call}");
}

#[test]
fn exec_without_dashes_takes_every_positional_as_the_command() {
    let mut t = with_file(FILE);
    t.project("running");
    t.runner().interactive_exit(0);
    t.sbt(&["env", "exec", "go", "test", "./..."]).unwrap();
    let call = t.runner().interactive_calls()[0].join(" ");
    assert!(call.ends_with("-- go test ./..."), "{call}");
}

#[test]
fn exec_passes_the_files_env_and_the_users_wins() {
    let mut t = with_file(FILE);
    t.project("running");
    t.runner().interactive_exit(0);
    t.sbt(&["env", "exec", "-e", "X=mine", "--", "env"])
        .unwrap();
    let call = t.runner().interactive_calls()[0].join(" ");
    let (file, user) = (call.find("-e X=one"), call.find("-e X=mine"));
    assert!(file.is_some() && user.is_some() && file < user, "{call}");
}

#[test]
fn exec_of_a_missing_sandbox_fails() {
    let mut t = with_file(FILE);
    t.no_machine();
    let err = t.sbt_err(&["env", "exec", "--", "ls"]);
    assert_eq!(
        err,
        "sandbox 'claude-proj' not found for this environment\n  try: bento env create"
    );
    assert!(t.runner().interactive_calls().is_empty());
}

#[test]
fn exec_works_when_the_workspace_is_gone() {
    let mut t = with_file(&FILE.replace("workspace: .", "workspace: ./gone"));
    t.project("running");
    t.runner().interactive_exit(0);
    t.sbt(&["env", "exec", "--", "ls"]).unwrap();
    let call = t.runner().interactive_calls()[0].join(" ");
    assert!(call.ends_with(" -- ls"), "the command ran: {call}");
}

fn set_scoped(t: &mut TestEnv, scope: &[&str]) {
    let mut a = vec!["secret", "set", "github", "-t", "tok"];
    a.extend_from_slice(scope);
    t.sbt(&a).unwrap();
}

fn deletes(t: &TestEnv) -> Vec<String> {
    lines(t)
        .into_iter()
        .filter(|l| l.starts_with("machine delete"))
        .collect()
}

#[test]
fn rm_force_removes_the_sandbox_and_only_its_scoped_secret() {
    let mut t = with_file(FILE);
    set_scoped(&mut t, &["--sandbox", "claude-proj"]);
    set_scoped(&mut t, &[]);
    listed(&t);
    assert_eq!(t.sbt(&["env", "rm", "--force"]).unwrap(), 0);
    let out = t.stdout();
    assert!(out.contains("ENVIRONMENT\n  Name:  claude-proj\n"), "{out}");
    assert!(out.contains("  - github\n"), "{out}");
    assert!(
        out.ends_with("Removed sandbox claude-proj\nRemoved secrets scoped to claude-proj\n"),
        "{out}"
    );
    assert_eq!(deletes(&t).len(), 1, "{:?}", lines(&t));
    assert!(scoped(&t).is_empty());
    assert_eq!(stored(&t, "github"), None);
    let global = SecretsFile::load(&t.ctx.paths).unwrap();
    assert!(global.secrets.iter().any(|e| e.scope == "global"));
    assert_eq!(
        t.ctx.store.get("global/github").unwrap().as_deref(),
        Some("tok")
    );
}

#[test]
fn rm_without_a_terminal_or_force_changes_nothing() {
    let mut t = with_file(FILE);
    set_scoped(&mut t, &["--sandbox", "claude-proj"]);
    listed(&t);
    let err = t.sbt_err(&["env", "rm"]);
    assert_eq!(
        err,
        "stdin is not a terminal; use --force to skip confirmation"
    );
    assert!(t.stdout().contains("ENVIRONMENT\n"));
    assert!(deletes(&t).is_empty());
    assert_eq!(scoped(&t).len(), 1);
}

#[test]
fn rm_of_nothing_exits_0() {
    let mut t = with_file(FILE);
    t.sandboxes(&[]);
    assert_eq!(t.sbt(&["env", "rm", "-f"]).unwrap(), 0);
    assert_eq!(t.stdout(), "");
    assert!(deletes(&t).is_empty());
}

#[test]
fn rm_with_only_scoped_secrets_removes_them() {
    let mut t = with_file(FILE);
    set_scoped(&mut t, &["--sandbox", "claude-proj"]);
    t.sandboxes(&[]);
    t.sbt(&["env", "rm", "-f"]).unwrap();
    assert!(
        t.stdout()
            .ends_with("\nRemoved secrets scoped to claude-proj\n"),
        "{}",
        t.stdout()
    );
    assert!(!t.stdout().contains("Removed sandbox"));
    assert!(scoped(&t).is_empty());
    assert_eq!(stored(&t, "github"), None);
}

#[test]
fn rm_refuses_a_sandbox_with_forks() {
    let mut t = with_file(FILE);
    t.sandboxes(&[
        ("claude-proj", "created", &[("sbx.agent", "claude")]),
        (
            "claude-proj-fork-1",
            "created",
            &[("sbx.fork-of", "claude-proj")],
        ),
    ]);
    let err = t.sbt_err(&["env", "rm", "-f"]);
    assert_eq!(
        err,
        "claude-proj has forks; remove its forks first: claude-proj-fork-1"
    );
    assert!(deletes(&t).is_empty());
}

#[test]
fn rm_needs_the_required_args() {
    let mut t = with_file(&format!("{FILE}args:\n  channel:\n    required: true\n"));
    assert!(t.sbt(&["env", "rm", "-f"]).is_err());
    assert!(t.sbt(&["env", "exec", "--", "ls"]).is_err());
}

#[test]
fn cloud_flags_exit_2() {
    let mut t = with_file(FILE);
    let err = t
        .sbt(&["env", "create", "--on-timeout", "stop"])
        .unwrap_err();
    assert_eq!(exit_code(&err), 2, "{err}");
    assert!(creates(&t).is_empty());
}

const COMMAND_SECRET: &str = "secrets:\n  github:\n    command: printf tok\n";

/// `text` as the file, approved on a terminal and created. Afterwards there is no terminal
/// and the sandbox exists.
fn approved(text: &str) -> TestEnv {
    let mut t = with_file(text);
    t.project_creatable();
    t.answer("y\n");
    t.sbt(&["env", "create"]).unwrap();
    assert!(t.stdout().contains("\n  Approve this plan? (y/N) "));
    t.ctx.stdin_tty = false;
    t
}

fn record(t: &TestEnv) -> Option<String> {
    std::fs::read_to_string(t.ctx.paths.env_records().join("claude-proj.toml")).ok()
}

/// `env plan`'s output with the project directory masked.
fn plan(t: &mut TestEnv) -> String {
    t.sbt(&["env", "plan"]).unwrap();
    t.stdout()
        .replace(&t.ctx.cwd.display().to_string(), "<proj>")
}

#[test]
fn plan_of_a_fresh_environment() {
    let mut t = with_file(&format!("{FILE}{COMMAND_SECRET}"));
    t.no_machine();
    insta::assert_snapshot!(plan(&mut t));
    assert!(creates(&t).is_empty());
    assert_eq!(record(&t), None, "a plan records nothing");
}

#[test]
fn plan_of_an_approved_environment() {
    let mut t = approved(FILE);
    assert_eq!(
        plan(&mut t),
        "ENVIRONMENT\n  Name:  claude-proj\n  File:  <proj>/sbxenv.yaml\n\n  \
             0 to add · 0 to change · 0 to destroy\n  \
             ✓ already approved — applying asks nothing\n"
    );
}

#[test]
fn plan_of_a_changed_environment() {
    let mut t = approved(FILE);
    let changed = FILE.replace("X: one", "X: two").replace("8080", "8081");
    std::fs::write(t.ctx.cwd.join("sbxenv.yaml"), changed).unwrap();
    insta::assert_snapshot!(plan(&mut t));
}

#[test]
fn plan_of_approved_host_commands_before_a_create() {
    let mut t = approved(&format!("{FILE}{COMMAND_SECRET}"));
    t.no_machine();
    insta::assert_snapshot!(plan(&mut t));
}

#[test]
fn an_approved_environment_applies_without_a_terminal() {
    let mut t = approved(FILE);
    // Attaching, and creating it again after a plain `rm`.
    t.sbt(&["env", "run", "-d"]).unwrap();
    t.project_creatable();
    t.sbt(&["env", "create"]).unwrap();
    assert_eq!(creates(&t).len(), 2);
}

#[test]
fn force_approves_nothing() {
    let mut t = with_file(FILE);
    t.project_creatable();
    t.sbt(&["env", "create", "--force"]).unwrap();
    assert_eq!(record(&t), None);
    let err = t.sbt_err(&["env", "run", "-d"]);
    assert!(err.contains("have not been approved"), "{err}");

    // Nor does it replace an earlier approval.
    let mut t = approved(FILE);
    let before = record(&t);
    std::fs::write(
        t.ctx.cwd.join("sbxenv.yaml"),
        FILE.replace("X: one", "X: two"),
    )
    .unwrap();
    t.sbt(&["env", "run", "-d", "--force"]).unwrap();
    assert_eq!(record(&t), before);
}

#[test]
fn a_changed_file_asks_again() {
    let mut t = approved(FILE);
    std::fs::write(
        t.ctx.cwd.join("sbxenv.yaml"),
        FILE.replace("X: one", "X: two"),
    )
    .unwrap();
    let err = t.sbt_err(&["env", "run", "-d"]);
    assert!(err.contains("have not been approved"), "{err}");
    // Declining on a terminal records nothing new.
    let before = record(&t);
    t.answer("n\n");
    assert_eq!(t.sbt_err(&["env", "run", "-d"]), "aborted");
    assert_eq!(record(&t), before);
}

#[test]
fn unchanged_host_commands_ask_every_time_unless_remembered() {
    let mut t = approved(&format!("{FILE}{COMMAND_SECRET}"));
    let file = t.ctx.cwd.join("sbxenv.yaml").display().to_string();
    let refusal = |cmd: &str| {
        format!(
            "{file} declares commands that run on this machine, which must be approved on \
                 every invocation; approve the plan by running it in a terminal or with --force \
                 (-f), or remember approval until the plan changes with the setting below\n  \
                 try: bento env {cmd} --force\n   \
                 or: bento settings set env.rememberHostCommands true"
        )
    };
    // As in sbx: also when attaching, where the secret's command doesn't run again.
    assert_eq!(t.sbt_err(&["env", "run", "-d"]), refusal("run -d"));
    t.stdout();
    t.project_creatable();
    assert_eq!(t.sbt_err(&["env", "create"]), refusal("create"));
    let out = t.stdout();
    assert!(
        out.ends_with(
            "  ! nothing in this plan has changed, but its commands run on this machine, \
                 outside the sandbox, with your own privileges, which needs explicit approval on \
                 each run\n"
        ),
        "{out}"
    );

    t.ctx
        .settings
        .set("env.rememberHostCommands", "true")
        .unwrap();
    t.project("running");
    t.sbt(&["env", "run", "-d"]).unwrap();
    t.project_creatable();
    t.sbt(&["env", "create"]).unwrap();
}

#[test]
fn env_rm_forgets_the_approval() {
    let mut t = approved(FILE);
    assert!(record(&t).is_some());
    listed(&t);
    t.sbt(&["env", "rm", "--force"]).unwrap();
    assert_eq!(record(&t), None);
}

#[test]
fn env_rm_forgets_the_approval_when_nothing_else_is_left() {
    // The sandbox went with a plain `rm`, which leaves the approval.
    let mut t = approved(FILE);
    t.sandboxes(&[]);
    t.sbt(&["env", "rm", "--force"]).unwrap();
    assert_eq!(record(&t), None);
}

#[test]
fn what_a_secret_or_a_port_does_is_part_of_the_approval() {
    // `snapshot` decides whether the command runs once or at every start; `hostIP` where
    // the port listens.
    let file = |snapshot: bool, host_ip: &str| {
        format!(
            "schemaVersion: \"1\"\nagent: claude\nworkspace: .\nports:\n  - sandbox: 80\n    \
                 host: 8080\n{host_ip}secrets:\n  github:\n    command: printf tok\n    \
                 snapshot: {snapshot}\n"
        )
    };
    const IP: &str = "    hostIP: 127.0.0.1\n";
    for changed in [file(false, IP), file(true, "")] {
        let mut t = approved(&file(true, IP));
        t.ctx
            .settings
            .set("env.rememberHostCommands", "true")
            .unwrap();
        t.sbt(&["env", "run", "-d"]).unwrap();
        std::fs::write(t.ctx.cwd.join("sbxenv.yaml"), changed).unwrap();
        let err = t.sbt_err(&["env", "run", "-d"]);
        assert!(err.contains("have not been approved"), "{err}");
    }
    let mut t = approved(&file(true, IP));
    t.no_machine();
    let plan = plan(&mut t);
    assert!(plan.contains("      snapshot: true\n"), "{plan}");
    assert!(plan.contains("      hostIP: 127.0.0.1\n"), "{plan}");
}

#[test]
fn the_record_is_private() {
    use std::os::unix::fs::PermissionsExt;
    let t = approved(FILE);
    let path = t.ctx.paths.env_records().join("claude-proj.toml");
    let mode = std::fs::metadata(path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
}

/// A file whose lifecycle commands append their phase to `<cwd>/log`.
fn lifecycle_file(extra: &str) -> String {
    format!(
        "{FILE}lifecycle:\n  initialize:\n    - command: echo init >> log\n  \
             postCreate:\n    - command: echo post >> log\n  \
             preRemove:\n    - command: echo pre >> log\n{extra}"
    )
}

fn log(t: &TestEnv) -> String {
    std::fs::read_to_string(t.ctx.cwd.join("log")).unwrap_or_default()
}

#[test]
fn lifecycle_phases_run_around_the_create_and_on_every_run() {
    let mut t = with_file(&lifecycle_file(""));
    t.project_creatable();
    t.sbt(&["env", "create", "--force"]).unwrap();
    assert_eq!(log(&t), "init\npost\n");
    let out = t.stdout();
    let (init, created, post) = (
        out.find("\nHOST INITIALIZE\n  ○ echo init >> log\n")
            .unwrap(),
        out.find("Created sandbox claude-proj").unwrap(),
        out.find("\nHOST POST-CREATE\n").unwrap(),
    );
    assert!(init < created && created < post, "{out}");

    // Attaching: `initialize` again, nothing else.
    t.sbt(&["env", "run", "-d", "--force"]).unwrap();
    assert_eq!(log(&t), "init\npost\ninit\n");
    // `env exec` runs none.
    t.sbt(&["env", "exec", "--", "true"]).unwrap();
    assert_eq!(log(&t), "init\npost\ninit\n");
}

#[test]
fn a_failing_initialize_creates_and_stores_nothing() {
    let mut t = with_file(&format!(
        "{FILE}secrets:\n  github:\n    value: ghp_dummy\nlifecycle:\n  initialize:\n    \
             - command: exit 7\n"
    ));
    t.project_creatable();
    for cmd in ["create", "run"] {
        assert_eq!(
            t.sbt_err(&["env", cmd, "--force"]),
            "initialize[0] (exit 7): exit status 7"
        );
    }
    assert!(creates(&t).is_empty());
    assert!(scoped(&t).is_empty());
}

#[test]
fn a_failing_post_create_keeps_the_sandbox() {
    let mut t = with_file(&format!(
        "{FILE}lifecycle:\n  postCreate:\n    - command: exit 4\n"
    ));
    t.project_creatable();
    assert_eq!(
        t.sbt_err(&["env", "run", "--force"]),
        "postCreate[0] (exit 4): exit status 4; remove this environment's sandbox and \
             provisioned secrets\n  try: bento env rm"
    );
    assert_eq!(creates(&t).len(), 1);
    assert!(deletes(&t).is_empty());
    assert!(t.runner().interactive_calls().is_empty(), "not attached");
}

#[test]
fn pre_remove_runs_with_or_without_the_sandbox_and_never_stops_the_removal() {
    let mut t = with_file(&lifecycle_file("    - command: exit 3\n"));
    listed(&t);
    t.sbt(&["env", "rm", "--force"]).unwrap();
    assert_eq!(log(&t), "pre\n");
    let out = t.stdout();
    assert!(
        out.contains("\nLIFECYCLE\n  > preRemove: echo pre >> log\n      workdir: "),
        "{out}"
    );
    assert!(out.contains(" · 1 to destroy · 2 to run\n"), "{out}");
    assert!(out.contains("\nHOST PRE-REMOVE\n"), "{out}");
    assert!(out.ends_with("Removed sandbox claude-proj\n"), "{out}");
    assert_eq!(deletes(&t).len(), 1);

    // The sandbox is gone already: the commands still run.
    t.sandboxes(&[]);
    t.sbt(&["env", "rm", "--force"]).unwrap();
    assert_eq!(log(&t), "pre\npre\n");
    assert_eq!(deletes(&t).len(), 1);
}

#[test]
fn skip_host_commands_skips_every_phase_and_leaves_the_approval() {
    let mut t = approved(&lifecycle_file(""));
    assert_eq!(log(&t), "init\npost\n");
    let before = record(&t);
    // Approved, and the lifecycle commands (which would ask every time) are left out.
    t.sbt(&["env", "run", "-d", "--skip-host-commands"])
        .unwrap();
    listed(&t);
    t.sbt(&["env", "rm", "--force", "--skip-host-commands"])
        .unwrap();
    assert_eq!(log(&t), "init\npost\n", "nothing more ran");
    let out = t.stdout();
    assert!(!out.contains("LIFECYCLE"), "{out}");
    assert!(!out.contains("HOST "), "{out}");
    // Until the `env rm`, the record was untouched.
    assert!(before.unwrap().contains("initialize[0]"));

    // A yes given with the flag approves what was shown and nothing else: a command changed
    // meanwhile stays unapproved, and the record keeps the one approved before.
    let mut t = approved(&lifecycle_file(""));
    let changed = lifecycle_file("")
        .replace("X: one", "X: two")
        .replace("echo init >> log", "echo CHANGED >> log");
    std::fs::write(t.ctx.cwd.join("sbxenv.yaml"), changed).unwrap();
    t.answer("y\n");
    t.sbt(&["env", "run", "-d", "--skip-host-commands"])
        .unwrap();
    assert!(!t.stdout().contains("CHANGED"), "the plan left it out");
    let record = record(&t).unwrap();
    assert!(record.contains("value\", \"two"), "{record}");
    assert!(record.contains("initialize: echo init >> log"), "{record}");
    assert!(!record.contains("CHANGED"), "{record}");
    t.ctx.stdin_tty = false;
    let err = t.sbt_err(&["env", "run", "-d"]);
    assert!(err.contains("have not been approved"), "{err}");
    assert_eq!(log(&t), "init\npost\n", "the changed command never ran");
}

#[test]
fn env_run_launches_the_entrypoint_and_cmd() {
    let launch = "entrypoint: [\"/bin/sh\", \"-c\"]\ncmd: [\"echo hi\"]\n";
    let mut t = with_file(&format!("{FILE}{launch}"));
    t.project("running");
    t.sbt(&["env", "run", "--force"]).unwrap();
    let call = t.runner().interactive_calls()[0].join(" ");
    assert!(call.ends_with(" -- /bin/sh -c echo hi"), "{call}");
    assert!(t.stdout().contains("\nAGENT LAUNCH\n  + entrypoint\n"));

    // Only `cmd`: the agent's own command with those arguments, as `-- ARGS` (measured: sbx
    // treats the two alike).
    let mut t = with_file(&format!("{FILE}cmd: [\"--version\"]\n"));
    t.project("running");
    t.sbt(&["env", "run", "--force"]).unwrap();
    let call = t.runner().interactive_calls()[0].join(" ");
    assert!(
        call.ends_with(" -- claude --dangerously-skip-permissions --version"),
        "{call}"
    );

    // Plain `run` doesn't know the file.
    let mut t = with_file(&format!("{FILE}{launch}"));
    t.project("running");
    t.sbt(&["run", "--name", "claude-proj"]).unwrap();
    let call = t.runner().interactive_calls()[0].join(" ");
    assert!(!call.contains("/bin/sh -c echo hi"), "{call}");
}

const REGISTRY: &str = "registries:\n  GHCR.io:\n    username:\n      value: me\n    \
        secret:\n      command: printf 'reg-%s' tok3n\n";

fn registries(t: &TestEnv) -> Vec<crate::secrets::RegistryEntry> {
    SecretsFile::load(&t.ctx.paths).unwrap().registries
}

#[test]
fn registries_are_stored_for_the_sandbox_and_removed_with_it() {
    let mut t = with_file(&format!("{FILE}{REGISTRY}"));
    // A host-wide login for the same host stays as it is.
    t.ctx.store.set("registry:ghcr.io", "host-wide").unwrap();
    t.project_creatable();
    t.sbt(&["env", "create", "--force"]).unwrap();
    let out = t.stdout();
    assert!(
        out.contains("\nPROVISION\n  Scope:  claude-proj\n  ✓ ghcr.io — registry\n"),
        "{out}"
    );
    assert!(!out.contains("reg-tok3n"), "{out}");
    let stored = registries(&t);
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].host, "ghcr.io");
    assert_eq!(stored[0].username.as_deref(), Some("me"));
    assert_eq!(stored[0].sandbox.as_deref(), Some("claude-proj"));
    let get = |t: &TestEnv, key: &str| t.ctx.store.get(key).unwrap();
    assert_eq!(
        get(&t, "sandbox-registry:claude-proj/ghcr.io").as_deref(),
        Some("reg-tok3n")
    );
    t.sbt(&["secret", "ls"]).unwrap();
    let ls = t.stdout();
    assert!(
        ls.contains("claude-proj   registry   ghcr.io   (stored)"),
        "{ls}"
    );
    // As in sbx, the sandbox's own listing has it too, and only it.
    t.sbt(&["secret", "ls", "--sandbox", "claude-proj"])
        .unwrap();
    let ls = t.stdout();
    assert!(
        ls.contains("claude-proj   registry   ghcr.io   (stored)"),
        "{ls}"
    );
    t.sbt(&["secret", "ls", "--sandbox", "other"]).unwrap();
    assert!(!t.stdout().contains("ghcr.io"));

    listed(&t);
    t.sbt(&["env", "rm", "--force"]).unwrap();
    let out = t.stdout();
    assert!(out.contains("\nREGISTRIES\n  - ghcr.io\n"), "{out}");
    assert!(out.contains(" · 2 to destroy\n"), "{out}");
    assert!(
        out.ends_with("Removed secrets scoped to claude-proj\n"),
        "{out}"
    );
    assert!(registries(&t).is_empty());
    assert_eq!(get(&t, "sandbox-registry:claude-proj/ghcr.io"), None);
    assert_eq!(get(&t, "registry:ghcr.io").as_deref(), Some("host-wide"));
}

#[test]
fn a_plain_rm_removes_the_sandboxs_registry_login() {
    let mut t = with_file(&format!("{FILE}{REGISTRY}"));
    t.project_creatable();
    t.sbt(&["env", "create", "--force"]).unwrap();
    listed(&t);
    t.sbt(&["rm", "-f", "claude-proj"]).unwrap();
    assert!(registries(&t).is_empty());
    let key = "sandbox-registry:claude-proj/ghcr.io";
    assert_eq!(t.ctx.store.get(key).unwrap(), None);
}

#[test]
fn a_registry_source_that_fails_stops_before_the_create() {
    let bad = REGISTRY.replace("printf 'reg-%s' tok3n", "exit 1");
    let mut t = with_file(&format!("{FILE}{bad}"));
    t.project_creatable();
    let err = t.sbt_err(&["env", "create", "--force"]);
    assert!(err.starts_with("registry \"GHCR.io\": secret: "), "{err}");
    assert!(creates(&t).is_empty());
    assert!(registries(&t).is_empty());
}

#[test]
fn env_run_detached_launches_nothing_and_no_workspace_means_mountless() {
    // Both measured on sbx 0.53.
    let file = "schemaVersion: \"1\"\nagent: claude\nname: claude-proj\n\
                    entrypoint: [\"/bin/sh\", \"-c\"]\ncmd: [\"echo hi\"]\n";
    let mut t = with_file(file);
    t.project_creatable();
    t.sbt(&["env", "run", "-d", "--force"]).unwrap();
    assert!(t.runner().interactive_calls().is_empty());
    let create = &creates(&t)[0];
    let cwd = t.ctx.cwd.display().to_string();
    assert!(!create.contains(&cwd), "no workspace mount: {create}");
}

#[test]
fn another_set_of_files_is_another_environment() {
    let mut t = approved(FILE);
    std::fs::write(t.ctx.cwd.join("same.yaml"), "env:\n  X: one\n").unwrap();
    let err = t.sbt_err(&["env", "run", "-d", "sbxenv.yaml", "same.yaml"]);
    let dir = t.ctx.cwd.display().to_string();
    assert!(
        err.starts_with(&format!(
            "the merged environment ({dir}/sbxenv.yaml, {dir}/same.yaml) changes things \
                 outside the sandbox that have not been approved"
        )),
        "{err}"
    );
    let out = t.stdout();
    assert!(
        out.contains(&format!(
            "  Name:   claude-proj\n  Files:  {dir}/sbxenv.yaml\n          {dir}/same.yaml\n"
        )),
        "{out}"
    );
    assert!(
        out.contains("  ! claude-proj — present, not recorded as applied"),
        "{out}"
    );
}

#[test]
fn env_plan_stores_nothing() {
    let mut t = with_file(&format!(
        "{FILE}secrets:\n  github:\n    value: ghp_dummy\n{REGISTRY}"
    ));
    t.no_machine();
    t.sbt(&["env", "plan"]).unwrap();
    assert!(scoped(&t).is_empty());
    assert!(registries(&t).is_empty());
    assert_eq!(record(&t), None);
}

#[test]
fn unchanged_host_commands_ask_on_a_terminal_too() {
    let mut t = approved(&lifecycle_file(""));
    t.answer("y\n");
    t.sbt(&["env", "run", "-d"]).unwrap();
    let out = t.stdout();
    assert!(
        out.contains(
            "  ! nothing in this plan has changed, but its commands run on this machine, \
                 outside the sandbox, with your own privileges, which needs explicit approval on \
                 each run\n  Approve this plan? (y/N) "
        ),
        "{out}"
    );
}

#[test]
fn a_failing_initialize_stores_no_registry_login() {
    let mut t = with_file(&format!(
        "{FILE}{REGISTRY}lifecycle:\n  initialize:\n    - command: exit 7\n"
    ));
    t.project_creatable();
    assert!(
        t.sbt_err(&["env", "create", "--force"])
            .ends_with("exit status 7")
    );
    assert!(registries(&t).is_empty());
}

#[test]
fn env_run_creates_runs_post_create_then_attaches_with_the_launch_command() {
    let launch = "entrypoint: [\"/bin/sh\", \"-c\"]\ncmd: [\"echo hi\"]\n";
    let mut t = with_file(&format!(
        "{FILE}{launch}lifecycle:\n  postCreate:\n    - command: echo post >> log\n"
    ));
    t.project_creatable();
    t.sbt(&["env", "run", "--force"]).unwrap();
    assert_eq!(log(&t), "post\n");
    let out = t.stdout();
    let (created, post) = (
        out.find("Created sandbox claude-proj").unwrap(),
        out.find("HOST POST-CREATE").unwrap(),
    );
    assert!(created < post, "{out}");
    let call = t.runner().interactive_calls()[0].join(" ");
    assert!(call.ends_with(" -- /bin/sh -c echo hi"), "{call}");
}

#[test]
fn arguments_after_dashes_replace_cmd_or_go_to_the_agent() {
    // Both measured on sbx 0.53: with an override they replace `cmd` (the plan still shows
    // the file's), without one the agent gets them.
    let launch = "entrypoint: [\"/bin/sh\", \"-c\"]\ncmd: [\"echo from-file\"]\n";
    let mut t = with_file(&format!("{FILE}{launch}"));
    t.project("running");
    t.sbt(&["env", "run", "--force", "--", "echo from-args"])
        .unwrap();
    let call = t.runner().interactive_calls()[0].join(" ");
    assert!(call.ends_with(" -- /bin/sh -c echo from-args"), "{call}");
    assert!(t.stdout().contains("argv: \"[\\\"echo from-file\\\"]\""));

    let mut t = with_file(FILE);
    t.project("running");
    t.sbt(&["env", "run", "--force", "--", "--version"])
        .unwrap();
    let call = t.runner().interactive_calls()[0].join(" ");
    assert!(
        call.ends_with(" -- claude --dangerously-skip-permissions --version"),
        "{call}"
    );

    // Paths still come before the dashes.
    let mut t = with_file(FILE);
    t.project("running");
    t.sbt(&["env", "run", "--force", "sbxenv.yaml", "--", "-c"])
        .unwrap();
    let call = t.runner().interactive_calls()[0].join(" ");
    assert!(
        call.ends_with(" -- claude --dangerously-skip-permissions -c"),
        "{call}"
    );
}

const BINDING: &str = "secrets:\n  github:\n    value: ghp_dummy\nbindings:\n  github:\n    apiKey:\n      domains: [uploads.github.com]\n";

fn bindings(t: &TestEnv) -> Vec<String> {
    let f = SecretsFile::load(&t.ctx.paths).unwrap();
    f.bindings.keys().cloned().collect()
}

#[test]
fn bindings_are_saved_globally_and_send_the_credential_there() {
    let mut t = with_file(&format!("{FILE}{BINDING}"));
    t.project_creatable();
    t.sbt(&["env", "create", "--force"]).unwrap();
    let out = t.stdout();
    assert!(
        out.contains("\nBINDINGS\n  + github\n      apiKey.domains: uploads.github.com\n"),
        "{out}"
    );
    let file = t.ctx.paths.secrets_file().display().to_string();
    assert!(
        out.contains(&format!(
            "  ✓ github — binding\n  ✓ Binding saved to {file}\n"
        )),
        "{out}"
    );
    assert_eq!(bindings(&t), ["github"]);
    let create = &creates(&t)[0];
    assert!(create.contains("uploads.github.com"), "{create}");
}

#[test]
fn env_rm_keeps_bindings_unless_pruned() {
    let mut t = with_file(&format!("{FILE}{BINDING}"));
    t.project_creatable();
    t.sbt(&["env", "create", "--force"]).unwrap();
    listed(&t);
    t.sbt(&["env", "rm", "--force"]).unwrap();
    assert_eq!(bindings(&t), ["github"]);
    t.stdout();
    // The sandbox is gone: only the binding is left to prune.
    t.sandboxes(&[]);
    t.sbt(&["env", "rm", "--force", "--prune-bindings"])
        .unwrap();
    let out = t.stdout();
    assert!(
        out.contains("\nBINDINGS\n  - github\n      apiKey.domains: uploads.github.com\n"),
        "{out}"
    );
    assert!(out.contains("Removed declared bindings from "), "{out}");
    assert!(bindings(&t).is_empty());
}

#[test]
fn a_binding_for_an_unknown_service_is_refused() {
    let mut t = with_file(&format!(
        "{FILE}bindings:\n  nosuch:\n    apiKey:\n      domains: [a.example]\n"
    ));
    t.project_creatable();
    let err = t.sbt_err(&["env", "create", "--force"]);
    assert!(err.starts_with("unknown service 'nosuch'"), "{err}");
}

#[test]
fn mcp_url_servers_are_registered_and_attached() {
    let mut t = with_file(&format!(
        "{FILE}mcp:\n  servers:\n    - name: deep\n      url: https://mcp.deepwiki.com/mcp\n"
    ));
    t.project_creatable();
    t.sbt(&["env", "create", "--force"]).unwrap();
    let out = t.stdout();
    assert!(
        out.contains("\nMCP SERVERS\n  + deep\n      url: https://mcp.deepwiki.com/mcp\n"),
        "{out}"
    );
    assert!(out.contains("  ✓ deep — mcp\n"), "{out}");
    let registered = crate::mcp::McpFile::load(&t.ctx.paths).unwrap();
    assert!(registered.servers.contains_key("deep"));
    let create = &creates(&t)[0];
    assert!(create.contains("sbx.mcp=deep"), "{create}");
    // It stays after `env rm`, as in sbx.
    listed(&t);
    t.sbt(&["env", "rm", "--force"]).unwrap();
    let registered = crate::mcp::McpFile::load(&t.ctx.paths).unwrap();
    assert!(registered.servers.contains_key("deep"));
}

#[test]
fn an_unreachable_mcp_server_fails_the_create_before_anything_is_stored() {
    // As sbx, which contacts the server when it registers it.
    let mut t = with_file(&format!(
        "{FILE}secrets:\n  github:\n    value: ghp_dummy\n\
             mcp:\n  servers:\n    - name: gone\n      url: https://mcp.example.invalid/mcp\n"
    ));
    t.project_creatable();
    let err = t.sbt_err(&["env", "create", "--force"]);
    assert!(
        err.starts_with(
            "register mcp server \"gone\": server \"gone\": discovery failed: connecting to \
                 server https://mcp.example.invalid/mcp: "
        ),
        "{err}"
    );
    assert!(creates(&t).is_empty());
    assert!(scoped(&t).is_empty());
    assert!(
        crate::mcp::McpFile::load(&t.ctx.paths)
            .unwrap()
            .servers
            .is_empty()
    );
}

#[test]
fn the_record_never_holds_a_secret_value() {
    let t = approved(&format!(
        "{FILE}secrets:\n  github:\n    value: s3cr3t-value\n"
    ));
    let record = record(&t).unwrap();
    assert!(!record.contains("s3cr3t-value"), "{record}");
    assert!(record.contains("sha256:"), "{record}");
}

#[test]
fn a_broken_record_is_no_approval() {
    let mut t = approved(FILE);
    std::fs::write(t.ctx.paths.env_records().join("claude-proj.toml"), "x = [").unwrap();
    let err = t.sbt_err(&["env", "run", "-d"]);
    assert!(err.contains("have not been approved"), "{err}");
}

#[test]
fn clone_takes_an_optional_value() {
    let clone = |args: &[&str]| {
        let cli = Cli::try_parse_from(["sbt", "env", "create"].iter().chain(args)).unwrap();
        match cli.command {
            Some(Cmd::Env(EnvCmd::Create(a))) => (a.apply.overrides.clone, a.common.paths),
            other => panic!("{other:?}"),
        }
    };
    assert_eq!(clone(&[]), (None, vec![]));
    assert_eq!(clone(&["--clone", "./p"]), (Some(true), vec!["./p".into()]));
    assert_eq!(clone(&["--clone=true"]).0, Some(true));
    assert_eq!(clone(&["--clone=false"]).0, Some(false));
}

/// As in sbx 0.54: a `kits:` entry that expands to nothing isn't planned (no blank `+ ` line);
/// filled in, it is.
#[test]
fn an_empty_kit_entry_is_not_planned() {
    let file = "schemaVersion: \"1\"\nagent: claude\nworkspace: .\nargs:\n  agentKit: {default: \"\"}\n\
                kits:\n  - ${{ env.args.agentKit }}\n";
    let mut t = with_file(file);
    t.no_machine();
    let out = plan(&mut t);
    assert!(!out.contains("KITS"), "{out}");
    t.sbt(&["env", "plan", "--env-arg", "agentKit=org/tool"])
        .unwrap();
    let out = t.stdout();
    assert!(out.contains("KITS\n  + org/tool"), "{out}");
}
