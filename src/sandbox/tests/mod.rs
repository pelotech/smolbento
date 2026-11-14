//! Tests of starting and creating sandboxes, by topic, with the fixtures they share.

mod clone;
mod guest_cmd;
mod kits;
mod start;

use crate::kits::apply::InstallStep;
use crate::kits::guest;
use crate::sandbox::*;
use crate::smolvm::NetworkSpec;
use crate::smolvm::fake::FakeRunner;
use crate::testutil::root_sh;
use crate::util::sh_quote;
use crate::workspace::clone::WorktreeHead;

pub(super) const STATUS: &str = include_str!("../../../tests/fixtures/smolvm/status.json");

/// The fixture sandbox, stopped.
pub(super) fn stopped() -> String {
    STATUS.replace("\"state\": \"running\"", "\"state\": \"stopped\"")
}

/// A fake smolvm whose `machine status` answers with `status`.
pub(super) fn vm_with(status: &str) -> Smolvm<FakeRunner> {
    let fake = FakeRunner::new();
    fake.ok(&["machine", "status"], status);
    Smolvm::new(fake)
}

pub(super) fn plan() -> StartPlan {
    StartPlan {
        network: NetworkSpec::Open,
        env: vec![("TOK".into(), "secret".into())],
        remove: vec!["GONE".into()],
        clone: None,
        branchable: true,
        kit: None,
    }
}

pub(super) fn bridged_status() -> String {
    stopped().replace(
        "\"sbx.docker\"",
        "\"sbx.bridge\": \"true\",\n    \"sbx.docker\"",
    )
}

pub(super) fn skills_status(label: &str) -> String {
    let l = label.replace('"', "\\\"");
    stopped().replace(
        "\"sbx.docker\"",
        &format!("\"sbx.skills\": \"{l}\",\n    \"sbx.docker\""),
    )
}

pub(super) const RO_LABEL: &str = r#"{"mode":"readonly","shared":"ro","dirs":[{"path":"/home/agent/.claude/skills","access":"link"}]}"#;

pub(super) fn step(dir: &str) -> CloneStep {
    CloneStep {
        dir: dir.into(),
        head: None,
        remotes: vec![],
    }
}

/// A stopped clone sandbox `r` of `/w/r`, and a plan that clones it.
pub(super) fn clone_sandbox() -> (Sandbox, StartPlan) {
    let sb = Sandbox {
        meta: Meta {
            name: "r".into(),
            mapped: true,
            workspace: Some("/w/r".into()),
            clone_repo: Some("/w/r".into()),
            ..Default::default()
        },
        machine: "sbx-r".into(),
        state: MachineState::Stopped,
        ports: vec![],
        image: None,
    };
    let plan = StartPlan {
        clone: Some(step("/w/r")),
        ..plan()
    };
    (sb, plan)
}

pub(super) const MACHINE: &str = "sbx-claude-myrepo";

/// A fake whose `status` answers with a freshly created (non-docker) `claude-myrepo`.
pub(super) fn created_vm() -> Smolvm<FakeRunner> {
    let fake = FakeRunner::new();
    let created = STATUS
        .replace("\"state\": \"running\"", "\"state\": \"created\"")
        .replace("\"sbx.docker\": \"true\"", "\"sbx.docker\": \"false\"");
    fake.ok(&["machine", "status"], &created);
    Smolvm::new(fake)
}

pub(super) fn request() -> CreateRequest {
    CreateRequest {
        name: "claude-myrepo".into(),
        agent: "claude".into(),
        image: "img".into(),
        cpus: 1,
        memory_mib: 1024,
        created: 1,
        ..Default::default()
    }
}

pub(super) fn restricted(hosts: &[&str]) -> NetworkSpec {
    NetworkSpec::Restricted(crate::smolvm::AllowList::new(
        hosts.iter().map(|h| h.to_string()),
        vec![],
        vec![],
    ))
}

pub(super) fn hook(n: usize, user: Option<&str>, script: &str) -> InstallStep {
    InstallStep {
        label: format!("kit k install hook {n}"),
        kit: Some("k".into()),
        user: user.map(String::from),
        script: script.into(),
        relay_stderr: false,
    }
}

pub(super) fn kit_plan(restart_without: &[&str]) -> StartPlan {
    StartPlan {
        network: restricted(&["api.example.com", "registry.npmjs.org"]),
        env: vec![
            ("TOK".into(), "secret".into()),
            ("KEEP".into(), "kept".into()),
        ],
        remove: vec![],
        kit: Some(KitFirstStart {
            steps: KitSteps {
                install_rules: vec!["r-npm".into()],
                install: vec![
                    hook(1, None, "echo install-1"),
                    hook(2, Some("agent"), "echo install-2"),
                ],
                files: vec!["echo files-1".into()],
                context: vec!["echo context-1".into()],
                startup_d: vec![("01-k.sh".into(), "echo startup".into())],
                kits_record: "k\tref@sha256:00\tnpm\n".into(),
            },
            restart_without: restart_without.iter().map(|v| v.to_string()).collect(),
            rule_ids: vec!["r-npm".into(), "r-api".into()],
            agent_backing: None,
        }),
        ..plan()
    }
}

pub(super) fn exec_line(user: &str, detach: bool, script: &str) -> String {
    let d = if detach { " -d" } else { "" };
    format!("machine exec --name {MACHINE} -u {user}{d} -- sh -c {script}")
}

pub(super) fn position(lines: &[String], what: &str, pred: impl Fn(&String) -> bool) -> usize {
    lines
        .iter()
        .position(pred)
        .unwrap_or_else(|| panic!("no {what} in {lines:#?}"))
}

/// The startup runner in `machine`, answering with exit `code`.
pub(super) fn failing_startup(fake: &FakeRunner, machine: &str, code: i32) {
    fake.on(
        &root_sh(machine, &startup_cmd(None)),
        crate::smolvm::Output {
            code,
            ..Default::default()
        },
    );
}
