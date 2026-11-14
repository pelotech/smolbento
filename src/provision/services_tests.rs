//! Host service units around create, start, rm, prune and the orphan sweep, with a fake service
//! manager: nothing here touches a real launchd or systemd.

use crate::host_service::fake::{FakeControl, services};
use crate::host_service::{Flavor, Kind};
use crate::testutil::*;
use sha2::Digest;

/// Gives the test's context a fake service manager under a short temp dir (socket paths are
/// limited to ~104 bytes); returns it, the directory of the unit files and the temp dir.
fn with_services(
    t: &mut TestEnv,
    ns: &str,
) -> (FakeControl, std::path::PathBuf, tempfile::TempDir) {
    let tmp = tempfile::Builder::new()
        .prefix("sbs")
        .tempdir_in("/tmp")
        .unwrap();
    let (s, ctl) = services(tmp.path(), Flavor::Launchd, ns);
    t.ctx.services = s;
    (ctl, tmp.path().join("units"), tmp)
}

/// Installs units for `name` as a create would.
fn install(t: &TestEnv, name: &str, kinds: &[Kind]) {
    t.ctx
        .services
        .sync(name, kinds, &t.ctx.paths, &t.ctx.env)
        .unwrap();
}

fn units(t: &TestEnv) -> Vec<String> {
    t.ctx
        .services
        .units()
        .into_iter()
        .map(|(n, k)| format!("{n}:{}", k.as_str()))
        .collect()
}

fn ls_json(names: &[&str]) -> String {
    let all: Vec<String> = names
        .iter()
        .map(|n| {
            machine_json(
                &crate::sandbox::name::machine_name(n),
                "stopped",
                &[("sbx.name", n), ("sbx.service", "true")],
            )
        })
        .collect();
    format!("[{}]", all.join(","))
}

#[test]
fn create_installs_the_units_before_the_first_start_and_mounts_their_sockets() {
    let mut t = test_env(&[]);
    let (ctl, unit_dir, _tmp) = with_services(&mut t, "ns1");
    creatable_as(&t, "claude-proj");
    t.sbt(&["create", "claude", "."]).unwrap();
    let calls = t.calls();
    let create = calls
        .iter()
        .position(|c| c.starts_with("machine create"))
        .unwrap();
    let start = calls
        .iter()
        .position(|c| c.starts_with("machine start"))
        .unwrap();
    assert!(create < start);
    let id = &crate::util::hex(&sha2::Sha256::digest(b"claude-proj"))[..10];
    let sock = t
        .ctx
        .services
        .sock_dir()
        .join(format!("ns1{id}.bridge.sock"));
    let line = &calls[create];
    assert!(
        line.contains(&format!(
            "--mount-socket {}:/run/smolbento/bridge.sock",
            sock.display()
        )),
        "{line}"
    );
    assert!(line.contains("--label sbx.service=true"), "{line}");
    assert_eq!(ctl.calls(), ["load dev.smolbento.ns1.claude-proj.bridge"]);
    assert!(
        unit_dir
            .join("dev.smolbento.ns1.claude-proj.bridge.plist")
            .exists()
    );
    let plist =
        std::fs::read_to_string(unit_dir.join("dev.smolbento.ns1.claude-proj.bridge.plist"))
            .unwrap();
    assert!(plist.contains("<string>_serve</string>"), "{plist}");
    assert!(plist.contains(&sock.display().to_string()), "{plist}");
}

#[test]
fn without_a_service_manager_a_create_is_as_before() {
    let mut t = test_env(&[]);
    creatable_as(&t, "claude-proj");
    t.sbt(&["create", "claude", "."]).unwrap();
    let create = &t.calls_of("machine create")[0];
    assert!(
        create.contains(&format!(
            "--mount-socket {}:/run/smolbento/bridge.sock",
            crate::bridge::host_socket("claude-proj").display()
        )),
        "{create}"
    );
    assert!(!create.contains("sbx.service=true"), "{create}");
}

#[test]
fn rm_removes_the_units_and_ignores_other_namespaces() {
    let mut t = test_env(&[]);
    let (ctl, _, _tmp) = with_services(&mut t, "ns1");
    install(&t, "box", &[Kind::Bridge, Kind::Agent]);
    t.sandbox("box", "stopped", &[("sbx.service", "true")]);
    t.runner()
        .ok(&["machine", "ls", "--json"], &ls_json(&["box"]));
    t.sbt(&["rm", "-f", "box"]).unwrap();
    assert!(units(&t).is_empty());
    assert!(t.made("machine delete -n sbx-box"));
    assert!(
        ctl.calls()
            .contains(&"unload dev.smolbento.ns1.box.agent".to_string())
    );
}

#[test]
fn prune_lists_and_removes_leftovers_of_sandboxes_deleted_with_smolvm() {
    let mut t = test_env(&[]);
    let _services = with_services(&mut t, "ns1");
    install(&t, "live", &[Kind::Bridge]);
    install(&t, "gone", &[Kind::Bridge, Kind::Agent]);
    t.runner().ok(&["machine", "ls", "--json"], "[]");
    // `live` runs, so prune keeps it, and its machine exists.
    let running = machine_json(
        "sbx-live",
        "running",
        &[("sbx.name", "live"), ("sbx.service", "true")],
    );
    t.runner()
        .ok(&["machine", "ls", "--json"], &format!("[{running}]"));
    t.runner()
        .ok(&["machine", "status", "-n", "sbx-live"], &running);

    t.sbt(&["prune", "--dry-run"]).unwrap();
    assert_eq!(t.stdout(), "Would remove gone (leftover host services)\n");
    assert_eq!(units(&t).len(), 3, "a dry run removes nothing");

    t.sbt(&["prune", "-f"]).unwrap();
    assert_eq!(t.stdout(), "Removed gone (leftover host services)\n");
    assert_eq!(units(&t), ["live:bridge"]);
    t.sbt(&["prune", "-f"]).unwrap();
    assert_eq!(t.stdout(), "Nothing to prune\n");
}

#[test]
fn ls_stays_read_only() {
    let mut t = test_env(&[]);
    let (ctl, _, _tmp) = with_services(&mut t, "ns1");
    install(&t, "gone", &[Kind::Bridge]);
    let before = ctl.calls();
    t.runner().ok(&["machine", "ls", "--json"], "[]");
    t.sbt(&["ls"]).unwrap();
    assert_eq!(units(&t), ["gone:bridge"]);
    assert_eq!(ctl.calls(), before);
}

#[test]
fn create_and_start_sweep_leftovers() {
    let mut t = test_env(&[]);
    let _services = with_services(&mut t, "ns1");
    install(&t, "gone", &[Kind::Bridge]);
    t.runner()
        .ok(&["machine", "ls", "--json"], &ls_json(&["box"]));
    t.sandbox(
        "box",
        "stopped",
        &[("sbx.service", "true"), ("sbx.bridge", "true")],
    );
    t.sbt(&["start", "box"]).unwrap();
    assert_eq!(
        units(&t),
        ["box:bridge"],
        "gone is swept, box's own is written"
    );

    install(&t, "gone2", &[Kind::Bridge]);
    creatable_as(&t, "claude-proj");
    t.sbt(&["create", "claude", "."]).unwrap();
    assert_eq!(units(&t), ["box:bridge", "claude-proj:bridge"]);
}

#[test]
fn start_rewrites_a_stale_unit_and_only_a_stale_one() {
    let mut t = test_env(&[]);
    let (ctl, unit_dir, _tmp) = with_services(&mut t, "ns1");
    t.sandbox(
        "box",
        "stopped",
        &[("sbx.service", "true"), ("sbx.bridge", "true")],
    );
    t.runner()
        .ok(&["machine", "ls", "--json"], &ls_json(&["box"]));
    install(&t, "box", &[Kind::Bridge]);
    assert_eq!(ctl.calls().len(), 1);
    t.sbt(&["start", "box"]).unwrap();
    assert_eq!(ctl.calls().len(), 1, "unchanged: not reloaded");
    let file = unit_dir.join("dev.smolbento.ns1.box.bridge.plist");
    std::fs::write(&file, "stale").unwrap();
    t.sandbox(
        "box",
        "stopped",
        &[("sbx.service", "true"), ("sbx.bridge", "true")],
    );
    t.sbt(&["start", "box"]).unwrap();
    assert_eq!(ctl.calls().len(), 2);
    assert!(std::fs::read_to_string(&file).unwrap().contains("_serve"));
}

#[test]
fn a_sandbox_made_before_units_gets_none() {
    let mut t = test_env(&[]);
    let (ctl, _, _tmp) = with_services(&mut t, "ns1");
    t.runner()
        .ok(&["machine", "ls", "--json"], &ls_json(&["old"]));
    t.sandbox("old", "stopped", &[("sbx.bridge", "true")]);
    t.sbt(&["start", "old"]).unwrap();
    assert!(ctl.calls().is_empty());
    assert!(units(&t).is_empty());
}

#[test]
fn diagnose_reports_leftovers_and_suggests_prune() {
    let mut t = test_env(&[]);
    let _services = with_services(&mut t, "ns1");
    install(&t, "gone", &[Kind::Bridge]);
    t.runner().ok(&["machine", "ls", "--json"], "[]");
    assert_eq!(t.sbt(&["diagnose"]).unwrap(), 1);
    let out = t.stdout();
    assert!(
        out.contains(
            "FAIL host services left by removed sandboxes: gone; `sbt prune` removes them"
        ),
        "{out}"
    );
    assert_eq!(units(&t), ["gone:bridge"], "diagnose only reads");
}

#[test]
fn a_failed_first_start_removes_the_units_with_the_sandbox() {
    let mut t = test_env(&[]);
    let (ctl, _, _tmp) = with_services(&mut t, "ns1");
    let fake = t.runner();
    // Later registrations win: gone for good, created for the second lookup, free for the first.
    fake.fail(&["machine", "status"], "NOT_FOUND", "vm not found");
    fake.once_ok(
        &["machine", "status"],
        &machine_json(
            "sbx-claude-proj",
            "created",
            &[("sbx.name", "claude-proj"), ("sbx.agent", "claude")],
        ),
    );
    fake.once_fail(&["machine", "status"], "NOT_FOUND", "vm not found");
    fake.fail(&["machine", "start"], "SMOLVM_ERROR", "boom");
    let err = t.sbt_err(&["create", "claude", "."]);
    assert!(t.made("machine delete"), "{err}: {:?}", t.calls());
    assert!(units(&t).is_empty(), "{:?}", units(&t));
    assert!(
        ctl.calls()
            .contains(&"unload dev.smolbento.ns1.claude-proj.bridge".to_string())
    );
}
