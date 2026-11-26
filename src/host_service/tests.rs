use super::fake::services;
use super::*;

fn paths(data: &str) -> Paths {
    Paths {
        config: "/c".into(),
        cache: "/k".into(),
        data: data.into(),
    }
}

fn envs(vars: &[(&str, &str)]) -> BTreeMap<String, String> {
    vars.iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

#[test]
fn the_namespace_follows_the_data_dir() {
    let a = namespace(&paths("/d/a"));
    assert_eq!(a.len(), 8);
    assert_eq!(a, namespace(&paths("/d/a")));
    assert_ne!(a, namespace(&paths("/d/b")));
}

#[test]
fn the_plist_has_the_socket_inetd_mode_and_the_serve_command() {
    let p = render_plist(
        "dev.smolbento.ab.s&1.agent",
        Path::new("/opt/bin/sbt"),
        Kind::Agent,
        "s&1",
        Path::new("/Users/me/Library/Application Support/smolbento/sock/x.sock"),
        None,
        &[("HOME".into(), "/Users/me".into())],
    );
    assert!(
        p.contains("<string>dev.smolbento.ab.s&amp;1.agent</string>"),
        "{p}"
    );
    assert!(p.contains("<string>/opt/bin/sbt</string>\n    <string>_serve</string>\n    <string>agent</string>\n    <string>s&amp;1</string>"), "{p}");
    assert!(
        p.contains("<key>SockPathMode</key>\n      <integer>384</integer>"),
        "{p}"
    );
    assert!(p.contains("<key>Wait</key>\n    <false/>"), "{p}");
    assert!(
        p.contains("Application Support/smolbento/sock/x.sock</string>"),
        "{p}"
    );
    assert!(
        p.contains("<key>HOME</key>\n    <string>/Users/me</string>"),
        "{p}"
    );
}

#[test]
fn the_systemd_pair_accepts_per_connection_on_a_0600_socket() {
    let s = render_systemd_socket(
        "a%b",
        Kind::Bridge,
        Path::new("/run/user/1/smolbento/x.sock"),
        None,
    );
    for want in [
        "ListenStream=/run/user/1/smolbento/x.sock\n",
        "SocketMode=0600\n",
        "DirectoryMode=0700\n",
        "Accept=yes\n",
        // The connections, and the processes login relays keep alive.
        "MaxConnections=12\n",
        "WantedBy=sockets.target",
        "sandbox a%%b",
    ] {
        assert!(s.contains(want), "{want}: {s}");
    }
    let agent = render_systemd_socket("s1", Kind::Agent, Path::new("/run/a.sock"), None);
    assert!(agent.contains("MaxConnections=8\n"), "{agent}");
    let svc = render_systemd_service(
        Path::new("/opt/sbt"),
        Kind::Bridge,
        "s1",
        "smolbento-n-s1-bridge.socket",
        None,
        &[("K".into(), "a\"b$c%d".into())],
    );
    // Stopping the socket (`rm`) stops its connections, a lingering login relay's included.
    assert!(
        svc.contains("PartOf=smolbento-n-s1-bridge.socket\n"),
        "{svc}"
    );
    assert!(
        svc.contains("ExecStart=\"/opt/sbt\" _serve bridge \"s1\"\n"),
        "{svc}"
    );
    assert!(svc.contains("StandardInput=socket\n"), "{svc}");
    assert!(svc.contains("KillMode=process\n"), "{svc}");
    assert!(svc.contains("Environment=\"K=a\\\"b$$c%%d\"\n"), "{svc}");
}

#[test]
fn the_egress_plist_owns_the_port_and_isnt_inetd() {
    let p = render_plist(
        "dev.smolbento.ab.s1.egress",
        Path::new("/opt/bin/sbt"),
        Kind::Egress,
        "s1",
        Path::new("/unused.sock"),
        Some((47331, Path::new("/d/egress.log"))),
        &[("HOME".into(), "/Users/me".into())],
    );
    for want in [
        "<string>_serve</string>\n    <string>egress</string>\n    <string>s1</string>",
        "<key>SockNodeName</key>\n      <string>127.0.0.1</string>",
        "<key>SockServiceName</key>\n      <string>47331</string>",
        "<key>SockType</key>\n      <string>stream</string>",
        "<key>SockFamily</key>\n      <string>IPv4</string>",
        "<key>ThrottleInterval</key>\n  <integer>1</integer>",
    ] {
        assert!(p.contains(want), "{want}: {p}");
    }
    assert!(!p.contains("inetdCompatibility"), "{p}");
    assert!(!p.contains("SockPathName"), "{p}");
}

#[test]
fn the_systemd_egress_pair_accepts_no_connections_itself() {
    let s = render_systemd_socket("s1", Kind::Egress, Path::new("/unused"), Some(47331));
    assert!(s.contains("ListenStream=127.0.0.1:47331\n"), "{s}");
    assert!(s.contains("Accept=no\n"), "{s}");
    assert!(!s.contains("Accept=yes"), "{s}");
    let svc = render_systemd_service(
        Path::new("/opt/sbt"),
        Kind::Egress,
        "s1",
        "smolbento-n-s1-egress.socket",
        None,
        &[],
    );
    assert!(
        svc.contains("PartOf=smolbento-n-s1-egress.socket\n"),
        "{svc}"
    );
    assert!(
        svc.contains("ExecStart=\"/opt/sbt\" _serve egress \"s1\"\n"),
        "{svc}"
    );
    assert!(!svc.contains("StandardInput=socket"), "{svc}");
}

#[test]
fn a_hosted_sandbox_gets_an_egress_unit() {
    for (flavor, files) in [
        (Flavor::Launchd, vec!["dev.smolbento.ns1.s1.egress.plist"]),
        (
            Flavor::Systemd,
            vec![
                "smolbento-ns1-s1-egress.socket",
                "smolbento-ns1-s1-egress.service",
            ],
        ),
    ] {
        let tmp = tempfile::tempdir().unwrap();
        let (s, ctl) = services(tmp.path(), flavor, "ns1");
        assert!(
            s.sync("s1", &[Kind::Egress], None, &paths("/d"), &envs(&[]))
                .is_err(),
            "no port, no unit"
        );
        s.sync("s1", &[Kind::Egress], Some(47331), &paths("/d"), &envs(&[]))
            .unwrap();
        for f in &files {
            assert!(tmp.path().join("units").join(f).exists(), "{f}");
        }
        assert_eq!(s.units(), [("s1".to_string(), Kind::Egress)]);
        s.restart_egress("s1").unwrap();
        assert!(ctl.calls().iter().any(|c| c.starts_with("restart ")));
        s.remove("s1").unwrap();
        for f in &files {
            assert!(!tmp.path().join("units").join(f).exists(), "{f}");
        }
        assert!(s.units().is_empty());
        let n = ctl.calls().len();
        s.restart_egress("s1").unwrap();
        assert_eq!(ctl.calls().len(), n, "no unit, no restart");
    }
}

#[test]
fn only_the_egress_unit_logs_stderr_to_a_file() {
    for (flavor, ext, files, want) in [
        (
            Flavor::Launchd,
            "plist",
            ["dev.smolbento.ns1.s1.egress", "dev.smolbento.ns1.s1.agent"],
            "<key>StandardErrorPath</key>\n  <string>/d/egress/s1/egress.log</string>",
        ),
        (
            Flavor::Systemd,
            "service",
            ["smolbento-ns1-s1-egress", "smolbento-ns1-s1-agent@"],
            "StandardError=append:/d/egress/s1/egress.log\n",
        ),
    ] {
        let tmp = tempfile::tempdir().unwrap();
        let (s, _ctl) = services(tmp.path(), flavor, "ns1");
        s.sync(
            "s1",
            &[Kind::Agent, Kind::Egress],
            Some(47331),
            &paths("/d"),
            &envs(&[]),
        )
        .unwrap();
        let read =
            |f: &str| std::fs::read_to_string(tmp.path().join(format!("units/{f}.{ext}"))).unwrap();
        let egress = read(files[0]);
        assert!(egress.contains(want), "{want}: {egress}");
        let agent = read(files[1]);
        assert!(!agent.contains("egress.log"), "{agent}");
    }
}

#[test]
fn only_the_egress_unit_gets_the_port() {
    let tmp = tempfile::tempdir().unwrap();
    let (s, _ctl) = services(tmp.path(), Flavor::Launchd, "ns1");
    s.sync(
        "s1",
        &[Kind::Agent, Kind::Bridge, Kind::Egress],
        Some(47331),
        &paths("/d"),
        &envs(&[]),
    )
    .unwrap();
    let read = |k: &str| {
        std::fs::read_to_string(
            tmp.path()
                .join(format!("units/dev.smolbento.ns1.s1.{k}.plist")),
        )
        .unwrap()
    };
    assert!(read("egress").contains("47331"));
    for k in ["agent", "bridge"] {
        let p = read(k);
        assert!(
            !p.contains("47331") && p.contains("inetdCompatibility"),
            "{k}: {p}"
        );
    }
}

#[test]
fn the_service_env_keeps_dirs_settings_and_session_vars_only() {
    let env = envs(&[
        ("HOME", "/h"),
        ("PATH", "/bin"),
        ("SMOLBENTO_SSH_AGENT_SOCKET", "/a"),
        ("SMOLBENTO_DATA_DIR", "/ignored"),
        // A log level must never rewrite (and restart) a running sandbox's units.
        ("SMOLBENTO_LOG", "debug"),
        ("AWS_SECRET_ACCESS_KEY", "nope"),
        ("SSH_AUTH_SOCK", "/s"),
        ("DISPLAY", ""),
    ]);
    let linux = service_env(&paths("/d"), &env, Flavor::Systemd);
    let keys: Vec<&str> = linux.iter().map(|(k, _)| k.as_str()).collect();
    assert_eq!(
        keys,
        [
            "HOME",
            "PATH",
            "SMOLBENTO_CACHE_DIR",
            "SMOLBENTO_CONFIG_DIR",
            "SMOLBENTO_DATA_DIR",
            "SMOLBENTO_SSH_AGENT_SOCKET",
            "SSH_AUTH_SOCK"
        ]
    );
    assert!(linux.contains(&("SMOLBENTO_DATA_DIR".into(), "/d".into())));
    let mac = service_env(&paths("/d"), &env, Flavor::Launchd);
    assert!(
        mac.iter().all(|(k, _)| k != "SSH_AUTH_SOCK"),
        "launchd supplies macOS's own"
    );
}

#[test]
fn names_are_namespaced_and_listed_back() {
    for (flavor, file) in [
        (Flavor::Launchd, "dev.smolbento.ns1.my.box.agent.plist"),
        (Flavor::Systemd, "smolbento-ns1-my.box-agent.socket"),
    ] {
        let tmp = tempfile::tempdir().unwrap();
        let (s, _) = services(tmp.path(), flavor, "ns1");
        let (other, _) = services(tmp.path(), flavor, "ns2");
        s.sync("my.box", &[Kind::Agent], None, &paths("/d"), &envs(&[]))
            .unwrap();
        assert!(tmp.path().join("units").join(file).exists(), "{file}");
        assert_eq!(s.units(), [("my.box".to_string(), Kind::Agent)]);
        assert!(
            other.units().is_empty(),
            "another setup's units are invisible"
        );
        assert!(other.orphans(&[]).is_empty());
    }
}

#[test]
fn sync_loads_once_and_again_only_when_the_text_changed() {
    let tmp = tempfile::tempdir().unwrap();
    let (s, ctl) = services(tmp.path(), Flavor::Launchd, "ns1");
    let sync = |env: &[(&str, &str)]| {
        s.sync(
            "s1",
            &[Kind::Agent, Kind::Bridge],
            None,
            &paths("/d"),
            &envs(env),
        )
        .unwrap()
    };
    sync(&[("PATH", "/bin")]);
    assert_eq!(
        ctl.calls(),
        [
            "refresh",
            "load dev.smolbento.ns1.s1.agent",
            "load dev.smolbento.ns1.s1.bridge"
        ]
    );
    sync(&[("PATH", "/bin")]);
    assert_eq!(ctl.calls().len(), 3, "unchanged: no reload");
    sync(&[("PATH", "/usr/bin")]);
    assert_eq!(
        ctl.calls().len(),
        6,
        "a changed PATH rewrites, refreshes once and reloads"
    );
}

#[test]
fn sync_writes_unit_files_through_write_atomic() {
    let tmp = tempfile::tempdir().unwrap();
    let (s, _) = services(tmp.path(), Flavor::Systemd, "ns1");
    let link = tmp.path().join("units/real");
    std::fs::create_dir_all(tmp.path().join("units")).unwrap();
    std::fs::write(&link, "x").unwrap();
    let unit = s.paths_of("s1", Kind::Agent);
    std::os::unix::fs::symlink(&link, &unit.files[0]).unwrap();
    s.sync("s1", &[Kind::Agent], None, &paths("/d"), &envs(&[]))
        .unwrap();
    // Symlink::Replace: the link is replaced, never written through; no temp files remain.
    assert_eq!(std::fs::read_to_string(&link).unwrap(), "x");
    assert!(!unit.files[0].is_symlink());
    let leftovers = std::fs::read_dir(tmp.path().join("units"))
        .unwrap()
        .filter(|e| {
            e.as_ref()
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".tmp")
        })
        .count();
    assert_eq!(leftovers, 0);
}

#[test]
fn sync_loads_an_unchanged_unit_that_is_no_longer_loaded() {
    let tmp = tempfile::tempdir().unwrap();
    let (s, ctl) = services(tmp.path(), Flavor::Launchd, "ns1");
    let sync = || {
        s.sync("s1", &[Kind::Agent], None, &paths("/d"), &envs(&[]))
            .unwrap()
    };
    sync();
    // A reboot unloads launchd jobs that aren't in ~/Library/LaunchAgents (we don't write there).
    ctl.0
        .borrow_mut()
        .push("unload dev.smolbento.ns1.s1.agent".into());
    sync();
    assert_eq!(
        ctl.calls().last().unwrap(),
        "load dev.smolbento.ns1.s1.agent"
    );
    assert_eq!(ctl.calls().len(), 5);
}

#[test]
fn sync_removes_the_kind_a_sandbox_no_longer_has() {
    let tmp = tempfile::tempdir().unwrap();
    let (s, _) = services(tmp.path(), Flavor::Systemd, "ns1");
    s.sync(
        "s1",
        &[Kind::Agent, Kind::Bridge],
        None,
        &paths("/d"),
        &envs(&[]),
    )
    .unwrap();
    s.sync("s1", &[Kind::Bridge], None, &paths("/d"), &envs(&[]))
        .unwrap();
    assert_eq!(s.units(), [("s1".to_string(), Kind::Bridge)]);
    let dir = tmp.path().join("units");
    assert!(!dir.join("smolbento-ns1-s1-agent@.service").exists());
    assert!(dir.join("smolbento-ns1-s1-bridge@.service").exists());
}

#[test]
fn remove_unloads_and_deletes_units_and_sockets_of_that_sandbox_only() {
    use std::os::unix::net::UnixListener;
    let tmp = tempfile::tempdir().unwrap();
    let (s, ctl) = services(tmp.path(), Flavor::Launchd, "ns1");
    for n in ["s1", "s2"] {
        s.sync(n, &[Kind::Agent], None, &paths("/d"), &envs(&[]))
            .unwrap();
    }
    // The socket launchd leaves behind after bootout.
    let sock = s.plan("s1").unwrap().agent;
    let _l = UnixListener::bind(&sock).unwrap();
    let slot = s.slot_files("s1", Kind::Agent).remove(0);
    fs::write(&slot, "").unwrap();
    s.remove("s1").unwrap();
    assert!(!sock.exists());
    assert!(!slot.exists(), "the slot files go too");
    assert_eq!(s.units(), [("s2".to_string(), Kind::Agent)]);
    assert!(
        ctl.calls()
            .contains(&"unload dev.smolbento.ns1.s1.agent".to_string())
    );
    assert!(
        !ctl.calls()
            .iter()
            .any(|c| c.contains("s2") && c.starts_with("unload"))
    );
}

#[test]
fn the_sweep_removes_units_without_a_machine_and_keeps_the_rest() {
    let tmp = tempfile::tempdir().unwrap();
    let (s, _) = services(tmp.path(), Flavor::Systemd, "ns1");
    for n in ["live", "gone", "also-gone"] {
        s.sync(
            n,
            &[Kind::Agent, Kind::Bridge],
            None,
            &paths("/d"),
            &envs(&[]),
        )
        .unwrap();
    }
    let live = vec!["live".to_string()];
    assert_eq!(s.orphans(&live), ["also-gone", "gone"]);
    for n in s.orphans(&live) {
        s.remove(&n).unwrap();
    }
    assert_eq!(s.units().len(), 2);
    assert!(s.orphans(&live).is_empty());
}

#[test]
fn a_plan_needs_a_private_dir_and_a_short_path() {
    let tmp = tempfile::tempdir().unwrap();
    let (s, _) = services(tmp.path(), Flavor::Launchd, "ns1");
    let p = s.plan("s1").unwrap();
    assert!(p.agent.starts_with(tmp.path().join("sock")));
    assert_ne!(p.agent, p.bridge);
    assert_ne!(p.agent, s.plan("s2").unwrap().agent);
    let (other, _) = services(tmp.path(), Flavor::Launchd, "ns2");
    assert_ne!(
        p.agent,
        other.plan("s1").unwrap().agent,
        "namespaced sockets"
    );
    // Not private: no units.
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(tmp.path().join("sock"), fs::Permissions::from_mode(0o755)).unwrap();
    assert!(s.plan("s1").is_none());
    assert!(
        s.sync("s1", &[Kind::Agent], None, &paths("/d"), &envs(&[]))
            .is_err()
    );
    // Too long.
    let long = tmp.path().join("x".repeat(120));
    let (s, _) = services(&long, Flavor::Launchd, "ns1");
    assert!(s.plan("s1").is_none());
}

#[test]
fn a_disabled_host_does_nothing() {
    let s = HostServices::disabled();
    assert!(!s.usable());
    assert!(s.plan("s1").is_none());
    s.sync("s1", &[Kind::Agent], None, &paths("/d"), &envs(&[]))
        .unwrap();
    s.remove("s1").unwrap();
    assert!(s.units().is_empty());
}

#[test]
fn the_binary_is_argv0_as_invoked() {
    let tmp = tempfile::tempdir().unwrap();
    let bin = tmp.path().join("sbt");
    fs::write(&bin, "#!/bin/sh\n").unwrap();
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&bin, fs::Permissions::from_mode(0o755)).unwrap();
    let env = envs(&[("PATH", &format!("/nonexistent:{}", tmp.path().display()))]);
    assert_eq!(resolve_exe(Some(OsStr::new("sbt")), &env), bin);
    assert_eq!(resolve_exe(Some(bin.as_os_str()), &envs(&[])), bin);
}
