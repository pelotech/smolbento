use std::fs;

use crate::kits::guest;
use crate::kits::model::Format;
use crate::kits::model::{Hook, HookCmd};
use crate::policy::Policy;
use crate::sandbox::labels::{self, KitRecord};
use crate::testutil::*;

const MACHINE: &str = "sbx-dev";
/// A kit record, as `sbx.kits` holds it.
fn rec(name: &str, reference: &str, provides: &[&str], format: Option<Format>) -> KitRecord {
    KitRecord {
        name: name.into(),
        reference: reference.into(),
        provides: provides.iter().map(|p| p.to_string()).collect(),
        format,
        args: Default::default(),
    }
}

/// The kits of most `dev` sandboxes: just `base`.
fn base() -> Vec<KitRecord> {
    vec![rec("base", "ghcr.io/acme/base@sha256:00", &["base"], None)]
}

/// A running shell sandbox `dev` whose `sbx.kits` holds `kits`.
fn dev_sandbox(t: &TestEnv, kits: &[KitRecord]) {
    dev_sandbox_in(t, "running", kits);
}

fn dev_sandbox_in(t: &TestEnv, state: &str, kits: &[KitRecord]) {
    // The shell kit's agent file, as create records it.
    let labels = [
        ("sbx.agent", "shell"),
        ("sbx.agent-file", "/home/agent/AGENTS.md"),
    ];
    dev_sandbox_labeled(t, state, &labels, kits);
}

/// `dev` with `labels` (and the default `sbx.command`) besides its name.
fn dev_sandbox_labeled(t: &TestEnv, state: &str, labels: &[(&str, &str)], kits: &[KitRecord]) {
    let value = labels::kits_value(kits);
    let mut all = labels.to_vec();
    if !kits.is_empty() {
        all.push(("sbx.kits", &value));
    }
    t.runner().ok(
        &["machine", "status", "-n", MACHINE],
        &sandbox_json("dev", state, &all),
    );
}

const NET_KIT: &str = r#"{"schemaVersion":"3","kind":"mixin","name":"net",
        "provides":["net@1.0.0"],"requires":["base"],
        "capabilities":[
          {"type":"com.docker.sandbox/network-policy@1","config":{
            "install":{"allow":["pkg.example.com"]},"runtime":{"allow":["api.net.example"]}}},
          {"type":"com.docker.sandbox/lifecycle@1","config":{
            "install":[{"command":"echo hi"}],
            "startup":[{"command":"echo up"}],
            "files":[{"path":"/home/agent/.netrc2","content":"x"}]}},
          {"type":"com.docker.sandbox/agent-context@1","config":{"content":"Use net."}}]}"#;

fn install_script() -> String {
    let h = Hook {
        command: HookCmd::Shell("echo hi".into()),
        user: None,
        env: vec![],
        background: false,
        clean_env: true,
    };
    format!("cd / && {}", guest::hook_script(&h))
}

/// Resources of `net`'s rules (`created_via = kit:net`).
fn kit_rules(t: &TestEnv) -> Vec<String> {
    Policy::load(&t.ctx.paths)
        .unwrap()
        .all_rules()
        .filter(|(r, _)| r.created_via == "kit:net")
        .flat_map(|(r, _)| r.resources.clone())
        .collect()
}

fn dev_calls(t: &TestEnv) -> Vec<String> {
    t.calls()
        .into_iter()
        .filter(|l| l.contains(MACHINE) && !l.contains("machine status"))
        .collect()
}

/// `kit inspect`'s SUPPORT column says what `resolve` does: `authenticate` limits and OAuth
/// without passthrough (the login happens inside the sandbox) both apply.
#[test]
fn support_is_what_resolve_accepts() {
    let cap = |ty: &str, body| crate::kits::model::Cap::new(ty, false, body);
    let host = cap(
        "com.docker.sandbox/host-mount@1",
        crate::kits::model::CapBody::HostMount {
            path: "/data".into(),
            mode: None,
        },
    );
    assert!(super::supported(&host, false));
    assert!(!super::supported(
        &cap("x", crate::kits::model::CapBody::Unsupported),
        false
    ));
    let ssh = cap(
        "com.docker.sandbox/ssh-agent@1",
        crate::kits::model::CapBody::SshAgent {
            phases: vec![crate::kits::model::SshPhase::Runtime],
            unrestricted: false,
            sign: vec!["git".into()],
            authenticate: vec!["github.com".into()],
        },
    );
    assert!(super::supported(&ssh, false));
}

#[test]
fn reference_kinds_know_every_shipped_kit() {
    for (reference, kind) in [
        ("docker", "builtin"),
        ("git-signing", "builtin"),
        ("nix", "registry"),
        ("docker.io/acme/kit:1", "registry"),
        ("./my-kit", "directory"),
        ("./my-kit/kit.yaml", "file"),
    ] {
        assert_eq!(super::reference_kind(reference), kind, "{reference}");
    }
}

#[test]
fn inspect_prints_sbxs_table_then_the_capability_support() {
    let mut t = kit_env();
    v3_kit(&t, "net", NET_KIT, &[]);
    t.sbt(&["kit", "inspect", "./net"]).unwrap();
    let out = t.stdout();
    let (head, rest) = out.split_once("Capabilities:\n").expect(&out);
    let template = head.lines().nth(3).unwrap();
    assert!(template.starts_with("Template: sbx-kit-src:net-"), "{out}");
    let head = head.replacen(template, "Template: T", 1);
    insta::assert_snapshot!(head, @r"
        Name: net
        Kind: mixin
        Schema: v3
        Template: T
        Policies:
          Network: 2 allow, 0 deny
        Credentials: 0 sources
        Commands: 1 install, 1 startup, 1 init files
        ");
    assert!(rest.contains("com.docker.sandbox/agent-context@1"), "{out}");
}

#[test]
fn inspect_counts_a_v2_kits_credentials_and_rules() {
    let mut t = kit_env();
    let full = v2_fixture("full");
    t.sbt(&["kit", "inspect", &full]).unwrap();
    let out = t.stdout();
    let head = out.split_once("Capabilities:").expect(&out).0;
    insta::assert_snapshot!(head, @r"
        Name: full-kit
        Kind: workload
        Schema: v2
        Policies:
          Network: 2 allow, 1 deny
        Credentials: 2 sources
        Commands: 2 install, 2 startup, 4 init files
        ");
    assert!(t.calls().is_empty());
}

#[test]
fn inspect_resolved_is_accepted_and_prints_the_same() {
    let mut t = kit_env();
    let full = v2_fixture("full");
    t.sbt(&["kit", "inspect", &full]).unwrap();
    let plain = t.stdout();
    t.sbt(&["kit", "inspect", "--resolved", &full]).unwrap();
    assert_eq!(t.stdout(), plain);
}

#[test]
fn inspect_json_is_the_v2_shaped_document_even_for_v3() {
    let mut t = kit_env();
    let full = v2_fixture("full");
    t.sbt(&["kit", "inspect", &full, "--format", "json"])
        .unwrap();
    let json = t.stdout();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    let keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
    assert_eq!(
        keys,
        [
            "credentials",
            "kind",
            "name",
            "permissions",
            "sandbox",
            "schemaVersion",
            "setup",
            "smolbento"
        ]
    );
    assert_eq!(v["schemaVersion"], "2");
    assert_eq!(v["kind"], "sandbox");
    assert_eq!(v["name"], "full-kit");
    assert_eq!(
        v["sandbox"],
        serde_json::json!({"image": "ghcr.io/example/agent:1.2",
                "resources": {"cpu": 2, "memory": "4g"}})
    );
    assert_eq!(
        v["permissions"],
        serde_json::json!({"network": {
                "allow": ["api.example.com", "*.cdn.example.com"],
                "deny": ["telemetry.example.com"]}})
    );
    assert_eq!(v["credentials"][0]["service"], "example");
    assert_eq!(v["credentials"][0]["apiKey"]["name"], "EXAMPLE_API_KEY");
    assert_eq!(
        v["setup"]["install"][1],
        serde_json::json!({"command": "echo hi", "user": "1000"})
    );
    // Two `setup.files` plus the two static files under `files/home` and `files/workspace`.
    assert_eq!(v["setup"]["files"].as_array().unwrap().len(), 4);

    t.sbt(&["kit", "inspect", &full, "--json"]).unwrap();
    assert_eq!(t.stdout(), json, "--json is --format json");

    v3_kit(&t, "net", NET_KIT, &[]);
    t.sbt(&["kit", "inspect", "./net", "--json"]).unwrap();
    let v: serde_json::Value = serde_json::from_str(&t.stdout()).unwrap();
    assert_eq!(v["schemaVersion"], "2");
    assert_eq!(v["kind"], "mixin");
    assert_eq!(
        v["permissions"]["network"]["allow"],
        serde_json::json!(["pkg.example.com", "api.net.example"])
    );
    assert_eq!(
        v["setup"]["install"],
        serde_json::json!([{"command": "echo hi"}])
    );
}

#[test]
fn inspect_yaml_carries_the_same_document() {
    let mut t = kit_env();
    let full = v2_fixture("full");
    t.sbt(&["kit", "inspect", &full, "--format", "json"])
        .unwrap();
    let json: serde_json::Value = serde_json::from_str(&t.stdout()).unwrap();
    t.sbt(&["kit", "inspect", &full, "--format", "yaml"])
        .unwrap();
    let yaml = t.stdout();
    assert!(yaml.starts_with("schemaVersion: "), "{yaml}");
    let back: serde_json::Value = serde_saphyr::from_str(&yaml).unwrap();
    assert_eq!(back, json);
}

#[test]
fn inspect_keeps_smolbentos_details_after_sbxs_table_and_under_one_json_key() {
    let mut t = kit_env();
    let kit = NET_KIT.replace(
            r#""provides":["net@1.0.0"]"#,
            r#""provides":["net@1.0.0"],"conflicts":["old"],"integrates":["extra"],
            "args":{"mode":{"default":"fast","enum":["fast","slow"]},"id":{"required":true}}"#,
        )
        .replace(
            r#""capabilities":["#,
            r#""capabilities":[
          {"type":"com.docker.sandbox/credential@1","config":{"service":"my-api","phase":"runtime","apiKey":{
            "inject":[{"domain":"api.x.com","header":"x-key"},{"domain":"up.x.com"}]}}},
          {"type":"com.docker.sandbox/credential@1","config":{"service":"droid","phase":"runtime","apiKey":{"name":"FACTORY_API_KEY"}}},
          {"type":"com.docker.sandbox/credential@1","config":{"service":"other","phase":"runtime","apiKey":{"name":"OTHER_KEY"}}},"#,
        );
    v3_kit(&t, "net", &kit, &[]);
    t.sbt(&["kit", "inspect", "./net"]).unwrap();
    let out = t.stdout();
    let tail = out.split_once("Source: ").expect(&out).1;
    let tail: Vec<&str> = tail.lines().collect();
    assert!(tail[0].ends_with("(local v3)"), "{out}");
    assert!(tail[1].starts_with("Digest: sha256:"), "{out}");
    assert_eq!(
        &tail[2..],
        [
            "Provides: net@1.0.0",
            "Requires: base",
            "Integrates: extra",
            "Conflicts: old",
            "Credentials:",
            "  my-api  sent to api.x.com, up.x.com",
            "  droid  sent to api.factory.ai, app.factory.ai, relay.factory.ai",
            "  other  sent to the service's own hosts",
            "Args:",
            "  id  required",
            "  mode  default \"fast\", one of fast|slow",
        ],
        "{out}"
    );

    t.sbt(&["kit", "inspect", "./net", "--json"]).unwrap();
    let v: serde_json::Value = serde_json::from_str(&t.stdout()).unwrap();
    let x = &v["smolbento"];
    assert_eq!(x["sourceType"], "local v3");
    assert_eq!(x["provides"], serde_json::json!(["net@1.0.0"]));
    assert_eq!(x["conflicts"], serde_json::json!(["old"]));
    assert_eq!(x["args"]["id"], serde_json::json!({"required": true}));
    assert_eq!(
        x["args"]["mode"],
        serde_json::json!({"required": false, "default": "fast", "enum": ["fast", "slow"]})
    );
    assert!(x["digest"].as_str().unwrap().starts_with("sha256:"));
}

fn v2_dir(t: &TestEnv, dir: &str, spec: &str) -> std::path::PathBuf {
    let d = t.ctx.cwd.join(dir);
    std::fs::create_dir_all(d.join("files/home")).unwrap();
    std::fs::write(d.join("spec.yaml"), spec).unwrap();
    std::fs::write(d.join("files/home/hello"), "hi").unwrap();
    d
}

#[test]
fn pack_writes_name_zip() {
    let mut t = kit_env();
    v2_dir(&t, "k", "schemaVersion: \"2\"\nkind: mixin\nname: demo\n");
    assert_eq!(t.sbt(&["kit", "pack", "./k"]).unwrap(), 0);
    assert_eq!(t.stdout(), "Packed artifact demo.zip\n");
    let z = std::fs::read(t.ctx.cwd.join("demo.zip")).unwrap();
    assert_eq!(z, crate::kits::artifact::zip(&t.ctx.cwd.join("k")).unwrap());
    assert_eq!(t.sbt(&["kit", "pack", "k", "-o", "out.zip"]).unwrap(), 0);
    assert_eq!(t.stdout(), "Packed artifact out.zip\n");
    assert!(t.ctx.cwd.join("out.zip").exists());
}

#[test]
fn pack_output_must_be_zip_in_an_existing_directory() {
    let mut t = kit_env();
    v2_dir(&t, "k", "schemaVersion: \"2\"\nkind: mixin\nname: demo\n");
    let e = t
        .sbt(&["kit", "pack", "./k", "-o", "out.tar.gz"])
        .unwrap_err();
    assert_eq!(
        e.to_string(),
        "pack: destination out.tar.gz must have a .zip extension"
    );
    let e = t
        .sbt(&["kit", "pack", "./k", "-o", "missing/x.zip"])
        .unwrap_err();
    let want = format!(
        "pack: resolve directory of missing/x.zip: lstat {}: no such file or directory",
        t.ctx.cwd.join("missing").display()
    );
    assert_eq!(e.to_string(), want);
}

#[test]
fn pack_refuses_a_missing_dir_and_a_bad_spec() {
    let mut t = kit_env();
    let e = t.sbt(&["kit", "pack", "./nope"]).unwrap_err();
    assert_eq!(
        format!("{e:#}"),
        "invalid artifact: artifact directory: stat ./nope: no such file or directory"
    );
    v2_dir(&t, "bad", "kind: mixin\n");
    let e = t.sbt(&["kit", "pack", "./bad"]).unwrap_err();
    assert_eq!(
        format!("{e:#}"),
        "invalid artifact: manifest: schemaVersion is required"
    );
    v2_dir(&t, "v3", "schemaVersion: \"3\"\nkind: mixin\n");
    let e = t.sbt(&["kit", "pack", "./v3"]).unwrap_err();
    assert_eq!(
        format!("{e:#}"),
        "invalid artifact: manifest: unsupported schemaVersion \"3\" (supported: [1 2])"
    );
    assert!(!t.ctx.cwd.join("demo.zip").exists());
}

#[test]
fn push_requires_a_tag_and_a_valid_kit_before_any_network_call() {
    let mut t = kit_env();
    v2_dir(&t, "k", "schemaVersion: \"2\"\nkind: mixin\nname: demo\n");
    for r in [
        "localhost:5000/k",
        "localhost:5000/k@sha256:0000000000000000000000000000000000000000000000000000000000000000",
    ] {
        let e = t.sbt(&["kit", "push", "./k", r]).unwrap_err();
        assert_eq!(
            e.to_string(),
            format!("invalid reference: {r} needs a tag (registry/repo:tag)")
        );
    }
    let e = t
        .sbt(&["kit", "push", "./nope", "localhost:5000/k:1"])
        .unwrap_err();
    assert!(format!("{e:#}").starts_with("invalid artifact: "), "{e:#}");
}

#[test]
fn pack_validates_the_directory_even_when_it_shares_a_shipped_kit_name() {
    let mut t = kit_env();
    v2_dir(&t, "docker", "schemaVersion: \"2\"\nkind: bogus\nname: d\n");
    let e = t.sbt(&["kit", "pack", "docker"]).unwrap_err();
    assert!(format!("{e:#}").starts_with("invalid artifact: "), "{e:#}");
    assert!(!t.ctx.cwd.join("d.zip").exists());
}

#[test]
fn pack_output_is_readable_like_any_new_file() {
    use std::os::unix::fs::PermissionsExt;
    let mut t = kit_env();
    v2_dir(&t, "k", "schemaVersion: \"2\"\nkind: mixin\nname: demo\n");
    t.sbt(&["kit", "pack", "./k"]).unwrap();
    let mode = std::fs::metadata(t.ctx.cwd.join("demo.zip"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o644);
}

#[test]
fn pull_applies_the_source_policy_and_push_does_not() {
    // sbx 0.53: `kit pull` of a source outside kit.allowedSources is refused before any
    // download; `kit push` doesn't check the policy.
    let mut t = test_env(&[("SMOLBENTO_KIT_ALLOWED_SOURCES", r#"["dhi.io/"]"#)]);
    let e = t
        .sbt(&["kit", "pull", "docker.io/sbx/gemini-kit:latest"])
        .unwrap_err();
    assert!(e.to_string().contains("not in your allowlist"), "{e}");
    assert!(!t.ctx.cwd.join("gemini-kit-latest.tar.gz").exists());
    v2_dir(&t, "k", "schemaVersion: \"2\"\nkind: mixin\nname: demo\n");
    // A closed loopback port: the push gets past the policy and fails at once, offline.
    let e = t
        .sbt(&["kit", "push", "./k", "127.0.0.1:1/k:1"])
        .unwrap_err();
    assert!(!e.to_string().contains("allowlist"), "{e}");
}

#[test]
fn sign_and_verify_refuse_a_local_directory() {
    let mut t = kit_env();
    v2_dir(&t, "k", "schemaVersion: \"2\"\nkind: mixin\nname: demo\n");
    for argv in [
        &["kit", "sign", "./k", "--key", "k.pem"][..],
        &["kit", "verify", "./k", "--key", "k.pub"][..],
    ] {
        let e = t.sbt(argv).unwrap_err();
        assert_eq!(
            e.to_string(),
            "signing and verifying a local kit directory isn't supported yet; push it and \
                 use the registry reference"
        );
        assert_eq!(super::super::exit_code(&e), 2);
    }
}

#[test]
fn keyless_verify_needs_an_identity_and_an_issuer() {
    let mut t = kit_env();
    let e = t.sbt(&["kit", "verify", "localhost:5000/k:1"]).unwrap_err();
    assert_eq!(
        e.to_string(),
        "keyless verification requires --certificate-identity or \
             --certificate-identity-regexp (or --key for a key-based signature)"
    );
    let e = t
        .sbt(&[
            "kit",
            "verify",
            "localhost:5000/k:1",
            "--certificate-identity",
            "me",
        ])
        .unwrap_err();
    assert_eq!(
        e.to_string(),
        "keyless verification requires --certificate-oidc-issuer or \
             --certificate-oidc-issuer-regexp"
    );
}

#[test]
fn signing_flags_need_sign_on_push() {
    let mut t = kit_env();
    v2_dir(&t, "k", "schemaVersion: \"2\"\nkind: mixin\nname: demo\n");
    let e = t
        .sbt(&["kit", "push", "./k", "localhost:5000/k:1", "--key", "k.pem"])
        .unwrap_err();
    assert_eq!(
        e.to_string(),
        "--key, --identity-token, --identity-token-file and --tlog-upload need --sign"
    );
}

#[test]
fn sign_and_verify_need_a_tag_or_digest() {
    let mut t = kit_env();
    for argv in [
        &["kit", "sign", "localhost:5000/k", "--key", "k.pem"][..],
        &["kit", "verify", "localhost:5000/k", "--key", "k.pub"][..],
    ] {
        let e = t.sbt(argv).unwrap_err();
        assert_eq!(e.to_string(), "fetch kit manifest: invalid reference");
    }
}

#[test]
fn tlog_upload_takes_its_value_only_with_equals() {
    use super::super::args::KitCmd;
    use clap::Parser;
    let cli = crate::cli::Cli::try_parse_from([
        "sbt",
        "kit",
        "sign",
        "--tlog-upload",
        "localhost:5000/k:1",
        "--key",
        "k.pem",
    ])
    .unwrap();
    let Some(crate::cli::Cmd::Kit(KitCmd::Sign { reference, signing })) = cli.command else {
        panic!("expected kit sign");
    };
    assert_eq!(reference, "localhost:5000/k:1");
    assert!(signing.tlog_upload);
}

#[test]
fn a_key_conflicts_with_keyless_flags() {
    use clap::Parser;
    for argv in [
        &[
            "sbt",
            "kit",
            "sign",
            "r:1",
            "--key",
            "k",
            "--identity-token",
            "t",
        ][..],
        &[
            "sbt",
            "kit",
            "verify",
            "r:1",
            "--key",
            "k",
            "--certificate-identity",
            "me",
        ][..],
    ] {
        assert!(crate::cli::Cli::try_parse_from(argv).is_err(), "{argv:?}");
    }
}

#[test]
fn keyless_sign_without_tlog_is_refused() {
    let mut t = kit_env();
    let e = t
        .sbt(&["kit", "sign", "localhost:5000/k:1", "--tlog-upload=false"])
        .unwrap_err();
    assert_eq!(
        e.to_string(),
        "keyless signing without the transparency log isn't supported yet (it needs a \
             timestamp authority); sign with --key for a private kit"
    );
    assert_eq!(super::super::exit_code(&e), 2);
}

#[test]
fn validate_reports_every_failure_as_json_or_yaml_and_exits_1() {
    let mut t = kit_env();
    let net = NET_KIT.replace(
        r#""capabilities":["#,
        r#""args":{"id":{"required":true}},"capabilities":["#,
    );
    v3_kit(&t, "needarg", &net, &[]);
    let cases: [(&str, &str, &str); 3] = [
        ("./missing", "directory", "doesn't exist"),
        ("docker.io/x/y:1", "registry", "--offline"),
        ("./needarg", "directory", "argument id is required"),
    ];
    for (reference, kind, msg) in cases {
        let offline = if reference.starts_with("docker.io") {
            "--offline"
        } else {
            "--json"
        };
        let mut argv = vec!["kit", "validate", reference, "--format", "json"];
        if offline == "--offline" {
            argv.push(offline);
        }
        assert_eq!(t.sbt(&argv).unwrap(), 1, "{reference}");
        let v: serde_json::Value = serde_json::from_str(&t.stdout()).unwrap();
        assert_eq!(v["reference"], reference);
        assert_eq!(v["kind"], kind);
        assert_eq!(v["valid"], false);
        assert_eq!(v["warnings"], serde_json::json!([]));
        let errors = v["errors"].as_array().unwrap();
        assert_eq!(errors.len(), 1, "{v}");
        assert!(errors[0].as_str().unwrap().contains(msg), "{v}");
    }
    v3_kit(
        &t,
        "odd",
        r#"{"schemaVersion":"3","kind":"mixin","name":"odd","capabilities":[
            {"type":"com.docker.sandbox/usb-device@1","optional":false}]}"#,
        &[],
    );
    assert_eq!(t.sbt(&["kit", "validate", "./odd", "--json"]).unwrap(), 1);
    let v: serde_json::Value = serde_json::from_str(&t.stdout()).unwrap();
    assert!(
        v["errors"][0].as_str().unwrap().contains("usb-device"),
        "{v}"
    );
    // yaml, and the plain error for a table.
    assert_eq!(
        t.sbt(&["kit", "validate", "./missing", "--format", "yaml"])
            .unwrap(),
        1
    );
    let y = t.stdout();
    assert!(
        y.starts_with("reference: ./missing\nkind: directory\nvalid: false\n"),
        "{y}"
    );
    let back: serde_json::Value = serde_saphyr::from_str(&y).unwrap();
    assert_eq!(back["valid"], false);
    t.sbt(&["kit", "validate", "./missing"]).unwrap_err();
    assert_eq!(t.stdout(), "");
    // A success has no `errors` key.
    t.sbt(&[
        "kit",
        "validate",
        &v2_fixture("tool-mixin"),
        "--format",
        "yaml",
    ])
    .unwrap();
    assert!(!t.stdout().contains("errors"));
}

#[test]
fn inspect_rejects_an_unknown_format() {
    let mut t = kit_env();
    let e = t
        .sbt(&["kit", "inspect", &v2_fixture("full"), "--format", "xml"])
        .unwrap_err();
    assert!(format!("{e:#}").contains("xml"), "{e:#}");
}

#[test]
fn offline_takes_local_v2_without_the_source_policy_and_refuses_the_network() {
    // Local kits are refused by default: --offline skips that check, as in sbx.
    let mut t = test_env(&[("SMOLBENTO_KIT_ALLOW_LOCAL_KITS", "false")]);
    let full = v2_fixture("full");
    t.sbt(&["kit", "inspect", &full]).unwrap_err();
    t.sbt(&["kit", "inspect", &full, "--offline"]).unwrap();
    assert!(t.stdout().starts_with("Name: full-kit"));
    let tool = v2_fixture("tool-mixin");
    t.sbt(&["kit", "validate", &tool, "--offline"]).unwrap();
    // A workload that takes its command from an image would need a registry lookup.
    let e = t.sbt(&["kit", "validate", &full, "--offline"]).unwrap_err();
    assert!(format!("{e:#}").contains("--offline"), "{e:#}");

    let e = t
        .sbt(&["kit", "inspect", "docker.io/x/y:1", "--offline"])
        .unwrap_err();
    assert!(format!("{e:#}").contains("--offline"), "{e:#}");
    let e = t
        .sbt(&["kit", "validate", "ghcr.io/x/y:1", "--offline"])
        .unwrap_err();
    assert!(format!("{e:#}").contains("--offline"), "{e:#}");
    assert!(t.calls().is_empty());
}

#[test]
fn offline_refuses_a_v3_source_directory_before_building() {
    let mut t = kit_env();
    v3_kit(&t, "net", NET_KIT, &[]);
    let e = t
        .sbt(&["kit", "inspect", "./net", "--offline"])
        .unwrap_err();
    let msg = format!("{e:#}");
    assert!(
        msg.contains("--offline") && msg.contains("v3 source kit"),
        "{msg}"
    );
    assert!(t.calls().is_empty());
}

#[test]
fn validate_json_reports_the_reference_kind_and_warnings() {
    let mut t = kit_env();
    let tool = v2_fixture("tool-mixin");
    t.sbt(&["kit", "validate", &tool, "--json"]).unwrap();
    let v: serde_json::Value = serde_json::from_str(&t.stdout()).unwrap();
    assert_eq!(
        v,
        serde_json::json!({"reference": tool, "kind": "directory", "valid": true,
                "warnings": []})
    );
    v3_kit(
        &t,
        "odd",
        r#"{"schemaVersion":"3","kind":"mixin","name":"odd","capabilities":[
            {"type":"com.docker.sandbox/usb-device@1","optional":true}]}"#,
        &[],
    );
    t.sbt(&["kit", "validate", "./odd", "--json"]).unwrap();
    let v: serde_json::Value = serde_json::from_str(&t.stdout()).unwrap();
    assert_eq!(v["reference"], "./odd");
    assert_eq!(v["kind"], "directory");
    assert_eq!(
        v["warnings"],
        serde_json::json!(["kit odd: skipping com.docker.sandbox/usb-device@1 (not supported)"])
    );
}

#[test]
fn inspect_marks_unsupported_capabilities() {
    let mut t = kit_env();
    v3_kit(
        &t,
        "odd",
        r#"{"schemaVersion":"3","kind":"mixin","name":"odd","capabilities":[
                {"type":"com.docker.sandbox/usb-device@1","optional":true}]}"#,
        &[],
    );
    t.sbt(&["kit", "inspect", "./odd"]).unwrap();
    let out = t.stdout();
    let l = out
        .lines()
        .find(|l| l.starts_with("com.docker.sandbox/usb-device@1"))
        .unwrap_or_else(|| panic!("{out}"));
    assert!(l.contains("yes") && l.ends_with("not supported"), "{l}");
}

#[test]
fn validate_prints_ok_or_fails_with_the_error() {
    let mut t = kit_env();
    assert_eq!(
        t.sbt(&["kit", "validate", &v2_fixture("tool-mixin")])
            .unwrap(),
        0
    );
    assert_eq!(
        t.stdout(),
        format!("✓ {} — valid\n", v2_fixture("tool-mixin"))
    );

    let yaml = fs::read_to_string(format!(
        "{}/tests/fixtures/kits/v3/bad-config-key.yaml",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    let v: serde_json::Value = serde_saphyr::from_str(&yaml).unwrap();
    v3_kit(&t, "bad", &v.to_string(), &[]);
    let e = t.sbt(&["kit", "validate", "./bad"]).unwrap_err();
    assert!(format!("{e:#}").contains("sise"), "{e:#}");
    assert_eq!(super::super::exit_code(&e), 1);
    assert_eq!(t.stdout(), "");
}

#[test]
fn validate_refuses_a_workload_without_a_command() {
    let mut t = kit_env();
    v3_kit(
        &t,
        "nocmd",
        r#"{"schemaVersion":"3","kind":"workload","name":"nocmd"}"#,
        &[],
    );
    let e = t.sbt(&["kit", "validate", "./nocmd"]).unwrap_err();
    assert_eq!(
        format!("{e:#}"),
        "workload kit image declares no ENTRYPOINT or CMD; the image config is the runtime \
             contract"
    );
    assert_eq!(t.stdout(), "");
}

#[test]
fn validate_refuses_a_v2_workload_without_an_image_or_command() {
    let mut t = kit_env();
    let kit = t.ctx.cwd.join("noimg");
    fs::create_dir(&kit).unwrap();
    fs::write(
        kit.join("spec.yaml"),
        "schemaVersion: \"2\"\nkind: sandbox\nname: noimg\n",
    )
    .unwrap();
    let e = t.sbt(&["kit", "validate", "./noimg"]).unwrap_err();
    assert_eq!(
        format!("{e:#}"),
        "workload kit declares no image or command"
    );
}

#[test]
fn validate_accepts_v2_workspace_files() {
    let mut t = kit_env();
    let ws = v2_fixture("workspace-files");
    assert_eq!(t.sbt(&["kit", "validate", &ws]).unwrap(), 0);
    assert_eq!(t.stdout(), format!("✓ {ws} — valid\n"));
}

#[test]
fn validate_checks_kit_args() {
    let mut t = kit_env();
    let e = t
        .sbt(&[
            "kit",
            "validate",
            &v2_fixture("tool-mixin"),
            "--kit-arg",
            "nope=1",
        ])
        .unwrap_err();
    assert!(format!("{e:#}").contains("nope"), "{e:#}");
}

#[test]
fn validate_reports_a_used_arg_with_no_value_like_sbx() {
    let mut t = kit_env();
    let dir = t.ctx.cwd.join("chk");
    fs::create_dir(&dir).unwrap();
    fs::write(
        dir.join("spec.yaml"),
        "schemaVersion: \"2\"\nkind: mixin\nname: chk\nargs:\n  opt:\n    description: d\n\
             setup:\n  install:\n    - command: echo ${{ kit.args.opt }}\n",
    )
    .unwrap();
    let e = t.sbt(&["kit", "validate", "./chk"]).unwrap_err();
    assert_eq!(
        format!("{e:#}"),
        "kit chk: create-phase kit arg \"opt\" has no resolved value; \
             artifact validation failed"
    );
    assert_eq!(
        t.sbt(&["kit", "validate", "./chk", "--kit-arg", "opt="])
            .unwrap(),
        0
    );
}

#[test]
fn adding_a_layered_mixin_needs_a_recreate() {
    let mut t = kit_env();
    dev_sandbox(&t, &base());
    v3_kit(
        &t,
        "layered",
        r#"{"schemaVersion":"3","kind":"mixin","name":"layered"}"#,
        &[b"layer"],
    );
    let e = t
        .sbt(&["kit", "add", "dev", "./layered", "--yes"])
        .unwrap_err();
    assert_eq!(format!("{e:#}"), "recreate required: image layers");
    assert!(dev_calls(&t).is_empty(), "{:#?}", dev_calls(&t));
    assert!(kit_rules(&t).is_empty());
}

#[test]
fn adding_a_mixin_with_a_host_mount_needs_a_recreate() {
    let mut t = kit_env();
    dev_sandbox(&t, &base());
    v3_kit(
        &t,
        "hm",
        r#"{"schemaVersion":"3","kind":"mixin","name":"hm","capabilities":[
                {"type":"com.docker.sandbox/host-mount@1","config":{"path":"/home/agent/x"}}]}"#,
        &[],
    );
    let e = t.sbt(&["kit", "add", "dev", "./hm", "--yes"]).unwrap_err();
    assert_eq!(format!("{e:#}"), "recreate required: host mounts");
    assert!(dev_calls(&t).is_empty(), "{:#?}", dev_calls(&t));
}

#[test]
fn adding_a_mixin_with_its_own_agent_file_needs_a_recreate() {
    // A new agent file gets every kit's context, and `add` has only the new kit's.
    let mut t = kit_env();
    dev_sandbox(&t, &base());
    v3_kit(
        &t,
        "ag",
        r#"{"schemaVersion":"3","kind":"mixin","name":"ag","capabilities":[
                {"type":"com.docker.sandbox/agent-context@2","optional":true,"config":{
                  "directory":"/home/agent/.ag","filename":"AGENTS.md","content":"Use ag."}}]}"#,
        &[],
    );
    let e = t.sbt(&["kit", "add", "dev", "./ag", "--yes"]).unwrap_err();
    assert_eq!(format!("{e:#}"), "recreate required: agent file");
    assert!(dev_calls(&t).is_empty(), "{:#?}", dev_calls(&t));
}

#[test]
fn adding_a_mixin_with_a_bundled_skill_needs_a_recreate() {
    let mut t = kit_env();
    dev_sandbox(&t, &base());
    v3_kit(
        &t,
        "sk",
        r#"{"schemaVersion":"3","kind":"mixin","name":"sk","capabilities":[
                {"type":"com.docker.sandbox/agent-skill@1","config":{"path":"/usr/share/x/pr"}}]}"#,
        &[],
    );
    let e = t.sbt(&["kit", "add", "dev", "./sk", "--yes"]).unwrap_err();
    assert_eq!(format!("{e:#}"), "recreate required: agent skills");
    assert!(dev_calls(&t).is_empty(), "{:#?}", dev_calls(&t));
}

/// The agent socket is mounted at create.
#[test]
fn adding_a_mixin_with_an_ssh_agent_needs_a_recreate() {
    let mut t = kit_env();
    dev_sandbox(&t, &base());
    v3_kit(
        &t,
        "sa",
        r#"{"schemaVersion":"3","kind":"mixin","name":"sa","capabilities":[
                {"type":"com.docker.sandbox/host-mount@1","config":{"path":"/home/agent/x"}},
                {"type":"com.docker.sandbox/ssh-agent@1","config":{"phase":"runtime"}}]}"#,
        &[],
    );
    let e = t.sbt(&["kit", "add", "dev", "./sa", "--yes"]).unwrap_err();
    assert_eq!(
        format!("{e:#}"),
        "recreate required: host mounts, SSH agent"
    );
    assert!(dev_calls(&t).is_empty(), "{:#?}", dev_calls(&t));
}

/// A v3 kit exports an argument as a variable (`env:`), which only a create can set. One without
/// a value exports nothing.
#[test]
fn adding_a_mixin_whose_argument_is_exported_needs_a_recreate() {
    let mut t = kit_env();
    dev_sandbox(&t, &base());
    v3_kit(
        &t,
        "ex",
        r#"{"schemaVersion":"3","kind":"mixin","name":"ex",
            "args":{"model":{"env":"TOOL_MODEL"}},"capabilities":[]}"#,
        &[],
    );
    let add = [
        "kit",
        "add",
        "dev",
        "./ex",
        "--yes",
        "--kit-arg",
        "model=fast",
    ];
    let e = t.sbt(&add).unwrap_err();
    assert_eq!(format!("{e:#}"), "recreate required: environment variables");
    assert!(dev_calls(&t).is_empty(), "{:#?}", dev_calls(&t));

    t.sbt(&add[..5]).unwrap();
}

/// The reasons come in one fixed order, whatever order the kit lists its capabilities in.
#[test]
fn recreate_reasons_keep_their_order() {
    let mut t = kit_env();
    dev_sandbox(&t, &base());
    v3_kit(
        &t,
        "many",
        r#"{"schemaVersion":"3","kind":"mixin","name":"many","capabilities":[
                {"type":"com.docker.sandbox/ssh-agent@1","config":{"phase":"runtime"}},
                {"type":"com.docker.sandbox/agent-skill@1","config":{"path":"/usr/share/x/pr"}},
                {"type":"com.docker.sandbox/port@1","config":{"container":8080}}]}"#,
        &[],
    );
    let e = t
        .sbt(&["kit", "add", "dev", "./many", "--yes"])
        .unwrap_err();
    assert_eq!(
        format!("{e:#}"),
        "recreate required: ports, agent skills, SSH agent"
    );
}

/// A config read only at create counts by its type: a port from an argument needs a recreate,
/// network rules from one don't.
#[test]
fn a_config_from_kit_arguments_needs_a_recreate_only_for_its_type() {
    let mut t = kit_env();
    dev_sandbox(&t, &base());
    v3_kit(
        &t,
        "argful",
        r#"{"schemaVersion":"3","kind":"mixin","name":"argful",
            "args":{"port":{"default":"8080"},"method":{"default":"GET"}},
            "capabilities":[
                {"type":"com.docker.sandbox/port@1","config":{"container":"${{ kit.args.port }}"}},
                {"type":"com.docker.sandbox/network-policy@2","optional":true,"config":{"runtime":
                    {"allow":[{"hosts":["a.example.com"],"methods":["${{ kit.args.method }}"]}]}}}]}"#,
        &[],
    );
    let e = t
        .sbt(&["kit", "add", "dev", "./argful", "--yes"])
        .unwrap_err();
    assert_eq!(format!("{e:#}"), "recreate required: ports");
}

#[test]
fn adding_a_mixin_with_ports_and_env_needs_a_recreate() {
    let mut t = kit_env();
    dev_sandbox(&t, &base());
    let e = t
        .sbt(&["kit", "add", "dev", &v2_fixture("tool-mixin"), "--yes"])
        .unwrap_err();
    assert_eq!(
        format!("{e:#}"),
        "recreate required: ports, environment variables"
    );
    assert!(dev_calls(&t).is_empty(), "{:#?}", dev_calls(&t));
}

#[test]
fn add_applies_a_network_and_hook_mixin_live() {
    let mut t = kit_env();
    set_policy(&t, "mode = \"deny-all\"\n");
    dev_sandbox(&t, &base());
    v3_kit(&t, "net", NET_KIT, &[]);
    t.sbt(&["kit", "add", "dev", "./net", "--yes"]).unwrap();
    assert!(t.stdout().contains("Added kit net to dev"));

    let lines = dev_calls(&t);
    let pos = |what: &str, pred: &dyn Fn(&String) -> bool| {
        lines
            .iter()
            .position(pred)
            .unwrap_or_else(|| panic!("no {what} in {lines:#?}"))
    };
    let open = pos("install network", &|l| {
        l.starts_with("machine update")
            && l.contains(" pkg.example.com")
            && l.contains(" api.net.example")
    });
    let hook = pos("hook", &|l| {
        *l == format!(
            "machine exec --name {MACHINE} -u root -- sh -c {}",
            install_script()
        )
    });
    let close = pos("runtime network", &|l| {
        l.starts_with("machine update")
            && l.contains("--reset-allow-list")
            && l.contains(" api.net.example")
            && !l.contains("pkg.example.com")
    });
    let file = pos("file", &|l| l.contains("/home/agent/.netrc2"));
    let context = pos("context", &|l| l.contains("Use net."));
    let startup_cp = pos("startup.d cp", &|l| {
        l.starts_with("machine cp ")
            && l.ends_with(&format!("{MACHINE}:/etc/smolbento/startup.d/02-net.sh"))
    });
    let script = Some("/etc/smolbento/startup.d/02-net.sh");
    let started = pos("startup", &|l| {
        *l == format!(
            "machine exec --name {MACHINE} -u root -- sh -c {}",
            crate::sandbox::startup_cmd(script)
        )
    });
    assert!(
        open < hook
            && hook < close
            && close < file
            && file < context
            && context < startup_cp
            && startup_cp < started,
        "{lines:#?}"
    );
    assert_eq!(lines.last(), Some(&lines[started]), "{lines:#?}");

    let net_dir = t.ctx.cwd.join("net").canonicalize().unwrap();
    // The record keeps each provide with its version, for a later `kit add`'s requires.
    let mut kits = base();
    kits.push(rec(
        "net",
        &net_dir.display().to_string(),
        &["net@1.0.0"],
        Some(Format::V3),
    ));
    let want = labels::kits_value(&kits);
    let record = pos("record", &|l| {
        l.starts_with("machine update") && l.contains("--label")
    });
    assert_eq!(
        lines[record],
        format!("machine update -n {MACHINE} --label sbx.kits={want}"),
        "{lines:#?}"
    );
    assert!(startup_cp < record && record < started, "{lines:#?}");
    let uploads: std::collections::BTreeMap<String, String> =
        t.runner().uploads().into_iter().collect();
    assert_eq!(
        uploads[&format!("{MACHINE}:{}", guest::STARTUP_PATH)],
        guest::STARTUP_RUNNER
    );
    assert_eq!(kit_rules(&t), vec!["api.net.example".to_string()]);
}

/// Whether `script` ran in `dev` as root, inline or copied in.
fn ran(t: &TestEnv, script: &str) -> bool {
    let inline = format!("machine exec --name {MACHINE} -u root -- sh -c {script}");
    dev_calls(t).contains(&inline) || t.runner().uploads().iter().any(|(_, c)| c == script)
}

#[test]
fn add_indexes_a_mixin_context_beside_the_workspace() {
    let mut t = kit_env();
    dev_sandbox_labeled(
        &t,
        "running",
        &[
            ("sbx.agent", "claude"),
            ("sbx.agent-file", "/w/CLAUDE.md"),
            ("sbx.workspace", "/w/proj"),
            ("sbx.workspaces", r#"["/w/proj"]"#),
        ],
        &base(),
    );
    v3_kit(&t, "net", NET_KIT, &[]);
    t.sbt(&["kit", "add", "dev", "./net", "--yes"]).unwrap();
    let path = "/w/kits-agent-context/net.md";
    assert!(ran(&t, &guest::kit_context_script(path, &["Use net."])));
    let index = guest::kits_index_script("/w/CLAUDE.md", &[("net".into(), path.into())]);
    assert!(ran(&t, &index), "{:#?}", dev_calls(&t));
    // The first kit with agent context settles the sandbox's version.
    let label = format!("machine update -n {MACHINE} --label sbx.agent-context=1");
    assert!(dev_calls(&t).contains(&label), "{:#?}", dev_calls(&t));
}

#[test]
fn add_keeps_to_the_sandboxes_agent_context_version() {
    let mut t = kit_env();
    dev_sandbox_labeled(
        &t,
        "running",
        &[
            ("sbx.agent", "claude"),
            ("sbx.agent-file", "/w/CLAUDE.md"),
            ("sbx.agent-context", "2"),
        ],
        &base(),
    );
    // NET_KIT gives its context as agent-context@1 only, and requires it.
    v3_kit(&t, "net", NET_KIT, &[]);
    let e = t.sbt(&["kit", "add", "dev", "./net", "--yes"]).unwrap_err();
    assert!(
        format!("{e:#}").contains("kit net: needs agent-context@1, but this sandbox's kits use"),
        "{e:#}"
    );
    assert_no_net_context(&t);
}

#[test]
fn add_indexes_into_a_workload_kits_recorded_agent_file() {
    let mut t = kit_env();
    dev_sandbox_labeled(
        &t,
        "running",
        &[("sbx.agent", "wl"), ("sbx.agent-file", "/x/AGENTS.md")],
        &base(),
    );
    v3_kit(&t, "net", NET_KIT, &[]);
    t.sbt(&["kit", "add", "dev", "./net", "--yes"]).unwrap();
    let path = "/x/kits-agent-context/net.md";
    let index = guest::kits_index_script("/x/AGENTS.md", &[("net".into(), path.into())]);
    assert!(ran(&t, &index), "{:#?}", dev_calls(&t));
}

#[test]
fn add_drops_a_mixin_context_when_the_workload_has_no_agent_file() {
    // Without a recorded agent file, a mixin's context is dropped, whatever the agent.
    for agent in ["wl", "claude"] {
        let mut t = kit_env();
        dev_sandbox_labeled(
            &t,
            "running",
            &[
                ("sbx.agent", agent),
                ("sbx.command", r#"["/bin/agent"]"#),
                ("sbx.workspace", "/w/proj"),
                ("sbx.workspaces", r#"["/w/proj"]"#),
            ],
            &base(),
        );
        v3_kit(&t, "net", NET_KIT, &[]);
        t.sbt(&["kit", "add", "dev", "./net", "--yes"]).unwrap();
        assert_no_net_context(&t);
    }
}

fn assert_no_net_context(t: &TestEnv) {
    assert!(
        !dev_calls(t).iter().any(|l| l.contains("Use net."))
            && !t
                .ctx
                .vm
                .runner()
                .uploads()
                .iter()
                .any(|(_, c)| c.contains("Use net.")),
        "{:#?}",
        dev_calls(t)
    );
}

/// R30 for `kit add`: the kit stays and the sandbox keeps running.
#[test]
fn a_failing_startup_hook_on_kit_add_only_warns() {
    let mut t = kit_env();
    set_policy(&t, "mode = \"deny-all\"\n");
    dev_sandbox(&t, &base());
    v3_kit(&t, "net", NET_KIT, &[]);
    let script = Some("/etc/smolbento/startup.d/02-net.sh");
    t.runner().on(
        &root_sh(MACHINE, &crate::sandbox::startup_cmd(script)),
        crate::smolvm::Output {
            code: 2,
            ..Default::default()
        },
    );
    t.sbt(&["kit", "add", "dev", "./net", "--yes"]).unwrap();
    assert!(t.stdout().contains("Added kit net to dev"));
    let lines = dev_calls(&t);
    assert!(
        !lines.iter().any(|l| l.starts_with("machine stop")),
        "{lines:#?}"
    );
}

#[test]
fn add_runs_install_hooks_in_the_recorded_image_workdir() {
    let mut t = kit_env();
    set_policy(&t, "mode = \"deny-all\"\n");
    dev_sandbox_labeled(
        &t,
        "running",
        &[("sbx.agent", "shell"), ("sbx.workdir", "/x")],
        &base(),
    );
    v3_kit(&t, "net", NET_KIT, &[]);
    t.sbt(&["kit", "add", "dev", "./net", "--yes"]).unwrap();
    let want = format!(
        "machine exec --name {MACHINE} -u root -- sh -c {}",
        install_script().replacen("cd / ", "cd '/x' ", 1)
    );
    assert!(dev_calls(&t).contains(&want), "{:#?}", dev_calls(&t));
}

#[test]
fn add_opens_install_rules_an_interrupted_add_left() {
    use crate::kits::model::{NetRule, Rules};
    let mut t = kit_env();
    set_policy(&t, "mode = \"deny-all\"\n");
    // Both of net's rules are already there, so this add adds none.
    let rules = |h: &str| Rules {
        allow: vec![NetRule::host(h)],
        deny: vec![],
    };
    let mut policy = Policy::load(&t.ctx.paths).unwrap();
    policy
        .add_kit_rules("dev", "net", &rules("api.net.example"), false)
        .unwrap();
    policy
        .add_kit_rules("dev", "net", &rules("pkg.example.com"), true)
        .unwrap();
    policy.save(&t.ctx.paths).unwrap();
    dev_sandbox(&t, &base());
    v3_kit(&t, "net", NET_KIT, &[]);
    t.sbt(&["kit", "add", "dev", "./net", "--yes"]).unwrap();

    let lines = dev_calls(&t);
    let hook = lines
        .iter()
        .position(|l| l.ends_with(&install_script()))
        .unwrap_or_else(|| panic!("{lines:#?}"));
    assert!(
        lines[..hook]
            .iter()
            .any(|l| l.starts_with("machine update") && l.contains(" pkg.example.com")),
        "{lines:#?}"
    );
    let p = Policy::load(&t.ctx.paths).unwrap();
    assert!(p.all_rules().all(|(r, _)| !r.is_kit_install()), "{p:?}");
}

#[test]
fn add_without_yes_and_without_a_terminal_changes_nothing() {
    let mut t = kit_env();
    set_policy(&t, "mode = \"deny-all\"\n");
    dev_sandbox(&t, &base());
    v3_kit(&t, "net", NET_KIT, &[]);
    let e = t.sbt(&["kit", "add", "dev", "./net"]).unwrap_err();
    assert_eq!(
        format!("{e:#}"),
        "kit add needs --yes to grant network access without a terminal"
    );
    assert!(dev_calls(&t).is_empty(), "{:#?}", dev_calls(&t));
    assert!(kit_rules(&t).is_empty());
}

#[test]
fn add_asks_before_granting_network_and_declining_changes_nothing() {
    let mut t = kit_env();
    set_policy(&t, "mode = \"deny-all\"\n");
    dev_sandbox(&t, &base());
    v3_kit(&t, "net", NET_KIT, &[]);
    t.answer("n\n");
    let e = sbt(&mut t.ctx, &["kit", "add", "dev", "./net"]).unwrap_err();
    assert_eq!(format!("{e:#}"), "aborted; nothing was changed");
    assert!(kit_rules(&t).is_empty());
}

#[test]
fn a_mixin_without_network_needs_no_approval() {
    let mut t = kit_env();
    dev_sandbox(&t, &base());
    v3_kit(
        &t,
        "quiet",
        r#"{"schemaVersion":"3","kind":"mixin","name":"quiet","capabilities":[
                {"type":"com.docker.sandbox/lifecycle@1","config":{"install":[{"command":"echo hi"}]}}]}"#,
        &[],
    );
    t.sbt(&["kit", "add", "dev", "./quiet"]).unwrap();
    let lines = dev_calls(&t);
    // The only update records the kit; there is no network change.
    assert!(
        lines
            .iter()
            .filter(|l| l.starts_with("machine update"))
            .all(|l| l.contains("--label sbx.kits=")),
        "{lines:#?}"
    );
    assert!(
        !lines.iter().any(|l| l.contains("startup.d")),
        "no startup hooks: {lines:#?}"
    );
}

#[test]
fn add_meets_a_requires_on_the_sandboxs_agent_kit() {
    let mut t = kit_env();
    // The claude kit provides its name, as sbx's does.
    let claude = rec(
        "claude",
        "docker.io/sbx/claude:latest@sha256:ab",
        &["claude@2.1.325"],
        Some(Format::V3),
    );
    dev_sandbox_labeled(&t, "running", &[("sbx.agent", "claude")], &[claude]);
    v3_kit(
        &t,
        "forclaude",
        r#"{"schemaVersion":"3","kind":"mixin","name":"forclaude","requires":["claude"],
                "capabilities":[{"type":"com.docker.sandbox/lifecycle@1",
                "config":{"install":[{"command":"echo hi"}]}}]}"#,
        &[],
    );
    t.sbt(&["kit", "add", "dev", "./forclaude"]).unwrap();
}

#[test]
fn add_takes_a_v2_kit_whatever_the_sandbox_already_has() {
    // The record doesn't say which format a kit had, so nothing in it is taken for v3.
    for (labels, record) in [
        (
            &[("sbx.agent", "shell")][..],
            vec![rec("docker", "builtin:docker", &["docker@1.0.0"], None)],
        ),
        (
            &[("sbx.agent", "wl"), ("sbx.command", r#"["wl"]"#)][..],
            vec![rec("other", "/k/other", &[], None)],
        ),
    ] {
        let mut t = kit_env();
        dev_sandbox_labeled(&t, "running", labels, &record);
        let dir = t.ctx.cwd.join("plain");
        std::fs::create_dir_all(&dir).unwrap();
        let spec = "schemaVersion: \"2\"\nkind: mixin\nname: plain\n";
        std::fs::write(dir.join("spec.yaml"), spec).unwrap();
        t.sbt(&["kit", "add", "dev", "./plain", "-y"]).unwrap();
    }
}

#[test]
fn add_refuses_mixing_formats_with_what_the_record_says() {
    // A record from this release says each kit's format; the shipped docker kit has none.
    let plain = |t: &TestEnv| {
        let dir = t.ctx.cwd.join("plain");
        std::fs::create_dir_all(&dir).unwrap();
        let spec = "schemaVersion: \"2\"\nkind: mixin\nname: plain\n";
        std::fs::write(dir.join("spec.yaml"), spec).unwrap();
    };
    let mut t = kit_env();
    dev_sandbox(
        &t,
        &[rec(
            "net",
            "ghcr.io/acme/net@sha256:01",
            &["net"],
            Some(Format::V3),
        )],
    );
    plain(&t);
    let e = t.sbt(&["kit", "add", "dev", "./plain", "-y"]).unwrap_err();
    assert_eq!(
        format!("{e:#}"),
        "cannot mix v3 kits with v1/v2 kits in one sandbox; compositions are single-format \
             (v3: net; v1/v2: plain). Use a v3 version of the v1/v2 kit"
    );

    let mut t = kit_env();
    dev_sandbox(
        &t,
        &[rec("docker", "builtin:docker", &["docker@1.0.0"], None)],
    );
    plain(&t);
    t.sbt(&["kit", "add", "dev", "./plain", "-y"]).unwrap();
}

#[test]
fn add_refuses_a_kit_already_in_the_sandbox_and_unmet_requirements() {
    let mut t = kit_env();
    dev_sandbox(
        &t,
        &[rec("net", "ghcr.io/acme/net@sha256:01", &["net"], None)],
    );
    v3_kit(&t, "net", NET_KIT, &[]);
    let e = t.sbt(&["kit", "add", "dev", "./net", "--yes"]).unwrap_err();
    assert_eq!(format!("{e:#}"), "kit net is already in dev");

    // No base kit: a missing record is no kits, and `requires: base` is unmet.
    let mut t = kit_env();
    dev_sandbox(&t, &[]);
    v3_kit(&t, "net", NET_KIT, &[]);
    let e = t.sbt(&["kit", "add", "dev", "./net", "--yes"]).unwrap_err();
    assert_eq!(
        format!("{e:#}"),
        "resolve: the kit set is not coherent:\n  - ./net requires \"base\" but nothing in \
             the set provides it; add a kit that provides com.docker.kit/base"
    );
    assert!(kit_rules(&t).is_empty());
}

#[test]
fn add_matches_versioned_requires_against_the_recorded_provides() {
    let kit = NET_KIT.replace(r#""requires":["base"]"#, r#""requires":["base >= 2, < 3"]"#);
    // An old record's bare provide has no version: it meets only unconstrained requires.
    let mut t = kit_env();
    dev_sandbox(&t, &base());
    v3_kit(&t, "net", &kit, &[]);
    let e = t.sbt(&["kit", "add", "dev", "./net", "--yes"]).unwrap_err();
    assert_eq!(
        format!("{e:#}"),
        "resolve: the kit set is not coherent:\n  - ./net requires \"base >= 2, < 3\" but the \
             set only offers base (unversioned, from base)"
    );

    let mut t = kit_env();
    dev_sandbox(
        &t,
        &[rec(
            "base",
            "ghcr.io/acme/base@sha256:00",
            &["base@2.4.1"],
            None,
        )],
    );
    v3_kit(&t, "net", &kit, &[]);
    t.sbt(&["kit", "add", "dev", "./net", "--yes"]).unwrap();
}

#[test]
fn validate_checks_a_mixin_against_a_set_that_meets_its_requires() {
    let mut t = kit_env();
    let kit = NET_KIT.replace(
        r#""requires":["base"]"#,
        r#""requires":["base > 2.1, < 3","com.example/tool = 1.4"]"#,
    );
    v3_kit(&t, "net", &kit, &[]);
    assert_eq!(t.sbt(&["kit", "validate", "./net"]).unwrap(), 0);
    assert_eq!(t.stdout(), "✓ ./net — valid\n");
}

#[test]
fn add_refuses_a_workload_kit() {
    let mut t = kit_env();
    dev_sandbox(&t, &base());
    let e = t
        .sbt(&["kit", "add", "dev", &v2_fixture("tool-workload"), "--yes"])
        .unwrap_err();
    assert!(format!("{e:#}").contains("not a mixin"), "{e:#}");
}

#[test]
fn a_failed_install_hook_drops_the_kits_rules() {
    let mut t = kit_env();
    set_policy(&t, "mode = \"deny-all\"\n");
    let mut policy = Policy::load(&t.ctx.paths).unwrap();
    let mine = policy
        .add_rule(
            Some("dev"),
            crate::policy::Decision::Allow,
            "mine.example",
            "added",
            None,
            None,
        )
        .unwrap();
    policy.save(&t.ctx.paths).unwrap();
    dev_sandbox(&t, &base());
    v3_kit(&t, "net", NET_KIT, &[]);
    t.runner()
        .fail(&root_sh(MACHINE, &install_script()), "exec", "apt broke");
    let e = t.sbt(&["kit", "add", "dev", "./net", "--yes"]).unwrap_err();
    let m = format!("{e:#}");
    assert!(
        m.starts_with("kit add failed; nothing was kept, but install hooks may have changed")
            && m.contains("kit net install hook 1 failed")
            && m.contains("apt broke"),
        "{m}"
    );
    assert!(kit_rules(&t).is_empty());
    let policy = Policy::load(&t.ctx.paths).unwrap();
    assert_eq!(
        policy.find(&mine).map(|(r, s)| (r.resources.clone(), s)),
        Some((vec!["mine.example".to_string()], Some("dev"))),
        "the user's own rule stays"
    );
    let lines = dev_calls(&t);
    let last_update = lines
        .iter()
        .rfind(|l| l.starts_with("machine update"))
        .unwrap();
    assert!(!last_update.contains("api.net.example"), "{lines:#?}");
    assert!(last_update.contains("mine.example"), "{lines:#?}");
    assert!(!lines.iter().any(|l| l.contains("machine delete")));
    assert!(!lines.iter().any(|l| l.contains("--label")), "{lines:#?}");
}

#[test]
fn a_failed_network_push_is_not_blamed_on_hooks() {
    let mut t = kit_env();
    set_policy(&t, "mode = \"deny-all\"\n");
    dev_sandbox(&t, &base());
    v3_kit(&t, "net", NET_KIT, &[]);
    t.runner()
        .once_fail(&["machine", "update", "-n", MACHINE], "net", "no route");
    let e = t.sbt(&["kit", "add", "dev", "./net", "--yes"]).unwrap_err();
    let m = format!("{e:#}");
    assert!(
        m.starts_with("kit add failed; nothing was kept: ") && !m.contains("install hooks"),
        "{m}"
    );
    assert!(m.contains("no route"), "{m}");
    assert!(kit_rules(&t).is_empty());
    assert!(
        !dev_calls(&t).iter().any(|l| l.contains("echo hi")),
        "no hook ran"
    );
}

#[test]
fn a_failed_write_without_kit_rules_claims_no_rule_removal() {
    let mut t = kit_env();
    dev_sandbox(&t, &base());
    v3_kit(
        &t,
        "quiet",
        r#"{"schemaVersion":"3","kind":"mixin","name":"quiet","capabilities":[
                {"type":"com.docker.sandbox/lifecycle@1","config":{"install":[{"command":"echo hi"}]}}]}"#,
        &[],
    );
    // The startup files' `mkdir`, the first write.
    t.runner().fail(
        &root_sh(MACHINE, "mkdir -p '/etc/smolbento'"),
        "exec",
        "disk full",
    );
    let e = t.sbt(&["kit", "add", "dev", "./quiet"]).unwrap_err();
    let m = format!("{e:#}");
    assert!(
        m.starts_with("kit add failed; files it wrote may remain: ") && !m.contains("rules"),
        "{m}"
    );
}

#[test]
fn a_refusal_after_starting_a_stopped_sandbox_says_so() {
    let mut t = kit_env();
    set_policy(&t, "mode = \"deny-all\"\n");
    dev_sandbox_in(&t, "stopped", &base());
    v3_kit(&t, "net", NET_KIT, &[]);
    let e = t.sbt(&["kit", "add", "dev", "./net"]).unwrap_err();
    assert_eq!(
        format!("{e:#}"),
        "kit add needs --yes to grant network access without a terminal\n\
             (dev was started for this and is still running)"
    );
    assert!(
        dev_calls(&t).iter().any(|l| l.starts_with("machine start")),
        "{:#?}",
        dev_calls(&t)
    );
}

/// A kept host-mount directory for kit `/k` at `path`, as a create leaves it.
fn kept_mount(t: &TestEnv, path: &str) -> std::path::PathBuf {
    use crate::kits::host_mount::{HostDir, Managed, create_managed, managed_dir};
    let host = managed_dir(&t.ctx.paths.kit_host_mounts(), "/k", path);
    let d = HostDir {
        host: host.clone(),
        guest: path.into(),
        managed: Some(Managed {
            mode: 0o755,
            kit: "/k".into(),
        }),
    };
    create_managed(&[d]).unwrap();
    host
}

#[test]
fn kit_mounts_ls_lists_kept_host_mounts() {
    let mut t = test_env(&[]);
    t.sbt(&["kit", "mounts", "ls"]).unwrap();
    assert_eq!(t.stdout(), "ID   KIT   PATH   HOST PATH\n");
    let host = kept_mount(&t, "/home/agent/.cache");
    t.sbt(&["kit", "mounts", "ls", "--json"]).unwrap();
    let v: serde_json::Value = serde_json::from_str(&t.stdout()).unwrap();
    assert_eq!(v[0]["kit"], "/k");
    assert_eq!(v[0]["path"], "/home/agent/.cache");
    assert_eq!(v[0]["host_path"], host.display().to_string());
    assert!(v[0]["id"].as_str().is_some_and(|id| !id.is_empty()));
}

#[test]
fn kit_mounts_rm_refuses_a_mount_a_sandbox_uses() {
    let mut t = test_env(&[]);
    let host = kept_mount(&t, "/data");
    let id = crate::kits::host_mount::kept(&t.ctx.paths.kit_host_mounts()).unwrap()[0]
        .id
        .clone();
    let label = format!(r#"{{"/data":"{}"}}"#, host.display());
    t.sandboxes(&[("a", "stopped", &[("sbx.host-mounts", &label)])]);
    let e = t.sbt_err(&["kit", "mounts", "rm", &id]);
    assert!(
        e.contains("sandbox a mounts it; remove the sandbox first"),
        "{e}"
    );
    assert!(host.exists());

    t.sandboxes(&[]);
    t.sbt(&["kit", "mounts", "rm", &id]).unwrap();
    assert!(!host.exists());
    assert_eq!(t.stdout(), format!("Removed {id}\n"));
}

/// A mixin with a required `network-policy@2` request rule, which only hosted egress enforces.
const REQUEST_RULE_KIT: &str = r#"{"schemaVersion":"3","kind":"mixin","name":"rr","capabilities":[
    {"type":"com.docker.sandbox/network-policy@2","config":{"runtime":
        {"allow":[{"hosts":["api.example.com"],"methods":["GET"],"paths":["/v1/**"]}]}}}]}"#;

/// The default (hosted) with a service manager, or `network.egress=smolvm`, and `./rr`.
fn request_rule_env(hosted: bool) -> (TestEnv, Option<tempfile::TempDir>) {
    let mut t = if hosted {
        kit_env()
    } else {
        test_env(&[
            ("SMOLBENTO_KIT_ALLOW_LOCAL_KITS", "true"),
            ("SMOLBENTO_NETWORK_EGRESS", "smolvm"),
        ])
    };
    let tmp = hosted.then(|| with_services(&mut t).1);
    v3_kit(&t, "rr", REQUEST_RULE_KIT, &[]);
    (t, tmp)
}

fn np2_support(t: &mut TestEnv) -> String {
    t.sbt(&["kit", "inspect", "./rr"]).unwrap();
    let out = t.stdout();
    out.lines()
        .find(|l| l.starts_with("com.docker.sandbox/network-policy@2"))
        .unwrap_or_else(|| panic!("{out}"))
        .to_string()
}

#[test]
fn kit_validate_accepts_request_rules_under_hosted_default() {
    let (mut t, _tmp) = request_rule_env(true);
    assert_eq!(t.sbt(&["kit", "validate", "./rr"]).unwrap(), 0);
    assert_eq!(t.stdout(), "✓ ./rr — valid\n");
}

#[test]
fn kit_inspect_flags_request_rules_under_smolvm() {
    let (mut t, _tmp) = request_rule_env(false);
    let l = np2_support(&mut t);
    assert!(l.ends_with("not supported"), "{l}");
}
