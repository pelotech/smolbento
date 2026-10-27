//! Kit v2 `spec.yaml` shim: reads the v2 grammar into the same model as v3, so everything after
//! parsing treats the two alike. Every struct rejects unknown keys, which is how v1 fields such
//! as `network.allowedDomains` fail to decode, as they do in sbx.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use serde_json::Value;

use crate::kits::model::*;
use crate::kits::v3::{check_name, name_from_source};

const NS: &str = "com.docker.sandbox/";
/// Left for apply to expand: the workspace path is only known at create time.
const WORKSPACE: &str = "${{ kit.env.WORKSPACE }}";
const HOME: &str = "/home/agent";

/// The kit's name as `parse` gives it, reading only the `name` field.
pub fn name_in(yaml: &str, dir: &Path) -> Result<String> {
    let v: Value = serde_saphyr::from_str(yaml).context("reading the v2 kit descriptor")?;
    let name = match v.get("name") {
        None | Some(Value::Null) => None,
        Some(Value::String(n)) => Some(n.clone()),
        Some(_) => bail!("reading the v2 kit descriptor: name must be a string"),
    };
    name_or_source(name, dir)
}

fn name_or_source(name: Option<String>, dir: &Path) -> Result<String> {
    match name {
        Some(n) => check_name(n),
        None => name_from_source(&Source::LocalV2(dir.to_path_buf())),
    }
}

/// `dir` is the kit directory: `spec.yaml` sits in it, with optional `files/home` and
/// `files/workspace` beside it. Fields smolbento ignores are warnings on stderr.
pub fn parse(yaml: &str, dir: &Path) -> Result<Kit> {
    let (kit, warnings) = parse_warn(yaml, dir)?;
    for w in warnings {
        eprintln!("{w}");
    }
    Ok(kit)
}

/// `parse`, returning its warnings instead of printing them.
fn parse_warn(yaml: &str, dir: &Path) -> Result<(Kit, Vec<String>)> {
    let v: Value = serde_saphyr::from_str(yaml).context("reading the v2 kit descriptor")?;
    let s: Spec = serde_json::from_value(v).context("reading the v2 kit descriptor")?;
    if s.schema_version != "2" {
        bail!("schemaVersion must be \"2\" (got {:?})", s.schema_version);
    }
    let kind = match s.kind.as_str() {
        "sandbox" => Kind::Workload,
        "mixin" => Kind::Mixin,
        k => bail!("unknown kind '{k}'"),
    };
    let source = Source::LocalV2(dir.to_path_buf());
    let name = name_or_source(s.name.clone(), dir)?;
    let mut warnings = Vec::new();
    let mut ignored =
        |field: &str| warnings.push(format!("warning: kit {name}: {field} is ignored"));

    let mut caps = Vec::new();
    let mut sandbox = s.sandbox.unwrap_or_default();
    if sandbox.build.is_some() {
        ignored("sandbox.build");
    }
    if sandbox.resources.as_ref().is_some_and(|r| r.gpu.is_some()) {
        ignored("sandbox.resources.gpu");
    }
    // Only a workload's command runs.
    if kind == Kind::Mixin {
        if sandbox.entrypoint.take().is_some() {
            ignored("sandbox.entrypoint");
        }
        if sandbox.command.take().is_some() {
            ignored("sandbox.command");
        }
    }
    if let Some(r) = sandbox.resources {
        caps.push(cap(
            "resources@1",
            CapBody::Resources {
                cpus: r.cpu.map(|n| n.to_string()),
                memory: r.memory,
            },
        ));
    }
    if let Some(n) = s.permissions.and_then(|p| p.network) {
        let rule = |host| NetRule {
            host,
            methods: vec![],
            paths: vec![],
        };
        caps.push(cap(
            "network-policy@1",
            CapBody::Network {
                install: Rules::default(),
                runtime: Rules {
                    allow: n.allow.into_iter().map(rule).collect(),
                    deny: n.deny.into_iter().map(rule).collect(),
                },
            },
        ));
    }
    for c in s.credentials {
        caps.push(cap("credential@1", CapBody::Credential(credential(c)?)));
    }
    for p in s.ports {
        if p.container == 0 {
            bail!("ports: container must be 1..65535");
        }
        let udp = match p.protocol.as_deref() {
            None | Some("") | Some("tcp") => false,
            Some("udp") => true,
            Some(t) => bail!("ports: protocol must be tcp or udp (got {t:?})"),
        };
        caps.push(cap(
            "port@1",
            CapBody::Port {
                container: p.container,
                udp,
            },
        ));
    }
    for v in s.volumes {
        let tmpfs = match v.ty.as_deref() {
            None | Some("") => false,
            Some("tmpfs") => true,
            Some(t) => bail!("volumes: type must be empty or tmpfs (got {t:?})"),
        };
        caps.push(cap(
            "volume@1",
            CapBody::Volume {
                path: v.path,
                tmpfs,
                mode: v.mode,
            },
        ));
    }
    if let Some(l) = lifecycle(s.setup.unwrap_or_default(), dir, &name, &mut warnings)? {
        caps.push(cap("lifecycle@1", CapBody::Lifecycle(l)));
    }
    // No content, nothing to write.
    if let Some(a) = s.agent_instructions
        && let Some(content) = a.content.filter(|c| !c.trim().is_empty())
    {
        if kind == Kind::Mixin && a.filename.is_some() {
            warnings.push(format!(
                "warning: kit {name}: agentInstructions.filename is only used for kind \
                 \"sandbox\", not \"mixin\""
            ));
        }
        caps.push(cap(
            "agent-context@2",
            CapBody::AgentContext(AgentContextReq {
                filename: a.filename,
                directory: None,
                content,
            }),
        ));
    }
    if s.security.is_some_and(|s| s.privileged) {
        caps.push(cap("privileged@1", CapBody::Privileged));
    }

    let args = s
        .args
        .into_iter()
        .map(|(name, a)| {
            let def = ArgDef {
                default: a.default,
                required: a.required,
                pattern: a.pattern,
                enum_values: a.enum_values,
                env: None,
            };
            (name, def)
        })
        .collect();
    let command = match (sandbox.entrypoint, sandbox.command) {
        (None, None) => None,
        (e, c) => Some(
            e.into_iter()
                .flatten()
                .chain(c.map(CommandCfg::default_argv).into_iter().flatten())
                .collect(),
        ),
    };
    let kit = Kit {
        name,
        source,
        digest: None,
        kind,
        provides: vec![],
        requires: s.requires.and_then(|r| r.agent).into_iter().collect(),
        args,
        caps,
        env: s.environment.variables.into_iter().collect(),
        content: sandbox.image.map_or(Content::None, Content::Image),
        command,
        config: None,
    };
    Ok((kit, warnings))
}

fn cap(name: &str, body: CapBody) -> Cap {
    Cap {
        ty: format!("{NS}{name}"),
        optional: false,
        body,
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Spec {
    schema_version: String,
    kind: String,
    name: Option<String>,
    // Descriptive only.
    #[allow(dead_code)]
    version: Option<String>,
    #[allow(dead_code)]
    display_name: Option<String>,
    #[allow(dead_code)]
    description: Option<String>,
    #[allow(dead_code)]
    #[serde(rename = "sourceURL")]
    source_url: Option<String>,
    #[allow(dead_code)]
    licenses: Option<Vec<String>>,
    #[allow(dead_code)]
    locked: Option<Vec<String>>,
    // Composition (`extends`, `mixins`) belongs to the resolver; the keys are accepted so valid
    // specs parse.
    #[allow(dead_code)]
    extends: Option<String>,
    #[allow(dead_code)]
    mixins: Option<Value>,
    requires: Option<RequiresCfg>,
    security: Option<SecurityCfg>,
    #[serde(default)]
    args: BTreeMap<String, ArgCfg>,
    agent_instructions: Option<AgentInstructions>,
    permissions: Option<Permissions>,
    #[serde(default)]
    ports: Vec<PortCfg>,
    #[serde(default)]
    credentials: Vec<CredCfg>,
    #[serde(default)]
    environment: Environment,
    setup: Option<Setup>,
    #[serde(default)]
    volumes: Vec<VolumeCfg>,
    sandbox: Option<SandboxCfg>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequiresCfg {
    agent: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SecurityCfg {
    #[serde(default)]
    privileged: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ArgCfg {
    #[serde(default, deserialize_with = "opt_scalar")]
    default: Option<String>,
    #[serde(default)]
    required: bool,
    #[allow(dead_code)]
    description: Option<String>,
    #[serde(default, rename = "enum", deserialize_with = "scalar_list")]
    enum_values: Vec<String>,
    pattern: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentInstructions {
    filename: Option<String>,
    content: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Permissions {
    network: Option<NetworkCfg>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkCfg {
    #[serde(default)]
    allow: Vec<String>,
    #[serde(default)]
    deny: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PortCfg {
    container: u16,
    protocol: Option<String>,
    #[allow(dead_code)]
    name: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VolumeCfg {
    path: String,
    #[serde(rename = "type")]
    ty: Option<String>,
    // smolvm volumes are not sized per mount.
    #[allow(dead_code)]
    size: Option<String>,
    mode: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct Environment {
    #[serde(default)]
    variables: BTreeMap<String, String>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct SandboxCfg {
    image: Option<String>,
    // Image builds are not supported (a warning); `image` is required alongside, per the sbx
    // docs.
    build: Option<Value>,
    entrypoint: Option<Vec<String>>,
    command: Option<CommandCfg>,
    resources: Option<ResourcesCfg>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum CommandCfg {
    List(Vec<String>),
    Map(CommandMap),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CommandMap {
    #[serde(default)]
    default: Vec<String>,
    // The interactive tail belongs to the agent launcher.
    #[allow(dead_code)]
    interactive: Option<Vec<String>>,
}

impl CommandCfg {
    fn default_argv(self) -> Vec<String> {
        match self {
            CommandCfg::List(l) => l,
            CommandCfg::Map(m) => m.default,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResourcesCfg {
    cpu: Option<f64>,
    memory: Option<String>,
    // Not supported: a warning.
    gpu: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CredCfg {
    service: String,
    #[allow(dead_code)]
    description: Option<String>,
    #[allow(dead_code)]
    required: Option<bool>,
    // Reserved upstream: accepted, no effect.
    #[allow(dead_code)]
    provider: Option<String>,
    #[serde(rename = "apiKey")]
    api_key: Option<ApiKeyCfg>,
    oauth: Option<OAuthCfg>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ApiKeyCfg {
    #[serde(default)]
    name: String,
    // The proxy always keeps real values off the guest, so the flag changes nothing here.
    #[allow(dead_code)]
    #[serde(default)]
    proxy_managed: bool,
    #[serde(default)]
    inject: Vec<InjectCfg>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InjectCfg {
    domain: String,
    header: Option<String>,
    format: Option<String>,
    scheme: Option<String>,
    username: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OAuthCfg {
    token_endpoint: Option<TokenEndpoint>,
    #[serde(default)]
    resource_hosts: Vec<String>,
    #[serde(default)]
    passthrough: bool,
    // Sentinel and credential-file plumbing is the proxy's business; accepted and ignored.
    #[allow(dead_code)]
    sentinels: Option<Value>,
    #[allow(dead_code)]
    credential_file: Option<Value>,
    #[allow(dead_code)]
    response_fields: Option<Value>,
    #[allow(dead_code)]
    skip_if_env: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenEndpoint {
    host: String,
    #[allow(dead_code)]
    path: Option<String>,
}

/// v2 credentials are always a runtime concern; install-phase injection is a v3 notion.
fn credential(c: CredCfg) -> Result<CredReq> {
    if c.api_key.is_none() && c.oauth.is_none() {
        bail!("credentials: {} needs apiKey or oauth", c.service);
    }
    let (env, inject) = match c.api_key {
        Some(k) => {
            let inject = k
                .inject
                .into_iter()
                .map(|i| inject(i, &c.service))
                .collect::<Result<_>>()?;
            ((!k.name.is_empty()).then_some(k.name), inject)
        }
        None => (None, vec![]),
    };
    let oauth = c.oauth.map(|o| OAuthReq {
        passthrough: o.passthrough,
        token_host: o.token_endpoint.map(|t| t.host),
        resource_hosts: o.resource_hosts,
    });
    Ok(CredReq {
        service: c.service,
        install: false,
        runtime: true,
        env,
        inject,
        oauth,
    })
}

/// `scheme` is shorthand: `bearer` is `Authorization: Bearer %s`; `basic` is implied by a
/// username, which the model carries instead.
fn inject(i: InjectCfg, service: &str) -> Result<Inject> {
    if i.format.is_some() && i.scheme.is_some() {
        bail!("credentials: {service} inject sets both format and scheme");
    }
    let (mut header, mut format) = (i.header, i.format);
    match i.scheme.as_deref() {
        None => {}
        Some("bearer") => {
            header.get_or_insert_with(|| "Authorization".to_string());
            format = Some("Bearer %s".to_string());
        }
        Some("basic") => {
            if i.username.is_none() {
                bail!("credentials: {service} scheme basic needs a username");
            }
        }
        Some(s) => bail!("credentials: {service} scheme must be bearer or basic (got {s:?})"),
    }
    Ok(Inject {
        domain: i.domain,
        header,
        format,
        basic_user: i.username,
    })
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct Setup {
    #[serde(default)]
    install: Vec<InstallCfg>,
    #[serde(default)]
    startup: Vec<StartupCfg>,
    #[serde(default)]
    files: Vec<FileCfg>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InstallCfg {
    command: String,
    user: Option<String>,
    #[allow(dead_code)]
    description: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StartupCfg {
    command: Vec<String>,
    user: Option<String>,
    #[serde(default)]
    background: bool,
    #[allow(dead_code)]
    description: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FileCfg {
    path: String,
    content: String,
    mode: Option<String>,
    #[serde(default)]
    only_if_missing: bool,
}

/// Hooks and files in v2 apply order: `files/home`, install, `setup.files`, startup,
/// `files/workspace`. Install and startup stay separate lists, so only the files need ordering.
fn lifecycle(
    s: Setup,
    dir: &Path,
    kit: &str,
    warnings: &mut Vec<String>,
) -> Result<Option<Lifecycle>> {
    // v2 defaults: install runs as root, startup as the agent user. Both get the full container
    // environment, as in sbx.
    let install = s.install.into_iter().map(|h| Hook {
        command: HookCmd::Shell(h.command),
        user: Some(h.user.unwrap_or_else(|| "0".into())),
        env: vec![],
        background: false,
        clean_env: false,
    });
    let startup = s.startup.into_iter().map(|h| Hook {
        command: HookCmd::Argv(h.command),
        user: Some(h.user.unwrap_or_else(|| "1000".into())),
        env: vec![],
        background: h.background,
        clean_env: false,
    });
    let mut static_files = |sub: &str, dest: &str| -> Result<Vec<FileReq>> {
        let root = dir.join(sub);
        let mut out = Vec::new();
        if root.is_dir() {
            walk(&root, &root, dest, &mut out, &mut |rel| {
                warnings.push(format!(
                    "warning: kit {kit}: {sub}/{rel} is a symlink; skipped"
                ))
            })?;
        }
        Ok(out)
    };
    let mut files = static_files("files/home", HOME)?;
    files.extend(s.files.into_iter().map(|f| FileReq {
        path: f.path,
        content: f.content.replace("${WORKDIR}", WORKSPACE),
        mode: f.mode,
        overwrite: !f.only_if_missing,
    }));
    files.extend(static_files("files/workspace", WORKSPACE)?);
    let l = Lifecycle {
        install: install.collect(),
        startup: startup.collect(),
        files,
    };
    check_hooks(kit, &l)?;
    let empty = l.install.is_empty() && l.startup.is_empty() && l.files.is_empty();
    Ok((!empty).then_some(l))
}

/// Every file under `root`, in path order, targeted at `dest` plus its relative path. Each
/// skipped symlink's path relative to `root` goes to `symlink`.
fn walk(
    root: &Path,
    dir: &Path,
    dest: &str,
    out: &mut Vec<FileReq>,
    symlink: &mut dyn FnMut(&str),
) -> Result<()> {
    let mut entries = std::fs::read_dir(dir)
        .with_context(|| format!("reading {}", dir.display()))?
        .collect::<std::io::Result<Vec<_>>>()?;
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let p = e.path();
        // Symlinks are skipped: following a directory link can loop forever, and a link could
        // pull in files from outside the kit (sbx rejects `../` traversal for the same reason).
        let ty = e.file_type()?;
        if ty.is_dir() {
            walk(root, &p, dest, out, symlink)?;
            continue;
        }
        let rel = p
            .strip_prefix(root)?
            .components()
            .map(|c| c.as_os_str().to_string_lossy())
            .collect::<Vec<_>>()
            .join("/");
        if ty.is_symlink() {
            symlink(&rel);
            continue;
        }
        if !ty.is_file() {
            continue;
        }
        let content = std::fs::read_to_string(&p)
            .with_context(|| format!("reading {} (static files must be text)", p.display()))?;
        out.push(FileReq {
            path: format!("{dest}/{rel}"),
            content,
            mode: None,
            overwrite: true,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v2_and_its_hand_written_v3_give_the_same_model() {
        let dir = Path::new("tests/fixtures/kits/v2/full");
        let v2 = parse(
            &std::fs::read_to_string(dir.join("spec.yaml")).unwrap(),
            dir,
        )
        .unwrap();
        let v3 = crate::kits::v3::parse(
            &std::fs::read_to_string("tests/fixtures/kits/v2/full-as-v3.yaml").unwrap(),
            Source::LocalV2(dir.into()),
        )
        .unwrap();
        // The one difference: sbx runs v3 install hooks in a clean environment, v2 hooks in the
        // container's.
        let mut v3_caps = v3.caps.clone();
        let mut hooks = 0;
        for (a, b) in v2.caps.iter().zip(&mut v3_caps) {
            if let (CapBody::Lifecycle(a), CapBody::Lifecycle(b)) = (&a.body, &mut b.body) {
                assert!(a.install.iter().chain(&a.startup).all(|h| !h.clean_env));
                for h in &mut b.install {
                    assert!(h.clean_env);
                    h.clean_env = false;
                    hooks += 1;
                }
            }
        }
        assert!(hooks > 0, "the fixture has an install hook");
        assert_eq!(v2.caps, v3_caps);
        assert_eq!(v2.kind, v3.kind);
    }

    #[test]
    fn v1_fields_are_decode_errors_as_in_sbx() {
        let e = parse(
            "schemaVersion: \"2\"\nkind: mixin\nnetwork:\n  allowedDomains: [a.com]\n",
            Path::new("."),
        )
        .unwrap_err();
        assert!(format!("{e:#}").contains("network"), "{e:#}");
    }

    #[test]
    fn name_env_image_and_kind_come_through() {
        let dir = Path::new("tests/fixtures/kits/v2/full");
        let k = parse(
            &std::fs::read_to_string(dir.join("spec.yaml")).unwrap(),
            dir,
        )
        .unwrap();
        assert_eq!(k.name, "full-kit");
        assert_eq!(k.kind, Kind::Workload);
        assert_eq!(k.env, [("TOOL_MODE".to_string(), "fast".to_string())]);
        assert_eq!(
            k.content,
            Content::Image("ghcr.io/example/agent:1.2".into())
        );
    }

    #[test]
    fn a_name_with_control_characters_is_refused() {
        for name in [r#""a\nb""#, r#""a\tb""#, r#""a\\b""#] {
            let e = parse(
                &format!("schemaVersion: \"2\"\nkind: mixin\nname: {name}\n"),
                Path::new("kits/x"),
            )
            .unwrap_err();
            assert!(format!("{e:#}").contains("may only contain"), "{e:#}");
        }
    }

    #[test]
    fn a_nameless_mixin_is_named_after_its_directory() {
        let k = parse(
            "schemaVersion: \"2\"\nkind: mixin\n",
            Path::new("kits/my-tools"),
        )
        .unwrap();
        assert_eq!(k.name, "my-tools");
        assert_eq!(k.kind, Kind::Mixin);
        assert!(k.caps.is_empty() && k.content == Content::None);
    }

    #[test]
    fn unknown_nested_keys_are_errors() {
        let e = parse(
            "schemaVersion: \"2\"\nkind: mixin\nsetup:\n  install:\n    - command: x\n      shell: y\n",
            Path::new("."),
        )
        .unwrap_err();
        assert!(format!("{e:#}").contains("shell"), "{e:#}");
    }

    #[test]
    fn bearer_scheme_expands_to_an_authorization_header() {
        let y = "schemaVersion: \"2\"\nkind: mixin\ncredentials:\n  - service: s\n    apiKey:\n      name: K\n      inject:\n        - domain: a.com\n          scheme: bearer\n";
        let k = parse(y, Path::new(".")).unwrap();
        let CapBody::Credential(c) = &k.caps[0].body else {
            panic!()
        };
        assert!(c.runtime && !c.install);
        assert_eq!(c.inject[0].header.as_deref(), Some("Authorization"));
        assert_eq!(c.inject[0].format.as_deref(), Some("Bearer %s"));
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_under_files_are_skipped_so_cycles_end() {
        let d = tempfile::tempdir().unwrap();
        let home = d.path().join("files/home");
        std::fs::create_dir_all(home.join("sub")).unwrap();
        std::fs::write(home.join("sub/a.txt"), "a").unwrap();
        std::os::unix::fs::symlink(&home, home.join("sub/loop")).unwrap();
        std::os::unix::fs::symlink(home.join("sub/a.txt"), home.join("link.txt")).unwrap();
        let (k, warnings) = parse_warn("schemaVersion: \"2\"\nkind: mixin\n", d.path()).unwrap();
        let CapBody::Lifecycle(l) = &k.caps[0].body else {
            panic!()
        };
        let paths: Vec<_> = l.files.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(paths, ["/home/agent/sub/a.txt"]);
        let name = k.name;
        assert_eq!(
            warnings,
            [
                format!("warning: kit {name}: files/home/link.txt is a symlink; skipped"),
                format!("warning: kit {name}: files/home/sub/loop is a symlink; skipped"),
            ]
        );
    }

    #[test]
    fn empty_agent_instructions_add_no_capability() {
        for body in [
            "",
            "agentInstructions:\n  filename: X.md\n",
            "agentInstructions:\n  content: \"  \"\n",
        ] {
            let yaml = format!("schemaVersion: \"2\"\nkind: mixin\nname: m\n{body}");
            let k = parse(&yaml, Path::new("/nonexistent")).unwrap();
            assert!(k.caps.is_empty(), "{body}: {:?}", k.caps);
        }
    }

    #[test]
    fn ignored_fields_warn_once_each() {
        let yaml = "schemaVersion: \"2\"\nkind: mixin\nname: m\nsandbox:\n  build: {context: .}\n  \
                    entrypoint: [a]\n  command: [b]\n  resources:\n    gpu: all\n";
        let (k, warnings) = parse_warn(yaml, Path::new("/nonexistent")).unwrap();
        assert_eq!(k.command, None);
        assert_eq!(
            warnings,
            [
                "warning: kit m: sandbox.build is ignored",
                "warning: kit m: sandbox.resources.gpu is ignored",
                "warning: kit m: sandbox.entrypoint is ignored",
                "warning: kit m: sandbox.command is ignored",
            ]
        );
        // A workload's command runs.
        let yaml = yaml.replace("kind: mixin", "kind: sandbox");
        let (k, warnings) = parse_warn(&yaml, Path::new("/nonexistent")).unwrap();
        assert_eq!(k.command, Some(vec!["a".to_string(), "b".to_string()]));
        assert_eq!(warnings.len(), 2, "{warnings:?}");
    }

    #[test]
    fn unquoted_numbers_and_bools_in_default_and_enum_become_strings() {
        let yaml = "schemaVersion: \"2\"\nkind: mixin\nname: m\nargs:\n  a:\n    default: 5\n    \
                    enum: [5, true, x]\n";
        let k = parse(yaml, Path::new("/nonexistent")).unwrap();
        assert_eq!(k.args["a"].default.as_deref(), Some("5"));
        assert_eq!(k.args["a"].enum_values, ["5", "true", "x"]);
    }

    #[test]
    fn an_empty_hook_command_is_an_error() {
        for (setup, want) in [
            (
                "install:\n    - command: \" \"\n",
                "kit m: install hook 1 has an empty command",
            ),
            (
                "install:\n    - command: ok\n    - command: \"\"\n",
                "kit m: install hook 2 has an empty command",
            ),
            (
                "startup:\n    - command: []\n",
                "kit m: startup hook 1 has an empty command",
            ),
        ] {
            let yaml = format!("schemaVersion: \"2\"\nkind: mixin\nname: m\nsetup:\n  {setup}");
            let e = parse(&yaml, Path::new("/nonexistent")).unwrap_err();
            assert_eq!(format!("{e:#}"), want);
        }
    }

    #[test]
    fn a_mixin_agent_instructions_filename_warns() {
        let y = "schemaVersion: \"2\"\nkind: mixin\nname: m\nagentInstructions:\n  filename: X.md\n  \
                 content: hi\n";
        let (_, w) = parse_warn(y, Path::new("/nonexistent")).unwrap();
        assert_eq!(
            w,
            [
                "warning: kit m: agentInstructions.filename is only used for kind \"sandbox\", not \"mixin\""
            ]
        );
        let y = y
            .replace("mixin", "sandbox")
            .replace("name: m", "name: m\nsandbox:\n  image: a:1");
        let (_, w) = parse_warn(&y, Path::new("/nonexistent")).unwrap();
        assert!(w.is_empty(), "{w:?}");
    }
}
