//! Kit v3 descriptor parser (docker/sandbox-kit-spec SPEC-v3, `spec/types.go`).
//!
//! Well-known capability configs reject unknown keys, so a typo like `sise` fails loudly instead
//! of silently dropping a limit. The top level and unknown capability types stay lenient.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};
use serde::Deserialize;
use serde_json::Value;

use crate::kits::model::*;

const NS: &str = "com.docker.sandbox/";

/// Parses a YAML descriptor. YAML goes through `serde_json::Value` so it shares one path with the
/// JSON form carried in manifest annotations.
pub fn parse(yaml: &str, source: Source) -> Result<Kit> {
    let v: Value = serde_saphyr::from_str(yaml).context("reading the kit descriptor")?;
    from_value(v, source)
}

pub fn parse_json(json: &str, source: Source) -> Result<Kit> {
    from_value(
        serde_json::from_str(json).context("reading the kit descriptor")?,
        source,
    )
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Descriptor {
    schema_version: String,
    kind: String,
    #[serde(default)]
    provides: Vec<String>,
    #[serde(default)]
    requires: Vec<String>,
    #[serde(default)]
    capabilities: Vec<CapabilityItem>,
    #[serde(default)]
    args: BTreeMap<String, Arg>,
}

#[derive(Deserialize)]
struct CapabilityItem {
    #[serde(default, rename = "type")]
    ty: String,
    #[serde(default)]
    optional: bool,
    #[serde(default)]
    config: Option<Value>,
}

// Lenient like the descriptor's top level: an unknown arg key is ignored.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Arg {
    default: Option<String>,
    #[serde(default)]
    required: bool,
    pattern: Option<String>,
    #[serde(default, rename = "enum")]
    enum_values: Vec<String>,
    env: Option<String>,
    // Build-time only; accepted so published descriptors parse.
    #[allow(dead_code)]
    description: Option<String>,
    #[allow(dead_code)]
    build_arg: Option<String>,
}

fn from_value(v: Value, source: Source) -> Result<Kit> {
    let d: Descriptor = serde_json::from_value(v).context("reading the kit descriptor")?;
    if d.schema_version != "3" {
        bail!("schemaVersion must be \"3\" (got {:?})", d.schema_version);
    }
    let kind = match d.kind.as_str() {
        "workload" | "sandbox" => Kind::Workload,
        "mixin" => Kind::Mixin,
        "set" => bail!("kind: set must be published (docker buildx build) before it can be run"),
        k => bail!("unknown kind '{k}'"),
    };
    let caps = d
        .capabilities
        .into_iter()
        .enumerate()
        .map(|(i, c)| {
            if c.ty.trim().is_empty() {
                bail!("capability {i} has no type");
            }
            cap(c)
        })
        .collect::<Result<Vec<_>>>()?;
    let args = d
        .args
        .into_iter()
        .map(|(name, a)| {
            let def = ArgDef {
                default: a.default,
                required: a.required,
                pattern: a.pattern,
                enum_values: a.enum_values,
                env: a.env,
            };
            (name, def)
        })
        .collect();
    let name = name_from_source(&source)?;
    Ok(Kit {
        name,
        source,
        digest: None,
        kind,
        provides: d.provides,
        requires: d.requires,
        args,
        caps,
        env: vec![],
        content: Content::None,
        command: None,
        config: None,
    })
}

/// A short token naming the kit: it scopes `--kit-arg` and tags policy rule origins, so it comes
/// from the source, never from the free-text `displayName`.
pub(crate) fn name_from_source(source: &Source) -> Result<String> {
    check_name(raw_name(source))
}

/// Kit names land in guest scripts, file names, markers and the tab-separated kits record.
pub(crate) fn check_name(name: String) -> Result<String> {
    let ok = |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-');
    if name.is_empty() || !name.chars().all(ok) {
        bail!("kit name '{name}' may only contain letters, digits, '.', '_' and '-'");
    }
    Ok(name)
}

fn raw_name(source: &Source) -> String {
    match source {
        Source::Registry(r) | Source::Preset(r) => {
            let last = r.rsplit('/').next().unwrap_or(r);
            let last = last.split('@').next().unwrap_or(last);
            last.split(':').next().unwrap_or(last).to_string()
        }
        Source::Builtin(n) => n.to_string(),
        Source::LocalV3(p) | Source::LocalV2(p) => path_name(p),
        Source::Smolfile(p) => {
            if p.file_name().is_some_and(|n| n == "Smolfile")
                && let Some(n) = project_dir_name(p)
            {
                return n;
            }
            path_name(p)
        }
    }
}

/// Name of the directory holding `p`. A bare or `./` path has a parent with no name of its own,
/// so that case resolves the parent against the filesystem.
fn project_dir_name(p: &Path) -> Option<String> {
    let parent = p.parent()?;
    let name = |d: &Path| Some(d.file_name()?.to_str()?.to_string());
    if let Some(n) = name(parent) {
        return Some(n);
    }
    let parent = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };
    let dir = std::fs::canonicalize(parent)
        .or_else(|_| std::env::current_dir())
        .ok()?;
    name(&dir)
}

/// Directory basename, or the file stem when the path is a file.
fn path_name(p: &Path) -> String {
    let part = if p.is_dir() {
        p.file_name()
    } else {
        p.file_stem()
    };
    part.and_then(|n| n.to_str()).unwrap_or("kit").to_string()
}

fn cap(item: CapabilityItem) -> Result<Cap> {
    let body = body(&item.ty, item.config).with_context(|| format!("capability {}", item.ty))?;
    Ok(Cap {
        ty: item.ty,
        optional: item.optional,
        body,
    })
}

/// Decodes a known config type, rejecting unknown keys (the structs carry `deny_unknown_fields`).
fn decode<T: serde::de::DeserializeOwned>(config: Option<Value>) -> Result<T> {
    let v = config.unwrap_or_else(|| Value::Object(Default::default()));
    serde_json::from_value(v).map_err(|e| anyhow!("{e}"))
}

fn no_config(config: Option<Value>) -> Result<()> {
    if config.is_some_and(|c| !c.is_null()) {
        bail!("takes no config");
    }
    Ok(())
}

fn body(ty: &str, config: Option<Value>) -> Result<CapBody> {
    let Some(name) = ty.strip_prefix(NS) else {
        return Ok(CapBody::Unsupported);
    };
    Ok(match name {
        "network-policy@1" => {
            let c: NetworkV1 = decode(config)?;
            CapBody::Network {
                install: c.install.unwrap_or_default().into_rules(),
                runtime: c.runtime.unwrap_or_default().into_rules(),
            }
        }
        "network-policy@2" => {
            let c: NetworkV2 = decode(config)?;
            CapBody::Network {
                install: c.install.unwrap_or_default().into_rules(),
                runtime: c.runtime.unwrap_or_default().into_rules(),
            }
        }
        "credential@1" => CapBody::Credential(credential(decode(config)?)?),
        "port@1" => {
            let c: PortCfg = decode(config)?;
            if c.container == 0 {
                bail!("container must be 1..65535");
            }
            let udp = match c.transport.as_deref() {
                None | Some("") | Some("tcp") => false,
                Some("udp") => true,
                Some(t) => bail!("transport must be tcp or udp (got {t:?})"),
            };
            CapBody::Port {
                container: c.container,
                udp,
            }
        }
        "volume@1" => {
            let c: VolumeCfg = decode(config)?;
            CapBody::Volume {
                path: c.path,
                tmpfs: c.tmpfs,
                mode: c.mode,
            }
        }
        "resources@1" => {
            let c: ResourcesCfg = decode(config)?;
            CapBody::Resources {
                cpus: c.cpu.map(|n| n.to_string()),
                memory: c.memory,
            }
        }
        "lifecycle@1" => CapBody::Lifecycle(lifecycle(decode(config)?)),
        "agent-context@1" => {
            let c: AgentContextV1 = decode(config)?;
            let content = match (c.content, c.content_file) {
                (Some(_), Some(_)) => bail!("content and contentFile are mutually exclusive"),
                (Some(c), None) => c,
                // The body is staged in the kit image; later code reads it from there.
                (None, Some(f)) => format!("file:{f}"),
                (None, None) => String::new(),
            };
            CapBody::AgentContext(AgentContextReq {
                filename: c.filename,
                directory: c.directory,
                content,
            })
        }
        "agent-context@2" => {
            let c: AgentContextV2 = decode(config)?;
            CapBody::AgentContext(AgentContextReq {
                filename: c.filename,
                directory: c.directory,
                content: c.content.unwrap_or_default(),
            })
        }
        "sbx@1" => {
            no_config(config)?;
            CapBody::Sbx
        }
        "git-identity@1" => {
            no_config(config)?;
            CapBody::GitIdentity
        }
        "long-running@1" => {
            no_config(config)?;
            CapBody::LongRunning
        }
        "privileged@1" => {
            no_config(config)?;
            CapBody::Privileged
        }
        // Its command templates matter to the agent launcher, not to the kit model.
        "agent-sessions@1" => CapBody::AgentSessions,
        // host-mount, ssh-agent, agent-skills, agent-skill, usb-device, kit-registry,
        // agent-interactive-sessions, acp and anything unknown.
        _ => CapBody::Unsupported,
    })
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct NetworkV1 {
    install: Option<RulesV1>,
    runtime: Option<RulesV1>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RulesV1 {
    #[serde(default)]
    allow: Vec<String>,
    #[serde(default)]
    deny: Vec<String>,
}

impl RulesV1 {
    fn into_rules(self) -> Rules {
        let rule = |host| NetRule {
            host,
            methods: vec![],
            paths: vec![],
        };
        Rules {
            allow: self.allow.into_iter().map(rule).collect(),
            deny: self.deny.into_iter().map(rule).collect(),
        }
    }
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct NetworkV2 {
    install: Option<RulesV2>,
    runtime: Option<RulesV2>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RulesV2 {
    #[serde(default)]
    allow: Vec<EntryV2>,
    #[serde(default)]
    deny: Vec<EntryV2>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EntryV2 {
    hosts: Vec<String>,
    #[serde(default)]
    methods: Vec<String>,
    #[serde(default)]
    paths: Vec<String>,
}

impl RulesV2 {
    fn into_rules(self) -> Rules {
        // One rule per host, each carrying the entry's methods and paths.
        let flat = |entries: Vec<EntryV2>| {
            entries
                .into_iter()
                .flat_map(|e| {
                    let (methods, paths) = (e.methods, e.paths);
                    e.hosts.into_iter().map(move |host| NetRule {
                        host,
                        methods: methods.clone(),
                        paths: paths.clone(),
                    })
                })
                .collect()
        };
        Rules {
            allow: flat(self.allow),
            deny: flat(self.deny),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CredCfg {
    service: String,
    phase: OneOrMany,
    #[serde(rename = "apiKey")]
    api_key: Option<ApiKeyCfg>,
    oauth: Option<OAuthCfg>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum OneOrMany {
    One(String),
    Many(Vec<String>),
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
    // `scheme: basic` is implied by a username; the scheme string itself is not kept.
    #[allow(dead_code)]
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
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenEndpoint {
    host: String,
    #[allow(dead_code)]
    path: Option<String>,
}

fn credential(c: CredCfg) -> Result<CredReq> {
    if c.api_key.is_none() && c.oauth.is_none() {
        bail!("one of apiKey or oauth is required");
    }
    let phases = match c.phase {
        OneOrMany::One(p) => vec![p],
        OneOrMany::Many(p) => p,
    };
    let (mut install, mut runtime) = (false, false);
    for p in &phases {
        match p.as_str() {
            "install" => install = true,
            "runtime" => runtime = true,
            other => bail!("phase must be install or runtime (got {other:?})"),
        }
    }
    if !install && !runtime {
        bail!("phase must name install, runtime or both");
    }
    let (env, inject) = match c.api_key {
        Some(k) => {
            let inject = k
                .inject
                .into_iter()
                .map(|i| Inject {
                    domain: i.domain,
                    header: i.header,
                    format: i.format,
                    basic_user: i.username,
                })
                .collect();
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
        install,
        runtime,
        env,
        inject,
        oauth,
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PortCfg {
    // Labels and the address family describe the service; the model does not need them.
    #[allow(dead_code)]
    name: Option<String>,
    container: u16,
    transport: Option<String>,
    #[allow(dead_code)]
    family: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VolumeCfg {
    path: String,
    // smolvm volumes are not sized per mount.
    #[allow(dead_code)]
    size: Option<String>,
    #[serde(default)]
    tmpfs: bool,
    mode: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResourcesCfg {
    cpu: Option<f64>,
    memory: Option<String>,
    #[allow(dead_code)]
    gpu: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AgentContextV1 {
    filename: Option<String>,
    directory: Option<String>,
    content: Option<String>,
    content_file: Option<String>,
}

// `contentFile` is rejected here by `deny_unknown_fields`, as the spec requires.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentContextV2 {
    filename: Option<String>,
    directory: Option<String>,
    content: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct LifecycleCfg {
    #[serde(default)]
    install: Vec<HookCfg>,
    #[serde(default)]
    startup: Vec<HookCfg>,
    #[serde(default)]
    files: Vec<FileCfg>,
    // The launch-argv tail for interactive sessions belongs to the agent launcher.
    #[allow(dead_code)]
    interactive: Option<Vec<String>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HookCfg {
    command: CommandCfg,
    user: Option<String>,
    #[serde(default)]
    env: Vec<String>,
    // Meaningful for startup hooks only.
    background: Option<bool>,
    #[allow(dead_code)]
    description: Option<String>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum CommandCfg {
    Shell(String),
    Argv(Vec<String>),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileCfg {
    path: String,
    content: String,
    mode: Option<String>,
    overwrite: Option<bool>,
    #[allow(dead_code)]
    description: Option<String>,
}

fn lifecycle(c: LifecycleCfg) -> Lifecycle {
    let hook = |h: HookCfg| Hook {
        command: match h.command {
            CommandCfg::Shell(s) => HookCmd::Shell(s),
            CommandCfg::Argv(a) => HookCmd::Argv(a),
        },
        user: h.user,
        env: h.env,
        background: h.background.unwrap_or(false),
    };
    Lifecycle {
        install: c.install.into_iter().map(hook).collect(),
        startup: c.startup.into_iter().map(hook).collect(),
        files: c
            .files
            .into_iter()
            .map(|f| FileReq {
                path: f.path,
                content: f.content,
                mode: f.mode,
                // The spec defaults to overwriting.
                overwrite: f.overwrite.unwrap_or(true),
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> String {
        std::fs::read_to_string(format!("tests/fixtures/kits/v3/{name}")).unwrap()
    }
    fn local(name: &str) -> Source {
        Source::LocalV3(name.into())
    }

    #[test]
    fn parses_network_v2_phases() {
        let k = parse(&fixture("network-v2.yaml"), local("n")).unwrap();
        assert_eq!(k.kind, Kind::Mixin);
        assert_eq!(k.provides, ["net2"]);
        let CapBody::Network { install, runtime } = &k.caps[0].body else {
            panic!()
        };
        assert_eq!(install.allow[0].host, "registry.npmjs.org");
        assert_eq!(runtime.allow[0].methods, ["GET"]);
        assert_eq!(runtime.deny[0].host, "telemetry.example.com");
    }

    #[test]
    fn unknown_types_parse_as_unsupported_keeping_optional() {
        let k = parse(&fixture("unknown-cap.yaml"), local("u")).unwrap();
        assert!(matches!(k.caps[0].body, CapBody::Unsupported));
        assert!(!k.caps[0].optional);
        assert!(k.caps[1].optional);
    }

    #[test]
    fn unknown_config_keys_of_known_types_are_errors() {
        let e = parse(&fixture("bad-config-key.yaml"), local("b")).unwrap_err();
        assert!(format!("{e:#}").contains("sise"), "{e:#}");
    }

    #[test]
    fn schema_version_must_be_3_and_set_is_refused_locally() {
        let e = parse("schemaVersion: \"2\"\nkind: mixin\n", local("x")).unwrap_err();
        assert!(format!("{e:#}").contains("schemaVersion"));
        let e = parse("schemaVersion: \"3\"\nkind: set\n", local("x")).unwrap_err();
        assert!(format!("{e:#}").contains("publish"), "{e:#}");
    }

    #[test]
    fn an_unknown_kind_is_an_error() {
        let e = parse("schemaVersion: \"3\"\nkind: plugin\n", local("x")).unwrap_err();
        assert_eq!(format!("{e:#}"), "unknown kind 'plugin'");
    }

    #[test]
    fn a_capability_without_a_type_is_an_error_naming_its_index() {
        for ty in [r#""#, r#""type":"","#] {
            let e = parse_json(
                &format!(
                    r#"{{"schemaVersion":"3","kind":"mixin","capabilities":[
                        {{"type":"com.docker.sandbox/sbx@1"}},{{{ty}"optional":true}}]}}"#
                ),
                local("t"),
            )
            .unwrap_err();
            assert_eq!(format!("{e:#}"), "capability 1 has no type");
        }
    }

    #[test]
    fn unknown_arg_keys_are_ignored() {
        let k = parse(
            "schemaVersion: \"3\"\nkind: mixin\nargs:\n  a:\n    default: x\n    later: 1\n",
            local("x"),
        )
        .unwrap();
        assert_eq!(k.args["a"].default.as_deref(), Some("x"));
    }

    #[test]
    fn a_port_of_zero_and_content_with_content_file_are_errors() {
        let e = one_cap(r#"{"type":"com.docker.sandbox/port@1","config":{"container":0}}"#)
            .unwrap_err();
        assert!(
            format!("{e:#}").contains("container must be 1..65535"),
            "{e:#}"
        );
        let e = one_cap(
            r#"{"type":"com.docker.sandbox/agent-context@1",
                "config":{"content":"x","contentFile":"/k/x.md"}}"#,
        )
        .unwrap_err();
        assert!(
            format!("{e:#}").contains("content and contentFile are mutually exclusive"),
            "{e:#}"
        );
    }

    #[test]
    fn sandbox_is_the_old_spelling_of_workload() {
        let k = parse_json(
            r#"{"schemaVersion":"3","kind":"sandbox"}"#,
            Source::Registry("r/k:1".into()),
        )
        .unwrap();
        assert_eq!(k.kind, Kind::Workload);
    }

    #[test]
    fn upstream_claude_mixin_parses() {
        parse(&fixture("claude-mixin.yaml"), local("c")).unwrap();
    }

    #[test]
    fn claude_mixin_capabilities_decode() {
        let k = parse(&fixture("claude-mixin.yaml"), local("c")).unwrap();
        assert_eq!(k.name, "c");
        assert_eq!(k.provides, ["claude@${{ kit.args.version }}"]);
        assert_eq!(k.args["version"].default.as_deref(), Some("2.1.311"));
        assert_eq!(k.args["reasoningEffort"].enum_values.len(), 7);
        assert_eq!(k.args["model"].env.as_deref(), Some("CLAUDE_MODEL"));

        let cred = k
            .caps
            .iter()
            .find_map(|c| match &c.body {
                CapBody::Credential(c) => Some(c.clone()),
                _ => None,
            })
            .unwrap();
        assert_eq!(cred.service, "anthropic");
        assert!(cred.runtime && !cred.install);
        assert_eq!(cred.env.as_deref(), Some("ANTHROPIC_API_KEY"));
        assert_eq!(cred.inject[0].header.as_deref(), Some("x-api-key"));
        let oauth = cred.oauth.unwrap();
        assert_eq!(oauth.token_host.as_deref(), Some("platform.claude.com"));
        assert!(!oauth.passthrough);

        let vols = k
            .caps
            .iter()
            .filter(|c| matches!(c.body, CapBody::Volume { .. }))
            .count();
        assert_eq!(vols, 5);

        let CapBody::Lifecycle(l) = &k
            .caps
            .iter()
            .find(|c| c.ty.ends_with("lifecycle@1"))
            .unwrap()
            .body
        else {
            panic!()
        };
        assert_eq!(l.install.len(), 4);
        assert_eq!(l.install[0].user.as_deref(), Some("0"));
        assert_eq!(l.install[0].env, ["WORKSPACE_DIR"]);
        assert!(matches!(l.install[0].command, HookCmd::Shell(_)));
        assert!(matches!(l.startup[0].command, HookCmd::Argv(_)));

        // agent-skills is unsupported but its optional flag survives.
        let skills = k
            .caps
            .iter()
            .find(|c| c.ty.ends_with("agent-skills@1"))
            .unwrap();
        assert!(matches!(skills.body, CapBody::Unsupported) && skills.optional);

        let ctx: Vec<_> = k
            .caps
            .iter()
            .filter_map(|c| match &c.body {
                CapBody::AgentContext(a) => Some(a),
                _ => None,
            })
            .collect();
        assert_eq!(ctx.len(), 2);
        assert_eq!(ctx[0], ctx[1]);
        assert_eq!(ctx[0].filename.as_deref(), Some("CLAUDE.md"));
        assert_eq!(ctx[0].directory.as_deref(), Some("/home/agent/.claude"));
        assert!(ctx[0].content.starts_with("Claude Code is installed"));
    }

    #[test]
    fn shell_workload_parses() {
        let k = parse(&fixture("shell-workload.yaml"), local("s")).unwrap();
        assert_eq!(k.kind, Kind::Workload);
        assert!(matches!(k.caps[0].body, CapBody::Sbx));
        let CapBody::Network { install, runtime } = &k.caps[1].body else {
            panic!()
        };
        assert!(install.allow.is_empty());
        assert_eq!(runtime.allow[1].host, "dhi.io");
    }

    #[test]
    fn network_v1_entries_are_plain_hosts_and_may_carry_ports() {
        let k = parse_json(
            r#"{"schemaVersion":"3","kind":"mixin","capabilities":[
                {"type":"com.docker.sandbox/network-policy@1",
                 "config":{"runtime":{"allow":["a.com:443"],"deny":["b.com"]}}}]}"#,
            local("n"),
        )
        .unwrap();
        let CapBody::Network { runtime, .. } = &k.caps[0].body else {
            panic!()
        };
        assert_eq!(runtime.allow[0].host, "a.com:443");
        assert!(runtime.allow[0].methods.is_empty());
        assert_eq!(runtime.deny[0].host, "b.com");
    }

    #[test]
    fn network_v2_entry_fans_out_per_host() {
        let k = parse_json(
            r#"{"schemaVersion":"3","kind":"mixin","capabilities":[
                {"type":"com.docker.sandbox/network-policy@2",
                 "config":{"runtime":{"allow":[{"hosts":["a","b"],"methods":["GET"]}]}}}]}"#,
            local("n"),
        )
        .unwrap();
        let CapBody::Network { runtime, .. } = &k.caps[0].body else {
            panic!()
        };
        assert_eq!(runtime.allow.len(), 2);
        assert_eq!(runtime.allow[1].host, "b");
        assert_eq!(runtime.allow[1].methods, ["GET"]);
    }

    fn one_cap(json_cap: &str) -> Result<Kit> {
        parse_json(
            &format!(r#"{{"schemaVersion":"3","kind":"mixin","capabilities":[{json_cap}]}}"#),
            local("t"),
        )
    }

    #[test]
    fn port_resources_and_agent_context_variants() {
        let k = one_cap(
            r#"{"type":"com.docker.sandbox/port@1","config":{"container":53,"transport":"udp"}}"#,
        )
        .unwrap();
        assert!(matches!(
            k.caps[0].body,
            CapBody::Port {
                container: 53,
                udp: true
            }
        ));

        let k = one_cap(
            r#"{"type":"com.docker.sandbox/resources@1","config":{"cpu":2.5,"memory":"4g"}}"#,
        )
        .unwrap();
        assert_eq!(
            k.caps[0].body,
            CapBody::Resources {
                cpus: Some("2.5".into()),
                memory: Some("4g".into())
            }
        );

        let k = one_cap(
            r#"{"type":"com.docker.sandbox/agent-context@1","config":{"contentFile":"/usr/share/sandbox/kit/x/ctx.md"}}"#,
        )
        .unwrap();
        let CapBody::AgentContext(a) = &k.caps[0].body else {
            panic!()
        };
        assert_eq!(a.content, "file:/usr/share/sandbox/kit/x/ctx.md");

        let e = one_cap(
            r#"{"type":"com.docker.sandbox/agent-context@2","config":{"contentFile":"x"}}"#,
        )
        .unwrap_err();
        assert!(format!("{e:#}").contains("contentFile"), "{e:#}");
    }

    #[test]
    fn config_less_capabilities_reject_config_and_files_default_to_overwrite() {
        let e = one_cap(r#"{"type":"com.docker.sandbox/sbx@1","config":{"a":1}}"#).unwrap_err();
        assert!(format!("{e:#}").contains("no config"), "{e:#}");

        let k = one_cap(
            r#"{"type":"com.docker.sandbox/lifecycle@1","config":{"files":[{"path":"/a","content":"x"}],
                "startup":[{"command":"sleep 1","background":true}]}}"#,
        )
        .unwrap();
        let CapBody::Lifecycle(l) = &k.caps[0].body else {
            panic!()
        };
        assert!(l.files[0].overwrite);
        assert!(l.startup[0].background);
    }

    #[test]
    fn credential_phase_list_and_validation() {
        let k = one_cap(
            r#"{"type":"com.docker.sandbox/credential@1","config":{"service":"github",
                "phase":["install","runtime"],
                "apiKey":{"name":"GH_TOKEN","inject":[{"domain":"github.com","scheme":"basic","username":"x-access-token"}]}}}"#,
        )
        .unwrap();
        let CapBody::Credential(c) = &k.caps[0].body else {
            panic!()
        };
        assert!(c.install && c.runtime);
        assert_eq!(c.inject[0].basic_user.as_deref(), Some("x-access-token"));

        let e = one_cap(r#"{"type":"com.docker.sandbox/credential@1","config":{"service":"s","phase":"runtime"}}"#)
            .unwrap_err();
        assert!(format!("{e:#}").contains("apiKey"), "{e:#}");
    }

    #[test]
    fn kit_names_are_restricted() {
        assert_eq!(check_name("my-kit_1.0".into()).unwrap(), "my-kit_1.0");
        for bad in ["", "a\nb", "a\tb", "a\\b", "a b", "a;b"] {
            let e = check_name(bad.into()).unwrap_err();
            assert_eq!(
                e.to_string(),
                format!("kit name '{bad}' may only contain letters, digits, '.', '_' and '-'")
            );
        }
        let e = name_from_source(&Source::LocalV3("/k/bad\nname".into())).unwrap_err();
        assert!(e.to_string().contains("may only contain"), "{e}");
    }

    #[test]
    fn name_comes_from_the_source_not_display_name() {
        let json = r#"{"schemaVersion":"3","kind":"mixin","displayName":"Fancy Name"}"#;
        let name = |src| parse_json(json, src).unwrap().name;
        assert_eq!(
            name(Source::Registry(
                "docker.io/acme/sbx-kit-team:1.0@sha256:abc".into()
            )),
            "sbx-kit-team"
        );
        assert_eq!(
            name(Source::Registry("ghcr.io/acme/tool:1.2".into())),
            "tool"
        );
        assert_eq!(name(Source::LocalV3("kits/dev.yaml".into())), "dev");
        let dir = tempfile::tempdir().unwrap();
        let kit_dir = dir.path().join("my-kit");
        std::fs::create_dir(&kit_dir).unwrap();
        assert_eq!(name(Source::LocalV3(kit_dir)), "my-kit");
        assert_eq!(name(Source::Smolfile("proj/Smolfile".into())), "proj");
        assert_eq!(name(Source::Registry("localhost:5000/kit:1".into())), "kit");
        let digest = format!("acme/kit@sha256:{}", "ab".repeat(32));
        assert_eq!(name(Source::Registry(digest)), "kit");

        // Relative paths: the parent has no name of its own, so it is resolved on disk.
        let cwd = std::env::current_dir().unwrap();
        let cwd_name = cwd.file_name().unwrap().to_str().unwrap().to_string();
        assert_eq!(name(Source::Smolfile("Smolfile".into())), cwd_name);
        assert_eq!(name(Source::Smolfile("./Smolfile".into())), cwd_name);
        let root = dir.path().canonicalize().unwrap();
        std::fs::create_dir(root.join("sub")).unwrap();
        let via_dotdot = root.join("sub").join("..").join("Smolfile");
        let want = root.file_name().unwrap().to_str().unwrap();
        assert_eq!(name(Source::Smolfile(via_dotdot)), want);
        assert_eq!(name(Source::Smolfile("proj/dev.smolfile".into())), "dev");
    }
}
