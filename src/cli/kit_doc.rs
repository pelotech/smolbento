//! `kit inspect` output: sbx's table, and its `--format json|yaml` document.
//!
//! sbx prints a v2-shaped descriptor (`schemaVersion` "2", kind `sandbox` or `mixin`) for every
//! kit, v3 included; `Doc` is that shape, built from the format-neutral model.

use std::collections::BTreeMap;

use anyhow::Result;
use serde::Serialize;
use serde_json::Value;

use crate::kits::model::{CapBody, Content, HookCmd, Kind, Kit, Source};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Doc {
    schema_version: &'static str,
    kind: &'static str,
    name: String,
    sandbox: Sandbox,
    permissions: Permissions,
    credentials: Vec<Cred>,
    setup: Setup,
    /// What sbx's descriptor has no place for; sbx's own keys stay as they are.
    smolbento: Extras,
}

#[derive(Serialize, Default)]
struct Extras {
    source: String,
    #[serde(rename = "sourceType")]
    source_type: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    digest: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    provides: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    requires: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    integrates: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    conflicts: Vec<String>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    args: BTreeMap<String, Arg>,
}

#[derive(Serialize)]
struct Arg {
    required: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    default: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pattern: Option<String>,
    #[serde(rename = "enum", skip_serializing_if = "Vec::is_empty")]
    enum_values: Vec<String>,
}

#[derive(Serialize, Default)]
struct Sandbox {
    #[serde(skip_serializing_if = "Option::is_none")]
    image: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    command: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resources: Option<Resources>,
}

#[derive(Serialize)]
struct Resources {
    #[serde(skip_serializing_if = "Option::is_none")]
    cpu: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    memory: Option<String>,
}

#[derive(Serialize, Default)]
struct Permissions {
    #[serde(skip_serializing_if = "Option::is_none")]
    network: Option<Network>,
}

#[derive(Serialize, Default)]
struct Network {
    allow: Vec<String>,
    deny: Vec<String>,
}

#[derive(Serialize)]
struct Cred {
    service: String,
    #[serde(rename = "apiKey", skip_serializing_if = "Option::is_none")]
    api_key: Option<ApiKey>,
    #[serde(skip_serializing_if = "Option::is_none")]
    oauth: Option<OAuth>,
}

#[derive(Serialize)]
struct ApiKey {
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    inject: Vec<Inject>,
}

#[derive(Serialize)]
struct Inject {
    domain: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    header: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    format: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<String>,
}

#[derive(Serialize)]
struct OAuth {
    #[serde(rename = "tokenEndpoint", skip_serializing_if = "Option::is_none")]
    token_endpoint: Option<TokenEndpoint>,
    #[serde(rename = "resourceHosts")]
    resource_hosts: Vec<String>,
    passthrough: bool,
}

#[derive(Serialize)]
struct TokenEndpoint {
    host: String,
}

#[derive(Serialize, Default)]
struct Setup {
    install: Vec<Hook>,
    startup: Vec<Hook>,
    files: Vec<File>,
}

#[derive(Serialize)]
struct Hook {
    command: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    user: Option<String>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    background: bool,
}

#[derive(Serialize)]
struct File {
    path: String,
    content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    mode: Option<String>,
    #[serde(rename = "onlyIfMissing", skip_serializing_if = "std::ops::Not::not")]
    only_if_missing: bool,
}

impl Doc {
    pub fn new(kit: &Kit) -> Doc {
        let mut sandbox = Sandbox {
            image: match &kit.content {
                Content::Image(i) if !i.is_empty() => Some(i.clone()),
                _ => None,
            },
            command: kit.command.clone(),
            resources: None,
        };
        let mut net: Option<Network> = None;
        let mut credentials = Vec::new();
        let mut setup = Setup::default();
        for c in &kit.caps {
            match &c.body {
                CapBody::Resources { cpus, memory } => {
                    let cpu = cpus.as_ref().map(|c| {
                        c.parse::<u64>()
                            .map(Value::from)
                            .or_else(|_| c.parse::<f64>().map(Value::from))
                            .unwrap_or_else(|_| Value::from(c.clone()))
                    });
                    sandbox.resources = Some(Resources {
                        cpu,
                        memory: memory.clone(),
                    });
                }
                CapBody::Network { install, runtime } => {
                    let n = net.get_or_insert_with(Network::default);
                    for (to, rules) in [
                        (&mut n.allow, [&install.allow, &runtime.allow]),
                        (&mut n.deny, [&install.deny, &runtime.deny]),
                    ] {
                        for r in rules.into_iter().flatten() {
                            if !to.contains(&r.host) {
                                to.push(r.host.clone());
                            }
                        }
                    }
                }
                CapBody::Credential(r) => credentials.push(Cred {
                    service: r.service.clone(),
                    api_key: (r.env.is_some() || !r.inject.is_empty()).then(|| ApiKey {
                        name: r.env.clone(),
                        inject: r
                            .inject
                            .iter()
                            .map(|i| Inject {
                                domain: i.domain.clone(),
                                header: i.header.clone(),
                                format: i.format.clone(),
                                username: i.basic_user.clone(),
                            })
                            .collect(),
                    }),
                    oauth: r.oauth.as_ref().map(|o| OAuth {
                        token_endpoint: o.token_host.clone().map(|host| TokenEndpoint { host }),
                        resource_hosts: o.resource_hosts.clone(),
                        passthrough: o.passthrough,
                    }),
                }),
                CapBody::Lifecycle(l) => {
                    let hook = |h: &crate::kits::model::Hook| Hook {
                        command: match &h.command {
                            HookCmd::Shell(s) => Value::from(s.clone()),
                            HookCmd::Argv(a) => Value::from(a.clone()),
                        },
                        user: h.user.clone(),
                        background: h.background,
                    };
                    setup.install.extend(l.install.iter().map(hook));
                    setup.startup.extend(l.startup.iter().map(hook));
                    setup.files.extend(l.files.iter().map(|f| File {
                        path: f.path.clone(),
                        content: f.content.clone(),
                        mode: f.mode.clone(),
                        only_if_missing: !f.overwrite,
                    }));
                }
                _ => {}
            }
        }
        let source = source_of(&kit.source);
        Doc {
            schema_version: "2",
            kind: match kit.kind {
                Kind::Workload => "sandbox",
                Kind::Mixin => "mixin",
            },
            name: kit.name.clone(),
            sandbox,
            permissions: Permissions { network: net },
            credentials,
            setup,
            smolbento: Extras {
                source: source.0,
                source_type: source.1,
                digest: kit.digest.clone(),
                provides: kit.provides.clone(),
                requires: kit.requires.clone(),
                integrates: kit.integrates.clone(),
                conflicts: kit.conflicts.clone(),
                args: kit
                    .args
                    .iter()
                    .map(|(n, a)| {
                        (
                            n.clone(),
                            Arg {
                                required: a.required,
                                default: a.default.clone(),
                                pattern: a.pattern.clone(),
                                enum_values: a.enum_values.clone(),
                            },
                        )
                    })
                    .collect(),
            },
        }
    }

    pub fn json(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    pub fn yaml(&self) -> Result<String> {
        Ok(serde_saphyr::to_string(self)?)
    }

    /// sbx's summary: name, kind, schema, template, then counts.
    pub fn table(&self, kit: &Kit) -> String {
        let (allow, deny) = self
            .permissions
            .network
            .as_ref()
            .map_or((0, 0), |n| (n.allow.len(), n.deny.len()));
        let mut s = format!("Name: {}\nKind: {}\n", kit.name, kind_word(kit.kind));
        s += &format!("Schema: {}\n", schema(&kit.source));
        if let Some(t) = template(kit) {
            s += &format!("Template: {t}\n");
        }
        s += &format!("Policies:\n  Network: {allow} allow, {deny} deny\n");
        s += &format!("Credentials: {} sources\n", self.credentials.len());
        s += &format!(
            "Commands: {} install, {} startup, {} init files\n",
            self.setup.install.len(),
            self.setup.startup.len(),
            self.setup.files.len()
        );
        s
    }

    /// smolbento's extra lines, after the capability list: only what the kit has.
    pub fn extras_table(&self) -> String {
        let e = &self.smolbento;
        let mut s = format!("Source: {} ({})\n", e.source, e.source_type);
        if let Some(d) = &e.digest {
            s += &format!("Digest: {d}\n");
        }
        for (label, list) in [
            ("Provides", &e.provides),
            ("Requires", &e.requires),
            ("Integrates", &e.integrates),
            ("Conflicts", &e.conflicts),
        ] {
            if !list.is_empty() {
                s += &format!("{label}: {}\n", list.join(", "));
            }
        }
        if !e.args.is_empty() {
            s += "Args:\n";
            for (name, a) in &e.args {
                let mut what = Vec::new();
                if a.required {
                    what.push("required".to_string());
                }
                if let Some(d) = &a.default {
                    what.push(format!("default {d:?}"));
                }
                if !a.enum_values.is_empty() {
                    what.push(format!("one of {}", a.enum_values.join("|")));
                }
                if let Some(p) = &a.pattern {
                    what.push(format!("pattern {p}"));
                }
                s += &format!("  {name}  {}\n", what.join(", "));
            }
        }
        s
    }
}

/// The ref or path, and what kind of source it is.
fn source_of(s: &Source) -> (String, &'static str) {
    match s {
        Source::Registry(r) => (r.clone(), "registry"),
        Source::Preset(r) => (r.clone(), "preset"),
        Source::Builtin(n) => (n.to_string(), "builtin"),
        Source::LocalV3(p) => (p.display().to_string(), "local v3"),
        Source::LocalV2(p) => (p.display().to_string(), "local v2"),
        Source::Smolfile(p) => (p.display().to_string(), "smolfile"),
    }
}

fn kind_word(k: Kind) -> &'static str {
    match k {
        Kind::Workload => "workload",
        Kind::Mixin => "mixin",
    }
}

fn schema(s: &Source) -> &'static str {
    match s {
        Source::LocalV2(_) => "v2",
        Source::Smolfile(_) => "smolfile",
        _ => "v3",
    }
}

/// sbx's name for a built local v3 kit: `sbx-kit-src:<dir>-<hash>`; the hash is the build's.
fn template(kit: &Kit) -> Option<String> {
    let (Source::LocalV3(dir), Content::Oci(layout)) = (&kit.source, &kit.content) else {
        return None;
    };
    let dir = dir.file_name()?.to_str()?;
    let hash = layout.file_name()?.to_str()?;
    let hash = hash.strip_prefix("sha256:").unwrap_or(hash);
    Some(format!("sbx-kit-src:{dir}-{}", &hash[..hash.len().min(12)]))
}
