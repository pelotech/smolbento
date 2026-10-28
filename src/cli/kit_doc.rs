//! `kit inspect` output: sbx's table, and its `--format json|yaml` document.
//!
//! sbx prints a v2-shaped descriptor (`schemaVersion` "2", kind `sandbox` or `mixin`) for every
//! kit, v3 included; `Doc` is that shape, built from the format-neutral model.

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
