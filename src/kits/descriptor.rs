//! Config shapes that v2 and v3 kit files share.

use serde::Deserialize;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ApiKeyCfg {
    #[serde(default)]
    pub(super) name: String,
    // The proxy always keeps real values off the guest, so the flag changes nothing here.
    #[allow(dead_code)]
    #[serde(default)]
    pub(super) proxy_managed: bool,
    #[serde(default)]
    pub(super) inject: Vec<InjectCfg>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct InjectCfg {
    pub(super) domain: String,
    pub(super) header: Option<String>,
    pub(super) format: Option<String>,
    /// v2 checks it; in v3 `basic` is implied by a username.
    pub(super) scheme: Option<String>,
    pub(super) username: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TokenEndpoint {
    pub(super) host: String,
    #[allow(dead_code)]
    pub(super) path: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ResourcesCfg {
    pub(super) cpu: Option<f64>,
    pub(super) memory: Option<String>,
    /// Not supported: v2 warns.
    pub(super) gpu: Option<String>,
}
