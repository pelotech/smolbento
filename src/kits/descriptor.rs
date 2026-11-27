//! Config shapes that v2 and v3 kit files share.

use anyhow::{Result, bail};
use serde::Deserialize;

use super::model::Inject;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
// Some fields are only accepted, so published descriptors parse.
#[allow(dead_code)]
pub(super) struct ApiKeyCfg {
    #[serde(default)]
    pub(super) name: String,
    // The proxy always keeps real values off the guest, so the flag changes nothing here.
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
    pub(super) scheme: Option<String>,
    pub(super) username: Option<String>,
}

impl InjectCfg {
    /// One outbound rewrite rule, as smolvm presents it (credential@1 `apiKey.inject[]`, the same
    /// in v2 and v3). `header`/`format` set a header. `scheme` is the non-header presentation:
    /// `bearer` is shorthand for `Authorization: Bearer %s`, and `basic` sends the credential as
    /// the password of HTTP basic auth for `username`, which a username alone also implies.
    /// smolvm can present only these two, so any other scheme is refused here rather than
    /// sending the raw value.
    pub(super) fn into_inject(self) -> Result<Inject> {
        if self.format.is_some() && self.scheme.is_some() {
            bail!("inject sets both format and scheme");
        }
        if self.username.is_some() && self.scheme.as_deref() != Some("basic") {
            bail!("username is only for scheme basic");
        }
        let (mut header, mut format) = (self.header, self.format);
        match self.scheme.as_deref() {
            None => {}
            Some("bearer") => {
                header.get_or_insert_with(|| "Authorization".to_string());
                format = Some("Bearer %s".to_string());
            }
            Some("basic") => {
                if self.username.is_none() {
                    bail!("scheme basic needs a username");
                }
            }
            Some(s) => bail!("scheme must be bearer or basic (got {s:?})"),
        }
        Ok(Inject {
            domain: self.domain,
            header,
            format,
            basic_user: self.username,
        })
    }
}

/// A credential's `apiKey` as its env var (none for an empty name) and inject rules; ERR adds
/// rule N's context to its error.
pub(super) fn api_key(
    key: Option<ApiKeyCfg>,
    err: impl Fn(usize, anyhow::Error) -> anyhow::Error,
) -> Result<(Option<String>, Vec<Inject>)> {
    let Some(k) = key else {
        return Ok((None, vec![]));
    };
    let inject = k
        .inject
        .into_iter()
        .enumerate()
        .map(|(n, i)| i.into_inject().map_err(|e| err(n, e)))
        .collect::<Result<_>>()?;
    Ok(((!k.name.is_empty()).then_some(k.name), inject))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
// Some fields are only accepted, so published descriptors parse.
#[allow(dead_code)]
pub(super) struct TokenEndpoint {
    pub(super) host: String,
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
