//! `_serve egress SANDBOX`: the interceptor a hosted sandbox's egress unit runs.

use super::{load_ca, policy, token};
use crate::cli::Ctx;
use crate::sandbox;
use crate::secrets::{SecretsFile, resolve::start_env};
use crate::smolvm::{Credential, Runner};
use anyhow::{Result, bail};
use egress_front::{Decision, InterceptorConfig, StaticResolver, activated_listener, serve};
use std::sync::Arc;

/// Serves the unit's activated listener until the process is stopped.
pub fn run<R: Runner>(ctx: &Ctx<R>, name: &str) -> Result<()> {
    let Some(listener) = activated_listener()? else {
        bail!("_serve egress runs only under its unit");
    };
    let sb = sandbox::get(&ctx.vm, name)?;
    let Some(label) = sb.meta.egress.as_ref() else {
        bail!("sandbox '{name}' has no sbx.egress label");
    };
    let ca = load_ca(&ctx.paths, name)?;
    let token = decode_token(&token(&ctx.paths, name)?)?;
    let secrets = SecretsFile::load(&ctx.paths)?;
    // The unit's stderr is its log. Resolution failures warn from `start_env`; names only, never values.
    let (pairs, missing) = start_env(&secrets, &sb.meta, ctx.store.as_ref(), false);
    for var in missing {
        eprintln!("egress: no value for {var}; requests using it will fail");
    }
    let config = InterceptorConfig {
        machine: sb.machine,
        policy: policy(label),
        placeholders: label
            .bindings
            .iter()
            .map(|b| (b.name.clone(), b.placeholder.clone()))
            .collect(),
        ca,
        extra_cas: vec![],
        upstream_roots_pem: vec![],
    };
    // Task 3 replaces this
    let decide = Arc::new(|_: &egress_front::Flow| Decision::Allow);
    serve(listener, token, config, Arc::new(resolver(pairs)), decide)
}

/// Values keyed by binding name; a variable with no value stays absent, so its requests fail.
fn resolver(pairs: Vec<(String, String)>) -> StaticResolver {
    pairs
        .into_iter()
        .fold(StaticResolver::new(), |r, (var, value)| {
            r.with(Credential::binding(&var), value)
        })
}

fn decode_token(hex: &str) -> Result<[u8; 32]> {
    let mut out = [0u8; 32];
    if hex.len() != 64 || !hex.is_ascii() {
        bail!("the egress token is not 64 hex digits");
    }
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16)?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use egress_front::CredentialResolver;

    fn ask(r: &StaticResolver, binding: &str) -> bool {
        let req = egress_front::CredentialRequest {
            machine: "m".into(),
            binding: binding.into(),
            host: "h".into(),
            port: 443,
            method: "GET".into(),
            path: "/".into(),
        };
        r.resolve(&req).is_ok()
    }

    #[test]
    fn bindings_resolve_by_their_variable() {
        let r = resolver(vec![("GH_TOKEN".into(), "v".into())]);
        assert!(ask(&r, "gh_token"));
        assert!(!ask(&r, "other_token"));
    }

    #[test]
    fn token_decodes_64_hex_digits_only() {
        assert_eq!(decode_token(&"ab".repeat(32)).unwrap(), [0xab; 32]);
        assert!(decode_token("ab").is_err());
        assert!(decode_token(&"zz".repeat(32)).is_err());
    }
}
