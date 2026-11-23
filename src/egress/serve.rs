//! `_serve egress SANDBOX`: the interceptor a hosted sandbox's egress unit runs.

use super::filter::{Filter, PolicySource, Restart, connection};
use super::rules::Rules;
use super::{load_ca, policy, token};
use crate::cli::Ctx;
use crate::sandbox;
use crate::secrets::{SecretsFile, resolve::start_env};
use crate::smolvm::{Credential, Runner};
use anyhow::{Context, Result, bail};
use egress_front::{Decision, Flow, InterceptorConfig, StaticResolver, activated_listener, serve};
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
    let hosts: Vec<String> = label
        .bindings
        .iter()
        .flat_map(|b| b.hosts.clone())
        .collect();
    let source = Arc::new(PolicySource::new(&ctx.paths, name, hosts.clone()));
    let ruled = source.ruled_hosts().unwrap_or_default();
    let mut terminated = hosts.clone();
    terminated.extend(ruled.iter().cloned());
    terminated.sort();
    terminated.dedup();
    // The unit's socket starts the process again on the next connection.
    let restart = Restart::new(ruled, Box::new(|| std::process::exit(0)));
    let rules = Rules::new(&ctx.paths, name, sb.meta.rec.host_access, hosts);
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
        terminate_hosts: terminated.clone(),
        request_filter: Some(Arc::new(Filter(source.clone()))),
    };
    let decide = Arc::new(move |f: &Flow| {
        restart.check(source.ruled_hosts().as_deref());
        let (mut decision, mut reason) = rules.decide(f);
        if decision == Decision::Allow
            && let Some(step) = connection(&source.current(), f, &terminated)
        {
            (decision, reason) = step;
        }
        if decision == Decision::Deny {
            eprintln!("{}", deny_line(f, &reason));
        }
        decision
    });
    serve(listener, token, config, Arc::new(resolver(pairs)), decide)
        .context("egress interceptor failed to start")
}

/// The log line for a denied flow. The name is the guest's, so it's capped at a DNS name's length
/// and escaped: a newline or terminal escape in an SNI can't forge or hide log lines.
fn deny_line(f: &Flow, reason: &str) -> String {
    let host = f.name.as_ref().map_or_else(
        || f.ip.to_string(),
        |n| n.chars().take(253).flat_map(char::escape_debug).collect(),
    );
    format!("deny {host}:{}: {reason}", f.port)
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
    fn a_guest_name_cant_forge_log_lines() {
        let f = Flow {
            name: Some(format!(
                "a.com\ndeny x.com:443: forged\u{1b}[2K{}",
                "z".repeat(400)
            )),
            kind: egress_front::FlowKind::Other,
            ip: "192.0.2.1".parse().unwrap(),
            port: 443,
        };
        let line = deny_line(&f, "why");
        assert!(!line.contains('\n') && !line.contains('\u{1b}'), "{line}");
        assert!(
            line.starts_with(r"deny a.com\ndeny x.com:443: forged\u{1b}[2K"),
            "{line}"
        );
        assert!(line.len() < 300, "{line}");
        assert!(line.ends_with(":443: why"), "{line}");
    }

    #[test]
    fn token_decodes_64_hex_digits_only() {
        assert_eq!(decode_token(&"ab".repeat(32)).unwrap(), [0xab; 32]);
        assert!(decode_token("ab").is_err());
        assert!(decode_token(&"zz".repeat(32)).is_err());
    }
}
