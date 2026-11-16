//! Registry logins from Docker's config file and credential helpers.

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use oci_client::secrets::RegistryAuth;
use serde_json::Value;

pub(super) fn docker_config_dir() -> Option<PathBuf> {
    std::env::var_os("DOCKER_CONFIG")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".docker")))
}

/// Credentials from the host's docker login, if any. Read-only; values are never logged.
pub(super) fn docker_auth(host: &str) -> Option<RegistryAuth> {
    let text = fs::read_to_string(docker_config_dir()?.join("config.json")).ok()?;
    auth_from_config(&text, host, &credential_helper)
}

/// Docker Hub's entry is keyed by its legacy URL.
pub(super) fn config_keys(host: &str) -> Vec<String> {
    if host == "index.docker.io" || host == "docker.io" {
        return vec![
            "https://index.docker.io/v1/".into(),
            "index.docker.io".into(),
        ];
    }
    vec![
        host.to_string(),
        format!("https://{host}"),
        format!("https://{host}/"),
    ]
}

pub(super) fn auth_from_config(
    text: &str,
    host: &str,
    helper: &dyn Fn(&str, &str) -> Option<RegistryAuth>,
) -> Option<RegistryAuth> {
    let cfg: Value = serde_json::from_str(text).ok()?;
    let keys = config_keys(host);
    for k in &keys {
        let e = &cfg["auths"][k.as_str()];
        if let Some(t) = e["identitytoken"].as_str().filter(|t| !t.is_empty()) {
            return Some(RegistryAuth::Bearer(t.to_string()));
        }
        if let Some(a) = e["auth"].as_str().filter(|a| !a.is_empty()) {
            let raw = String::from_utf8(STANDARD.decode(a.trim()).ok()?).ok()?;
            let (user, pass) = raw.split_once(':')?;
            return Some(RegistryAuth::Basic(user.into(), pass.into()));
        }
    }
    let name = keys
        .iter()
        .find_map(|k| cfg["credHelpers"][k.as_str()].as_str())
        .or_else(|| cfg["credsStore"].as_str())?;
    // Docker Hub helpers are asked by its legacy URL, other registries by host.
    let server = keys.first().map(String::as_str).unwrap_or(host);
    helper(name, server)
}

/// Runs `docker-credential-<name> get`, only when that binary is on PATH.
pub(super) fn credential_helper(name: &str, server: &str) -> Option<RegistryAuth> {
    if name.is_empty() || name.contains(['/', '\\']) {
        return None;
    }
    let bin = format!("docker-credential-{name}");
    crate::util::find_on_path(std::env::var_os("PATH"), &bin)?;
    let mut child = Command::new(&bin)
        .arg("get")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    child.stdin.take()?.write_all(server.as_bytes()).ok()?;
    let out = child.wait_with_output().ok()?;
    if !out.status.success() {
        return None;
    }
    let v: Value = serde_json::from_slice(&out.stdout).ok()?;
    let user = v["Username"].as_str()?;
    let secret = v["Secret"].as_str()?;
    // Helpers return identity tokens under this sentinel user name.
    if user == "<token>" {
        Some(RegistryAuth::Bearer(secret.into()))
    } else {
        Some(RegistryAuth::Basic(user.into(), secret.into()))
    }
}
