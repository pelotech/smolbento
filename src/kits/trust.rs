//! Which kit sources may be loaded: registries by pattern, and local directories.

use anyhow::{Result, anyhow, bail};

use crate::config::Settings;
use crate::kits::model::Source;

pub fn check(source: &Source, settings: &Settings) -> Result<()> {
    match source {
        // smolbento's own presets and shipped kits.
        Source::Preset(_) | Source::Builtin(_) => Ok(()),
        Source::Registry(r) => {
            let name = normalise(r)?;
            let allowed = allowed_sources(settings)?;
            if allowed.iter().any(|p| matches(&name, p)) {
                return Ok(());
            }
            let org: Vec<&str> = name.split('/').take(2).collect();
            let mut suggested = allowed.clone();
            suggested.push(format!("{}/", org.join("/")));
            bail!(
                "kit \"{r}\" cannot be installed \u{2014} its source is not in your allowlist; \
                 current kit.allowedSources: {}\n\
                 try: sbt settings set kit.allowedSources '{}' (or '[\"*\"]')",
                serde_json::to_string(&allowed)?,
                serde_json::to_string(&suggested)?,
            )
        }
        Source::LocalV3(_) | Source::LocalV2(_) | Source::Smolfile(_) => {
            if !settings.bool("kit.allowLocalKits")? {
                bail!(
                    "local kits are disabled; enable them with \
                     sbt settings set kit.allowLocalKits true"
                );
            }
            Ok(())
        }
    }
}

/// `kit.allowedSources`: a JSON array of strings.
fn allowed_sources(settings: &Settings) -> Result<Vec<String>> {
    parse_allowed_sources(&settings.value("kit.allowedSources")?)
}

/// Also checked by `sbt settings set`, so a bad value is refused before it's saved.
pub(crate) fn parse_allowed_sources(raw: &str) -> Result<Vec<String>> {
    let list: Vec<String> = serde_json::from_str(raw).map_err(|e| {
        anyhow!(
            "setting kit.allowedSources must be a JSON array of strings, e.g. [\"docker.io/\"]: {e}"
        )
    })?;
    if list.iter().any(String::is_empty) {
        bail!(
            "setting kit.allowedSources has an empty prefix; remove it, or use \"*\" to allow any \
             source"
        );
    }
    Ok(list)
}

/// Whether the normalised ref `name` is allowed by prefix `p`. A prefix without `/` names a
/// registry host and matches only that whole host, so `ghcr.io` doesn't allow `ghcr.io.evil.com`.
fn matches(name: &str, p: &str) -> bool {
    if p == "*" {
        return true;
    }
    if !p.contains('/') {
        let host = p.to_ascii_lowercase();
        return name
            .strip_prefix(&host)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'));
    }
    name.starts_with(&normalise_prefix(p))
}

/// `registry/repo` with Docker's defaults applied and the tag or digest dropped. Refs a puller
/// would read differently (or refuse) are errors, so the check never sees another name than the pull.
pub(crate) fn normalise(r: &str) -> Result<String> {
    let invalid = || anyhow!("invalid kit reference '{r}'");
    if r.is_empty() || r.contains(char::is_whitespace) || r.contains("//") || r.contains("..") {
        return Err(invalid());
    }
    let (name, digest) = match r.split_once('@') {
        Some((n, d)) => (n, Some(d)),
        None => (r, None),
    };
    if let Some(d) = digest {
        let hex = d.strip_prefix("sha256:").ok_or_else(invalid)?;
        let ok = hex.len() == 64 && hex.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'));
        if !ok {
            return Err(invalid());
        }
    }
    let mut parts: Vec<String> = name.split('/').map(str::to_string).collect();
    if let Some(last) = parts.last_mut() {
        *last = last.split(':').next().unwrap_or_default().to_string();
    }
    if parts.iter().any(String::is_empty) {
        return Err(invalid());
    }
    let has_host = parts.len() > 1 && (parts[0].contains(['.', ':']) || parts[0] == "localhost");
    if has_host {
        parts[0] = parts[0].to_ascii_lowercase();
    } else {
        parts.insert(0, "docker.io".to_string());
    }
    if parts.len() == 2 && parts[0] == "docker.io" {
        parts.insert(1, "library".to_string());
    }
    Ok(parts.join("/"))
}

/// A `kit.allowedSources` prefix with its registry host lowercased, as `normalise` does a ref's.
fn normalise_prefix(p: &str) -> String {
    match p.split_once('/') {
        Some((host, rest))
            if host.contains(['.', ':']) || host.eq_ignore_ascii_case("localhost") =>
        {
            format!("{}/{rest}", host.to_ascii_lowercase())
        }
        _ => p.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::test_paths;
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    fn settings(pairs: &[(&str, &str)]) -> (tempfile::TempDir, Settings) {
        let (dir, paths) = test_paths();
        let env: BTreeMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        (dir, Settings::load(&paths, env).0)
    }

    fn registry(r: &str) -> Source {
        Source::Registry(r.to_string())
    }

    const KEY: &str = "SMOLBENTO_KIT_ALLOWED_SOURCES";

    #[test]
    fn pattern_hosts_are_case_insensitive_and_aliases_are_not_folded() {
        let (_d, s) = settings(&[(KEY, r#"["GHCR.IO/acme/"]"#)]);
        check(&registry("ghcr.io/acme/k:1"), &s).unwrap();
        check(&registry("GHCR.io/acme/k:1"), &s).unwrap();
        // Only the host: a repository path keeps its case.
        let (_d, s) = settings(&[(KEY, r#"["ghcr.io/Acme/"]"#)]);
        assert!(check(&registry("ghcr.io/acme/k:1"), &s).is_err());
        // sbx does not treat Docker Hub's other hosts as docker.io.
        let (_d, s) = settings(&[(KEY, r#"["index.docker.io/acme/"]"#)]);
        check(&registry("index.docker.io/acme/k:1"), &s).unwrap();
        assert!(check(&registry("acme/k:1"), &s).is_err());
    }

    #[test]
    fn default_allows_docker_hub_only() {
        let (_d, s) = settings(&[]);
        for r in [
            "docker/sandbox-kit-x:1",
            "alpine:1",
            "docker.io/foo/bar@sha256:0000000000000000000000000000000000000000000000000000000000000000",
        ] {
            check(&registry(r), &s).unwrap_or_else(|e| panic!("{r}: {e}"));
        }
        let err = check(&registry("ghcr.io/x/y:1"), &s)
            .unwrap_err()
            .to_string();
        assert_eq!(
            err,
            "kit \"ghcr.io/x/y:1\" cannot be installed \u{2014} its source is not in your allowlist; \
             current kit.allowedSources: [\"docker.io/\"]\n\
             try: sbt settings set kit.allowedSources '[\"docker.io/\",\"ghcr.io/x/\"]' \
             (or '[\"*\"]')"
        );
    }

    #[test]
    fn hub_aliases_are_refused_under_the_default() {
        let (_d, s) = settings(&[]);
        for r in [
            "index.docker.io/x",
            "registry-1.docker.io/a/b",
            "Index.Docker.IO/x",
        ] {
            assert!(check(&registry(r), &s).is_err(), "{r} must be refused");
        }
    }

    #[test]
    fn normalises_refs() {
        assert_eq!(normalise("alpine:1").unwrap(), "docker.io/library/alpine");
        assert_eq!(normalise("foo/bar").unwrap(), "docker.io/foo/bar");
        assert_eq!(normalise("localhost/x:2").unwrap(), "localhost/x");
        assert_eq!(normalise("localhost:5000/x:2").unwrap(), "localhost:5000/x");
        let digest = format!("reg.io:443/a/b@sha256:{}", "f".repeat(64));
        assert_eq!(normalise(&digest).unwrap(), "reg.io:443/a/b");
        assert_eq!(normalise("Reg.IO/A/b").unwrap(), "reg.io/A/b");
        assert_eq!(normalise("index.docker.io/x").unwrap(), "index.docker.io/x");
    }

    #[test]
    fn allowed_sources_are_json_prefixes() {
        let (_d, s) = settings(&[(KEY, r#"["docker.io/", "ghcr.io/acme/"]"#)]);
        check(&registry("ghcr.io/acme/kit/sub:1"), &s).unwrap();
        assert!(check(&registry("ghcr.io/other/kit"), &s).is_err());
        assert!(check(&registry("ghcr.io/acmex/kit"), &s).is_err());
        let (_d, s) = settings(&[(KEY, r#"["*"]"#)]);
        check(&registry("quay.io/a/b"), &s).unwrap();
        let (_d, s) = settings(&[(KEY, r#"["docker.io/library/alpine"]"#)]);
        check(&registry("alpine"), &s).unwrap();
        let (_d, s) = settings(&[(KEY, "[]")]);
        assert!(check(&registry("alpine"), &s).is_err());
    }

    #[test]
    fn invalid_allowed_sources_name_the_setting() {
        for bad in ["docker.io/*", "[1]", "{}", ""] {
            let (_d, s) = settings(&[(KEY, bad)]);
            let e = check(&registry("alpine"), &s).unwrap_err().to_string();
            assert!(e.contains("kit.allowedSources"), "{bad}: {e}");
            assert!(e.contains("JSON array"), "{bad}: {e}");
        }
    }

    #[test]
    fn a_host_only_prefix_matches_at_a_host_boundary() {
        let (_d, s) = settings(&[(KEY, r#"["ghcr.io", "LocalHost:5000"]"#)]);
        check(&registry("ghcr.io/x/y:1"), &s).unwrap();
        check(&registry("GHCR.IO/x"), &s).unwrap();
        check(&registry("localhost:5000/k:1"), &s).unwrap();
        for r in [
            "ghcr.io.evil.com/x",
            "ghcr.iox/y",
            "ghcr.io:5000/x",
            "localhost:50001/k",
            "localhost/k",
        ] {
            assert!(check(&registry(r), &s).is_err(), "{r} must be refused");
        }
    }

    #[test]
    fn an_empty_prefix_is_an_error() {
        for bad in [r#"[""]"#, r#"["docker.io/", ""]"#] {
            let (_d, s) = settings(&[(KEY, bad)]);
            let e = check(&registry("alpine"), &s).unwrap_err().to_string();
            assert!(e.contains("kit.allowedSources"), "{bad}: {e}");
            assert!(e.contains("empty"), "{bad}: {e}");
        }
        assert!(parse_allowed_sources(r#"["docker.io/","*"]"#).is_ok());
        assert!(parse_allowed_sources(r#"[""]"#).is_err());
        assert!(parse_allowed_sources("[1]").is_err());
    }

    #[test]
    fn local_kits_can_be_disabled() {
        let (_d, s) = settings(&[]);
        let p = PathBuf::from("/k");
        check(&Source::LocalV3(p.clone()), &s).unwrap();
        let (_d, s) = settings(&[("SMOLBENTO_KIT_ALLOW_LOCAL_KITS", "false")]);
        for src in [
            Source::LocalV3(p.clone()),
            Source::LocalV2(p.clone()),
            Source::Smolfile(p),
        ] {
            assert_eq!(
                check(&src, &s).unwrap_err().to_string(),
                "local kits are disabled; enable them with sbt settings set kit.allowLocalKits true"
            );
        }
        check(&registry("a/b"), &s).unwrap();
    }

    #[test]
    fn lookalike_and_malformed_refs_are_denied() {
        let (_d, s) = settings(&[]);
        for r in [
            "docker.io.evil.com/x",
            "evil.com/docker.io/x",
            "docker.ioevil/x",
            "evil.com@docker.io/x",
            "docker.io/x@sha256:abc",
            "docker.io/x@sha256:ABCDEF",
            "docker.io/x@md5:aa",
            "docker.io//x",
            "docker.io/../x",
            "docker.io/x y",
            "",
        ] {
            assert!(check(&registry(r), &s).is_err(), "{r} must be denied");
        }
        let err = check(&registry("evil.com@docker.io/x"), &s).unwrap_err();
        assert_eq!(
            err.to_string(),
            "invalid kit reference 'evil.com@docker.io/x'"
        );
    }

    #[test]
    fn registry_host_is_case_insensitive() {
        let (_d, s) = settings(&[]);
        check(&registry("DOCKER.IO/x"), &s).unwrap();
        assert!(check(&registry("GHCR.io/x/y"), &s).is_err());
        let (_d, s) = settings(&[(KEY, r#"["ghcr.io/Acme/"]"#)]);
        check(&registry("GHCR.IO/Acme/k"), &s).unwrap();
        assert!(
            check(&registry("ghcr.io/acme/k"), &s).is_err(),
            "repo case is kept"
        );
    }
}
