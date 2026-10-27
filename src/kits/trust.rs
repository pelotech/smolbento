//! Which kit sources may be loaded: registries by pattern, and local directories.

use anyhow::{Result, anyhow, bail};

use crate::config::Settings;
use crate::kits::model::Source;

pub fn check(source: &Source, settings: &Settings) -> Result<()> {
    match source {
        // smolbento's own presets.
        Source::Preset(_) => Ok(()),
        Source::Registry(r) => {
            let name = normalise(r)?;
            let patterns = settings.value("kit.sources")?;
            if patterns
                .split(',')
                .map(str::trim)
                .any(|p| !p.is_empty() && glob(p, &name))
            {
                return Ok(());
            }
            let registry = name.split('/').next().unwrap_or_default();
            bail!(
                "kit source {name} isn't allowed; allow it with \
                 sbt settings set kit.sources '{patterns},{registry}/*'"
            )
        }
        Source::LocalV3(_) | Source::LocalV2(_) | Source::Smolfile(_) => {
            if !settings.bool("kit.allow-local")? {
                bail!(
                    "local kits are disabled; enable them with \
                     sbt settings set kit.allow-local true"
                );
            }
            Ok(())
        }
    }
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
        if matches!(
            parts[0].as_str(),
            "index.docker.io" | "registry-1.docker.io"
        ) {
            parts[0] = "docker.io".to_string();
        }
    } else {
        parts.insert(0, "docker.io".to_string());
    }
    if parts.len() == 2 && parts[0] == "docker.io" {
        parts.insert(1, "library".to_string());
    }
    Ok(parts.join("/"))
}

/// `*` matches any run of characters, `/` included.
fn glob(pattern: &str, text: &str) -> bool {
    let mut pieces = pattern.split('*');
    let first = pieces.next().unwrap_or_default();
    let Some(mut rest) = text.strip_prefix(first) else {
        return false;
    };
    let pieces: Vec<&str> = pieces.collect();
    let Some((last, middle)) = pieces.split_last() else {
        return rest.is_empty();
    };
    for p in middle {
        match rest.find(p) {
            Some(i) => rest = &rest[i + p.len()..],
            None => return false,
        }
    }
    rest.ends_with(last)
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
            "kit source ghcr.io/x/y isn't allowed; allow it with \
             sbt settings set kit.sources 'docker.io/*,ghcr.io/*'"
        );
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
        assert_eq!(
            normalise("index.docker.io/x").unwrap(),
            "docker.io/library/x"
        );
        assert_eq!(
            normalise("registry-1.docker.io/a/b").unwrap(),
            "docker.io/a/b"
        );
    }

    #[test]
    fn patterns_are_comma_separated_globs() {
        let (_d, s) = settings(&[("SMOLBENTO_KIT_SOURCES", "docker.io/*, ghcr.io/acme/*")]);
        check(&registry("ghcr.io/acme/kit/sub:1"), &s).unwrap();
        assert!(check(&registry("ghcr.io/other/kit"), &s).is_err());
        let (_d, s) = settings(&[("SMOLBENTO_KIT_SOURCES", "*")]);
        check(&registry("quay.io/a/b"), &s).unwrap();
        let (_d, s) = settings(&[("SMOLBENTO_KIT_SOURCES", "docker.io/library/alpine")]);
        check(&registry("alpine"), &s).unwrap();
        assert!(check(&registry("alpine2"), &s).is_err());
    }

    #[test]
    fn local_kits_can_be_disabled() {
        let (_d, s) = settings(&[]);
        let p = PathBuf::from("/k");
        check(&Source::LocalV3(p.clone()), &s).unwrap();
        let (_d, s) = settings(&[("SMOLBENTO_KIT_ALLOW_LOCAL", "false")]);
        for src in [
            Source::LocalV3(p.clone()),
            Source::LocalV2(p.clone()),
            Source::Smolfile(p),
        ] {
            assert_eq!(
                check(&src, &s).unwrap_err().to_string(),
                "local kits are disabled; enable them with sbt settings set kit.allow-local true"
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
        check(&registry("Index.Docker.IO/x"), &s).unwrap();
        check(&registry("registry-1.docker.io/a/b"), &s).unwrap();
        assert!(check(&registry("GHCR.io/x/y"), &s).is_err());
        let (_d, s) = settings(&[("SMOLBENTO_KIT_SOURCES", "ghcr.io/Acme/*")]);
        check(&registry("GHCR.IO/Acme/k"), &s).unwrap();
        assert!(
            check(&registry("ghcr.io/acme/k"), &s).is_err(),
            "repo case is kept"
        );
    }

    #[test]
    fn glob_handles_middle_wildcards_and_overlap() {
        assert!(glob("a*b*c", "abc"));
        assert!(glob("a*b*c", "aXXbYYc"));
        assert!(glob("a*b*c", "abbc"));
        assert!(!glob("a*b*c", "acb"));
        assert!(!glob("a*b*c", "ab"));
        assert!(!glob("a*a", "a"));
        assert!(glob("a*a", "aa"));
        assert!(glob("a*a", "aXa"));
        assert!(glob("*x*", "x"));
        assert!(glob("*x*", "a/x/b"));
        assert!(!glob("*x*", "abc"));
        assert!(glob("*", ""));
        assert!(glob("abc", "abc"));
        assert!(!glob("abc", "abcd"));
    }
}
