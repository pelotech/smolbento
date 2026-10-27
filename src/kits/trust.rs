//! Which kit sources may be loaded: registries by pattern, and local directories.

use anyhow::{Result, bail};

use crate::config::Settings;
use crate::kits::model::Source;

pub fn check(source: &Source, settings: &Settings) -> Result<()> {
    match source {
        Source::Registry(r) => {
            let name = normalise(r);
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
        _ => {
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

/// `registry/repo` with Docker's defaults applied and the tag or digest dropped.
fn normalise(r: &str) -> String {
    let r = r.split('@').next().unwrap_or(r);
    let mut parts: Vec<&str> = r.split('/').collect();
    if let Some(last) = parts.last_mut() {
        *last = last.split(':').next().unwrap_or(last);
    }
    let has_host = parts.len() > 1 && (parts[0].contains(['.', ':']) || parts[0] == "localhost");
    if !has_host {
        parts.insert(0, "docker.io");
    }
    if parts.len() == 2 && parts[0] == "docker.io" {
        parts.insert(1, "library");
    }
    parts.join("/")
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
            "docker.io/foo/bar@sha256:ab",
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
        assert_eq!(normalise("alpine:1"), "docker.io/library/alpine");
        assert_eq!(normalise("foo/bar"), "docker.io/foo/bar");
        assert_eq!(normalise("localhost/x:2"), "localhost/x");
        assert_eq!(normalise("localhost:5000/x:2"), "localhost:5000/x");
        assert_eq!(normalise("reg.io:443/a/b@sha256:ff"), "reg.io:443/a/b");
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
}
