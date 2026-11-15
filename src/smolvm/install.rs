//! The managed smolvm: the pinned release, downloaded on first need into
//! `<home>/engine/<version>/`, verified against the compiled-in SHA-256 and unpacked untouched.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result, bail};

use super::pin::{Pin, asset_url};

/// A temp dir older than this is left over from an interrupted install; a younger one may be
/// another `sbt`'s install in progress.
const STALE: Duration = Duration::from_secs(600);

/// Where version `version` is installed under `home`.
pub fn engine_dir(home: &Path, version: &str) -> PathBuf {
    home.join("engine").join(version)
}

/// The pinned smolvm's wrapper, downloading and installing it first when it's missing. `base` is
/// the releases URL (`pin::RELEASES`, or a test server); `progress` gets one line per download.
pub fn ensure(
    home: &Path,
    pin: &Pin,
    platform: &str,
    base: &str,
    progress: &mut dyn FnMut(&str),
) -> Result<PathBuf> {
    let bin = engine_dir(home, &pin.version).join("smolvm");
    if bin.is_file() {
        return Ok(bin);
    }
    let want = pin
        .sha256
        .get(platform)
        .with_context(|| format!("smolvm.lock has no checksum for {platform}"))?;
    let engine = home.join("engine");
    std::fs::create_dir_all(&engine).with_context(|| format!("creating {}", engine.display()))?;
    clean_stale(&engine);
    let url = asset_url(base, &pin.version, platform);
    let bytes = download(&url, &pin.version, progress).with_context(|| {
        format!(
            "downloading smolvm from {url}; set SMOLBENTO_SMOLVM to a smolvm you installed \
             yourself to skip the download"
        )
    })?;
    let got = crate::util::sha256_digest(&bytes);
    if got.trim_start_matches("sha256:") != want {
        bail!("smolvm download from {url} failed its checksum: expected {want}, got {got}");
    }
    let bin = install_from(home, &pin.version, &bytes)?;
    prune(&engine, &pin.version);
    Ok(bin)
}

/// GETs `url` (following GitHub's redirect), saying how big it is first.
fn download(url: &str, version: &str, progress: &mut dyn FnMut(&str)) -> Result<Vec<u8>> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("starting the download client")?
        .block_on(async {
            // Same TLS setup as `kits::registry`. Err means a provider is already installed.
            let _ = rustls::crypto::ring::default_provider().install_default();
            let client = reqwest::Client::builder()
                .connect_timeout(Duration::from_secs(30))
                .read_timeout(Duration::from_secs(60))
                .build()?;
            let res = client.get(url).send().await?.error_for_status()?;
            let mb = res.content_length().unwrap_or(0) / 1_000_000;
            progress(&format!("downloading smolvm {version} ({mb} MB)…"));
            Ok(res.bytes().await?.to_vec())
        })
}

/// Unpacks a release tarball (one top-level directory) into `<home>/engine/<version>` by way of a
/// temp dir and a rename, so a half copy never takes its place. When another `sbt` got there
/// first, its copy stays and this one goes.
fn install_from(home: &Path, version: &str, tarball: &[u8]) -> Result<PathBuf> {
    let engine = home.join("engine");
    std::fs::create_dir_all(&engine)?;
    let tmp = tempfile::Builder::new()
        .prefix(".tmp-")
        .tempdir_in(&engine)
        .context("creating a temp dir for smolvm")?;
    let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(tarball));
    archive.set_preserve_permissions(true);
    // `tar` skips any entry that would land outside the temp dir.
    archive
        .unpack(tmp.path())
        .context("unpacking the smolvm release")?;
    let tops: Vec<PathBuf> = std::fs::read_dir(tmp.path())?
        .map(|e| e.map(|e| e.path()))
        .collect::<std::io::Result<_>>()?;
    let [top] = tops.as_slice() else {
        bail!("the smolvm release isn't one directory");
    };
    if !top.join("smolvm").is_file() {
        bail!("the smolvm release has no smolvm wrapper");
    }
    let target = engine_dir(home, version);
    if !target.exists()
        && let Err(e) = std::fs::rename(top, &target)
        && !target.exists()
    {
        return Err(e).with_context(|| format!("installing smolvm into {}", target.display()));
    }
    Ok(target.join("smolvm"))
}

/// Removes temp dirs an interrupted install left behind.
fn clean_stale(engine: &Path) {
    let Ok(entries) = std::fs::read_dir(engine) else {
        return;
    };
    for e in entries.flatten() {
        let old = e
            .metadata()
            .and_then(|m| m.modified())
            .is_ok_and(|t| SystemTime::now().duration_since(t).unwrap_or_default() > STALE);
        if e.file_name().to_string_lossy().starts_with(".tmp-") && old {
            let _ = std::fs::remove_dir_all(e.path());
        }
    }
}

/// Removes every other installed version. A failure only warns: a sandbox started by the old
/// version keeps its open files, and the next upgrade tries again.
fn prune(engine: &Path, keep: &str) {
    let Ok(entries) = std::fs::read_dir(engine) else {
        return;
    };
    for e in entries.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if name.starts_with('.') || name == keep {
            continue;
        }
        if let Err(err) = std::fs::remove_dir_all(e.path()) {
            eprintln!("warning: couldn't remove smolvm {name}: {err}");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    use super::*;
    use crate::smolvm::pin::Pin;
    use crate::testutil::http_server;

    /// A release tarball like smolvm's: one top-level directory with the wrapper and a library
    /// symlink.
    fn tarball(top: &str) -> Vec<u8> {
        let gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut b = tar::Builder::new(gz);
        let mut file = |path: &str, mode: u32, data: &[u8]| {
            let mut h = tar::Header::new_gnu();
            h.set_size(data.len() as u64);
            h.set_mode(mode);
            h.set_cksum();
            b.append_data(&mut h, path, data).unwrap();
        };
        file(&format!("{top}/smolvm"), 0o755, b"#!/bin/sh\n");
        file(&format!("{top}/lib/libx.so.1"), 0o644, b"lib");
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Symlink);
        h.set_size(0);
        h.set_mode(0o777);
        h.set_cksum();
        b.append_link(&mut h, format!("{top}/lib/libx.so"), "libx.so.1")
            .unwrap();
        b.into_inner().unwrap().finish().unwrap()
    }

    fn pin_for(bytes: &[u8]) -> Pin {
        Pin {
            version: "1.0.0".into(),
            sha256: BTreeMap::from([(
                "linux-x86_64".to_string(),
                crate::util::sha256_digest(bytes)
                    .trim_start_matches("sha256:")
                    .to_string(),
            )]),
        }
    }

    fn run(home: &Path, pin: &Pin, base: &str) -> (Result<PathBuf>, Vec<String>) {
        let mut said = Vec::new();
        let r = ensure(home, pin, "linux-x86_64", base, &mut |s| {
            said.push(s.to_string())
        });
        (r, said)
    }

    #[test]
    fn installs_verifies_and_returns_the_wrapper() {
        let home = tempfile::tempdir().unwrap();
        let bytes = tarball("smolvm-1.0.0-linux-x86_64");
        let (base, seen) = http_server(bytes.clone());
        let (r, said) = run(home.path(), &pin_for(&bytes), &base);
        let bin = r.unwrap();
        assert_eq!(bin, home.path().join("engine/1.0.0/smolvm"));
        assert_eq!(
            std::fs::metadata(&bin).unwrap().permissions().mode() & 0o777,
            0o755
        );
        let link = home.path().join("engine/1.0.0/lib/libx.so");
        assert_eq!(std::fs::read_link(link).unwrap(), Path::new("libx.so.1"));
        assert_eq!(said, ["downloading smolvm 1.0.0 (0 MB)…"]);
        assert_eq!(
            seen.lock().unwrap()[0],
            "GET /v1.0.0/smolvm-1.0.0-linux-x86_64.tar.gz HTTP/1.1"
        );
    }

    #[test]
    fn an_installed_copy_needs_no_network() {
        let home = tempfile::tempdir().unwrap();
        let bytes = tarball("smolvm-1.0.0-linux-x86_64");
        let (base, _) = http_server(bytes.clone());
        run(home.path(), &pin_for(&bytes), &base).0.unwrap();
        let (r, said) = run(home.path(), &pin_for(&bytes), "http://127.0.0.1:1");
        assert!(r.is_ok(), "{r:?}");
        assert!(said.is_empty());
    }

    #[test]
    fn a_checksum_mismatch_installs_nothing() {
        let home = tempfile::tempdir().unwrap();
        let bytes = tarball("smolvm-1.0.0-linux-x86_64");
        let (base, _) = http_server(bytes);
        let (r, _) = run(home.path(), &pin_for(b"something else"), &base);
        assert!(format!("{:#}", r.unwrap_err()).contains("checksum"));
        let left: Vec<_> = std::fs::read_dir(home.path().join("engine"))
            .map(|d| d.map(|e| e.unwrap().file_name()).collect())
            .unwrap_or_default();
        assert!(left.is_empty(), "{left:?}");
    }

    #[test]
    fn an_unreachable_server_names_the_url_and_the_override() {
        let home = tempfile::tempdir().unwrap();
        let (r, _) = run(home.path(), &pin_for(b"x"), "http://127.0.0.1:1");
        let e = format!("{:#}", r.unwrap_err());
        assert!(
            e.contains("http://127.0.0.1:1/v1.0.0/smolvm-1.0.0-linux-x86_64.tar.gz"),
            "{e}"
        );
        assert!(e.contains("SMOLBENTO_SMOLVM"), "{e}");
    }

    #[test]
    fn a_stale_temp_dir_is_cleaned() {
        let home = tempfile::tempdir().unwrap();
        let stale = home.path().join("engine/.tmp-old");
        std::fs::create_dir_all(stale.join("x")).unwrap();
        let hour_ago = std::time::SystemTime::now() - std::time::Duration::from_secs(3600);
        std::fs::File::open(&stale)
            .unwrap()
            .set_modified(hour_ago)
            .unwrap();
        let bytes = tarball("smolvm-1.0.0-linux-x86_64");
        let (base, _) = http_server(bytes.clone());
        run(home.path(), &pin_for(&bytes), &base).0.unwrap();
        assert!(!home.path().join("engine/.tmp-old").exists());
    }

    #[test]
    fn older_versions_are_pruned_and_a_failure_only_warns() {
        let home = tempfile::tempdir().unwrap();
        let engine = home.path().join("engine");
        std::fs::create_dir_all(engine.join("0.9.0")).unwrap();
        std::fs::create_dir_all(engine.join("0.8.0/stuck")).unwrap();
        std::fs::write(engine.join("0.8.0/stuck/f"), "x").unwrap();
        let ro = engine.join("0.8.0/stuck");
        std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o500)).unwrap();
        let bytes = tarball("smolvm-1.0.0-linux-x86_64");
        let (base, _) = http_server(bytes.clone());
        let r = run(home.path(), &pin_for(&bytes), &base).0;
        std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(r.is_ok(), "{r:?}");
        assert!(!engine.join("0.9.0").exists());
    }

    #[test]
    fn a_racing_install_keeps_the_first() {
        let home = tempfile::tempdir().unwrap();
        let bytes = tarball("smolvm-1.0.0-linux-x86_64");
        let a = install_from(home.path(), "1.0.0", &bytes).unwrap();
        let b = install_from(home.path(), "1.0.0", &bytes).unwrap();
        assert_eq!(a, b);
        assert!(a.is_file());
    }

    #[test]
    fn an_entry_escaping_the_dir_is_refused() {
        let gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut b = tar::Builder::new(gz);
        let mut h = tar::Header::new_gnu();
        h.set_size(1);
        h.set_mode(0o644);
        // `set_path` refuses `..`; write the name bytes directly, as a hostile archive would.
        h.as_old_mut().name[..9].copy_from_slice(b"../escape");
        h.set_cksum();
        b.append(&h, &b"x"[..]).unwrap();
        let bytes = b.into_inner().unwrap().finish().unwrap();
        let home = tempfile::tempdir().unwrap();
        let r = install_from(home.path(), "1.0.0", &bytes);
        assert!(r.is_err(), "{r:?}");
        assert!(!home.path().join("escape").exists());
    }
}
