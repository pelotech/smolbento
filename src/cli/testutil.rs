use std::collections::BTreeMap;

use anyhow::Result;
use clap::Parser;

use super::{Cli, Ctx, dispatch};
use crate::config::{Paths, Settings};
use crate::smolvm::Smolvm;
use crate::smolvm::fake::FakeRunner;
pub use crate::testgit::*;

pub struct TestEnv {
    pub ctx: Ctx<FakeRunner>,
    /// Keeps the temp dirs alive for the test's duration.
    _dir: tempfile::TempDir,
}

/// A context with temp config/cache dirs, cwd `<tmp>/proj`, `now` = 1_000_000, uid 501 and smolvm
/// 1.32.2.
pub fn test_env(extra_env: &[(&str, &str)]) -> TestEnv {
    let dir = tempfile::tempdir().unwrap();
    let mut env = BTreeMap::from([
        (
            "SMOLBENTO_CONFIG_DIR".to_string(),
            dir.path().join("config").display().to_string(),
        ),
        (
            "SMOLBENTO_CACHE_DIR".to_string(),
            dir.path().join("cache").display().to_string(),
        ),
    ]);
    for (k, v) in extra_env {
        env.insert(k.to_string(), v.to_string());
    }
    let paths = Paths::from_env(&env).unwrap();
    std::fs::create_dir_all(&paths.config).unwrap();
    std::fs::write(paths.policy_file(), "mode = \"allow-all\"\n").unwrap();
    let (settings, config_error) = Settings::load(&paths, env.clone());
    let fake = FakeRunner::new();
    fake.ok(&["--version"], "smolvm 1.32.2\n");
    let cwd = dir.path().join("proj");
    std::fs::create_dir_all(&cwd).unwrap();
    let cwd = cwd.canonicalize().unwrap();
    TestEnv {
        ctx: Ctx {
            vm: Smolvm::new(fake),
            settings,
            paths,
            cwd,
            env,
            now: 1_000_000,
            stdin_tty: false,
            uid: 501,
            store: Box::new(crate::secrets::store::MemoryStore::default()),
            config_error,
        },
        _dir: dir,
    }
}

/// Replaces config.toml with invalid TOML and reloads the settings as `main` would.
pub fn break_config(t: &mut TestEnv) {
    let file = t.ctx.paths.config_file();
    std::fs::create_dir_all(file.parent().unwrap()).unwrap();
    std::fs::write(&file, "docker = [broken").unwrap();
    let (settings, config_error) = Settings::load(&t.ctx.paths, t.ctx.env.clone());
    t.ctx.settings = settings;
    t.ctx.config_error = config_error;
}

/// Replaces policy.toml.
pub fn set_policy(t: &TestEnv, toml: &str) {
    std::fs::write(t.ctx.paths.policy_file(), toml).unwrap();
}

pub fn sbt(ctx: &mut Ctx<FakeRunner>, args: &[&str]) -> Result<i32> {
    let cli = Cli::try_parse_from(std::iter::once("sbt").chain(args.iter().copied()))?;
    dispatch(ctx, cli)
}

/// `machine status --json` output for a smolbento sandbox.
pub fn machine_json(machine: &str, state: &str, labels: &[(&str, &str)]) -> String {
    let labels: BTreeMap<&str, &str> = labels.iter().copied().collect();
    serde_json::json!({
        "name": machine,
        "state": state,
        "image": "img",
        "labels": labels,
        "created_at": 999_000,
        "published_ports": [],
    })
    .to_string()
}
