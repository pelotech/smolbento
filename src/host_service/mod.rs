//! Host services for a sandbox's life: the OS service manager (launchd, systemd --user) owns the
//! sockets smolvm mounts into a sandbox and runs `smolbento _serve KIND SANDBOX` for each
//! connection, so the SSH agent and the browser and clipboard bridge answer without an attached
//! `bento`, and without a smolbento daemon.
//!
//! Units are namespaced by a hash of smolbento's data dir, so separate setups (the conformance
//! adapter's isolated dirs) never see or remove each other's. Without a usable service manager
//! nothing here does anything, and sandboxes are served while attached, as before.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};

use crate::config::Paths;
use crate::smolvm::locate::MACOS_SOCKET_LIMIT;
use crate::util::hex;

/// What a unit serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Agent,
    Bridge,
    /// One long-running process per hosted sandbox on a loopback TCP port (the others are
    /// started per connection on a unix socket).
    Egress,
}

impl Kind {
    pub const ALL: [Kind; 3] = [Kind::Agent, Kind::Bridge, Kind::Egress];

    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Agent => "agent",
            Kind::Bridge => "bridge",
            Kind::Egress => "egress",
        }
    }

    pub fn parse(s: &str) -> Option<Kind> {
        Kind::ALL.into_iter().find(|k| k.as_str() == s)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flavor {
    Launchd,
    Systemd,
}

/// The host sockets of a sandbox served by units (`--mount-socket` sources).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sockets {
    pub bridge: PathBuf,
    pub agent: PathBuf,
}

/// Where a unit's files and socket are, and what the service manager calls it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnitPaths {
    /// The launchd label, or the systemd socket unit's name.
    pub id: String,
    /// The unit files, the first being what is loaded.
    pub files: Vec<PathBuf>,
    pub socket: PathBuf,
}

/// Drives the service manager. Tests use a fake; nothing else may touch the user's real units.
pub trait Control {
    /// Whether the user's service manager can be used.
    fn usable(&self) -> bool;
    /// Once after a batch of unit files is written, before they are loaded.
    fn refresh(&self) -> Result<()> {
        Ok(())
    }
    /// Loads the unit (again, if it was loaded) once its files are written.
    fn load(&self, unit: &UnitPaths) -> Result<()>;
    /// Whether the unit is loaded now (a launchd job is gone after a reboot: its plist is not in
    /// `~/Library/LaunchAgents`, which would raise a "Background Items Added" notice).
    fn loaded(&self, unit: &UnitPaths) -> bool;
    /// Unloads the unit; its files and socket are deleted after.
    fn unload(&self, unit: &UnitPaths);
    /// Restarts the unit's process (it runs again from the next connection at the latest).
    fn restart(&self, unit: &UnitPaths) -> Result<()>;
    /// After unit files were deleted.
    fn settle(&self) {}
}

pub struct HostServices {
    flavor: Flavor,
    ns: String,
    unit_dir: PathBuf,
    sock_dir: PathBuf,
    /// The smolbento the units run, as found on PATH.
    exe: PathBuf,
    /// `None`: no service manager (units off).
    ctl: Option<Box<dyn Control>>,
    usable: OnceLock<bool>,
}

/// A short hash of the data dir: the namespace of this setup's units.
pub fn namespace(paths: &Paths) -> String {
    hex(&Sha256::digest(paths.data.as_os_str().as_encoded_bytes()))[..8].to_string()
}

/// Connections a unit serves at once per sandbox and kind (`_serve` holds one `flock`ed slot file
/// each; the in-process agent server allowed the same). More are closed on arrival.
pub const MAX_CONNECTIONS: usize = 8;

/// `_serve bridge` processes a sandbox's login relays may keep alive after their connection ends
/// (each holds a `flock`ed relay slot file while its relays run, `bridge::relay::LIFETIME`).
pub const RELAY_SLOTS: usize = 4;

/// Locks the first free file of `slots` (created 0600) until the returned file is dropped or the
/// process ends; `None` when every one is held, or the files can't be made.
pub fn acquire_slot(slots: &[PathBuf]) -> Option<File> {
    slots.iter().find_map(|p| lock(p))
}

fn lock(path: &Path) -> Option<File> {
    let f = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .open(path)
        .ok()?;
    // SAFETY: flock on a descriptor we own; it fails (EWOULDBLOCK) when another process holds it.
    (unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0).then_some(f)
}

impl HostServices {
    /// This host's service manager (launchd on macOS, `systemd --user` on Linux), if it has one
    /// and `env` locates its directories; else units are off.
    pub fn detect(paths: &Paths, env: &BTreeMap<String, String>, argv0: Option<&OsStr>) -> Self {
        let abs = |k: &str| {
            env.get(k)
                .filter(|v| Path::new(v).is_absolute())
                .map(PathBuf::from)
        };
        let Some(home) = abs("HOME") else {
            return Self::disabled();
        };
        let (flavor, unit_dir, sock_dir, ctl): (_, _, _, Box<dyn Control>) =
            if cfg!(target_os = "macos") {
                (
                    Flavor::Launchd,
                    home.join("Library/Application Support/smolbento/launchd"),
                    home.join("Library/Application Support/smolbento/sock"),
                    Box::new(Launchctl {
                        uid: crate::util::host_uid(),
                    }),
                )
            } else if cfg!(target_os = "linux") {
                let Some(run) = abs("XDG_RUNTIME_DIR") else {
                    return Self::disabled();
                };
                let config = abs("XDG_CONFIG_HOME").unwrap_or_else(|| home.join(".config"));
                (
                    Flavor::Systemd,
                    config.join("systemd/user"),
                    run.join("smolbento"),
                    Box::new(Systemctl),
                )
            } else {
                return Self::disabled();
            };
        HostServices::new(
            flavor,
            namespace(paths),
            unit_dir,
            sock_dir,
            resolve_exe(argv0, env),
            ctl,
        )
    }

    pub fn new(
        flavor: Flavor,
        ns: String,
        unit_dir: PathBuf,
        sock_dir: PathBuf,
        exe: PathBuf,
        ctl: Box<dyn Control>,
    ) -> Self {
        HostServices {
            flavor,
            ns,
            unit_dir,
            sock_dir,
            exe,
            ctl: Some(ctl),
            usable: OnceLock::new(),
        }
    }

    /// No service manager: nothing is ever written or loaded.
    pub fn disabled() -> Self {
        HostServices {
            flavor: Flavor::Launchd,
            ns: String::new(),
            unit_dir: PathBuf::new(),
            sock_dir: PathBuf::new(),
            exe: PathBuf::new(),
            ctl: None,
            usable: OnceLock::new(),
        }
    }

    pub fn usable(&self) -> bool {
        self.active().is_some()
    }

    /// The service manager, when there is one and it can be used.
    fn active(&self) -> Option<&dyn Control> {
        let ctl = self.ctl.as_deref()?;
        (*self.usable.get_or_init(|| ctl.usable())).then_some(ctl)
    }

    /// The directory of the sockets, which must be private and ours.
    pub fn sock_dir(&self) -> &Path {
        &self.sock_dir
    }

    fn socket_path(&self, name: &str, kind: Kind) -> PathBuf {
        // Short: the isolated setups of the conformance adapter put the directory near the limit.
        let id = &hex(&Sha256::digest(name.as_bytes()))[..10];
        self.sock_dir
            .join(format!("{}{id}.{}.sock", self.ns, kind.as_str()))
    }

    /// Whether this host has a service manager and `name`'s sockets fit the OS path limit.
    pub fn fits(&self, name: &str) -> bool {
        self.usable()
            && self.socket_path(name, Kind::Bridge).as_os_str().len() <= MACOS_SOCKET_LIMIT
            && self.socket_path(name, Kind::Agent).as_os_str().len() <= MACOS_SOCKET_LIMIT
    }

    /// The sockets a new sandbox `name` gets, or `None` (served while attached, as before) when
    /// there is no service manager, the directory isn't private and ours, or a path is too long.
    pub fn plan(&self, name: &str) -> Option<Sockets> {
        if !self.fits(name) || !crate::bridge::ensure_private_dir(&self.sock_dir) {
            return None;
        }
        Some(Sockets {
            bridge: self.socket_path(name, Kind::Bridge),
            agent: self.socket_path(name, Kind::Agent),
        })
    }

    /// The slot files `_serve` locks for sandbox `name`'s `kind`, beside its socket.
    pub fn slot_files(&self, name: &str, kind: Kind) -> Vec<PathBuf> {
        let sock = self.socket_path(name, kind);
        (0..MAX_CONNECTIONS)
            .map(|i| sock.with_extension(format!("slot{i}")))
            .collect()
    }

    /// The relay slot files of sandbox `name`'s bridge (`RELAY_SLOTS`), beside its socket.
    pub fn relay_slot_files(&self, name: &str) -> Vec<PathBuf> {
        let sock = self.socket_path(name, Kind::Bridge);
        (0..RELAY_SLOTS)
            .map(|i| sock.with_extension(format!("relay{i}")))
            .collect()
    }

    fn paths_of(&self, name: &str, kind: Kind) -> UnitPaths {
        let k = kind.as_str();
        match self.flavor {
            Flavor::Launchd => {
                let id = format!("dev.smolbento.{}.{name}.{k}", self.ns);
                UnitPaths {
                    files: vec![self.unit_dir.join(format!("{id}.plist"))],
                    id,
                    socket: self.socket_path(name, kind),
                }
            }
            Flavor::Systemd => {
                let base = format!("smolbento-{}-{name}-{k}", self.ns);
                // Accept=yes sockets start a service instance per connection (a template).
                let service = if kind == Kind::Egress {
                    format!("{base}.service")
                } else {
                    format!("{base}@.service")
                };
                UnitPaths {
                    files: vec![
                        self.unit_dir.join(format!("{base}.socket")),
                        self.unit_dir.join(service),
                    ],
                    id: format!("{base}.socket"),
                    socket: self.socket_path(name, kind),
                }
            }
        }
    }

    /// `egress` is an egress unit's loopback TCP port and log file (`None` for the others).
    fn render(
        &self,
        name: &str,
        kind: Kind,
        egress: Option<(u16, &Path)>,
        env: &[(String, String)],
    ) -> Vec<String> {
        let unit = self.paths_of(name, kind);
        match self.flavor {
            Flavor::Launchd => vec![render_plist(
                &unit.id,
                &self.exe,
                kind,
                name,
                &unit.socket,
                egress,
                env,
            )],
            Flavor::Systemd => vec![
                render_systemd_socket(name, kind, &unit.socket, egress.map(|e| e.0)),
                render_systemd_service(&self.exe, kind, name, &unit.id, egress.map(|e| e.1), env),
            ],
        }
    }

    /// Makes `kinds` of sandbox `name` served by units, and removes the other kind's: writes the
    /// files and loads them only when they differ from what is there. `port` is the egress unit's,
    /// needed when `kinds` has one.
    pub fn sync(
        &self,
        name: &str,
        kinds: &[Kind],
        port: Option<u16>,
        paths: &Paths,
        env: &BTreeMap<String, String>,
    ) -> Result<()> {
        let Some(ctl) = self.active() else {
            return Ok(());
        };
        let mut to_load = Vec::new();
        // Only the egress unit owns a port, and logs: its failures are otherwise invisible. The
        // others serve one connection each on a socket path.
        let log = paths.egress(name).join("egress.log");
        let written = Kind::ALL.map(|kind| {
            if kinds.contains(&kind) {
                let egress = port
                    .filter(|_| kind == Kind::Egress)
                    .map(|p| (p, log.as_path()));
                let env = service_env(paths, env, self.flavor);
                self.write_units(ctl, name, kind, egress, &env)
                    .map(|unit| to_load.extend(unit))
            } else {
                self.remove_kind(ctl, name, kind)
            }
        });
        // One reload for every file written, then the loads.
        let mut loaded = Vec::new();
        if !to_load.is_empty() {
            loaded.push(ctl.refresh());
            loaded.extend(to_load.iter().map(|u| ctl.load(u)));
        }
        first_error(written.into_iter().chain(loaded))
    }

    /// Writes the unit files of `kind` unless they're current and loaded; returns the unit when
    /// it needs loading.
    fn write_units(
        &self,
        ctl: &dyn Control,
        name: &str,
        kind: Kind,
        egress: Option<(u16, &Path)>,
        env: &[(String, String)],
    ) -> Result<Option<UnitPaths>> {
        if kind == Kind::Egress && egress.is_none() {
            bail!("an egress unit needs a port");
        }
        if !crate::bridge::ensure_private_dir(&self.sock_dir) {
            bail!(
                "{} isn't a private directory owned by you",
                self.sock_dir.display()
            );
        }
        let unit = self.paths_of(name, kind);
        let texts = self.render(name, kind, egress, env);
        let current = |f: &PathBuf| fs::read_to_string(f).ok();
        if unit
            .files
            .iter()
            .zip(&texts)
            .all(|(f, t)| current(f).as_deref() == Some(t))
            && ctl.loaded(&unit)
        {
            return Ok(None);
        }
        for (f, t) in unit.files.iter().zip(&texts) {
            crate::config::write_atomic(f, t.as_bytes(), None, crate::config::Symlink::Replace)
                .with_context(|| format!("writing {}", f.display()))?;
        }
        Ok(Some(unit))
    }

    /// Restarts sandbox `name`'s egress process so it resolves its secrets again. Does nothing
    /// without a unit.
    pub fn restart_egress(&self, name: &str) -> Result<()> {
        let unit = self.paths_of(name, Kind::Egress);
        match self.active() {
            Some(ctl) if unit.files.iter().all(|f| f.exists()) => ctl.restart(&unit),
            _ => Ok(()),
        }
    }

    /// Unloads and deletes the units and sockets of sandbox `name`.
    pub fn remove(&self, name: &str) -> Result<()> {
        let Some(ctl) = self.active() else {
            return Ok(());
        };
        first_error(Kind::ALL.map(|kind| self.remove_kind(ctl, name, kind)))
    }

    fn remove_kind(&self, ctl: &dyn Control, name: &str, kind: Kind) -> Result<()> {
        let unit = self.paths_of(name, kind);
        let relays = (kind == Kind::Bridge).then(|| self.relay_slot_files(name));
        for slot in self
            .slot_files(name, kind)
            .into_iter()
            .chain(relays.into_iter().flatten())
        {
            let _ = fs::remove_file(slot);
        }
        let socket_kind = fs::symlink_metadata(&unit.socket).map(|m| m.file_type());
        let present = unit.files.iter().any(|f| f.exists())
            || socket_kind.as_ref().is_ok_and(FileTypeExt::is_socket);
        if !present {
            return Ok(());
        }
        ctl.unload(&unit);
        let mut result = Ok(());
        for f in &unit.files {
            if let Err(e) = fs::remove_file(f)
                && e.kind() != std::io::ErrorKind::NotFound
            {
                result = Err(anyhow::Error::new(e).context(format!("removing {}", f.display())));
            }
        }
        if socket_kind.is_ok_and(|t| t.is_socket()) {
            let _ = fs::remove_file(&unit.socket);
        }
        ctl.settle();
        result
    }

    /// The `(sandbox, kind)` of every unit of this namespace.
    pub fn units(&self) -> Vec<(String, Kind)> {
        if !self.usable() {
            return Vec::new();
        }
        let Ok(dir) = fs::read_dir(&self.unit_dir) else {
            return Vec::new();
        };
        let (prefix, suffix, sep) = match self.flavor {
            Flavor::Launchd => (format!("dev.smolbento.{}.", self.ns), ".plist", '.'),
            Flavor::Systemd => (format!("smolbento-{}-", self.ns), ".socket", '-'),
        };
        let mut out: Vec<(String, Kind)> = dir
            .filter_map(|e| {
                let file = e.ok()?.file_name().into_string().ok()?;
                let mid = file.strip_prefix(&prefix)?.strip_suffix(suffix)?;
                let (name, kind) = mid.rsplit_once(sep)?;
                Some((name.to_string(), Kind::parse(kind)?))
            })
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.as_str().cmp(b.1.as_str())));
        out
    }

    /// Sandbox names with units here and not in `live` (machines smolvm has).
    pub fn orphans(&self, live: &[String]) -> Vec<String> {
        let mut names: Vec<String> = self
            .units()
            .into_iter()
            .map(|(n, _)| n)
            .filter(|n| !live.contains(n))
            .collect();
        names.dedup();
        names
    }
}

/// The first error of `results`, each already run (collected, not a lazy iterator).
fn first_error(results: impl IntoIterator<Item = Result<()>>) -> Result<()> {
    results.into_iter().find(Result::is_err).unwrap_or(Ok(()))
}

/// The environment `_serve` needs: this setup's directories and settings, `HOME` and `PATH`
/// (a launchd job has almost none), what the bridge reads to see a display, and on Linux the
/// `SSH_AUTH_SOCK` of the user who last ran smolbento (systemd's user session has none; launchd
/// supplies macOS's own).
fn service_env(
    paths: &Paths,
    env: &BTreeMap<String, String>,
    flavor: Flavor,
) -> Vec<(String, String)> {
    let mut out: BTreeMap<String, String> = BTreeMap::new();
    let dirs = [
        ("SMOLBENTO_CONFIG_DIR", &paths.config),
        ("SMOLBENTO_CACHE_DIR", &paths.cache),
        ("SMOLBENTO_DATA_DIR", &paths.data),
    ];
    for (k, v) in dirs {
        out.insert(k.into(), v.display().to_string());
    }
    for (k, v) in env {
        // Not the log level: changing it would rewrite the units, restarting their processes.
        let kept = (k.starts_with("SMOLBENTO_") && k != crate::log::VAR)
            || [
                "HOME",
                "PATH",
                "DISPLAY",
                "WAYLAND_DISPLAY",
                "SSH_CONNECTION",
            ]
            .contains(&k.as_str())
            || (flavor == Flavor::Systemd && k == "SSH_AUTH_SOCK");
        if kept && !v.is_empty() && !out.contains_key(k) {
            out.insert(k.clone(), v.clone());
        }
    }
    out.into_iter().collect()
}

/// The smolbento the units run: `argv0` as invoked (made absolute, or found on `PATH`), not
/// `current_exe`'s canonical path, which under Homebrew is a versioned Cellar path.
fn resolve_exe(argv0: Option<&OsStr>, env: &BTreeMap<String, String>) -> PathBuf {
    let current = || std::env::current_exe().unwrap_or_else(|_| "smolbento".into());
    let Some(argv0) = argv0.filter(|a| !a.is_empty()) else {
        return current();
    };
    let p = Path::new(argv0);
    if p.components().count() > 1 {
        return std::path::absolute(p).unwrap_or_else(|_| current());
    }
    env.get("PATH")
        .into_iter()
        .flat_map(|path| std::env::split_paths(path))
        .map(|d| d.join(p))
        .find(|c| is_executable(c))
        .unwrap_or_else(current)
}

fn is_executable(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

/// Runs `program args`; its stderr is the error when it fails.
fn run(program: &str, args: &[&str]) -> Result<()> {
    let out = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .output()
        .with_context(|| format!("running {program}"))?;
    if !out.status.success() {
        bail!(
            "{program} {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

mod launchd;
mod systemd;

use launchd::{Launchctl, render_plist};
use systemd::{Systemctl, render_systemd_service, render_systemd_socket};

#[cfg(test)]
pub(crate) mod fake;

#[cfg(test)]
mod tests;
