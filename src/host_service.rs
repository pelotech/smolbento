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
use crate::util::hex;

/// What a unit serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Agent,
    Bridge,
}

impl Kind {
    pub const ALL: [Kind; 2] = [Kind::Agent, Kind::Bridge];

    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Agent => "agent",
            Kind::Bridge => "bridge",
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

/// Socket paths must be shorter than this: macOS caps them at 104 bytes including the NUL.
const MAX_SOCKET_PATH: usize = 104;

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
            && self.socket_path(name, Kind::Bridge).as_os_str().len() < MAX_SOCKET_PATH
            && self.socket_path(name, Kind::Agent).as_os_str().len() < MAX_SOCKET_PATH
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
                UnitPaths {
                    files: vec![
                        self.unit_dir.join(format!("{base}.socket")),
                        self.unit_dir.join(format!("{base}@.service")),
                    ],
                    id: format!("{base}.socket"),
                    socket: self.socket_path(name, kind),
                }
            }
        }
    }

    fn render(&self, name: &str, kind: Kind, env: &[(String, String)]) -> Vec<String> {
        let unit = self.paths_of(name, kind);
        match self.flavor {
            Flavor::Launchd => vec![render_plist(
                &unit.id,
                &self.exe,
                kind,
                name,
                &unit.socket,
                env,
            )],
            Flavor::Systemd => vec![
                render_systemd_socket(name, kind, &unit.socket),
                render_systemd_service(&self.exe, kind, name, &unit.id, env),
            ],
        }
    }

    /// Makes `kinds` of sandbox `name` served by units, and removes the other kind's: writes the
    /// files and loads them only when they differ from what is there.
    pub fn sync(
        &self,
        name: &str,
        kinds: &[Kind],
        paths: &Paths,
        env: &BTreeMap<String, String>,
    ) -> Result<()> {
        let Some(ctl) = self.active() else {
            return Ok(());
        };
        let mut to_load = Vec::new();
        let written = Kind::ALL.map(|kind| {
            if kinds.contains(&kind) {
                self.write_units(ctl, name, kind, &service_env(paths, env, self.flavor))
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
        env: &[(String, String)],
    ) -> Result<Option<UnitPaths>> {
        if !crate::bridge::ensure_private_dir(&self.sock_dir) {
            bail!(
                "{} isn't a private directory owned by you",
                self.sock_dir.display()
            );
        }
        let unit = self.paths_of(name, kind);
        let texts = self.render(name, kind, env);
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
        let kept = k.starts_with("SMOLBENTO_")
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

fn xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn render_plist(
    label: &str,
    exe: &Path,
    kind: Kind,
    sandbox: &str,
    socket: &Path,
    env: &[(String, String)],
) -> String {
    let args = [
        exe.display().to_string(),
        "_serve".into(),
        kind.as_str().into(),
        sandbox.into(),
    ];
    let args: String = args
        .iter()
        .map(|a| format!("    <string>{}</string>\n", xml(a)))
        .collect();
    let env: String = env
        .iter()
        .map(|(k, v)| {
            format!(
                "    <key>{}</key>\n    <string>{}</string>\n",
                xml(k),
                xml(v)
            )
        })
        .collect();
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{label}</string>
  <key>ProgramArguments</key>
  <array>
{args}  </array>
  <key>EnvironmentVariables</key>
  <dict>
{env}  </dict>
  <key>inetdCompatibility</key>
  <dict>
    <key>Wait</key>
    <false/>
  </dict>
  <key>Sockets</key>
  <dict>
    <key>Listeners</key>
    <dict>
      <key>SockPathName</key>
      <string>{socket}</string>
      <key>SockPathMode</key>
      <integer>384</integer>
    </dict>
  </dict>
</dict>
</plist>
"#,
        label = xml(label),
        socket = xml(&socket.display().to_string()),
    )
}

/// A systemd word: quoted, with the specifiers and variable syntax escaped.
fn systemd_quote(s: &str) -> String {
    let s = s
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('%', "%%")
        .replace('$', "$$");
    format!("\"{s}\"")
}

fn render_systemd_socket(sandbox: &str, kind: Kind, socket: &Path) -> String {
    format!(
        "[Unit]\nDescription=smolbento {} socket for sandbox {}\n\n[Socket]\nListenStream={}\n\
         SocketMode=0600\nDirectoryMode=0700\nAccept=yes\nMaxConnections={}\n\n[Install]\nWantedBy=sockets.target\n",
        kind.as_str(),
        sandbox.replace('%', "%%"),
        socket.display().to_string().replace('%', "%%"),
        // systemd counts a process that a login relay keeps alive as a connection.
        MAX_CONNECTIONS + if kind == Kind::Bridge { RELAY_SLOTS } else { 0 },
    )
}

fn render_systemd_service(
    exe: &Path,
    kind: Kind,
    sandbox: &str,
    socket_unit: &str,
    env: &[(String, String)],
) -> String {
    let env: String = env
        .iter()
        .map(|(k, v)| format!("Environment={}\n", systemd_quote(&format!("{k}={v}"))))
        .collect();
    // The bridge spawns clipboard holders (wl-copy/xclip/xsel) and browsers that must outlive the
    // short-lived `_serve bridge` process; systemd's default control-group KillMode kills them on exit.
    let kill = if kind == Kind::Bridge {
        "KillMode=process\n"
    } else {
        ""
    };
    format!(
        "[Unit]\nDescription=smolbento {} connection for sandbox {}\nPartOf={}\n\n[Service]\n\
         ExecStart={} _serve {} {}\nStandardInput=socket\nStandardOutput=null\nStandardError=null\n{kill}{env}",
        kind.as_str(),
        sandbox.replace('%', "%%"),
        socket_unit.replace('%', "%%"),
        systemd_quote(&exe.display().to_string()),
        kind.as_str(),
        systemd_quote(sandbox),
    )
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

struct Launchctl {
    uid: u32,
}

impl Launchctl {
    fn domain(&self) -> String {
        format!("gui/{}", self.uid)
    }
}

impl Control for Launchctl {
    fn usable(&self) -> bool {
        run("launchctl", &["print", &self.domain()]).is_ok()
    }

    fn load(&self, unit: &UnitPaths) -> Result<()> {
        // Replaces a loaded one (its files changed); not loaded yet is an error to ignore.
        self.unload(unit);
        run(
            "launchctl",
            &[
                "bootstrap",
                &self.domain(),
                &unit.files[0].display().to_string(),
            ],
        )
    }

    fn loaded(&self, unit: &UnitPaths) -> bool {
        run(
            "launchctl",
            &["print", &format!("{}/{}", self.domain(), unit.id)],
        )
        .is_ok()
    }

    fn unload(&self, unit: &UnitPaths) {
        let _ = run(
            "launchctl",
            &["bootout", &format!("{}/{}", self.domain(), unit.id)],
        );
    }
}

struct Systemctl;

impl Control for Systemctl {
    fn usable(&self) -> bool {
        run("systemctl", &["--user", "show-environment"]).is_ok()
    }

    fn refresh(&self) -> Result<()> {
        run("systemctl", &["--user", "daemon-reload"])
    }

    fn load(&self, unit: &UnitPaths) -> Result<()> {
        run("systemctl", &["--user", "enable", &unit.id])?;
        run("systemctl", &["--user", "restart", &unit.id])
    }

    fn loaded(&self, unit: &UnitPaths) -> bool {
        run("systemctl", &["--user", "is-active", &unit.id]).is_ok()
    }

    fn unload(&self, unit: &UnitPaths) {
        let _ = run("systemctl", &["--user", "disable", "--now", &unit.id]);
    }

    fn settle(&self) {
        let _ = run("systemctl", &["--user", "daemon-reload"]);
    }
}

#[cfg(test)]
pub(crate) mod fake {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    /// Records the loads and unloads; never touches a service manager.
    #[derive(Clone, Default)]
    pub struct FakeControl(pub Rc<RefCell<Vec<String>>>);

    impl Control for FakeControl {
        fn usable(&self) -> bool {
            true
        }
        fn refresh(&self) -> Result<()> {
            self.0.borrow_mut().push("refresh".into());
            Ok(())
        }
        fn load(&self, u: &UnitPaths) -> Result<()> {
            self.0.borrow_mut().push(format!("load {}", u.id));
            Ok(())
        }
        fn loaded(&self, u: &UnitPaths) -> bool {
            let last = self
                .0
                .borrow()
                .iter()
                .rfind(|c| c.ends_with(&format!(" {}", u.id)))
                .cloned();
            last.is_some_and(|c| c.starts_with("load "))
        }
        fn unload(&self, u: &UnitPaths) {
            self.0.borrow_mut().push(format!("unload {}", u.id));
        }
        fn settle(&self) {
            self.0.borrow_mut().push("settle".into());
        }
    }

    impl FakeControl {
        pub fn calls(&self) -> Vec<String> {
            self.0.borrow().clone()
        }
    }

    /// Units under `dir`, as `flavor`, controlled by the returned fake.
    pub fn services(dir: &Path, flavor: Flavor, ns: &str) -> (HostServices, FakeControl) {
        let ctl = FakeControl::default();
        let s = HostServices::new(
            flavor,
            ns.into(),
            dir.join("units"),
            dir.join("sock"),
            "/usr/local/bin/sbt".into(),
            Box::new(ctl.clone()),
        );
        (s, ctl)
    }
}

#[cfg(test)]
mod tests {
    use super::fake::services;
    use super::*;

    fn paths(data: &str) -> Paths {
        Paths {
            config: "/c".into(),
            cache: "/k".into(),
            data: data.into(),
        }
    }

    fn envs(vars: &[(&str, &str)]) -> BTreeMap<String, String> {
        vars.iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn the_namespace_follows_the_data_dir() {
        let a = namespace(&paths("/d/a"));
        assert_eq!(a.len(), 8);
        assert_eq!(a, namespace(&paths("/d/a")));
        assert_ne!(a, namespace(&paths("/d/b")));
    }

    #[test]
    fn the_plist_has_the_socket_inetd_mode_and_the_serve_command() {
        let p = render_plist(
            "dev.smolbento.ab.s&1.agent",
            Path::new("/opt/bin/sbt"),
            Kind::Agent,
            "s&1",
            Path::new("/Users/me/Library/Application Support/smolbento/sock/x.sock"),
            &[("HOME".into(), "/Users/me".into())],
        );
        assert!(
            p.contains("<string>dev.smolbento.ab.s&amp;1.agent</string>"),
            "{p}"
        );
        assert!(p.contains("<string>/opt/bin/sbt</string>\n    <string>_serve</string>\n    <string>agent</string>\n    <string>s&amp;1</string>"), "{p}");
        assert!(
            p.contains("<key>SockPathMode</key>\n      <integer>384</integer>"),
            "{p}"
        );
        assert!(p.contains("<key>Wait</key>\n    <false/>"), "{p}");
        assert!(
            p.contains("Application Support/smolbento/sock/x.sock</string>"),
            "{p}"
        );
        assert!(
            p.contains("<key>HOME</key>\n    <string>/Users/me</string>"),
            "{p}"
        );
    }

    #[test]
    fn the_systemd_pair_accepts_per_connection_on_a_0600_socket() {
        let s = render_systemd_socket(
            "a%b",
            Kind::Bridge,
            Path::new("/run/user/1/smolbento/x.sock"),
        );
        for want in [
            "ListenStream=/run/user/1/smolbento/x.sock\n",
            "SocketMode=0600\n",
            "DirectoryMode=0700\n",
            "Accept=yes\n",
            // The connections, and the processes login relays keep alive.
            "MaxConnections=12\n",
            "WantedBy=sockets.target",
            "sandbox a%%b",
        ] {
            assert!(s.contains(want), "{want}: {s}");
        }
        let agent = render_systemd_socket("s1", Kind::Agent, Path::new("/run/a.sock"));
        assert!(agent.contains("MaxConnections=8\n"), "{agent}");
        let svc = render_systemd_service(
            Path::new("/opt/sbt"),
            Kind::Bridge,
            "s1",
            "smolbento-n-s1-bridge.socket",
            &[("K".into(), "a\"b$c%d".into())],
        );
        // Stopping the socket (`rm`) stops its connections, a lingering login relay's included.
        assert!(
            svc.contains("PartOf=smolbento-n-s1-bridge.socket\n"),
            "{svc}"
        );
        assert!(
            svc.contains("ExecStart=\"/opt/sbt\" _serve bridge \"s1\"\n"),
            "{svc}"
        );
        assert!(svc.contains("StandardInput=socket\n"), "{svc}");
        assert!(svc.contains("KillMode=process\n"), "{svc}");
        assert!(svc.contains("Environment=\"K=a\\\"b$$c%%d\"\n"), "{svc}");
    }

    #[test]
    fn the_service_env_keeps_dirs_settings_and_session_vars_only() {
        let env = envs(&[
            ("HOME", "/h"),
            ("PATH", "/bin"),
            ("SMOLBENTO_SSH_AGENT_SOCKET", "/a"),
            ("SMOLBENTO_DATA_DIR", "/ignored"),
            ("AWS_SECRET_ACCESS_KEY", "nope"),
            ("SSH_AUTH_SOCK", "/s"),
            ("DISPLAY", ""),
        ]);
        let linux = service_env(&paths("/d"), &env, Flavor::Systemd);
        let keys: Vec<&str> = linux.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(
            keys,
            [
                "HOME",
                "PATH",
                "SMOLBENTO_CACHE_DIR",
                "SMOLBENTO_CONFIG_DIR",
                "SMOLBENTO_DATA_DIR",
                "SMOLBENTO_SSH_AGENT_SOCKET",
                "SSH_AUTH_SOCK"
            ]
        );
        assert!(linux.contains(&("SMOLBENTO_DATA_DIR".into(), "/d".into())));
        let mac = service_env(&paths("/d"), &env, Flavor::Launchd);
        assert!(
            mac.iter().all(|(k, _)| k != "SSH_AUTH_SOCK"),
            "launchd supplies macOS's own"
        );
    }

    #[test]
    fn names_are_namespaced_and_listed_back() {
        for (flavor, file) in [
            (Flavor::Launchd, "dev.smolbento.ns1.my.box.agent.plist"),
            (Flavor::Systemd, "smolbento-ns1-my.box-agent.socket"),
        ] {
            let tmp = tempfile::tempdir().unwrap();
            let (s, _) = services(tmp.path(), flavor, "ns1");
            let (other, _) = services(tmp.path(), flavor, "ns2");
            s.sync("my.box", &[Kind::Agent], &paths("/d"), &envs(&[]))
                .unwrap();
            assert!(tmp.path().join("units").join(file).exists(), "{file}");
            assert_eq!(s.units(), [("my.box".to_string(), Kind::Agent)]);
            assert!(
                other.units().is_empty(),
                "another setup's units are invisible"
            );
            assert!(other.orphans(&[]).is_empty());
        }
    }

    #[test]
    fn sync_loads_once_and_again_only_when_the_text_changed() {
        let tmp = tempfile::tempdir().unwrap();
        let (s, ctl) = services(tmp.path(), Flavor::Launchd, "ns1");
        let sync = |env: &[(&str, &str)]| {
            s.sync("s1", &[Kind::Agent, Kind::Bridge], &paths("/d"), &envs(env))
                .unwrap()
        };
        sync(&[("PATH", "/bin")]);
        assert_eq!(
            ctl.calls(),
            [
                "refresh",
                "load dev.smolbento.ns1.s1.agent",
                "load dev.smolbento.ns1.s1.bridge"
            ]
        );
        sync(&[("PATH", "/bin")]);
        assert_eq!(ctl.calls().len(), 3, "unchanged: no reload");
        sync(&[("PATH", "/usr/bin")]);
        assert_eq!(
            ctl.calls().len(),
            6,
            "a changed PATH rewrites, refreshes once and reloads"
        );
    }

    #[test]
    fn sync_writes_unit_files_through_write_atomic() {
        let tmp = tempfile::tempdir().unwrap();
        let (s, _) = services(tmp.path(), Flavor::Systemd, "ns1");
        let link = tmp.path().join("units/real");
        std::fs::create_dir_all(tmp.path().join("units")).unwrap();
        std::fs::write(&link, "x").unwrap();
        let unit = s.paths_of("s1", Kind::Agent);
        std::os::unix::fs::symlink(&link, &unit.files[0]).unwrap();
        s.sync("s1", &[Kind::Agent], &paths("/d"), &envs(&[]))
            .unwrap();
        // Symlink::Replace: the link is replaced, never written through; no temp files remain.
        assert_eq!(std::fs::read_to_string(&link).unwrap(), "x");
        assert!(!unit.files[0].is_symlink());
        let leftovers = std::fs::read_dir(tmp.path().join("units"))
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".tmp")
            })
            .count();
        assert_eq!(leftovers, 0);
    }

    #[test]
    fn sync_loads_an_unchanged_unit_that_is_no_longer_loaded() {
        let tmp = tempfile::tempdir().unwrap();
        let (s, ctl) = services(tmp.path(), Flavor::Launchd, "ns1");
        let sync = || {
            s.sync("s1", &[Kind::Agent], &paths("/d"), &envs(&[]))
                .unwrap()
        };
        sync();
        // A reboot unloads launchd jobs that aren't in ~/Library/LaunchAgents (we don't write there).
        ctl.0
            .borrow_mut()
            .push("unload dev.smolbento.ns1.s1.agent".into());
        sync();
        assert_eq!(
            ctl.calls().last().unwrap(),
            "load dev.smolbento.ns1.s1.agent"
        );
        assert_eq!(ctl.calls().len(), 5);
    }

    #[test]
    fn sync_removes_the_kind_a_sandbox_no_longer_has() {
        let tmp = tempfile::tempdir().unwrap();
        let (s, _) = services(tmp.path(), Flavor::Systemd, "ns1");
        s.sync("s1", &[Kind::Agent, Kind::Bridge], &paths("/d"), &envs(&[]))
            .unwrap();
        s.sync("s1", &[Kind::Bridge], &paths("/d"), &envs(&[]))
            .unwrap();
        assert_eq!(s.units(), [("s1".to_string(), Kind::Bridge)]);
        let dir = tmp.path().join("units");
        assert!(!dir.join("smolbento-ns1-s1-agent@.service").exists());
        assert!(dir.join("smolbento-ns1-s1-bridge@.service").exists());
    }

    #[test]
    fn remove_unloads_and_deletes_units_and_sockets_of_that_sandbox_only() {
        use std::os::unix::net::UnixListener;
        let tmp = tempfile::tempdir().unwrap();
        let (s, ctl) = services(tmp.path(), Flavor::Launchd, "ns1");
        for n in ["s1", "s2"] {
            s.sync(n, &[Kind::Agent], &paths("/d"), &envs(&[])).unwrap();
        }
        // The socket launchd leaves behind after bootout.
        let sock = s.plan("s1").unwrap().agent;
        let _l = UnixListener::bind(&sock).unwrap();
        let slot = s.slot_files("s1", Kind::Agent).remove(0);
        fs::write(&slot, "").unwrap();
        s.remove("s1").unwrap();
        assert!(!sock.exists());
        assert!(!slot.exists(), "the slot files go too");
        assert_eq!(s.units(), [("s2".to_string(), Kind::Agent)]);
        assert!(
            ctl.calls()
                .contains(&"unload dev.smolbento.ns1.s1.agent".to_string())
        );
        assert!(
            !ctl.calls()
                .iter()
                .any(|c| c.contains("s2") && c.starts_with("unload"))
        );
    }

    #[test]
    fn the_sweep_removes_units_without_a_machine_and_keeps_the_rest() {
        let tmp = tempfile::tempdir().unwrap();
        let (s, _) = services(tmp.path(), Flavor::Systemd, "ns1");
        for n in ["live", "gone", "also-gone"] {
            s.sync(n, &[Kind::Agent, Kind::Bridge], &paths("/d"), &envs(&[]))
                .unwrap();
        }
        let live = vec!["live".to_string()];
        assert_eq!(s.orphans(&live), ["also-gone", "gone"]);
        for n in s.orphans(&live) {
            s.remove(&n).unwrap();
        }
        assert_eq!(s.units().len(), 2);
        assert!(s.orphans(&live).is_empty());
    }

    #[test]
    fn a_plan_needs_a_private_dir_and_a_short_path() {
        let tmp = tempfile::tempdir().unwrap();
        let (s, _) = services(tmp.path(), Flavor::Launchd, "ns1");
        let p = s.plan("s1").unwrap();
        assert!(p.agent.starts_with(tmp.path().join("sock")));
        assert_ne!(p.agent, p.bridge);
        assert_ne!(p.agent, s.plan("s2").unwrap().agent);
        let (other, _) = services(tmp.path(), Flavor::Launchd, "ns2");
        assert_ne!(
            p.agent,
            other.plan("s1").unwrap().agent,
            "namespaced sockets"
        );
        // Not private: no units.
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(tmp.path().join("sock"), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(s.plan("s1").is_none());
        assert!(
            s.sync("s1", &[Kind::Agent], &paths("/d"), &envs(&[]))
                .is_err()
        );
        // Too long.
        let long = tmp.path().join("x".repeat(120));
        let (s, _) = services(&long, Flavor::Launchd, "ns1");
        assert!(s.plan("s1").is_none());
    }

    #[test]
    fn a_disabled_host_does_nothing() {
        let s = HostServices::disabled();
        assert!(!s.usable());
        assert!(s.plan("s1").is_none());
        s.sync("s1", &[Kind::Agent], &paths("/d"), &envs(&[]))
            .unwrap();
        s.remove("s1").unwrap();
        assert!(s.units().is_empty());
    }

    #[test]
    fn the_binary_is_argv0_as_invoked() {
        let tmp = tempfile::tempdir().unwrap();
        let bin = tmp.path().join("sbt");
        fs::write(&bin, "#!/bin/sh\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&bin, fs::Permissions::from_mode(0o755)).unwrap();
        let env = envs(&[("PATH", &format!("/nonexistent:{}", tmp.path().display()))]);
        assert_eq!(resolve_exe(Some(OsStr::new("sbt")), &env), bin);
        assert_eq!(resolve_exe(Some(bin.as_os_str()), &envs(&[])), bin);
    }
}
