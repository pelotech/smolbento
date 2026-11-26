//! systemd --user: a `.socket` and `.service` per unit, loaded with `systemctl`.

use super::*;

/// A systemd word: quoted, with the specifiers and variable syntax escaped.
fn systemd_quote(s: &str) -> String {
    let s = s
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('%', "%%")
        .replace('$', "$$");
    format!("\"{s}\"")
}

pub(super) fn render_systemd_socket(
    sandbox: &str,
    kind: Kind,
    socket: &Path,
    port: Option<u16>,
) -> String {
    if let Some(port) = port {
        return format!(
            "[Unit]\nDescription=smolbento egress socket for sandbox {}\n\n[Socket]\n\
             ListenStream=127.0.0.1:{port}\nAccept=no\n\n[Install]\nWantedBy=sockets.target\n",
            sandbox.replace('%', "%%"),
        );
    }
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

pub(super) fn render_systemd_service(
    exe: &Path,
    kind: Kind,
    sandbox: &str,
    socket_unit: &str,
    log: Option<&Path>,
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
    // Egress is one process that serves the socket systemd hands it, not a connection on stdin.
    let stdin = if kind == Kind::Egress {
        ""
    } else {
        "StandardInput=socket\n"
    };
    let stderr = log.map_or_else(
        || "null".to_string(),
        |l| format!("append:{}", l.display().to_string().replace('%', "%%")),
    );
    format!(
        "[Unit]\nDescription=smolbento {} connection for sandbox {}\nPartOf={}\n\n[Service]\n\
         ExecStart={} _serve {} {}\n{stdin}StandardOutput=null\nStandardError={stderr}\n{kill}{env}",
        kind.as_str(),
        sandbox.replace('%', "%%"),
        socket_unit.replace('%', "%%"),
        systemd_quote(&exe.display().to_string()),
        kind.as_str(),
        systemd_quote(sandbox),
    )
}

pub(super) struct Systemctl;

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

    fn restart(&self, unit: &UnitPaths) -> Result<()> {
        // The socket's id is `<base>.socket`; its process is `<base>.service`.
        let base = unit.id.strip_suffix(".socket").unwrap_or(&unit.id);
        let service = format!("{base}.service");
        run("systemctl", &["--user", "restart", &service])
    }

    fn settle(&self) {
        let _ = run("systemctl", &["--user", "daemon-reload"]);
    }
}
