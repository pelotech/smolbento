//! launchd: a plist per unit, loaded with `launchctl`.

use super::*;

fn xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

pub(super) fn render_plist(
    label: &str,
    exe: &Path,
    kind: Kind,
    sandbox: &str,
    socket: &Path,
    egress: Option<(u16, &Path)>,
    env: &[(String, String)],
) -> String {
    let log = egress.map_or_else(String::new, |(_, l)| {
        format!(
            "  <key>StandardErrorPath</key>\n  <string>{}</string>\n",
            xml(&l.display().to_string())
        )
    });
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
    // An egress job owns a loopback port and keeps its process; the others serve one connection each.
    let (inetd, listener) = match egress {
        Some((port, _)) => (
            String::new(),
            format!(
                "      <key>SockNodeName</key>\n      <string>127.0.0.1</string>\n      \
                 <key>SockServiceName</key>\n      <string>{port}</string>\n      \
                 <key>SockType</key>\n      <string>stream</string>\n      \
                 <key>SockFamily</key>\n      <string>IPv4</string>\n"
            ),
        ),
        None => (
            "  <key>inetdCompatibility</key>\n  <dict>\n    <key>Wait</key>\n    <false/>\n  </dict>\n"
                .to_string(),
            format!(
                "      <key>SockPathName</key>\n      <string>{}</string>\n      \
                 <key>SockPathMode</key>\n      <integer>384</integer>\n",
                xml(&socket.display().to_string())
            ),
        ),
    };
    // ThrottleInterval is launchd's minimum: the default 10 s made each `kickstart -k` wait it out.
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
{log}{inetd}  <key>ThrottleInterval</key>
  <integer>1</integer>
  <key>Sockets</key>
  <dict>
    <key>Listeners</key>
    <dict>
{listener}    </dict>
  </dict>
</dict>
</plist>
"#,
        label = xml(label),
    )
}

pub(super) struct Launchctl {
    pub(super) uid: u32,
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

    fn restart(&self, unit: &UnitPaths) -> Result<()> {
        run(
            "launchctl",
            &["kickstart", "-k", &format!("{}/{}", self.domain(), unit.id)],
        )
    }

    fn unload(&self, unit: &UnitPaths) {
        let _ = run(
            "launchctl",
            &["bootout", &format!("{}/{}", self.domain(), unit.id)],
        );
    }
}
