//! The guest shims. POSIX `sh`; each sends its request with `curl` over the bridge socket (the body
//! is the raw URL or text) and falls back when that fails or there is no `curl`. Option handling
//! follows sbx's shims where it's simple.

use crate::sandbox::sh_quote;

use super::GUEST_SOCKET;

/// What the shims (except `wl-paste`) start with: their name (`pbcopy` and `clip.exe` are links
/// to `wl-copy`); `post PATH`, which sends stdin to the host (`-m 10`: a listener that never
/// answers can't hang the agent); `need`, for an option's value; and `copy`, which sends stdin to
/// the host clipboard. With `trim` set, `copy` drops one trailing newline; that goes through a
/// shell variable, so NUL bytes are lost on that path only (clipboard text has none).
fn prelude() -> String {
    format!(
        r#"#!/bin/sh
# smolbento: reaches the host browser and clipboard while a session is attached.
n=${{0##*/}}
post() {{
  command -v curl >/dev/null 2>&1 &&
    curl -sf -m 10 --unix-socket {GUEST_SOCKET} -X POST --data-binary @- "http://bridge/$1" >/dev/null 2>&1
}}
bad() {{ echo "$n: unsupported option $1" >&2; exit 1; }}
need() {{ [ "$1" -gt 1 ] || {{ echo "$n: option requires an argument" >&2; exit 1; }}; }}
copy() {{
  if [ -n "$trim" ]; then
    t=$(cat; printf x); t=${{t%x}}; t=${{t%"
"}}
    printf %s "$t" | post copy
  else
    post copy
  fi || {{ echo "$n: failed to write host clipboard" >&2; exit 1; }}
}}
trim=
"#
    )
}

const XDG_OPEN: &str = r#"[ $# -eq 1 ] || { echo "usage: $n URL" >&2; exit 1; }
printf %s "$1" | post open && exit 0
echo "Open this URL in your browser: $1"
"#;

/// `-t`: text types only, as sbx's `wl-copy`.
const WL_COPY: &str = r#"text=
while [ $# -gt 0 ]; do
  case $1 in
    -n|--trim-newline) trim=1 ;;
    -p|--primary|-f|--foreground|-o|--paste-once) ;;
    -t|--type) need $#; shift; case $1 in text/*|TEXT|STRING|UTF8_STRING) ;; *) bad "$1" ;; esac ;;
    --) shift; text=1; break ;;
    -*) bad "$1" ;;
    *) text=1; break ;;
  esac
  shift
done
if [ -n "$text" ]; then printf %s "$*" | copy; else copy; fi
"#;

/// Reading the host clipboard isn't supported: no output. A whole script, without the prelude.
const WL_PASTE: &str = "#!/bin/sh\n# smolbento: host clipboard reads are not supported.\nexit 1\n";

const XCLIP: &str = r#"while [ $# -gt 0 ]; do
  case $1 in
    -i|-in) ;;
    -o|-out) exit 1 ;;
    -sel*|-d|-display) need $#; shift ;;
    -t|-target) need $#; shift; case $1 in text/*|TEXT|STRING|UTF8_STRING) ;; *) bad "$1" ;; esac ;;
    -r|-rmlastnl) trim=1 ;;
    -q|-quiet|-silent|-verbose|-noutf8) ;;
    *) bad "$1" ;;
  esac
  shift
done
copy
"#;

/// Without `-i` or `-o`, xsel reads when stdin isn't a terminal.
const XSEL: &str = r#"mode=
for a in "$@"; do
  case $a in
    --input) mode=in ;;
    --output) mode=out ;;
    --clipboard|--primary|--secondary|--nodetach) ;;
    --*) bad "$a" ;;
    -?*)
      f=${a#-}
      while [ -n "$f" ]; do
        c=${f%"${f#?}"}; f=${f#?}
        case $c in i) mode=in ;; o) mode=out ;; b|p|s|n) ;; *) bad "-$c" ;; esac
      done ;;
    *) bad "$a" ;;
  esac
done
[ -n "$mode" ] || { [ -t 0 ] && mode=out || mode=in; }
if [ "$mode" = out ]; then
  echo "xsel: host clipboard text reads are not supported" >&2
  exit 1
fi
copy
"#;

/// The shims' file names, and the links to `wl-copy`.
const SHIMS: [(&str, &str); 5] = [
    ("xdg-open", XDG_OPEN),
    ("wl-copy", WL_COPY),
    ("wl-paste", WL_PASTE),
    ("xclip", XCLIP),
    ("xsel", XSEL),
];
const LINKS: [&str; 2] = ["pbcopy", "clip.exe"];

/// As root at every start of a bridged sandbox: writes the shims into `/usr/local/bin`, replacing
/// what's there.
pub fn install_cmd() -> String {
    install_script("/usr/local/bin")
}

/// `install_cmd` into `dir` (tests use a temp dir). Files are removed first so a write can't
/// follow a link to some other program.
fn install_script(dir: &str) -> String {
    let names: Vec<&str> = SHIMS.iter().map(|(n, _)| *n).chain(LINKS).collect();
    let mut s = format!(
        "set -e\nmkdir -p {d}\ncd {d}\nrm -f {}\n",
        names.join(" "),
        d = sh_quote(dir)
    );
    let prelude = prelude();
    for (name, body) in SHIMS {
        let prelude = if body.starts_with("#!") { "" } else { &prelude };
        s += &format!("cat > {name} <<'SMOLBENTO_SHIM'\n{prelude}{body}SMOLBENTO_SHIM\n");
    }
    let files: Vec<&str> = SHIMS.iter().map(|(n, _)| *n).collect();
    s += &format!("chmod 0755 {}\n", files.join(" "));
    for link in LINKS {
        s += &format!("ln -s wl-copy {link}\n");
    }
    s
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};

    use super::*;

    /// The shims installed into a temp dir, and a `bin` dir for `PATH` holding `cat` and, unless
    /// `curl` is `None`, a fake `curl` that records its argv and body then exits with `curl`.
    struct Guest {
        dir: tempfile::TempDir,
    }

    impl Guest {
        fn new(curl: Option<i32>) -> Guest {
            let dir = tempfile::tempdir().unwrap();
            let shims = dir.path().join("shims");
            let out = Command::new("sh")
                .arg("-c")
                .arg(install_script(&shims.display().to_string()))
                .output()
                .unwrap();
            assert!(out.status.success(), "{out:?}");
            let bin = dir.path().join("bin");
            std::fs::create_dir(&bin).unwrap();
            let cat = Command::new("sh")
                .args(["-c", "command -v cat"])
                .output()
                .unwrap();
            let cat = String::from_utf8(cat.stdout).unwrap();
            std::os::unix::fs::symlink(cat.trim(), bin.join("cat")).unwrap();
            if let Some(code) = curl {
                let log = dir.path().display();
                let fake = format!(
                    "#!/bin/sh\nprintf '%s\\n' \"$@\" > {log}/args\ncat > {log}/body\nexit {code}\n"
                );
                std::fs::write(bin.join("curl"), fake).unwrap();
                std::fs::set_permissions(bin.join("curl"), PermissionsExt::from_mode(0o755))
                    .unwrap();
            }
            Guest { dir }
        }

        fn path(&self, name: &str) -> PathBuf {
            self.dir.path().join(name)
        }

        /// Runs a shim with `input` on stdin: (exit code, stdout, stderr).
        fn run(&self, shim: &str, args: &[&str], input: &str) -> (i32, String, String) {
            let mut child = Command::new(self.path("shims").join(shim))
                .args(args)
                .env("PATH", self.path("bin"))
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            // A shim that exits early may not read its stdin.
            let _ = child.stdin.take().unwrap().write_all(input.as_bytes());
            let out = child.wait_with_output().unwrap();
            let text = |b: Vec<u8>| String::from_utf8(b).unwrap();
            (
                out.status.code().unwrap(),
                text(out.stdout),
                text(out.stderr),
            )
        }

        /// What the fake `curl` was sent: its argv and body.
        fn sent(&self) -> Option<(Vec<String>, String)> {
            let args = std::fs::read_to_string(self.path("args")).ok()?;
            let body = std::fs::read_to_string(self.path("body")).unwrap();
            Some((args.lines().map(String::from).collect(), body))
        }
    }

    fn request(path: &str) -> Vec<String> {
        [
            "-sf",
            "-m",
            "10",
            "--unix-socket",
            GUEST_SOCKET,
            "-X",
            "POST",
            "--data-binary",
            "@-",
        ]
        .iter()
        .map(|s| s.to_string())
        .chain([format!("http://bridge/{path}")])
        .collect()
    }

    #[test]
    fn install_writes_executable_shims_and_links_and_replaces_whats_there() {
        let g = Guest::new(None);
        let shims = g.path("shims");
        for name in ["xdg-open", "wl-copy", "wl-paste", "xclip", "xsel"] {
            let mode = std::fs::metadata(shims.join(name))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o755, "{name}");
        }
        for link in ["pbcopy", "clip.exe"] {
            assert_eq!(
                std::fs::read_link(shims.join(link)).unwrap(),
                Path::new("wl-copy")
            );
        }
        // A second start replaces them, and never writes through a link to another program.
        let other = g.path("other");
        std::fs::write(&other, "keep").unwrap();
        std::fs::remove_file(shims.join("xsel")).unwrap();
        std::os::unix::fs::symlink(&other, shims.join("xsel")).unwrap();
        let out = Command::new("sh")
            .arg("-c")
            .arg(install_script(&shims.display().to_string()))
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
        assert_eq!(std::fs::read_to_string(&other).unwrap(), "keep");
        assert!(
            std::fs::read_to_string(shims.join("xsel"))
                .unwrap()
                .contains("xsel")
        );
    }

    #[test]
    fn install_creates_a_missing_dir() {
        let d = tempfile::tempdir().unwrap();
        let shims = d.path().join("usr/local/bin");
        let out = Command::new("sh")
            .arg("-c")
            .arg(install_script(&shims.display().to_string()))
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
        assert!(shims.join("xdg-open").exists());
    }

    #[test]
    fn xdg_open_sends_the_url_and_is_silent() {
        let g = Guest::new(Some(0));
        let url = "https://example.com/a?b=c&d='e'";
        assert_eq!(g.run("xdg-open", &[url], ""), (0, "".into(), "".into()));
        assert_eq!(g.sent(), Some((request("open"), url.into())));
    }

    #[test]
    fn xdg_open_prints_the_url_when_the_bridge_fails_or_curl_is_missing() {
        let url = "http://localhost:3000/";
        let fallback = format!("Open this URL in your browser: {url}\n");
        // 7: no listener; 28: curl's `-m` timeout, a listener that never answered.
        for g in [Guest::new(Some(7)), Guest::new(Some(28)), Guest::new(None)] {
            assert_eq!(
                g.run("xdg-open", &[url], ""),
                (0, fallback.clone(), "".into())
            );
        }
        let (code, _, err) = Guest::new(Some(0)).run("xdg-open", &[], "");
        assert_eq!((code, err.as_str()), (1, "usage: xdg-open URL\n"));
    }

    #[test]
    fn copies_send_stdin_as_is() {
        for (shim, args) in [
            ("wl-copy", vec![]),
            ("pbcopy", vec![]),
            ("clip.exe", vec![]),
            ("xclip", vec!["-selection", "clipboard"]),
            ("xclip", vec!["-sel", "c", "-i", "-t", "text/plain"]),
            ("xsel", vec!["-bi"]),
            ("xsel", vec!["--clipboard", "--input"]),
            ("xsel", vec!["-b"]),
        ] {
            let g = Guest::new(Some(0));
            let text = "two\nlines\n\n";
            assert_eq!(
                g.run(shim, &args, text),
                (0, "".into(), "".into()),
                "{shim} {args:?}"
            );
            assert_eq!(
                g.sent(),
                Some((request("copy"), text.into())),
                "{shim} {args:?}"
            );
        }
    }

    #[test]
    fn trim_drops_one_trailing_newline() {
        for (shim, flag) in [
            ("wl-copy", "-n"),
            ("wl-copy", "--trim-newline"),
            ("xclip", "-rmlastnl"),
        ] {
            let g = Guest::new(Some(0));
            assert_eq!(g.run(shim, &[flag], "a\n\n").0, 0);
            assert_eq!(g.sent().unwrap().1, "a\n", "{shim} {flag}");
        }
    }

    #[test]
    fn wl_copy_copies_its_arguments() {
        let g = Guest::new(Some(0));
        assert_eq!(g.run("wl-copy", &["-n", "hello", "world"], "ignored").0, 0);
        assert_eq!(g.sent().unwrap().1, "hello world");
    }

    #[test]
    fn a_failed_copy_says_so() {
        for g in [Guest::new(Some(22)), Guest::new(Some(28)), Guest::new(None)] {
            for shim in ["wl-copy", "pbcopy", "xclip", "xsel"] {
                let args: &[&str] = if shim == "xsel" { &["-i"] } else { &[] };
                assert_eq!(
                    g.run(shim, args, "x"),
                    (
                        1,
                        "".into(),
                        format!("{shim}: failed to write host clipboard\n")
                    )
                );
            }
        }
    }

    #[test]
    fn unsupported_options_fail_without_sending() {
        for (shim, args, bad) in [
            ("wl-copy", vec!["--clear"], "--clear"),
            ("wl-copy", vec!["-t", "image/png"], "image/png"),
            ("xclip", vec!["-filter"], "-filter"),
            ("xclip", vec!["file.txt"], "file.txt"),
            ("xsel", vec!["-ba"], "-a"),
            ("xsel", vec!["--append"], "--append"),
        ] {
            let g = Guest::new(Some(0));
            assert_eq!(
                g.run(shim, &args, "x"),
                (1, "".into(), format!("{shim}: unsupported option {bad}\n")),
                "{shim} {args:?}"
            );
            assert_eq!(g.sent(), None);
        }
    }

    #[test]
    fn a_value_option_given_last_needs_its_value() {
        for (shim, args) in [
            ("wl-copy", vec!["-t"]),
            ("wl-copy", vec!["-n", "--type"]),
            ("xclip", vec!["-selection"]),
            ("xclip", vec!["-i", "-t"]),
            ("xclip", vec!["-d"]),
        ] {
            let g = Guest::new(Some(0));
            assert_eq!(
                g.run(shim, &args, "x"),
                (
                    1,
                    "".into(),
                    format!("{shim}: option requires an argument\n")
                ),
                "{shim} {args:?}"
            );
            assert_eq!(g.sent(), None);
        }
    }

    #[test]
    fn reads_print_nothing_and_fail() {
        let g = Guest::new(Some(0));
        assert_eq!(g.run("wl-paste", &[], ""), (1, "".into(), "".into()));
        assert_eq!(g.run("xclip", &["-o"], ""), (1, "".into(), "".into()));
        assert_eq!(
            g.run("xclip", &["-selection", "clipboard", "-out"], ""),
            (1, "".into(), "".into())
        );
        let msg = "xsel: host clipboard text reads are not supported\n";
        assert_eq!(g.run("xsel", &["-bo"], ""), (1, "".into(), msg.into()));
        assert_eq!(g.run("xsel", &["--output"], ""), (1, "".into(), msg.into()));
        assert_eq!(g.sent(), None);
    }
}
