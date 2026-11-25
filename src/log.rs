//! `SMOLBENTO_LOG`: tracing spans and events on stderr, each span with its time when it closes.
//! Off unless it or `-D` is set; never on `ctx.out`, so stdout and `--json` stay clean.

use tracing::Subscriber;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::filter::ParseError;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::fmt::format::FmtSpan;

/// An `EnvFilter`: `info`, `debug`, `smolbento=debug,smolvm_credentials=info`.
pub const VAR: &str = "SMOLBENTO_LOG";

/// Crates that carry request bytes stay at `info` unless the filter names them: their debug and
/// trace output can hold header values, swapped credentials among them.
const CAPPED: &str = "h2=info,hyper=info,hyper_util=info,reqwest=info,rustls=info";

/// Installs the subscriber when `SMOLBENTO_LOG` is set, or at `info` for `-D` (`debug`). Called
/// once, after `_serve` moved stderr off the guest's socket.
pub fn init(debug: bool) {
    let set = std::env::var(VAR).ok();
    match subscriber(wanted(set.as_deref(), debug), std::io::stderr) {
        None => {}
        Some(Ok(s)) => {
            let _ = tracing::subscriber::set_global_default(s);
        }
        Some(Err(e)) => crate::warning!("{VAR}: {e}; logging is off"),
    }
}

/// The filter: `SMOLBENTO_LOG` when set, else `info` with `-D`.
fn wanted(set: Option<&str>, debug: bool) -> Option<&str> {
    set.filter(|v| !v.trim().is_empty())
        .or(debug.then_some("info"))
}

/// The subscriber for a `SMOLBENTO_LOG` of `value`, writing to `writer`; none when unset or empty.
pub fn subscriber<W>(
    value: Option<&str>,
    writer: W,
) -> Option<Result<impl Subscriber + Send + Sync + use<W>, ParseError>>
where
    W: for<'a> MakeWriter<'a> + Send + Sync + 'static,
{
    let value = value.filter(|v| !v.trim().is_empty())?;
    // A later directive for the same target wins, so the user's own setting overrides a cap.
    Some(
        EnvFilter::builder()
            .parse(format!("{CAPPED},{value}"))
            .map(|filter| {
                tracing_subscriber::fmt()
                    .with_env_filter(filter)
                    .with_writer(writer)
                    .with_span_events(FmtSpan::CLOSE)
                    .finish()
            }),
    )
}

#[cfg(test)]
pub(crate) use tests::logged;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smolvm::{ProcessRunner, Runner};
    use crate::testutil::*;
    use std::sync::{Arc, Mutex};

    /// A writer the test can read back.
    #[derive(Clone, Default)]
    struct Buf(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Buf {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for Buf {
        type Writer = Buf;
        fn make_writer(&'a self) -> Buf {
            self.clone()
        }
    }

    impl Buf {
        fn text(&self) -> String {
            String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
        }
    }

    /// Runs `f` with a `SMOLBENTO_LOG` of `value`; returns what it logged.
    pub(crate) fn logged<T>(value: &str, f: impl FnOnce() -> T) -> (T, String) {
        let buf = Buf::default();
        let sub = subscriber(Some(value), buf.clone()).unwrap().unwrap();
        let out = tracing::subscriber::with_default(sub, f);
        (out, buf.text())
    }

    #[test]
    fn off_unless_set() {
        assert_eq!(wanted(None, false), None);
        assert_eq!(wanted(Some(""), false), None);
        assert_eq!(wanted(None, true), Some("info"));
        assert_eq!(wanted(Some("debug"), true), Some("debug"));
        assert!(subscriber(None, Buf::default()).is_none());
        assert!(subscriber(Some(" "), Buf::default()).is_none());
        assert!(
            subscriber(Some("no=such=level"), Buf::default())
                .unwrap()
                .is_err()
        );
    }

    #[test]
    fn request_byte_crates_are_capped_unless_named() {
        let enabled = |filter| {
            logged(
                filter,
                || tracing::enabled!(target: "h2", tracing::Level::DEBUG),
            )
            .0
        };
        assert!(!enabled("trace"));
        assert!(enabled("trace,h2=debug"));
    }

    #[test]
    fn logging_leaves_command_output_alone() {
        // The create's report, with its temp dir's name made the same.
        let create = |t: &mut TestEnv| {
            creatable_as(t, "claude-proj");
            t.sbt(&["create", "claude", "."]).unwrap();
            let tmp = t.ctx.cwd.parent().unwrap().file_name().unwrap();
            t.stdout().replace(tmp.to_str().unwrap(), "TMP")
        };
        let plain = create(&mut test_env(&[]));
        let mut t = test_env(&[]);
        let (logged_out, log) = logged("debug", || create(&mut t));
        assert_eq!(logged_out, plain);
        assert!(log.contains("provision{sandbox=claude-proj}"), "{log}");
        assert!(log.contains("close"), "{log}");
    }

    #[test]
    fn a_smolvm_span_names_the_call_but_no_secret_or_env_value() {
        let secret = "s3cr3t-token-value";
        let runner = ProcessRunner::new("true");
        let args: Vec<String> = [
            "machine",
            "create",
            "-n",
            "m",
            "--credential",
            "gh_token=GH_TOKEN@github.com",
            "-e",
            &format!("TOKEN={secret}"),
            "--label",
            &format!("sbx.long={}", "x".repeat(100)),
            "--",
            "gh",
            "--with-token",
            "ghp_x",
        ]
        .map(String::from)
        .to_vec();
        let env = [("GH_TOKEN".to_string(), secret.to_string())];
        let (out, log) = logged("trace", || runner.run_with_env(&args, &env, &[]).unwrap());
        assert_eq!(out.code, 0);
        assert!(log.contains("smolvm"), "{log}");
        assert!(
            log.contains("--credential gh_token=GH_TOKEN@github.com"),
            "{log}"
        );
        assert!(log.contains("-e TOKEN=…"), "{log}");
        assert!(log.contains("code=0"), "{log}");
        assert!(log.contains("time.busy"), "{log}");
        assert!(!log.contains(secret), "{log}");
        assert!(!log.contains("xxxx"), "{log}");
        assert!(log.contains("-- gh (+2 args)"), "{log}");
        assert!(!log.contains("ghp_x"), "{log}");
    }
}
