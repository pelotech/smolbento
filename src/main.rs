use std::process::ExitCode;

fn main() -> ExitCode {
    // Rust starts with SIGPIPE ignored, so writing to a closed pipe (`sbt ls | head -1`) errors and
    // print!/clap panic. Restore the default so the process just ends, like other Unix tools.
    // SAFETY: called before any threads start; resets one signal disposition to its default.
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) };
    match smolbento::cli::main(std::env::args_os()) {
        Ok(code) => ExitCode::from(u8::try_from(code).unwrap_or(1)),
        Err(err) => {
            eprintln!("sbt: {err:#}");
            ExitCode::from(smolbento::cli::exit_code(&err))
        }
    }
}
