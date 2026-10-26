use std::process::ExitCode;

fn main() -> ExitCode {
    match smolbento::cli::main(std::env::args_os()) {
        Ok(code) => ExitCode::from(u8::try_from(code).unwrap_or(1)),
        Err(err) => {
            eprintln!("sbt: {err:#}");
            ExitCode::from(smolbento::cli::exit_code(&err))
        }
    }
}
