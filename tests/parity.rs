//! Every sbx command line in tests/parity/sbx-commands.txt must parse.

use clap::Parser;
use smolbento::cli::Cli;

#[test]
fn sbx_command_lines_parse() {
    let lines = include_str!("parity/sbx-commands.txt");
    let mut failures = Vec::new();
    for line in lines
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        let words = shlex::split(line).expect("valid shell words");
        if let Err(e) = Cli::try_parse_from(std::iter::once("sbt".to_string()).chain(words)) {
            failures.push(format!("{line}\n{e}"));
        }
    }
    assert!(
        failures.is_empty(),
        "unparsed sbx command lines:\n{}",
        failures.join("\n\n")
    );
}
