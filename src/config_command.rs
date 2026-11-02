//! `libra config`: the configuration file, written out rather than read.

use clap::Subcommand;
use libra_config::template::TEMPLATE;
use std::io::{self, Write};

/// A configuration file command.
#[derive(Subcommand, Debug)]
pub enum ConfigCommand {
    /// Print a configuration file with every key at its built-in default.
    ///
    /// The file is optional; Libra runs on the same defaults without one. Redirect the output to
    /// start one, `libra config init > libra.toml`, then keep only the keys you change.
    Init,
}

/// Runs the command, writing its output to `out`.
///
/// # Errors
///
/// Returns the error `out` gave while being written to.
pub fn run(command: &ConfigCommand, out: &mut impl Write) -> io::Result<()> {
    match command {
        ConfigCommand::Init => out.write_all(TEMPLATE.as_bytes()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_prints_the_template_unchanged() {
        let mut out = Vec::new();
        run(&ConfigCommand::Init, &mut out).unwrap();

        assert_eq!(String::from_utf8(out).unwrap(), TEMPLATE);
    }
}
