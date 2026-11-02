//! The Libra binary: supply the program's own identity and hand everything else to `libra-server`.
//!
//! No enforcement logic lives here. Every security rule belongs to a crate under `crates/`; the
//! stack they are assembled into, and everything that has to happen before it serves, is
//! `libra-server`'s. With a subcommand, the binary administers the API key store or prints a
//! configuration file instead of serving, and one hidden subcommand writes the command-line
//! reference from the argument definitions themselves.

mod config_command;
mod markdown;

use crate::config_command::ConfigCommand;
use clap::{Parser, Subcommand};
use human_panic::setup_panic;
use libra_config::{ConfigError, Loaded, pending::PendingConfig};
use libra_identity_key_commands::command::{AdminCommand, run};
use libra_server::{
    extensions::Extensions,
    launch::{administer, launch},
};
use std::{io::stdout, process::ExitCode};

/// Libra: an NGSI-LD authentication and authorization proxy.
///
/// With no subcommand, Libra serves.
#[derive(Parser, Debug)]
#[command(version = libra_build_info::long_version(), about, long_about = None)]
#[command(disable_help_subcommand = true)]
#[command(styles = clap_themes::CLAP_V3)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

/// What the binary can do besides serving.
#[derive(Subcommand, Debug)]
enum Command {
    /// The key-store administration commands, `key` and `principal`.
    #[command(flatten)]
    Admin(AdminCommand),
    /// Work with the configuration file.
    #[command(subcommand)]
    Config(ConfigCommand),
    /// Write the command-line reference to `reference/cli.md` beneath the working directory.
    #[command(hide = true)]
    Markdown,
}

/// The name this binary reports itself by in startup failures.
const BINARY: &str = "libra";

#[tokio::main]
async fn main() -> ExitCode {
    setup_panic!(libra_build_info::panic_metadata());

    match Cli::parse().command {
        None => launch(BINARY, assemble).await,
        Some(Command::Admin(command)) => {
            administer(BINARY, assemble, |config| async move {
                run(command, config.key_store.enabled_path(), &mut stdout().lock()).await
            })
            .await
        }
        Some(Command::Config(command)) => match config_command::run(&command, &mut stdout().lock()) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{BINARY}: {error}");
                ExitCode::FAILURE
            }
        },
        Some(Command::Markdown) => match markdown::generate_markdown::<Cli>("reference/cli.md") {
            Ok(path) => {
                eprintln!("wrote the command-line reference to {}", path.display());
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("{BINARY}: {error}");
                ExitCode::FAILURE
            }
        },
    }
}

/// Accepts the configuration. This binary adds nothing to the proxy and claims no section, so a
/// section in the file that the proxy does not define stops it here.
fn assemble(pending: PendingConfig) -> Result<(Extensions, Loaded), ConfigError> {
    Ok((Extensions::default(), pending.finish()?))
}
