//! Generation of the command-line reference from the clap definitions, so the reference cannot
//! drift from the argument definitions it documents.

use clap::CommandFactory;
use std::{fs::File, io, io::Write, path::PathBuf};
use thiserror::Error;

/// Renders the command-line reference for `T` from its clap definitions and writes it to
/// `output_path`, returning the path written.
///
/// # Errors
///
/// Returns [`MarkdownError`] when the file cannot be created or written.
pub fn generate_markdown<T: CommandFactory>(output_path: &str) -> Result<PathBuf, MarkdownError> {
    let markdown = render::<T>();

    let mut file = File::create(output_path).map_err(|source| MarkdownError::Create {
        source,
        path: PathBuf::from(output_path),
    })?;

    file.write_all(markdown.as_bytes()).map_err(|source| MarkdownError::Write {
        source,
        path: PathBuf::from(output_path),
    })?;

    Ok(PathBuf::from(output_path))
}

/// Renders the command-line reference for `T`.
///
/// clap-markdown separates a name from its help with a spaced em dash and has no option for it, so
/// the separator is rewritten to the colon the rest of the documentation uses.
fn render<T: CommandFactory>() -> String {
    clap_markdown::help_markdown::<T>().replace(" \u{2014} ", ": ")
}

/// Why the command-line reference could not be written.
#[derive(Debug, Error)]
pub enum MarkdownError {
    /// The reference file could not be created.
    #[error("cannot create {path}")]
    Create {
        /// The underlying I/O failure.
        #[source]
        source: io::Error,
        /// The path the reference was written to.
        path: PathBuf,
    },
    /// The reference file could not be written to.
    #[error("cannot write {path}")]
    Write {
        /// The underlying I/O failure.
        #[source]
        source: io::Error,
        /// The path the reference was written to.
        path: PathBuf,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{Parser, Subcommand};

    /// A command with a subcommand, an option and a positional argument, the three shapes the
    /// reference lists with a separator.
    #[derive(Parser)]
    struct Sample {
        #[command(subcommand)]
        command: SampleCommand,
    }

    #[derive(Subcommand)]
    enum SampleCommand {
        /// Revoke a key
        Revoke {
            /// The key's id
            id: String,
            /// The principal the key belongs to
            #[arg(long)]
            principal: Option<String>,
        },
    }

    #[test]
    fn the_reference_separates_a_name_from_its_help_with_a_colon() {
        let markdown = render::<Sample>();

        assert!(!markdown.contains('\u{2014}'), "{markdown}");
        assert!(markdown.contains("* `revoke`: Revoke a key"), "{markdown}");
        assert!(markdown.contains("* `<ID>`: The key's id"), "{markdown}");
        assert!(markdown.contains("* `--principal <PRINCIPAL>`: The principal the key belongs to"), "{markdown}");
    }
}
