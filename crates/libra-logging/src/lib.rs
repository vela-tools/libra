//! Tracing initialisation for Libra.
//!
//! Two independent sinks, console and file, each with its own level, format, and display options.
//! `libra-config` describes what the operator asked for; this crate is the only place that knows
//! how to turn that into a subscriber.

use libra_config::logging::{ConsoleLogging, FileLogging, LogFormat, LogLevel, LogRotation, Logging};
use std::{io, path::PathBuf};
use tracing::Subscriber;
use tracing_appender::{
    non_blocking::{NonBlocking, WorkerGuard},
    rolling::{InitError, RollingFileAppender, Rotation},
};
use tracing_subscriber::{
    Layer,
    Registry,
    filter::LevelFilter,
    fmt,
    fmt::MakeWriter,
    layer::SubscriberExt,
    registry::LookupSpan,
    util::{SubscriberInitExt, TryInitError},
};

/// What can go wrong while setting logging up.
#[derive(Debug, thiserror::Error)]
pub enum LoggingError {
    /// Both sinks were disabled. Refused rather than defaulted: a proxy that decides
    /// authorization silently is worse than one that will not start.
    #[error("at least one logging output, console or file, must be enabled")]
    NoOutputEnabled,

    /// The log directory could not be opened for writing.
    ///
    /// `RollingFileAppender::new` panics here. A directory that does not exist or cannot be written
    /// is a deployment mistake to report at startup, not a crash.
    #[error("cannot write logs to '{}': {source}", .directory.display())]
    FileSink {
        /// The directory the configuration named.
        directory: PathBuf,
        /// Why it could not be used.
        #[source]
        source: InitError,
    },

    /// A global subscriber was already installed.
    #[error("failed to install the tracing subscriber")]
    Init(#[from] TryInitError),
}

/// Keeps the non-blocking file writer alive.
///
/// Dropping this flushes and closes the file appender, so the composition root must hold it for
/// as long as the process runs. Without it, the last writes before shutdown are lost.
#[derive(Debug)]
pub struct LoggerGuard {
    /// Held only to be dropped: its drop is the flush.
    _worker: Option<WorkerGuard>,
}

/// Display options shared by both sinks.
struct LayerOptions {
    format: LogFormat,
    ansi: bool,
    file_line: bool,
    target: bool,
    thread_ids: bool,
    level: LogLevel,
}

impl From<&ConsoleLogging> for LayerOptions {
    fn from(config: &ConsoleLogging) -> Self {
        Self {
            format: config.format,
            ansi: config.ansi,
            file_line: config.file_line,
            target: config.target,
            thread_ids: config.thread_ids,
            level: config.level,
        }
    }
}

impl From<&FileLogging> for LayerOptions {
    fn from(config: &FileLogging) -> Self {
        Self {
            format: config.format,
            // Never ANSI in a file: the escape codes survive into the log and break every reader
            // that is not a terminal.
            ansi: false,
            file_line: config.file_line,
            target: config.target,
            thread_ids: config.thread_ids,
            level: config.level,
        }
    }
}

const fn level_filter(level: LogLevel) -> LevelFilter {
    match level {
        LogLevel::Trace => LevelFilter::TRACE,
        LogLevel::Debug => LevelFilter::DEBUG,
        LogLevel::Info => LevelFilter::INFO,
        LogLevel::Warn => LevelFilter::WARN,
        LogLevel::Error => LevelFilter::ERROR,
    }
}

const fn rotation(policy: LogRotation) -> Rotation {
    match policy {
        LogRotation::Minutely => Rotation::MINUTELY,
        LogRotation::Hourly => Rotation::HOURLY,
        LogRotation::Daily => Rotation::DAILY,
        LogRotation::Never => Rotation::NEVER,
    }
}

/// Builds one formatting layer. The three formats differ only in the builder method that selects
/// them, so everything else is configured once.
fn make_layer<S, W>(options: &LayerOptions, writer: W) -> Box<dyn Layer<S> + Send + Sync + 'static>
where
    S: Subscriber + for<'span> LookupSpan<'span>,
    W: for<'writer> MakeWriter<'writer> + Send + Sync + 'static,
{
    let base = fmt::layer()
        .with_ansi(options.ansi)
        .with_file(options.file_line)
        .with_line_number(options.file_line)
        .with_target(options.target)
        .with_thread_ids(options.thread_ids)
        .with_writer(writer);

    let filter = level_filter(options.level);

    match options.format {
        LogFormat::Compact => Box::new(base.compact().with_filter(filter)),
        LogFormat::Pretty => Box::new(base.pretty().with_filter(filter)),
        LogFormat::Json => Box::new(base.json().with_filter(filter)),
    }
}

/// Builds the file layer and the guard that keeps its writer alive.
fn make_file_layer<S>(config: &FileLogging) -> Result<(Box<dyn Layer<S> + Send + Sync + 'static>, WorkerGuard), LoggingError>
where
    S: Subscriber + for<'span> LookupSpan<'span>,
{
    let appender = RollingFileAppender::builder()
        .rotation(rotation(config.rotation))
        .filename_prefix(config.file_prefix.as_str())
        .build(&config.directory)
        .map_err(|source| LoggingError::FileSink {
            directory: config.directory.clone(), // the error owns the directory, the configuration is borrowed
            source,
        })?;
    let (writer, worker): (NonBlocking, WorkerGuard) = tracing_appender::non_blocking(appender);

    Ok((make_layer(&LayerOptions::from(config), writer), worker))
}

/// Installs the global subscriber described by `config`.
///
/// The returned guard must be kept alive for the lifetime of the process.
///
/// # Errors
///
/// Returns [`LoggingError::NoOutputEnabled`] if neither sink is enabled, and
/// [`LoggingError::Init`] if a global subscriber is already installed.
pub fn init(config: &Logging) -> Result<LoggerGuard, LoggingError> {
    // Collected into a Vec rather than chained with `.with()`: chaining changes the subscriber
    // type at every step, so a boxed layer built for `Registry` does not fit the second slot.
    // A Vec of boxed layers is itself a layer, which keeps both sinks independent.
    let mut layers: Vec<Box<dyn Layer<Registry> + Send + Sync + 'static>> = Vec::new();
    let mut worker = None;

    if config.console.enabled {
        layers.push(make_layer(&LayerOptions::from(&config.console), io::stdout));
    }

    if config.file.enabled {
        let (layer, file_worker) = make_file_layer(&config.file)?;
        layers.push(layer);
        worker = Some(file_worker);
    }

    if layers.is_empty() {
        return Err(LoggingError::NoOutputEnabled);
    }

    Registry::default().with(layers).try_init()?;

    Ok(LoggerGuard { _worker: worker })
}

#[cfg(test)]
mod tests {
    use super::*;
    use libra_config::log_file_prefix::LogFilePrefix;
    use pretty_assertions::assert_eq;
    use std::fs;
    use tracing::{error, subscriber::with_default};

    #[test]
    fn refuses_to_start_with_every_sink_disabled() {
        let config = Logging {
            console: ConsoleLogging {
                enabled: false,
                ..ConsoleLogging::default()
            },
            file: FileLogging {
                enabled: false,
                ..FileLogging::default()
            },
        };

        let error = init(&config).expect_err("logging with no sink must fail");

        assert!(matches!(error, LoggingError::NoOutputEnabled));
        assert!(error.to_string().contains("at least one logging output"));
    }

    #[test]
    fn a_log_directory_that_cannot_be_written_is_an_error_not_a_panic() {
        let directory = tempfile::tempdir().unwrap();
        // A path under a regular file can never be created as a directory.
        let blocker = directory.path().join("not-a-directory");
        fs::write(&blocker, b"x").unwrap();
        let config = FileLogging {
            enabled: true,
            directory: blocker.join("logs"),
            ..FileLogging::default()
        };

        let error = make_file_layer::<Registry>(&config).err().expect("the sink cannot be opened");

        assert!(matches!(error, LoggingError::FileSink { .. }));
        assert!(error.to_string().contains("not-a-directory"));
    }

    #[test]
    fn a_file_sink_writes_where_it_was_told_to() {
        // Exercises the appender and the guard without installing a global subscriber, which a
        // second test in the same process could not undo.
        let directory = tempfile::tempdir().unwrap();
        let config = FileLogging {
            enabled: true,
            directory: directory.path().to_path_buf(),
            file_prefix: LogFilePrefix::new("libra-test".to_owned()).expect("a valid prefix"),
            rotation: LogRotation::Never,
            ..FileLogging::default()
        };

        let (layer, worker) = make_file_layer::<Registry>(&config).expect("a writable directory");
        let subscriber = Registry::default().with(layer);
        with_default(subscriber, || error!("written to the file sink"));
        drop(worker);

        let written = fs::read_dir(directory.path()).unwrap().count();
        assert_eq!(written, 1, "the appender should have created exactly one log file");
    }
}
