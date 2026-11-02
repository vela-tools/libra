//! `[logging]`: console and file sinks.
//!
//! These types describe what the operator asked for. Turning them into a tracing subscriber is
//! `libra-logging`'s job, so this crate does not depend on the tracing stack.

use crate::log_file_prefix::LogFilePrefix;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Log level.
#[derive(Deserialize, Serialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Trace,
    Debug,
    #[default]
    Info,
    Warn,
    Error,
}

/// Log output format.
#[derive(Deserialize, Serialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    /// Compact single-line format.
    #[default]
    Compact,
    /// Pretty multi-line format, for development.
    Pretty,
    /// JSON, for log aggregation.
    Json,
}

/// Log file rotation policy.
#[derive(Deserialize, Serialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum LogRotation {
    /// Rotate every minute. For testing.
    Minutely,
    /// Rotate every hour.
    Hourly,
    /// Rotate every day.
    #[default]
    Daily,
    /// Never rotate.
    Never,
}

/// Console logging configuration.
#[derive(Deserialize, Serialize, Clone, Debug)]
#[serde(default, rename_all = "kebab-case", deny_unknown_fields)]
pub struct ConsoleLogging {
    /// Write logs to stdout.
    pub enabled: bool,
    /// Level for console output.
    pub level: LogLevel,
    /// Format for console output.
    pub format: LogFormat,
    /// Emit ANSI colour codes.
    pub ansi: bool,
    /// Include the source file and line.
    pub file_line: bool,
    /// Include the target, that is the module path.
    pub target: bool,
    /// Include thread identifiers.
    pub thread_ids: bool,
}

impl Default for ConsoleLogging {
    fn default() -> Self {
        Self {
            enabled: true,
            level: LogLevel::Info,
            format: LogFormat::Compact,
            ansi: true,
            file_line: false,
            target: true,
            thread_ids: false,
        }
    }
}

/// File logging configuration.
#[derive(Deserialize, Serialize, Clone, Debug)]
#[serde(default, rename_all = "kebab-case", deny_unknown_fields)]
pub struct FileLogging {
    /// Write logs to a file.
    pub enabled: bool,
    /// Level for file output.
    pub level: LogLevel,
    /// Format for file output.
    pub format: LogFormat,
    /// Directory to store log files in.
    pub directory: PathBuf,
    /// Prefix for log file names, so `libra` becomes `libra.2026-01-15.log`.
    pub file_prefix: LogFilePrefix,
    /// Rotation policy.
    pub rotation: LogRotation,
    /// Include the source file and line.
    pub file_line: bool,
    /// Include the target, that is the module path.
    pub target: bool,
    /// Include thread identifiers.
    pub thread_ids: bool,
}

impl Default for FileLogging {
    fn default() -> Self {
        Self {
            enabled: false,
            level: LogLevel::Info,
            format: LogFormat::Json,
            directory: PathBuf::from("logs"),
            file_prefix: LogFilePrefix::libra(),
            rotation: LogRotation::Daily,
            file_line: true,
            target: true,
            thread_ids: false,
        }
    }
}

/// Logging configuration, with independent console and file settings.
#[derive(Deserialize, Serialize, Clone, Debug, Default)]
#[serde(default, rename_all = "kebab-case", deny_unknown_fields)]
pub struct Logging {
    /// Console output.
    pub console: ConsoleLogging,
    /// File output.
    pub file: FileLogging,
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn console_is_on_by_default_and_file_is_not() {
        let logging = Logging::default();

        assert!(logging.console.enabled);
        assert_eq!(logging.console.level, LogLevel::Info);
        assert!(logging.console.ansi);

        assert!(!logging.file.enabled);
        assert_eq!(logging.file.directory, PathBuf::from("logs"));
        assert_eq!(logging.file.file_prefix, LogFilePrefix::libra());
        assert_eq!(logging.file.rotation, LogRotation::Daily);
    }
}
