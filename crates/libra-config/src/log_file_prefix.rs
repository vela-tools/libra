//! The first part of a log file's name.

use derive_more::{Display, Into};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use thiserror::Error;

/// A prefix that cannot start the name of a file inside the log directory.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("logging.file.file-prefix '{prefix}' is not usable: {reason}")]
pub struct InvalidLogFilePrefix {
    /// What was written.
    pub prefix: String,
    /// Why it was refused.
    pub reason: &'static str,
}

/// A non-empty file name prefix with no path separator in it.
///
/// The prefix is joined onto the log directory, so one that carries a separator or is `..` would
/// write outside the directory the operator named.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Display, Into, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
#[display("{_0}")]
#[into(String)]
pub struct LogFilePrefix(Cow<'static, str>);

impl LogFilePrefix {
    /// The prefix Libra uses when it is not given one.
    #[must_use]
    pub const fn libra() -> Self {
        Self(Cow::Borrowed("libra"))
    }

    /// Checks and wraps a prefix read from a file.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidLogFilePrefix`] if the prefix is empty, is `.` or `..`, or contains a path
    /// separator or a NUL.
    pub fn new(prefix: String) -> Result<Self, InvalidLogFilePrefix> {
        match reason(&prefix) {
            Some(reason) => Err(InvalidLogFilePrefix { prefix, reason }),
            None => Ok(Self(Cow::Owned(prefix))),
        }
    }

    /// The prefix as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for LogFilePrefix {
    type Error = InvalidLogFilePrefix;

    fn try_from(prefix: String) -> Result<Self, Self::Error> {
        Self::new(prefix)
    }
}

/// Why `prefix` cannot start a file name, or `None` if it can.
fn reason(prefix: &str) -> Option<&'static str> {
    if prefix.is_empty() {
        return Some("it is empty");
    }
    if matches!(prefix, "." | "..") {
        return Some("it names a directory");
    }
    if prefix.contains(['/', '\\', '\0']) {
        return Some("it contains a path separator or a NUL");
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_ordinary_prefix_is_accepted() {
        assert_eq!(LogFilePrefix::new("libra-test".to_owned()).unwrap().as_str(), "libra-test");
        assert_eq!(LogFilePrefix::libra().as_str(), "libra");
    }

    #[test]
    fn a_prefix_that_could_leave_the_log_directory_is_refused() {
        for hostile in ["", ".", "..", "../x", "a/b", "a\\b", "a\0b"] {
            assert!(LogFilePrefix::new(hostile.to_owned()).is_err(), "{hostile:?} must not be a prefix");
        }
    }
}
