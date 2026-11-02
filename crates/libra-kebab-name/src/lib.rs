//! A validated lowercase kebab-case name.
//!
//! Libra's own formats name things in kebab-case, and a name is the whole contract between a file
//! and the crate that reads it. A name that could be spelled two ways is a name nobody can grep for,
//! so the grammar is narrow and checked once, here, for every kind of name that uses it.

use derive_more::{Display, Into};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use thiserror::Error;

/// Longest name Libra will accept.
const MAX_NAME_LENGTH: usize = 64;

/// A name is not lowercase kebab-case.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("'{value}' is not a valid name: {reason}")]
pub struct KebabNameError {
    /// What was written.
    pub value: String,
    /// Why it was refused.
    pub reason: &'static str,
}

/// A non-empty lowercase kebab-case name that starts with a letter.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Display, Into, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
#[display("{_0}")]
#[into(String)]
pub struct KebabName(Cow<'static, str>);

impl KebabName {
    /// Wraps a name known at compile time.
    ///
    /// Checked in a constant context: a name that is not valid fails the build that contains it, so
    /// a restriction or a section cannot be shipped under a name no file could use.
    ///
    /// # Panics
    ///
    /// Panics during constant evaluation, which is a compile error, if `value` is not a valid name.
    #[must_use]
    pub const fn from_static(value: &'static str) -> Self {
        assert!(
            reason(value).is_none(),
            "a name must be non-empty lowercase kebab-case, start with a letter, and not exceed 64 characters"
        );

        Self(Cow::Borrowed(value))
    }

    /// Checks and wraps a name read from a file.
    ///
    /// # Errors
    ///
    /// Returns [`KebabNameError`] if the name is empty, too long, or not lowercase kebab-case
    /// starting with a letter.
    pub fn new(value: impl Into<String>) -> Result<Self, KebabNameError> {
        let value = value.into();

        match reason(&value) {
            Some(reason) => Err(KebabNameError { value, reason }),
            None => Ok(Self(Cow::Owned(value))),
        }
    }

    /// The name as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for KebabName {
    type Error = KebabNameError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

/// Why `value` is not a legal name, or `None` if it is.
const fn reason(value: &str) -> Option<&'static str> {
    let bytes = value.as_bytes();

    if bytes.is_empty() {
        return Some("it is empty");
    }
    if bytes.len() > MAX_NAME_LENGTH {
        return Some("it is longer than 64 characters");
    }
    if !bytes[0].is_ascii_lowercase() {
        return Some("it does not start with a lowercase letter");
    }

    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if !(byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-') {
            return Some("it contains something other than lowercase letters, digits and '-'");
        }
        index += 1;
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn a_kebab_case_name_is_accepted() {
        assert_eq!(KebabName::new("aggregation").unwrap().as_str(), "aggregation");
        assert_eq!(KebabName::new("min-period-2").unwrap().as_str(), "min-period-2");
    }

    #[test]
    fn a_name_that_could_be_another_spelling_is_refused() {
        // `Aggregation`, `aggregation_x` and ` aggregation` would each be a second way to write a
        // name, and a file that mixes them is a file nobody can grep.
        for hostile in [
            "",
            "Aggregation",
            "aggregation_x",
            " aggregation",
            "1aggregation",
            "-aggregation",
            "agg regation",
            "agg.regation",
        ] {
            assert!(KebabName::new(hostile).is_err(), "{hostile:?} must not be a name");
        }
    }

    #[test]
    fn a_refusal_carries_what_was_written_and_why() {
        let refused = KebabName::new("Policy").unwrap_err();

        assert_eq!(refused.value, "Policy");
        assert_eq!(refused.reason, "it does not start with a lowercase letter");
    }

    #[test]
    fn a_name_longer_than_the_limit_is_refused() {
        assert!(KebabName::new("a".repeat(MAX_NAME_LENGTH)).is_ok());
        assert!(KebabName::new("a".repeat(MAX_NAME_LENGTH + 1)).is_err());
    }

    #[test]
    fn a_static_name_equals_the_same_name_read_from_a_file() {
        const STATIC: KebabName = KebabName::from_static("aggregation");

        assert_eq!(STATIC, KebabName::new("aggregation").unwrap());
    }

    #[test]
    fn a_name_is_displayed_as_written() {
        assert_eq!(KebabName::from_static("aggregation").to_string(), "aggregation");
    }

    #[test]
    fn a_name_round_trips_through_a_file_key() {
        let parsed: BTreeMap<KebabName, i64> = toml::from_str("aggregation = 1").unwrap();

        assert_eq!(parsed.get(&KebabName::from_static("aggregation")), Some(&1));
        assert!(toml::from_str::<BTreeMap<KebabName, i64>>("Aggregation = 1").is_err());
    }
}
