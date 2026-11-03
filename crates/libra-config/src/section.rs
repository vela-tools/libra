//! A configuration section that some other crate owns.
//!
//! The sections [`crate::Config`] defines are the ones every build reads. A crate that adds
//! behaviour to a build, such as a response cache, owns its own section instead, so this crate
//! carries no key that only that build understands.

use derive_more::Display;
use serde::{Serialize, de::DeserializeOwned};
use std::borrow::Cow;
use thiserror::Error;

/// Longest section name Libra will accept.
const MAX_NAME_LENGTH: usize = 64;

/// A section name is not lowercase kebab-case.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("'{value}' is not a valid section name: {reason}")]
pub struct SectionNameError {
    /// What was written.
    pub value: String,
    /// Why it was refused.
    pub reason: &'static str,
}

/// The name of a top-level section of the configuration file.
///
/// Kebab-case like every other name in the file, and the same name whether the section is written
/// as a table or set through `LIBRA__<SECTION>__<KEY>`. A name that could be spelled two ways is a
/// name nobody can grep for, so the grammar is narrow: non-empty, at most 64 characters, lowercase
/// letters, digits and `-`, starting with a letter.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Display)]
#[display("{_0}")]
pub struct SectionName(Cow<'static, str>);

impl SectionName {
    /// Wraps a name known at compile time.
    ///
    /// Checked in a constant context: a name that is not valid fails the build that contains it, so
    /// a section cannot be shipped under a name no file could use.
    ///
    /// # Panics
    ///
    /// Panics during constant evaluation, which is a compile error, if `value` is not a valid name.
    #[must_use]
    pub const fn from_static(value: &'static str) -> Self {
        assert!(
            reason(value).is_none(),
            "a section name must be non-empty lowercase kebab-case, start with a letter, and not exceed 64 characters"
        );

        Self(Cow::Borrowed(value))
    }

    /// Checks and wraps a name read from outside.
    ///
    /// # Errors
    ///
    /// Returns [`SectionNameError`] if the name is empty, too long, or not lowercase kebab-case
    /// starting with a letter.
    pub fn new(value: impl Into<String>) -> Result<Self, SectionNameError> {
        let value = value.into();

        match reason(&value) {
            Some(reason) => Err(SectionNameError { value, reason }),
            None => Ok(Self(Cow::Owned(value))),
        }
    }

    /// The name as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Why `value` is not a legal section name, or `None` if it is.
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

/// A section of the configuration file owned by the crate that reads it.
///
/// `Default` supplies every key the file leaves out, so a section is complete whether the file
/// mentions it or not. The type should deny unknown fields, which is what makes a mistyped key one
/// level down a startup error and not a default.
pub trait ConfigSection: Default + Serialize + DeserializeOwned {
    /// The name of the section.
    const NAME: SectionName;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_kebab_case_name_is_accepted() {
        assert_eq!(SectionName::new("policy-api").unwrap().as_str(), "policy-api");
        assert_eq!(SectionName::new("min-period-2").unwrap().as_str(), "min-period-2");
    }

    #[test]
    fn a_name_that_could_be_another_spelling_is_refused() {
        // `PolicyApi`, `policy_api` and ` policy-api` would each be a second way to write a name,
        // and a file that mixes them is a file nobody can grep.
        for hostile in ["", "PolicyApi", "policy_api", " policy-api", "1policy", "-policy", "policy api", "policy.api"] {
            assert!(SectionName::new(hostile).is_err(), "{hostile:?} must not be a name");
        }
    }

    #[test]
    fn a_refusal_carries_what_was_written_and_why() {
        let refused = SectionName::new("Policy").unwrap_err();

        assert_eq!(refused.value, "Policy");
        assert_eq!(refused.reason, "it does not start with a lowercase letter");
    }

    #[test]
    fn a_name_longer_than_the_limit_is_refused() {
        assert!(SectionName::new("a".repeat(MAX_NAME_LENGTH)).is_ok());
        assert!(SectionName::new("a".repeat(MAX_NAME_LENGTH + 1)).is_err());
    }

    #[test]
    fn a_static_section_name_equals_the_same_name_read_from_outside() {
        const NAME: SectionName = SectionName::from_static("cache");

        assert_eq!(NAME, SectionName::new("cache").unwrap());
        assert_eq!(NAME.to_string(), "cache");
    }
}
