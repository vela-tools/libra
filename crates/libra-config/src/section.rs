//! A configuration section that some other crate owns.
//!
//! The sections [`crate::Config`] defines are the ones every build reads. A crate that adds
//! behaviour to a build, such as a response cache, owns its own section instead, so this crate
//! carries no key that only that build understands.

use derive_more::Display;
use libra_kebab_name::{KebabName, KebabNameError};
use serde::{Serialize, de::DeserializeOwned};

/// The name of a top-level section of the configuration file.
///
/// Kebab-case like every other name in the file, and the same name whether the section is written
/// as a table or set through `LIBRA__<SECTION>__<KEY>`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Display)]
pub struct SectionName(KebabName);

impl SectionName {
    /// Wraps a name known at compile time.
    ///
    /// # Panics
    ///
    /// Panics during constant evaluation, which is a compile error, if `value` is not a valid name.
    #[must_use]
    pub const fn from_static(value: &'static str) -> Self {
        Self(KebabName::from_static(value))
    }

    /// Checks and wraps a name read from outside.
    ///
    /// # Errors
    ///
    /// Returns [`KebabNameError`] if the name is not lowercase kebab-case.
    pub fn new(value: impl Into<String>) -> Result<Self, KebabNameError> {
        KebabName::new(value).map(Self)
    }

    /// The name as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
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
    fn a_section_name_is_a_kebab_case_name() {
        assert_eq!(SectionName::new("policy-api").unwrap().as_str(), "policy-api");
        assert!(SectionName::new("policy_api").is_err());
        assert!(SectionName::new("PolicyApi").is_err());
    }

    #[test]
    fn a_static_section_name_equals_the_same_name_read_from_outside() {
        const NAME: SectionName = SectionName::from_static("cache");

        assert_eq!(NAME, SectionName::new("cache").unwrap());
        assert_eq!(NAME.to_string(), "cache");
    }
}
