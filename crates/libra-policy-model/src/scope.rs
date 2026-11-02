//! Hierarchical scope restrictions.
//!
//! An NGSI-LD scope is a path, not a name: `/Madrid/Gardens/ParqueNorte`. It is not resolved
//! against a context and never becomes an IRI, so a scope pattern is compared as written, but it
//! is still checked when the policy loads, because a pattern with a wildcard in the wrong place
//! matches nothing and a policy that matches nothing is a policy that is not doing its job.

use crate::{error::ValueError, member_on_write::MemberOnWrite};
use derive_more::Display;
use serde::{Deserialize, Deserializer, Serialize, de::Error as DeError};

/// A scope pattern, in the syntax `scopeQ` uses.
///
/// `#` matches the remaining levels and may only be the last segment; `+` matches exactly one
/// level and may appear anywhere.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, Display)]
#[display("{_0}")]
#[serde(try_from = "String", into = "String")]
pub struct ScopePattern(String);

impl ScopePattern {
    /// Checks and wraps a scope pattern.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError::ScopePattern`] if the pattern does not start with `/`, holds a control
    /// character, has an empty segment, or places `#` anywhere but last.
    pub fn new(value: impl Into<String>) -> Result<Self, ValueError> {
        let value = value.into();

        let reason = check(&value);

        match reason {
            Some(reason) => Err(ValueError::ScopePattern { value, reason }),
            None => Ok(Self(value)),
        }
    }

    /// The pattern as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The pattern's segments, without the leading slash.
    pub fn segments(&self) -> impl Iterator<Item = &str> {
        self.0.trim_start_matches('/').split('/')
    }
}

/// Says why a scope pattern is unusable, or `None` if it is fine.
fn check(value: &str) -> Option<&'static str> {
    if !value.starts_with('/') {
        return Some("a scope is an absolute path and must start with '/'");
    }

    // No scope level admits one (ETSI GS CIM 009 v1.9.1 clauses 4.18 and 4.19), and a broker may
    // strip it, stop at it or refuse it, so the scope judged here need not be the one it stores.
    if value.chars().any(char::is_control) {
        return Some("it holds a control character");
    }

    let segments: Vec<&str> = value[1..].split('/').collect();

    if segments.iter().any(|segment| segment.is_empty()) {
        // `/a//b` and a trailing slash both produce a segment that can never match a level.
        return Some("it has an empty segment");
    }

    if segments
        .iter()
        .enumerate()
        .any(|(index, segment)| *segment == "#" && index != segments.len() - 1)
    {
        return Some("'#' matches the remaining levels, so it can only be the last segment");
    }

    None
}

impl TryFrom<String> for ScopePattern {
    type Error = ValueError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<ScopePattern> for String {
    fn from(pattern: ScopePattern) -> Self {
        pattern.0
    }
}

/// Which scopes a policy allows access to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ScopeRestriction {
    /// The scopes this policy allows. Must name at least one.
    #[serde(deserialize_with = "non_empty_patterns")]
    pub allowed: Vec<ScopePattern>,

    /// What a write payload that carries no scope meets under this restriction.
    #[serde(default)]
    pub scope_on_write: MemberOnWrite,
}

/// Rejects an empty scope allow list.
fn non_empty_patterns<'de, D>(deserializer: D) -> Result<Vec<ScopePattern>, D::Error>
where
    D: Deserializer<'de>,
{
    let patterns = Vec::<ScopePattern>::deserialize(deserializer)?;

    if patterns.is_empty() {
        return Err(DeError::custom(ValueError::EmptyAllowList {
            restriction: "a scope restriction",
        }));
    }

    Ok(patterns)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn a_well_formed_pattern_is_accepted() {
        assert!(ScopePattern::new("/Madrid/Gardens/ParqueNorte").is_ok());
        assert!(ScopePattern::new("/Madrid/Gardens/#").is_ok());
        assert!(ScopePattern::new("/Madrid/+/Parterre1").is_ok());
        assert!(ScopePattern::new("/Madrid").is_ok());
    }

    #[test]
    fn a_pattern_that_could_never_match_is_refused_at_load() {
        // Each of these parses as a string and matches nothing. Left until enforcement, the policy
        // would appear to be in force while allowing access to no scope at all.
        for broken in ["Madrid/Gardens", "", "/", "/Madrid//Gardens", "/Madrid/Gardens/", "/Madrid/#/Parterre1"] {
            let refused = ScopePattern::new(broken);

            assert!(refused.is_err(), "{broken:?} must be refused, got {refused:?}");
        }
    }

    #[test]
    fn a_pattern_holding_a_control_character_is_refused_and_named_escaped() {
        for forged in ["/Madrid\u{0}/Gardens", "/Madrid/Gar\u{1b}dens", "/Madrid\u{7f}"] {
            let refused = ScopePattern::new(forged).unwrap_err().to_string();

            assert!(refused.contains("control character"), "{refused}");
            assert!(!refused.chars().any(char::is_control), "{refused:?}");
        }
    }

    #[test]
    fn an_empty_allow_list_is_refused() {
        // An empty list reads as "allow nothing" but enforces as an empty filter, which a broker
        // reads as no filter. A policy that allows nothing is written as a deny.
        let refused = toml::from_str::<ScopeRestriction>("allowed = []");

        assert!(refused.is_err(), "an empty scope allow list must be refused");
    }

    #[test]
    fn a_write_without_a_scope_is_refused_unless_the_policy_says_otherwise() {
        let restriction: ScopeRestriction = toml::from_str(r#"allowed = ["/Madrid/#"]"#).unwrap();

        assert_eq!(restriction.scope_on_write, MemberOnWrite::Required, "the default must be the closed one");

        let relaxed: ScopeRestriction = toml::from_str(
            r#"
            allowed = ["/Madrid/#"]
            scope-on-write = "optional"
            "#,
        )
        .unwrap();

        assert_eq!(relaxed.scope_on_write, MemberOnWrite::Optional);
    }

    #[test]
    fn an_unknown_key_in_a_restriction_is_refused() {
        // A misspelled `scope-on-write` would otherwise take its default silently, which is the
        // difference between refusing an unlabelled write and accepting one.
        assert!(
            toml::from_str::<ScopeRestriction>(
                r#"
                allowed = ["/Madrid/#"]
                scope_on_write = "optional"
                "#
            )
            .is_err()
        );
    }

    #[test]
    fn segments_drop_the_leading_slash() {
        assert_eq!(
            ScopePattern::new("/Madrid/Gardens/#").unwrap().segments().collect::<Vec<_>>(),
            ["Madrid", "Gardens", "#"]
        );
    }

    #[test]
    fn a_pattern_is_written_back_exactly_as_it_was_read() {
        // A scope pattern reaches the broker's scopeQ filter in this form.
        let pattern = ScopePattern::new("/Madrid/Gardens/#").unwrap();

        assert_eq!(pattern.as_str(), "/Madrid/Gardens/#");
        assert_eq!(String::from(pattern), "/Madrid/Gardens/#");
    }
}
