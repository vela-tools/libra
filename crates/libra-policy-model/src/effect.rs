//! What a matched policy does.

use serde::{Deserialize, Serialize};

/// The outcome a matched policy produces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Effect {
    /// Let the request through, subject to the access block's restrictions.
    Allow,
    /// Refuse the request.
    Deny,
}

impl Effect {
    /// Whether this effect refuses.
    #[must_use]
    pub const fn is_deny(self) -> bool {
        matches!(self, Self::Deny)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn effects_are_written_in_lower_case() {
        assert_eq!(toml::from_str::<Wrapper>("effect = \"deny\"").unwrap().effect, Effect::Deny);
        assert_eq!(toml::from_str::<Wrapper>("effect = \"allow\"").unwrap().effect, Effect::Allow);
    }

    #[test]
    fn an_unrecognised_effect_is_refused_rather_than_defaulted() {
        // There is no default here on purpose. A policy whose effect did not parse must not become
        // an allow, and guessing a deny would hide the typo.
        assert!(toml::from_str::<Wrapper>("effect = \"Allow\"").is_err());
        assert!(toml::from_str::<Wrapper>("effect = \"permit\"").is_err());
    }

    #[derive(Deserialize)]
    struct Wrapper {
        effect: Effect,
    }
}
