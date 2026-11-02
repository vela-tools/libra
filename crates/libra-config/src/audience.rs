//! The audience a token must be issued for.

use derive_more::{Display, Into};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// An audience that no token could carry.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("jwt.audience '{audience}' is not usable: {reason}")]
pub struct InvalidAudience {
    /// What was written.
    pub audience: String,
    /// Why it was refused.
    pub reason: &'static str,
}

/// An expected `aud` value, per RFC 7519 section 4.1.3: a case-sensitive string, usually a client
/// id or a URI.
///
/// An empty audience is refused rather than read as "no audience configured": with the audience
/// check off, a token minted for another service is accepted, and a file that wrote `audience = ""`
/// meant to turn it on.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Display, Into, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
#[display("{_0}")]
#[into(String)]
pub struct Audience(String);

impl Audience {
    /// Checks and wraps an audience read from a file.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidAudience`] if the audience is empty or contains whitespace or control
    /// characters.
    pub fn new(audience: String) -> Result<Self, InvalidAudience> {
        if audience.is_empty() {
            return Err(InvalidAudience {
                audience,
                reason: "it is empty",
            });
        }
        if audience.chars().any(|character| character.is_whitespace() || character.is_control()) {
            return Err(InvalidAudience {
                audience,
                reason: "it contains whitespace or a control character",
            });
        }

        Ok(Self(audience))
    }

    /// The audience as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Audience {
    type Error = InvalidAudience;

    fn try_from(audience: String) -> Result<Self, Self::Error> {
        Self::new(audience)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_client_id_or_a_uri_is_accepted() {
        assert_eq!(Audience::new("ngsi-client".to_owned()).unwrap().as_str(), "ngsi-client");
        assert_eq!(
            Audience::new("https://api.example.test/ngsi".to_owned()).unwrap().as_str(),
            "https://api.example.test/ngsi"
        );
    }

    #[test]
    fn an_audience_no_token_could_carry_is_refused() {
        for hostile in ["", " ", "two words", "tab\there", "line\nbreak"] {
            assert!(Audience::new(hostile.to_owned()).is_err(), "{hostile:?} must not be an audience");
        }
    }
}
