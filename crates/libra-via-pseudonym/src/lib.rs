//! The name Libra gives itself in the `Via` header.
//!
//! RFC 9110 section 7.6.3 lets a proxy identify itself by a pseudonym instead of a host name. The
//! pseudonym is written into a header value that a client reads back, so it is checked once, when
//! it is read from the configuration, rather than when the first request is forwarded.

use http::HeaderValue;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// A pseudonym that cannot be written into `Via` without changing what the header says.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("'{pseudonym}' is not usable as a Via pseudonym: it must be a single non-empty run of visible ASCII characters with no comma")]
pub struct InvalidViaPseudonym {
    /// What was written.
    pub pseudonym: String,
}

/// A single `Via` received-by token.
///
/// A comma ends one `Via` element and starts another, and whitespace ends the received-by field, so
/// either would read as a hop that is not in the chain. Both are refused, along with anything that
/// is not visible ASCII.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ViaPseudonym(HeaderValue);

impl ViaPseudonym {
    /// Checks and wraps a pseudonym.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidViaPseudonym`] if the pseudonym is empty, contains a comma, or contains
    /// anything other than visible ASCII.
    pub fn new(pseudonym: String) -> Result<Self, InvalidViaPseudonym> {
        if pseudonym.is_empty() || pseudonym.bytes().any(|byte| !byte.is_ascii_graphic() || byte == b',') {
            return Err(InvalidViaPseudonym { pseudonym });
        }

        HeaderValue::from_str(&pseudonym).map(Self).map_err(|_| InvalidViaPseudonym { pseudonym })
    }

    /// The pseudonym as the header value it is written as, consuming it.
    #[must_use]
    pub fn into_header_value(self) -> HeaderValue {
        self.0
    }

    /// The pseudonym as the header value it is written as.
    #[must_use]
    pub const fn header_value(&self) -> &HeaderValue {
        &self.0
    }
}

impl TryFrom<String> for ViaPseudonym {
    type Error = InvalidViaPseudonym;

    fn try_from(pseudonym: String) -> Result<Self, Self::Error> {
        Self::new(pseudonym)
    }
}

/// A derive cannot express this: the value is stored as a header value, which has no `Into<String>`,
/// and the bytes were checked to be visible ASCII on construction, so the lossy conversion is exact.
impl From<ViaPseudonym> for String {
    fn from(pseudonym: ViaPseudonym) -> Self {
        Self::from_utf8_lossy(pseudonym.0.as_bytes()).into_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn a_single_token_is_accepted() {
        assert_eq!(ViaPseudonym::new("libra".to_owned()).expect("a token").header_value(), "libra");
        assert_eq!(
            ViaPseudonym::new("libra.example.test:5667".to_owned()).expect("a token").header_value(),
            "libra.example.test:5667"
        );
    }

    #[test]
    fn a_pseudonym_that_would_fake_a_hop_is_refused() {
        // A comma ends one `Via` element and starts another, so `libra, 1.1 elsewhere` would put a
        // hop in the chain that does not exist.
        for pseudonym in ["", "libra, 1.1 elsewhere", "two words", "libra\n", "caf\u{e9}"] {
            assert!(ViaPseudonym::new(pseudonym.to_owned()).is_err(), "'{pseudonym}' must not be accepted");
        }
    }

    #[test]
    fn a_pseudonym_round_trips_through_its_text_form() {
        #[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
        struct Holder {
            via: ViaPseudonym,
        }

        let parsed: Holder = toml::from_str("via = \"edge-1\"").expect("a pseudonym");

        assert_eq!(toml::to_string(&parsed).expect("serialisable").trim(), "via = \"edge-1\"");
        assert!(toml::from_str::<Holder>("via = \"a b\"").is_err());
    }
}
