//! The credential an `Authorization: Bearer` header carries.

use derive_more::{Debug, From};
use thiserror::Error;

/// The authentication scheme Libra accepts (RFC 6750 section 2.1).
const BEARER_SCHEME: &str = "Bearer";

/// Why an `Authorization` header value carries no bearer credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum BearerError {
    /// The header names some other authentication scheme.
    #[error("the authorization header does not carry a bearer credential")]
    NotBearer,

    /// The header names the bearer scheme but carries nothing after it.
    #[error("the authorization header carries an empty bearer token")]
    EmptyToken,
}

/// A bearer credential, borrowed from the header that carried it (RFC 6750 section 2.1).
///
/// Holding one proves nothing about it: it is what the caller sent, and only an authenticator
/// decides whether it is accepted. The type exists so the credential cannot be passed where some
/// other text is expected, and so it cannot be written to a log by formatting it: it has no
/// `Display`, and its `Debug` prints no part of it, because whoever reads a log line holding a live
/// credential can replay it.
#[derive(Clone, Copy, PartialEq, Eq, Debug, From)]
#[debug("BearerToken(..)")]
pub struct BearerToken<'a>(&'a str);

impl<'a> BearerToken<'a> {
    /// Reads the credential out of an `Authorization` header value.
    ///
    /// The scheme is matched without regard to case: RFC 7235 section 2.1 defines `auth-scheme` as
    /// a case-insensitive token, and clients do send `bearer`.
    ///
    /// # Errors
    ///
    /// Returns [`BearerError::NotBearer`] if the value names another scheme, and
    /// [`BearerError::EmptyToken`] if it names the bearer scheme but carries no credential.
    pub fn from_header(header_value: &'a str) -> Result<Self, BearerError> {
        let value = header_value.trim();

        let Some((scheme, credentials)) = value.split_once(char::is_whitespace) else {
            // `Bearer` on its own is a bearer credential with nothing in it; anything else is some
            // other scheme entirely, and the two are worth telling apart in a log.
            return Err(if value.eq_ignore_ascii_case(BEARER_SCHEME) {
                BearerError::EmptyToken
            } else {
                BearerError::NotBearer
            });
        };

        if !scheme.eq_ignore_ascii_case(BEARER_SCHEME) {
            return Err(BearerError::NotBearer);
        }

        let token = credentials.trim();
        if token.is_empty() {
            return Err(BearerError::EmptyToken);
        }

        Ok(Self(token))
    }

    /// The credential as the caller wrote it.
    #[must_use]
    pub const fn as_str(&self) -> &'a str {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn the_debug_form_does_not_carry_the_token() {
        let rendered = format!("{:?}", BearerToken::from("eyJhbGciOiJSUzI1NiJ9.secret.signature"));

        assert_eq!(rendered, "BearerToken(..)");
    }

    #[test]
    fn the_token_text_is_kept_verbatim() {
        assert_eq!(BearerToken::from("abc.def.ghi").as_str(), "abc.def.ghi");
    }

    #[test]
    fn the_bearer_scheme_is_matched_without_regard_to_case() {
        // Matching the literal `Bearer ` rejected conforming clients as unauthenticated with
        // nothing to explain it.
        for spelling in ["Bearer abc123", "bearer abc123", "BEARER abc123", "BeArEr abc123"] {
            assert_eq!(BearerToken::from_header(spelling), Ok(BearerToken::from("abc123")), "{spelling}");
        }
    }

    #[test]
    fn whitespace_around_the_header_value_and_the_token_is_ignored() {
        assert_eq!(BearerToken::from_header("  Bearer   abc123  "), Ok(BearerToken::from("abc123")));
        assert_eq!(BearerToken::from_header("Bearer\tabc123"), Ok(BearerToken::from("abc123")));
    }

    #[test]
    fn a_bearer_header_with_no_token_is_rejected() {
        for empty in ["Bearer", "Bearer ", "bearer    ", "  Bearer  "] {
            assert_eq!(BearerToken::from_header(empty), Err(BearerError::EmptyToken), "{empty:?}");
        }
    }

    #[test]
    fn another_authentication_scheme_is_not_read_as_a_bearer_token() {
        for other in ["Basic abc123", "abc123", "Bearerabc123", "Negotiate abc123"] {
            assert_eq!(BearerToken::from_header(other), Err(BearerError::NotBearer), "{other:?}");
        }
    }
}
