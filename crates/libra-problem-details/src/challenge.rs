//! The authentication challenge a 401 is sent with.

use axum::http::HeaderValue;

/// The `WWW-Authenticate` challenge a 401 carries.
///
/// RFC 9110 section 15.5.2 requires every 401 to carry at least one challenge. Every credential
/// Libra reads is presented as a bearer token, so the challenge is always the `Bearer` scheme of
/// RFC 6750 section 3; what varies is whether it names an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Challenge {
    /// `Bearer`, naming no error: the request carried no bearer token to judge. RFC 6750 section
    /// 3.1 says a request that lacks any authentication information gets no error code.
    Bearer,
    /// `Bearer error="invalid_token"`: a bearer token was presented and not accepted, whatever the
    /// reason (RFC 6750 section 3.1). The reason itself is not sent.
    InvalidToken,
}

impl Challenge {
    /// The value of the `WWW-Authenticate` header.
    #[must_use]
    pub const fn header_value(self) -> HeaderValue {
        match self {
            Challenge::Bearer => HeaderValue::from_static("Bearer"),
            Challenge::InvalidToken => HeaderValue::from_static(r#"Bearer error="invalid_token""#),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::challenge::Challenge;
    use pretty_assertions::assert_eq;

    #[test]
    fn a_request_without_a_token_is_challenged_without_an_error_code() {
        assert_eq!(Challenge::Bearer.header_value(), "Bearer");
    }

    #[test]
    fn a_refused_token_is_challenged_as_invalid() {
        assert_eq!(Challenge::InvalidToken.header_value(), r#"Bearer error="invalid_token""#);
    }
}
