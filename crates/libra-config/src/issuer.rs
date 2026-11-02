//! The issuer a token must come from.

use derive_more::{Display, Into};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

/// An issuer identifier that is not one.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("jwt.issuer '{issuer}' is not usable: {reason}")]
pub struct InvalidIssuer {
    /// What was written.
    pub issuer: String,
    /// Why it was refused.
    pub reason: &'static str,
}

/// An issuer identifier: an absolute `http` or `https` URL with no query and no fragment, as
/// the OIDC Discovery specification section 3 and RFC 8414 section 2 define it.
///
/// Kept as written rather than as a parsed [`Url`]: the `iss` claim is compared to it as a string,
/// and parsing would add a trailing `/` to a bare host that the identity provider never wrote.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Display, Into, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
#[display("{_0}")]
#[into(String)]
pub struct Issuer(String);

impl Issuer {
    /// Checks and wraps an issuer read from a file.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidIssuer`] if the text is not an absolute `http` or `https` URL, or has a
    /// query or a fragment.
    pub fn new(issuer: String) -> Result<Self, InvalidIssuer> {
        let reason = match Url::parse(&issuer) {
            Err(_) => Some("it is not an absolute URL"),
            Ok(url) if !matches!(url.scheme(), "http" | "https") || !url.has_host() => Some("it is not an http or https URL"),
            Ok(url) if url.query().is_some() || url.fragment().is_some() => Some("it has a query or a fragment"),
            Ok(_) => None,
        };

        match reason {
            Some(reason) => Err(InvalidIssuer { issuer, reason }),
            None => Ok(Self(issuer)),
        }
    }

    /// The issuer as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Issuer {
    type Error = InvalidIssuer;

    fn try_from(issuer: String) -> Result<Self, Self::Error> {
        Self::new(issuer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_issuer_is_kept_exactly_as_written() {
        assert_eq!(Issuer::new("https://idp.example.test".to_owned()).unwrap().as_str(), "https://idp.example.test");
        assert_eq!(
            Issuer::new("https://idp.example.test/realms/fiware".to_owned()).unwrap().as_str(),
            "https://idp.example.test/realms/fiware"
        );
    }

    #[test]
    fn text_that_is_not_an_issuer_identifier_is_refused() {
        for hostile in [
            "",
            "idp",
            "ftp://idp.example.test",
            "https://idp.example.test/?x=1",
            "https://idp.example.test/#f",
        ] {
            assert!(Issuer::new(hostile.to_owned()).is_err(), "{hostile:?} must not be an issuer");
        }
    }
}
