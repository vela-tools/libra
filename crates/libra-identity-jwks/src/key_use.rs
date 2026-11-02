//! What a published key is for.

use serde::Deserialize;

/// The intended use of a public key, the JWK `use` member (RFC 7517 section 4.2).
///
/// The two values RFC 7517 defines are named; any other value is kept apart rather than refused,
/// because the member is optional and its absence or an unknown value does not by itself exclude
/// a key from signature verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum KeyUse {
    /// `sig`, signature verification.
    #[serde(rename = "sig")]
    Signature,
    /// `enc`, encryption.
    #[serde(rename = "enc")]
    Encryption,
    /// A value RFC 7517 does not define.
    #[serde(other)]
    Other,
}

#[cfg(test)]
mod tests {
    use crate::key_use::KeyUse;
    use pretty_assertions::assert_eq;
    use serde_json::from_str;

    #[test]
    fn the_registered_uses_are_read_by_their_wire_names() {
        assert_eq!(from_str::<KeyUse>(r#""sig""#).ok(), Some(KeyUse::Signature));
        assert_eq!(from_str::<KeyUse>(r#""enc""#).ok(), Some(KeyUse::Encryption));
    }

    #[test]
    fn an_unregistered_use_is_kept_apart_rather_than_refused() {
        assert_eq!(from_str::<KeyUse>(r#""tls""#).ok(), Some(KeyUse::Other));
    }
}
