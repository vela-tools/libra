//! The `kid` that ties a token to the key it was signed with.

use derive_more::Display;
use serde::Deserialize;
use std::str::FromStr;
use thiserror::Error;

/// The longest key id accepted. Identity providers publish ids of a few dozen characters (a UUID,
/// a base64url thumbprint); anything longer is padding, and padding in a log field is a cost
/// whoever sends the token chooses.
const MAXIMUM_BYTES: usize = 128;

/// A key id was refused.
///
/// The offending text is not carried: it comes out of an unverified token header, and an error
/// that repeated it would carry it into the log the check exists to protect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum KeyIdError {
    /// The id is longer than the length limit on a key id.
    #[error("the key id is {bytes} bytes; at most {MAXIMUM_BYTES} are accepted")]
    TooLong {
        /// How long the id is.
        bytes: usize,
    },
    /// The id holds a character outside visible ASCII.
    #[error("the key id holds a character outside visible ASCII")]
    NotVisibleAscii,
}

/// A JWK key id (RFC 7517 section 4.5).
///
/// The specification leaves the structure to the publisher and compares ids case-sensitively, so
/// equality is exact. On the token side the id comes out of an unverified header (RFC 7515 section
/// 4.1.4), so its text is chosen by whoever sent the token, anonymously. It is therefore held to
/// visible ASCII (no space, no control character, nothing outside ASCII) and at most
/// 128 bytes: such an id cannot end a log line, forge another field on it, or pad it,
/// in any log format. Every id an identity provider publishes in practice fits.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Display, Deserialize)]
#[serde(try_from = "String")]
pub struct KeyId(String);

impl KeyId {
    /// Checks `text` against the rules every key id meets.
    fn check(text: &str) -> Result<(), KeyIdError> {
        if text.len() > MAXIMUM_BYTES {
            return Err(KeyIdError::TooLong { bytes: text.len() });
        }

        if !text.bytes().all(|byte| byte.is_ascii_graphic()) {
            return Err(KeyIdError::NotVisibleAscii);
        }

        Ok(())
    }
}

impl TryFrom<String> for KeyId {
    type Error = KeyIdError;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        Self::check(&text)?;

        Ok(Self(text))
    }
}

impl FromStr for KeyId {
    type Err = KeyIdError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::check(text)?;

        Ok(Self(text.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use crate::key_id::{KeyId, KeyIdError};
    use pretty_assertions::assert_eq;
    use serde_json::from_str;

    #[test]
    fn a_key_id_is_read_from_its_json_string() {
        assert_eq!(from_str::<KeyId>(r#""key-1""#).ok(), Some("key-1".parse().unwrap()));
    }

    #[test]
    fn key_ids_compare_case_sensitively() {
        assert_ne!("Key".parse::<KeyId>().unwrap(), "key".parse::<KeyId>().unwrap());
    }

    #[test]
    fn a_key_id_displays_as_its_text() {
        assert_eq!("key-1".parse::<KeyId>().unwrap().to_string(), "key-1");
    }

    #[test]
    fn ids_identity_providers_publish_are_accepted() {
        for published in [
            "f2b3c6a1-6d0e-4c43-9a4b-0d6f5b7e2a91",
            "NjVBRjY5MDlCMUIwNzU4RTA2QzZFMDQ4QzQ2MDAyQjVDNjk1RTM2Qg",
            "kWbkaa6qs8wsTnBwiiNYOhHbnAw=",
            "rsa1/2026",
        ] {
            assert!(published.parse::<KeyId>().is_ok(), "{published}");
        }
    }

    #[test]
    fn a_key_id_that_could_end_or_extend_a_log_line_is_refused() {
        for forged in ["key\nlevel=ERROR forged", "key\r", "key\u{1b}[2J", "key other=field", "key\u{0}", "kéy"] {
            assert_eq!(forged.parse::<KeyId>(), Err(KeyIdError::NotVisibleAscii), "{forged:?}");
        }
    }

    #[test]
    fn a_key_id_longer_than_128_bytes_is_refused() {
        assert!("k".repeat(128).parse::<KeyId>().is_ok());
        assert_eq!("k".repeat(129).parse::<KeyId>(), Err(KeyIdError::TooLong { bytes: 129 }));
    }

    #[test]
    fn a_json_key_id_with_a_newline_is_refused_when_read() {
        assert!(from_str::<KeyId>(r#""key\nforged""#).is_err());
    }

    #[test]
    fn the_refusal_repeats_no_part_of_the_id() {
        let refused = "secret-looking\nid".parse::<KeyId>().unwrap_err().to_string();

        assert!(!refused.contains("secret-looking"), "{refused}");
    }
}
