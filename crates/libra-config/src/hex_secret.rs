//! A secret written in the configuration file as hex.

use derive_more::Debug;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// The shortest key worth the name: 128 bits. Shorter than this, the secret it names is
/// guessable material rather than a key, and a deployment that writes one has not made the
/// decision it thinks it made.
const MINIMUM_BYTES: usize = 16;

/// A hex secret could not be read.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum HexSecretError {
    /// The value is not hexadecimal.
    ///
    /// The value is not repeated: a secret that is mistyped is still mostly the secret, and the
    /// error reaches the startup log.
    #[error("the value is not a hexadecimal string")]
    NotHexadecimal,
    /// The key is shorter than 128 bits.
    #[error("the key is {bytes} bytes; at least {MINIMUM_BYTES} are required")]
    TooShort {
        /// How many bytes decoded.
        bytes: usize,
    },
}

/// A secret key, written as hex and read as bytes.
///
/// Written with `openssl rand -hex 32` or its equivalent. The value does not render in [`Debug`]:
/// a key in a diagnostic line is a key given away.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(try_from = "String", into = "String")]
#[debug("HexSecret")]
pub struct HexSecret(Vec<u8>);

impl TryFrom<String> for HexSecret {
    type Error = HexSecretError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        // `hex::decode` takes lowercase and uppercase alike and refuses an odd length, so every
        // way a value can fail to be a key folds into the one `NotHexadecimal` answer.
        let bytes = hex::decode(value).map_err(|_| HexSecretError::NotHexadecimal)?;

        if bytes.len() < MINIMUM_BYTES {
            return Err(HexSecretError::TooShort { bytes: bytes.len() });
        }

        Ok(Self(bytes))
    }
}

impl From<HexSecret> for String {
    fn from(secret: HexSecret) -> Self {
        hex::encode(secret.0)
    }
}

impl HexSecret {
    /// The key's bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn a_well_formed_key_round_trips() {
        let secret: HexSecret = "00ff10ee0d0c0b0a0908070605040302".to_owned().try_into().unwrap();

        assert_eq!(secret.bytes().len(), 16);
        assert_eq!(String::from(secret), "00ff10ee0d0c0b0a0908070605040302");
    }

    #[test]
    fn uppercase_hex_is_accepted() {
        let secret: HexSecret = "00FF10EE0D0C0B0A0908070605040302".to_owned().try_into().unwrap();

        assert_eq!(secret.bytes()[0], 0x00);
        assert_eq!(secret.bytes()[1], 0xff);
    }

    #[test]
    fn a_value_that_is_not_hexadecimal_is_refused() {
        for broken in ["not hex", "0", "0g", "00ff0g"] {
            assert_eq!(HexSecret::try_from(broken.to_owned()), Err(HexSecretError::NotHexadecimal), "{broken}");
        }
    }

    #[test]
    fn a_refusal_repeats_no_part_of_the_value() {
        let mistyped = "00ff10ee0d0c0b0a090807060504030z";
        let message = HexSecret::try_from(mistyped.to_owned()).map(|_| ()).unwrap_err().to_string();

        assert!(!message.contains("00ff10ee"), "{message}");
        assert!(!message.contains('z'), "{message}");
    }

    #[test]
    fn a_key_shorter_than_128_bits_is_refused() {
        // A key that short is not a decision to keep a secret; it is a placeholder where one
        // should have been, and accepting it would fingerprint every credential under a key an
        // attacker guesses along with the deployment.
        assert_eq!(HexSecret::try_from("00ff".to_owned()), Err(HexSecretError::TooShort { bytes: 2 }));
    }

    #[test]
    fn the_debug_rendering_gives_nothing_away() {
        let secret: HexSecret = "00ff10ee0d0c0b0a0908070605040302".to_owned().try_into().unwrap();

        assert_eq!(format!("{secret:?}"), "HexSecret");
    }

    #[test]
    fn a_value_that_does_not_parse_is_refused_at_load_rather_than_defaulted() {
        // `deny_unknown_fields` guards a key that is not there; this guards one that is there and
        // does not parse, so neither mistake can pass silently.
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Carries {
            key: HexSecret,
        }

        let read: Carries = toml::from_str(r#"key = "00ff10ee0d0c0b0a0908070605040302""#).expect("a well-formed key should load");
        assert_eq!(read.key.bytes().len(), 16);
        assert!(toml::from_str::<Carries>(r#"key = "guessable""#).is_err());
    }
}
