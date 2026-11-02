//! The secret half of a key.

use crate::error::{GenerationError, KeyFormatError};
use bs58::decode::Error as DecodeError;
use secrecy::{ExposeSecret, SecretBox, SecretString};
use zeroize::Zeroizing;

/// How many random bytes a secret holds: 256 bits, beyond any guessing.
pub const SECRET_LENGTH: usize = 32;

/// A key's secret, zeroized when dropped.
///
/// Its `Debug` form shows none of it, and it has no `Display`: the only way to its bytes is
/// [`KeySecret::expose`], which says at the call site that a secret is being handled.
#[derive(Debug)]
pub struct KeySecret(SecretBox<[u8; SECRET_LENGTH]>);

impl KeySecret {
    /// A fresh secret from the operating system's random source.
    ///
    /// # Errors
    ///
    /// Returns [`GenerationError::RandomSource`] if the random source fails.
    pub fn generate() -> Result<Self, GenerationError> {
        let mut bytes = Box::new([0; SECRET_LENGTH]);
        getrandom::fill(bytes.as_mut_slice()).map_err(GenerationError::RandomSource)?;

        Ok(Self(SecretBox::new(bytes)))
    }

    /// Reads a secret from its `Base58Check` text.
    ///
    /// # Errors
    ///
    /// Returns [`KeyFormatError::SecretChecksum`] when the checksum does not match,
    /// [`KeyFormatError::SecretLength`] when the payload is not 32 bytes, and
    /// [`KeyFormatError::SecretEncoding`] for anything else that is not `Base58Check`.
    pub fn decode(text: &str) -> Result<Self, KeyFormatError> {
        // Decoded into one buffer sized up front, so the secret is never left behind in a buffer a
        // reallocation abandoned, and zeroized when it goes out of scope.
        let mut decoded = Zeroizing::new(Vec::with_capacity(text.len()));
        bs58::decode(text).with_check(None).onto(&mut *decoded).map_err(|error| {
            if matches!(error, DecodeError::InvalidChecksum { .. }) {
                KeyFormatError::SecretChecksum
            } else {
                KeyFormatError::SecretEncoding
            }
        })?;

        let mut bytes = Box::new([0; SECRET_LENGTH]);
        if decoded.len() != SECRET_LENGTH {
            return Err(KeyFormatError::SecretLength);
        }
        bytes.copy_from_slice(&decoded);

        Ok(Self(SecretBox::new(bytes)))
    }

    /// The secret as `Base58Check` text, for the one time a key is shown to whoever created it.
    #[must_use]
    pub fn encode(&self) -> SecretString {
        SecretString::from(bs58::encode(self.expose()).with_check().into_string())
    }

    /// The secret's bytes.
    #[must_use]
    pub fn expose(&self) -> &[u8; SECRET_LENGTH] {
        self.0.expose_secret()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn text(secret: &KeySecret) -> String {
        secret.encode().expose_secret().to_owned()
    }

    #[test]
    fn a_secret_round_trips_through_its_text() {
        let secret = KeySecret::generate().unwrap();

        assert_eq!(KeySecret::decode(&text(&secret)).unwrap().expose(), secret.expose());
    }

    #[test]
    fn two_secrets_differ() {
        assert_ne!(KeySecret::generate().unwrap().expose(), KeySecret::generate().unwrap().expose());
    }

    #[test]
    fn one_changed_character_fails_the_checksum() {
        let original = text(&KeySecret::generate().unwrap());
        let replacement = if original.ends_with('2') { '3' } else { '2' };
        let mistyped: String = original.chars().take(original.len() - 1).chain([replacement]).collect();

        assert_eq!(KeySecret::decode(&mistyped).map(|_| ()), Err(KeyFormatError::SecretChecksum));
    }

    #[test]
    fn a_character_outside_base58_is_refused() {
        for outside in ['0', 'O', 'l', 'I', '_'] {
            let text = format!("{outside}{}", text(&KeySecret::generate().unwrap()));
            assert_eq!(KeySecret::decode(&text).map(|_| ()), Err(KeyFormatError::SecretEncoding), "{outside}");
        }
    }

    #[test]
    fn a_payload_of_the_wrong_length_is_refused_even_with_a_valid_checksum() {
        for length in [31, 33] {
            let text = bs58::encode(vec![9_u8; length]).with_check().into_string();
            assert_eq!(KeySecret::decode(&text).map(|_| ()), Err(KeyFormatError::SecretLength), "{length}");
        }
    }

    #[test]
    fn the_debug_form_shows_no_part_of_the_secret() {
        let secret = KeySecret::generate().unwrap();

        assert!(!format!("{secret:?}").contains(&text(&secret)));
        assert!(!format!("{secret:?}").contains(&format!("{:?}", secret.expose())));
    }
}
