//! What the store keeps in place of a key's secret.

use crate::{error::KeyMismatch, key_id::KeyId, key_secret::KeySecret};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Names the construction, so a verifier computed some other way can never be mistaken for one.
const DOMAIN_TAG: &[u8] = b"libra-api-key-v1";

/// `SHA-256("libra-api-key-v1" || id || secret)`, the only form of a key that is stored.
///
/// Unkeyed and fast on purpose. A slow hash protects low-entropy secrets, and a 256-bit secret is
/// not guessable either way, while a slow hash run on every request is CPU any caller can make
/// Libra spend by sending keys. Hashing the id with the secret binds the two, so a verifier copied
/// onto another key's row verifies nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verifier([u8; 32]);

impl Verifier {
    /// The verifier of the key with this id and secret.
    #[must_use]
    pub fn of(id: &KeyId, secret: &KeySecret) -> Self {
        let mut digest = Sha256::new();
        digest.update(DOMAIN_TAG);
        digest.update(id.to_bytes());
        digest.update(secret.expose());

        Self(digest.finalize().into())
    }

    /// Checks a presented id and secret against this verifier, in constant time.
    ///
    /// # Errors
    ///
    /// Returns [`KeyMismatch`] when they do not match.
    pub fn verify(&self, id: &KeyId, secret: &KeySecret) -> Result<(), KeyMismatch> {
        if bool::from(Self::of(id, secret).0.ct_eq(&self.0)) {
            Ok(())
        } else {
            Err(KeyMismatch)
        }
    }

    /// The verifier as stored.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// A verifier read back from the store.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use std::str::FromStr;

    fn secret_of(byte: u8) -> KeySecret {
        let text = bs58::encode([byte; 32]).with_check().into_string();
        KeySecret::decode(&text).unwrap()
    }

    #[test]
    fn the_construction_is_fixed() {
        // A known answer: any change to the tag, the order or the encoding of the parts breaks
        // every key already issued, and has to show up here first.
        let id = KeyId::from_str("01J9ZQ4X7K2V3M5N6P8R9S0T1V").unwrap();
        let expected = "57194bbcb3d4bac57ef832308f325bee02e10cfed78d7813dd9566cd77cb83f3";

        assert_eq!(hex::encode(Verifier::of(&id, &secret_of(7)).as_bytes()), expected);
    }

    #[test]
    fn a_verifier_accepts_its_own_key_and_no_other() {
        let id = KeyId::from_parts(1, 1);
        let other_id = KeyId::from_parts(1, 2);
        let verifier = Verifier::of(&id, &secret_of(1));

        assert_eq!(verifier.verify(&id, &secret_of(1)), Ok(()));
        assert_eq!(verifier.verify(&id, &secret_of(2)), Err(KeyMismatch));
        // The binding: the right secret under another id does not verify.
        assert_eq!(verifier.verify(&other_id, &secret_of(1)), Err(KeyMismatch));
    }

    #[test]
    fn a_verifier_round_trips_through_its_stored_bytes() {
        let verifier = Verifier::of(&KeyId::from_parts(1, 1), &secret_of(1));

        assert_eq!(Verifier::from_bytes(*verifier.as_bytes()), verifier);
    }
}
