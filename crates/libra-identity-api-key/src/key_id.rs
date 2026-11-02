//! The public half of a key.

use crate::error::KeyFormatError;
use derive_more::Display;
use std::str::FromStr;
use ulid::{DecodeError, ULID_LEN, Ulid};

/// A key's id: a ULID, written in its canonical Crockford base32 spelling.
///
/// Not secret. It names the key in listings, revocations and logs, and is the key's primary key in
/// the store.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Display)]
#[display("{_0}")]
pub struct KeyId(Ulid);

impl KeyId {
    /// The id from its creation time in milliseconds and 80 random bits.
    #[must_use]
    pub const fn from_parts(created_ms: u64, random: u128) -> Self {
        Self(Ulid::from_parts(created_ms, random))
    }

    /// The id as its 16 big-endian bytes, the form that is stored and hashed.
    #[must_use]
    pub const fn to_bytes(&self) -> [u8; 16] {
        self.0.to_bytes()
    }

    /// The id from its 16 big-endian bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(Ulid::from_bytes(bytes))
    }

    /// When the id was minted, in milliseconds since the Unix epoch.
    #[must_use]
    pub const fn created_ms(&self) -> u64 {
        self.0.timestamp_ms()
    }
}

/// Written by hand rather than derived through `Ulid`'s own `FromStr`, which also accepts lowercase:
/// one key would then have two spellings in every log and listing, and only one of them would match
/// a search for the other.
impl FromStr for KeyId {
    type Err = KeyFormatError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let ulid = Ulid::from_string(text).map_err(|error| match error {
            DecodeError::InvalidLength => KeyFormatError::IdLength,
            DecodeError::InvalidChar => KeyFormatError::IdEncoding,
        })?;

        let mut canonical = [0; ULID_LEN];
        if ulid.array_to_str(&mut canonical) != text {
            return Err(KeyFormatError::NonCanonicalId);
        }

        Ok(Self(ulid))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    const ID: &str = "01J9ZQ4X7K2V3M5N6P8R9S0T1V";

    #[test]
    fn an_id_reads_and_writes_in_its_canonical_spelling() {
        let id = KeyId::from_str(ID).unwrap();

        assert_eq!(id.to_string(), ID);
        assert_eq!(KeyId::from_bytes(id.to_bytes()), id);
    }

    #[test]
    fn an_id_in_another_spelling_or_shape_is_refused() {
        assert_eq!(KeyId::from_str(&ID.to_lowercase()), Err(KeyFormatError::NonCanonicalId));
        assert_eq!(KeyId::from_str(&ID[1..]), Err(KeyFormatError::IdLength));
        assert_eq!(KeyId::from_str(&format!("{ID}0")), Err(KeyFormatError::IdLength));
        assert_eq!(KeyId::from_str("01J9ZQ4X7K2V3M5N6P8R9S0T1U"), Err(KeyFormatError::IdEncoding));
    }

    #[test]
    fn an_id_beyond_128_bits_is_refused() {
        assert!(KeyId::from_str("8ZZZZZZZZZZZZZZZZZZZZZZZZZ").is_err());
    }

    #[test]
    fn the_creation_time_is_carried_in_the_id() {
        assert_eq!(KeyId::from_parts(1_700_000_000_000, 5).created_ms(), 1_700_000_000_000);
    }
}
