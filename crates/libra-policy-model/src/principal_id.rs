//! The stable identifier of a principal.

use derive_more::Display;
use ulid::Ulid;

/// A principal's identifier: a ULID, assigned when the principal is created and never reused.
///
/// The name is what policies match; the id is what the broker and the audit record are given, as
/// `urn:libra:principal:<ulid>`, so a principal removed and created again under the same name is
/// recorded as a different one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Display)]
#[display("{_0}")]
pub struct PrincipalId(Ulid);

/// The URN namespace a principal is named in downstream. Informal, as the NGSI-LD namespace is.
const URN_PREFIX: &str = "urn:libra:principal:";

impl PrincipalId {
    /// The id from its creation time in milliseconds and 80 random bits.
    #[must_use]
    pub const fn from_parts(created_ms: u64, random: u128) -> Self {
        Self(Ulid::from_parts(created_ms, random))
    }

    /// The id as its 16 big-endian bytes, the form that is stored.
    #[must_use]
    pub const fn to_bytes(&self) -> [u8; 16] {
        self.0.to_bytes()
    }

    /// The id from its 16 big-endian bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(Ulid::from_bytes(bytes))
    }

    /// The principal as `urn:libra:principal:<ulid>`.
    #[must_use]
    pub fn urn(&self) -> String {
        format!("{URN_PREFIX}{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn an_id_round_trips_through_its_stored_bytes_and_names_itself_as_a_urn() {
        let id = PrincipalId::from_parts(1_700_000_000_000, 42);

        assert_eq!(PrincipalId::from_bytes(id.to_bytes()), id);
        assert_eq!(id.urn(), format!("urn:libra:principal:{id}"));
        assert_eq!(id.to_string().len(), 26);
    }
}
