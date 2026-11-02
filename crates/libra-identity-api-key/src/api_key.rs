//! A key Libra has just issued.

use crate::{PREFIX, error::GenerationError, key_id::KeyId, key_secret::KeySecret, verifier::Verifier};
use jiff::Timestamp;
use secrecy::{ExposeSecret, SecretString};

/// A freshly generated key, the only time Libra holds one whole.
#[derive(Debug)]
pub struct ApiKey {
    id: KeyId,
    secret: KeySecret,
}

impl ApiKey {
    /// Generates a key whose id records `now` as its creation time.
    ///
    /// # Errors
    ///
    /// Returns [`GenerationError`] if the random source fails or `now` is before 1970.
    pub fn generate(now: Timestamp) -> Result<Self, GenerationError> {
        let created_ms = u64::try_from(now.as_millisecond()).map_err(|_| GenerationError::ClockBeforeEpoch)?;

        // A ULID's 80 random bits make two ids minted in the same millisecond distinct. They are
        // not the secret and need not be kept from anyone.
        let mut random = [0; 16];
        getrandom::fill(&mut random[6..]).map_err(GenerationError::RandomSource)?;

        Ok(Self {
            id: KeyId::from_parts(created_ms, u128::from_be_bytes(random)),
            secret: KeySecret::generate()?,
        })
    }

    /// The key's id.
    #[must_use]
    pub const fn id(&self) -> &KeyId {
        &self.id
    }

    /// What the store keeps of this key.
    #[must_use]
    pub fn verifier(&self) -> Verifier {
        Verifier::of(&self.id, &self.secret)
    }

    /// The key as its holder presents it, `libra_<id>_<secret>`.
    ///
    /// Shown once, to whoever created it. Assembled in a buffer sized exactly, so moving it into the
    /// secret box does not reallocate and leave a copy behind.
    #[must_use]
    pub fn reveal(&self) -> SecretString {
        let secret = self.secret.encode();
        let id = self.id.to_string();
        let mut key = String::with_capacity(PREFIX.len() + 1 + id.len() + 1 + secret.expose_secret().len());
        key.push_str(PREFIX);
        key.push('_');
        key.push_str(&id);
        key.push('_');
        key.push_str(secret.expose_secret());

        SecretString::from(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{error::KeyFormatError, presented_key::PresentedKey};
    use pretty_assertions::assert_eq;

    fn now() -> Timestamp {
        Timestamp::from_millisecond(1_760_000_000_000).unwrap()
    }

    fn generated() -> ApiKey {
        ApiKey::generate(now()).unwrap()
    }

    fn revealed(key: &ApiKey) -> String {
        key.reveal().expose_secret().to_owned()
    }

    #[test]
    fn a_generated_key_reads_back_and_verifies() {
        let key = generated();
        let text = revealed(&key);

        assert!(text.starts_with("libra_"));
        assert_eq!(text.split('_').nth(1).map(str::len), Some(26));

        let presented = PresentedKey::parse(&text).unwrap();
        assert_eq!(presented.id(), key.id());
        assert_eq!(key.verifier().verify(presented.id(), presented.secret()), Ok(()));
    }

    #[test]
    fn two_generated_keys_differ_and_carry_their_creation_time() {
        let (first, second) = (generated(), generated());

        assert_ne!(first.id(), second.id());
        assert_ne!(first.verifier(), second.verifier());
        assert_eq!(first.id().created_ms(), 1_760_000_000_000);
    }

    #[test]
    fn a_time_before_1970_cannot_be_an_id() {
        let before = Timestamp::from_second(-1).unwrap();

        assert!(matches!(ApiKey::generate(before), Err(GenerationError::ClockBeforeEpoch)));
    }

    #[test]
    fn each_malformed_part_is_refused_with_its_own_reason() {
        let text = revealed(&generated());
        let (_, rest) = text.split_once('_').unwrap();
        let (id, secret) = rest.split_once('_').unwrap();

        let refused = |credential: String| PresentedKey::parse(&credential).map(|_| ()).unwrap_err();

        assert_eq!(refused(format!("seam_{id}_{secret}")), KeyFormatError::WrongPrefix);
        assert_eq!(refused(format!("Libra_{id}_{secret}")), KeyFormatError::WrongPrefix);
        assert_eq!(refused(format!("libra_{id}")), KeyFormatError::MissingPart);
        assert_eq!(refused("libra".to_owned()), KeyFormatError::MissingPart);
        assert_eq!(refused(format!("libra_{id}_{secret}_x")), KeyFormatError::ExtraPart);
        assert_eq!(refused(format!("libra_{}_{secret}", id.to_lowercase())), KeyFormatError::NonCanonicalId);
        assert_eq!(refused(format!("libra_{}_{secret}", &id[1..])), KeyFormatError::IdLength);
        assert_eq!(refused(format!("libra_{id}0_{secret}")), KeyFormatError::IdLength);
        assert_eq!(refused(format!("libra_{}U_{secret}", &id[1..])), KeyFormatError::IdEncoding);
    }

    #[test]
    fn the_debug_form_of_a_key_shows_no_part_of_its_secret() {
        let key = generated();
        let text = revealed(&key);
        let secret = text.rsplit('_').next().unwrap();

        assert!(!format!("{key:?}").contains(secret));
        assert!(!format!("{:?}", PresentedKey::parse(&text).unwrap()).contains(secret));
        assert!(!format!("{:?}", key.reveal()).contains(secret));
    }
}
