//! A key as a caller presents it.

use crate::{PREFIX, error::KeyFormatError, key_id::KeyId, key_secret::KeySecret};
use std::str::FromStr;

/// A credential read as a Libra API key: well formed, and not yet checked against anything.
#[derive(Debug)]
pub struct PresentedKey {
    id: KeyId,
    secret: KeySecret,
}

impl PresentedKey {
    /// Reads `libra_<id>_<secret>`.
    ///
    /// # Errors
    ///
    /// Returns the [`KeyFormatError`] naming the first part that is not as a Libra key writes it.
    pub fn parse(credential: &str) -> Result<Self, KeyFormatError> {
        let (prefix, rest) = credential.split_once('_').ok_or(KeyFormatError::MissingPart)?;
        if prefix != PREFIX {
            return Err(KeyFormatError::WrongPrefix);
        }

        let (id, secret) = rest.split_once('_').ok_or(KeyFormatError::MissingPart)?;
        if secret.contains('_') {
            return Err(KeyFormatError::ExtraPart);
        }

        Ok(Self {
            id: KeyId::from_str(id)?,
            secret: KeySecret::decode(secret)?,
        })
    }

    /// The id, which is how the key is looked up.
    #[must_use]
    pub const fn id(&self) -> &KeyId {
        &self.id
    }

    /// The secret, which is checked against the stored verifier.
    #[must_use]
    pub const fn secret(&self) -> &KeySecret {
        &self.secret
    }
}
