//! The JWKS document as an identity provider publishes it, and the keys Libra takes from it.

use crate::{error::KeyStoreError, key_id::KeyId, key_use::KeyUse};
use jsonwebtoken::DecodingKey;
use serde::Deserialize;
use std::{collections::HashMap, sync::Arc};
use tracing::{debug, warn};
use url::Url;

/// A JWKS document, as published.
#[derive(Debug, Deserialize)]
pub(crate) struct JwksDocument {
    #[serde(default)]
    keys: Vec<JwksKey>,
}

/// One entry of a JWKS document.
///
/// Every field is optional so that one unusable entry costs that entry rather than the whole
/// document: a key set legitimately mixes RSA signing keys with keys Libra cannot use, and those
/// carry different members entirely.
///
/// The published `alg` is deliberately not read. The algorithm a token may be signed with comes
/// from Libra's own configuration; taking it from the key set would let whoever serves the key set
/// choose it.
#[derive(Debug, Deserialize)]
struct JwksKey {
    /// Read as text and checked per entry, so that one id Libra refuses costs that entry and not
    /// the whole document.
    #[serde(default)]
    kid: Option<String>,
    #[serde(default)]
    n: Option<String>,
    #[serde(default)]
    e: Option<String>,
    #[serde(default, rename = "use")]
    usage: Option<KeyUse>,
}

impl JwksDocument {
    /// Turns a JWKS document into the keys that can verify a signature.
    ///
    /// One unreadable entry is skipped with a warning; a document with nothing usable in it is an
    /// error, so the cache is never replaced by an empty one.
    pub(crate) fn usable_keys(self, url: &Arc<Url>) -> Result<HashMap<KeyId, DecodingKey>, KeyStoreError> {
        let mut keys = HashMap::new();

        for key in self.keys {
            let Some(kid) = key.kid else {
                warn!(url = %url, "skipping a JWKS entry that carries no key id");
                continue;
            };

            let kid = match KeyId::try_from(kid) {
                Ok(kid) => kid,
                Err(error) => {
                    // No token could name it either: the same rule refuses it in a token header.
                    warn!(url = %url, %error, "skipping a JWKS entry whose key id Libra does not accept");
                    continue;
                }
            };

            // A key published for encryption cannot verify anything. Accepting one would mean
            // holding a key for a purpose its publisher explicitly excluded.
            if key.usage == Some(KeyUse::Encryption) {
                debug!(kid = %kid, "skipping a JWKS entry published for encryption");
                continue;
            }

            let (Some(modulus), Some(exponent)) = (key.n, key.e) else {
                warn!(kid = %kid, "skipping a JWKS entry that carries no RSA components");
                continue;
            };

            match DecodingKey::from_rsa_components(&modulus, &exponent) {
                Ok(decoding_key) => {
                    debug!(kid = %kid, "loaded a JWKS signing key");
                    keys.insert(kid, decoding_key);
                }
                Err(error) => {
                    // Non-fatal: one malformed entry must not cost the working keys beside it,
                    // which would turn a cosmetic provider bug into a total authentication outage.
                    warn!(kid = %kid, %error, "skipping a JWKS entry that could not be read");
                }
            }
        }

        if keys.is_empty() {
            return Err(KeyStoreError::NoUsableKey { url: Arc::clone(url) });
        }

        Ok(keys)
    }
}
