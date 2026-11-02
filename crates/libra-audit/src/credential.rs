//! Fingerprinting the credential a request presented.
//!
//! The audit record names the caller by `subject`, which answers *who* but not *which
//! credential*: one subject may hold several tokens, and after a rotation the requests still
//! presenting the old one are indistinguishable from the rest. A refusal is worse off still: an
//! invalid or expired token often has no usable subject, so the record holds only a peer address
//! and cannot tell one misbehaving client from many presenting the same dead token.
//!
//! The fingerprint closes that gap without ever recording the credential. It is HMAC-SHA-256 of
//! the token under a deployment-chosen key, truncated to eight bytes and written as sixteen hex
//! characters: enough to tell credentials apart in a deployment's own records, too little to be
//! worth anything outside them. The key is what stops the record from being brute-forced back to
//! the token: an unsalted hash of a low-entropy credential would fall to a dictionary, an HMAC
//! under a secret key does not.
//!
//! Rotating the key changes every fingerprint at once. That is the contract: fingerprints
//! correlate requests within one key's lifetime, and a rotation is a deliberate break of that
//! correlation. The token itself is never written, to the record or the log.

use crypto_common::{Key, KeyInit};
use derive_more::Display;
use hmac::{Mac, SimpleHmac};
use serde::Serialize;
use sha2::{Digest, Sha256};

/// How many bytes of the HMAC are kept. Sixty-four bits of output: a collision needs on the
/// order of two billion distinct credentials before it becomes likely, which no deployment has.
const KEPT_BYTES: usize = 8;

/// The key the fingerprints of one deployment are computed under.
///
/// Built from `[audit] token-fingerprint-key` by the composition root; absent there, no
/// fingerprint is computed at all.
#[derive(Clone)]
pub struct FingerprintKey(SimpleHmac<Sha256>);

impl FingerprintKey {
    /// Builds the key from its configured bytes.
    ///
    /// The bytes are hashed and the digest zero-padded to the block size, which is exactly what
    /// HMAC does internally with a key shorter than its block: making the padding explicit is
    /// what allows the MAC's infallible constructor, which takes one size only. HMAC under a
    /// digest-derived key is the standard construction: what matters is that the key is secret
    /// and at least as wide as the hash, and the configuration refuses a key shorter than 128
    /// bits before this is reached.
    #[must_use]
    pub fn new(bytes: &[u8]) -> Self {
        let digest = Sha256::digest(bytes);
        let mut block = Key::<SimpleHmac<Sha256>>::default();
        block[..digest.len()].copy_from_slice(&digest);

        Self(SimpleHmac::new(&block))
    }

    /// The fingerprint of one presented token.
    #[must_use]
    pub fn fingerprint(&self, token: &str) -> CredentialFingerprint {
        let mut mac = self.0.clone();
        mac.update(token.as_bytes());

        let full = mac.finalize().into_bytes();

        CredentialFingerprint(hex::encode(&full[..KEPT_BYTES]))
    }
}

/// One presented credential, as it appears in an audit record.
///
/// The value is keyed HMAC output, not credential material: it identifies a token within one
/// deployment's records and under one key, and nothing else.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Display)]
pub struct CredentialFingerprint(String);

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    const TOKEN: &str = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJvcGVyYXRvciJ9.sig";
    const KEY: &[u8] = &[7_u8; 32];

    #[test]
    fn one_token_under_one_key_has_one_fingerprint() {
        let key = FingerprintKey::new(KEY);

        assert_eq!(key.fingerprint(TOKEN), key.fingerprint(TOKEN));
    }

    #[test]
    fn a_fingerprint_is_sixteen_hexadecimal_characters() {
        let fingerprint = FingerprintKey::new(KEY).fingerprint(TOKEN).to_string();

        assert_eq!(fingerprint.len(), 16, "{fingerprint}");
        assert!(fingerprint.bytes().all(|byte| byte.is_ascii_hexdigit()), "{fingerprint}");
    }

    #[test]
    fn another_token_or_another_key_gives_another_fingerprint() {
        // The first is the audit's purpose (telling credentials apart) and the second is the
        // rotation contract: a new key breaks the correlation with the old records.
        let key = FingerprintKey::new(KEY);
        let rotated = FingerprintKey::new(&[9_u8; 32]);

        assert_ne!(key.fingerprint(TOKEN), key.fingerprint("another token"));
        assert_ne!(key.fingerprint(TOKEN), rotated.fingerprint(TOKEN));
    }

    #[test]
    fn a_shorter_key_is_still_a_key() {
        // HMAC pads and hashes keys of any length; the minimum-length rule lives where the key is
        // read, so a key built in code from fewer bytes still fingerprints deterministically.
        let short = FingerprintKey::new(b"a");

        assert_eq!(short.fingerprint(TOKEN), short.fingerprint(TOKEN));
    }
}
