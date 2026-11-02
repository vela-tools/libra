//! Why a key could not be generated or read.

use thiserror::Error;

/// Why a presented credential is not a Libra API key.
///
/// The variants are for the operator's log. A caller is told only that the credential was not
/// accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum KeyFormatError {
    /// The credential does not start with the Libra prefix.
    #[error("the key does not start with 'libra_'")]
    WrongPrefix,
    /// The credential has fewer than three `_`-separated parts.
    #[error("the key is missing its id or its secret")]
    MissingPart,
    /// The credential has more than three `_`-separated parts.
    #[error("the key has more parts than a prefix, an id and a secret")]
    ExtraPart,
    /// The id is not 26 characters long.
    #[error("the key id is not 26 characters long")]
    IdLength,
    /// The id holds a character outside Crockford base32, or does not fit 128 bits.
    #[error("the key id is not a ULID")]
    IdEncoding,
    /// The id is a ULID, spelled other than its canonical uppercase form.
    #[error("the key id is not in its canonical spelling")]
    NonCanonicalId,
    /// The secret holds a character outside the base58 alphabet.
    #[error("the key secret is not base58")]
    SecretEncoding,
    /// The secret's checksum does not match: the key was mistyped or truncated.
    #[error("the key secret's checksum does not match")]
    SecretChecksum,
    /// The secret does not decode to 32 bytes.
    #[error("the key secret is not 32 bytes long")]
    SecretLength,
}

/// Why a key could not be generated.
#[derive(Debug, Error)]
pub enum GenerationError {
    /// The operating system's random source failed. No key is issued from anything weaker.
    #[error("the operating system's random source failed: {0}")]
    RandomSource(getrandom::Error),
    /// The clock reads a time before 1970, which a ULID cannot carry.
    #[error("the clock reads a time before 1970")]
    ClockBeforeEpoch,
}

/// The presented secret does not match the stored verifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("the key does not match its stored verifier")]
pub struct KeyMismatch;
