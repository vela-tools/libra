//! The Libra API key format: `libra_<id>_<secret>`.
//!
//! Seam's prefixed API key convention as revised by truestamp's fork. The id is a ULID in its
//! canonical Crockford base32 spelling: it is public, names the key in listings and logs, and is how
//! the key is looked up. The secret is 32 bytes from the operating system's random source,
//! Base58Check-encoded so a mistyped key is refused by its checksum before anything is looked up.
//! Neither part can contain `_`, so the three parts split unambiguously, and the `libra_` prefix is
//! what a secret scanner matches.
//!
//! Only a [`verifier::Verifier`] is ever stored. This crate does no I/O: generating, parsing and
//! verifying are all it knows.

pub mod api_key;
pub mod error;
pub mod key_id;
pub mod key_secret;
pub mod presented_key;
pub mod verifier;

/// The prefix every Libra API key starts with, before its first `_`.
pub const PREFIX: &str = "libra";
