//! Why the key set could not be fetched, read or searched.

use crate::key_id::KeyId;
use std::sync::Arc;
use thiserror::Error;
use url::Url;

/// The JWKS could not be fetched, read, or searched.
#[derive(Debug, Error)]
pub enum KeyStoreError {
    /// The HTTP client itself could not be constructed.
    #[error("could not build the http client for '{url}'")]
    Client {
        /// The endpoint the client was being built for.
        url: Arc<Url>,
        /// What the HTTP stack reported.
        #[source]
        source: reqwest::Error,
    },

    /// The endpoint could not be reached, or the body stopped arriving.
    #[error("could not fetch the JWKS from '{url}'")]
    Fetch {
        /// The endpoint that was being read.
        url: Arc<Url>,
        /// What the HTTP stack reported.
        #[source]
        source: reqwest::Error,
    },

    /// The endpoint answered, but not with a success status.
    #[error("the JWKS endpoint '{url}' answered with status {status}")]
    Status {
        /// The endpoint that answered.
        url: Arc<Url>,
        /// The status it answered with.
        status: u16,
    },

    /// The body exceeded `limit` bytes and was abandoned part-read.
    #[error("the JWKS body from '{url}' is larger than the {limit} byte limit")]
    TooLarge {
        /// The endpoint that answered.
        url: Arc<Url>,
        /// The cap, in bytes.
        limit: usize,
    },

    /// The body arrived but is not a JWKS document.
    #[error("the JWKS document from '{url}' could not be read")]
    Parse {
        /// The endpoint that answered.
        url: Arc<Url>,
        /// What the JSON reader reported.
        #[source]
        source: serde_json::Error,
    },

    /// The document was read but held nothing that can verify a signature.
    ///
    /// An error rather than an empty key set: replacing the cache with nothing would reject every
    /// token in flight, and a provider that answers with an empty or entirely unusable key set is
    /// misconfigured rather than key-less.
    #[error("the JWKS document from '{url}' holds no usable signing key")]
    NoUsableKey {
        /// The endpoint that answered.
        url: Arc<Url>,
    },

    /// No cached key carries the id the token asked for.
    ///
    /// The id is carried as a field rather than written into the message: it comes out of an
    /// unverified token header, so it is attacker-chosen text, and the caller decides whether to
    /// log it as a structured field where the subscriber can escape it.
    #[error("no signing key matches the key id in the token header")]
    UnknownKeyId {
        /// The `kid` the token header carried.
        kid: KeyId,
    },
}
