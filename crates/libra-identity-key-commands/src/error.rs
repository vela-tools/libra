//! Why a command did not complete.

use jiff::Timestamp;
use libra_identity_api_key::error::GenerationError;
use libra_identity_key_store::error::StoreError;
use std::io;
use thiserror::Error;

/// A command that did not complete.
#[derive(Debug, Error)]
pub enum CommandError {
    /// The configuration turns the key store off.
    #[error("the key store is turned off; set [key-store] enabled = true")]
    NoKeyStore,

    /// The key store refused the change or could not be read.
    #[error(transparent)]
    Store(#[from] StoreError),

    /// A key could not be generated.
    #[error(transparent)]
    Generation(#[from] GenerationError),

    /// No expiry was given. Every key expires.
    #[error("a key needs an expiry: give --expires-at or --expires-in")]
    NoExpiry,

    /// The requested expiry is not in the future.
    #[error("the expiry {expires_at} is not in the future")]
    ExpiryNotInFuture {
        /// The expiry asked for.
        expires_at: Timestamp,
    },

    /// The expiry is beyond what a timestamp can hold.
    #[error("the expiry is too far in the future")]
    ExpiryOutOfRange,

    /// The output could not be written.
    #[error("the output could not be written: {0}")]
    Output(#[from] io::Error),
}
