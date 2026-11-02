//! What can go wrong in the store.

use libra_identity_api_key::key_id::KeyId;
use libra_policy_model::identity::PrincipalName;
use sqlx::migrate::MigrateError;
use thiserror::Error;

/// A store operation that did not happen.
#[derive(Debug, Error)]
pub enum StoreError {
    /// The database could not be opened, read or written.
    #[error("the key store database failed: {0}")]
    Database(#[from] sqlx::Error),

    /// The schema could not be brought up to date.
    #[error("the key store schema could not be migrated: {0}")]
    Migration(#[from] MigrateError),

    /// A principal of that name already exists.
    #[error("a principal named '{name}' already exists")]
    PrincipalExists {
        /// The name.
        name: PrincipalName,
    },

    /// No principal of that name exists.
    #[error("no principal is named '{name}'")]
    UnknownPrincipal {
        /// The name.
        name: PrincipalName,
    },

    /// No key with that id exists.
    #[error("no key has the id {id}")]
    UnknownKey {
        /// The id.
        id: KeyId,
    },

    /// The key is already revoked.
    #[error("the key {id} is already revoked")]
    AlreadyRevoked {
        /// The id.
        id: KeyId,
    },

    /// The operating system's random source failed while assigning an id.
    #[error("the operating system's random source failed: {0}")]
    RandomSource(getrandom::Error),

    /// The clock reads a time before 1970, which an id cannot carry.
    #[error("the clock reads a time before 1970")]
    ClockBeforeEpoch,

    /// A row holds a value its type refuses: a name, a timestamp or a byte length outside what
    /// Libra writes. Refused rather than read, because a value nothing checked is how a row edited
    /// by hand would become a caller.
    #[error("the key store holds a row Libra did not write: {reason}")]
    CorruptRow {
        /// Which value was refused.
        reason: &'static str,
    },
}
