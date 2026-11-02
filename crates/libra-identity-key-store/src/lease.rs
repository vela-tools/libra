//! The lease that keeps one proxy instance on a store.
//!
//! An instance claims the lease at startup and renews it while it serves. A second instance that
//! finds a live lease refuses to start; one that finds a stale lease, left by an instance that
//! crashed, takes it over. SQLite is a local file that two hosts cannot share safely, and two
//! instances on one host would each believe they were the only one, so the lease turns that mistake
//! into a startup error instead of a silent one.

use crate::{
    error::StoreError,
    store::ApiKeyStore,
    timestamp::{from_stored, to_stored},
};
use derive_more::Display;
use jiff::{SignedDuration, Timestamp};
use sqlx::FromRow;
use thiserror::Error;
use ulid::Ulid;

/// How often a serving instance renews its lease.
pub const RENEW_EVERY: SignedDuration = SignedDuration::from_secs(10);

/// How long after its last renewal a lease may be taken over.
///
/// Three renewal periods, so a crashed instance locks its replacement out for half a minute at
/// most, and a live one can miss two renewals before it is mistaken for a crashed one.
pub const STALE_AFTER: SignedDuration = SignedDuration::from_secs(30);

/// How long a serving instance goes without a successful renewal before it stops serving.
///
/// Shorter than [`STALE_AFTER`] by one renewal period: past this point another instance may claim
/// the lease before the next renewal could succeed, and two instances must never both believe
/// they hold it.
pub const LOST_AFTER: SignedDuration = SignedDuration::from_secs(20);

/// One run of one proxy process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Display)]
#[display("{_0}")]
pub struct InstanceId(Ulid);

impl InstanceId {
    /// A fresh id for a process starting at `now`.
    ///
    /// # Errors
    ///
    /// Returns [`LeaseError::RandomSource`] if the operating system's random source fails, and
    /// [`LeaseError::ClockBeforeEpoch`] if `now` is before 1970.
    pub fn generate(now: Timestamp) -> Result<Self, LeaseError> {
        let mut random = [0; 16];
        getrandom::fill(&mut random[6..]).map_err(LeaseError::RandomSource)?;
        let millis = u64::try_from(now.as_millisecond()).map_err(|_| LeaseError::ClockBeforeEpoch)?;

        Ok(Self(Ulid::from_parts(millis, u128::from_be_bytes(random))))
    }

    const fn to_bytes(self) -> [u8; 16] {
        self.0.to_bytes()
    }
}

/// A lease this instance holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lease {
    holder: InstanceId,
    started_at: Timestamp,
}

impl Lease {
    /// The instance holding it.
    #[must_use]
    pub const fn holder(&self) -> InstanceId {
        self.holder
    }

    /// When the holder claimed it.
    #[must_use]
    pub const fn started_at(&self) -> Timestamp {
        self.started_at
    }
}

/// Why the lease could not be claimed or kept.
#[derive(Debug, Error)]
pub enum LeaseError {
    /// Another instance holds a live lease.
    #[error("another Libra instance, started at {since}, holds the key store's lease; only one instance may use a key store")]
    Held {
        /// When that instance claimed the lease.
        since: Timestamp,
    },

    /// Another instance took the lease over.
    #[error("another Libra instance took over the key store's lease")]
    Lost,

    /// The operating system's random source failed.
    #[error("the operating system's random source failed: {0}")]
    RandomSource(getrandom::Error),

    /// The clock reads a time before 1970, which an instance id cannot carry.
    #[error("the clock reads a time before 1970")]
    ClockBeforeEpoch,

    /// The store could not be read or written.
    #[error(transparent)]
    Store(#[from] StoreError),
}

impl From<sqlx::Error> for LeaseError {
    fn from(error: sqlx::Error) -> Self {
        Self::Store(StoreError::Database(error))
    }
}

/// The lease row, before its values are checked.
#[derive(FromRow)]
struct LeaseRow {
    holder: Vec<u8>,
    started_at: i64,
    renewed_at: i64,
}

impl ApiKeyStore {
    /// Claims the lease for `holder`.
    ///
    /// Taken in an immediate transaction, so two instances starting together cannot both read an
    /// empty row and both claim it.
    ///
    /// # Errors
    ///
    /// Returns [`LeaseError::Held`] if another instance renewed the lease less than
    /// [`STALE_AFTER`] ago.
    pub async fn claim_lease(&self, holder: InstanceId, now: Timestamp) -> Result<Lease, LeaseError> {
        let mut transaction = self.pool().begin_with("BEGIN IMMEDIATE").await?;

        let current: Option<LeaseRow> = sqlx::query_as("SELECT holder, started_at, renewed_at FROM instance_lease WHERE slot = 1")
            .fetch_optional(&mut *transaction)
            .await?;

        if let Some(current) = current
            && current.holder != holder.to_bytes()
            && now.duration_since(from_stored(current.renewed_at)?) < STALE_AFTER
        {
            return Err(LeaseError::Held {
                since: from_stored(current.started_at)?,
            });
        }

        sqlx::query("INSERT OR REPLACE INTO instance_lease (slot, holder, started_at, renewed_at) VALUES (1, $1, $2, $2)")
            .bind(holder.to_bytes().as_slice())
            .bind(to_stored(now))
            .execute(&mut *transaction)
            .await?;

        transaction.commit().await?;

        Ok(Lease { holder, started_at: now })
    }

    /// Renews a lease this instance holds.
    ///
    /// # Errors
    ///
    /// Returns [`LeaseError::Lost`] if another instance has taken it over.
    pub async fn renew_lease(&self, lease: &Lease, now: Timestamp) -> Result<(), LeaseError> {
        let renewed = sqlx::query("UPDATE instance_lease SET renewed_at = $1 WHERE slot = 1 AND holder = $2")
            .bind(to_stored(now))
            .bind(lease.holder.to_bytes().as_slice())
            .execute(self.pool())
            .await?;

        if renewed.rows_affected() == 0 { Err(LeaseError::Lost) } else { Ok(()) }
    }

    /// Gives the lease up, so a replacement can start at once.
    ///
    /// # Errors
    ///
    /// Returns [`LeaseError::Store`] if the store cannot be written.
    pub async fn release_lease(&self, lease: Lease) -> Result<(), LeaseError> {
        sqlx::query("DELETE FROM instance_lease WHERE slot = 1 AND holder = $1")
            .bind(lease.holder.to_bytes().as_slice())
            .execute(self.pool())
            .await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_store::store;
    use pretty_assertions::assert_eq;

    fn at(seconds: i64) -> Timestamp {
        Timestamp::from_second(seconds).unwrap()
    }

    fn instance(seconds: i64) -> InstanceId {
        InstanceId::generate(at(seconds)).unwrap()
    }

    #[tokio::test]
    async fn a_live_lease_keeps_a_second_instance_out() {
        let (_directory, store) = store().await;
        let (first, second) = (instance(100), instance(110));

        let lease = store.claim_lease(first, at(100)).await.unwrap();
        assert_eq!(lease.started_at(), at(100));

        let refused = store.claim_lease(second, at(129)).await;
        assert!(matches!(refused, Err(LeaseError::Held { since }) if since == at(100)));
    }

    #[tokio::test]
    async fn a_renewed_lease_stays_live() {
        let (_directory, store) = store().await;
        let (first, second) = (instance(100), instance(110));

        let lease = store.claim_lease(first, at(100)).await.unwrap();
        store.renew_lease(&lease, at(120)).await.unwrap();

        assert!(matches!(store.claim_lease(second, at(140)).await, Err(LeaseError::Held { .. })));
    }

    #[tokio::test]
    async fn a_stale_lease_is_taken_over_and_its_old_holder_learns_it_is_lost() {
        let (_directory, store) = store().await;
        let (first, second) = (instance(100), instance(130));

        let old = store.claim_lease(first, at(100)).await.unwrap();
        let new = store.claim_lease(second, at(130)).await.unwrap();

        assert_eq!(new.holder(), second);
        assert!(matches!(store.renew_lease(&old, at(131)).await, Err(LeaseError::Lost)));
        store.renew_lease(&new, at(131)).await.unwrap();
    }

    #[tokio::test]
    async fn a_released_lease_can_be_claimed_at_once() {
        let (_directory, store) = store().await;
        let (first, second) = (instance(100), instance(101));

        let lease = store.claim_lease(first, at(100)).await.unwrap();
        store.release_lease(lease).await.unwrap();

        assert_eq!(store.claim_lease(second, at(101)).await.unwrap().holder(), second);
    }

    #[tokio::test]
    async fn an_instance_may_claim_its_own_lease_again() {
        let (_directory, store) = store().await;
        let first = instance(100);

        store.claim_lease(first, at(100)).await.unwrap();

        assert_eq!(store.claim_lease(first, at(105)).await.unwrap().started_at(), at(105));
    }
}
