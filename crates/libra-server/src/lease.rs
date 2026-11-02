//! Keeping the API key store's lease while serving.
//!
//! The lease is renewed on a fixed period. If it is taken over, or cannot be renewed for long enough
//! that another instance could take it over, this instance stops serving the way a termination
//! signal stops it: two instances must never both believe they hold the store.

use crate::{
    shutdown::{OsSignals, ShutdownRequests},
    startup::LeasedKeyStore,
};
use jiff::Timestamp;
use libra_identity_key_store::{
    lease::{LOST_AFTER, Lease, LeaseError, RENEW_EVERY},
    store::ApiKeyStore,
};
use std::{future::pending, sync::Arc};
use tokio::{
    spawn,
    sync::Notify,
    task::JoinHandle,
    time::{MissedTickBehavior, interval},
};
use tracing::{error, warn};

/// The outcome of one renewal attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Renewal {
    /// Renewed at this time.
    Kept(Timestamp),
    /// Not renewed, and still safe to try again.
    Retry,
    /// The lease is gone, or may be: stop serving.
    Lost,
}

/// The renewal task, and the signal it gives when the lease is lost.
pub struct LeaseKeeper {
    task: JoinHandle<()>,
    lost: Arc<Notify>,
}

impl LeaseKeeper {
    /// Starts renewing the lease.
    #[must_use]
    pub fn start(held: &LeasedKeyStore) -> Self {
        let lost = Arc::new(Notify::new());
        // A handle to the shared pool and a copy of the lease, both owned by the task.
        let (store, lease, signal) = (held.store.clone(), held.lease, Arc::clone(&lost));

        let task = spawn(async move {
            let mut ticker = interval(RENEW_EVERY.unsigned_abs());
            ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
            // The first tick completes at once, and the lease was claimed a moment ago.
            ticker.tick().await;

            let mut renewed_at = lease.started_at();
            loop {
                ticker.tick().await;

                match renew(&store, &lease, renewed_at, Timestamp::now()).await {
                    Renewal::Kept(at) => renewed_at = at,
                    Renewal::Retry => {}
                    Renewal::Lost => {
                        signal.notify_one();
                        return;
                    }
                }
            }
        });

        Self { task, lost }
    }

    /// The requests to stop serving: the operating system's, and this lease being lost.
    #[must_use]
    pub fn stop_requests(&self) -> LeaseOrSignals {
        LeaseOrSignals {
            lost: Some(Arc::clone(&self.lost)),
        }
    }

    /// Stops renewing.
    pub fn stop(self) {
        self.task.abort();
    }
}

/// Stop requests from the operating system, and from the lease keeper when there is one.
#[derive(Debug, Clone, Default)]
pub struct LeaseOrSignals {
    lost: Option<Arc<Notify>>,
}

impl ShutdownRequests for LeaseOrSignals {
    async fn next_request(&mut self) {
        let lost = self.lost.clone(); // a handle, so the notification can be awaited without borrowing self
        let lease_lost = async move {
            match lost {
                Some(lost) => lost.notified().await,
                None => pending::<()>().await,
            }
        };

        let mut signals = OsSignals;

        tokio::select! {
            () = signals.next_request() => {}
            () = lease_lost => {
                // Reported once; a second request to stop can only come from the operating system.
                self.lost = None;
            }
        }
    }
}

/// Renews the lease once.
///
/// A failed renewal is retried until [`LOST_AFTER`] has passed since the last one that succeeded;
/// past that point another instance may already have claimed the lease.
async fn renew(store: &ApiKeyStore, lease: &Lease, last: Timestamp, now: Timestamp) -> Renewal {
    match store.renew_lease(lease, now).await {
        Ok(()) => Renewal::Kept(now),
        Err(LeaseError::Lost) => {
            error!("another instance took over the key store's lease; stopping");
            Renewal::Lost
        }
        Err(failure @ (LeaseError::Held { .. } | LeaseError::RandomSource(_) | LeaseError::ClockBeforeEpoch | LeaseError::Store(_))) => {
            if now.duration_since(last) >= LOST_AFTER {
                error!(error = %failure, "the key store's lease could not be renewed in time; stopping");
                Renewal::Lost
            } else {
                warn!(error = %failure, "the key store's lease could not be renewed; retrying");
                Renewal::Retry
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jiff::SignedDuration;
    use libra_identity_key_store::lease::InstanceId;
    use pretty_assertions::assert_eq;
    use std::time::Duration;
    use tempfile::TempDir;
    use tokio::time::timeout;

    fn at(seconds: i64) -> Timestamp {
        Timestamp::from_second(seconds).unwrap()
    }

    async fn store() -> (TempDir, ApiKeyStore) {
        let directory = TempDir::new().unwrap();
        let store = ApiKeyStore::open(&directory.path().join("keys.db")).await.unwrap();
        (directory, store)
    }

    #[tokio::test]
    async fn a_held_lease_is_kept() {
        let (_directory, store) = store().await;
        let lease = store.claim_lease(InstanceId::generate(at(100)).unwrap(), at(100)).await.unwrap();

        assert_eq!(renew(&store, &lease, at(100), at(110)).await, Renewal::Kept(at(110)));
    }

    #[tokio::test]
    async fn a_lease_taken_over_is_lost() {
        let (_directory, store) = store().await;
        let old = store.claim_lease(InstanceId::generate(at(100)).unwrap(), at(100)).await.unwrap();
        store.claim_lease(InstanceId::generate(at(140)).unwrap(), at(140)).await.unwrap();

        assert_eq!(renew(&store, &old, at(100), at(141)).await, Renewal::Lost);
    }

    #[tokio::test]
    async fn a_failed_renewal_is_retried_until_another_instance_could_claim_the_lease() {
        let (_directory, store) = store().await;
        let lease = store.claim_lease(InstanceId::generate(at(100)).unwrap(), at(100)).await.unwrap();
        // A closed pool fails every query, standing in for a store that cannot be written.
        store.close().await;

        let almost = at(100) + LOST_AFTER - SignedDuration::from_secs(1);
        assert_eq!(renew(&store, &lease, at(100), almost).await, Renewal::Retry);
        assert_eq!(renew(&store, &lease, at(100), at(100) + LOST_AFTER).await, Renewal::Lost);
    }

    #[tokio::test]
    async fn a_lost_lease_is_a_request_to_stop() {
        let lost = Arc::new(Notify::new());
        let mut requests = LeaseOrSignals { lost: Some(Arc::clone(&lost)) };

        lost.notify_one();

        assert!(timeout(Duration::from_secs(5), requests.next_request()).await.is_ok());
        assert!(requests.lost.is_none(), "the lease is reported lost once");
    }
}
