//! Who may fetch the key set right now, and who waits for them.
//!
//! The previous arrangement was one async mutex that guarded both the cooldown timestamp and the
//! fetch itself, so the lock was held across an HTTP request of up to ten seconds. While the
//! identity provider hung, every request carrying an unknown key id queued behind it, and so did the
//! scheduled refresh. Here the decision is made in a short synchronous critical section that never
//! spans an `.await`: a caller either becomes the one fetcher, or is handed a [`Waiter`] for the
//! fetch already running, or is told the cooldown forbids another attempt.

use std::{
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    time::{Duration, Instant},
};
use tokio::{sync::watch, time::timeout};

/// What a caller may do about getting a fresh key set.
pub enum Claim {
    /// Nobody is fetching: the caller is now the one fetcher and holds the guard until it is done.
    Fetch(FetchGuard),
    /// A fetch is already running: wait for it instead of starting another.
    Join(Waiter),
}

/// How a wait for somebody else's fetch ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Wait {
    /// The fetch ended, whether it succeeded or not. The cache is as current as it is going to get.
    Finished,
    /// The limit passed first. The fetch is still running and is not abandoned.
    TimedOut,
}

/// A handle onto the fetch in flight.
pub struct Waiter {
    /// Nothing is ever sent on this channel. The fetcher dropping its sender is the signal, which
    /// `changed` reports as an error.
    finished: watch::Receiver<()>,
}

impl Waiter {
    /// Waits for the fetch to end, for at most `limit`.
    ///
    /// The limit is the caller's, not the fetch's: a request must not be held for as long as a hung
    /// identity provider takes to give up.
    pub async fn until_finished(mut self, limit: Duration) -> Wait {
        match timeout(limit, self.finished.changed()).await {
            Ok(Ok(()) | Err(_)) => Wait::Finished,
            Err(_) => Wait::TimedOut,
        }
    }
}

/// The right to fetch, held for the length of one fetch.
///
/// Dropping it, including because the request that held it was cancelled, ends the fetch's claim
/// and wakes every waiter. A cancelled fetch therefore cannot leave the gate claimed forever.
pub struct FetchGuard {
    gate: Arc<RefreshGate>,
    /// Dropped after [`Drop::drop`] has cleared the gate, so a woken waiter sees a gate that is
    /// already free.
    _signal: watch::Sender<()>,
}

impl Drop for FetchGuard {
    /// Frees the gate and starts the cooldown from the end of the fetch.
    ///
    /// Stamped again here, not only when the claim was made: against a provider that takes seconds
    /// to fail, the cooldown measured from the start would already be over by the time the failure
    /// arrived, and the next unknown key id would start another fetch straight away.
    fn drop(&mut self) {
        let mut state = self.gate.lock();
        state.in_flight = None;
        state.last_attempt = Some(Instant::now());
    }
}

/// What the gate remembers between callers.
struct GateState {
    /// When a fetch was last claimed or finished.
    last_attempt: Option<Instant>,
    /// The fetch running now, if any.
    in_flight: Option<watch::Receiver<()>>,
}

/// Serialises fetches of the key set and rate limits the ones an unknown key id asks for.
pub struct RefreshGate {
    state: Mutex<GateState>,
    /// How long after an attempt the next unknown key id may force another.
    cooldown: Duration,
}

impl RefreshGate {
    /// A gate that has never been used, so the first unknown key id may fetch.
    #[must_use]
    pub const fn new(cooldown: Duration) -> RefreshGate {
        RefreshGate {
            state: Mutex::new(GateState {
                last_attempt: None,
                in_flight: None,
            }),
            cooldown,
        }
    }

    /// Claims a fetch for a caller that does not answer to the cooldown: startup and the schedule.
    ///
    /// Joins a fetch already running rather than starting a second one beside it.
    #[must_use]
    pub fn claim_scheduled(self: &Arc<Self>) -> Claim {
        let mut state = self.lock();

        self.claim_locked(&mut state)
    }

    /// Claims a fetch for a token that named a key id nobody has cached.
    ///
    /// `None` when the cooldown has not elapsed and no fetch is running: the key id is attacker
    /// chosen, so it only earns an outbound request once per cooldown. A caller that finds a fetch
    /// running joins it however recent the last attempt was, because waiting costs the provider
    /// nothing.
    #[must_use]
    pub fn claim_on_demand(self: &Arc<Self>) -> Option<Claim> {
        let mut state = self.lock();

        let cooling = state.in_flight.is_none() && state.last_attempt.is_some_and(|attempt| attempt.elapsed() < self.cooldown);
        if cooling {
            return None;
        }

        Some(self.claim_locked(&mut state))
    }

    /// Joins the fetch in flight, or starts one, under the lock the caller already holds.
    fn claim_locked(self: &Arc<Self>, state: &mut GateState) -> Claim {
        if let Some(finished) = &state.in_flight {
            // A receiver is a handle onto the one shared channel, not a copy of anything.
            return Claim::Join(Waiter { finished: finished.clone() });
        }

        let (signal, finished) = watch::channel(());
        state.last_attempt = Some(Instant::now());
        state.in_flight = Some(finished);

        Claim::Fetch(FetchGuard {
            gate: Arc::clone(self),
            _signal: signal,
        })
    }

    /// The state, tolerating a poisoned lock: it holds two plain values, and nothing here can leave
    /// them half-written.
    fn lock(&self) -> MutexGuard<'_, GateState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    const COOLDOWN: Duration = Duration::from_secs(30);

    fn gate(cooldown: Duration) -> Arc<RefreshGate> {
        Arc::new(RefreshGate::new(cooldown))
    }

    #[test]
    fn a_gate_that_has_never_fetched_lets_an_unknown_key_id_fetch() {
        let gate = gate(COOLDOWN);

        assert!(matches!(gate.claim_on_demand(), Some(Claim::Fetch(_))));
    }

    #[test]
    fn a_caller_arriving_during_a_fetch_joins_it_whichever_way_it_asks() {
        let gate = gate(COOLDOWN);
        let fetcher = gate.claim_scheduled();

        assert!(matches!(fetcher, Claim::Fetch(_)));
        assert!(matches!(gate.claim_scheduled(), Claim::Join(_)));
        assert!(matches!(gate.claim_on_demand(), Some(Claim::Join(_))));
    }

    #[test]
    fn an_unknown_key_id_is_refused_during_the_cooldown_but_the_schedule_is_not() {
        let gate = gate(COOLDOWN);
        drop(gate.claim_scheduled());

        assert!(gate.claim_on_demand().is_none(), "the finished fetch started the cooldown");
        assert!(matches!(gate.claim_scheduled(), Claim::Fetch(_)));
    }

    #[test]
    fn a_zero_cooldown_never_refuses_an_unknown_key_id() {
        let gate = gate(Duration::ZERO);
        drop(gate.claim_scheduled());

        assert!(matches!(gate.claim_on_demand(), Some(Claim::Fetch(_))));
    }

    #[test]
    fn dropping_the_guard_frees_the_gate_for_the_next_fetcher() {
        // A request cancelled mid-fetch drops its guard. The gate must not stay claimed.
        let gate = gate(Duration::ZERO);
        let first = gate.claim_scheduled();
        assert!(matches!(gate.claim_scheduled(), Claim::Join(_)));

        drop(first);

        assert!(matches!(gate.claim_scheduled(), Claim::Fetch(_)));
    }

    #[tokio::test]
    async fn a_waiter_is_released_when_the_fetch_ends() {
        let gate = gate(COOLDOWN);
        let Claim::Fetch(guard) = gate.claim_scheduled() else {
            panic!("a fresh gate hands out the fetch");
        };
        let Claim::Join(waiter) = gate.claim_scheduled() else {
            panic!("a second caller joins");
        };

        drop(guard);

        assert_eq!(waiter.until_finished(Duration::from_secs(5)).await, Wait::Finished);
    }

    #[tokio::test]
    async fn a_waiter_gives_up_at_its_limit_while_the_fetch_is_still_running() {
        let gate = gate(COOLDOWN);
        let Claim::Fetch(_guard) = gate.claim_scheduled() else {
            panic!("a fresh gate hands out the fetch");
        };
        let Claim::Join(waiter) = gate.claim_scheduled() else {
            panic!("a second caller joins");
        };

        assert_eq!(waiter.until_finished(Duration::from_millis(50)).await, Wait::TimedOut);
    }
}
