//! The requests to stop that the process receives.
//!
//! Stopping takes two of them. The first starts a drain, in which in-flight requests are given time
//! to finish. The second, from an operator who is tired of waiting, ends the drain at once. Both
//! arrive through the same source so that serving does not have to know whether it is listening to
//! the operating system or to a test.

use std::future::{Future, pending};
use tokio::signal;
#[cfg(unix)]
use tokio::signal::unix::{SignalKind, signal as unix_signal};
use tracing::{info, warn};

/// A source of requests to stop.
pub trait ShutdownRequests {
    /// Resolves when the next request to stop arrives.
    ///
    /// Called again after it has resolved, to wait for a further request.
    fn next_request(&mut self) -> impl Future<Output = ()> + Send;
}

/// Interrupt and termination, as the operating system delivers them.
#[derive(Debug, Default, Clone, Copy)]
pub struct OsSignals;

impl ShutdownRequests for OsSignals {
    async fn next_request(&mut self) {
        tokio::select! {
            () = interrupt() => info!("interrupted"),
            () = terminate() => info!("termination requested"),
        }
    }
}

/// Resolves on an interrupt, or never when the handler cannot be installed.
///
/// A handler that cannot be installed means the process cannot be stopped politely by that signal.
/// It is reported and waited on for ever, so shutdown falls back to the default action of the
/// signal instead of to a process that cannot be stopped at all.
async fn interrupt() {
    if let Err(error) = signal::ctrl_c().await {
        warn!(error = %error, "could not listen for an interrupt");
        pending::<()>().await;
    }
}

/// Resolves on a termination request, or never when the handler cannot be installed.
#[cfg(unix)]
async fn terminate() {
    match unix_signal(SignalKind::terminate()) {
        Ok(mut stream) => {
            stream.recv().await;
        }
        Err(error) => {
            warn!(error = %error, "could not listen for a termination signal");
            pending::<()>().await;
        }
    }
}

/// There is no termination request to wait for on this platform.
#[cfg(not(unix))]
async fn terminate() {
    pending::<()>().await;
}
