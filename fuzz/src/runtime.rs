//! The one Tokio runtime the asynchronous targets run on.
//!
//! Multi-threaded, so a server a target starts keeps answering on the workers while the target
//! blocks the fuzzing thread on a request to it.

use std::sync::LazyLock;
use tokio::runtime::{Builder, Runtime};

static RUNTIME: LazyLock<Runtime> = LazyLock::new(|| {
    Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("a Tokio runtime starts")
});

/// The shared runtime.
#[must_use]
pub fn shared() -> &'static Runtime {
    &RUNTIME
}
