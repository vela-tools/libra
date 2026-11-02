//! `[limits]`: how many requests may be in flight at once.

use serde::{Deserialize, Serialize};

/// Concurrency limit configuration.
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(default, rename_all = "kebab-case", deny_unknown_fields)]
pub struct Limits {
    /// Enforce the in-flight ceiling.
    pub enabled: bool,
    /// Maximum requests processed at the same time.
    pub max_in_flight_requests: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            enabled: true,
            max_in_flight_requests: 256,
        }
    }
}
