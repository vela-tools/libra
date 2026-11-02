//! `[timeout]`: upstream request timeout.

use serde::{Deserialize, Serialize};

/// Timeout configuration.
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(default, rename_all = "kebab-case", deny_unknown_fields)]
pub struct Timeout {
    /// Timeout for upstream requests, in seconds.
    pub upstream_timeout_seconds: u64,
}

impl Default for Timeout {
    fn default() -> Self {
        Self { upstream_timeout_seconds: 30 }
    }
}
