//! `[payload]`: request body size limit.

use serde::{Deserialize, Serialize};

/// Payload size configuration.
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(default, rename_all = "kebab-case", deny_unknown_fields)]
pub struct Payload {
    /// Enforce the body size limit.
    pub enabled: bool,
    /// Maximum request body size in bytes.
    pub max_body_size_bytes: usize,
}

impl Default for Payload {
    fn default() -> Self {
        Self {
            enabled: true,
            max_body_size_bytes: 2_097_152,
        }
    }
}
