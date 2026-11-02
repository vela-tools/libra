//! `[helmet]`: security response headers.

use serde::{Deserialize, Serialize};

/// Security header configuration.
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(default, rename_all = "kebab-case", deny_unknown_fields)]
pub struct Helmet {
    /// Emit security headers on every response.
    pub enabled: bool,
}

impl Default for Helmet {
    fn default() -> Self {
        Self { enabled: true }
    }
}
