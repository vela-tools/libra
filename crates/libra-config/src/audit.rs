//! `[audit]`: the audit trail.

use crate::hex_secret::HexSecret;
use serde::{Deserialize, Serialize};

/// Audit configuration.
#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq, Default)]
#[serde(default, rename_all = "kebab-case", deny_unknown_fields)]
pub struct Audit {
    /// The key the audit record's credential fingerprints are computed under, as hex.
    ///
    /// Absent, no fingerprint is computed and the audit record carries only the subject.
    /// Setting a key is the deliberate decision to record a keyed digest of every
    /// presented credential: it correlates requests by credential (including refused ones a
    /// subject could not name), and rotating the key deliberately breaks that correlation.
    pub token_fingerprint_key: Option<HexSecret>,
}
