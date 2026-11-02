//! `[authz]`: the policy engine's own settings.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// What to do with a request no policy matched.
///
/// Mirrors the `effect` field of a policy file on the wire, but is declared here as configuration
/// so this crate does not depend on the policy model. `libra-policy-store` converts it.
#[derive(Deserialize, Serialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum DefaultEffect {
    /// Let the request through.
    Allow,
    /// Refuse the request. The default, and the only fail-secure choice.
    #[default]
    Deny,
}

/// Authorization policy engine configuration.
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(default, rename_all = "kebab-case", deny_unknown_fields)]
pub struct Authz {
    /// Directory containing policy TOML files.
    pub policies_dir: PathBuf,
    /// Effect applied when no policy matches.
    pub default_effect: DefaultEffect,
}

impl Default for Authz {
    fn default() -> Self {
        Self {
            policies_dir: PathBuf::from("/etc/libra/policies"),
            default_effect: DefaultEffect::Deny,
        }
    }
}
