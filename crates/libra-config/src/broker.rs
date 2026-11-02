//! `[broker]`: the upstream NGSI-LD context broker.

use serde::{Deserialize, Serialize};
use url::Url;

/// Backend context broker configuration.
///
/// Required, with no default. A guessed address would forward every request to whatever answers
/// under that name on the deployment's network, so a configuration that names no broker is refused
/// at startup with the key it is missing.
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Broker {
    /// URL of the NGSI-LD context broker.
    pub url: Url,
}
