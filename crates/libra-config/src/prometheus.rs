//! `[prometheus]`: the metrics endpoint.

use crate::metrics_path::MetricsPath;
use serde::{Deserialize, Serialize};

/// Prometheus metrics configuration.
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(default, rename_all = "kebab-case", deny_unknown_fields)]
pub struct Prometheus {
    /// Collect and expose metrics.
    pub enabled: bool,
    /// Path the metrics are served on.
    pub path: MetricsPath,
}

impl Default for Prometheus {
    fn default() -> Self {
        Self {
            enabled: true,
            path: MetricsPath::from_static("/ngsi-ld/auth/metrics"),
        }
    }
}
