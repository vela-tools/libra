//! The route the metrics endpoint is mounted on.

use derive_more::{Display, Into};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use thiserror::Error;

/// Every route Libra serves for itself sits under this prefix, beside the proxied API rather than
/// inside it.
const LIBRA_ROUTES: &str = "/ngsi-ld/auth/";

/// A metrics path outside the routes Libra keeps for itself.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("prometheus.path '{path}' must be a route under '{LIBRA_ROUTES}'")]
pub struct MetricsPathOutsideLibraRoutes {
    /// What was written.
    pub path: String,
}

/// The route the metrics endpoint is mounted on: a path under `/ngsi-ld/auth/`.
///
/// Every other path is the broker's. A metrics route mounted on one would answer in place of the
/// proxied route of that name, unauthenticated and unaudited, and a path with no leading slash
/// makes axum panic while building the router; both are refused where the file is read.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Display, Into, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
#[display("{_0}")]
#[into(String)]
pub struct MetricsPath(Cow<'static, str>);

impl MetricsPath {
    /// Wraps a path known at compile time.
    ///
    /// # Panics
    ///
    /// Panics during constant evaluation, which is a compile error, if `path` is not under
    /// `/ngsi-ld/auth/`.
    #[must_use]
    pub const fn from_static(path: &'static str) -> Self {
        assert!(is_libra_route(path), "a metrics path must be under /ngsi-ld/auth/");

        Self(Cow::Borrowed(path))
    }

    /// Checks and wraps a path read from a file.
    ///
    /// # Errors
    ///
    /// Returns [`MetricsPathOutsideLibraRoutes`] if the path is not under `/ngsi-ld/auth/` or is
    /// that prefix alone.
    pub fn new(path: String) -> Result<Self, MetricsPathOutsideLibraRoutes> {
        if is_libra_route(&path) {
            Ok(Self(Cow::Owned(path)))
        } else {
            Err(MetricsPathOutsideLibraRoutes { path })
        }
    }

    /// The path as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for MetricsPath {
    type Error = MetricsPathOutsideLibraRoutes;

    fn try_from(path: String) -> Result<Self, Self::Error> {
        Self::new(path)
    }
}

/// Whether `path` names a route below [`LIBRA_ROUTES`], not the prefix itself.
///
/// An index loop because a `const fn` can neither compare slices nor call iterator adapters.
const fn is_libra_route(path: &str) -> bool {
    let (path, prefix) = (path.as_bytes(), LIBRA_ROUTES.as_bytes());
    if path.len() <= prefix.len() {
        return false;
    }

    let mut index = 0;
    while index < prefix.len() {
        if path[index] != prefix[index] {
            return false;
        }
        index += 1;
    }

    true
}

#[cfg(test)]
mod tests {
    use crate::metrics_path::MetricsPath;
    use pretty_assertions::assert_eq;

    #[test]
    fn a_path_under_libras_own_routes_is_accepted() {
        assert_eq!(MetricsPath::new("/ngsi-ld/auth/metrics".to_owned()).unwrap().as_str(), "/ngsi-ld/auth/metrics");
    }

    #[test]
    fn a_path_a_proxied_route_could_have_is_refused() {
        for proxied in ["/metrics", "/ngsi-ld/v1/entities", "/ngsi-ld/v1/types", "/", "/ngsi-ld/authority"] {
            assert!(MetricsPath::new(proxied.to_owned()).is_err(), "{proxied:?} must not be a metrics path");
        }
    }

    #[test]
    fn the_prefix_alone_or_a_relative_path_is_refused() {
        for written in ["", "metrics", "./metrics", "/ngsi-ld/auth/", "/ngsi-ld/auth"] {
            assert!(MetricsPath::new(written.to_owned()).is_err(), "{written:?} must not be a metrics path");
        }
    }

    #[test]
    fn the_refusal_names_what_was_written() {
        assert_eq!(MetricsPath::new("/metrics".to_owned()).unwrap_err().path, "/metrics");
    }
}
