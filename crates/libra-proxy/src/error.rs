//! Why a proxy could not be built.
//!
//! Everything here happens once, at startup. A request that fails on the way to the broker is not
//! an error of this kind: it becomes a [`libra_problem_details::problem::Problem`] and is answered.

use thiserror::Error;
use url::Url;

/// The proxy could not be constructed from its settings.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ProxyError {
    /// The upstream is not something a request can be forwarded to.
    ///
    /// Checked once here rather than per request, so a deployment with a mistyped broker URL fails
    /// at startup instead of answering every request with a gateway error.
    #[error("upstream '{upstream}' is not an absolute http or https URL without a query")]
    InvalidUpstream {
        /// The upstream as configured.
        upstream: Url,
    },

    /// The TLS client could not be built.
    #[error("could not build the upstream TLS client: {reason}")]
    Tls {
        /// What rustls reported.
        reason: String,
    },
}
