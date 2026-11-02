//! Why a pre-flight produced nothing a layer can act on.

use http::StatusCode;
use libra_json_body::error::BodyError;
use thiserror::Error;
use url::ParseError;

/// The pre-flight did not produce an entity document.
///
/// Every variant means the same thing to the layer that asked: the entity's type or scope could
/// not be established, so the request is refused. The variants exist for the log.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PreflightError {
    /// The HTTP client could not be constructed.
    #[error("the pre-flight http client could not be built: {reason}")]
    Client {
        /// What the HTTP stack reported.
        reason: String,
    },

    /// The broker URL and the entity identifier do not form a URL.
    #[error("the pre-flight URL could not be built: {source}")]
    Url {
        /// What the URL parser reported.
        #[from]
        source: ParseError,
    },

    /// The broker could not be reached, or did not answer in time.
    #[error("the pre-flight request to the broker failed: {reason}")]
    Unreachable {
        /// What the HTTP stack reported.
        reason: String,
    },

    /// The broker answered with something other than success.
    #[error("the broker answered the pre-flight with status {status}")]
    Status {
        /// The status it answered with.
        status: StatusCode,
    },

    /// The answer exceeded the configured body limit.
    #[error("the pre-flight response is larger than the configured limit")]
    TooLarge,

    /// The body stopped arriving.
    #[error("the pre-flight response could not be read: {reason}")]
    Unreadable {
        /// What the HTTP stack reported.
        reason: String,
    },

    /// The body is not a JSON document the strict parse accepts: not JSON at all, nested past
    /// the limit, or repeating a member.
    #[error("the pre-flight response is not a readable JSON document: {source}")]
    NotJson {
        /// What the strict parse refused.
        #[from]
        source: BodyError,
    },
}
