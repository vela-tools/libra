//! Why a request could not be turned into an operation.
//!
//! Every variant here is a refusal, not a fallback. A request whose shape Libra cannot name is a
//! request Libra cannot make an authorization decision about, and the only safe answer is to say
//! so rather than to guess at a resource kind and enforce the wrong rules.

use http::Method;
use thiserror::Error;

/// A request could not be classified.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum OperationError {
    /// The HTTP method has no NGSI-LD meaning.
    ///
    /// `TRACE` lands here deliberately: it reflects the request back, headers included, and the
    /// proxy adds identity headers of its own on the way to the broker.
    #[error("HTTP method {method} is not allowed")]
    MethodNotAllowed {
        /// The method as it arrived.
        method: Method,
    },

    /// A path segment is, or hides, a relative segment.
    ///
    /// Normalisation differs between HTTP stacks, so a dot segment is a way for one hop to see a
    /// different resource than the next, whether it was written plainly or reached only after
    /// percent-decoding.
    #[error("path contains a relative segment")]
    RelativeSegment,

    /// A segment another hop could split or truncate differently.
    #[error("path segment is ambiguous: {reason}")]
    AmbiguousSegment {
        /// What makes it ambiguous.
        reason: &'static str,
    },

    /// A path segment is not valid UTF-8 once decoded.
    #[error("path segment {segment} is not valid UTF-8 when decoded")]
    UndecodableSegment {
        /// The offending segment, still encoded.
        segment: String,
    },
}
