//! Why an answer could not be rewritten.

use strum::{Display, IntoStaticStr};
use thiserror::Error;

/// Why a successful answer could not be read.
///
/// Every variant means the body is withheld. An answer a layer cannot read is one it cannot show
/// free of what it was asked to remove, and forwarding it whole is the disclosure the rewrite exists
/// to prevent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Display, IntoStaticStr)]
pub enum UnreadableResponse {
    /// The body is compressed. `Accept-Encoding` is removed on the way out, so a broker that
    /// compresses anyway is answering a request it was not sent.
    #[strum(to_string = "the upstream response is content-encoded")]
    ContentEncoded,
    /// The body is larger than the configured limit.
    #[strum(to_string = "the upstream response is larger than the configured limit")]
    TooLarge,
    /// The body is labelled as something other than JSON, JSON-LD or `GeoJSON`.
    #[strum(to_string = "the upstream response is not JSON")]
    NotJson,
    /// The body is labelled JSON and the strict parse refuses it: it is not JSON, nests arrays
    /// and objects past the limit, or repeats a member.
    #[strum(to_string = "the upstream response is not the JSON its content type claims")]
    Unparsable,
}

impl UnreadableResponse {
    /// The reason, for an error variant that carries it.
    #[must_use]
    pub fn reason(self) -> &'static str {
        self.into()
    }
}

/// A rewrite failed, either around the edit or in it.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RewriteError<E> {
    /// The body could not be read.
    #[error("{0}")]
    Unreadable(UnreadableResponse),
    /// The edit itself refused the document.
    #[error("{0}")]
    Edit(E),
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn the_reason_is_the_message() {
        assert_eq!(UnreadableResponse::NotJson.reason(), "the upstream response is not JSON");
        assert_eq!(UnreadableResponse::NotJson.reason(), UnreadableResponse::NotJson.to_string());
    }
}
