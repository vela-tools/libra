//! The path of a request, as recorded.

use axum::http::Uri;
use derive_more::Display;

/// The path of a request with its query string removed.
///
/// A query string on an NGSI-LD request holds entity ids, geo-queries and attribute filters, and
/// copying those into the audit sink leaks the data the request was authorized for into a system
/// with different access rules, so this type can only be built from the path component.
#[derive(Debug, Clone, PartialEq, Eq, Display)]
#[display("{_0}")]
pub struct RequestPath(String);

impl RequestPath {
    /// Takes the path of a request URI, dropping its query.
    #[must_use]
    pub fn of(uri: &Uri) -> Self {
        Self(uri.path().to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn the_query_string_is_dropped() {
        let uri: Uri = "/ngsi-ld/v1/entities?type=Vehicle&id=urn:ngsi-ld:Vehicle:secret".parse().unwrap();

        assert_eq!(RequestPath::of(&uri).to_string(), "/ngsi-ld/v1/entities");
    }
}
