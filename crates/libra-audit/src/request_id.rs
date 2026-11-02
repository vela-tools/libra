//! The correlation id assigned to a request at the edge.

use axum::http::{HeaderMap, HeaderName};
use derive_more::Display;
use uuid::Uuid;

/// The header carrying the correlation id assigned at the edge.
pub const REQUEST_ID_HEADER: HeaderName = HeaderName::from_static("x-request-id");

/// The correlation id of a request, as it appears in logs and the audit record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Display)]
pub enum RequestId {
    /// The id Libra minted for the request.
    #[display("{_0}")]
    Assigned(Uuid),
    /// The request carried no id Libra could read, as when the edge layer is not in front of this
    /// one. Written as `-` so a log field is never empty.
    #[display("-")]
    Unassigned,
}

impl RequestId {
    /// Reads the id the edge layer put in the request headers.
    ///
    /// Anything that is not a UUID is [`RequestId::Unassigned`]: the edge layer discards whatever
    /// the caller sent and mints a UUID of its own, so a value of any other shape was not put there
    /// by Libra and is not worth copying into an audit sink.
    #[must_use]
    pub fn from_headers(headers: &HeaderMap) -> Self {
        headers
            .get(REQUEST_ID_HEADER)
            .and_then(|value| value.to_str().ok())
            .and_then(|text| Uuid::parse_str(text).ok())
            .map_or(Self::Unassigned, Self::Assigned)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    const MINTED: &str = "67e55044-10b1-426f-9247-bb680e5fe0c8";

    #[test]
    fn a_minted_id_is_read_back_unchanged() {
        let mut headers = HeaderMap::new();
        headers.insert(REQUEST_ID_HEADER, MINTED.parse().unwrap());

        assert_eq!(RequestId::from_headers(&headers).to_string(), MINTED);
    }

    #[test]
    fn a_missing_id_is_written_as_a_dash() {
        assert_eq!(RequestId::from_headers(&HeaderMap::new()), RequestId::Unassigned);
        assert_eq!(RequestId::Unassigned.to_string(), "-");
    }

    #[test]
    fn a_value_that_is_not_a_uuid_is_not_copied_into_the_record() {
        let mut headers = HeaderMap::new();
        headers.insert(REQUEST_ID_HEADER, "forged-by-the-caller".parse().unwrap());

        assert_eq!(RequestId::from_headers(&headers), RequestId::Unassigned);
    }
}
