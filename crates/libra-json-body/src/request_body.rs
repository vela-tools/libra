//! The request body as every layer below the context layer reads it.
//!
//! The body is parsed exactly once, where its `@context` is looked for, and every layer that judges
//! or narrows it reads that one parse from the request extensions. Two parses of one body are two
//! chances to read it two ways; one parse in one place means every check sees the same document.

use crate::{
    error::{BodyError, DocumentError},
    strict,
};
use axum::{
    body::Body,
    http::{HeaderValue, header::CONTENT_LENGTH, request::Parts},
};
use jstrict::Value;

/// A request's body, as it was read once.
///
/// The bytes stay in the request's body and are forwarded as they are unless a layer narrows the
/// document; then [`RequestBody::replace`] writes the document and the bytes together, so the two
/// never describe different bodies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestBody {
    /// The request carries no body.
    Empty,

    /// The body is not JSON. A layer that has to read a document refuses it.
    NotJson,

    /// The body's JSON document.
    Json(Value),
}

impl RequestBody {
    /// Reads a body's bytes.
    ///
    /// Bytes that are not JSON are [`RequestBody::NotJson`] rather than an error: whether that is
    /// acceptable depends on the request, which the caller of this knows and this does not.
    ///
    /// # Errors
    ///
    /// Returns [`BodyError::TooDeep`] and [`BodyError::RepeatedMember`]: JSON that two readers can
    /// read differently is refused whatever the request.
    pub fn read(bytes: &[u8]) -> Result<Self, BodyError> {
        if bytes.is_empty() {
            return Ok(Self::Empty);
        }

        match strict::parse(bytes) {
            Ok(document) => Ok(Self::Json(document)),
            Err(BodyError::NotUtf8 | BodyError::NotJson) => Ok(Self::NotJson),
            Err(error @ (BodyError::TooDeep { .. } | BodyError::RepeatedMember { .. })) => Err(error),
        }
    }

    /// The body a request was read with, or `None` when no layer above read it.
    #[must_use]
    pub fn of(parts: &Parts) -> Option<&Self> {
        parts.extensions.get::<Self>()
    }

    /// The JSON document of a request whose body a layer above read, or `None` for an empty body.
    ///
    /// # Errors
    ///
    /// Returns [`DocumentError::Unread`] when no layer above read the body, and
    /// [`DocumentError::NotJson`] when it is not JSON.
    pub fn document_in(parts: &Parts) -> Result<Option<&Value>, DocumentError> {
        match Self::of(parts) {
            None => Err(DocumentError::Unread),
            Some(Self::Empty) => Ok(None),
            Some(Self::NotJson) => Err(DocumentError::NotJson),
            Some(Self::Json(document)) => Ok(Some(document)),
        }
    }

    /// Takes the JSON document out of the extensions so it can be narrowed, or `None` for an empty
    /// body, which stays where it was.
    ///
    /// The caller puts a taken document back: through [`RequestBody::replace`] when it changed it,
    /// and as it was when it did not, so the layers below still read it.
    ///
    /// # Errors
    ///
    /// Returns [`DocumentError::Unread`] when no layer above read the body, and
    /// [`DocumentError::NotJson`] when it is not JSON.
    pub fn take_document(parts: &mut Parts) -> Result<Option<Value>, DocumentError> {
        match parts.extensions.remove::<Self>() {
            None => Err(DocumentError::Unread),
            Some(Self::Empty) => {
                parts.extensions.insert(Self::Empty);
                Ok(None)
            }
            Some(Self::NotJson) => {
                parts.extensions.insert(Self::NotJson);
                Err(DocumentError::NotJson)
            }
            Some(Self::Json(document)) => Ok(Some(document)),
        }
    }

    /// Puts back a document [`RequestBody::take_document`] took and nothing changed.
    pub fn restore(parts: &mut Parts, document: Value) {
        parts.extensions.insert(Self::Json(document));
    }

    /// The JSON document, if the body is one.
    #[must_use]
    pub const fn document(&self) -> Option<&Value> {
        match self {
            Self::Json(document) => Some(document),
            Self::Empty | Self::NotJson => None,
        }
    }

    /// Makes `document` the request's body: in the extensions, as the bytes forwarded, and in
    /// `Content-Length`.
    ///
    /// The original `Content-Length` describes the body the caller sent, and forwarding a different body
    /// under it is how a proxied request ends up truncated or hanging.
    pub fn replace(parts: &mut Parts, document: Value) -> Body {
        let bytes = strict::print(&document);

        parts.headers.remove(CONTENT_LENGTH);
        parts.headers.insert(CONTENT_LENGTH, HeaderValue::from(bytes.len()));
        parts.extensions.insert(Self::Json(document));

        Body::from(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use jstrict::json;
    use pretty_assertions::assert_eq;

    #[test]
    fn no_bytes_are_an_empty_body() {
        assert_eq!(RequestBody::read(b""), Ok(RequestBody::Empty));
    }

    #[test]
    fn bytes_that_are_not_json_are_read_as_such() {
        assert_eq!(RequestBody::read(b"plain text"), Ok(RequestBody::NotJson));
    }

    #[test]
    fn a_json_body_is_read_as_its_document() {
        assert_eq!(RequestBody::read(br#"{"id":"urn:a"}"#), Ok(RequestBody::Json(json!({"id": "urn:a"}))));
    }

    #[test]
    fn a_repeated_member_is_refused_whatever_the_request() {
        assert_eq!(
            RequestBody::read(br#"{"id":"urn:a","id":"urn:b"}"#),
            Err(BodyError::RepeatedMember { member: "id".to_owned() })
        );
    }

    #[test]
    fn a_body_no_layer_read_is_absent() {
        let (parts, ()) = Request::new(()).into_parts();

        assert_eq!(RequestBody::of(&parts), None);
    }

    #[tokio::test]
    async fn a_replaced_body_is_the_document_the_bytes_and_the_length_at_once() {
        let (mut parts, ()) = Request::builder().header(CONTENT_LENGTH, "999").body(()).unwrap().into_parts();

        let body = RequestBody::replace(&mut parts, json!({"type": "Vehicle"}));
        let bytes = body.collect().await.unwrap().to_bytes();

        assert_eq!(&bytes[..], br#"{"type":"Vehicle"}"#);
        assert_eq!(parts.headers.get(CONTENT_LENGTH).unwrap(), "18");
        assert_eq!(RequestBody::of(&parts), Some(&RequestBody::Json(json!({"type": "Vehicle"}))));
    }

    fn parts(body: Option<RequestBody>) -> Parts {
        let (mut parts, ()) = Request::new(()).into_parts();
        if let Some(body) = body {
            parts.extensions.insert(body);
        }

        parts
    }

    #[test]
    fn a_body_no_layer_read_cannot_be_read_or_taken() {
        assert_eq!(RequestBody::document_in(&parts(None)), Err(DocumentError::Unread));
        assert_eq!(RequestBody::take_document(&mut parts(None)), Err(DocumentError::Unread));
    }

    #[test]
    fn an_empty_body_has_no_document_and_stays_in_place() {
        let mut empty = parts(Some(RequestBody::Empty));

        assert_eq!(RequestBody::document_in(&empty), Ok(None));
        assert_eq!(RequestBody::take_document(&mut empty), Ok(None));
        assert_eq!(RequestBody::of(&empty), Some(&RequestBody::Empty));
    }

    #[test]
    fn a_body_that_is_not_json_has_no_document_and_stays_in_place() {
        let mut not_json = parts(Some(RequestBody::NotJson));

        assert_eq!(RequestBody::document_in(&not_json), Err(DocumentError::NotJson));
        assert_eq!(RequestBody::take_document(&mut not_json), Err(DocumentError::NotJson));
        assert_eq!(RequestBody::of(&not_json), Some(&RequestBody::NotJson));
    }

    #[test]
    fn a_taken_document_leaves_the_extensions_until_it_is_restored() {
        let mut json = parts(Some(RequestBody::Json(json!({"id": "urn:a"}))));

        let document = RequestBody::take_document(&mut json).unwrap().unwrap();
        assert_eq!(RequestBody::of(&json), None);

        RequestBody::restore(&mut json, document);
        assert_eq!(RequestBody::document_in(&json), Ok(Some(&json!({"id": "urn:a"}))));
    }
}
