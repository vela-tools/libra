//! The one read-edit-write of a JSON answer.

use crate::error::{RewriteError, UnreadableResponse};
use axum::{
    body::{Body, to_bytes},
    http::{
        HeaderMap,
        HeaderValue,
        StatusCode,
        header::{CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE},
    },
    response::Response,
};
use jstrict::Value;
use libra_json_body::strict::{parse, print};
use libra_ngsi_ld_representation::accept::MediaType;

/// Applies `edit` to the JSON document a successful response carries.
///
/// A non-success response carries a problem description and an empty or `204` body carries
/// nothing, so both pass through untouched. Otherwise the body is read up to `max_body_bytes`,
/// parsed as the media type the broker labelled it with, not the one the caller asked for: a broker
/// may answer `Accept: application/geo+json` with plain JSON, and the body is edited as what it is, then
/// written back, and given a `Content-Length` that matches.
///
/// The parse is the strict one every body Libra reads goes through, and the print keeps member
/// order and the lexical form of every number, so what the edit leaves alone reaches the caller as
/// the broker wrote it.
///
/// # Errors
///
/// Returns [`RewriteError::Unreadable`] when the body is content-encoded, larger than
/// `max_body_bytes`, not a JSON media type, or refused by the strict parse (not JSON, nested past
/// its limit, or repeating a member), and [`RewriteError::Edit`] when `edit` refuses the document.
pub async fn rewrite<F, E>(response: Response, max_body_bytes: usize, edit: F) -> Result<Response, RewriteError<E>>
where
    F: FnOnce(&mut Value, MediaType) -> Result<(), E> + Send,
    E: Send,
{
    if !response.status().is_success() {
        return Ok(response);
    }

    let (mut parts, body) = response.into_parts();

    if parts.headers.contains_key(CONTENT_ENCODING) {
        return Err(RewriteError::Unreadable(UnreadableResponse::ContentEncoded));
    }

    let bytes = to_bytes(body, max_body_bytes)
        .await
        .map_err(|_| RewriteError::Unreadable(UnreadableResponse::TooLarge))?;

    if bytes.is_empty() || parts.status == StatusCode::NO_CONTENT {
        return Ok(Response::from_parts(parts, Body::from(bytes)));
    }

    let Some(media_type) = MediaType::from_content_type(parts.headers.get(CONTENT_TYPE).and_then(|value| value.to_str().ok())) else {
        return Err(RewriteError::Unreadable(UnreadableResponse::NotJson));
    };

    // A repeated member is refused rather than edited: the occurrence an edit removes may not be
    // the one the caller's parser keeps.
    let mut document = parse(&bytes).map_err(|_| RewriteError::Unreadable(UnreadableResponse::Unparsable))?;

    edit(&mut document, media_type).map_err(RewriteError::Edit)?;

    let rewritten = print(&document);

    restate_length(&mut parts.headers, rewritten.len());

    Ok(Response::from_parts(parts, Body::from(rewritten)))
}

/// Replaces `Content-Length` with the length of the body that is actually sent.
///
/// The broker's `Content-Length` describes the body the broker sent, and forwarding a different one under it is how
/// a proxied response ends up truncated or hanging.
fn restate_length(headers: &mut HeaderMap, length: usize) {
    headers.remove(CONTENT_LENGTH);

    if let Ok(value) = HeaderValue::from_str(&length.to_string()) {
        headers.insert(CONTENT_LENGTH, value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;
    use jstrict::json;
    use libra_json_body::nesting::MAX_DEPTH;
    use pretty_assertions::assert_eq;
    use std::convert::Infallible;

    fn response(status: StatusCode, headers: &[(&'static str, &'static str)], body: impl Into<Body>) -> Response {
        let mut builder = Response::builder().status(status);
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }

        builder.body(body.into()).unwrap()
    }

    async fn body_of(response: Response) -> String {
        let bytes = response.into_body().collect().await.map(http_body_util::Collected::to_bytes).unwrap();

        String::from_utf8(bytes.to_vec()).unwrap()
    }

    /// An edit that removes the `secret` member of an object, and refuses an object naming it twice.
    fn remove_secret() -> impl FnOnce(&mut Value, MediaType) -> Result<(), &'static str> + Send {
        |document, _media_type| {
            if let Some(entity) = document.as_object_mut() {
                entity.remove_unique("secret").map_err(|_| "secret is named twice")?;
            }

            Ok(())
        }
    }

    /// An edit that leaves the document as it is.
    fn leave_alone() -> impl FnOnce(&mut Value, MediaType) -> Result<(), Infallible> + Send {
        |_document, _media_type| Ok(())
    }

    #[tokio::test]
    async fn a_json_answer_is_edited_and_its_length_restated() {
        let original = response(
            StatusCode::OK,
            &[("content-type", "application/json"), ("content-length", "33")],
            r#"{"id":"urn:a","secret":"hidden"}"#,
        );

        let rewritten = rewrite(original, 1024, remove_secret()).await.unwrap();

        assert_eq!(rewritten.headers().get(CONTENT_LENGTH).unwrap(), "14");
        assert_eq!(body_of(rewritten).await, r#"{"id":"urn:a"}"#);
    }

    #[tokio::test]
    async fn the_edit_is_given_the_media_type_the_broker_answered_with() {
        let original = response(StatusCode::OK, &[("content-type", "application/geo+json; charset=utf-8")], "{}");

        let seen = rewrite(original, 1024, |_document: &mut Value, media_type| match media_type {
            MediaType::GeoJson => Ok(()),
            MediaType::Json | MediaType::JsonLd => Err(media_type),
        })
        .await;

        assert!(seen.is_ok());
    }

    #[tokio::test]
    async fn an_error_answer_and_an_empty_answer_pass_through_untouched() {
        let problem = response(StatusCode::NOT_FOUND, &[("content-type", "text/plain")], "not found");
        assert_eq!(body_of(rewrite(problem, 1024, remove_secret()).await.unwrap()).await, "not found");

        let empty = response(StatusCode::NO_CONTENT, &[], "");
        assert_eq!(body_of(rewrite(empty, 1024, remove_secret()).await.unwrap()).await, "");
    }

    #[tokio::test]
    async fn a_body_that_cannot_be_read_is_refused_rather_than_forwarded() {
        let cases = [
            (
                response(StatusCode::OK, &[("content-type", "application/json"), ("content-encoding", "gzip")], "{}"),
                UnreadableResponse::ContentEncoded,
            ),
            (
                response(StatusCode::OK, &[("content-type", "application/json")], r#"{"padding":"................"}"#),
                UnreadableResponse::TooLarge,
            ),
            (
                response(StatusCode::OK, &[("content-type", "text/html")], "<html></html>"),
                UnreadableResponse::NotJson,
            ),
            (response(StatusCode::OK, &[], "{}"), UnreadableResponse::NotJson),
            (
                response(StatusCode::OK, &[("content-type", "application/ld+json")], "{not json"),
                UnreadableResponse::Unparsable,
            ),
        ];

        for (original, expected) in cases {
            assert_eq!(
                rewrite(original, 16, remove_secret()).await.err(),
                Some(RewriteError::Unreadable(expected)),
                "{expected}"
            );
        }
    }

    #[tokio::test]
    async fn an_edit_that_refuses_the_document_is_reported_as_such() {
        let original = response(StatusCode::OK, &[("content-type", "application/json")], r#"{"id":"urn:a"}"#);

        let refused = rewrite(
            original,
            1024,
            |document: &mut Value, _media_type| {
                if document == &json!({ "id": "urn:a" }) { Err("not an index") } else { Ok(()) }
            },
        )
        .await;

        assert_eq!(refused.err(), Some(RewriteError::Edit("not an index")));
    }

    #[tokio::test]
    async fn an_answer_nested_past_the_limit_is_unreadable() {
        let nested = format!("{}{}", "[".repeat(MAX_DEPTH + 1), "]".repeat(MAX_DEPTH + 1));
        let original = response(StatusCode::OK, &[("content-type", "application/json")], nested);

        assert_eq!(
            rewrite(original, 1024, leave_alone()).await.err(),
            Some(RewriteError::Unreadable(UnreadableResponse::Unparsable))
        );
    }

    #[tokio::test]
    async fn an_answer_repeating_a_member_is_unreadable() {
        let original = response(
            StatusCode::OK,
            &[("content-type", "application/ld+json")],
            r#"{"id":"urn:a","secret":"hidden","secret":"also hidden"}"#,
        );

        assert_eq!(
            rewrite(original, 1024, remove_secret()).await.err(),
            Some(RewriteError::Unreadable(UnreadableResponse::Unparsable))
        );
    }

    #[tokio::test]
    async fn an_unedited_answer_keeps_member_order_and_number_lexical_forms() {
        let text = r#"{"z":1.0,"a":1e400,"m":12345678901234567890123}"#;
        let original = response(StatusCode::OK, &[("content-type", "application/json")], text);

        assert_eq!(body_of(rewrite(original, 1024, leave_alone()).await.unwrap()).await, text);
    }
}
