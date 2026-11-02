//! Correlating a request across logs, the audit record and the response.
//!
//! The identifier is Libra's own. `SetRequestIdLayer` keeps an `x-request-id` the caller already
//! sent, which would let a caller forge or duplicate correlation ids and pad log fields up to the
//! header size limit; the inbound value is removed first, so every request carries an id Libra
//! minted.

use axum::{Router, extract::Request, middleware::map_request};
use libra_audit::request_id::REQUEST_ID_HEADER;
use tower_http::{
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    trace::TraceLayer,
};
use tracing::{Span, debug_span};

/// Removes whatever identifier the caller supplied.
async fn discard_inbound(mut request: Request) -> Request {
    request.headers_mut().remove(REQUEST_ID_HEADER);

    request
}

/// The span every log line of one request is written under: the method and the path.
///
/// The query string is left out. It carries entity ids, attribute values and filter expressions a
/// caller was not meant to leave in a log, and the audit record holds the path without it too.
fn request_span(request: &Request) -> Span {
    debug_span!("request", method = %request.method(), path = request.uri().path())
}

/// Wraps the router so each request gets a fresh identifier, is traced under it, and returns it.
pub fn apply(router: Router) -> Router {
    router
        .layer(PropagateRequestIdLayer::new(REQUEST_ID_HEADER))
        .layer(TraceLayer::new_for_http().make_span_with(request_span))
        .layer(SetRequestIdLayer::new(REQUEST_ID_HEADER, MakeRequestUuid))
        // Outermost: it has to run before `SetRequestIdLayer` looks for an existing value.
        .layer(map_request(discard_inbound))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{Body, to_bytes},
        http::Request as HttpRequest,
        routing::get,
    };
    use libra_audit::request_id::RequestId;
    use libra_log_capture::{Kind, captured};
    use pretty_assertions::assert_eq;
    use tower::ServiceExt;

    async fn id_seen_by_the_handler(request: HttpRequest<Body>) -> (String, String) {
        let app = apply(Router::new().route(
            "/",
            get(|request: Request| async move { RequestId::from_headers(request.headers()).to_string() }),
        ));

        let response = app.oneshot(request).await.unwrap();
        let returned = response
            .headers()
            .get(REQUEST_ID_HEADER)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        let seen = String::from_utf8(to_bytes(response.into_body(), 1024).await.unwrap().to_vec()).unwrap();

        (seen, returned)
    }

    #[tokio::test]
    async fn a_caller_supplied_request_id_is_replaced_not_trusted() {
        let (seen, returned) = id_seen_by_the_handler(
            HttpRequest::builder()
                .uri("/")
                .header(REQUEST_ID_HEADER, "forged-id")
                .body(Body::empty())
                .unwrap(),
        )
        .await;

        assert_ne!(seen, "forged-id");
        assert_eq!(seen, returned, "the id the handler logged is the one the caller gets back");
        assert_eq!(seen.len(), 36, "a freshly minted UUID: {seen}");
        assert_ne!(seen, "-", "the audit layer must be able to read the minted id");
    }

    #[tokio::test]
    async fn a_request_without_an_id_gets_one() {
        let (seen, _) = id_seen_by_the_handler(HttpRequest::builder().uri("/").body(Body::empty()).unwrap()).await;

        assert_eq!(seen.len(), 36);
    }

    #[tokio::test]
    async fn the_request_span_records_the_method_and_path_and_never_the_query() {
        let router = apply(Router::new().route("/entities", get(|| async { "" })));
        let request = HttpRequest::builder()
            .uri("/entities?q=owner==%22someone%22&id=urn:ngsi-ld:Vehicle:hidden")
            .body(Body::empty())
            .unwrap();

        let (_, records) = captured(router.oneshot(request)).await;

        let span = records.iter().find(|record| record.kind == Kind::Span && record.name == "request").unwrap();
        assert_eq!(span.field("method"), Some("GET"));
        assert_eq!(span.field("path"), Some("/entities"));
        for record in &records {
            assert!(!record.mentions("someone") && !record.mentions("hidden"), "{record:?}");
        }
    }
}
