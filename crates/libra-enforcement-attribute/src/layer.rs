//! The Tower layer that applies an attribute restriction to a request and its response.
//!
//! Placement matters as much as the code. The layer must sit below authorization, so a decision
//! exists by the time it runs, and above the proxy, so it sees the response before the caller
//! does. It must also sit below any cache: a cached response has already been filtered for
//! whoever it was cached for, and filtering it again for someone else would be filtering the wrong
//! entry rather than the wrong body. A request without a decision is refused as a wiring fault.

use crate::{
    document,
    error::FilterError,
    filters::DEFAULT_GEOPROPERTY,
    index,
    narrowing::{DocumentPlan, ResponsePlan, narrow},
    registration,
};
use axum::{
    extract::Request,
    response::{IntoResponse, Response},
};
use jstrict::Value;
use libra_jsonld_context_layer::RequestContextExtension;
use libra_jsonld_term_expansion::{name::Term, resolved::ResolvedContext};
use libra_ngsi_ld_entity_document::{
    linked::{Visibility, judge_linked},
    unwalkable::Unwalkable,
};
use libra_ngsi_ld_representation::accept::MediaType;
use libra_policy_engine::decision::Decision;
use libra_policy_model::attribute::CompiledAttributeRestriction;
use libra_response_json::{error::RewriteError, rewrite::rewrite};
use std::{
    convert::Infallible,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tower::{Layer, Service, ServiceExt};
use tracing::{debug, warn};

/// Applies attribute restrictions.
#[derive(Debug, Clone, Copy)]
pub struct AttributeFilterLayer {
    max_body_bytes: usize,
}

impl AttributeFilterLayer {
    /// Builds the layer.
    ///
    /// `max_body_bytes` bounds the response body read to filter it, so no answer is materialised
    /// without a ceiling. The request body is read, and bounded, once by the context layer above.
    #[must_use]
    pub const fn new(max_body_bytes: usize) -> Self {
        Self { max_body_bytes }
    }
}

impl<S> Layer<S> for AttributeFilterLayer {
    type Service = AttributeFilterService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AttributeFilterService {
            inner,
            max_body_bytes: self.max_body_bytes,
        }
    }
}

/// The service produced by [`AttributeFilterLayer`].
#[derive(Debug, Clone)]
pub struct AttributeFilterService<S> {
    inner: S,
    max_body_bytes: usize,
}

impl<S> Service<Request> for AttributeFilterService<S>
where
    S: Service<Request, Response = Response, Error = Infallible> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = Response;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Response, Infallible>> + Send>>;

    /// Always ready. The inner service's readiness is driven by `oneshot` in [`Self::call`], on
    /// the clone that actually serves the request.
    fn poll_ready(&mut self, _context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request) -> Self::Future {
        let inner = self.inner.clone();
        let max_body_bytes = self.max_body_bytes;

        Box::pin(async move {
            match apply(inner, request, max_body_bytes).await {
                Ok(response) => Ok(response),
                Err(error) => {
                    warn!(error = %error, "attribute filtering refused the request");

                    Ok(error.to_problem().into_response())
                }
            }
        })
    }
}

/// Narrows the request, forwards it, and filters what comes back.
async fn apply<S>(inner: S, request: Request, max_body_bytes: usize) -> Result<Response, FilterError>
where
    S: Service<Request, Response = Response, Error = Infallible> + Send + 'static,
    S::Future: Send + 'static,
{
    let decision = request.extensions().get::<Decision>().ok_or(FilterError::Undecided)?;

    // A reference count, not a copy: the request that owns the decision is moved into the rewrite and forward steps while the restriction is still read.
    let Some(restriction) = decision.attribute.clone() else {
        // The policy that allowed the request attached no attribute restriction.
        return Ok(inner.oneshot(request).await.unwrap_or_else(|error| match error {}));
    };

    let Some(context) = request.extensions().get::<RequestContextExtension>().map(|extension| Arc::clone(&extension.0)) else {
        return Err(FilterError::Unresolved);
    };

    let (request, plan) = narrow(request, &restriction, &context)?;

    let response = inner.oneshot(request).await.unwrap_or_else(|error| match error {});

    match plan {
        // A write's response carries the identifiers it touched, not attribute values.
        ResponsePlan::Passthrough => Ok(response),
        ResponsePlan::Registration(resource) => registration::filter_response(response, &resource, &restriction, &context, max_body_bytes).await,
        ResponsePlan::Document(plan) => filter_response(response, &restriction, &context, &plan, max_body_bytes).await,
    }
}

/// Removes from the response what the restriction does not allow.
async fn filter_response(
    response: Response,
    restriction: &CompiledAttributeRestriction,
    context: &ResolvedContext,
    plan: &DocumentPlan,
    max_body_bytes: usize,
) -> Result<Response, FilterError> {
    rewrite(response, max_body_bytes, |document, media_type| {
        filter_document(document, media_type, restriction, context, plan)
    })
    .await
    .map_err(|error| FilterError::Unfilterable {
        reason: match error {
            RewriteError::Unreadable(unreadable) => unreadable.reason(),
            RewriteError::Edit(reason) => reason,
        },
    })
}

/// Removes from one answer document what the restriction does not allow, or says why it cannot.
///
/// `media_type` is what the broker actually sent, not what the caller asked for: a broker is
/// entitled to answer an `Accept: application/geo+json` with plain JSON, and filtering that answer
/// as a Feature would edit members it does not have.
///
/// A Feature's `geometry` is kept only when `location` is allowed. A `geometryProperty` or a
/// `geoproperty` the caller named was judged on the way in, so `location`, the default every broker
/// falls back to (NGSI-LD 4.5.16.1), is the one attribute the geometry may have been lifted from that
/// nothing has judged yet; a broker that ignores the named one would otherwise publish it.
fn filter_document(
    document: &mut Value,
    media_type: MediaType,
    restriction: &CompiledAttributeRestriction,
    context: &ResolvedContext,
    plan: &DocumentPlan,
) -> Result<(), &'static str> {
    let removed = match plan {
        DocumentPlan::Entity { join } => {
            let geoproperty = &Term::new(DEFAULT_GEOPROPERTY);
            let mut removed = document::filter(document, restriction, context, geoproperty, media_type).map_err(Unwalkable::reason)?;

            if let Some(mode) = join {
                let mut failure = Ok(());

                // A linked entity that cannot be filtered is withheld, and the whole answer with it.
                judge_linked(document, media_type, *mode, |entity| {
                    match document::filter_entity(entity, restriction, context, geoproperty) {
                        Ok(count) => {
                            removed += count;
                            Visibility::Show
                        }
                        Err(unwalkable) => {
                            failure = Err(unwalkable);
                            Visibility::Withhold
                        }
                    }
                })
                .map_err(Unwalkable::reason)?;
                failure.map_err(Unwalkable::reason)?;
            }

            removed
        }
        DocumentPlan::MetadataIndex => index::filter(document, restriction, context).ok_or("the upstream response is not a metadata-index document")?,
    };

    debug!(removed, "filtered attributes out of the response");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use http::{
        Method,
        StatusCode,
        header::{ACCEPT_ENCODING, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE},
    };
    use http_body_util::BodyExt;
    use libra_config::representation::RepresentationStrictness;
    use libra_json_body::request_body::RequestBody;
    use libra_jsonld_term_expansion::name::{ExpandedIri, Term};
    use libra_linked_entity_layer::layer::LinkedEntityLayer;
    use libra_log_capture::{Emitted, captured};
    use libra_ngsi_ld_operation_layer::layer::{OperationLayer, classify};
    use libra_ngsi_ld_query_layer::layer::{QueryLayer, read_query};
    use libra_ngsi_ld_representation_layer::RepresentationLayer;
    use libra_policy_model::{attribute::AttributeAction, effect::Effect};
    use pretty_assertions::assert_eq;
    use serde_json::{Value, json};
    use std::sync::{Arc, Mutex, PoisonError};
    use tower::util::BoxCloneService;

    fn context() -> Arc<ResolvedContext> {
        Arc::new(
            ResolvedContext::from_json(
                r#"{
                    "@vocab": "https://uri.etsi.org/ngsi-ld/default-context/",
                    "speed": "https://uri.fiware.org/ns/data-models#speed",
                    "location": "https://uri.etsi.org/ngsi-ld/location"
                }"#,
            )
            .expect("the test context should process"),
        )
    }

    fn iri(term: &str) -> ExpandedIri {
        context().expand(&Term::new(term)).expect("the term should expand")
    }

    fn decision(action: AttributeAction, terms: &[&str]) -> Decision {
        Decision {
            effect: Effect::Allow,
            matched: None,
            scope: None,
            entity_type: None,
            time: None,
            attribute: Some(Arc::new(CompiledAttributeRestriction::new(
                action,
                terms.iter().map(|term| iri(term)).collect(),
            ))),
            aggregation: None,
        }
    }

    /// A decision that allows the request with no attribute restriction.
    fn unrestricted() -> Decision {
        Decision {
            attribute: None,
            ..decision(AttributeAction::Omit, &[])
        }
    }

    /// What the upstream saw, so a test can assert on the outgoing request too.
    #[derive(Clone, Default)]
    struct Seen {
        uri: Arc<Mutex<String>>,
        accept_encoding: Arc<Mutex<Option<String>>>,
        body: Arc<Mutex<(Vec<u8>, Option<String>)>>,
    }

    impl Seen {
        /// The forwarded body, as JSON, and the `Content-Length` it was sent with.
        fn body(&self) -> (Value, Option<String>) {
            let (bytes, length) = self.body.lock().unwrap_or_else(PoisonError::into_inner).clone();

            (serde_json::from_slice(&bytes).unwrap_or(Value::Null), length)
        }

        fn uri(&self) -> String {
            self.uri.lock().unwrap_or_else(PoisonError::into_inner).to_owned()
        }

        fn accept_encoding(&self) -> Option<String> {
            self.accept_encoding
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .as_deref()
                .map(str::to_owned)
        }
    }

    /// A stand-in broker returning a fixed body.
    fn upstream(seen: &Seen, content_type: &'static str, body: impl Into<String>, encoded: bool) -> BoxCloneService<Request, Response, Infallible> {
        let uri = Arc::clone(&seen.uri);
        let accept_encoding = Arc::clone(&seen.accept_encoding);
        let forwarded = Arc::clone(&seen.body);
        let body: Arc<str> = Arc::from(body.into());
        BoxCloneService::new(tower::service_fn(move |request: Request| {
            let uri = Arc::clone(&uri);
            let accept_encoding = Arc::clone(&accept_encoding);
            let forwarded = Arc::clone(&forwarded);
            let body = Arc::clone(&body);
            async move {
                *uri.lock().unwrap_or_else(PoisonError::into_inner) = request.uri().to_string();
                *accept_encoding.lock().unwrap_or_else(PoisonError::into_inner) =
                    request.headers().get(ACCEPT_ENCODING).and_then(|value| value.to_str().ok()).map(str::to_owned);
                let length = request.headers().get(CONTENT_LENGTH).and_then(|value| value.to_str().ok()).map(str::to_owned);
                let bytes = request.into_body().collect().await.map(http_body_util::Collected::to_bytes).unwrap_or_default();
                *forwarded.lock().unwrap_or_else(PoisonError::into_inner) = (bytes.to_vec(), length);

                let mut builder = Response::builder().status(StatusCode::OK).header(CONTENT_TYPE, content_type);
                if encoded {
                    builder = builder.header(CONTENT_ENCODING, "gzip");
                }

                Ok(builder.body(Body::from(body.to_string())).unwrap_or_else(|_| Response::new(Body::empty())))
            }
        }))
    }

    fn request(method: Method, uri: &str, decision: Option<Decision>, body: &'static str) -> Request {
        let mut request = Request::builder()
            .method(method)
            .uri(uri)
            .header(ACCEPT_ENCODING, "gzip, br")
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(body))
            .unwrap_or_else(|_| Request::new(Body::empty()));

        request.extensions_mut().insert(RequestContextExtension(context()));
        // The body the context layer above would have read from the request.
        request
            .extensions_mut()
            .insert(RequestBody::read(body.as_bytes()).expect("the test body is readable"));
        if let Some(decision) = decision {
            request.extensions_mut().insert(decision);
        }

        request
    }

    /// The layer under the four that resolve, above authorization, what it reads.
    async fn run(request: Request, upstream: BoxCloneService<Request, Response, Infallible>) -> Response {
        let mut service = OperationLayer::new().layer(
            QueryLayer::new().layer(
                LinkedEntityLayer::new()
                    .layer(RepresentationLayer::new(RepresentationStrictness::default()).layer(AttributeFilterLayer::new(64 * 1024).layer(upstream))),
            ),
        );

        service.call(request).await.unwrap_or_else(|error| match error {})
    }

    async fn body_of(response: Response) -> String {
        let bytes = response
            .into_body()
            .collect()
            .await
            .map(http_body_util::Collected::to_bytes)
            .unwrap_or_default();

        String::from_utf8_lossy(&bytes).into_owned()
    }

    const ENTITY: &str = r#"{"id":"urn:ngsi-ld:Vehicle:1","type":"Vehicle","speed":42,"location":"here"}"#;

    #[tokio::test]
    async fn a_request_with_no_restriction_passes_through_untouched() {
        let seen = Seen::default();
        let response = run(
            request(Method::GET, "/ngsi-ld/v1/entities?type=Vehicle", Some(unrestricted()), ""),
            upstream(&seen, "application/json", ENTITY, false),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_of(response).await, ENTITY);
    }

    #[tokio::test]
    async fn an_omitted_attribute_is_removed_from_the_response() {
        // The half that matters most: `attrs` cannot express "everything except these", so the
        // request goes out unnarrowed and the response is where the policy is applied.
        let seen = Seen::default();
        let response = run(
            request(
                Method::GET,
                "/ngsi-ld/v1/entities?type=Vehicle",
                Some(decision(AttributeAction::Omit, &["location"])),
                "",
            ),
            upstream(&seen, "application/json", ENTITY, false),
        )
        .await;

        let body = body_of(response).await;

        assert!(body.contains("speed"), "{body}");
        assert!(!body.contains("location"), "{body}");
    }

    #[tokio::test]
    async fn a_pick_narrows_the_request_and_still_filters_the_response() {
        // Both halves, because `attrs` is a hint a broker may ignore. Returning whatever came back
        // because the request had already been narrowed is how a broker that ignores `attrs`
        // becomes a way past the policy.
        let seen = Seen::default();
        let response = run(
            request(
                Method::GET,
                "/ngsi-ld/v1/entities?type=Vehicle",
                Some(decision(AttributeAction::Pick, &["speed"])),
                "",
            ),
            upstream(&seen, "application/json", ENTITY, false),
        )
        .await;

        assert!(seen.uri().contains("attrs=speed"), "the request should say what it wants: {}", seen.uri());

        let body = body_of(response).await;
        assert!(body.contains("speed"), "{body}");
        assert!(
            !body.contains("location"),
            "the response is filtered even though the request was narrowed: {body}"
        );
    }

    #[tokio::test]
    async fn accept_encoding_is_removed_so_the_response_can_be_filtered() {
        let seen = Seen::default();
        let _ = run(
            request(
                Method::GET,
                "/ngsi-ld/v1/entities?type=Vehicle",
                Some(decision(AttributeAction::Omit, &["location"])),
                "",
            ),
            upstream(&seen, "application/json", ENTITY, false),
        )
        .await;

        assert_eq!(seen.accept_encoding(), None, "a compressed response cannot be filtered");
    }

    #[tokio::test]
    async fn a_geojson_feature_is_still_filtered_in_both_places() {
        // Driven by the `Content-Type` the broker sent rather than by the shape of the body. Under
        // `application/geo+json` the hidden attribute is in `properties` and projected to `geometry`,
        // and both copies have to go.
        const FEATURE: &str = r#"{"type":"Feature","id":"urn:ngsi-ld:Vehicle:1","geometry":{"type":"Point","coordinates":[1,2]},"properties":{"type":"Vehicle","speed":42,"location":"here"}}"#;

        let response = run(
            request(
                Method::GET,
                "/ngsi-ld/v1/entities?type=Vehicle",
                Some(decision(AttributeAction::Omit, &["location"])),
                "",
            ),
            upstream(&Seen::default(), "application/geo+json", FEATURE, false),
        )
        .await;

        let body = body_of(response).await;

        assert!(!body.contains("geometry"), "the projected copy must go too: {body}");
        assert!(!body.contains("location"), "{body}");
        assert!(body.contains("speed"), "everything else survives: {body}");
    }

    #[tokio::test]
    async fn an_entity_whose_type_is_feature_is_not_mistaken_for_geojson() {
        // The same document under `application/ld+json` is an ordinary entity whose type happens to
        // be `Feature`. Reading the body rather than the media type sends it down the Feature
        // branch, where `properties` is the container rather than an attribute, and the policy that
        // named `properties` does nothing at all.
        const ENTITY_CALLED_FEATURE: &str = r#"{"id":"urn:ngsi-ld:Sighting:1","type":"Feature","properties":"hidden","speed":42}"#;

        let response = run(
            request(
                Method::GET,
                "/ngsi-ld/v1/entities?type=Feature",
                Some(decision(AttributeAction::Omit, &["properties"])),
                "",
            ),
            upstream(&Seen::default(), "application/ld+json", ENTITY_CALLED_FEATURE, false),
        )
        .await;

        let body = body_of(response).await;

        assert!(!body.contains("properties"), "the restricted attribute must be removed: {body}");
        assert!(body.contains("speed"), "{body}");
        assert!(body.contains("Feature"), "the entity keeps its type: {body}");
    }

    #[tokio::test]
    async fn a_response_type_libra_cannot_filter_is_still_unfilterable() {
        // A media type outside the three Libra can produce is withheld, not forwarded unfiltered.
        let response = run(
            request(
                Method::GET,
                "/ngsi-ld/v1/entities?type=Vehicle",
                Some(decision(AttributeAction::Omit, &["location"])),
                "",
            ),
            upstream(&Seen::default(), "text/csv", ENTITY, false),
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn a_response_that_cannot_be_filtered_is_withheld_rather_than_forwarded() {
        // Returned unchanged, a body that cannot be parsed is exactly the case where the caller
        // receives what the policy was hiding.
        for (content_type, encoded) in [("application/json", true), ("text/plain", false)] {
            let response = run(
                request(
                    Method::GET,
                    "/ngsi-ld/v1/entities?type=Vehicle",
                    Some(decision(AttributeAction::Omit, &["location"])),
                    "",
                ),
                upstream(&Seen::default(), content_type, ENTITY, encoded),
            )
            .await;

            assert_eq!(
                response.status(),
                StatusCode::BAD_GATEWAY,
                "an unfilterable body must not reach the caller ({content_type}, encoded={encoded})"
            );
        }
    }

    #[tokio::test]
    async fn the_attributes_index_drops_a_hidden_attribute_name() {
        // The metadata index (NGSI-LD 5.2.27) lists attribute names aggregated over every instance.
        // An omit restriction that keeps `location` out of every entity read is undone if the index still
        // names it, so the response is narrowed as an index rather than as an entity.
        const INDEX: &str = r#"{"id":"urn:ngsi-ld:AttributeList:1","type":"AttributeList","attributeList":["speed","location"]}"#;

        let response = run(
            request(Method::GET, "/ngsi-ld/v1/attributes", Some(decision(AttributeAction::Omit, &["location"])), ""),
            upstream(&Seen::default(), "application/json", INDEX, false),
        )
        .await;

        let body = body_of(response).await;

        assert!(body.contains("speed"), "{body}");
        assert!(!body.contains("location"), "the index must not name a hidden attribute: {body}");
    }

    #[tokio::test]
    async fn a_filter_that_reads_a_hidden_attribute_is_refused() {
        let response = run(
            request(
                Method::GET,
                "/ngsi-ld/v1/entities?q=location",
                Some(decision(AttributeAction::Omit, &["location"])),
                "",
            ),
            upstream(&Seen::default(), "application/json", ENTITY, false),
        )
        .await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn addressing_a_hidden_attribute_by_path_is_refused() {
        let response = run(
            request(
                Method::GET,
                "/ngsi-ld/v1/entities/urn:ngsi-ld:Vehicle:1/attrs/location",
                Some(decision(AttributeAction::Omit, &["location"])),
                "",
            ),
            upstream(&Seen::default(), "application/json", ENTITY, false),
        )
        .await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn a_write_carrying_a_hidden_attribute_is_refused() {
        let response = run(
            request(
                Method::POST,
                "/ngsi-ld/v1/entities",
                Some(decision(AttributeAction::Omit, &["location"])),
                r#"{"id":"urn:ngsi-ld:Vehicle:1","type":"Vehicle","location":"here"}"#,
            ),
            upstream(&Seen::default(), "application/json", ENTITY, false),
        )
        .await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn an_allowed_write_reaches_the_broker_with_its_body_intact() {
        let seen = Seen::default();
        let response = run(
            request(
                Method::POST,
                "/ngsi-ld/v1/entities",
                Some(decision(AttributeAction::Omit, &["location"])),
                r#"{"id":"urn:ngsi-ld:Vehicle:1","type":"Vehicle","speed":42}"#,
            ),
            upstream(&seen, "application/json", ENTITY, false),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn an_error_response_is_left_alone() {
        let upstream = BoxCloneService::new(tower::service_fn(|_: Request| async {
            Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .header(CONTENT_TYPE, "application/problem+json")
                .body(Body::from(r#"{"title":"Not Found"}"#))
                .unwrap_or_else(|_| Response::new(Body::empty())))
        }));

        let response = run(
            request(
                Method::GET,
                "/ngsi-ld/v1/entities/urn:ngsi-ld:Vehicle:9",
                Some(decision(AttributeAction::Omit, &["location"])),
                "",
            ),
            upstream,
        )
        .await;

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn a_request_reaching_this_layer_without_a_resolved_context_is_refused() {
        // A wiring error, not a request. Filtering without a context would compare names that have
        // no meaning, which is the same as not filtering.
        let mut request = Request::builder()
            .method(Method::GET)
            .uri("/ngsi-ld/v1/entities")
            .body(Body::empty())
            .unwrap_or_else(|_| Request::new(Body::empty()));
        request.extensions_mut().insert(RequestBody::Empty);
        request.extensions_mut().insert(decision(AttributeAction::Omit, &["location"]));

        let response = run(request, upstream(&Seen::default(), "application/json", ENTITY, false)).await;

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn a_request_without_a_parsed_body_is_refused() {
        // A wiring error: the context layer above reads every body. A write checked against no
        // document would be forwarded with whatever attributes it carries.
        let seen = Seen::default();
        let mut request = Request::builder()
            .method(Method::POST)
            .uri("/ngsi-ld/v1/entities")
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"id":"urn:ngsi-ld:Vehicle:1","type":"Vehicle","location":"here"}"#))
            .unwrap_or_else(|_| Request::new(Body::empty()));
        request.extensions_mut().insert(RequestContextExtension(context()));
        request.extensions_mut().insert(decision(AttributeAction::Omit, &["location"]));
        let (mut parts, body) = request.into_parts();
        classify(&mut parts).unwrap();
        read_query(&mut parts).unwrap();
        let request = Request::from_parts(parts, body);

        let response = AttributeFilterLayer::new(64 * 1024)
            .layer(upstream(&seen, "application/json", ENTITY, false))
            .call(request)
            .await
            .unwrap_or_else(|error| match error {});

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(seen.uri(), "", "nothing reached the broker");
    }

    fn parking(location: bool) -> Value {
        let mut entity = json!({ "id": "urn:ngsi-ld:OffStreetParking:P1", "type": "OffStreetParking", "name": { "type": "Property", "value": "Downtown" } });
        if location {
            entity["location"] = json!({ "type": "GeoProperty", "value": { "type": "Point", "coordinates": [13.4, 52.5] } });
        }
        entity
    }

    async fn joined(uri: &str, decision: Decision, content_type: &'static str, answer: &Value) -> (Seen, Value) {
        let seen = Seen::default();

        let response = run(
            request(Method::GET, uri, Some(decision), ""),
            upstream(&seen, content_type, answer.to_string(), false),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);

        (seen, serde_json::from_str(&body_of(response).await).expect("JSON"))
    }

    #[tokio::test]
    async fn a_linked_entity_is_filtered_as_an_entity_at_every_depth() {
        // Linked Entity Retrieval (NGSI-LD 4.5.23) nests entities the request narrowing never
        // reached. They are entities of the answer, and a policy that hides `location` hides it on
        // them too.
        let mut level_one = parking(true);
        level_one["operator"] = json!({ "type": "Relationship", "object": "urn:ngsi-ld:OffStreetParking:P1", "entity": parking(true) });
        let answer = json!([{ "id": "urn:ngsi-ld:Vehicle:1", "type": "Vehicle", "speed": 42,
            "isParked": { "type": "Relationship", "object": "urn:ngsi-ld:OffStreetParking:P1", "entity": level_one } }]);

        let (seen, body) = joined(
            "/ngsi-ld/v1/entities?type=Vehicle&join=inline&joinLevel=2",
            decision(AttributeAction::Omit, &["location"]),
            "application/json",
            &answer,
        )
        .await;

        assert_eq!(seen.accept_encoding(), None);
        assert_eq!(body[0]["isParked"]["entity"]["name"]["value"], "Downtown");
        assert_eq!(body[0]["isParked"]["entity"].get("location"), None);
        assert_eq!(body[0]["isParked"]["entity"]["operator"]["entity"], parking(false));
    }

    /// The count of names removed that the debug log reports for one filtered answer.
    fn removed_count<'a>(records: &'a [Emitted], message: &str) -> Option<&'a str> {
        records
            .iter()
            .find(|record| record.message() == message)
            .and_then(|record| record.field("removed"))
    }

    #[tokio::test]
    async fn the_debug_log_counts_the_attributes_removed_from_linked_entities_too() {
        let mut level_one = parking(true);
        level_one["operator"] = json!({ "type": "Relationship", "object": "urn:ngsi-ld:OffStreetParking:P1", "entity": parking(true) });
        let answer = json!([{ "id": "urn:ngsi-ld:Vehicle:1", "type": "Vehicle", "speed": 42,
            "isParked": { "type": "Relationship", "object": "urn:ngsi-ld:OffStreetParking:P1", "entity": level_one } }]);

        let (_, records) = captured(joined(
            "/ngsi-ld/v1/entities?type=Vehicle&join=inline&joinLevel=2",
            decision(AttributeAction::Omit, &["location"]),
            "application/json",
            &answer,
        ))
        .await;

        // The top-level entity carries no `location`; each of the two linked parkings carries one.
        assert_eq!(removed_count(&records, "filtered attributes out of the response"), Some("2"));
    }

    #[tokio::test]
    async fn a_linked_feature_of_a_flat_geojson_answer_loses_its_geometry_with_its_location() {
        let feature = json!({ "id": "urn:ngsi-ld:OffStreetParking:P1", "type": "Feature", "geometry": { "type": "Point", "coordinates": [13.4, 52.5] },
            "properties": parking(true) });
        let answer = json!({ "type": "FeatureCollection", "features": [feature] });

        let (_, body) = joined(
            "/ngsi-ld/v1/entities?type=Vehicle&join=flat",
            decision(AttributeAction::Omit, &["location"]),
            "application/geo+json",
            &answer,
        )
        .await;

        assert_eq!(body["features"][0].get("geometry"), None);
        assert_eq!(body["features"][0]["properties"], parking(false));
    }

    #[tokio::test]
    async fn a_linked_projection_term_under_an_allowed_relationship_is_forwarded_and_its_names_filtered() {
        // The term reaches into the linked entity, whose names the restriction judges in the answer: under
        // a pick of `isParked`, the linked entity keeps its `id` and `type` and nothing else.
        let answer = json!([{ "id": "urn:ngsi-ld:Vehicle:1", "type": "Vehicle",
            "isParked": { "type": "Relationship", "object": "urn:ngsi-ld:OffStreetParking:P1", "entity": parking(true) } }]);

        let (seen, body) = joined(
            "/ngsi-ld/v1/entities?type=Vehicle&join=inline&pick=id,type,isParked%7Bname%7D",
            decision(AttributeAction::Pick, &["isParked"]),
            "application/json",
            &answer,
        )
        .await;

        assert!(seen.uri().contains("pick=id%2Ctype%2CisParked%7Bname%7D"), "{}", seen.uri());
        assert_eq!(
            body[0]["isParked"]["entity"],
            json!({ "id": "urn:ngsi-ld:OffStreetParking:P1", "type": "OffStreetParking" })
        );
    }

    #[tokio::test]
    async fn a_linked_projection_term_under_a_forbidden_relationship_is_dropped() {
        let seen = Seen::default();
        let response = run(
            request(
                Method::GET,
                "/ngsi-ld/v1/entities?type=Vehicle&join=inline&pick=speed,isParked%7Bname%7D",
                Some(decision(AttributeAction::Pick, &["speed"])),
                "",
            ),
            upstream(&seen, "application/json", ENTITY, false),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert!(seen.uri().contains("pick=speed"), "{}", seen.uri());
        assert!(!seen.uri().contains("isParked"), "{}", seen.uri());

        let refused = run(
            request(
                Method::GET,
                "/ngsi-ld/v1/entities?type=Vehicle&join=inline&pick=isParked%7Bname%7D",
                Some(decision(AttributeAction::Pick, &["speed"])),
                "",
            ),
            upstream(&Seen::default(), "application/json", ENTITY, false),
        )
        .await;

        assert_eq!(refused.status(), StatusCode::FORBIDDEN, "nothing the caller asked for is allowed");
    }

    #[tokio::test]
    async fn a_linked_projection_term_without_a_join_is_refused_when_attributes_are_restricted() {
        // `attrs=parkedIn{name}` reaches an attribute inside a linked entity (clause 4.21), in an
        // answer of no shape the request named.
        let response = run(
            request(
                Method::GET,
                "/ngsi-ld/v1/entities?type=Vehicle&attrs=parkedIn%7Bname%7D",
                Some(decision(AttributeAction::Omit, &["location"])),
                "",
            ),
            upstream(&Seen::default(), "application/json", ENTITY, false),
        )
        .await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn a_linked_filter_path_is_forwarded_when_every_name_in_it_is_allowed() {
        for (uri, picked) in [
            ("/ngsi-ld/v1/entities?type=Vehicle&q=isParked%7Bname%7D==%22x%22", &["isParked", "name"][..]),
            (
                "/ngsi-ld/v1/entities?type=Vehicle&q=isParked%7BBuilding,Garage:owner%7Bname%7D%7D==%22x%22",
                &["isParked", "owner", "name"][..],
            ),
        ] {
            let seen = Seen::default();
            let response = run(
                request(Method::GET, uri, Some(decision(AttributeAction::Pick, picked)), ""),
                upstream(&seen, "application/json", "[]", false),
            )
            .await;

            assert_eq!(response.status(), StatusCode::OK, "{uri}");
            assert!(seen.uri().contains("q=isParked"), "{uri} went out as {}", seen.uri());
        }
    }

    #[tokio::test]
    async fn a_linked_filter_path_naming_a_forbidden_attribute_is_refused() {
        for (uri, picked) in [
            ("/ngsi-ld/v1/entities?type=Vehicle&q=isParked%7Bname%7D==%22x%22", &["isParked"][..]),
            (
                "/ngsi-ld/v1/entities?type=Vehicle&q=isParked%7BBuilding,Garage:owner%7Bname%7D%7D==%22x%22",
                &["isParked", "name"][..],
            ),
        ] {
            let seen = Seen::default();
            let response = run(
                request(Method::GET, uri, Some(decision(AttributeAction::Pick, picked)), ""),
                upstream(&seen, "application/json", "[]", false),
            )
            .await;

            assert_eq!(response.status(), StatusCode::FORBIDDEN, "{uri}");
            assert_eq!(seen.uri(), "", "{uri}");
        }
    }

    #[tokio::test]
    async fn a_query_body_projection_is_narrowed_and_its_length_restated() {
        let seen = Seen::default();
        let response = run(
            request(
                Method::POST,
                "/ngsi-ld/v1/entityOperations/query",
                Some(decision(AttributeAction::Omit, &["location"])),
                r#"{"type": "Query", "entities": [{"type": "Vehicle"}], "attrs": ["speed", "location"]}"#,
            ),
            upstream(&seen, "application/json", "[]", false),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        let (body, length) = seen.body();
        assert_eq!(body, json!({ "type": "Query", "entities": [{ "type": "Vehicle" }], "attrs": ["speed"] }));
        assert_eq!(length, Some(serde_json::to_vec(&body).unwrap().len().to_string()));
    }

    #[tokio::test]
    async fn a_query_body_left_with_nothing_or_filtering_on_a_forbidden_attribute_is_refused() {
        for body in [
            r#"{"type": "Query", "entities": [{"type": "Vehicle"}], "pick": ["location"]}"#,
            r#"{"type": "Query", "entities": [{"type": "Vehicle"}], "q": "location!=null"}"#,
        ] {
            let seen = Seen::default();
            let response = run(
                request(
                    Method::POST,
                    "/ngsi-ld/v1/entityOperations/query",
                    Some(decision(AttributeAction::Omit, &["location"])),
                    body,
                ),
                upstream(&seen, "application/json", "[]", false),
            )
            .await;

            assert_eq!(response.status(), StatusCode::FORBIDDEN, "{body}");
            assert_eq!(seen.uri(), "", "{body}");
        }
    }

    const REGISTRATION: &str = r#"[{"id":"urn:r:1","type":"ContextSourceRegistration","endpoint":"http://source.test","information":[{"entities":[{"type":"Vehicle"}],"propertyNames":["speed","location"]}]}]"#;

    #[tokio::test]
    async fn a_registration_listing_keeps_its_structure_and_narrows_its_names() {
        let seen = Seen::default();
        let response = run(
            request(
                Method::GET,
                "/ngsi-ld/v1/csourceRegistrations",
                Some(decision(AttributeAction::Pick, &["speed"])),
                "",
            ),
            upstream(&seen, "application/json", REGISTRATION, false),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(seen.accept_encoding(), None);
        assert_eq!(seen.uri(), "/ngsi-ld/v1/csourceRegistrations", "no attrs is injected into a registration query");
        let body: Value = serde_json::from_str(&body_of(response).await).unwrap_or(Value::Null);
        assert_eq!(
            body,
            json!([{ "id": "urn:r:1", "type": "ContextSourceRegistration", "endpoint": "http://source.test",
                "information": [{ "entities": [{ "type": "Vehicle" }], "propertyNames": ["speed"] }] }])
        );
    }

    #[tokio::test]
    async fn the_debug_log_counts_the_names_removed_from_registrations() {
        let seen = Seen::default();
        let (response, records) = captured(run(
            request(
                Method::GET,
                "/ngsi-ld/v1/csourceRegistrations",
                Some(decision(AttributeAction::Pick, &["speed"])),
                "",
            ),
            upstream(&seen, "application/json", REGISTRATION, false),
        ))
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(removed_count(&records, "filtered attribute names out of the registrations"), Some("1"));
    }

    #[tokio::test]
    async fn a_registration_create_is_checked_against_the_names_it_registers() {
        for (body, expected) in [
            (
                r#"{"type":"ContextSourceRegistration","endpoint":"http://source.test","information":[{"propertyNames":["location"]}]}"#,
                StatusCode::FORBIDDEN,
            ),
            (
                r#"{"type":"ContextSourceRegistration","endpoint":"http://source.test","information":[{"propertyNames":["speed"]}]}"#,
                StatusCode::OK,
            ),
        ] {
            let seen = Seen::default();
            let response = run(
                request(
                    Method::POST,
                    "/ngsi-ld/v1/csourceRegistrations",
                    Some(decision(AttributeAction::Omit, &["location"])),
                    body,
                ),
                upstream(&seen, "application/json", "", false),
            )
            .await;

            assert_eq!(response.status(), expected, "{body}");
            assert_eq!(seen.uri().is_empty(), expected != StatusCode::OK, "{body}");
        }
    }

    #[tokio::test]
    async fn unservable_linked_entity_retrieval_in_a_batch_query_body_is_refused_when_attributes_are_restricted() {
        // NGSI-LD 5.2.23 gives the Query body `join`, `joinLevel`, projections and `q` of its own,
        // and what no answer can be judged against is refused there as it is in the query string.
        for body in [
            r#"{"type": "Query", "entities": [{"type": "Vehicle"}], "joinLevel": 2}"#,
            r#"{"type": "Query", "entities": [{"type": "Vehicle"}], "attrs": ["speed", "parkedIn{name}"]}"#,
        ] {
            let seen = Seen::default();
            let response = run(
                request(
                    Method::POST,
                    "/ngsi-ld/v1/entityOperations/query",
                    Some(decision(AttributeAction::Omit, &["location"])),
                    body,
                ),
                upstream(&seen, "application/json", ENTITY, false),
            )
            .await;

            assert_eq!(response.status(), StatusCode::FORBIDDEN, "{body}");
            assert_eq!(seen.uri(), "", "{body}");
        }
    }

    #[tokio::test]
    async fn linked_entity_retrieval_in_a_subscription_is_refused_when_attributes_are_restricted() {
        // NGSI-LD 5.2.14: narrowing the notification's projection reaches only the subscribed
        // entities' own members, never a linked entity the notification nests or appends.
        for body in [
            r#"{"type": "Subscription", "entities": [{"type": "Vehicle"}], "notification": {"join": "inline", "endpoint": {"uri": "http://sink.test"}}}"#,
            r#"{"type": "Subscription", "entities": [{"type": "Vehicle"}], "notification": {"omit": ["parkedIn{name}"], "endpoint": {"uri": "http://sink.test"}}}"#,
        ] {
            let seen = Seen::default();
            let response = run(
                request(
                    Method::POST,
                    "/ngsi-ld/v1/subscriptions",
                    Some(decision(AttributeAction::Omit, &["location"])),
                    body,
                ),
                upstream(&seen, "application/json", ENTITY, false),
            )
            .await;

            assert_eq!(response.status(), StatusCode::FORBIDDEN, "{body}");
            assert_eq!(seen.uri(), "", "{body}");
        }
    }

    #[tokio::test]
    async fn a_projection_separated_by_pipes_is_narrowed_rather_than_refused() {
        // Clause 4.21 lets `|` separate projected attributes. Read as one name, `speed|location`
        // could not be expanded and every caller would be refused.
        let seen = Seen::default();
        let response = run(
            request(
                Method::GET,
                "/ngsi-ld/v1/entities?type=Vehicle&attrs=speed%7Clocation",
                Some(decision(AttributeAction::Omit, &["location"])),
                "",
            ),
            upstream(&seen, "application/json", ENTITY, false),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert!(seen.uri().contains("attrs=speed"), "{}", seen.uri());
        assert!(!seen.uri().contains("location"), "the omitted attribute is narrowed out: {}", seen.uri());
    }

    #[tokio::test]
    async fn a_join_read_passes_when_no_attribute_restriction() {
        // The layer only filters when an attribute restriction is attached; an unrestricted caller
        // keeps linked retrieval, and the response is returned untouched.
        let seen = Seen::default();
        let response = run(
            request(Method::GET, "/ngsi-ld/v1/entities?type=Vehicle&join=inline", Some(unrestricted()), ""),
            upstream(&seen, "application/json", ENTITY, false),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_of(response).await, ENTITY);
    }

    #[tokio::test]
    async fn a_single_attribute_update_of_an_allowed_attribute_is_not_over_refused() {
        // `PATCH /entities/{id}/attrs/{attr}` carries the attribute's value representation, whose
        // members (`value`, `unitCode`) are not attribute names. Under a pick that allows the
        // attribute, the update must be forwarded: walking the value members as attribute names
        // would refuse a legitimate write because `value` is not in the pick list.
        let seen = Seen::default();
        let response = run(
            request(
                Method::PATCH,
                "/ngsi-ld/v1/entities/urn:ngsi-ld:Vehicle:1/attrs/speed",
                Some(decision(AttributeAction::Pick, &["speed"])),
                r#"{"value":50,"unitCode":"KMH"}"#,
            ),
            upstream(&seen, "application/json", "", false),
        )
        .await;

        assert_eq!(
            response.status(),
            StatusCode::OK,
            "a value-representation update of an allowed attribute must be forwarded"
        );
        assert!(
            seen.uri().starts_with("/ngsi-ld/v1/entities/urn:ngsi-ld:Vehicle:1/attrs/speed"),
            "and it must reach the broker: {}",
            seen.uri()
        );
    }

    #[tokio::test]
    async fn a_single_attribute_update_of_a_forbidden_attribute_is_still_refused() {
        // The path attribute is authoritative: skipping the body scan for a single-attribute write
        // does not weaken the check, because the path names the attribute and it is checked first.
        let seen = Seen::default();
        let response = run(
            request(
                Method::PATCH,
                "/ngsi-ld/v1/entities/urn:ngsi-ld:Vehicle:1/attrs/location",
                Some(decision(AttributeAction::Pick, &["speed"])),
                r#"{"value":1}"#,
            ),
            upstream(&seen, "application/json", "", false),
        )
        .await;

        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "a write to a forbidden attribute is refused from the path"
        );
        assert_eq!(seen.uri(), "", "the refused write must not reach the broker");
    }

    /// Serves `method uri` carrying `body` under `decision`, against a broker answering `ENTITY`.
    async fn refused(method: Method, uri: &str, decision: Decision, body: &'static str) -> (StatusCode, Seen) {
        let seen = Seen::default();
        let response = run(request(method, uri, Some(decision), body), upstream(&seen, "application/json", ENTITY, false)).await;

        (response.status(), seen)
    }

    #[tokio::test]
    async fn an_entity_map_read_is_refused_under_an_attribute_restriction() {
        for uri in [
            "/ngsi-ld/v1/entityMaps",
            "/ngsi-ld/v1/entityMaps/urn:ngsi-ld:EntityMap:1",
            "/ngsi-ld/v1/temporal/entityMaps",
        ] {
            let (status, seen) = refused(Method::GET, uri, decision(AttributeAction::Omit, &["location"]), "").await;

            assert_eq!(status, StatusCode::FORBIDDEN, "{uri}");
            assert_eq!(seen.uri(), "", "{uri}");
        }
    }

    #[tokio::test]
    async fn an_entity_map_creation_with_a_body_q_is_refused_under_an_attribute_restriction() {
        // The body's `q` selects which entities the map lists, so the map's contents disclose the
        // hidden attribute the way an answer filtered by it would.
        let (status, seen) = refused(
            Method::POST,
            "/ngsi-ld/v1/entityMaps",
            decision(AttributeAction::Omit, &["location"]),
            r#"{"type":"Query","q":"location!=null"}"#,
        )
        .await;

        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(seen.uri(), "");
    }

    #[tokio::test]
    async fn a_context_source_subscription_is_refused_under_an_attribute_restriction() {
        for (method, uri, body) in [
            (Method::GET, "/ngsi-ld/v1/csourceSubscriptions", ""),
            (
                Method::POST,
                "/ngsi-ld/v1/csourceSubscriptions",
                r#"{"type":"Subscription","notification":{"endpoint":{"uri":"http://sink.test"}}}"#,
            ),
            (Method::DELETE, "/ngsi-ld/v1/csourceSubscriptions/urn:ngsi-ld:Subscription:1", ""),
        ] {
            let (status, seen) = refused(method, uri, decision(AttributeAction::Pick, &["speed"]), body).await;

            assert_eq!(status, StatusCode::FORBIDDEN, "{uri}");
            assert_eq!(seen.uri(), "", "{uri}");
        }
    }

    #[tokio::test]
    async fn an_entity_map_header_is_forwarded_under_an_attribute_restriction() {
        // Paging through an entity map pages through entities the attribute filtering still reaches:
        // every page is an ordinary answer and is filtered as one.
        let seen = Seen::default();
        let mut paged = request(
            Method::GET,
            "/ngsi-ld/v1/entities?type=Vehicle",
            Some(decision(AttributeAction::Omit, &["location"])),
            "",
        );
        paged
            .headers_mut()
            .insert("NGSILD-EntityMap", http::HeaderValue::from_static("urn:ngsi-ld:EntityMap:1"));

        let response = run(paged, upstream(&seen, "application/json", ENTITY, false)).await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = body_of(response).await;
        assert!(!body.contains("location"), "{body}");
        assert!(body.contains("speed"), "{body}");
    }

    #[tokio::test]
    async fn reading_subscriptions_is_refused_under_a_restriction() {
        for uri in ["/ngsi-ld/v1/subscriptions", "/ngsi-ld/v1/subscriptions/urn:ngsi-ld:Subscription:1"] {
            let (status, seen) = refused(Method::GET, uri, decision(AttributeAction::Omit, &["location"]), "").await;

            assert_eq!(status, StatusCode::FORBIDDEN, "{uri}");
            assert_eq!(seen.uri(), "", "{uri}");
        }
    }

    #[tokio::test]
    async fn updating_a_subscription_is_refused_under_a_restriction() {
        let (status, seen) = refused(
            Method::PATCH,
            "/ngsi-ld/v1/subscriptions/urn:ngsi-ld:Subscription:1",
            decision(AttributeAction::Omit, &["location"]),
            r#"{"type":"Subscription","notification":{"attributes":["speed"]}}"#,
        )
        .await;

        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(seen.uri(), "");
    }

    #[tokio::test]
    async fn deleting_a_subscription_is_refused_under_a_restriction() {
        let (status, seen) = refused(
            Method::DELETE,
            "/ngsi-ld/v1/subscriptions/urn:ngsi-ld:Subscription:1",
            decision(AttributeAction::Omit, &["location"]),
            "",
        )
        .await;

        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(seen.uri(), "");
    }

    #[tokio::test]
    async fn creating_a_subscription_is_still_narrowed() {
        let seen = Seen::default();
        let response = run(
            request(
                Method::POST,
                "/ngsi-ld/v1/subscriptions",
                Some(decision(AttributeAction::Pick, &["speed"])),
                r#"{"type":"Subscription","entities":[{"type":"Vehicle"}],"notification":{"endpoint":{"uri":"http://sink.test"}}}"#,
            ),
            upstream(&seen, "application/json", ENTITY, false),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        let (forwarded, _) = seen.body();
        assert_eq!(forwarded["notification"]["pick"], json!(["speed"]), "{forwarded}");
    }

    #[tokio::test]
    async fn subscriptions_are_forwarded_without_a_restriction() {
        for (method, uri) in [
            (Method::GET, "/ngsi-ld/v1/subscriptions"),
            (Method::PATCH, "/ngsi-ld/v1/subscriptions/urn:ngsi-ld:Subscription:1"),
            (Method::DELETE, "/ngsi-ld/v1/subscriptions/urn:ngsi-ld:Subscription:1"),
        ] {
            let (status, seen) = refused(method, uri, unrestricted(), "").await;

            assert_eq!(status, StatusCode::OK, "{uri}");
            assert_eq!(seen.uri(), uri);
        }
    }

    #[tokio::test]
    async fn deleting_a_whole_entity_is_refused_under_omit() {
        let (status, seen) = refused(
            Method::DELETE,
            "/ngsi-ld/v1/entities/urn:ngsi-ld:Vehicle:1",
            decision(AttributeAction::Omit, &["location"]),
            "",
        )
        .await;

        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(seen.uri(), "");
    }

    #[tokio::test]
    async fn replacing_a_whole_entity_is_refused_under_pick() {
        // NGSI-LD 5.6.18: the replacement drops every attribute the body does not carry, including
        // the ones the caller cannot see.
        let (status, seen) = refused(
            Method::PUT,
            "/ngsi-ld/v1/entities/urn:ngsi-ld:Vehicle:1",
            decision(AttributeAction::Pick, &["speed"]),
            r#"{"id":"urn:ngsi-ld:Vehicle:1","type":"Vehicle","speed":1}"#,
        )
        .await;

        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(seen.uri(), "");
    }

    #[tokio::test]
    async fn a_batch_delete_is_refused_under_an_attribute_restriction() {
        let (status, seen) = refused(
            Method::POST,
            "/ngsi-ld/v1/entityOperations/delete",
            decision(AttributeAction::Omit, &["location"]),
            r#"["urn:ngsi-ld:Vehicle:1"]"#,
        )
        .await;

        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(seen.uri(), "");
    }

    #[tokio::test]
    async fn a_batch_upsert_that_replaces_is_refused() {
        // NGSI-LD 6.15.3.1: `replace` is the default mode, so an upsert naming no option replaces.
        for uri in ["/ngsi-ld/v1/entityOperations/upsert", "/ngsi-ld/v1/entityOperations/upsert?options=replace"] {
            let (status, seen) = refused(
                Method::POST,
                uri,
                decision(AttributeAction::Omit, &["location"]),
                r#"[{"id":"urn:ngsi-ld:Vehicle:1","type":"Vehicle","speed":1}]"#,
            )
            .await;

            assert_eq!(status, StatusCode::FORBIDDEN, "{uri}");
            assert_eq!(seen.uri(), "", "{uri}");
        }
    }

    #[tokio::test]
    async fn a_batch_upsert_with_update_is_judged_by_its_attributes() {
        let uri = "/ngsi-ld/v1/entityOperations/upsert?options=update";

        let (allowed, seen) = refused(
            Method::POST,
            uri,
            decision(AttributeAction::Omit, &["location"]),
            r#"[{"id":"urn:ngsi-ld:Vehicle:1","type":"Vehicle","speed":1}]"#,
        )
        .await;
        assert_eq!(allowed, StatusCode::OK);
        assert_eq!(seen.uri(), uri);

        let (hidden, _) = refused(
            Method::POST,
            uri,
            decision(AttributeAction::Omit, &["location"]),
            r#"[{"id":"urn:ngsi-ld:Vehicle:1","type":"Vehicle","location":"here"}]"#,
        )
        .await;
        assert_eq!(hidden, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn deleting_an_allowed_attribute_is_forwarded() {
        let uri = "/ngsi-ld/v1/entities/urn:ngsi-ld:Vehicle:1/attrs/speed";

        let (status, seen) = refused(Method::DELETE, uri, decision(AttributeAction::Omit, &["location"]), "").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(seen.uri(), uri);

        let (hidden, _) = refused(
            Method::DELETE,
            "/ngsi-ld/v1/entities/urn:ngsi-ld:Vehicle:1/attrs/location",
            decision(AttributeAction::Omit, &["location"]),
            "",
        )
        .await;
        assert_eq!(hidden, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn a_request_without_a_decision_is_refused() {
        // A wiring fault: authorization attaches a decision to everything it lets through.
        let (status, seen) = {
            let seen = Seen::default();
            let response = run(
                request(Method::GET, "/ngsi-ld/v1/entities?type=Vehicle", None, ""),
                upstream(&seen, "application/json", ENTITY, false),
            )
            .await;

            (response.status(), seen)
        };

        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(seen.uri(), "", "nothing reached the broker");
    }

    #[tokio::test]
    async fn ordering_by_a_hidden_attribute_reaches_no_broker() {
        let (status, seen) = refused(
            Method::GET,
            "/ngsi-ld/v1/entities?type=Vehicle&orderBy=location;dist-asc&orderFrom=%5B8,40%5D",
            decision(AttributeAction::Omit, &["location"]),
            "",
        )
        .await;

        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(seen.uri(), "");

        let (bad, _) = refused(
            Method::GET,
            "/ngsi-ld/v1/entities?type=Vehicle&orderBy=speed;sideways",
            decision(AttributeAction::Omit, &["location"]),
            "",
        )
        .await;
        assert_eq!(bad, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn a_geometry_is_withheld_whenever_location_is_hidden() {
        // A broker that ignores `geometryProperty` lifts `location` into the geometry anyway, so a
        // allowed `geometryProperty` does not make the geometry safe to return.
        const FEATURE: &str = r#"{"type":"Feature","id":"urn:ngsi-ld:Vehicle:1","geometry":{"type":"Point","coordinates":[1,2]},"properties":{"type":"Vehicle","speed":42,"location":"here"}}"#;

        let response = run(
            request(
                Method::GET,
                "/ngsi-ld/v1/entities?type=Vehicle&geometryProperty=speed",
                Some(decision(AttributeAction::Omit, &["location"])),
                "",
            ),
            upstream(&Seen::default(), "application/geo+json", FEATURE, false),
        )
        .await;

        let body = body_of(response).await;
        assert!(!body.contains("geometry"), "{body}");
    }
}
