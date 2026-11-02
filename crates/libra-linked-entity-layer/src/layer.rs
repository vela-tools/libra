//! The Tower layer that reads a request's Linked Entity Retrieval selectors once.
//!
//! Placement: directly above authorization. Authorization is the first reader (a request that
//! joins touches entities of types it never names, so it is weighed as touching every type) and
//! every enforcement layer below it reads the same answer. Above the context layer it would read
//! nothing it needs; below authorization it would be too late for the first reader.

use axum::{
    extract::Request,
    http::request::Parts,
    response::{IntoResponse, Response},
};
use jstrict::Value;
use libra_json_body::request_body::RequestBody;
use libra_ngsi_ld_operation::{
    operation::{Mode, Operation},
    resource::{BatchAction, Resource},
};
use libra_ngsi_ld_operation_layer::classified::operation;
use libra_ngsi_ld_query::linked_entity::LinkedEntityRequest;
use libra_ngsi_ld_query_layer::parsed::parameters;
use libra_problem_details::problem::Problem;
use std::{
    convert::Infallible,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
use tower::{Layer, Service, ServiceExt};

/// Resolves [`LinkedEntityRequest`] and places it in the request extensions.
#[derive(Debug, Clone, Copy, Default)]
pub struct LinkedEntityLayer;

impl LinkedEntityLayer {
    /// Builds the layer.
    #[must_use]
    pub const fn new() -> LinkedEntityLayer {
        LinkedEntityLayer
    }
}

impl<S> Layer<S> for LinkedEntityLayer {
    type Service = LinkedEntityService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        LinkedEntityService { inner }
    }
}

/// The service produced by [`LinkedEntityLayer`].
#[derive(Debug, Clone)]
pub struct LinkedEntityService<S> {
    inner: S,
}

impl<S> Service<Request> for LinkedEntityService<S>
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
        let (mut parts, body) = request.into_parts();
        let resolved = resolve(&parts);

        Box::pin(async move {
            match resolved {
                Ok(requested) => {
                    parts.extensions.insert(requested);
                    inner.oneshot(Request::from_parts(parts, body)).await
                }
                Err(problem) => Ok(problem.into_response()),
            }
        })
    }
}

/// Where a request carries its selectors besides the query string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Carrier {
    /// The query string alone.
    QueryString,
    /// A batch query: the query string and a `Query` body (clause 5.2.23).
    QueryBody,
    /// A subscription write: its body, whose notification never passes back through Libra.
    Subscription,
}

impl Carrier {
    /// Where an operation carries its selectors.
    fn of(operation: &Operation) -> Self {
        match operation {
            Operation {
                resource: Resource::EntityBatch { action: BatchAction::Query } | Resource::TemporalBatchQuery,
                ..
            } => Self::QueryBody,
            operation if operation.resource.is_subscription() && operation.mode == Mode::Write => Self::Subscription,
            Operation { .. } => Self::QueryString,
        }
    }
}

/// Reads what a request asks for in Linked Entity Retrieval from its selectors.
///
/// A selector that does not parse is refused for every caller: the broker would refuse it too, and
/// what it asks for cannot be told. The operation, the query and the body are read from the layers
/// above, and the body is forwarded untouched.
fn resolve(parts: &Parts) -> Result<LinkedEntityRequest, Problem> {
    let operation = operation(&parts.extensions).map_err(|error| Problem::Internal(error.to_string()))?;
    let parameters = parameters(&parts.extensions).map_err(|error| Problem::Internal(error.to_string()))?;

    let requested = match Carrier::of(operation) {
        Carrier::QueryString => parameters.linked_entity_request(),
        Carrier::QueryBody => LinkedEntityRequest::of_query(parameters, document(parts)?),
        Carrier::Subscription => document(parts)?.map_or(Ok(LinkedEntityRequest::NOTHING), LinkedEntityRequest::of_subscription),
    };

    requested.map_err(|error| Problem::BadRequest(error.to_string()))
}

/// The request's JSON document; an empty body is no document.
///
/// The body is read by the context layer above; a request that arrives here without it was not
/// wired through that layer, and its selectors cannot be read, so it is refused rather than
/// forwarded unjudged.
fn document(parts: &Parts) -> Result<Option<&Value>, Problem> {
    match RequestBody::of(parts) {
        None => Err(Problem::Internal("the request body was not read before linked entity retrieval".to_owned())),
        Some(RequestBody::Empty) => Ok(None),
        Some(RequestBody::NotJson) => Err(Problem::BadRequest("the request body is not a JSON document".to_owned())),
        Some(RequestBody::Json(document)) => Ok(Some(document)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Method, StatusCode},
    };
    use http_body_util::BodyExt;
    use libra_ngsi_ld_operation_layer::layer::classify;
    use libra_ngsi_ld_query::{
        linked_entity::{JoinMode, LinkedAnswer, LinkedEntityRetrieval, LinkedFilter},
        parameters::QueryParameters,
    };
    use libra_ngsi_ld_query_layer::layer::read_query;
    use pretty_assertions::assert_eq;
    use std::sync::{Arc, Mutex, PoisonError};
    use tower::util::BoxCloneService;

    /// What the inner service saw.
    #[derive(Clone, Default)]
    struct Seen {
        requested: Arc<Mutex<Option<LinkedEntityRequest>>>,
        body: Arc<Mutex<Vec<u8>>>,
    }

    fn inner(seen: &Seen) -> BoxCloneService<Request, Response, Infallible> {
        let requested = Arc::clone(&seen.requested);
        let body = Arc::clone(&seen.body);
        BoxCloneService::new(tower::service_fn(move |request: Request| {
            let requested = Arc::clone(&requested);
            let body = Arc::clone(&body);
            async move {
                *requested.lock().unwrap_or_else(PoisonError::into_inner) = request.extensions().get::<LinkedEntityRequest>().cloned();
                let bytes = request.into_body().collect().await.map(http_body_util::Collected::to_bytes).unwrap_or_default();
                *body.lock().unwrap_or_else(PoisonError::into_inner) = bytes.to_vec();

                Ok(Response::new(Body::empty()))
            }
        }))
    }

    /// `request` with what the operation and query layers above would have read from it.
    fn classified(request: Request) -> Request {
        let (mut parts, body) = request.into_parts();
        classify(&mut parts).unwrap();
        read_query(&mut parts).unwrap();

        Request::from_parts(parts, body)
    }

    /// `request` with the body the context layer above would have read from it, too.
    fn parsed(request: Request, body: &str) -> Request {
        let mut request = classified(request);
        request.extensions_mut().insert(RequestBody::read(body.as_bytes()).unwrap());

        request
    }

    async fn serve(request: Request) -> (StatusCode, Seen) {
        let seen = Seen::default();

        let response = LinkedEntityLayer::new()
            .layer(inner(&seen))
            .call(request)
            .await
            .unwrap_or_else(|error| match error {});

        (response.status(), seen)
    }

    async fn run(method: Method, uri: &str, body: &'static str) -> (StatusCode, Seen) {
        serve(parsed(Request::builder().method(method).uri(uri).body(Body::from(body)).unwrap(), body)).await
    }

    fn requested(seen: &Seen) -> Option<LinkedEntityRequest> {
        seen.requested.lock().unwrap_or_else(PoisonError::into_inner).clone()
    }

    fn mode(seen: &Seen) -> Option<JoinMode> {
        match requested(seen).map(|requested| requested.answer) {
            Some(LinkedAnswer::Join(join)) => Some(join.mode()),
            Some(LinkedAnswer::NotRequested | LinkedAnswer::Unservable(_)) | None => None,
        }
    }

    #[tokio::test]
    async fn the_query_string_is_read_for_every_request() {
        let (status, seen) = run(Method::GET, "/ngsi-ld/v1/entities?type=Vehicle&join=inline", "").await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(mode(&seen), Some(JoinMode::Inline));

        let (_, seen) = run(Method::GET, "/ngsi-ld/v1/entities?type=Vehicle", "").await;
        assert_eq!(requested(&seen), Some(LinkedEntityRequest::NOTHING));
    }

    #[tokio::test]
    async fn a_batch_query_body_is_read_and_forwarded_byte_for_byte() {
        const BODY: &str = r#"{ "type": "Query",  "entities": [{"type": "Vehicle"}], "join": "flat" }"#;

        let (status, seen) = run(Method::POST, "/ngsi-ld/v1/entityOperations/query", BODY).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(mode(&seen), Some(JoinMode::Flat));
        assert_eq!(seen.body.lock().unwrap_or_else(PoisonError::into_inner).as_slice(), BODY.as_bytes());
    }

    #[tokio::test]
    async fn a_temporal_batch_query_body_is_read_too() {
        let (_, seen) = run(
            Method::POST,
            "/ngsi-ld/v1/temporal/entityOperations/query",
            r#"{"type":"Query","join":"inline"}"#,
        )
        .await;

        assert_eq!(mode(&seen), Some(JoinMode::Inline));
    }

    #[tokio::test]
    async fn a_subscription_body_is_read_for_its_notification() {
        let (_, seen) = run(
            Method::POST,
            "/ngsi-ld/v1/subscriptions",
            r#"{"type":"Subscription","notification":{"join":"flat","endpoint":{"uri":"http://sink.test"}}}"#,
        )
        .await;

        assert_eq!(
            requested(&seen),
            Some(LinkedEntityRequest {
                answer: LinkedAnswer::Unservable(LinkedEntityRetrieval::Subscription),
                filter: LinkedFilter::None,
                removed: Vec::new(),
            })
        );
    }

    #[tokio::test]
    async fn a_body_that_carries_no_selectors_is_not_read_as_one() {
        // A create carries entities, not a query; a `join` member there is an attribute.
        let (_, seen) = run(Method::POST, "/ngsi-ld/v1/entities", r#"{"id":"urn:a","type":"Vehicle","join":"inline"}"#).await;

        assert_eq!(requested(&seen), Some(LinkedEntityRequest::NOTHING));
    }

    #[tokio::test]
    async fn a_selector_that_cannot_be_read_is_refused_for_everyone() {
        for (method, uri, body) in [
            (Method::GET, "/ngsi-ld/v1/entities?pick=a{b", ""),
            (Method::POST, "/ngsi-ld/v1/entityOperations/query", r#"{"type":"Query","pick":["a{"]}"#),
            (Method::POST, "/ngsi-ld/v1/entityOperations/query", "not json"),
        ] {
            let (status, seen) = run(method, uri, body).await;

            assert_eq!(status, StatusCode::BAD_REQUEST, "{uri} {body}");
            assert_eq!(requested(&seen), None, "{uri} {body}");
        }
    }

    #[tokio::test]
    async fn a_request_without_a_parsed_body_is_refused() {
        // A body nobody parsed is a layer stack wired without the context layer; its selectors
        // cannot be read, and forwarding it would let a join through unjudged.
        for (uri, body) in [
            ("/ngsi-ld/v1/entityOperations/query", r#"{"type":"Query","join":"inline"}"#),
            ("/ngsi-ld/v1/subscriptions", r#"{"type":"Subscription","notification":{"join":"flat"}}"#),
        ] {
            let request = classified(Request::builder().method(Method::POST).uri(uri).body(Body::from(body)).unwrap());

            let (status, seen) = serve(request).await;

            assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{uri}");
            assert_eq!(requested(&seen), None, "{uri}");
        }
    }

    #[tokio::test]
    async fn a_request_whose_selectors_are_in_the_query_string_alone_needs_no_parsed_body() {
        let request = classified(Request::builder().uri("/ngsi-ld/v1/entities?join=flat").body(Body::empty()).unwrap());

        let (status, seen) = serve(request).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(mode(&seen), Some(JoinMode::Flat));
    }

    #[tokio::test]
    async fn the_selectors_are_read_from_the_stored_query_not_from_the_request_target() {
        let mut request = classified(Request::builder().uri("/ngsi-ld/v1/entities?join=flat").body(Body::empty()).unwrap());
        request.extensions_mut().insert(QueryParameters::parse("join=inline").unwrap());

        let (_, seen) = serve(request).await;

        assert_eq!(mode(&seen), Some(JoinMode::Inline));
    }

    #[tokio::test]
    async fn a_request_that_reached_this_layer_unclassified_or_unparsed_is_refused() {
        let mut unclassified = classified(Request::builder().uri("/ngsi-ld/v1/entities?join=flat").body(Body::empty()).unwrap());
        unclassified.extensions_mut().remove::<Operation>();
        assert_eq!(serve(unclassified).await.0, StatusCode::INTERNAL_SERVER_ERROR);

        let mut unparsed = classified(Request::builder().uri("/ngsi-ld/v1/entities?join=flat").body(Body::empty()).unwrap());
        unparsed.extensions_mut().remove::<QueryParameters>();
        assert_eq!(serve(unparsed).await.0, StatusCode::INTERNAL_SERVER_ERROR);
    }
}
