//! Resolves what a response will look like once, and puts it where everything downstream can find
//! it.
//!
//! The shape of an answer is decided by three things the caller sends (the `Accept` header, the
//! `options` parameter and the `format` parameter) and every layer that keys, coalesces or
//! rewrites a response has to agree about what they said. Reading them twice is how two layers end
//! up describing different answers to one request, which is the same argument that puts context
//! resolution in one place.
//!
//! This layer holds no opinion about the answer itself. It reads the request, writes
//! [`RequestRepresentation`] into the extensions, and gets out of the way. The model it uses,
//! `libra-ngsi-ld-representation`, is deliberately HTTP-free, so the Tower adapter lives here
//! rather than growing into it.
//!
//! # Resolving is not refusing
//!
//! By default a request whose representation cannot be decided is forwarded untouched, and the
//! broker answers it as it would without Libra. That is what keeps wiring this layer in from being a
//! behaviour change. A deployment that wants the gateway to refuse instead says so in
//! `[representation]`.
//!
//! Under the default, the extension holds [`RequestRepresentation::Unresolvable`] together with the
//! reason. It deliberately does not hold a fallback: a consumer that needs a representation and
//! finds one it cannot trust must decline to act, not substitute a default, because the default
//! would be a claim about a response nobody made.

use axum::{
    extract::Request,
    http::{HeaderValue, header::ACCEPT},
    response::{IntoResponse, Response},
};
use libra_config::representation::{ContradictoryOptions, RepresentationStrictness, UnsatisfiableAccept};
use libra_ngsi_ld_query::{parameter_name::ParameterName, parameters::QueryParameters};
use libra_ngsi_ld_query_layer::parsed::parameters;
use libra_ngsi_ld_representation::{error::RepresentationError, selection::ResponseRepresentation};
use libra_problem_details::problem::Problem;
use std::{
    convert::Infallible,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
use tower::{Layer, Service, ServiceExt};
use tracing::debug;

/// What the request said about the shape of its answer, as placed in the request extensions.
///
/// A named enum rather than a `Result` in the extensions: a consumer reading this is asking "what
/// will the answer look like", and the two answers to that are "this" and "nobody knows". Spelling
/// the second one out is what stops it being read as an absent extension, which is a wiring error
/// and means something else entirely.
#[derive(Debug, Clone)]
pub enum RequestRepresentation {
    /// The request named exactly one media type and one entity shape.
    Resolved(ResponseRepresentation),

    /// The request named no answer this proxy can describe, and the deployment chose to forward it
    /// anyway.
    Unresolvable(RepresentationError),
}

/// Layer that resolves the response representation.
#[derive(Debug, Clone, Copy)]
pub struct RepresentationLayer {
    strictness: RepresentationStrictness,
}

impl RepresentationLayer {
    /// Builds the layer from the `[representation]` section.
    #[must_use]
    pub const fn new(strictness: RepresentationStrictness) -> Self {
        Self { strictness }
    }
}

impl<S> Layer<S> for RepresentationLayer {
    type Service = RepresentationService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RepresentationService {
            inner,
            strictness: self.strictness,
        }
    }
}

/// The service produced by [`RepresentationLayer`].
#[derive(Debug, Clone, Copy)]
pub struct RepresentationService<S> {
    inner: S,
    strictness: RepresentationStrictness,
}

impl<S> Service<Request> for RepresentationService<S>
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
        let strictness = self.strictness;

        Box::pin(async move {
            match resolve(request, strictness) {
                Ok(request) => inner.oneshot(request).await,
                Err(problem) => Ok(problem.into_response()),
            }
        })
    }
}

/// Reads the representation and attaches it, or refuses the request if the deployment asked for
/// that.
fn resolve(mut request: Request, strictness: RepresentationStrictness) -> Result<Request, Problem> {
    let parameters = parameters(request.extensions()).map_err(|error| Problem::Internal(error.to_string()))?;

    match read(&request, parameters) {
        Ok(representation) => {
            request.extensions_mut().insert(RequestRepresentation::Resolved(representation));
        }
        Err(error) => {
            if let Some(problem) = refusal(&error, strictness) {
                return Err(problem);
            }

            debug!(error = %error, "forwarding a request whose response representation could not be decided");
            request.extensions_mut().insert(RequestRepresentation::Unresolvable(error));
        }
    }

    Ok(request)
}

/// The representation one request asks for, from its `Accept` header and the query parsed above.
fn read(request: &Request, parameters: &QueryParameters) -> Result<ResponseRepresentation, RepresentationError> {
    let accept = combined_accept(request)?;

    ResponseRepresentation::parse(
        accept.as_deref(),
        parameters.get(&ParameterName::OPTIONS),
        parameters.get(&ParameterName::FORMAT),
    )
}

/// Every `Accept` field line of the request, combined into one list, or `None` if there is none.
///
/// `Accept` is a list-valued field, so a request may send it on several lines and the recipient
/// reads them as one comma-separated list (RFC 9110 sections 5.3 and 12.5.1). Reading the first line
/// alone would negotiate from part of what the caller asked for, while the broker combines them all,
/// and the two could settle on different representations.
fn combined_accept(request: &Request) -> Result<Option<String>, RepresentationError> {
    let lines = request.headers().get_all(ACCEPT).iter().map(readable_accept).collect::<Result<Vec<_>, _>>()?;

    Ok((!lines.is_empty()).then(|| lines.join(", ")))
}

/// One `Accept` field line as text, or the reason it is not negotiable.
///
/// A header value may carry bytes that are not visible ASCII, and no such byte belongs in a media
/// range. Reading it as an absent header would negotiate plain JSON on the strength of something
/// the caller did not say.
fn readable_accept(value: &HeaderValue) -> Result<&str, RepresentationError> {
    value.to_str().map_err(|_| RepresentationError::NotAcceptable {
        accept: String::from_utf8_lossy(value.as_bytes()).into_owned(),
    })
}

/// The refusal a failure earns under this deployment's settings, if any.
///
/// Two keys and two classes. An `Accept` naming nothing producible is a content negotiation
/// failure and is reported as one; everything else is the caller having written a query that names
/// two different answers, which is a malformed request.
fn refusal(error: &RepresentationError, strictness: RepresentationStrictness) -> Option<Problem> {
    match error {
        RepresentationError::NotAcceptable { .. } => match strictness.unsatisfiable_accept {
            UnsatisfiableAccept::Refuse => Some(Problem::NotAcceptable(error.to_string())),
            UnsatisfiableAccept::Forward => None,
        },
        RepresentationError::ContradictoryOptions { .. }
        | RepresentationError::ContradictoryTemporalOptions { .. }
        | RepresentationError::ContradictoryFormat { .. }
        | RepresentationError::MisspelledOption { .. }
        | RepresentationError::UnknownFormat { .. } => match strictness.contradictory_options {
            ContradictoryOptions::Refuse => Some(Problem::BadRequest(error.to_string())),
            ContradictoryOptions::Forward => None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{StatusCode, header::CONTENT_TYPE},
    };
    use libra_ngsi_ld_query_layer::layer::QueryLayer;
    use libra_ngsi_ld_representation::{
        accept::MediaType,
        representation::{Representation, SystemAttributes},
    };
    use pretty_assertions::assert_eq;
    use std::sync::{
        Arc,
        Mutex,
        PoisonError,
        atomic::{AtomicUsize, Ordering},
    };

    /// Records what reached it, so a test can assert both that the request arrived and what the
    /// extension looked like when it did.
    #[derive(Clone)]
    struct Downstream {
        calls: Arc<AtomicUsize>,
        seen: Arc<Mutex<Option<RequestRepresentation>>>,
    }

    impl Downstream {
        fn new() -> Self {
            Self {
                calls: Arc::new(AtomicUsize::new(0)),
                seen: Arc::new(Mutex::new(None)),
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }

        /// The representation the downstream saw, removed from the recorder.
        fn take_representation(&self) -> Option<RequestRepresentation> {
            self.seen.lock().unwrap_or_else(PoisonError::into_inner).take()
        }
    }

    impl Service<Request> for Downstream {
        type Response = Response;
        type Error = Infallible;
        type Future = Pin<Box<dyn Future<Output = Result<Response, Infallible>> + Send>>;

        fn poll_ready(&mut self, _context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, request: Request) -> Self::Future {
            self.calls.fetch_add(1, Ordering::SeqCst);
            *self.seen.lock().unwrap_or_else(PoisonError::into_inner) = request.extensions().get::<RequestRepresentation>().cloned();

            Box::pin(async { Ok(StatusCode::IM_A_TEAPOT.into_response()) })
        }
    }

    fn refusing() -> RepresentationStrictness {
        RepresentationStrictness {
            unsatisfiable_accept: UnsatisfiableAccept::Refuse,
            contradictory_options: ContradictoryOptions::Refuse,
        }
    }

    /// A second handle onto the recorder, for the service while the test keeps the first.
    fn handle(downstream: &Downstream) -> Downstream {
        // The service takes its downstream by value and the test inspects it afterwards.
        downstream.clone()
    }

    async fn run(strictness: RepresentationStrictness, uri: &str, accept: Option<&str>) -> (Response, Downstream) {
        let downstream = Downstream::new();
        let service = QueryLayer::new().layer(RepresentationLayer::new(strictness).layer(handle(&downstream)));

        let mut builder = Request::builder().uri(uri);
        if let Some(accept) = accept {
            builder = builder.header(ACCEPT, accept);
        }

        let request = builder.body(Body::empty()).expect("the test request should build");
        let response = service.oneshot(request).await.unwrap_or_else(|error| match error {});

        (response, downstream)
    }

    fn resolved(downstream: &Downstream) -> ResponseRepresentation {
        match downstream.take_representation() {
            Some(RequestRepresentation::Resolved(representation)) => representation,
            other => panic!("expected a resolved representation, found {other:?}"),
        }
    }

    fn unresolvable(downstream: &Downstream) -> RepresentationError {
        match downstream.take_representation() {
            Some(RequestRepresentation::Unresolvable(error)) => error,
            other => panic!("expected an unresolvable representation, found {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_request_with_no_accept_resolves_to_plain_json() {
        let (response, downstream) = run(RepresentationStrictness::default(), "/ngsi-ld/v1/entities", None).await;

        assert_eq!(response.status(), StatusCode::IM_A_TEAPOT);
        let resolved = resolved(&downstream);
        assert_eq!(resolved.media_type(), MediaType::Json);
        assert_eq!(resolved.representation(), Representation::Normalized);
    }

    #[tokio::test]
    async fn the_options_parameter_reaches_the_extension() {
        let (_, downstream) = run(
            RepresentationStrictness::default(),
            "/ngsi-ld/v1/entities?type=Vehicle&options=keyValues,sysAttrs",
            None,
        )
        .await;

        let resolved = resolved(&downstream);
        assert_eq!(resolved.representation(), Representation::Simplified);
        assert_eq!(resolved.system_attributes(), SystemAttributes::Included);
    }

    #[tokio::test]
    async fn an_unsatisfiable_accept_is_forwarded_by_default() {
        // Wiring this layer in must not manufacture a refusal the broker would not have made.
        let (response, downstream) = run(RepresentationStrictness::default(), "/ngsi-ld/v1/entities", Some("text/csv")).await;

        assert_eq!(downstream.calls(), 1, "the broker must still be asked");
        assert_eq!(response.status(), StatusCode::IM_A_TEAPOT, "the answer is whatever the broker said");
        assert!(matches!(unresolvable(&downstream), RepresentationError::NotAcceptable { .. }));
    }

    #[tokio::test]
    async fn an_unsatisfiable_accept_is_refused_when_configured_to_refuse() {
        let (response, downstream) = run(refusing(), "/ngsi-ld/v1/entities", Some("text/csv")).await;

        assert_eq!(response.status(), StatusCode::NOT_ACCEPTABLE);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).and_then(|value| value.to_str().ok()),
            Some("application/problem+json")
        );
        assert_eq!(downstream.calls(), 0, "a refused request must not reach the broker");
    }

    #[tokio::test]
    async fn contradictory_options_are_forwarded_by_default() {
        let (_, downstream) = run(RepresentationStrictness::default(), "/ngsi-ld/v1/entities?options=keyValues,concise", None).await;

        assert_eq!(downstream.calls(), 1);
        assert!(matches!(unresolvable(&downstream), RepresentationError::ContradictoryOptions { .. }));
    }

    #[tokio::test]
    async fn contradictory_options_are_refused_when_configured_to_refuse() {
        let (response, downstream) = run(refusing(), "/ngsi-ld/v1/entities?options=keyValues,concise", None).await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(downstream.calls(), 0);
    }

    #[tokio::test]
    async fn a_format_disagreeing_with_options_is_the_same_class_of_refusal() {
        let (response, downstream) = run(refusing(), "/ngsi-ld/v1/entities?options=concise&format=keyValues", None).await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(downstream.calls(), 0);
    }

    #[tokio::test]
    async fn an_accept_header_that_is_not_text_is_not_negotiated_against() {
        // A header carrying bytes outside visible ASCII is not a media range. Reading it as an
        // absent header would negotiate plain JSON on the strength of something nobody wrote.
        let downstream = Downstream::new();
        let service = QueryLayer::new().layer(RepresentationLayer::new(RepresentationStrictness::default()).layer(handle(&downstream)));

        let mut request = Request::builder()
            .uri("/ngsi-ld/v1/entities")
            .body(Body::empty())
            .expect("the test request should build");
        request
            .headers_mut()
            .insert(ACCEPT, HeaderValue::from_bytes(b"application/\xff+json").expect("the header should build"));

        let response = service.oneshot(request).await.unwrap_or_else(|error| match error {});

        assert_eq!(response.status(), StatusCode::IM_A_TEAPOT);
        assert!(matches!(unresolvable(&downstream), RepresentationError::NotAcceptable { .. }));
    }

    /// Runs a request that sends `lines` as separate `Accept` field lines.
    async fn negotiated_from_lines(lines: &[&'static str]) -> MediaType {
        let downstream = Downstream::new();
        let service = QueryLayer::new().layer(RepresentationLayer::new(refusing()).layer(handle(&downstream)));

        let mut request = Request::builder()
            .uri("/ngsi-ld/v1/entities")
            .body(Body::empty())
            .expect("the test request should build");
        for line in lines {
            request.headers_mut().append(ACCEPT, HeaderValue::from_static(line));
        }

        let response = service.oneshot(request).await.unwrap_or_else(|error| match error {});
        assert_eq!(response.status(), StatusCode::IM_A_TEAPOT);

        resolved(&downstream).media_type()
    }

    #[tokio::test]
    async fn accept_lines_are_negotiated_as_one_list() {
        // RFC 9110 section 5.3: the lines combine. The first line alone names nothing producible,
        // so reading only it would refuse a request the broker serves as JSON-LD.
        assert_eq!(negotiated_from_lines(&["text/plain", "application/ld+json"]).await, MediaType::JsonLd);
    }

    #[tokio::test]
    async fn a_preference_on_a_later_accept_line_outranks_an_earlier_one() {
        assert_eq!(
            negotiated_from_lines(&["application/json;q=0.5", "application/ld+json"]).await,
            MediaType::JsonLd
        );
    }

    #[tokio::test]
    async fn one_unreadable_accept_line_makes_the_whole_list_unnegotiable() {
        let downstream = Downstream::new();
        let service = QueryLayer::new().layer(RepresentationLayer::new(RepresentationStrictness::default()).layer(handle(&downstream)));

        let mut request = Request::builder()
            .uri("/ngsi-ld/v1/entities")
            .body(Body::empty())
            .expect("the test request should build");
        request.headers_mut().append(ACCEPT, HeaderValue::from_static("application/ld+json"));
        request
            .headers_mut()
            .append(ACCEPT, HeaderValue::from_bytes(b"application/\xff+json").expect("the header should build"));

        let _response = service.oneshot(request).await.unwrap_or_else(|error| match error {});

        assert!(matches!(unresolvable(&downstream), RepresentationError::NotAcceptable { .. }));
    }
}
