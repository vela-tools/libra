//! Resolves a request's JSON-LD context once, and puts it where everything downstream can find it.
//!
//! Resolution has to happen exactly once per request. Doing it twice is not merely wasteful: two
//! resolutions can disagree (a cache entry expires between them, a remote context changes) and
//! then one layer authorizes against a meaning a later layer does not share.
//!
//! The context also has to be resolved before anything that compares a name. Everything that makes
//! a decision about an entity type, an attribute or a scope reads [`RequestContextExtension`] from
//! the request extensions, and finding it absent is a bug rather than a reason to continue.
//!
//! The body is read here too, because the context may be in it, and it is read once: the parsed
//! [`RequestBody`] goes into the extensions beside the context, and every layer below judges that
//! parse rather than one of its own.

mod body_context;

use axum::{
    body::{Body, to_bytes},
    extract::Request,
    http::{
        StatusCode,
        header::{CONTENT_TYPE, LINK},
    },
    response::{IntoResponse, Response},
};
use http_body_util::LengthLimitError;
use jstrict::Value;
use libra_json_body::request_body::RequestBody;
use libra_jsonld_context::{
    error::ContextError,
    resolver::{ContextResolver, RequestContext},
};
use libra_jsonld_term_expansion::resolved::ResolvedContext;
use libra_problem_details::problem::Problem;
use std::{
    convert::Infallible,
    error::Error,
    future::Future,
    iter::successors,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tower::{Layer, Service, ServiceExt};
use tracing::{debug, warn};

/// The resolved context, as placed in the request extensions.
///
/// Wrapped in an `Arc` because every downstream layer reads it and none of them own it.
#[derive(Debug, Clone)]
pub struct RequestContextExtension(pub Arc<ResolvedContext>);

impl RequestContextExtension {
    /// The resolved context.
    #[must_use]
    pub fn context(&self) -> &ResolvedContext {
        &self.0
    }
}

/// Layer that resolves the request context.
#[derive(Clone)]
pub struct ContextLayer {
    resolver: Arc<ContextResolver>,
    max_body_bytes: usize,
}

impl ContextLayer {
    /// Builds the layer.
    ///
    /// `max_body_bytes` bounds how much of a body will be buffered to look for an inline
    /// `@context`. It should be the same limit the payload-limit layer enforces; this layer runs
    /// before the body reaches the broker, so an unbounded read here would be a way around it.
    #[must_use]
    pub const fn new(resolver: Arc<ContextResolver>, max_body_bytes: usize) -> Self {
        Self { resolver, max_body_bytes }
    }
}

impl<S> Layer<S> for ContextLayer {
    type Service = ContextService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ContextService {
            inner,
            resolver: Arc::clone(&self.resolver),
            max_body_bytes: self.max_body_bytes,
        }
    }
}

/// The service produced by [`ContextLayer`].
#[derive(Clone)]
pub struct ContextService<S> {
    inner: S,
    resolver: Arc<ContextResolver>,
    max_body_bytes: usize,
}

impl<S> Service<Request> for ContextService<S>
where
    S: Service<Request, Response = Response, Error = Infallible> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = Response;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Response, Infallible>> + Send>>;

    fn poll_ready(&mut self, _context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request) -> Self::Future {
        let inner = self.inner.clone();
        let resolver = Arc::clone(&self.resolver);
        let max_body_bytes = self.max_body_bytes;

        Box::pin(async move {
            match resolve(&resolver, request, max_body_bytes).await {
                Ok(request) => inner.oneshot(request).await,
                Err(problem) => Ok(problem.into_response()),
            }
        })
    }
}

/// Resolves the context and reattaches the body.
async fn resolve(resolver: &ContextResolver, request: Request, max_body_bytes: usize) -> Result<Request, Problem> {
    let (mut parts, body) = request.into_parts();

    // One readable value or none. Reading the first of two, or a value that is not ASCII as absent,
    // would decide the context channel on a media type the broker may not see the same way.
    let mut content_types = parts.headers.get_all(CONTENT_TYPE).iter();
    let content_type = match (content_types.next(), content_types.next()) {
        (None, _) => None,
        (Some(_), Some(_)) => return Err(Problem::BadRequest("the request carries more than one Content-Type header".to_owned())),
        (Some(value), None) => Some(
            value
                .to_str()
                .map_err(|_| Problem::BadRequest("the Content-Type header is not visible ASCII".to_owned()))?,
        ),
    };
    // Every Link header, not the first, and a header that is not readable is an error rather than
    // an absent one. Dropping it silently would resolve the request against a different context
    // than the broker will.
    let link_headers = parts
        .headers
        .get_all(LINK)
        .iter()
        .map(|value| value.to_str().map_err(|_| Problem::BadRequest("Link header is not visible ASCII".to_owned())))
        .collect::<Result<Vec<&str>, Problem>>()?;

    // Every body is read, not only an `application/ld+json` one. An `@context` in an
    // `application/json` body is a combination the broker refuses, and refusing it here means
    // looking for it: buffering only the ld+json case would authorise such a request against the
    // core context and forward it, while a broker whose content-type parsing handles it under the
    // ld+json rules would store it under the caller's context instead. A body with no content at all
    // costs nothing to read, and the size is bounded by the payload limit.
    let bytes = to_bytes(body, max_body_bytes).await.map_err(|error| unreadable(&error, max_body_bytes))?;

    let request_body = RequestBody::read(&bytes).map_err(|error| Problem::BadRequest(error.to_string()))?;
    let body_context = body_context::find(&request_body, content_type)?;

    let jsonld = resolve_context(resolver, content_type, &link_headers, body_context.as_ref()).await?;
    parts.extensions.insert(RequestContextExtension(Arc::new(jsonld)));
    parts.extensions.insert(request_body);

    Ok(Request::from_parts(parts, Body::from(bytes)))
}

/// The problem a request body that could not be read is answered with.
///
/// Only a body that ran past the limit is a 413, whether this read stopped it or the payload limit
/// above did. Anything else (the caller closed the connection mid-body, the transfer broke) is a
/// 400: answering it as too large would put a size refusal in the audit record of a request that
/// was never too large.
fn unreadable(error: &axum::Error, max_body_bytes: usize) -> Problem {
    let over_the_limit = successors(Some(error as &(dyn Error + 'static)), |&error| error.source())
        .any(|error| error.is::<LengthLimitError>() || matches!(error.downcast_ref::<Problem>(), Some(Problem::PayloadTooLarge(_))));

    if over_the_limit {
        Problem::PayloadTooLarge(format!("request body exceeds the {max_body_bytes} byte limit"))
    } else {
        Problem::BadRequest("the request body could not be read".to_owned())
    }
}

async fn resolve_context(
    resolver: &ContextResolver,
    content_type: Option<&str>,
    link_headers: &[&str],
    body_context: Option<&Value>,
) -> Result<ResolvedContext, Problem> {
    let request = RequestContext {
        content_type,
        body_context,
        link_headers,
    };

    match resolver.resolve(&request).await {
        Ok(jsonld) => {
            debug!("resolved the request context");
            Ok(jsonld)
        }
        Err(error) => {
            warn!(error = %error, "failed to resolve the request context");
            Err(problem_for(&error))
        }
    }
}

/// Maps a resolution failure onto the response the caller sees.
///
/// Every one of these refuses the request. None of them may fall through to a request handled
/// without a context: that would mean comparing names whose meaning is unknown, which is the same
/// as not comparing them at all.
fn problem_for(error: &ContextError) -> Problem {
    let detail = error.to_string();

    match error {
        // The caller chose a context the deployment will not fetch, or sent one that is not
        // usable, or mixed the two channels. All of these are the request's fault.
        ContextError::NotAllowed { .. }
        | ContextError::RemoteFetchDisabled { .. }
        | ContextError::QueryNotAllowed { .. }
        | ContextError::AmbiguousPath { .. }
        | ContextError::NotAUrl { .. }
        | ContextError::Malformed { .. }
        | ContextError::MalformedBodyContext { .. }
        | ContextError::MalformedLinkHeader { .. }
        | ContextError::UnusableContextLink { .. }
        | ContextError::RedefinesCoreTerm { .. }
        | ContextError::LinkHeaderNotAllowed
        | ContextError::BodyContextNotAllowed
        | ContextError::Unresolvable => Problem::BadRequest(detail),

        // The context host is a dependency, and the fault is Libra's dependency, not the caller's.
        ContextError::Timeout { .. } => Problem::GatewayTimeout(detail),
        ContextError::Fetch { .. } => Problem::BadGateway(detail),

        // Startup reads every preloaded context, so reaching this on a request means the file
        // became unreadable while the process was running. Nothing the caller did, and nothing
        // they can fix.
        //
        // The fetching client is built once at startup, so a request cannot be what broke it either.
        ContextError::PreloadUnreadable { .. } | ContextError::Client { .. } => Problem::Internal(detail),
    }
}

/// The status a resolution failure produces, exposed for tests and documentation.
#[must_use]
pub fn status_for(error: &ContextError) -> StatusCode {
    problem_for(error).status()
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::stream;
    use http::header::LINK;
    use iri_rs::IriBuf;
    use libra_config::jsonld::JsonLd;
    use libra_jsonld_context::resolver::CONTEXT_RELATION;
    use libra_jsonld_term_expansion::name::Term;
    use pretty_assertions::assert_eq;
    use std::{
        io,
        sync::{
            Mutex,
            atomic::{AtomicUsize, Ordering},
        },
    };
    use url::Url;

    /// Records what reached it, so a test can assert both that the request arrived and what it
    /// looked like when it did.
    #[derive(Clone)]
    struct Downstream {
        calls: Arc<AtomicUsize>,
        seen_body: Arc<Mutex<Vec<u8>>>,
        seen_type: Arc<Mutex<Option<String>>>,
        seen_parsed: Arc<Mutex<Option<RequestBody>>>,
    }

    impl Downstream {
        fn new() -> Self {
            Self {
                calls: Arc::new(AtomicUsize::new(0)),
                seen_body: Arc::new(Mutex::new(Vec::new())),
                seen_type: Arc::new(Mutex::new(None)),
                seen_parsed: Arc::new(Mutex::new(None)),
            }
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

            let extension = request.extensions().get::<RequestContextExtension>().cloned();
            let expanded = extension.map(|extension| extension.context().expand(&Term::new("Vehicle")));
            let seen_type = Arc::clone(&self.seen_type);
            let seen_body = Arc::clone(&self.seen_body);
            if let Ok(mut slot) = self.seen_parsed.lock() {
                *slot = request.extensions().get::<RequestBody>().cloned();
            }

            Box::pin(async move {
                if let Ok(mut slot) = seen_type.lock() {
                    *slot = expanded.flatten().map(|iri| iri.as_str().to_owned());
                }

                let bytes = to_bytes(request.into_body(), 64 * 1024).await.unwrap_or_default();
                if let Ok(mut slot) = seen_body.lock() {
                    *slot = bytes.to_vec();
                }

                Ok(StatusCode::OK.into_response())
            })
        }
    }

    /// A second handle onto the recorder, handed to the service while the test keeps the first.
    fn handle(downstream: &Downstream) -> Downstream {
        // The service takes its downstream by value and the test inspects it afterwards.
        downstream.clone()
    }

    fn layer(config: &JsonLd) -> ContextLayer {
        ContextLayer::new(Arc::new(ContextResolver::new(config).expect("resolver")), 64 * 1024)
    }

    #[tokio::test]
    async fn a_request_without_a_context_still_gets_one() {
        let downstream = Downstream::new();
        let service = layer(&JsonLd::default()).layer(handle(&downstream));

        let request = Request::builder().uri("/ngsi-ld/v1/entities").body(Body::empty()).unwrap();
        let response = service.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            downstream.seen_type.lock().unwrap().as_deref(),
            Some("https://uri.etsi.org/ngsi-ld/default-context/Vehicle"),
            "downstream must always find a context, falling back to the core one"
        );
    }

    #[tokio::test]
    async fn an_inline_context_reaches_downstream_and_the_body_survives() {
        let downstream = Downstream::new();
        let service = layer(&JsonLd::default()).layer(handle(&downstream));

        let body = r#"{"id":"urn:ngsi-ld:Probe:1","type":"Vehicle","@context":{"Vehicle":"https://example.test/probe#Vehicle"}}"#;
        let request = Request::builder()
            .method("POST")
            .uri("/ngsi-ld/v1/entities")
            .header(CONTENT_TYPE, "application/ld+json")
            .body(Body::from(body))
            .unwrap();

        let response = service.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            downstream.seen_type.lock().unwrap().as_deref(),
            Some("https://example.test/probe#Vehicle"),
            "the caller's context must be the one downstream sees"
        );
        assert_eq!(
            str::from_utf8(&downstream.seen_body.lock().unwrap()).unwrap(),
            body,
            "buffering the body to read @context must not consume it"
        );
    }

    #[tokio::test]
    async fn a_context_that_cannot_be_resolved_stops_the_request() {
        let downstream = Downstream::new();
        let service = layer(&JsonLd::default()).layer(handle(&downstream));

        let link = format!("<https://not-allowed.test/ctx.jsonld>; rel=\"{CONTEXT_RELATION}\"");
        let request = Request::builder().uri("/ngsi-ld/v1/entities").header(LINK, link).body(Body::empty()).unwrap();

        let response = service.oneshot(request).await.unwrap();

        assert!(
            response.status().is_client_error() || response.status().is_server_error(),
            "an unresolvable context must not be let through"
        );
        assert_eq!(
            downstream.calls.load(Ordering::SeqCst),
            0,
            "the request must not reach the broker without a context"
        );
    }

    #[tokio::test]
    async fn mixing_context_channels_stops_the_request() {
        let downstream = Downstream::new();
        let service = layer(&JsonLd::default()).layer(handle(&downstream));

        let link = format!("<https://example.test/ctx.jsonld>; rel=\"{CONTEXT_RELATION}\"");
        let request = Request::builder()
            .method("POST")
            .uri("/ngsi-ld/v1/entities")
            .header(CONTENT_TYPE, "application/ld+json")
            .header(LINK, link)
            .body(Body::from(r#"{"@context":{"Thing":"https://example.test/Thing"}}"#))
            .unwrap();

        let response = service.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(downstream.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn a_context_in_a_plain_json_body_is_refused() {
        // The combination the broker refuses. Finding it means reading the body of a request that
        // is not `application/ld+json`: skipping it on the grounds that only an ld+json body may carry
        // a context would resolve the request against the core context and forward it, and a broker
        // whose content-type parsing handles it under the ld+json rules would store it under a context
        // Libra never saw.
        let downstream = Downstream::new();
        let service = layer(&JsonLd::default()).layer(handle(&downstream));

        let request = Request::builder()
            .method("POST")
            .uri("/ngsi-ld/v1/entities")
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(
                r#"{"id":"urn:ngsi-ld:Vehicle:1","@context":{"Vehicle":"https://example.test/ns#Vehicle"}}"#,
            ))
            .unwrap();
        let response = service.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(downstream.calls.load(Ordering::SeqCst), 0, "a refused request must not reach the broker");
    }

    #[tokio::test]
    async fn a_context_in_a_body_sent_under_an_unknown_content_type_is_refused_too() {
        // Anything that is not `application/ld+json` follows the plain-JSON rules, so the check
        // cannot be conditioned on the content type being one Libra recognises.
        let downstream = Downstream::new();
        let service = layer(&JsonLd::default()).layer(handle(&downstream));

        let request = Request::builder()
            .method("POST")
            .uri("/ngsi-ld/v1/entities")
            .header(CONTENT_TYPE, "text/plain")
            .body(Body::from(r#"{"@context":{"Vehicle":"https://example.test/ns#Vehicle"}}"#))
            .unwrap();
        let response = service.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    fn post(body: impl Into<Body>) -> Request {
        Request::builder()
            .method("POST")
            .uri("/ngsi-ld/v1/entities")
            .header(CONTENT_TYPE, "application/json")
            .body(body.into())
            .unwrap()
    }

    #[tokio::test]
    async fn the_parsed_body_is_placed_in_the_extensions() {
        let downstream = Downstream::new();
        let service = layer(&JsonLd::default()).layer(handle(&downstream));

        let response = service.oneshot(post(r#"{"id":"urn:a","type":"Vehicle"}"#)).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            *downstream.seen_parsed.lock().unwrap(),
            Some(RequestBody::Json(jstrict::json!({"id": "urn:a", "type": "Vehicle"})))
        );
    }

    #[tokio::test]
    async fn a_request_without_a_body_carries_an_empty_one() {
        let downstream = Downstream::new();
        let service = layer(&JsonLd::default()).layer(handle(&downstream));

        let request = Request::builder().uri("/ngsi-ld/v1/entities").body(Body::empty()).unwrap();
        service.oneshot(request).await.unwrap();

        assert_eq!(*downstream.seen_parsed.lock().unwrap(), Some(RequestBody::Empty));
    }

    #[tokio::test]
    async fn a_body_nested_past_the_limit_is_refused_without_parsing_it() {
        let downstream = Downstream::new();
        let service = ContextLayer::new(Arc::new(ContextResolver::new(&JsonLd::default()).unwrap()), 1024 * 1024).layer(handle(&downstream));

        let body = format!("{}{}", "[".repeat(100_000), "]".repeat(100_000));
        let response = service.oneshot(post(body)).await.unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(downstream.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn a_body_repeating_a_member_is_refused() {
        let downstream = Downstream::new();
        let service = layer(&JsonLd::default()).layer(handle(&downstream));

        let response = service.oneshot(post(r#"{"id":"urn:a","type":"Secret","type":"Vehicle"}"#)).await.unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(downstream.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn two_content_types_are_refused() {
        let downstream = Downstream::new();
        let service = layer(&JsonLd::default()).layer(handle(&downstream));

        let request = Request::builder()
            .method("POST")
            .uri("/ngsi-ld/v1/entities")
            .header(CONTENT_TYPE, "application/json")
            .header(CONTENT_TYPE, "application/ld+json")
            .body(Body::from(r#"{"id":"urn:a"}"#))
            .unwrap();

        assert_eq!(service.oneshot(request).await.unwrap().status(), StatusCode::BAD_REQUEST);
        assert_eq!(downstream.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn a_content_type_that_is_not_ascii_is_refused_rather_than_read_as_absent() {
        let downstream = Downstream::new();
        let service = layer(&JsonLd::default()).layer(handle(&downstream));

        let request = Request::builder()
            .method("POST")
            .uri("/ngsi-ld/v1/entities")
            .header(CONTENT_TYPE, http::HeaderValue::from_bytes(b"application/ld+json\xe9").unwrap())
            .body(Body::from(r#"{"id":"urn:a"}"#))
            .unwrap();

        assert_eq!(service.oneshot(request).await.unwrap().status(), StatusCode::BAD_REQUEST);
        assert_eq!(downstream.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn a_body_over_the_limit_is_refused_rather_than_buffered() {
        let downstream = Downstream::new();
        let service = ContextLayer::new(Arc::new(ContextResolver::new(&JsonLd::default()).unwrap()), 128).layer(handle(&downstream));

        let body = format!(r#"{{"pad":"{}"}}"#, "x".repeat(4096));
        let request = Request::builder()
            .method("POST")
            .uri("/ngsi-ld/v1/entities")
            .header(CONTENT_TYPE, "application/ld+json")
            .body(Body::from(body))
            .unwrap();

        let response = service.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(downstream.calls.load(Ordering::SeqCst), 0);
    }

    async fn status_for_body(body: Body) -> StatusCode {
        let downstream = Downstream::new();
        let service = ContextLayer::new(Arc::new(ContextResolver::new(&JsonLd::default()).unwrap()), 128).layer(handle(&downstream));

        let response = service.oneshot(post(body)).await.unwrap();
        assert_eq!(downstream.calls.load(Ordering::SeqCst), 0);

        response.status()
    }

    #[tokio::test]
    async fn a_body_that_breaks_off_mid_transfer_is_a_bad_request_not_a_payload_too_large() {
        let chunks: [Result<&'static str, io::Error>; 2] = [Ok(r#"{"id":"#), Err(io::Error::from(io::ErrorKind::ConnectionReset))];

        assert_eq!(status_for_body(Body::from_stream(stream::iter(chunks))).await, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn a_body_the_payload_limit_stopped_mid_stream_is_still_a_payload_too_large() {
        let chunks: [Result<&'static str, Problem>; 1] = [Err(Problem::PayloadTooLarge("over the limit".to_owned()))];

        assert_eq!(status_for_body(Body::from_stream(stream::iter(chunks))).await, StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn a_context_link_in_a_later_header_is_still_found() {
        // A request may repeat the Link header. Reading only the first would resolve this against
        // the core context while the broker used the caller's, and the two would then disagree
        // about what every term means.
        let downstream = Downstream::new();
        let service = layer(&JsonLd::default()).layer(handle(&downstream));

        let request = Request::builder()
            .uri("/ngsi-ld/v1/entities")
            .header(LINK, "<https://example.test/next>; rel=\"next\"")
            .header(LINK, format!("<https://not-allowed.test/ctx.jsonld>; rel=\"{CONTEXT_RELATION}\""))
            .body(Body::empty())
            .unwrap();

        let response = service.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "the context link in the second header must be seen");
        assert_eq!(downstream.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn a_context_link_folded_beside_other_relations_is_still_found() {
        // RFC 8288 allows several link-values in one header, so a context link can arrive next to
        // pagination links. Taking the first link-value would pick the wrong one.
        let downstream = Downstream::new();
        let service = layer(&JsonLd::default()).layer(handle(&downstream));

        let folded = format!("<https://example.test/next>; rel=\"next\", <https://not-allowed.test/ctx.jsonld>; rel=\"{CONTEXT_RELATION}\"");
        let request = Request::builder().uri("/ngsi-ld/v1/entities").header(LINK, folded).body(Body::empty()).unwrap();

        let response = service.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "a folded context link must be seen");
        assert_eq!(downstream.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn a_malformed_link_header_is_refused_rather_than_ignored() {
        let downstream = Downstream::new();
        let service = layer(&JsonLd::default()).layer(handle(&downstream));

        let request = Request::builder()
            .uri("/ngsi-ld/v1/entities")
            .header(LINK, "<https://example.test/ctx.jsonld; rel=\"ctx\"")
            .body(Body::empty())
            .unwrap();

        let response = service.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(downstream.calls.load(Ordering::SeqCst), 0);
    }

    fn address() -> Url {
        Url::parse("https://x.test").expect("a URL")
    }

    #[test]
    fn every_resolution_failure_refuses_the_request() {
        // No variant may map to a success status: a context failure that let the request through
        // would be an authorization decision made without knowing what the names mean.
        let failures = [
            ContextError::NotAllowed { url: Box::new(address()) },
            ContextError::RemoteFetchDisabled { url: Box::new(address()) },
            ContextError::Timeout { url: Box::new(address()) },
            ContextError::Fetch {
                url: Box::new(address()),
                reason: "no".to_owned(),
            },
            ContextError::Malformed {
                url: Box::new(address()),
                reason: "no".to_owned(),
            },
            ContextError::NotAUrl {
                iri: IriBuf::new("urn:x".to_owned()).expect("a valid IRI"),
            },
            ContextError::Client { reason: "no".to_owned() },
            ContextError::MalformedBodyContext { reason: "no".to_owned() },
            ContextError::MalformedLinkHeader { reason: "no".to_owned() },
            ContextError::LinkHeaderNotAllowed,
            ContextError::BodyContextNotAllowed,
            ContextError::Unresolvable,
        ];

        for failure in &failures {
            let status = status_for(failure);
            assert!(status.is_client_error() || status.is_server_error(), "{failure:?} produced {status}");
        }
    }
}
