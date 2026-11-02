//! Refuses request bodies larger than the deployment allows.
//!
//! Two mechanisms, because one is not enough. `Content-Length` is the cheap check and catches the
//! honest caller, but it is a claim the client makes about itself and a client that wants to
//! exhaust the proxy's memory has no reason to make it truthfully. [`Limited`] is therefore
//! applied to the body as well, so the bytes are counted rather than believed.
//!
//! A body with no declared length is read here rather than downstream. Wrapping it in [`Limited`]
//! and forwarding it would defer the limit until something happened to read the body: the check
//! would fire mid-stream, after the response had already been decided, and the caller would see a
//! broken connection or a 200 instead of a 413. Reading up to the limit here costs the same memory
//! the limit already allows, and keeps the refusal an ordinary response.

use axum::{
    body::Body,
    extract::Request,
    http::header::CONTENT_LENGTH,
    response::{IntoResponse, Response},
};
use http_body_util::{BodyExt, LengthLimitError, Limited};
use libra_problem_details::problem::Problem;
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
use tower::{BoxError, Layer, Service, ServiceExt};
use tracing::warn;

/// Layer that rejects request bodies over `max_bytes` with a 413.
#[derive(Clone, Copy, Debug)]
pub struct PayloadLimitLayer {
    max_bytes: usize,
}

impl PayloadLimitLayer {
    /// Creates the layer with the maximum body size, in bytes.
    ///
    /// A body of exactly `max_bytes` is allowed; the limit is the largest acceptable size, not the
    /// first rejected one.
    #[must_use]
    pub const fn new(max_bytes: usize) -> Self {
        Self { max_bytes }
    }
}

impl<S> Layer<S> for PayloadLimitLayer {
    type Service = PayloadLimitService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        PayloadLimitService {
            inner,
            max_bytes: self.max_bytes,
        }
    }
}

/// The service produced by [`PayloadLimitLayer`].
#[derive(Clone, Debug)]
pub struct PayloadLimitService<S> {
    inner: S,
    max_bytes: usize,
}

impl<S> Service<Request> for PayloadLimitService<S>
where
    S: Service<Request, Response = Response> + Clone + Send + 'static,
    S::Error: Send + 'static,
    S::Future: Send + 'static,
{
    type Response = Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Response, S::Error>> + Send>>;

    /// Always ready. Readiness of the inner service is driven by `oneshot` in [`Self::call`], on
    /// the clone that actually serves the request.
    fn poll_ready(&mut self, _context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request) -> Self::Future {
        let inner = self.inner.clone();
        let max_bytes = self.max_bytes;

        Box::pin(async move {
            match enforce(request, max_bytes).await {
                Ok(request) => inner.oneshot(request).await,
                Err(problem) => Ok(problem.into_response()),
            }
        })
    }
}

/// Applies the limit, returning the request to forward or the problem to answer with.
async fn enforce(request: Request, max_bytes: usize) -> Result<Request, Problem> {
    let declared = request
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok());

    if let Some(length) = declared {
        if length > max_bytes {
            warn!(
                content_length = length,
                limit = max_bytes,
                "refusing a request whose declared body size is over the limit"
            );
            return Err(too_large(length, max_bytes));
        }

        // The declared length was acceptable, so the body may stream on. `Limited` still rides
        // along: a caller that under-declares its length would otherwise have talked its way past
        // the only check there is.
        let (parts, body) = request.into_parts();
        let guarded = Limited::new(body, max_bytes).map_err(move |error| relabel(error, max_bytes));

        return Ok(Request::from_parts(parts, Body::new(guarded)));
    }

    // No declared length. The size is unknowable without reading, so read it, bounded by the very
    // limit being enforced, and answer with a real response rather than failing downstream.
    let (parts, body) = request.into_parts();
    match Limited::new(body, max_bytes).collect().await {
        Ok(collected) => Ok(Request::from_parts(parts, Body::from(collected.to_bytes()))),
        Err(error) => {
            if error.is::<LengthLimitError>() {
                warn!(limit = max_bytes, "refusing a request whose undeclared body ran over the limit");
                Err(Problem::PayloadTooLarge(format!(
                    "Request body exceeds the maximum allowed size of {max_bytes} bytes"
                )))
            } else {
                Err(Problem::BadRequest("Request body could not be read".to_owned()))
            }
        }
    }
}

/// The refusal sent when a body is, or claims to be, over the limit.
fn too_large(length: usize, max_bytes: usize) -> Problem {
    Problem::PayloadTooLarge(format!("Request body of {length} bytes exceeds the maximum allowed size of {max_bytes} bytes"))
}

/// Renames a mid-stream limit breach into the problem it actually is.
///
/// Without this the failure travels as `LengthLimitError`, which the outermost handler cannot
/// recognise and therefore reports as an opaque 500, a proxy fault, for a request the client
/// oversized on purpose.
fn relabel(error: BoxError, max_bytes: usize) -> BoxError {
    if error.is::<LengthLimitError>() {
        warn!(limit = max_bytes, "a request body ran past the limit its Content-Length promised to respect");
        return Box::new(Problem::PayloadTooLarge(format!(
            "Request body exceeds the maximum allowed size of {max_bytes} bytes"
        )));
    }

    error
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Bytes, http::StatusCode};
    use pretty_assertions::assert_eq;
    use std::{
        convert::Infallible,
        sync::{
            Arc,
            Mutex,
            atomic::{AtomicUsize, Ordering},
        },
    };

    /// Answers 200 without touching the body, the way a service that only inspects headers would.
    #[derive(Clone)]
    struct Downstream {
        calls: Arc<AtomicUsize>,
    }

    impl Downstream {
        fn new() -> Self {
            Self {
                calls: Arc::new(AtomicUsize::new(0)),
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

        fn call(&mut self, _request: Request) -> Self::Future {
            self.calls.fetch_add(1, Ordering::SeqCst);

            Box::pin(async { Ok(StatusCode::OK.into_response()) })
        }
    }

    /// Reads the body, and reports what reading it produced.
    #[derive(Clone)]
    struct ReadingDownstream {
        read: Arc<Mutex<Option<Result<Bytes, String>>>>,
    }

    impl ReadingDownstream {
        fn new() -> Self {
            Self {
                read: Arc::new(Mutex::new(None)),
            }
        }
    }

    impl Service<Request> for ReadingDownstream {
        type Response = Response;
        type Error = Infallible;
        type Future = Pin<Box<dyn Future<Output = Result<Response, Infallible>> + Send>>;

        fn poll_ready(&mut self, _context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, request: Request) -> Self::Future {
            let read = Arc::clone(&self.read);

            Box::pin(async move {
                // The body error arrives wrapped in `axum::Error`; unwrapping it is how a real
                // reader would find out what went wrong.
                let outcome = match request.into_body().collect().await {
                    Ok(collected) => Ok(collected.to_bytes()),
                    Err(error) => Err(error
                        .into_inner()
                        .downcast_ref::<Problem>()
                        .map_or_else(|| "not a problem".to_owned(), |problem| problem.title().to_owned())),
                };

                if let Ok(mut slot) = read.lock() {
                    *slot = Some(outcome);
                }

                Ok(StatusCode::OK.into_response())
            })
        }
    }

    /// A second handle onto a recording downstream, for the service while the test keeps the first.
    fn handle<T: Clone>(downstream: &T) -> T {
        // The service takes its downstream by value and the test inspects it afterwards.
        downstream.clone()
    }

    #[tokio::test]
    async fn a_declared_length_under_the_limit_passes_through() {
        let downstream = Downstream::new();
        let service = PayloadLimitLayer::new(1024).layer(handle(&downstream));

        let request = Request::builder().header(CONTENT_LENGTH, "100").body(Body::empty()).unwrap();
        let response = service.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(downstream.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_declared_length_over_the_limit_is_refused() {
        let downstream = Downstream::new();
        let service = PayloadLimitLayer::new(1024).layer(handle(&downstream));

        let request = Request::builder().header(CONTENT_LENGTH, "2048").body(Body::empty()).unwrap();
        let response = service.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(downstream.calls.load(Ordering::SeqCst), 0, "an oversized request must not reach the broker");
    }

    #[tokio::test]
    async fn a_declared_length_exactly_at_the_limit_is_allowed() {
        // The limit is the largest acceptable body, not the first rejected one. Moving this by one
        // byte silently breaks every caller sitting on the boundary.
        let downstream = Downstream::new();
        let service = PayloadLimitLayer::new(1024).layer(handle(&downstream));

        let request = Request::builder().header(CONTENT_LENGTH, "1024").body(Body::from(vec![0_u8; 1024])).unwrap();
        let response = service.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(downstream.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_body_without_a_declared_length_over_the_limit_is_refused_with_413() {
        // A chunked body has no declared length, so it is read here: wrapped in `Limited` and forwarded,
        // the limit would fire only if something downstream read it, and a service that answers from
        // headers alone would return 200 without ever rejecting the oversized body.
        let downstream = Downstream::new();
        let service = PayloadLimitLayer::new(1024).layer(handle(&downstream));

        let request = Request::builder().body(Body::from(vec![0_u8; 2048])).unwrap();
        assert!(
            request.headers().get(CONTENT_LENGTH).is_none(),
            "the request must be undeclared for this test to mean anything"
        );

        let response = service.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(downstream.calls.load(Ordering::SeqCst), 0, "an oversized request must not reach the broker");
    }

    #[tokio::test]
    async fn a_body_without_a_declared_length_under_the_limit_arrives_intact() {
        let downstream = ReadingDownstream::new();
        let service = PayloadLimitLayer::new(1024).layer(handle(&downstream));

        let request = Request::builder().body(Body::from(vec![7_u8; 512])).unwrap();
        let response = service.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            downstream.read.lock().unwrap().as_ref(),
            Some(&Ok(Bytes::from(vec![7_u8; 512]))),
            "reading the body to size it must not consume it"
        );
    }

    #[tokio::test]
    async fn a_body_that_outgrows_its_declared_length_fails_as_a_payload_problem() {
        // The fast path trusted `Content-Length`, so `Limited` is the only thing still counting.
        // Its own error is anonymous; relabelled, a reader can tell the client oversized the body
        // rather than reporting a proxy fault.
        let downstream = ReadingDownstream::new();
        let service = PayloadLimitLayer::new(1024).layer(handle(&downstream));

        let request = Request::builder().header(CONTENT_LENGTH, "10").body(Body::from(vec![0_u8; 4096])).unwrap();
        let response = service.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK, "the lie is only discovered once the body is read");
        assert_eq!(downstream.read.lock().unwrap().as_ref(), Some(&Err("Payload Too Large".to_owned())));
    }

    #[tokio::test]
    async fn an_unparseable_content_length_falls_back_to_counting_the_bytes() {
        // A header that is not a number says nothing, so the body is read rather than trusted.
        let downstream = Downstream::new();
        let service = PayloadLimitLayer::new(1024).layer(handle(&downstream));

        let request = Request::builder()
            .header(CONTENT_LENGTH, "not-a-number")
            .body(Body::from(vec![0_u8; 2048]))
            .unwrap();
        let response = service.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(downstream.calls.load(Ordering::SeqCst), 0);
    }
}
