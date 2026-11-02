//! Refuses a request that arrives while the deployment's ceiling of in-flight requests is held.
//!
//! Every request that is being processed pins memory (a buffered body, a parsed context, a parsed
//! response) and, once it is being forwarded, a connection to the broker. A ceiling bounds the sum
//! of those pins, so a flood turns into 503 answers instead of memory exhaustion.
//!
//! A semaphore with `try_acquire` rather than tower's `ConcurrencyLimit` with `LoadShed`:
//! `LoadShed` sheds whenever the inner service is not ready, which includes waiting on a slow
//! broker, so broker slowness would shed healthy traffic; `ConcurrencyLimit` alone queues instead
//! of refusing, and a queued flood is the memory this layer exists to refuse. The slot is
//! acquired in `call` and moved into the future, so it is released when the future completes:
//! on success, on an error response, and when the inner service itself fails.

use axum::{
    extract::Request,
    response::{IntoResponse, Response},
};
use libra_problem_details::problem::Problem;
use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::sync::Semaphore;
use tower::{Layer, Service, ServiceExt};

/// Layer that refuses requests over the in-flight ceiling with a 503.
#[derive(Clone, Debug)]
pub struct InFlightLimitLayer {
    ceiling: Arc<Semaphore>,
}

impl InFlightLimitLayer {
    /// Creates the layer holding at most `max_in_flight_requests` slots.
    #[must_use]
    pub fn new(max_in_flight_requests: usize) -> Self {
        Self {
            ceiling: Arc::new(Semaphore::new(max_in_flight_requests)),
        }
    }
}

impl<S> Layer<S> for InFlightLimitLayer {
    type Service = InFlightLimitService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        InFlightLimitService {
            inner,
            ceiling: Arc::clone(&self.ceiling),
        }
    }
}

/// The service produced by [`InFlightLimitLayer`].
#[derive(Clone, Debug)]
pub struct InFlightLimitService<S> {
    inner: S,
    ceiling: Arc<Semaphore>,
}

impl<S> Service<Request> for InFlightLimitService<S>
where
    S: Service<Request, Response = Response> + Clone + Send + 'static,
    S::Error: Send + 'static,
    S::Future: Send + 'static,
{
    type Response = Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Response, S::Error>> + Send>>;

    /// The inner service's readiness. The ceiling is not consulted here: [`Self::call`] answers 503
    /// when no slot is free, so readiness never waits on one.
    fn poll_ready(&mut self, context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(context)
    }

    fn call(&mut self, request: Request) -> Self::Future {
        let Ok(slot) = self.ceiling.clone().try_acquire_owned() else {
            return Box::pin(async { Ok(Problem::ServiceUnavailable("the request ceiling is reached".to_owned()).into_response()) });
        };

        // Cloned because the future is `'static`. The slot moves in with it and drops when it
        // completes, which releases the slot whatever the outcome is.
        let inner = self.inner.clone();
        Box::pin(async move {
            let answer = inner.oneshot(request).await;
            drop(slot);
            answer
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{Body, Bytes},
        http::StatusCode,
    };
    use http_body_util::BodyExt;
    use pretty_assertions::assert_eq;
    use std::{convert::Infallible, sync::Mutex, time::Duration};
    use tokio::{sync::Notify, time::timeout};
    use tower::ServiceExt;

    /// A service that parks every request until `gate` fires, then answers 200.
    #[derive(Clone)]
    struct Parking {
        held: Arc<Notify>,
        gate: Arc<Notify>,
    }

    impl Parking {
        /// The service and a second handle onto its gate, for the test to keep.
        fn new() -> (Self, Arc<Notify>) {
            let gate = Arc::new(Notify::new());
            (
                Self {
                    held: Arc::new(Notify::new()),
                    gate: Arc::clone(&gate),
                },
                gate,
            )
        }
    }

    impl Service<Request> for Parking {
        type Response = Response;
        type Error = Infallible;
        type Future = Pin<Box<dyn Future<Output = Result<Response, Infallible>> + Send>>;

        fn poll_ready(&mut self, _context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _request: Request) -> Self::Future {
            let held = Arc::clone(&self.held);
            let gate = Arc::clone(&self.gate);

            Box::pin(async move {
                held.notify_one();
                gate.notified().await;

                Ok(StatusCode::OK.into_response())
            })
        }
    }

    /// A service that answers every request with a non-success status.
    #[derive(Clone)]
    struct Refusing;

    impl Service<Request> for Refusing {
        type Response = Response;
        type Error = Infallible;
        type Future = Pin<Box<dyn Future<Output = Result<Response, Infallible>> + Send>>;

        fn poll_ready(&mut self, _context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _request: Request) -> Self::Future {
            Box::pin(async { Ok(StatusCode::FORBIDDEN.into_response()) })
        }
    }

    /// A service that fails every request.
    #[derive(Clone, Default)]
    struct Failing;

    impl Service<Request> for Failing {
        type Response = Response;
        type Error = Failure;
        type Future = Pin<Box<dyn Future<Output = Result<Response, Failure>> + Send>>;

        fn poll_ready(&mut self, _context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _request: Request) -> Self::Future {
            Box::pin(async { Err(Failure) })
        }
    }

    /// A failure type that is not `Infallible`, so the release test cannot pass by accident.
    #[derive(Debug, thiserror::Error)]
    #[error("the inner service failed")]
    struct Failure;

    /// A service that records the body it was handed.
    #[derive(Clone)]
    struct Reading {
        body: Arc<Mutex<Option<Bytes>>>,
    }

    impl Reading {
        fn new() -> Self {
            Self {
                body: Arc::new(Mutex::new(None)),
            }
        }
    }

    impl Service<Request> for Reading {
        type Response = Response;
        type Error = Infallible;
        type Future = Pin<Box<dyn Future<Output = Result<Response, Infallible>> + Send>>;

        fn poll_ready(&mut self, _context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, request: Request) -> Self::Future {
            let body = Arc::clone(&self.body);

            Box::pin(async move {
                let collected = request.into_body().collect().await.expect("the body").to_bytes();
                *body.lock().unwrap() = Some(collected);

                Ok(StatusCode::OK.into_response())
            })
        }
    }

    fn request() -> Request {
        Request::builder().body(Body::empty()).expect("a valid request")
    }

    #[tokio::test]
    async fn a_request_under_the_ceiling_is_forwarded() {
        let (inner, gate) = Parking::new();
        let held = Arc::clone(&inner.held);
        let service = InFlightLimitLayer::new(1).layer(inner);

        let first = tokio::spawn({
            let service = service.clone();
            async move { service.oneshot(request()).await }
        });
        timeout(Duration::from_secs(5), held.notified())
            .await
            .expect("the request reaches the inner service");

        gate.notify_one();
        let answer = timeout(Duration::from_secs(5), first)
            .await
            .expect("the request finishes")
            .expect("the inner service never fails")
            .expect("the request succeeds");

        assert_eq!(answer.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn a_request_when_the_ceiling_is_held_is_refused_with_503() {
        let (inner, gate) = Parking::new();
        let held = Arc::clone(&inner.held);
        let service = InFlightLimitLayer::new(1).layer(inner);

        let first = tokio::spawn({
            let service = service.clone();
            async move { service.oneshot(request()).await }
        });
        timeout(Duration::from_secs(5), held.notified())
            .await
            .expect("the first request reaches the inner service");

        let second = service.clone().oneshot(request()).await.expect("a refusal is an answer, not a failure");

        assert_eq!(second.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            second.headers().get("content-type").unwrap(),
            "application/problem+json",
            "the refusal must be a problem-details response"
        );

        gate.notify_one();
        let answer = timeout(Duration::from_secs(5), first)
            .await
            .expect("the first request finishes")
            .expect("the inner service never fails")
            .expect("the first request succeeds");
        assert_eq!(answer.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn the_slot_is_released_when_the_answer_is_an_error_status() {
        let service = InFlightLimitLayer::new(1).layer(Refusing);

        let first = service.clone().oneshot(request()).await.expect("the answer arrives");
        assert_eq!(first.status(), StatusCode::FORBIDDEN);

        let second = service.oneshot(request()).await.expect("the second request is admitted");
        assert_eq!(second.status(), StatusCode::FORBIDDEN, "the slot must have been released");
    }

    #[tokio::test]
    async fn the_slot_is_released_when_the_inner_service_fails() {
        let service = InFlightLimitLayer::new(1).layer(Failing);

        assert!(service.clone().oneshot(request()).await.is_err());

        let second = service.oneshot(request()).await;
        assert!(second.is_err(), "an admitted request proves the failed one released its slot");
    }

    #[tokio::test]
    async fn a_body_with_a_declared_length_is_forwarded_unread_and_intact() {
        let reading = Reading::new();
        let handle = Arc::clone(&reading.body);
        let service = InFlightLimitLayer::new(4).layer(reading);

        let response = service
            .oneshot(
                Request::builder()
                    .header("content-length", "8")
                    .body(Body::from(b"payload!".to_vec()))
                    .expect("a valid request"),
            )
            .await
            .expect("the answer arrives");

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            handle.lock().unwrap().as_deref(),
            Some(&b"payload!"[..]),
            "the ceiling must not cost the body anything"
        );
    }

    #[tokio::test]
    async fn a_refusal_is_rendered_as_a_problem_details_response() {
        let (inner, gate) = Parking::new();
        let held = Arc::clone(&inner.held);
        let service = InFlightLimitLayer::new(1).layer(inner);

        let first = tokio::spawn({
            let service = service.clone();
            async move { service.oneshot(request()).await }
        });
        timeout(Duration::from_secs(5), held.notified())
            .await
            .expect("the first request reaches the inner service");

        let refused = service.clone().oneshot(request()).await.expect("a refusal is an answer");
        let body = refused.into_body().collect().await.expect("the body").to_bytes();
        let text = String::from_utf8(body.to_vec()).expect("problem details are UTF-8");

        // The renderer keeps detail text generic for a 503, so the body names the type and the
        // status rather than the reason.
        assert!(text.contains("\"status\":503"), "{text}");
        assert!(text.contains("ServiceUnavailable"), "{text}");

        gate.notify_one();
        let _ = timeout(Duration::from_secs(5), first).await;
    }
}
