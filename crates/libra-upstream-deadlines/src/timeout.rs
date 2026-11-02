//! Bounds how long the upstream broker may take.
//!
//! The bound covers the whole answer: the response future, and then the body that follows it (see
//! [`response_deadline`]).
//!
//! `tower` already implements the timeout; the only thing added here is a name for what happened.
//! Its [`Elapsed`] error is not part of Libra's taxonomy, so on its own it reaches the outermost
//! handler as an unrecognised boxed error and is reported as an opaque 500, a proxy fault, for
//! something that is squarely the broker's. Relabelled as [`Problem::GatewayTimeout`] it becomes
//! the 504 the caller can actually act on.

use crate::response_deadline;
use axum::{extract::Request, response::Response};
use libra_problem_details::problem::Problem;
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::Instant;
use tower::{
    BoxError,
    Layer,
    Service,
    ServiceExt,
    timeout::{Timeout, TimeoutLayer, error::Elapsed},
};
use tracing::warn;

/// Layer that fails a request the upstream did not answer in time.
#[derive(Clone, Copy, Debug)]
pub struct UpstreamTimeoutLayer {
    timeout: Duration,
}

impl UpstreamTimeoutLayer {
    /// Creates the layer with the maximum time the upstream may take.
    #[must_use]
    pub const fn new(timeout: Duration) -> Self {
        Self { timeout }
    }
}

impl<S> Layer<S> for UpstreamTimeoutLayer {
    type Service = UpstreamTimeoutService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        UpstreamTimeoutService {
            inner: TimeoutLayer::new(self.timeout).layer(inner),
            timeout: self.timeout,
        }
    }
}

/// The service produced by [`UpstreamTimeoutLayer`].
#[derive(Clone, Debug)]
pub struct UpstreamTimeoutService<S> {
    inner: Timeout<S>,
    timeout: Duration,
}

impl<S> Service<Request> for UpstreamTimeoutService<S>
where
    S: Service<Request, Response = Response> + Clone + Send + 'static,
    S::Error: Into<BoxError>,
    S::Future: Send + 'static,
{
    type Response = Response;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<Response, BoxError>> + Send>>;

    /// Always ready. Readiness of the inner service is driven by `oneshot` in [`Self::call`], on
    /// the clone that actually serves the request.
    fn poll_ready(&mut self, _context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request) -> Self::Future {
        let inner = self.inner.clone();
        let timeout = self.timeout;
        let deadline = Instant::now() + timeout;

        Box::pin(async move {
            let response = inner.oneshot(request).await.map_err(|error| {
                if error.is::<Elapsed>() {
                    warn!(timeout = ?timeout, "the upstream did not answer in time");
                    return Box::new(Problem::GatewayTimeout(format!(
                        "Upstream did not respond within {} seconds",
                        timeout.as_secs()
                    ))) as BoxError;
                }

                error
            })?;

            Ok(response.map(|body| response_deadline::bound(body, deadline)))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stalled_body::OneChunkThenSilence;
    use axum::{body::Body, http::StatusCode, response::IntoResponse};
    use http_body_util::BodyExt;
    use pretty_assertions::assert_eq;
    use tokio::time::sleep;

    fn request() -> Request {
        Request::builder().uri("/ngsi-ld/v1/entities").body(Body::empty()).unwrap()
    }

    /// Answers after the given delay.
    #[derive(Clone)]
    struct Slow {
        delay: Duration,
    }

    impl Service<Request> for Slow {
        type Response = Response;
        type Error = BoxError;
        type Future = Pin<Box<dyn Future<Output = Result<Response, BoxError>> + Send>>;

        fn poll_ready(&mut self, _context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _request: Request) -> Self::Future {
            let delay = self.delay;

            Box::pin(async move {
                sleep(delay).await;

                Ok(StatusCode::OK.into_response())
            })
        }
    }

    /// Fails immediately with something that is not a timeout.
    #[derive(Clone)]
    struct Refusing;

    impl Service<Request> for Refusing {
        type Response = Response;
        type Error = BoxError;
        type Future = Pin<Box<dyn Future<Output = Result<Response, BoxError>> + Send>>;

        fn poll_ready(&mut self, _context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _request: Request) -> Self::Future {
            Box::pin(async { Err(Box::new(Problem::Forbidden("no".to_owned())) as BoxError) })
        }
    }

    #[tokio::test(start_paused = true)]
    async fn an_upstream_that_answers_in_time_is_left_alone() {
        let service = UpstreamTimeoutLayer::new(Duration::from_secs(30)).layer(Slow { delay: Duration::from_secs(1) });

        let response = service.oneshot(request()).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test(start_paused = true)]
    async fn an_upstream_that_runs_over_becomes_a_gateway_timeout() {
        let service = UpstreamTimeoutLayer::new(Duration::from_secs(5)).layer(Slow {
            delay: Duration::from_secs(600),
        });

        let error = service.oneshot(request()).await.expect_err("the request should have timed out");

        assert!(!error.is::<Elapsed>(), "an anonymous Elapsed reaches the outermost handler as an opaque 500");
        assert_eq!(error.downcast_ref::<Problem>().map(Problem::status), Some(StatusCode::GATEWAY_TIMEOUT));
    }

    /// Answers at once with a body that never finishes.
    #[derive(Clone)]
    struct Trickling;

    impl Service<Request> for Trickling {
        type Response = Response;
        type Error = BoxError;
        type Future = Pin<Box<dyn Future<Output = Result<Response, BoxError>> + Send>>;

        fn poll_ready(&mut self, _context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _request: Request) -> Self::Future {
            Box::pin(async { Ok(Response::new(Body::new(OneChunkThenSilence::default()))) })
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_body_the_upstream_never_finishes_is_cut_off_at_the_same_deadline() {
        let service = UpstreamTimeoutLayer::new(Duration::from_secs(5)).layer(Trickling);

        let response = service.oneshot(request()).await.expect("the headers arrive in time");

        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.into_body().collect().await.is_err(), "the body must not be waited on forever");
    }

    #[tokio::test(start_paused = true)]
    async fn an_error_that_is_not_a_timeout_keeps_its_own_identity() {
        let service = UpstreamTimeoutLayer::new(Duration::from_secs(30)).layer(Refusing);

        let error = service.oneshot(request()).await.expect_err("the inner service refuses every request");

        assert_eq!(error.downcast_ref::<Problem>().map(Problem::status), Some(StatusCode::FORBIDDEN));
    }
}
