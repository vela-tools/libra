//! The outermost layer: turns any error escaping the stack into a response.
//!
//! Nothing below this may return an error to the client without passing through here, which is
//! what makes the error taxonomy exhaustive in practice rather than only on paper.

use crate::problem::Problem;
use axum::{extract::Request, response::Response};
use std::{
    convert::Infallible,
    error::Error as StdError,
    future::Future,
    io::{Error as IoError, ErrorKind},
    pin::Pin,
    task::{Context, Poll},
};
use tower::{BoxError, Layer, Service, ServiceExt, timeout::error::Elapsed};

type BoxFuture = Pin<Box<dyn Future<Output = Result<Response, Infallible>> + Send>>;

/// Layer that converts inner-service errors into RFC 9457 responses.
#[derive(Clone, Copy, Default, Debug)]
pub struct ErrorHandlerLayer;

impl ErrorHandlerLayer {
    /// Creates the layer.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl<S> Layer<S> for ErrorHandlerLayer
where
    S: Service<Request, Response = Response> + Clone + Send + 'static,
    S::Error: Into<BoxError>,
    S::Future: Send + 'static,
{
    type Service = ErrorHandlerService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ErrorHandlerService { inner }
    }
}

/// The service produced by [`ErrorHandlerLayer`].
#[derive(Clone, Debug)]
pub struct ErrorHandlerService<S> {
    inner: S,
}

impl<S> Service<Request> for ErrorHandlerService<S>
where
    S: Service<Request, Response = Response> + Clone + Send + 'static,
    S::Error: Into<BoxError>,
    S::Future: Send + 'static,
{
    type Response = Response;
    /// This service never fails: every error becomes a response.
    type Error = Infallible;
    type Future = BoxFuture;

    /// Always ready. Readiness of the inner service is driven by `oneshot` in [`Self::call`], on
    /// the clone that actually serves the request.
    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request) -> Self::Future {
        // The inner service is cloned so it can be moved into the future. Calling `call` directly
        // on the clone would be wrong: `poll_ready` was driven on `self.inner`, not on the clone,
        // and a `Buffer` panics if it is called without having been polled ready. `oneshot` does
        // the ready-then-call sequence on the clone itself.
        let inner = self.inner.clone();

        Box::pin(async move {
            match inner.oneshot(request).await {
                Ok(response) => Ok(response),
                Err(error) => Ok(error_to_response(&error.into())),
            }
        })
    }
}

/// Maps a boxed error onto a response.
///
/// Errors arrive type-erased because that is how Tower propagates them across layers. Recovering
/// the concrete type is therefore a downcast, and everything that fails to downcast becomes a
/// deliberately vague 500: an error the taxonomy does not name must not leak its `Display` text to
/// a caller, since at this position that text can come from anywhere in the stack.
fn error_to_response(error: &BoxError) -> Response {
    if let Some(problem) = error.downcast_ref::<Problem>() {
        return problem.to_response();
    }

    if error.is::<Elapsed>() {
        return Problem::GatewayTimeout("Upstream request timed out".to_owned()).to_response();
    }

    // Transport failures arrive wrapped, so walk the source chain rather than inspecting only the
    // outermost error.
    let mut current: Option<&(dyn StdError + 'static)> = Some(error.as_ref());
    while let Some(source) = current {
        if let Some(io_error) = source.downcast_ref::<IoError>()
            && io_error.kind() == ErrorKind::ConnectionRefused
        {
            return Problem::BadGateway("Context broker unreachable (connection refused)".to_owned()).to_response();
        }

        if let Some(hyper_error) = source.downcast_ref::<hyper::Error>()
            && hyper_error.is_closed()
        {
            return Problem::BadGateway("Context broker unreachable (connection closed)".to_owned()).to_response();
        }

        current = source.source();
    }

    Problem::Internal(format!("unhandled error reached the error handler: {error:?}")).to_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::challenge::Challenge;
    use axum::{body::Body, http::StatusCode};
    use pretty_assertions::assert_eq;

    #[derive(Clone)]
    struct FailingService;

    impl Service<Request> for FailingService {
        type Response = Response;
        type Error = BoxError;
        type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _request: Request) -> Self::Future {
            Box::pin(async {
                Err(Box::new(Problem::Unauthorized {
                    challenge: Challenge::Bearer,
                    detail: "test".to_owned(),
                }) as BoxError)
            })
        }
    }

    #[tokio::test]
    async fn an_inner_error_becomes_a_response() {
        let service = ErrorHandlerLayer::new().layer(FailingService);
        let request = Request::builder().uri("/test").body(Body::empty()).unwrap();

        let response = service.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn a_boxed_problem_keeps_its_status() {
        let error: BoxError = Box::new(Problem::Forbidden("denied".to_owned()));

        assert_eq!(error_to_response(&error).status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn a_refused_connection_becomes_a_bad_gateway() {
        let error: BoxError = Box::new(IoError::new(ErrorKind::ConnectionRefused, "refused"));

        assert_eq!(error_to_response(&error).status(), StatusCode::BAD_GATEWAY);
    }

    #[test]
    fn an_unrecognised_error_becomes_an_opaque_500() {
        let error: BoxError = Box::new(IoError::other("something the taxonomy does not name"));

        assert_eq!(error_to_response(&error).status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
