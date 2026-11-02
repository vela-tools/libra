//! Refuses a request that asks another hop to change its method.
//!
//! Libra classifies a request by its method: a `GET` is a read and a `POST` a write, and a policy
//! that allows reads allows the first. `X-HTTP-Method-Override`, `X-HTTP-Method` and
//! `X-Method-Override` ask a server that honours them to run the request as another method, so a
//! request Libra judged as a read could run as a `DELETE` behind it. NGSI-LD defines none of them;
//! a request carrying one is refused rather than judged under the method nobody will run.

use axum::{
    extract::Request,
    http::HeaderName,
    response::{IntoResponse, Response},
};
use libra_problem_details::problem::Problem;
use std::{
    convert::Infallible,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
use tower::{Layer, Service, ServiceExt};

/// The headers that ask a server to run a request as another method.
pub const METHOD_OVERRIDE_HEADERS: [HeaderName; 3] = [
    HeaderName::from_static("x-http-method-override"),
    HeaderName::from_static("x-http-method"),
    HeaderName::from_static("x-method-override"),
];

/// Layer that refuses every request carrying a [`METHOD_OVERRIDE_HEADERS`] entry.
#[derive(Clone, Copy, Default, Debug)]
pub struct MethodOverrideRefusalLayer;

impl MethodOverrideRefusalLayer {
    /// Creates the layer.
    #[must_use]
    pub const fn new() -> MethodOverrideRefusalLayer {
        MethodOverrideRefusalLayer
    }
}

impl<S> Layer<S> for MethodOverrideRefusalLayer {
    type Service = MethodOverrideRefusalService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        MethodOverrideRefusalService { inner }
    }
}

/// The service produced by [`MethodOverrideRefusalLayer`].
#[derive(Clone, Debug)]
pub struct MethodOverrideRefusalService<S> {
    inner: S,
}

impl<S> Service<Request> for MethodOverrideRefusalService<S>
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
        if METHOD_OVERRIDE_HEADERS.iter().any(|name| request.headers().contains_key(name)) {
            return Box::pin(async { Ok(Problem::BadRequest("a request may not ask to be run as another method".to_owned()).into_response()) });
        }

        // The future outlives `&mut self`, so it takes its own handle on the inner service.
        let inner = self.inner.clone();

        Box::pin(async move { inner.oneshot(request).await })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::StatusCode};
    use pretty_assertions::assert_eq;

    async fn status(header: Option<&'static str>) -> StatusCode {
        let inner = tower::service_fn(|_request: Request| async { Ok::<_, Infallible>(Response::new(Body::empty())) });
        let mut builder = Request::builder().uri("/ngsi-ld/v1/entities");
        if let Some(name) = header {
            builder = builder.header(name, "DELETE");
        }

        MethodOverrideRefusalLayer::new()
            .layer(inner)
            .oneshot(builder.body(Body::empty()).unwrap())
            .await
            .unwrap_or_else(|never| match never {})
            .status()
    }

    #[tokio::test]
    async fn every_method_override_header_is_refused() {
        for name in ["X-HTTP-Method-Override", "X-HTTP-Method", "X-Method-Override"] {
            assert_eq!(status(Some(name)).await, StatusCode::BAD_REQUEST, "{name}");
        }
    }

    #[tokio::test]
    async fn a_request_without_one_is_forwarded() {
        assert_eq!(status(None).await, StatusCode::OK);
    }
}
