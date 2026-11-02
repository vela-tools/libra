//! The Tower layer that classifies a request's operation once.
//!
//! Placement: below identity, so a caller who presented no acceptable credential learns nothing
//! about which paths exist, and above everything that reads the operation.

use axum::{
    extract::Request,
    http::request::Parts,
    response::{IntoResponse, Response},
};
use libra_ngsi_ld_operation::operation::Operation;
use libra_problem_details::problem::Problem;
use std::{
    convert::Infallible,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
use tower::{Layer, Service, ServiceExt};

/// Classifies the operation and places it in the request extensions.
#[derive(Debug, Clone, Copy, Default)]
pub struct OperationLayer;

impl OperationLayer {
    /// Builds the layer.
    #[must_use]
    pub const fn new() -> OperationLayer {
        OperationLayer
    }
}

impl<S> Layer<S> for OperationLayer {
    type Service = OperationService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        OperationService { inner }
    }
}

/// The service produced by [`OperationLayer`].
#[derive(Debug, Clone)]
pub struct OperationService<S> {
    inner: S,
}

impl<S> Service<Request> for OperationService<S>
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
        let classified = classify(&mut parts);

        Box::pin(async move {
            match classified {
                Ok(()) => inner.oneshot(Request::from_parts(parts, body)).await,
                Err(problem) => Ok(problem.into_response()),
            }
        })
    }
}

/// Classifies the request by its method and path and places the [`Operation`] in its extensions.
///
/// # Errors
///
/// Returns [`Problem::BadRequest`] for a method or path no hop can be trusted to read the same way,
/// and [`Problem::NotFound`] for a path outside the NGSI-LD API. Everything Libra does not route
/// explicitly falls through to the stack this layer sits in, so the second is the ordinary answer for
/// a path that does not exist rather than an internal invariant: a caller asking for `/admin` has not
/// broken anything.
pub fn classify(parts: &mut Parts) -> Result<(), Problem> {
    let classified = Operation::classify(&parts.method, parts.uri.path()).map_err(|error| Problem::BadRequest(error.to_string()))?;
    let operation = classified.ok_or_else(|| Problem::NotFound("no such resource".to_owned()))?;

    parts.extensions.insert(operation);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Method, StatusCode},
    };
    use libra_ngsi_ld_operation::{operation::Mode, resource::Resource};
    use pretty_assertions::assert_eq;
    use std::sync::{Arc, Mutex, PoisonError};

    async fn serve(method: Method, uri: &str) -> (StatusCode, Option<Operation>) {
        let seen = Arc::new(Mutex::new(None));
        let recorded = Arc::clone(&seen);
        let inner = tower::service_fn(move |request: Request| {
            let recorded = Arc::clone(&recorded);
            async move {
                *recorded.lock().unwrap_or_else(PoisonError::into_inner) = request.extensions().get::<Operation>().cloned();
                Ok::<_, Infallible>(Response::new(Body::empty()))
            }
        });

        let request = Request::builder().method(method).uri(uri).body(Body::empty()).unwrap();
        let response = OperationLayer::new().layer(inner).oneshot(request).await.unwrap_or_else(|never| match never {});
        let operation = seen.lock().unwrap_or_else(PoisonError::into_inner).take();

        (response.status(), operation)
    }

    #[tokio::test]
    async fn an_ngsi_ld_request_reaches_the_inner_service_with_its_operation() {
        let (status, operation) = serve(Method::GET, "/ngsi-ld/v1/entities?type=Vehicle").await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            operation,
            Some(Operation {
                resource: Resource::Entities,
                mode: Mode::Read,
            })
        );
    }

    #[tokio::test]
    async fn a_path_outside_the_api_is_not_found_and_not_forwarded() {
        assert_eq!(serve(Method::GET, "/admin").await, (StatusCode::NOT_FOUND, None));
    }

    #[tokio::test]
    async fn a_method_with_no_ngsi_ld_meaning_is_refused_and_not_forwarded() {
        assert_eq!(serve(Method::TRACE, "/ngsi-ld/v1/entities").await, (StatusCode::BAD_REQUEST, None));
    }

    #[tokio::test]
    async fn a_relative_segment_is_refused_and_not_forwarded() {
        assert_eq!(serve(Method::GET, "/ngsi-ld/v1/entities/%2e%2e/types").await, (StatusCode::BAD_REQUEST, None));
    }
}
