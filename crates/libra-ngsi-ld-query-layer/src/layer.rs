//! The Tower layer that parses a request's query string once.
//!
//! Placement: directly below the operation layer, and above everything that reads the query.

use axum::{
    extract::Request,
    http::request::Parts,
    response::{IntoResponse, Response},
};
use libra_ngsi_ld_query::parameters::QueryParameters;
use libra_problem_details::problem::Problem;
use std::{
    convert::Infallible,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
use tower::{Layer, Service, ServiceExt};

/// Parses the query string and places the parameters in the request extensions.
#[derive(Debug, Clone, Copy, Default)]
pub struct QueryLayer;

impl QueryLayer {
    /// Builds the layer.
    #[must_use]
    pub const fn new() -> QueryLayer {
        QueryLayer
    }
}

impl<S> Layer<S> for QueryLayer {
    type Service = QueryService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        QueryService { inner }
    }
}

/// The service produced by [`QueryLayer`].
#[derive(Debug, Clone)]
pub struct QueryService<S> {
    inner: S,
}

impl<S> Service<Request> for QueryService<S>
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
        let parsed = read_query(&mut parts);

        Box::pin(async move {
            match parsed {
                Ok(()) => inner.oneshot(Request::from_parts(parts, body)).await,
                Err(problem) => Ok(problem.into_response()),
            }
        })
    }
}

/// Parses the request's query string and places the [`QueryParameters`] in its extensions.
///
/// # Errors
///
/// Returns [`Problem::BadRequest`] for a query that does not parse: a repeated parameter, a
/// parameter spelled in two cases, or one that does not decode. Its selectors cannot be told, and
/// the broker would refuse it too.
pub fn read_query(parts: &mut Parts) -> Result<(), Problem> {
    let parameters = QueryParameters::parse(parts.uri.query().unwrap_or_default()).map_err(|error| Problem::BadRequest(error.to_string()))?;

    parts.extensions.insert(parameters);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::StatusCode};
    use libra_ngsi_ld_query::parameter_name::ParameterName;
    use pretty_assertions::assert_eq;
    use std::sync::{Arc, Mutex, PoisonError};

    async fn serve(uri: &str) -> (StatusCode, Option<QueryParameters>) {
        let seen = Arc::new(Mutex::new(None));
        let recorded = Arc::clone(&seen);
        let inner = tower::service_fn(move |request: Request| {
            let recorded = Arc::clone(&recorded);
            async move {
                *recorded.lock().unwrap_or_else(PoisonError::into_inner) = request.extensions().get::<QueryParameters>().cloned();
                Ok::<_, Infallible>(Response::new(Body::empty()))
            }
        });

        let request = Request::builder().uri(uri).body(Body::empty()).unwrap();
        let response = QueryLayer::new().layer(inner).oneshot(request).await.unwrap_or_else(|never| match never {});
        let parameters = seen.lock().unwrap_or_else(PoisonError::into_inner).take();

        (response.status(), parameters)
    }

    #[tokio::test]
    async fn the_inner_service_reads_the_parsed_query() {
        let (status, parameters) = serve("/ngsi-ld/v1/entities?type=Vehicle&attrs=speed").await;

        assert_eq!(status, StatusCode::OK);
        let parameters = parameters.unwrap();
        assert_eq!(parameters.get(&ParameterName::TYPE), Some("Vehicle"));
        assert_eq!(parameters.get(&ParameterName::ATTRS), Some("speed"));
    }

    #[tokio::test]
    async fn a_request_without_a_query_carries_empty_parameters() {
        assert_eq!(serve("/ngsi-ld/v1/entities").await, (StatusCode::OK, Some(QueryParameters::default())));
    }

    #[tokio::test]
    async fn a_repeated_parameter_is_refused_and_not_forwarded() {
        assert_eq!(serve("/ngsi-ld/v1/entities?type=Vehicle&type=Building").await, (StatusCode::BAD_REQUEST, None));
    }
}
