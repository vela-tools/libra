//! The Tower adapter that resolves a request's tenant.
//!
//! It runs before authentication, because the missing-tenant policy decides whether a request may
//! be anonymous at all, and it puts its answer in the request extensions so that nothing below it
//! reads the header again. That is the point: the layer that authorizes, the layer that builds a
//! cache key, and the layer that propagates identity would otherwise each read `NGSILD-Tenant` for
//! themselves, and a request with two of them would show each of them whichever one it happened to
//! pick.

use axum::{
    extract::Request,
    response::{IntoResponse, Response},
};
use libra_audit::slot::AuditSlot;
use libra_config::multitenancy::Multitenancy;
use libra_problem_details::{challenge::Challenge, problem::Problem};
use libra_tenant::{PublicAccess, PublicAccessAllowed, Resolution, Tenant, TenantError, resolve};
use std::{
    convert::Infallible,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tower::{Layer, Service, ServiceExt};
use tracing::debug;

/// Resolves the tenant of every request.
#[derive(Debug, Clone)]
pub struct TenantLayer {
    config: Arc<Multitenancy>,
}

impl TenantLayer {
    /// Builds the layer from the `[multitenancy]` configuration.
    #[must_use]
    pub fn new(config: Multitenancy) -> Self {
        Self { config: Arc::new(config) }
    }
}

impl<S> Layer<S> for TenantLayer {
    type Service = TenantService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        TenantService {
            inner,
            config: Arc::clone(&self.config),
        }
    }
}

/// The service produced by [`TenantLayer`].
#[derive(Debug, Clone)]
pub struct TenantService<S> {
    inner: S,
    config: Arc<Multitenancy>,
}

impl<S> Service<Request> for TenantService<S>
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

    fn call(&mut self, mut request: Request) -> Self::Future {
        let inner = self.inner.clone();
        let config = Arc::clone(&self.config);

        Box::pin(async move {
            let resolution = match resolve(request.headers(), &config) {
                Ok(resolution) => resolution,
                Err(error) => return Ok(problem_for(&error).into_response()),
            };

            debug!(tenant = %resolution.tenant.as_selector(), public_access = %resolution.public_access, "resolved the tenant");

            let Resolution { tenant, public_access } = resolution;
            if let (Some(audit), Tenant::Named(named)) = (request.extensions().get::<AuditSlot>(), &tenant) {
                audit.record_tenant(named.clone()); // the request keeps its own `Tenant`; the slot outlives it
            }
            request.extensions_mut().insert(tenant);
            if public_access == PublicAccess::Allowed {
                request.extensions_mut().insert(PublicAccessAllowed);
            }

            inner.oneshot(request).await
        })
    }
}

/// The response a caller sees when the tenant cannot be resolved.
fn problem_for(error: &TenantError) -> Problem {
    match error {
        // The header is there and Libra will not carry it. That is the caller's request to fix.
        TenantError::Repeated | TenantError::NotText | TenantError::Unusable { .. } => Problem::InvalidTenantHeader(error.to_string()),
        // The deployment requires a tenant and the caller did not name one.
        TenantError::Required => Problem::Unauthorized {
            challenge: Challenge::Bearer,
            detail: error.to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::StatusCode};
    use libra_config::multitenancy::MissingTenantHeaderPolicy;
    use pretty_assertions::assert_eq;
    use tower::util::BoxCloneService;

    /// Reports what reached the inner service.
    fn inner() -> BoxCloneService<Request, Response, Infallible> {
        BoxCloneService::new(tower::service_fn(|request: Request| async move {
            let tenant = request
                .extensions()
                .get::<Tenant>()
                .map_or_else(|| "(none)".to_owned(), |tenant| tenant.as_selector().to_string());
            let public = request.extensions().get::<PublicAccessAllowed>().is_some();

            Ok(Response::builder()
                .status(StatusCode::OK)
                .body(Body::from(format!("{tenant}|{public}")))
                .unwrap_or_else(|_| Response::new(Body::empty())))
        }))
    }

    #[tokio::test]
    async fn a_named_tenant_is_audited_and_an_untenanted_request_names_none() {
        let named = audited_tenant(&["acme"]).await;
        let untenanted = audited_tenant(&[]).await;

        assert_eq!(named.as_deref(), Some("acme"));
        assert_eq!(untenanted, None);
    }

    /// The tenant the audit slot learned for a request carrying these `NGSILD-Tenant` headers.
    async fn audited_tenant(headers: &[&str]) -> Option<String> {
        let mut builder = Request::builder().uri("/ngsi-ld/v1/entities");
        for value in headers {
            builder = builder.header("NGSILD-Tenant", *value);
        }
        let mut request = builder.body(Body::empty()).unwrap_or_else(|_| Request::new(Body::empty()));
        let slot = AuditSlot::default();
        // The slot is shared storage: the request carries one handle, the test reads the other.
        request.extensions_mut().insert(slot.clone());

        let mut service = TenantLayer::new(Multitenancy::default()).layer(inner());
        let _response = service.call(request).await.unwrap_or_else(|error| match error {});

        slot.contributions().tenant.map(String::from)
    }

    async fn run(headers: &[&str], policy: MissingTenantHeaderPolicy) -> (StatusCode, String) {
        use http_body_util::BodyExt;

        let mut builder = Request::builder().uri("/ngsi-ld/v1/entities");
        for value in headers {
            builder = builder.header("NGSILD-Tenant", *value);
        }
        let request = builder.body(Body::empty()).unwrap_or_else(|_| Request::new(Body::empty()));

        let mut service = TenantLayer::new(Multitenancy { policy }).layer(inner());
        let response = service.call(request).await.unwrap_or_else(|error| match error {});
        let status = response.status();
        let bytes = response
            .into_body()
            .collect()
            .await
            .map(http_body_util::Collected::to_bytes)
            .unwrap_or_default();

        (status, String::from_utf8_lossy(&bytes).into_owned())
    }

    #[tokio::test]
    async fn a_named_tenant_reaches_everything_downstream() {
        let (status, seen) = run(&["acme"], MissingTenantHeaderPolicy::AllowPublic).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(seen, "acme|false", "naming a tenant always requires authentication");
    }

    #[tokio::test]
    async fn a_request_with_no_tenant_is_marked_public_only_where_the_deployment_allows_it() {
        assert_eq!(run(&[], MissingTenantHeaderPolicy::AllowPublic).await.1, "*untenanted|true");
        assert_eq!(run(&[], MissingTenantHeaderPolicy::Authenticate).await.1, "*untenanted|false");
        assert_eq!(run(&[], MissingTenantHeaderPolicy::RequireHeader).await.0, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn a_repeated_tenant_header_is_refused() {
        // Libra forwards the request unchanged, so a broker reading the other copy would serve a
        // tenant this proxy never authorized.
        let (status, _) = run(&["acme", "other"], MissingTenantHeaderPolicy::AllowPublic).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn an_empty_tenant_header_is_refused_rather_than_read_as_no_tenant() {
        let (status, _) = run(&[""], MissingTenantHeaderPolicy::RequireHeader).await;

        assert_eq!(status, StatusCode::BAD_REQUEST, "an empty value is not an absent header");
    }
}
