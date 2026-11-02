//! Security response headers, on or off.
//!
//! Libra proxies an API rather than a web page, so the browser-facing headers are cheap and mostly
//! irrelevant, but a broker is often browsed directly during development, and the ones that
//! matter there (`X-Content-Type-Options`, `X-Frame-Options`, a restrictive CSP) cost nothing to
//! send. `tower_helmet` already picks a sound default set, so this module adds no policy of its
//! own; it only decides whether the layer is installed at all.

use libra_config::helmet::Helmet;
use tower_helmet::HelmetLayer;

/// Builds the security-header layer, unless the deployment has turned it off.
///
/// Returns `None` when disabled, which composes with `ServiceBuilder::option_layer`.
#[must_use]
pub fn security_headers_layer(config: &Helmet) -> Option<HelmetLayer> {
    config.enabled.then(HelmetLayer::with_defaults)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        extract::Request,
        http::{StatusCode, header::X_CONTENT_TYPE_OPTIONS},
        response::{IntoResponse, Response},
    };
    use pretty_assertions::assert_eq;
    use std::{
        convert::Infallible,
        future::Future,
        pin::Pin,
        task::{Context, Poll},
    };
    use tower::{Layer, Service, ServiceExt};

    #[derive(Clone)]
    struct Downstream;

    impl Service<Request> for Downstream {
        type Response = Response;
        type Error = Infallible;
        type Future = Pin<Box<dyn Future<Output = Result<Response, Infallible>> + Send>>;

        fn poll_ready(&mut self, _context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _request: Request) -> Self::Future {
            Box::pin(async { Ok(StatusCode::OK.into_response()) })
        }
    }

    #[test]
    fn disabling_the_section_installs_no_layer() {
        let config = Helmet { enabled: false };

        assert!(security_headers_layer(&config).is_none());
    }

    #[tokio::test]
    async fn the_default_configuration_sends_the_headers() {
        let layer = security_headers_layer(&Helmet::default()).expect("helmet is on by default");
        let service = layer.layer(Downstream);

        let response = service.oneshot(Request::builder().body(Body::empty()).unwrap()).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(X_CONTENT_TYPE_OPTIONS).and_then(|value| value.to_str().ok()),
            Some("nosniff")
        );
    }
}
