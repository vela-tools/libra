//! Strips the identity headers Libra injects, so that no caller can forge one.
//!
//! Libra tells the broker who the caller is by injecting `X-Auth-*` headers, and the broker trusts
//! them because it trusts the proxy sitting in front of it. That trust only holds while a header
//! the caller sent cannot be mistaken for one Libra injected. This layer is what makes that true:
//! every propagated name is removed from every inbound request, unconditionally, before any other
//! layer reads the headers.
//!
//! The strip list and the inject list are one list, [`PROPAGATED_HEADERS`]. With two lists, a header
//! the injector emits and the stripper does not know about (such as `X-Auth-Tenant-State`) would let
//! an anonymous request (no `Authorization` header at all, therefore no claims and nothing injected)
//! carry a tenant state of the caller's choosing all the way to the broker.

use axum::{extract::Request, http::HeaderName, response::Response};
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
use tower::{Layer, Service, ServiceExt};
use tracing::debug;

/// How many headers [`PROPAGATED_HEADERS`] holds.
///
/// A constant of its own because `HeaderName` has a destructor, so the array's length cannot be
/// read in a constant context, and the injector sizes the list of values it writes by it.
pub const PROPAGATED_HEADER_COUNT: usize = 7;

/// Every header Libra injects downstream on a caller's behalf.
///
/// This constant is the single source of truth for both directions, and exporting it is the whole
/// point: the stripping layer in this crate removes exactly these names from every inbound
/// request, and the identity-propagation crate must inject only from this same list. A name that
/// exists in one direction and not the other is a spoofing hole, because whatever Libra injects
/// but does not strip is a header a client can simply send for itself.
///
/// `X-Auth-Tenants` is deliberately absent: nothing in Libra produces it, so stripping it would guard
/// a door that does not exist.
pub const PROPAGATED_HEADERS: [HeaderName; PROPAGATED_HEADER_COUNT] = [
    HeaderName::from_static("x-auth-subject"),
    HeaderName::from_static("x-auth-username"),
    HeaderName::from_static("x-auth-email"),
    HeaderName::from_static("x-auth-tenant-state"),
    HeaderName::from_static("x-auth-groups"),
    HeaderName::from_static("x-auth-roles"),
    HeaderName::from_static("x-auth-machine"),
];

/// Whether `name` is a propagated header once each underscore in it is read as a hyphen.
///
/// An HTTP name is case-insensitive and `HeaderName` has already folded the case, but `x_auth_subject`
/// is a different name from `x-auth-subject` to Libra and the same one to a broker behind a CGI-style
/// or servlet front end that normalises underscores to hyphens. Stripping only the hyphenated spelling
/// would let a caller's `X_Auth_Subject` reach such a broker as Libra's own word.
fn names_a_propagated_header(name: &HeaderName) -> bool {
    PROPAGATED_HEADERS.iter().any(|propagated| {
        name.as_str()
            .bytes()
            .map(|byte| if byte == b'_' { b'-' } else { byte })
            .eq(propagated.as_str().bytes())
    })
}

/// Layer that removes every [`PROPAGATED_HEADERS`] entry, and every underscore spelling of one, from
/// the inbound request.
#[derive(Clone, Copy, Default, Debug)]
pub struct IdentityHeaderStripLayer;

impl IdentityHeaderStripLayer {
    /// Creates the layer.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl<S> Layer<S> for IdentityHeaderStripLayer {
    type Service = IdentityHeaderStripService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        IdentityHeaderStripService { inner }
    }
}

/// The service produced by [`IdentityHeaderStripLayer`].
#[derive(Clone, Debug)]
pub struct IdentityHeaderStripService<S> {
    inner: S,
}

impl<S> Service<Request> for IdentityHeaderStripService<S>
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

    fn call(&mut self, mut request: Request) -> Self::Future {
        let inner = self.inner.clone();

        // Unconditional, for every request and every method. Making the strip conditional on the
        // request looking authenticated is what creates the anonymous-request hole: a request with
        // no credentials is exactly the one whose forged headers nothing else would overwrite.
        // The names are collected first because the map cannot be edited while its keys are borrowed;
        // a `HeaderName` clone is a reference-count bump or a static pointer, not an allocation.
        let forged: Vec<HeaderName> = request.headers().keys().filter(|name| names_a_propagated_header(name)).cloned().collect();
        for name in &forged {
            request.headers_mut().remove(name);
        }

        if !forged.is_empty() {
            debug!(count = forged.len(), "stripped inbound identity headers a client had no business sending");
        }

        Box::pin(async move { inner.oneshot(request).await })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{HeaderMap, StatusCode, header::AUTHORIZATION},
        response::IntoResponse,
    };
    use pretty_assertions::assert_eq;
    use std::{
        convert::Infallible,
        sync::{Arc, Mutex},
    };

    /// Records the headers that reached it, so a test can assert on what the broker would see.
    #[derive(Clone)]
    struct Downstream {
        seen: Arc<Mutex<HeaderMap>>,
    }

    impl Downstream {
        fn new() -> Self {
            Self {
                seen: Arc::new(Mutex::new(HeaderMap::new())),
            }
        }

        fn header(&self, name: &str) -> Option<String> {
            let seen = self.seen.lock().expect("downstream headers");
            seen.get(name).and_then(|value| value.to_str().ok()).map(str::to_owned)
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
            let (parts, _body) = request.into_parts();
            let headers = parts.headers;
            let seen = Arc::clone(&self.seen);

            Box::pin(async move {
                if let Ok(mut slot) = seen.lock() {
                    *slot = headers;
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
    async fn every_propagated_header_is_stripped_from_an_inbound_request() {
        let downstream = Downstream::new();
        let service = IdentityHeaderStripLayer::new().layer(handle(&downstream));

        let mut builder = Request::builder().uri("/ngsi-ld/v1/entities");
        for header in PROPAGATED_HEADERS {
            builder = builder.header(header, "forged");
        }
        let response = service.oneshot(builder.body(Body::empty()).unwrap()).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        for header in PROPAGATED_HEADERS {
            assert_eq!(downstream.header(header.as_str()), None, "{header} reached the broker as the client sent it");
        }
    }

    #[tokio::test]
    async fn an_underscore_spelling_of_a_propagated_header_is_stripped() {
        let downstream = Downstream::new();
        let service = IdentityHeaderStripLayer::new().layer(handle(&downstream));

        let spellings = [
            "X_Auth_Subject",
            "x_auth_username",
            "X-Auth_Email",
            "X_AUTH_TENANT_STATE",
            "x_auth-groups",
            "X_Auth_Roles",
            "x_auth_machine",
        ];
        let mut builder = Request::builder().uri("/ngsi-ld/v1/entities");
        for spelling in spellings {
            builder = builder.header(spelling, "forged");
        }
        let response = service.oneshot(builder.body(Body::empty()).unwrap()).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        for spelling in spellings {
            assert_eq!(downstream.header(spelling), None, "{spelling} reached the broker as the client sent it");
        }
    }

    #[tokio::test]
    async fn a_repeated_propagated_header_is_stripped_in_every_occurrence() {
        let downstream = Downstream::new();
        let service = IdentityHeaderStripLayer::new().layer(handle(&downstream));

        let request = Request::builder()
            .uri("/ngsi-ld/v1/entities")
            .header("X-Auth-Subject", "first")
            .header("X-Auth-Subject", "second")
            .header("X_Auth_Subject", "third")
            .body(Body::empty())
            .unwrap();
        service.oneshot(request).await.unwrap();

        assert_eq!(downstream.header("x-auth-subject"), None);
        assert_eq!(downstream.header("x_auth_subject"), None);
    }

    #[tokio::test]
    async fn a_header_that_only_resembles_a_propagated_one_survives_stripping() {
        let downstream = Downstream::new();
        let service = IdentityHeaderStripLayer::new().layer(handle(&downstream));

        let request = Request::builder()
            .uri("/ngsi-ld/v1/entities")
            .header("X-Auth-Subjects", "keep-me")
            .header("X_Auth_Other", "keep-me-too")
            .body(Body::empty())
            .unwrap();
        service.oneshot(request).await.unwrap();

        assert_eq!(downstream.header("x-auth-subjects"), Some("keep-me".to_owned()));
        assert_eq!(downstream.header("x_auth_other"), Some("keep-me-too".to_owned()));
    }

    #[tokio::test]
    async fn an_unrelated_header_survives_stripping() {
        let downstream = Downstream::new();
        let service = IdentityHeaderStripLayer::new().layer(handle(&downstream));

        let request = Request::builder()
            .uri("/ngsi-ld/v1/entities")
            .header("X-Custom-Header", "keep-me")
            .header(AUTHORIZATION, "Bearer token")
            .body(Body::empty())
            .unwrap();
        let response = service.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(downstream.header("X-Custom-Header"), Some("keep-me".to_owned()));
        assert_eq!(
            downstream.header("authorization"),
            Some("Bearer token".to_owned()),
            "stripping must not touch the caller's credentials"
        );
    }

    #[tokio::test]
    async fn a_forged_tenant_state_on_an_anonymous_request_is_stripped() {
        // `X-Auth-Tenant-State` is injected, so it is also stripped. On an anonymous request there are no
        // claims and the injector writes nothing, so a caller's own value would survive all the way to the
        // broker, which reads it as Libra's word.
        let downstream = Downstream::new();
        let service = IdentityHeaderStripLayer::new().layer(handle(&downstream));

        let request = Request::builder()
            .uri("/ngsi-ld/v1/entities")
            .header("X-Auth-Tenant-State", "explicit:production")
            .body(Body::empty())
            .unwrap();
        assert!(
            request.headers().get(AUTHORIZATION).is_none(),
            "the request must be anonymous for this test to mean anything"
        );

        let response = service.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(downstream.header("X-Auth-Tenant-State"), None, "a forged tenant state reached the broker");
    }

    #[test]
    fn the_propagated_list_holds_no_duplicates_and_no_stale_name() {
        // Two entries for one header, or a name nothing injects, both mean the two directions have drifted
        // apart.
        for (index, header) in PROPAGATED_HEADERS.iter().enumerate() {
            assert!(!PROPAGATED_HEADERS[index + 1..].contains(header), "{header} appears twice");
        }

        assert!(
            !PROPAGATED_HEADERS.contains(&HeaderName::from_static("x-auth-tenants")),
            "nothing injects X-Auth-Tenants"
        );
    }
}
