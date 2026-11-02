//! Withholds what a context source registration carries for its source.
//!
//! The authorization layer decides, for every registration read, whether the caller could also have
//! written registrations, and records the answer as a [`RegistrationDisclosure`]. This layer reads
//! it and, for a caller who could not, removes `contextSourceInfo` (NGSI-LD clause 5.2.9) from every
//! registration of the answer, in listings and in retrievals alike. A registration read that reaches
//! this layer without that answer is refused: showing the registrations whole would be the
//! fail-open reading of a wiring fault.

use axum::{
    extract::Request,
    http::header::ACCEPT_ENCODING,
    response::{IntoResponse, Response},
};
use libra_ngsi_ld_operation_layer::classified::operation;
use libra_ngsi_ld_registration::source_info::withhold_source_info;
use libra_policy_engine::registration_disclosure::RegistrationDisclosure;
use libra_problem_details::problem::Problem;
use libra_response_json::{error::RewriteError, rewrite::rewrite};
use std::{
    convert::Infallible,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
use tower::{Layer, Service, ServiceExt};
use tracing::warn;

/// Applies the [`RegistrationDisclosure`] the authorization layer recorded.
#[derive(Debug, Clone, Copy)]
pub struct RegistrationDisclosureLayer {
    max_body_bytes: usize,
}

impl RegistrationDisclosureLayer {
    /// Builds the layer. `max_body_bytes` bounds how much of a registration answer is read to edit.
    #[must_use]
    pub const fn new(max_body_bytes: usize) -> RegistrationDisclosureLayer {
        RegistrationDisclosureLayer { max_body_bytes }
    }
}

impl<S> Layer<S> for RegistrationDisclosureLayer {
    type Service = RegistrationDisclosureService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RegistrationDisclosureService {
            inner,
            max_body_bytes: self.max_body_bytes,
        }
    }
}

/// The service produced by [`RegistrationDisclosureLayer`].
#[derive(Debug, Clone)]
pub struct RegistrationDisclosureService<S> {
    inner: S,
    max_body_bytes: usize,
}

/// What this layer does to one request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Plan {
    /// Not a registration read, or one the caller may see whole.
    Forward,
    /// A registration read whose answer loses `contextSourceInfo`.
    Withhold,
}

impl<S> Service<Request> for RegistrationDisclosureService<S>
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

    fn call(&mut self, mut request: Request) -> Self::Future {
        // The future outlives `&mut self`, so it takes its own handle on the inner service.
        let inner = self.inner.clone();
        let max_body_bytes = self.max_body_bytes;

        Box::pin(async move {
            let plan = match plan(&request) {
                Ok(plan) => plan,
                Err(problem) => return Ok(problem.into_response()),
            };
            if plan == Plan::Withhold {
                // The answer is edited, and a compressed body cannot be: asking for one would turn
                // every registration read of this caller into a 502.
                request.headers_mut().remove(ACCEPT_ENCODING);
            }

            let response = inner.oneshot(request).await?;

            Ok(match plan {
                Plan::Forward => response,
                Plan::Withhold => withhold(response, max_body_bytes).await,
            })
        })
    }
}

/// Decides from the request what happens to its answer.
fn plan(request: &Request) -> Result<Plan, Problem> {
    // A request that was not classified cannot be shown not to be a registration read, so it is
    // refused rather than forwarded with its answer whole.
    let operation = operation(request.extensions()).map_err(|error| Problem::Internal(error.to_string()))?;
    let registration_read = operation.is_read() && operation.resource.is_context_source_registration();

    match (registration_read, request.extensions().get::<RegistrationDisclosure>()) {
        (false, _) | (true, Some(RegistrationDisclosure::Whole)) => Ok(Plan::Forward),
        (true, Some(RegistrationDisclosure::WithoutSourceInfo)) => Ok(Plan::Withhold),
        (true, None) => Err(Problem::Internal(
            "a registration read reached the disclosure layer without an authorization decision".to_owned(),
        )),
    }
}

/// Removes `contextSourceInfo` from every registration the answer holds.
async fn withhold(response: Response, max_body_bytes: usize) -> Response {
    let edited = rewrite(response, max_body_bytes, |document, _media_type| {
        withhold_source_info(document);
        Ok::<(), Infallible>(())
    })
    .await;

    match edited {
        Ok(response) => response,
        Err(RewriteError::Unreadable(unreadable)) => {
            // An answer that cannot be edited cannot be shown without what it might carry.
            warn!(
                reason = unreadable.reason(),
                "a registration answer could not be read to withhold its source information"
            );

            Problem::BadGateway("the broker's registration answer could not be filtered".to_owned()).into_response()
        }
        Err(RewriteError::Edit(never)) => match never {},
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Method, StatusCode, header::CONTENT_TYPE},
    };
    use http_body_util::BodyExt;
    use libra_ngsi_ld_operation_layer::layer::classify;
    use pretty_assertions::assert_eq;

    const ANSWER: &str = r#"[{"id":"urn:r:1","endpoint":"http://source.test","contextSourceInfo":[{"key":"Authorization","value":"Bearer secret"}]}]"#;

    async fn run(method: Method, uri: &str, disclosure: Option<RegistrationDisclosure>) -> (StatusCode, String) {
        let broker = tower::service_fn(|_request: Request| async {
            Ok::<_, Infallible>(
                Response::builder()
                    .header(CONTENT_TYPE, "application/ld+json")
                    .body(Body::from(ANSWER))
                    .unwrap(),
            )
        });
        let service = RegistrationDisclosureLayer::new(64 * 1024).layer(broker);

        let (mut parts, body) = Request::builder().method(method).uri(uri).body(Body::empty()).unwrap().into_parts();
        classify(&mut parts).unwrap();
        let mut request = Request::from_parts(parts, body);
        if let Some(disclosure) = disclosure {
            request.extensions_mut().insert(disclosure);
        }

        let response = service.oneshot(request).await.unwrap_or_else(|never| match never {});
        let status = response.status();
        let body = response.into_body().collect().await.unwrap().to_bytes();

        (status, String::from_utf8(body.to_vec()).unwrap())
    }

    #[tokio::test]
    async fn a_reader_who_may_not_write_registrations_does_not_see_source_info() {
        let (status, body) = run(
            Method::GET,
            "/ngsi-ld/v1/csourceRegistrations?type=Vehicle",
            Some(RegistrationDisclosure::WithoutSourceInfo),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, r#"[{"id":"urn:r:1","endpoint":"http://source.test"}]"#);
    }

    #[tokio::test]
    async fn a_registration_read_whose_answer_is_edited_asks_for_an_uncompressed_answer() {
        let broker = tower::service_fn(|request: Request| async move {
            let status = if request.headers().contains_key(ACCEPT_ENCODING) {
                StatusCode::NOT_ACCEPTABLE
            } else {
                StatusCode::OK
            };

            Ok::<_, Infallible>(
                Response::builder()
                    .status(status)
                    .header(CONTENT_TYPE, "application/ld+json")
                    .body(Body::from(ANSWER))
                    .unwrap(),
            )
        });
        let service = RegistrationDisclosureLayer::new(64 * 1024).layer(broker);
        let (mut parts, body) = Request::builder()
            .uri("/ngsi-ld/v1/csourceRegistrations?type=Vehicle")
            .header(ACCEPT_ENCODING, "gzip, br")
            .body(Body::empty())
            .unwrap()
            .into_parts();
        classify(&mut parts).unwrap();
        let mut request = Request::from_parts(parts, body);
        request.extensions_mut().insert(RegistrationDisclosure::WithoutSourceInfo);

        let response = service.oneshot(request).await.unwrap_or_else(|never| match never {});

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn a_reader_who_may_write_registrations_sees_them_whole() {
        let (_, body) = run(Method::GET, "/ngsi-ld/v1/csourceRegistrations/urn:r:1", Some(RegistrationDisclosure::Whole)).await;

        assert_eq!(body, ANSWER);
    }

    #[tokio::test]
    async fn a_registration_read_without_a_decision_is_refused() {
        let (status, _) = run(Method::GET, "/ngsi-ld/v1/csourceRegistrations?type=Vehicle", None).await;

        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn a_request_that_was_not_classified_is_refused_rather_than_forwarded_whole() {
        let service = RegistrationDisclosureLayer::new(64 * 1024).layer(tower::service_fn(|_request: Request| async {
            Ok::<_, Infallible>(Response::new(Body::from(ANSWER)))
        }));
        let request = Request::builder().uri("/ngsi-ld/v1/csourceRegistrations").body(Body::empty()).unwrap();

        let response = service.oneshot(request).await.unwrap_or_else(|never| match never {});
        let status = response.status();
        let body = response.into_body().collect().await.unwrap().to_bytes();

        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(!String::from_utf8_lossy(&body).contains("contextSourceInfo"));
    }

    #[tokio::test]
    async fn anything_else_is_forwarded_untouched() {
        let (status, body) = run(Method::GET, "/ngsi-ld/v1/entities?type=Vehicle", None).await;

        assert_eq!((status, body.as_str()), (StatusCode::OK, ANSWER));
    }

    #[tokio::test]
    async fn a_registration_write_is_forwarded_untouched() {
        let (_, body) = run(Method::POST, "/ngsi-ld/v1/csourceRegistrations", None).await;

        assert_eq!(body, ANSWER);
    }
}
