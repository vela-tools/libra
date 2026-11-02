//! The proxy's error taxonomy and its RFC 9457 representation.

use crate::challenge::Challenge;
use axum::{
    http::{StatusCode, Uri, header::WWW_AUTHENTICATE},
    response::{IntoResponse, Response},
};
use iri_rs::Iri;
use problem_details::ProblemDetails;
use thiserror::Error;
use tracing::warn;

/// Type URIs for proxy-level problems.
///
/// These are user-facing and stable: they appear in the `type` field of every error response, and
/// each one must resolve to a page describing the problem once the project is published.
pub mod type_uri {
    use iri_rs::{Iri, iri};

    /// Base every Libra problem type URI is built on.
    pub static BASE: Iri<&str> = iri!("https://libra.velacontext.com/problems/");

    pub static UNAUTHORIZED: Iri<&str> = iri!("https://libra.velacontext.com/problems/Unauthorized");
    pub static ACCESS_DENIED: Iri<&str> = iri!("https://libra.velacontext.com/problems/AccessDenied");
    pub static METHOD_NOT_ALLOWED: Iri<&str> = iri!("https://libra.velacontext.com/problems/MethodNotAllowed");
    pub static NOT_FOUND: Iri<&str> = iri!("https://libra.velacontext.com/problems/ResourceNotFound");
    pub static NOT_ACCEPTABLE: Iri<&str> = iri!("https://libra.velacontext.com/problems/NotAcceptable");
    pub static BAD_GATEWAY: Iri<&str> = iri!("https://libra.velacontext.com/problems/BadGateway");
    pub static BAD_REQUEST: Iri<&str> = iri!("https://libra.velacontext.com/problems/BadRequest");
    pub static PAYLOAD_TOO_LARGE: Iri<&str> = iri!("https://libra.velacontext.com/problems/PayloadTooLarge");
    pub static GATEWAY_TIMEOUT: Iri<&str> = iri!("https://libra.velacontext.com/problems/GatewayTimeout");
    pub static INTERNAL_ERROR: Iri<&str> = iri!("https://libra.velacontext.com/problems/InternalError");
    pub static INVALID_TENANT_HEADER: Iri<&str> = iri!("https://libra.velacontext.com/problems/InvalidTenantHeader");
    pub static SERVICE_UNAVAILABLE: Iri<&str> = iri!("https://libra.velacontext.com/problems/ServiceUnavailable");
    pub static TOO_MANY_REQUESTS: Iri<&str> = iri!("https://libra.velacontext.com/problems/TooManyRequests");
}

/// A proxy-level problem, convertible into an RFC 9457 response.
#[derive(Debug, Error)]
pub enum Problem {
    /// No credential the request could be served under: missing, malformed or not accepted.
    #[error("Unauthorized: {detail}")]
    Unauthorized {
        /// The `WWW-Authenticate` challenge the response carries.
        challenge: Challenge,
        /// What the caller is told.
        detail: String,
    },

    /// A valid token without sufficient permission.
    #[error("Access Denied: {0}")]
    Forbidden(String),

    /// The method is not allowed on this resource.
    #[error("Method Not Allowed: {0}")]
    MethodNotAllowed(String),

    /// The path is not one Libra serves.
    ///
    /// Distinct from a refusal: nothing was denied, there is simply no such resource. Reporting it
    /// as an internal error would say the
    /// gateway broke when the caller asked for something that does not exist.
    #[error("Resource Not Found: {0}")]
    NotFound(String),

    /// Nothing the caller will accept is a representation Libra can produce.
    ///
    /// Only raised when the deployment has asked for it. By default an `Accept` header naming
    /// nothing Libra produces is forwarded to the broker, whose own answer is the one the caller
    /// gets: the gateway refusing on the broker's behalf would be a decision no operator made.
    #[error("Not Acceptable: {0}")]
    NotAcceptable(String),

    /// The upstream broker could not be reached.
    #[error("Bad Gateway: {0}")]
    BadGateway(String),

    /// The request was malformed.
    #[error("Bad Request: {0}")]
    BadRequest(String),

    /// The request body exceeded the configured limit.
    #[error("Payload Too Large: {0}")]
    PayloadTooLarge(String),

    /// The upstream broker did not answer in time.
    #[error("Gateway Timeout: {0}")]
    GatewayTimeout(String),

    /// The `NGSILD-Tenant` header is repeated, is not printable ASCII, or is not a usable tenant
    /// name, the empty value included.
    #[error("Invalid Tenant Header: {0}")]
    InvalidTenantHeader(String),

    /// The caller exceeded its rate limit.
    #[error("Too Many Requests: {0}")]
    TooManyRequests(String),

    /// The proxy is shedding load, or will not forward to an upstream that keeps failing.
    #[error("Service Unavailable: {0}")]
    ServiceUnavailable(String),

    /// An unexpected internal failure.
    #[error("Internal Error: {0}")]
    Internal(String),
}

impl Problem {
    /// The HTTP status this problem is reported with.
    #[must_use]
    pub const fn status(&self) -> StatusCode {
        match self {
            Problem::Unauthorized { .. } => StatusCode::UNAUTHORIZED,
            Problem::Forbidden(_) => StatusCode::FORBIDDEN,
            Problem::MethodNotAllowed(_) => StatusCode::METHOD_NOT_ALLOWED,
            Problem::NotFound(_) => StatusCode::NOT_FOUND,
            Problem::NotAcceptable(_) => StatusCode::NOT_ACCEPTABLE,
            Problem::BadGateway(_) => StatusCode::BAD_GATEWAY,
            Problem::BadRequest(_) | Problem::InvalidTenantHeader(_) => StatusCode::BAD_REQUEST,
            Problem::PayloadTooLarge(_) => StatusCode::PAYLOAD_TOO_LARGE,
            Problem::GatewayTimeout(_) => StatusCode::GATEWAY_TIMEOUT,
            Problem::TooManyRequests(_) => StatusCode::TOO_MANY_REQUESTS,
            Problem::ServiceUnavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            Problem::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// The stable type URI for this problem.
    #[must_use]
    pub const fn type_uri(&self) -> &'static Iri<&'static str> {
        match self {
            Problem::Unauthorized { .. } => &type_uri::UNAUTHORIZED,
            Problem::Forbidden(_) => &type_uri::ACCESS_DENIED,
            Problem::MethodNotAllowed(_) => &type_uri::METHOD_NOT_ALLOWED,
            Problem::NotFound(_) => &type_uri::NOT_FOUND,
            Problem::NotAcceptable(_) => &type_uri::NOT_ACCEPTABLE,
            Problem::BadGateway(_) => &type_uri::BAD_GATEWAY,
            Problem::BadRequest(_) => &type_uri::BAD_REQUEST,
            Problem::PayloadTooLarge(_) => &type_uri::PAYLOAD_TOO_LARGE,
            Problem::GatewayTimeout(_) => &type_uri::GATEWAY_TIMEOUT,
            Problem::InvalidTenantHeader(_) => &type_uri::INVALID_TENANT_HEADER,
            Problem::TooManyRequests(_) => &type_uri::TOO_MANY_REQUESTS,
            Problem::ServiceUnavailable(_) => &type_uri::SERVICE_UNAVAILABLE,
            Problem::Internal(_) => &type_uri::INTERNAL_ERROR,
        }
    }

    /// The short, human-readable title.
    #[must_use]
    pub const fn title(&self) -> &'static str {
        match self {
            Problem::Unauthorized { .. } => "Unauthorized",
            Problem::Forbidden(_) => "Access Denied",
            Problem::MethodNotAllowed(_) => "Method Not Allowed",
            Problem::NotFound(_) => "Resource Not Found",
            Problem::NotAcceptable(_) => "Not Acceptable",
            Problem::BadGateway(_) => "Bad Gateway",
            Problem::BadRequest(_) => "Bad Request",
            Problem::PayloadTooLarge(_) => "Payload Too Large",
            Problem::GatewayTimeout(_) => "Gateway Timeout",
            Problem::InvalidTenantHeader(_) => "Invalid Tenant Header",
            Problem::TooManyRequests(_) => "Too Many Requests",
            Problem::ServiceUnavailable(_) => "Service Unavailable",
            Problem::Internal(_) => "Internal Error",
        }
    }

    /// Whether this problem is the caller's fault rather than the upstream's.
    ///
    /// A layer that judges the broker's health by the failures below it, such as a circuit breaker,
    /// uses this: a 401, a 403, or an oversized body says nothing about the broker's health, so it
    /// must not count toward a failure threshold.
    #[must_use]
    pub const fn is_client_error(&self) -> bool {
        match self {
            Problem::Unauthorized { .. }
            | Problem::Forbidden(_)
            | Problem::MethodNotAllowed(_)
            | Problem::NotFound(_)
            | Problem::NotAcceptable(_)
            | Problem::PayloadTooLarge(_)
            | Problem::InvalidTenantHeader(_)
            | Problem::TooManyRequests(_)
            | Problem::BadRequest(_) => true,
            Problem::BadGateway(_) | Problem::GatewayTimeout(_) | Problem::ServiceUnavailable(_) | Problem::Internal(_) => false,
        }
    }

    /// The fixed `detail` a caller is shown in place of this problem's own text, if it is withheld.
    ///
    /// A client error describes the caller's own request, so its text is theirs to read. A server
    /// error's text is written for the operator: it can carry a broker address, a transport error
    /// or a file path, none of which is the caller's business, so the caller gets a fixed sentence
    /// and the text goes to the log.
    #[must_use]
    pub const fn withheld_detail(&self) -> Option<&'static str> {
        match self {
            Problem::Unauthorized { .. }
            | Problem::Forbidden(_)
            | Problem::MethodNotAllowed(_)
            | Problem::NotFound(_)
            | Problem::NotAcceptable(_)
            | Problem::PayloadTooLarge(_)
            | Problem::InvalidTenantHeader(_)
            | Problem::TooManyRequests(_)
            | Problem::BadRequest(_) => None,
            Problem::BadGateway(_) => Some("An upstream service failed to give a usable answer"),
            Problem::GatewayTimeout(_) => Some("An upstream service did not answer in time"),
            Problem::ServiceUnavailable(_) => Some("The service is temporarily unavailable"),
            Problem::Internal(_) => Some("An unexpected error occurred"),
        }
    }

    /// Renders this problem as an RFC 9457 response.
    ///
    /// Takes `&self` so a borrowed problem, such as one recovered from a boxed error, can be
    /// rendered without being cloned or rebuilt variant by variant.
    #[must_use]
    pub fn to_response(&self) -> Response {
        let detail = match self.withheld_detail() {
            Some(withheld) => {
                warn!(problem = %self, "answered with a server error whose detail is withheld from the caller");
                withheld.to_owned()
            }
            None => self.to_string(),
        };

        let mut response = ProblemDetails::from_status_code(self.status())
            .with_type(Uri::from_static(self.type_uri().as_str()))
            .with_title(self.title())
            .with_detail(detail)
            .into_response();

        if let Problem::Unauthorized { challenge, .. } = self {
            response.headers_mut().insert(WWW_AUTHENTICATE, challenge.header_value());
        }

        response
    }
}

impl IntoResponse for Problem {
    fn into_response(self) -> Response {
        self.to_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use pretty_assertions::assert_eq;
    use serde_json::Value;

    fn every_problem() -> [Problem; 13] {
        [
            Problem::Unauthorized {
                challenge: Challenge::Bearer,
                detail: String::new(),
            },
            Problem::Forbidden(String::new()),
            Problem::MethodNotAllowed(String::new()),
            Problem::NotFound(String::new()),
            Problem::NotAcceptable(String::new()),
            Problem::BadGateway(String::new()),
            Problem::BadRequest(String::new()),
            Problem::PayloadTooLarge(String::new()),
            Problem::GatewayTimeout(String::new()),
            Problem::InvalidTenantHeader(String::new()),
            Problem::TooManyRequests(String::new()),
            Problem::ServiceUnavailable(String::new()),
            Problem::Internal(String::new()),
        ]
    }

    #[test]
    fn every_type_uri_is_under_the_base() {
        for problem in &every_problem() {
            assert!(
                problem.type_uri().as_str().starts_with(type_uri::BASE.as_str()),
                "{} is not under {}",
                problem.type_uri(),
                type_uri::BASE
            );
            // Uri::from_static panics on a malformed URI, so this also proves every URI parses.
            let _response = problem.to_response();
        }
    }

    #[test]
    fn every_detail_is_labelled_with_its_title() {
        // A client reading `detail` and one reading `title` see the same name for the problem.
        for problem in &every_problem() {
            assert!(
                problem.to_string().starts_with(&format!("{}: ", problem.title())),
                "{problem} is not labelled '{}'",
                problem.title()
            );
        }
    }

    #[test]
    fn client_errors_do_not_implicate_the_broker() {
        assert!(
            Problem::Unauthorized {
                challenge: Challenge::Bearer,
                detail: String::new()
            }
            .is_client_error()
        );
        assert!(Problem::PayloadTooLarge(String::new()).is_client_error());
        // A caller that has run out of quota has said nothing about the broker's health, so a 429
        // must not count as an upstream failure.
        assert!(Problem::TooManyRequests(String::new()).is_client_error());
        // A caller that will accept nothing Libra produces has described their own request, not
        // the broker's health.
        assert!(Problem::NotAcceptable(String::new()).is_client_error());
        assert!(!Problem::BadGateway(String::new()).is_client_error());
        assert!(!Problem::GatewayTimeout(String::new()).is_client_error());
    }

    async fn detail_of(problem: &Problem) -> String {
        let body = to_bytes(problem.to_response().into_body(), usize::MAX).await.unwrap();
        let document: Value = serde_json::from_slice(&body).unwrap();

        document["detail"].as_str().unwrap().to_owned()
    }

    #[tokio::test]
    async fn a_server_error_does_not_show_the_caller_its_internal_text() {
        let problems = [
            Problem::BadGateway("http://broker.internal:1026 answered 500".to_owned()),
            Problem::GatewayTimeout("http://broker.internal:1026 did not answer".to_owned()),
            Problem::ServiceUnavailable("breaker open after http://broker.internal:1026 failed".to_owned()),
            Problem::Internal("cannot read /etc/libra/contexts/fleet.jsonld".to_owned()),
        ];

        for problem in &problems {
            let detail = detail_of(problem).await;

            assert!(!detail.contains("broker.internal") && !detail.contains("/etc/libra"), "{detail}");
            assert_eq!(Some(detail.as_str()), problem.withheld_detail());
        }
    }

    #[tokio::test]
    async fn a_client_error_tells_the_caller_what_was_wrong_with_their_request() {
        let detail = detail_of(&Problem::BadRequest("the q parameter does not parse".to_owned())).await;

        assert!(detail.contains("the q parameter does not parse"), "{detail}");
    }

    #[test]
    fn a_401_carries_its_challenge() {
        let response = Problem::Unauthorized {
            challenge: Challenge::InvalidToken,
            detail: String::new(),
        }
        .to_response();

        assert_eq!(response.headers().get(WWW_AUTHENTICATE), Some(&Challenge::InvalidToken.header_value()));
    }

    #[test]
    fn a_handler_returning_a_problem_answers_with_its_status_and_challenge() {
        // A handler that returns `Err(Problem)` is turned into a response by `IntoResponse`, not by
        // `to_response`, so the conversion axum calls has to produce the same answer.
        let response = Problem::Unauthorized {
            challenge: Challenge::InvalidToken,
            detail: String::new(),
        }
        .into_response();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(response.headers().get(WWW_AUTHENTICATE), Some(&Challenge::InvalidToken.header_value()));
        assert_eq!(Problem::NotFound(String::new()).into_response().status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn a_problem_other_than_a_401_carries_no_challenge() {
        assert!(!Problem::Forbidden(String::new()).to_response().headers().contains_key(WWW_AUTHENTICATE));
    }

    #[test]
    fn status_matches_the_variant() {
        assert_eq!(
            Problem::Unauthorized {
                challenge: Challenge::Bearer,
                detail: String::new()
            }
            .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(Problem::Forbidden(String::new()).status(), StatusCode::FORBIDDEN);
        assert_eq!(Problem::InvalidTenantHeader(String::new()).status(), StatusCode::BAD_REQUEST);
        assert_eq!(Problem::NotAcceptable(String::new()).status(), StatusCode::NOT_ACCEPTABLE);
        assert_eq!(Problem::TooManyRequests(String::new()).status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(Problem::Internal(String::new()).status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
