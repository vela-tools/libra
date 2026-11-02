//! Judging the bearer credential a request presents.
//!
//! The proxied path and the management routes authenticate a caller the same way, so they share
//! one reading of the `Authorization` header: which header counts, what a malformed one is
//! answered with, when the fingerprint and the subject are recorded, and how a refusal is logged.
//! Two readings would drift, and a header one of them refuses the other would judge.

use axum::http::{HeaderMap, header::AUTHORIZATION};
use libra_audit::{credential::FingerprintKey, slot::AuditSlot};
use libra_identity_authenticator::{
    authentication::Authentication,
    authenticators::{AuthenticationError, Authenticators},
    bearer_token::{BearerError, BearerToken},
};
use libra_problem_details::{challenge::Challenge, problem::Problem};
use tracing::{debug, warn};

/// What a request presented, when it presented nothing the gate refuses outright.
#[derive(Debug)]
pub enum Presented {
    /// No `Authorization` header. Whether that is enough is the gate's decision, not this one's.
    Nothing,
    /// A credential an authenticator accepted, and who it says the caller is.
    Accepted(Authentication),
}

/// Judges the credential in `headers`.
///
/// `audit` is the request's audit slot, if it carries one: the credential's fingerprint is recorded
/// there under `fingerprint` before the credential is judged, and the caller's subject once it is
/// accepted.
///
/// # Errors
///
/// Returns the 401 the request is refused with: a second `Authorization` header, a header that is
/// not printable ASCII or not a bearer token, or a credential no authenticator accepts.
pub async fn authenticate(
    headers: &HeaderMap,
    audit: Option<&AuditSlot>,
    authenticators: &Authenticators,
    fingerprint: Option<&FingerprintKey>,
) -> Result<Presented, Problem> {
    let mut presented = headers.get_all(AUTHORIZATION).iter();
    let Some(header) = presented.next() else {
        return Ok(Presented::Nothing);
    };

    // Only one credential is judged, so a second one is a credential nobody judged. Libra never
    // forwards either, but refusing the request keeps it from being read as two callers by
    // anything that looks.
    if presented.next().is_some() {
        return Err(unauthorized(Challenge::Bearer, "the request carries more than one Authorization header"));
    }

    // Present but unreadable is not the same as absent, and is reported as what it is.
    let Ok(header) = header.to_str() else {
        return Err(unauthorized(Challenge::Bearer, "the Authorization header is not printable ASCII"));
    };

    let token = BearerToken::from_header(header).map_err(bearer_problem)?;

    // Recorded before the credential is judged, so a refusal carries it too: a refused credential
    // often names nobody, and the fingerprint is then the only thing that tells one misbehaving
    // client from many presenting the same dead credential.
    if let (Some(audit), Some(fingerprint)) = (audit, fingerprint) {
        audit.record_credential(fingerprint.fingerprint(token.as_str()));
    }

    let authentication = authenticators.authenticate(token).await.map_err(|error| {
        warn!(error = %error, "the credential was not accepted");

        refused(error)
    })?;

    // Who the caller is goes to the audit record, not the log: a name is a personal identifier,
    // and debug logging is switched on in deployments that never meant to keep one.
    debug!("caller authenticated");

    // The identifier worth keeping in an audit trail is the stable one, not the username. It is
    // recorded before any privilege decision, so a caller who is refused is named in the record of
    // their refusal as well as one who is served.
    if let (Some(audit), Some(subject)) = (audit, authentication.caller.subject.as_ref()) {
        // Owned by the audit record, which outlives the request's extensions.
        audit.record_subject(subject.clone());
    }

    Ok(Presented::Accepted(authentication))
}

/// The 401 for a request that presented no credential where one is required.
#[must_use]
pub fn required() -> Problem {
    unauthorized(Challenge::Bearer, "an Authorization header is required")
}

fn unauthorized(challenge: Challenge, detail: &str) -> Problem {
    Problem::Unauthorized {
        challenge,
        detail: detail.to_owned(),
    }
}

/// The response for an `Authorization` header that carries no bearer token. There is no token to
/// call invalid, so the challenge names no error.
fn bearer_problem(error: BearerError) -> Problem {
    unauthorized(
        Challenge::Bearer,
        match error {
            BearerError::NotBearer => "the Authorization header is not a Bearer token",
            BearerError::EmptyToken => "the Authorization header carries no token",
        },
    )
}

/// The response a caller sees when their credential is not accepted.
///
/// Every one is the same 401. The reason is logged, not returned: which check failed is a detail
/// that helps whoever is probing more than it helps whoever is misconfigured.
fn refused(error: AuthenticationError) -> Problem {
    match error {
        AuthenticationError::Unrecognized | AuthenticationError::Ambiguous | AuthenticationError::Refused(_) => {
            unauthorized(Challenge::InvalidToken, "the access token was not accepted")
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::credential::{Presented, authenticate};
    use axum::http::{HeaderMap, HeaderValue, StatusCode, header::AUTHORIZATION};
    use libra_audit::slot::{AuditSlot, Contributions};
    use libra_identity_authenticator::authenticators::Authenticators;
    use libra_problem_details::{challenge::Challenge, problem::Problem};
    use pretty_assertions::assert_eq;

    /// Judges `headers` with no authenticator configured, so anything that reaches one is refused.
    async fn judged(headers: &HeaderMap) -> (Result<Presented, Problem>, Contributions) {
        let audit = AuditSlot::default();
        let outcome = authenticate(headers, Some(&audit), &Authenticators::new(Vec::new()), None).await;

        (outcome, audit.contributions())
    }

    fn refusal(outcome: Result<Presented, Problem>) -> (StatusCode, Option<Challenge>) {
        match outcome {
            Err(problem @ Problem::Unauthorized { challenge, .. }) => (problem.status(), Some(challenge)),
            Err(problem) => (problem.status(), None),
            Ok(presented) => panic!("expected a refusal, got {presented:?}"),
        }
    }

    #[tokio::test]
    async fn a_request_without_an_authorization_header_presented_nothing() {
        let (outcome, audited) = judged(&HeaderMap::new()).await;

        assert!(matches!(outcome, Ok(Presented::Nothing)));
        assert_eq!(audited, Contributions::default());
    }

    #[tokio::test]
    async fn a_second_authorization_header_is_refused_before_either_is_judged() {
        let mut headers = HeaderMap::new();
        headers.append(AUTHORIZATION, HeaderValue::from_static("Bearer first"));
        headers.append(AUTHORIZATION, HeaderValue::from_static("Bearer second"));

        let (outcome, audited) = judged(&headers).await;

        assert_eq!(refusal(outcome), (StatusCode::UNAUTHORIZED, Some(Challenge::Bearer)));
        assert_eq!(audited, Contributions::default());
    }

    #[tokio::test]
    async fn a_header_that_is_not_printable_ascii_is_refused_rather_than_read_as_absent() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_bytes(b"Bearer \xff").unwrap());

        let (outcome, _) = judged(&headers).await;

        assert_eq!(refusal(outcome), (StatusCode::UNAUTHORIZED, Some(Challenge::Bearer)));
    }

    #[tokio::test]
    async fn a_token_no_authenticator_recognizes_is_refused_as_an_invalid_token() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer unknown"));

        let (outcome, _) = judged(&headers).await;

        assert_eq!(refusal(outcome), (StatusCode::UNAUTHORIZED, Some(Challenge::InvalidToken)));
    }
}
