//! The Tower adapter that establishes who the caller is.
//!
//! It reads the bearer credential, has the deployment's [`Authenticators`] judge it, and puts the
//! outcome in the request extensions as two values: a [`PolicyIdentity`], which is the only form
//! authorization ever sees, and a [`CallerProfile`], for whatever propagates or records the caller.
//! Keeping those apart is what lets the policy model stay free of how identity is established.
//!
//! The credential itself stops here: once judged, the `Authorization` header is removed, so
//! nothing below this layer, the broker included, ever receives it.

use crate::credential::{Presented, authenticate, required};
use axum::{
    extract::Request,
    http::header::AUTHORIZATION,
    response::{IntoResponse, Response},
};
use libra_audit::{
    credential::FingerprintKey,
    slot::{Access, AuditSlot},
};
use libra_identity_authenticator::{authentication::Authentication, authenticators::Authenticators, caller::CallerProfile};
use libra_policy_model::identity::PolicyIdentity;
use libra_problem_details::problem::Problem;
use libra_tenant::PublicAccessAllowed;
use std::{
    convert::Infallible,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tower::{Layer, Service, ServiceExt};
use tracing::debug;

pub mod credential;

/// Establishes the caller on every request that carries a credential.
#[derive(Clone)]
pub struct IdentityLayer {
    authenticators: Arc<Authenticators>,
    fingerprint: Option<FingerprintKey>,
}

impl IdentityLayer {
    /// Builds the layer over the deployment's authenticators.
    ///
    /// `fingerprint` is the deployment's audit key: present, every presented credential is
    /// recorded in the audit slot as its keyed digest, refusals included; absent, no fingerprint
    /// is computed.
    #[must_use]
    pub const fn new(authenticators: Arc<Authenticators>, fingerprint: Option<FingerprintKey>) -> Self {
        Self { authenticators, fingerprint }
    }
}

impl<S> Layer<S> for IdentityLayer {
    type Service = IdentityService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        IdentityService {
            inner,
            authenticators: Arc::clone(&self.authenticators),
            // Each service owns its key; the key is a few bytes and is never mutated.
            fingerprint: self.fingerprint.clone(),
        }
    }
}

/// The service produced by [`IdentityLayer`].
#[derive(Clone)]
pub struct IdentityService<S> {
    inner: S,
    authenticators: Arc<Authenticators>,
    fingerprint: Option<FingerprintKey>,
}

impl<S> Service<Request> for IdentityService<S>
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
        // The future outlives `&mut self`, so it takes its own handle on the inner service and on
        // the key, as every Tower service that serves a request in a boxed future does.
        let inner = self.inner.clone();
        let authenticators = Arc::clone(&self.authenticators);
        let fingerprint = self.fingerprint.clone();

        Box::pin(async move {
            match establish(&mut request, &authenticators, fingerprint.as_ref()).await {
                Ok(()) => inner.oneshot(request).await,
                Err(problem) => Ok(problem.into_response()),
            }
        })
    }
}

/// Establishes who the caller is and puts it in the request extensions, removing the credential.
///
/// # Errors
///
/// Returns the 401 the request is refused with.
async fn establish(request: &mut Request, authenticators: &Authenticators, fingerprint: Option<&FingerprintKey>) -> Result<(), Problem> {
    let presented = authenticate(request.headers(), request.extensions().get::<AuditSlot>(), authenticators, fingerprint).await?;

    // A credential that is present is always judged, even where public access is allowed, and a
    // refused one never reaches this point. Falling back to anonymous on a bad one would let a
    // caller downgrade themselves out of a deny that names them.
    let Authentication { identity, caller } = match presented {
        Presented::Accepted(authentication) => authentication,
        Presented::Nothing => {
            if request.extensions().get::<PublicAccessAllowed>().is_none() {
                return Err(required());
            }

            // Anonymous, and the deployment said so. The policy set still decides whether
            // anonymous may do anything; this only means there is nobody to name.
            debug!("proceeding without a caller, as the deployment allows");
            if let Some(audit) = request.extensions().get::<AuditSlot>() {
                audit.record_access(Access::Public);
            }
            request.extensions_mut().insert(PolicyIdentity::anonymous());

            return Ok(());
        }
    };

    // The credential has done its job. Nothing below needs it: authorization reads the
    // identity, and the broker is told who asked through the propagated identity headers.
    // Forwarding it would hand a long-lived secret to the broker, and through any context
    // source registration that copies `Authorization` (NGSI-LD clause 4.3.6.5) to whoever
    // registered it.
    request.headers_mut().remove(AUTHORIZATION);
    request.extensions_mut().insert(identity);
    request.extensions_mut().insert::<CallerProfile>(caller);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{HeaderValue, StatusCode, header::WWW_AUTHENTICATE},
    };
    use libra_audit::slot::Contributions;
    use libra_identity_authenticator::{
        authenticator::{AuthenticationFuture, Authenticator, Recognition},
        bearer_token::BearerToken,
        caller::CallerKind,
        refusal::Refusal,
    };
    use libra_policy_model::identity::{GroupName, IdentityName, PrincipalName, Subject};
    use libra_problem_details::challenge::Challenge;
    use pretty_assertions::assert_eq;
    use std::sync::Mutex;
    use tower::util::BoxCloneService;

    /// Recognizes `key_` tokens: `key_good` is the machine `ingest` in group `fleet`, and any
    /// other is refused as revoked.
    struct Keys;

    impl Authenticator for Keys {
        fn recognizes(&self, token: BearerToken<'_>) -> Recognition {
            if token.as_str().starts_with("key_") {
                Recognition::Recognized
            } else {
                Recognition::Unrecognized
            }
        }

        fn authenticate<'a>(&'a self, token: BearerToken<'a>) -> AuthenticationFuture<'a> {
            let outcome = if token.as_str() == "key_good" {
                Ok(Authentication {
                    identity: PolicyIdentity {
                        name: Some(IdentityName::Principal(PrincipalName::new("ingest").unwrap())),
                        groups: vec![GroupName::new("fleet").unwrap()],
                        roles: Vec::new(),
                    },
                    caller: CallerProfile {
                        subject: Some(Subject::new("urn:libra:principal:01J9ZQ4X7K2V3M5N6P8R9S0T1V").unwrap()),
                        kind: CallerKind::Machine,
                        ..CallerProfile::default()
                    },
                })
            } else {
                Err(Refusal::Revoked)
            };

            Box::pin(async move { outcome })
        }
    }

    /// What the inner service saw.
    type Seen = Arc<Mutex<Option<(Option<PolicyIdentity>, Option<CallerProfile>)>>>;

    fn inner(seen: &Seen) -> BoxCloneService<Request, Response, Infallible> {
        let seen = Arc::clone(seen);
        BoxCloneService::new(tower::service_fn(move |request: Request| {
            let seen = Arc::clone(&seen);
            async move {
                *seen.lock().unwrap() = Some((
                    request.extensions().get::<PolicyIdentity>().cloned(),
                    request.extensions().get::<CallerProfile>().cloned(),
                ));
                Ok(Response::new(Body::empty()))
            }
        }))
    }

    struct Outcome {
        status: StatusCode,
        challenge: Option<HeaderValue>,
        audited: Contributions,
        seen: Option<(Option<PolicyIdentity>, Option<CallerProfile>)>,
    }

    /// Runs a request through the layer, with `authenticators` as the deployment's list and
    /// `fingerprint` as the audit key the composition root builds from the configuration.
    async fn run(authenticators: Authenticators, allowed_public: bool, authorization: Option<&str>, fingerprint: Option<FingerprintKey>) -> Outcome {
        let seen = Seen::default();
        let mut service = IdentityLayer::new(Arc::new(authenticators), fingerprint).layer(inner(&seen));

        let mut builder = Request::builder().uri("/ngsi-ld/v1/entities");
        if let Some(authorization) = authorization {
            builder = builder.header(AUTHORIZATION, authorization);
        }
        let mut request = builder.body(Body::empty()).unwrap();

        let slot = AuditSlot::default();
        // The slot is shared storage: the request carries one handle, the test reads the other.
        request.extensions_mut().insert(slot.clone());
        if allowed_public {
            request.extensions_mut().insert(PublicAccessAllowed);
        }

        let response = service.call(request).await.unwrap_or_else(|error| match error {});
        let seen = seen.lock().unwrap().take();

        Outcome {
            status: response.status(),
            challenge: response.headers().get(WWW_AUTHENTICATE).cloned(),
            audited: slot.contributions(),
            seen,
        }
    }

    fn keys() -> Authenticators {
        Authenticators::new(vec![Arc::new(Keys)])
    }

    #[tokio::test]
    async fn a_request_with_no_credential_is_refused_and_the_refusal_has_nobody_to_name() {
        let outcome = run(keys(), false, None, None).await;

        assert_eq!(outcome.status, StatusCode::UNAUTHORIZED);
        assert_eq!(outcome.audited, Contributions::default());
    }

    #[tokio::test]
    async fn an_anonymous_request_the_deployment_allows_is_audited_as_public_access() {
        let outcome = run(keys(), true, None, None).await;

        assert_eq!(outcome.status, StatusCode::OK);
        assert_eq!(outcome.audited.access, Access::Public);
        assert_eq!(outcome.audited.subject, None);
        assert_eq!(outcome.seen, Some((Some(PolicyIdentity::anonymous()), None)));
    }

    #[tokio::test]
    async fn a_credential_that_is_not_accepted_never_falls_back_to_anonymous_even_where_public_access_is_allowed() {
        // A caller must not be able to downgrade themselves out of a deny that names them.
        let outcome = run(keys(), true, Some("Bearer key_revoked"), None).await;

        assert_eq!(outcome.status, StatusCode::UNAUTHORIZED);
        assert_eq!(outcome.audited.access, Access::Credentialed);
        assert_eq!(outcome.audited.subject, None);
        assert_eq!(outcome.seen, None);
    }

    #[tokio::test]
    async fn a_credential_no_authenticator_recognizes_is_refused_and_still_fingerprinted() {
        let key = FingerprintKey::new(&[1_u8; 32]);
        let outcome = run(keys(), true, Some("Bearer not-a-credential"), Some(key.clone())).await;

        assert_eq!(outcome.status, StatusCode::UNAUTHORIZED);
        assert_eq!(outcome.audited.credential, Some(key.fingerprint("not-a-credential")));
    }

    #[tokio::test]
    async fn a_credential_two_authenticators_recognize_is_refused() {
        let ambiguous = Authenticators::new(vec![Arc::new(Keys), Arc::new(Keys)]);

        let outcome = run(ambiguous, false, Some("Bearer key_good"), None).await;

        assert_eq!(outcome.status, StatusCode::UNAUTHORIZED);
        assert_eq!(outcome.seen, None);
    }

    #[tokio::test]
    async fn an_accepted_credential_reaches_the_inner_service_as_an_identity_and_a_profile() {
        let outcome = run(keys(), false, Some("Bearer key_good"), None).await;

        assert_eq!(outcome.status, StatusCode::OK);
        assert_eq!(
            outcome.audited.subject.as_ref().map(Subject::as_str),
            Some("urn:libra:principal:01J9ZQ4X7K2V3M5N6P8R9S0T1V")
        );

        let (identity, caller) = outcome.seen.unwrap();
        let identity = identity.unwrap();
        let caller = caller.unwrap();
        assert_eq!(identity.name, Some(IdentityName::Principal(PrincipalName::new("ingest").unwrap())));
        assert_eq!(identity.groups, vec![GroupName::new("fleet").unwrap()]);
        assert_eq!(caller.kind, CallerKind::Machine);
    }

    /// Runs a request carrying every value of `authorizations` as its own `Authorization` header,
    /// and answers the status and whether the inner service still saw an `Authorization` header.
    async fn forwarded(authorizations: &[&str]) -> (StatusCode, Option<bool>) {
        let saw = Arc::new(Mutex::new(None));
        let recorder = Arc::clone(&saw);
        let inner = tower::service_fn(move |request: Request| {
            let recorder = Arc::clone(&recorder);
            async move {
                *recorder.lock().unwrap() = Some(request.headers().contains_key(AUTHORIZATION));
                Ok::<_, Infallible>(Response::new(Body::empty()))
            }
        });
        let mut service = IdentityLayer::new(Arc::new(keys()), None).layer(inner);

        let mut builder = Request::builder().uri("/ngsi-ld/v1/entities");
        for authorization in authorizations {
            builder = builder.header(AUTHORIZATION, *authorization);
        }

        let response = service.call(builder.body(Body::empty()).unwrap()).await.unwrap_or_else(|error| match error {});
        let saw = *saw.lock().unwrap();

        (response.status(), saw)
    }

    #[tokio::test]
    async fn the_credential_is_removed_once_the_caller_is_authenticated() {
        assert_eq!(forwarded(&["Bearer key_good"]).await, (StatusCode::OK, Some(false)));
    }

    #[tokio::test]
    async fn two_authorization_headers_are_refused_before_either_is_judged() {
        assert_eq!(forwarded(&["Bearer key_good", "Bearer key_good"]).await, (StatusCode::UNAUTHORIZED, None));
    }

    #[tokio::test]
    async fn a_deployment_that_configured_no_key_records_no_fingerprint() {
        let outcome = run(keys(), false, Some("Bearer key_revoked"), None).await;

        assert_eq!(outcome.status, StatusCode::UNAUTHORIZED);
        assert_eq!(outcome.audited.credential, None);
    }

    #[tokio::test]
    async fn a_header_of_another_scheme_is_refused_before_any_authenticator_is_asked() {
        let outcome = run(keys(), false, Some("Basic dXNlcg=="), None).await;

        assert_eq!(outcome.status, StatusCode::UNAUTHORIZED);
        assert_eq!(outcome.audited.credential, None);
    }

    #[tokio::test]
    async fn every_refusal_carries_the_challenge_its_reason_calls_for() {
        // RFC 6750 section 3.1: no error code where no token was presented, `invalid_token` where
        // one was presented and not accepted.
        for (authorization, challenge) in [
            (None, Challenge::Bearer),
            (Some("Basic dXNlcg=="), Challenge::Bearer),
            (Some("Bearer "), Challenge::Bearer),
            (Some("Bearer key_revoked"), Challenge::InvalidToken),
            (Some("Bearer not-a-credential"), Challenge::InvalidToken),
        ] {
            let outcome = run(keys(), false, authorization, None).await;

            assert_eq!(outcome.status, StatusCode::UNAUTHORIZED, "{authorization:?}");
            assert_eq!(outcome.challenge, Some(challenge.header_value()), "{authorization:?}");
        }
    }

    #[tokio::test]
    async fn a_credential_two_authenticators_recognize_is_challenged_as_an_invalid_token() {
        let ambiguous = Authenticators::new(vec![Arc::new(Keys), Arc::new(Keys)]);

        let outcome = run(ambiguous, false, Some("Bearer key_good"), None).await;

        assert_eq!(outcome.challenge, Some(Challenge::InvalidToken.header_value()));
    }

    #[tokio::test]
    async fn an_accepted_credential_is_answered_without_a_challenge() {
        assert_eq!(run(keys(), false, Some("Bearer key_good"), None).await.challenge, None);
    }
}
