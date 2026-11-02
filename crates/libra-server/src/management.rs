//! The gate on the management endpoints.
//!
//! The privilege decision knows nothing about HTTP beyond the method, and the credential is judged
//! exactly as on the proxied path. This is the adapter that has the credential judged, turns the
//! accepted caller into the shape the decision reads, and refuses the request when the caller is
//! not privileged. It lives in the composition root because "which routes are privileged" is a
//! wiring question rather than a rule.

use axum::{
    extract::Request,
    response::{IntoResponse, Response},
};
use libra_audit::{credential::FingerprintKey, slot::AuditSlot};
use libra_identity_authenticator::{authentication::Authentication, authenticators::Authenticators};
use libra_identity_layer::credential::{Presented, authenticate, required};
use libra_management_auth::{Caller, PrivilegeSettings};
use libra_policy_model::identity::IdentityName;
use libra_problem_details::problem::Problem;
use std::{
    convert::Infallible,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tower::{Layer, Service, ServiceExt};
use tracing::warn;

/// Requires a privileged caller on the routes it wraps.
#[derive(Clone)]
pub struct ManagementAuthLayer {
    authenticators: Arc<Authenticators>,
    settings: Arc<PrivilegeSettings>,
    fingerprint: Option<FingerprintKey>,
}

impl ManagementAuthLayer {
    /// Builds the gate.
    ///
    /// `fingerprint` is the deployment's audit key: present, every presented credential is
    /// recorded as its keyed digest, refusals included, exactly as on the proxied path.
    #[must_use]
    pub fn new(authenticators: Arc<Authenticators>, settings: PrivilegeSettings, fingerprint: Option<FingerprintKey>) -> Self {
        Self {
            authenticators,
            settings: Arc::new(settings),
            fingerprint,
        }
    }
}

impl<S> Layer<S> for ManagementAuthLayer {
    type Service = ManagementAuthService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ManagementAuthService {
            inner,
            authenticators: Arc::clone(&self.authenticators),
            settings: Arc::clone(&self.settings),
            fingerprint: self.fingerprint.clone(), // each service owns its key; it is a few bytes and never mutated
        }
    }
}

/// The service produced by [`ManagementAuthLayer`].
#[derive(Clone)]
pub struct ManagementAuthService<S> {
    inner: S,
    authenticators: Arc<Authenticators>,
    settings: Arc<PrivilegeSettings>,
    fingerprint: Option<FingerprintKey>,
}

impl<S> Service<Request> for ManagementAuthService<S>
where
    S: Service<Request, Response = Response, Error = Infallible> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = Response;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Response, Infallible>> + Send>>;

    /// Always ready. The inner service's readiness is driven by `oneshot` in [`Self::call`].
    fn poll_ready(&mut self, _context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request) -> Self::Future {
        let inner = self.inner.clone(); // the boxed future outlives `&mut self`
        let authenticators = Arc::clone(&self.authenticators);
        let fingerprint = self.fingerprint.clone(); // as above
        let settings = Arc::clone(&self.settings);

        Box::pin(async move {
            let audit = request.extensions().get::<AuditSlot>();
            let Authentication { identity, caller } = match authenticate(request.headers(), audit, &authenticators, fingerprint.as_ref()).await {
                Ok(Presented::Accepted(authentication)) => authentication,
                // No anonymous path here, whatever the multitenancy policy says. These routes read
                // and change the rules everything else is judged by.
                Ok(Presented::Nothing) => return Ok(required().into_response()),
                Err(problem) => return Ok(problem.into_response()),
            };

            // Both names come from the policy identity, the one an authenticator decided the caller
            // is matched by, so `admin-users` and a policy's `users` name the same accounts.
            let (username, principal) = match &identity.name {
                Some(IdentityName::Account(username)) => (Some(username), None),
                Some(IdentityName::Principal(principal)) => (None, Some(principal)),
                None => (None, None),
            };
            let caller = Caller {
                username,
                principal,
                subject: caller.subject.as_ref(),
                client_id: caller.client.as_ref(),
                groups: &identity.groups,
                roles: &identity.roles,
            };

            if let Err(error) = settings.authorize(request.method(), &caller) {
                // Named by the credential's fingerprint, never by name: the name is a personal
                // identifier and belongs in the audit record, not the log.
                let credential = request.extensions().get::<AuditSlot>().and_then(AuditSlot::credential);
                warn!(
                    credential = credential.as_ref().map(display),
                    method = %request.method(),
                    // The path alone: a query string can carry values the caller was not meant to
                    // leave in a log.
                    path = request.uri().path(),
                    "management endpoint refused"
                );

                return Ok(Problem::Forbidden(error.to_string()).into_response());
            }

            inner.oneshot(request).await
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{StatusCode, header::AUTHORIZATION},
    };
    use libra_config::management_api::{ManagementAccess, ManagementApi};
    use libra_identity_authenticator::{
        authenticator::{AuthenticationFuture, Authenticator, Recognition},
        bearer_token::BearerToken,
        caller::{CallerKind, CallerProfile},
        refusal::Refusal,
    };
    use libra_log_capture::captured;
    use libra_policy_model::identity::{PolicyIdentity, PrincipalName, RoleName, Subject, Username};
    use pretty_assertions::assert_eq;
    use tower::{service_fn, util::BoxCloneService};

    /// `role_<role>` is the principal `ingest` holding that role; `principal_<name>` is the principal
    /// of that name holding no role; `account_<name>` is the account of that name holding no role,
    /// described the way a JWT caller is, with no username in its profile.
    struct Callers;

    impl Authenticator for Callers {
        fn recognizes(&self, token: BearerToken<'_>) -> Recognition {
            if ["role_", "principal_", "account_"].iter().any(|prefix| token.as_str().starts_with(prefix)) {
                Recognition::Recognized
            } else {
                Recognition::Unrecognized
            }
        }

        fn authenticate<'a>(&'a self, token: BearerToken<'a>) -> AuthenticationFuture<'a> {
            let (name, roles) = match (token.as_str().strip_prefix("principal_"), token.as_str().strip_prefix("account_")) {
                (Some(principal), _) => (IdentityName::Principal(PrincipalName::new(principal).unwrap()), Vec::new()),
                (None, Some(account)) => (IdentityName::Account(Username::new(account).unwrap()), Vec::new()),
                (None, None) => (
                    IdentityName::Principal(PrincipalName::new("ingest").unwrap()),
                    vec![token.as_str().trim_start_matches("role_")],
                ),
            };
            let roles: Result<Vec<RoleName>, Refusal> = roles.into_iter().map(|role| RoleName::new(role).map_err(|_| Refusal::Malformed)).collect();
            let outcome = roles.map(|roles| Authentication {
                identity: PolicyIdentity {
                    name: Some(name),
                    groups: Vec::new(),
                    roles,
                },
                caller: CallerProfile {
                    subject: Some(Subject::new("urn:libra:principal:01J9ZQ4X7K2V3M5N6P8R9S0T1V").unwrap()),
                    kind: CallerKind::Machine,
                    ..CallerProfile::default()
                },
            });

            Box::pin(async move { outcome })
        }
    }

    /// The gate under test: `ops`, `operator` and `libra-admin` are privileged, for reads and writes.
    fn gate(fingerprint: Option<FingerprintKey>) -> BoxCloneService<Request, Response, Infallible> {
        let config = ManagementApi {
            admin_users: vec![Username::new("ops").unwrap()],
            admin_principals: vec![PrincipalName::new("operator").unwrap()],
            admin_roles: vec![RoleName::new("libra-admin").unwrap()],
            ..ManagementApi::default()
        };
        let settings = PrivilegeSettings::for_group(&config, ManagementAccess::Privileged);
        let layer = ManagementAuthLayer::new(Arc::new(Authenticators::new(vec![Arc::new(Callers)])), settings, fingerprint);
        let inner = BoxCloneService::new(service_fn(|_request: Request| async { Ok::<_, Infallible>(Response::new(Body::empty())) }));

        BoxCloneService::new(layer.layer(inner))
    }

    fn request(authorization: &str) -> Request {
        Request::builder()
            .uri("/ngsi-ld/auth/info")
            .header(AUTHORIZATION, authorization)
            .body(Body::empty())
            .unwrap()
    }

    async fn status(authorization: &str) -> StatusCode {
        gate(None).oneshot(request(authorization)).await.unwrap_or_else(|error| match error {}).status()
    }

    #[tokio::test]
    async fn a_refusal_is_logged_by_credential_fingerprint_and_never_by_caller_name() {
        let key = FingerprintKey::new(&[5_u8; 32]);
        let mut request = request("Bearer account_someone");
        request.extensions_mut().insert(AuditSlot::default());

        let (response, records) = captured(gate(Some(key.clone())).oneshot(request)).await; // the test keeps the key to compute the expected fingerprint

        assert_eq!(response.unwrap_or_else(|error| match error {}).status(), StatusCode::FORBIDDEN);
        let refusal = records.iter().find(|record| record.message() == "management endpoint refused").unwrap();
        assert_eq!(refusal.field("credential"), Some(key.fingerprint("account_someone").to_string().as_str()));
        for record in &records {
            assert!(!record.mentions("someone"), "{record:?}");
        }
    }

    #[tokio::test]
    async fn a_machine_holding_an_admin_role_passes_the_gate() {
        assert_eq!(status("Bearer role_libra-admin").await, StatusCode::OK);
    }

    #[tokio::test]
    async fn a_principal_named_in_admin_principals_passes_the_gate() {
        assert_eq!(status("Bearer principal_operator").await, StatusCode::OK);
        assert_eq!(status("Bearer principal_ingest").await, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn an_account_named_in_admin_users_passes_the_gate_without_a_username_in_its_profile() {
        // An account named in `admin-users` passes by that name, although a JWT caller has no username
        // in its profile.
        assert_eq!(status("Bearer account_ops").await, StatusCode::OK);
        assert_eq!(status("Bearer account_someone").await, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn a_principal_is_not_the_account_of_the_same_name() {
        assert_eq!(status("Bearer principal_ops").await, StatusCode::FORBIDDEN);
        assert_eq!(status("Bearer account_operator").await, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn a_machine_without_an_admin_role_is_forbidden() {
        assert_eq!(status("Bearer role_reader").await, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn a_credential_no_authenticator_recognizes_is_unauthorized() {
        assert_eq!(status("Bearer something-else").await, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn a_second_authorization_header_is_refused_even_when_the_first_would_pass() {
        let request = Request::builder()
            .uri("/ngsi-ld/auth/info")
            .header(AUTHORIZATION, "Bearer account_ops")
            .header(AUTHORIZATION, "Bearer account_someone")
            .body(Body::empty())
            .unwrap();

        let response = gate(None).oneshot(request).await.unwrap_or_else(|error| match error {});

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn a_request_without_a_credential_is_unauthorized() {
        let request = Request::builder().uri("/ngsi-ld/auth/info").body(Body::empty()).unwrap();

        let response = gate(None).oneshot(request).await.unwrap_or_else(|error| match error {});

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
