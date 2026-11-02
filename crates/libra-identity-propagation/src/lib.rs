//! The Tower adapter that propagates the authenticated caller to the broker.
//!
//! It is the innermost layer before the request leaves Libra, and it is the only thing that writes
//! an `X-Auth-*` header. The list it writes is [`PROPAGATED_HEADERS`], the same constant
//! `libra-hardening` strips on the way in: one list, so the stripper cannot remove a header nothing
//! produces while leaving one this layer writes. Every header in the list is written or removed on
//! every request, so an unauthenticated request cannot hand the broker a forged value that nothing
//! overwrote.

use axum::{extract::Request, http::HeaderValue, response::Response};
use libra_hardening::identity_headers::{PROPAGATED_HEADER_COUNT, PROPAGATED_HEADERS};
use libra_identity_authenticator::caller::{CallerKind, CallerProfile};
use libra_policy_model::identity::{GroupName, PolicyIdentity, RoleName};
use libra_tenant::Tenant;
use std::task::{Context, Poll};
use tower::{Layer, Service};
use tracing::{debug, warn};

/// Adds the identity headers the broker sees.
#[derive(Debug, Clone, Copy, Default)]
pub struct PropagationLayer;

impl PropagationLayer {
    /// Builds the layer.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl<S> Layer<S> for PropagationLayer {
    type Service = PropagationService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        PropagationService { inner }
    }
}

/// The service produced by [`PropagationLayer`].
#[derive(Debug, Clone)]
pub struct PropagationService<S> {
    inner: S,
}

impl<S> Service<Request> for PropagationService<S>
where
    S: Service<Request, Response = Response>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(&mut self, context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(context)
    }

    /// Adds the headers and forwards. This layer can fail in no way, so it does not box.
    fn call(&mut self, mut request: Request) -> Self::Future {
        inject(&mut request);

        self.inner.call(request)
    }
}

/// Writes the identity headers, one per [`PROPAGATED_HEADERS`] entry.
///
/// Every entry is written or explicitly removed, never left to whatever arrived. The stripping
/// layer above should already have removed any inbound copy, but this layer is what the broker
/// trusts, and it must not depend on another layer having run for that trust to hold.
fn inject(request: &mut Request) {
    // Owned copies, because the values are written into the headers of the request that holds them.
    let caller = request.extensions().get::<CallerProfile>().cloned();
    let tenant = request.extensions().get::<Tenant>().cloned();
    let identity = request.extensions().get::<PolicyIdentity>().cloned();

    let (subject, username, email, machine) = match caller {
        Some(caller) => {
            let machine = match caller.kind {
                CallerKind::Machine => Some("true".to_owned()),
                CallerKind::Unstated => None,
            };
            (
                caller.subject.map(String::from),
                caller.username.map(String::from),
                caller.email.map(String::from),
                machine,
            )
        }
        None => (None, None, None, None),
    };
    let tenant_state = tenant.map(|tenant| match tenant {
        Tenant::Untenanted => "none".to_owned(),
        // The tenant character set excludes `:`, so this is unambiguous to split.
        Tenant::Named(named) => format!("explicit:{named}"),
    });
    // Joined from the validated names, not from the credential: the name types refuse the comma that
    // separates the list, so a group `ops,admins` cannot become two groups at the broker.
    let groups = identity
        .as_ref()
        .map(|identity| join(identity.groups.iter().map(GroupName::as_str)))
        .filter(|joined| !joined.is_empty());
    let roles = identity
        .as_ref()
        .map(|identity| join(identity.roles.iter().map(RoleName::as_str)))
        .filter(|joined| !joined.is_empty());

    // Ordered exactly as PROPAGATED_HEADERS, and destructured so that adding a header to the
    // constant without adding its value here does not compile.
    let values: [Option<String>; PROPAGATED_HEADER_COUNT] = [subject, username, email, tenant_state, groups, roles, machine];

    for (name, value) in PROPAGATED_HEADERS.into_iter().zip(values) {
        let Some(value) = value else {
            // Removed rather than skipped. A header Libra has no value for must not be one the
            // caller supplied.
            request.headers_mut().remove(name);
            continue;
        };

        if let Ok(header) = HeaderValue::from_str(&value) {
            request.headers_mut().insert(name, header);
        } else {
            // A name the identity provider allows and HTTP does not (a non-ASCII display name or
            // address). Removing it is the only safe answer: leaving the previous value in place
            // would attribute the request to whoever the caller said.
            warn!(header = %name, "the identity value is not a legal header value; the header has been removed");
            request.headers_mut().remove(name);
        }
    }

    // The values are not logged: they identify a person, and who made a request is the audit
    // record's to keep.
    debug!("propagated the identity");
}

/// Joins names with the separator the broker splits on.
fn join<'names>(names: impl Iterator<Item = &'names str>) -> String {
    names.collect::<Vec<_>>().join(",")
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use libra_policy_model::identity::{EmailAddress, IdentityName, PrincipalName, Subject, TenantId, Username};
    use pretty_assertions::assert_eq;

    /// A caller as an authenticator hands it over: the policy identity and the profile.
    fn person() -> (PolicyIdentity, CallerProfile) {
        let identity = PolicyIdentity {
            name: Some(IdentityName::Account(Username::new("alice").unwrap())),
            groups: vec![GroupName::new("fleet").unwrap(), GroupName::new("ops").unwrap()],
            roles: vec![RoleName::new("fleet-operator").unwrap()],
        };
        let caller = CallerProfile {
            subject: Some(Subject::new("2b5e-uuid").unwrap()),
            username: Some(Username::new("alice").unwrap()),
            email: Some(EmailAddress::new("alice@example.test").unwrap()),
            client: None,
            kind: CallerKind::Unstated,
        };

        (identity, caller)
    }

    fn inject_into(request: &mut Request) {
        inject(request);
    }

    fn request_with(caller: Option<(PolicyIdentity, CallerProfile)>, tenant: Option<Tenant>, forged: &[(&str, &str)]) -> Request {
        let mut builder = Request::builder().uri("/ngsi-ld/v1/entities");
        for (name, value) in forged {
            builder = builder.header(*name, *value);
        }
        let mut request = builder.body(Body::empty()).unwrap_or_else(|_| Request::new(Body::empty()));

        if let Some((identity, caller)) = caller {
            request.extensions_mut().insert(identity);
            request.extensions_mut().insert(caller);
        }
        if let Some(tenant) = tenant {
            request.extensions_mut().insert(tenant);
        }

        request
    }

    fn header(request: &Request, name: &str) -> Option<String> {
        request.headers().get(name).and_then(|value| value.to_str().ok()).map(str::to_owned)
    }

    #[test]
    fn an_authenticated_request_carries_its_identity() {
        let mut request = request_with(Some(person()), Some(Tenant::Named(TenantId::new("acme").unwrap())), &[]);

        inject_into(&mut request);

        assert_eq!(header(&request, "X-Auth-Subject").as_deref(), Some("2b5e-uuid"));
        assert_eq!(header(&request, "X-Auth-Username").as_deref(), Some("alice"));
        assert_eq!(header(&request, "X-Auth-Email").as_deref(), Some("alice@example.test"));
        assert_eq!(header(&request, "X-Auth-Tenant-State").as_deref(), Some("explicit:acme"));
        assert_eq!(header(&request, "X-Auth-Groups").as_deref(), Some("fleet,ops"));
        assert_eq!(header(&request, "X-Auth-Roles").as_deref(), Some("fleet-operator"));
        assert_eq!(
            header(&request, "X-Auth-Machine"),
            None,
            "a caller not known to be a machine is not said to be one"
        );
    }

    #[test]
    fn an_anonymous_request_carries_no_forged_identity() {
        // With no caller there is nothing to write, and every header must still be overwritten:
        // a header the stripper did not know about would otherwise reach the broker intact.
        let forged = [
            ("X-Auth-Subject", "root"),
            ("X-Auth-Username", "root"),
            ("X-Auth-Tenant-State", "explicit:production"),
            ("X-Auth-Roles", "admin"),
            ("X-Auth-Machine", "true"),
        ];
        let mut request = request_with(None, None, &forged);

        inject_into(&mut request);

        for (name, _) in forged {
            assert_eq!(header(&request, name), None, "{name} must not survive an unauthenticated request");
        }
    }

    #[test]
    fn every_propagated_header_is_written_or_removed() {
        // The invariant that keeps the strip list and the inject list honest: nothing in the
        // constant may be left to whatever the caller sent.
        let mut request = request_with(None, None, &PROPAGATED_HEADERS.each_ref().map(|name| (name.as_str(), "forged")));

        inject_into(&mut request);

        for name in PROPAGATED_HEADERS {
            assert_eq!(header(&request, name.as_str()), None, "{name}");
        }
    }

    #[test]
    fn an_untenanted_request_says_so_rather_than_saying_nothing() {
        let mut request = request_with(Some(person()), Some(Tenant::Untenanted), &[]);

        inject_into(&mut request);

        assert_eq!(header(&request, "X-Auth-Tenant-State").as_deref(), Some("none"));
    }

    #[test]
    fn a_machine_is_marked_as_one() {
        let (identity, mut caller) = person();
        caller.kind = CallerKind::Machine;
        let mut request = request_with(Some((identity, caller)), None, &[]);

        inject_into(&mut request);

        assert_eq!(header(&request, "X-Auth-Machine").as_deref(), Some("true"));
    }

    #[test]
    fn an_api_key_principal_is_propagated_by_its_urn_and_never_as_an_account() {
        // What the API key authenticator produces: the principal's URN as subject, no username
        // and no email, and always a machine.
        let identity = PolicyIdentity {
            name: Some(IdentityName::Principal(PrincipalName::new("ingest").unwrap())),
            groups: vec![GroupName::new("fleet").unwrap()],
            roles: Vec::new(),
        };
        let caller = CallerProfile {
            subject: Some(Subject::new("urn:libra:principal:01J9ZQ4X7K2V3M5N6P8R9S0T1V").unwrap()),
            username: None,
            email: None,
            client: None,
            kind: CallerKind::Machine,
        };
        let forged = [("X-Auth-Email", "forged@example.test"), ("X-Auth-Username", "ingest")];
        let mut request = request_with(Some((identity, caller)), None, &forged);

        inject_into(&mut request);

        assert_eq!(
            header(&request, "X-Auth-Subject").as_deref(),
            Some("urn:libra:principal:01J9ZQ4X7K2V3M5N6P8R9S0T1V")
        );
        assert_eq!(header(&request, "X-Auth-Username"), None);
        assert_eq!(header(&request, "X-Auth-Email"), None);
        assert_eq!(header(&request, "X-Auth-Groups").as_deref(), Some("fleet"));
        assert_eq!(header(&request, "X-Auth-Roles"), None);
        assert_eq!(header(&request, "X-Auth-Machine").as_deref(), Some("true"));
    }

    #[test]
    fn a_value_http_cannot_carry_removes_the_header_rather_than_leaving_the_old_one() {
        // A non-ASCII display name is legal in an identity provider and not in a header. Leaving
        // the caller's own value in place would attribute the request to whoever they said.
        let (identity, mut caller) = person();
        caller.username = Some(Username::new("Ana\u{0142}").unwrap());
        let mut request = request_with(Some((identity, caller)), None, &[("X-Auth-Username", "root")]);

        inject_into(&mut request);

        assert_eq!(header(&request, "X-Auth-Username"), None);
    }
}
