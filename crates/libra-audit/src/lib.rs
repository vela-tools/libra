//! One structured audit line per request, assembled from what the layers above left behind.
//!
//! The record is deliberately shallow. This crate knows nothing about claims, tenants or policies:
//! the layers that do contribute already-checked names through an [`AuditSlot`]. That keeps the
//! audit trail independent of how identity happens to be established, and it means a change to the
//! claim shape cannot silently change what gets audited.
//!
//! # Where the layer goes
//!
//! [`AuditLayer`] sits **above** authentication, tenant resolution and authorization, outermost in
//! the stack, so that it sees the response to every request those layers refuse as well as every
//! request they pass. Below them it would never see a 401, a 403 or a 413, and the audit
//! trail would contain no denial that a security layer produced. The cost is that it cannot read
//! what those layers learn from the request extensions, so it hands them an [`AuditSlot`] on the
//! way in and reads it back when the response arrives.
//!
//! It is also above any decision cache, so a request answered from a cached authorization decision
//! is audited exactly like one that went through the policy engine.
//!
//! # What is never recorded
//!
//! Nothing here touches the `Authorization` header, and the path is recorded without its query
//! string. Query strings on NGSI-LD requests carry entity ids and filter expressions: that is
//! the payload the caller was authorized to see, not metadata about the decision, and an audit
//! sink is usually a lower-trust system than the broker.

use crate::{
    client_ip::ClientIp,
    credential::CredentialFingerprint,
    request_id::RequestId,
    request_path::RequestPath,
    slot::{Access, AuditSlot},
    timestamp::Timestamp,
};
use axum::{
    extract::{ConnectInfo, Request},
    http::{Method, StatusCode},
    response::Response,
};
use libra_policy_model::{
    identity::{Subject, TenantId},
    policy::PolicyId,
};
use serde::Serialize;
use serde_with::{DisplayFromStr, serde_as};
use std::{
    future::Future,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
    time::{Duration, Instant},
};
use strum::Display;
use tower::{Layer, Service, ServiceExt};
use tracing::{field, info, warn};

pub mod client_ip;
pub mod credential;
pub mod request_id;
pub mod request_path;
pub mod slot;
pub mod timestamp;

/// What the request was trying to do, in the coarse terms an auditor reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Display)]
#[serde(rename_all = "lowercase")]
#[strum(serialize_all = "lowercase")]
pub enum AuditAction {
    /// A method that only observes state.
    Read,
    /// A method that creates or changes state.
    Write,
    /// A method that removes state.
    Delete,
    /// Anything else. The `method` field still carries the exact verb.
    Other,
}

impl AuditAction {
    /// Classifies an HTTP method.
    #[must_use]
    pub const fn from_method(method: &Method) -> Self {
        match *method {
            Method::GET | Method::HEAD | Method::OPTIONS | Method::TRACE => Self::Read,
            Method::POST | Method::PUT | Method::PATCH => Self::Write,
            Method::DELETE => Self::Delete,
            _ => Self::Other,
        }
    }
}

/// How the request ended, from an access-control point of view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Display)]
#[serde(rename_all = "UPPERCASE")]
#[strum(serialize_all = "UPPERCASE")]
pub enum AuditOutcome {
    /// The request was served.
    Allowed,
    /// The request was refused because the caller was not allowed to make it.
    Denied,
    /// The request failed for some other reason.
    Error,
}

impl AuditOutcome {
    /// Classifies a response status.
    ///
    /// A 401 or a 403 is a refusal and nothing else; every other client error and every server
    /// error is a failure. Both are distinguished from success, because an audit trail that
    /// records a refused or failed request as allowed is worse than no audit trail: it reports the
    /// opposite of what happened.
    #[must_use]
    pub const fn from_status(status: StatusCode) -> Self {
        match status.as_u16() {
            401 | 403 => Self::Denied,
            400..=599 => Self::Error,
            _ => Self::Allowed,
        }
    }
}

/// Everything about a request that can be known before it is served.
///
/// Read once, on the way in, because the request is moved into the inner service and the response
/// carries none of it back.
#[derive(Debug, Clone)]
pub struct RequestFacts {
    request_id: RequestId,
    method: Method,
    action: AuditAction,
    path: RequestPath,
    client_ip: ClientIp,
    slot: AuditSlot,
}

impl RequestFacts {
    /// Reads the auditable facts out of a request.
    #[must_use]
    pub fn from_request(request: &Request) -> Self {
        let method = request.method();
        let extensions = request.extensions();

        Self {
            request_id: RequestId::from_headers(request.headers()),
            method: method.clone(), // the request is moved into the inner service, so the record keeps its own copy
            action: AuditAction::from_method(method),
            path: RequestPath::of(request.uri()),
            client_ip: extensions.get::<ConnectInfo<SocketAddr>>().map(|connect_info| connect_info.0.ip()).into(),
            slot: AuditSlot::default(),
        }
    }

    /// The slot the layers below write into. It has to be put into the request before it is passed
    /// down.
    #[must_use]
    pub fn slot(&self) -> AuditSlot {
        self.slot.clone() // a handle to the same shared slot, which is the point
    }

    /// Completes the record once the request has been served.
    ///
    /// `status` is `None` when the inner service returned an error instead of a response, so no
    /// status was ever produced.
    #[must_use]
    pub fn into_record(self, status: Option<StatusCode>, elapsed: Duration) -> AuditRecord {
        let contributions = self.slot.contributions();

        AuditRecord {
            timestamp: Timestamp::now(),
            request_id: self.request_id,
            subject: contributions.subject,
            credential: contributions.credential,
            tenant: contributions.tenant,
            policy: contributions.policy,
            method: self.method,
            path: self.path,
            action: self.action,
            outcome: status.map_or(AuditOutcome::Error, AuditOutcome::from_status),
            status_code: status.map(|status| status.as_u16()),
            client_ip: self.client_ip,
            access: contributions.access,
            // Saturating rather than truncating: a request that somehow ran for 584 million years
            // should be reported as absurdly long, not as three milliseconds.
            duration_ms: u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
        }
    }
}

/// One audited request.
///
/// The values with a textual wire form of their own are written through their [`Display`](std::fmt::Display)
/// spelling.
#[serde_as]
#[derive(Debug, Clone, Serialize)]
pub struct AuditRecord {
    /// When the record was completed, RFC 3339.
    #[serde_as(as = "DisplayFromStr")]
    pub timestamp: Timestamp,
    /// The correlation id from `x-request-id`, or `-`.
    #[serde_as(as = "DisplayFromStr")]
    pub request_id: RequestId,
    /// The authenticated caller, absent for anonymous requests.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<Subject>,
    /// The fingerprint of the credential presented, absent when there was none or the deployment
    /// configured no key to compute it with.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential: Option<CredentialFingerprint>,
    /// The tenant the request was resolved against, absent when it named none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant: Option<TenantId>,
    /// The policy that decided the request, absent when none matched or the request was refused
    /// before authorization.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<PolicyId>,
    /// The HTTP method.
    #[serde_as(as = "DisplayFromStr")]
    pub method: Method,
    /// The request path, without its query string.
    #[serde_as(as = "DisplayFromStr")]
    pub path: RequestPath,
    /// The method reduced to read, write or delete.
    pub action: AuditAction,
    /// Whether the request was allowed, refused, or failed.
    pub outcome: AuditOutcome,
    /// The response status, absent when the inner service failed without producing a response.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_code: Option<u16>,
    /// The peer address, or `-` when the server was built without connection info.
    #[serde_as(as = "DisplayFromStr")]
    pub client_ip: ClientIp,
    /// Whether the caller's credentials or a public-access rule let this through.
    pub access: Access,
    /// How long the request took, in milliseconds.
    pub duration_ms: u64,
}

/// Emits one record as a set of individual tracing fields.
///
/// The fields are written one by one and never as a serialised blob. Serialising the record into a
/// single field means that under the JSON log format the value arrives as a JSON string containing
/// JSON, which every consumer then has to unwrap twice, and which silently becomes an empty
/// string if serialisation ever fails.
macro_rules! emit_record {
    ($emit:ident, $message:literal, $record:expr) => {
        $emit!(
            timestamp = %$record.timestamp,
            request_id = %$record.request_id,
            subject = $record.subject.as_ref().map(field::display),
            credential = $record.credential.as_ref().map(field::display),
            tenant = $record.tenant.as_ref().map(field::display),
            policy = $record.policy.as_ref().map(field::display),
            method = %$record.method,
            path = %$record.path,
            action = %$record.action,
            outcome = %$record.outcome,
            status_code = $record.status_code,
            client_ip = %$record.client_ip,
            access = %$record.access,
            duration_ms = $record.duration_ms,
            $message
        )
    };
}

/// Writes a record to the log at the level its outcome deserves.
///
/// A denial is not routine traffic. Recording it at `info` puts it below the level most
/// deployments actually ship, which turns "someone was refused" into a line nobody ever sees:
/// the one line the audit trail exists for.
pub fn emit(record: &AuditRecord) {
    // The message text is fixed per outcome, so a log query can match on it; the level varies with
    // the outcome.
    match record.outcome {
        AuditOutcome::Allowed => emit_record!(info, "AUDIT_SUCCESS", record),
        AuditOutcome::Denied => emit_record!(warn, "AUDIT_DENIED", record),
        AuditOutcome::Error => emit_record!(warn, "AUDIT_ERROR", record),
    }
}

/// Layer that records one audit line per request.
#[derive(Debug, Clone, Copy, Default)]
pub struct AuditLayer;

impl AuditLayer {
    /// Builds the layer.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl<S> Layer<S> for AuditLayer {
    type Service = AuditService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AuditService { inner }
    }
}

/// The service produced by [`AuditLayer`].
#[derive(Debug, Clone)]
pub struct AuditService<S> {
    inner: S,
}

impl<S, E> Service<Request> for AuditService<S>
where
    S: Service<Request, Response = Response, Error = E> + Clone + Send + 'static,
    S::Future: Send + 'static,
    E: Send + 'static,
{
    type Response = Response;
    type Error = E;
    type Future = Pin<Box<dyn Future<Output = Result<Response, E>> + Send>>;

    /// Always ready: readiness is driven by `ServiceExt::oneshot` on the clone taken in `call`.
    fn poll_ready(&mut self, _context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, mut request: Request) -> Self::Future {
        let inner = self.inner.clone();
        let started = Instant::now();
        let facts = RequestFacts::from_request(&request);
        request.extensions_mut().insert(facts.slot());

        Box::pin(async move {
            let result = inner.oneshot(request).await;

            // Both arms record. An enforcement layer that refuses by returning an error rather
            // than a response would otherwise propagate straight past this layer, and the denial
            // it exists to capture would never be written down.
            match result {
                Ok(response) => {
                    let status = response.status();
                    emit(&facts.into_record(Some(status), started.elapsed()));
                    Ok(response)
                }
                Err(error) => {
                    emit(&facts.into_record(None, started.elapsed()));
                    Err(error)
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{credential::FingerprintKey, request_id::REQUEST_ID_HEADER};
    use axum::{body::Body, http::header::AUTHORIZATION};
    use libra_log_capture::{Emitted, Kind, captured};
    use pretty_assertions::assert_eq;
    use tracing::Level;

    const REQUEST_ID: &str = "67e55044-10b1-426f-9247-bb680e5fe0c8";

    /// An inner service that answers with a fixed status, or fails, after telling the audit slot
    /// whatever `contribute` says, as the authentication and authorization layers do.
    #[derive(Clone)]
    struct Inner {
        status: Option<StatusCode>,
        contribute: fn(&AuditSlot),
    }

    /// What authentication, tenant resolution and authorization contribute for an ordinary caller.
    fn alice_in_acme(slot: &AuditSlot) {
        slot.record_subject(Subject::new("alice").unwrap());
        slot.record_credential(FingerprintKey::new(&[2_u8; 32]).fingerprint("alice's token"));
        slot.record_tenant(TenantId::new("acme").unwrap());
        slot.record_policy(PolicyId::new("fleet-read").unwrap());
    }

    /// A layer that learned nothing, as when the request was refused before any of them ran.
    fn nothing_learned(_slot: &AuditSlot) {}

    /// An anonymous request let through by the public-access rule.
    fn anonymous_public(slot: &AuditSlot) {
        slot.record_access(Access::Public);
    }

    impl Service<Request> for Inner {
        type Response = Response;
        type Error = &'static str;
        type Future = Pin<Box<dyn Future<Output = Result<Response, &'static str>> + Send>>;

        fn poll_ready(&mut self, _context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, request: Request) -> Self::Future {
            let status = self.status;
            if let Some(slot) = request.extensions().get::<AuditSlot>() {
                (self.contribute)(slot);
            }
            Box::pin(async move {
                match status {
                    Some(status) => Ok(Response::builder().status(status).body(Body::empty()).unwrap()),
                    None => Err("the inner service refused"),
                }
            })
        }
    }

    fn request() -> Request {
        let mut request = Request::builder()
            .method(Method::GET)
            .uri("/ngsi-ld/v1/entities?type=Vehicle&id=urn:ngsi-ld:Vehicle:secret")
            .header(REQUEST_ID_HEADER, REQUEST_ID)
            .body(Body::empty())
            .unwrap();
        request.extensions_mut().insert(ConnectInfo("10.0.0.7:4711".parse::<SocketAddr>().unwrap()));
        request
    }

    /// Runs one request through the layer and returns everything it logged.
    async fn audited(status: Option<StatusCode>, request: Request) -> Vec<Emitted> {
        audited_with(status, alice_in_acme, request).await
    }

    /// As [`audited`], with the layers below contributing whatever `contribute` says.
    async fn audited_with(status: Option<StatusCode>, contribute: fn(&AuditSlot), request: Request) -> Vec<Emitted> {
        let service = AuditLayer::new().layer(Inner { status, contribute });
        let (_, records) = captured(service.oneshot(request)).await;

        records.into_iter().filter(|record| record.kind == Kind::Event).collect()
    }

    #[tokio::test]
    async fn an_allowed_request_is_recorded_at_info() {
        let events = audited(Some(StatusCode::OK), request()).await;

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].level, Level::INFO);
        assert_eq!(events[0].message(), "AUDIT_SUCCESS");
        assert_eq!(events[0].field("outcome"), Some("ALLOWED"));
    }

    #[tokio::test]
    async fn a_denied_request_is_recorded_at_warn_and_not_at_info() {
        // A denial is logged above info: a denial below the shipped log level is a denial nobody ever
        // reads.
        for status in [StatusCode::UNAUTHORIZED, StatusCode::FORBIDDEN] {
            let events = audited(Some(status), request()).await;

            assert_eq!(events.len(), 1);
            assert_eq!(events[0].level, Level::WARN, "{status} must be recorded at warn");
            assert_eq!(events[0].message(), "AUDIT_DENIED");
            assert_eq!(events[0].field("outcome"), Some("DENIED"));
        }
    }

    #[tokio::test]
    async fn a_client_error_is_not_recorded_as_a_success() {
        // A 4xx that is not 401 or 403 is recorded as a failure, so a wall of rejected requests does
        // not read as a wall of served ones.
        for status in [
            StatusCode::BAD_REQUEST,
            StatusCode::NOT_FOUND,
            StatusCode::CONFLICT,
            StatusCode::TOO_MANY_REQUESTS,
        ] {
            let events = audited(Some(status), request()).await;

            assert_eq!(events.len(), 1);
            assert_eq!(events[0].field("outcome"), Some("ERROR"), "{status} must not be recorded as allowed");
            assert_eq!(events[0].message(), "AUDIT_ERROR");
            assert_eq!(events[0].level, Level::WARN);
        }
    }

    #[tokio::test]
    async fn a_server_error_is_recorded_as_an_error_at_warn() {
        let events = audited(Some(StatusCode::INTERNAL_SERVER_ERROR), request()).await;

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].level, Level::WARN);
        assert_eq!(events[0].message(), "AUDIT_ERROR");
    }

    #[tokio::test]
    async fn a_failing_inner_service_is_still_recorded() {
        // Enforcement layers below this one refuse by returning an error rather than a response, so
        // the record is written on the Err path as well.
        let events = audited(None, request()).await;

        assert_eq!(events.len(), 1, "an inner failure must still produce exactly one record");
        assert_eq!(events[0].level, Level::WARN);
        assert_eq!(events[0].field("outcome"), Some("ERROR"));
        assert_eq!(events[0].field("status_code"), None, "no response means no status to report");
    }

    #[tokio::test]
    async fn the_record_is_emitted_as_individual_fields_and_not_as_one_json_blob() {
        // The record is emitted as individual fields. A single serialised `audit` field would arrive
        // double-encoded under the JSON log format, and every consumer would have to parse the line and
        // then a string inside it.
        let events = audited(Some(StatusCode::OK), request()).await;

        assert_eq!(events[0].field("audit"), None, "the record must not be collapsed into one field");
        assert_eq!(events[0].field("request_id"), Some(REQUEST_ID));
        assert_eq!(events[0].field("subject"), Some("alice"));
        let credential = FingerprintKey::new(&[2_u8; 32]).fingerprint("alice's token").to_string();
        assert_eq!(
            events[0].field("credential"),
            Some(credential.as_str()),
            "the fingerprint is the digest the authentication layer computed, and not the credential"
        );
        assert_eq!(events[0].field("tenant"), Some("acme"));
        assert_eq!(events[0].field("method"), Some("GET"));
        assert_eq!(events[0].field("action"), Some("read"));
        assert_eq!(events[0].field("status_code"), Some("200"));
        assert_eq!(events[0].field("client_ip"), Some("10.0.0.7"));
        assert_eq!(events[0].field("access"), Some("credentialed"));
        assert!(events[0].field("duration_ms").is_some());
        assert!(events[0].field("timestamp").is_some());
    }

    #[tokio::test]
    async fn no_credential_ever_reaches_the_record() {
        let mut request = request();
        request
            .headers_mut()
            .insert(AUTHORIZATION, "Bearer eyJhbGciOiJSUzI1NiJ9.super-secret-token".parse().unwrap());

        let events = audited(Some(StatusCode::OK), request).await;

        assert!(
            !events[0].mentions("super-secret-token") && !events[0].mentions("Bearer"),
            "a field leaked the Authorization header: {:?}",
            events[0]
        );
    }

    #[tokio::test]
    async fn the_query_string_is_not_recorded() {
        // Query strings carry entity ids and filter values: the data the caller was authorized
        // for, which the audit sink is not.
        let events = audited(Some(StatusCode::OK), request()).await;

        assert_eq!(events[0].field("path"), Some("/ngsi-ld/v1/entities"));
        assert!(
            !events[0].mentions("urn:ngsi-ld:Vehicle:secret"),
            "a field leaked the query string: {:?}",
            events[0]
        );
    }

    #[tokio::test]
    async fn a_request_nobody_contributed_to_is_recorded_as_anonymous() {
        let request = Request::builder()
            .method(Method::DELETE)
            .uri("/ngsi-ld/v1/entities/urn:x")
            .body(Body::empty())
            .unwrap();

        let events = audited_with(Some(StatusCode::NO_CONTENT), nothing_learned, request).await;

        assert_eq!(events[0].field("subject"), None);
        assert_eq!(events[0].field("tenant"), None);
        assert_eq!(events[0].field("request_id"), Some("-"));
        assert_eq!(events[0].field("client_ip"), Some("-"));
        assert_eq!(events[0].field("action"), Some("delete"));
    }

    #[tokio::test]
    async fn public_access_is_recorded_when_a_layer_says_so() {
        let events = audited_with(Some(StatusCode::OK), anonymous_public, request()).await;

        assert_eq!(events[0].field("access"), Some("public"));
        assert_eq!(events[0].field("subject"), None);
    }

    #[tokio::test]
    async fn the_policy_that_decided_the_request_is_recorded() {
        let events = audited(Some(StatusCode::OK), request()).await;

        assert_eq!(events[0].field("policy"), Some("fleet-read"));
    }

    #[tokio::test]
    async fn a_refusal_by_a_layer_that_learned_nothing_is_still_a_denial_record() {
        // Authentication refusing a request produces a 401 before tenant or authorization ran, so
        // the record has no subject, tenant or policy. It must exist all the same: it is the line
        // the audit trail is for.
        let events = audited_with(Some(StatusCode::UNAUTHORIZED), nothing_learned, request()).await;

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].message(), "AUDIT_DENIED");
        assert_eq!(events[0].field("subject"), None);
        assert_eq!(events[0].field("policy"), None);
    }

    #[test]
    fn the_outcome_of_a_status_is_classified_honestly() {
        assert_eq!(AuditOutcome::from_status(StatusCode::OK), AuditOutcome::Allowed);
        assert_eq!(AuditOutcome::from_status(StatusCode::NO_CONTENT), AuditOutcome::Allowed);
        assert_eq!(AuditOutcome::from_status(StatusCode::NOT_MODIFIED), AuditOutcome::Allowed);
        assert_eq!(AuditOutcome::from_status(StatusCode::UNAUTHORIZED), AuditOutcome::Denied);
        assert_eq!(AuditOutcome::from_status(StatusCode::FORBIDDEN), AuditOutcome::Denied);
        assert_eq!(AuditOutcome::from_status(StatusCode::BAD_REQUEST), AuditOutcome::Error);
        assert_eq!(AuditOutcome::from_status(StatusCode::NOT_FOUND), AuditOutcome::Error);
        assert_eq!(AuditOutcome::from_status(StatusCode::BAD_GATEWAY), AuditOutcome::Error);
    }

    #[test]
    fn the_action_follows_the_method() {
        assert_eq!(AuditAction::from_method(&Method::GET), AuditAction::Read);
        assert_eq!(AuditAction::from_method(&Method::HEAD), AuditAction::Read);
        assert_eq!(AuditAction::from_method(&Method::OPTIONS), AuditAction::Read);
        assert_eq!(AuditAction::from_method(&Method::POST), AuditAction::Write);
        assert_eq!(AuditAction::from_method(&Method::PUT), AuditAction::Write);
        assert_eq!(AuditAction::from_method(&Method::PATCH), AuditAction::Write);
        assert_eq!(AuditAction::from_method(&Method::DELETE), AuditAction::Delete);
        assert_eq!(AuditAction::from_method(&Method::CONNECT), AuditAction::Other);
    }

    #[test]
    fn the_serialized_record_keeps_its_field_names_and_spellings() {
        let facts = RequestFacts::from_request(&request());
        alice_in_acme(&facts.slot());

        let record = serde_json::to_value(facts.into_record(Some(StatusCode::OK), Duration::from_millis(12))).unwrap();

        assert_eq!(record["request_id"], REQUEST_ID);
        assert_eq!(record["subject"], "alice");
        assert_eq!(record["tenant"], "acme");
        assert_eq!(record["policy"], "fleet-read");
        assert_eq!(record["method"], "GET");
        assert_eq!(record["path"], "/ngsi-ld/v1/entities");
        assert_eq!(record["action"], "read");
        assert_eq!(record["outcome"], "ALLOWED");
        assert_eq!(record["status_code"], 200);
        assert_eq!(record["client_ip"], "10.0.0.7");
        assert_eq!(record["access"], "credentialed");
        assert_eq!(record["duration_ms"], 12);
        assert!(record["timestamp"].as_str().unwrap().ends_with("+00:00"));
    }

    #[test]
    fn an_unidentified_request_serializes_dashes_and_omits_what_nobody_contributed() {
        let bare = Request::builder().uri("/").body(Body::empty()).unwrap();

        let record = serde_json::to_value(RequestFacts::from_request(&bare).into_record(None, Duration::ZERO)).unwrap();

        assert_eq!(record["request_id"], "-");
        assert_eq!(record["client_ip"], "-");
        assert_eq!(record["outcome"], "ERROR");
        assert!(record.get("subject").is_none());
        assert!(record.get("tenant").is_none());
        assert!(record.get("policy").is_none());
        assert!(record.get("status_code").is_none());
    }
}
