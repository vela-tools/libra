//! The Tower layer that keeps a request inside the scopes its policy allows.
//!
//! What the request carries or asks for is checked and narrowed in [`crate::request`]; this layer
//! decides whether a restriction applies, refuses what no narrowing can fix, and filters the
//! response.
//!
//! What a query answers with is judged entity by entity on the way back: an entity no allowed scope
//! covers, or one with no scope at all, is withheld from the answer, as a read of it by identifier
//! is refused. Entity maps, by path or by the `NGSILD-EntityMap` header, context source
//! subscriptions and existing subscriptions are refused whole; creating a subscription stays
//! possible, narrowed to the restriction.
//!
//! A request whose decision carries no scope restriction passes through untouched. That is safe
//! only because of where this layer sits: below `libra-policy-layer`, which has already refused
//! anything the policy set does not allow and attached its decision to everything else. A request
//! carrying no decision at all is one nobody authorized, and is refused as a wiring fault rather than
//! passed through.

use crate::{
    error::ScopeError,
    registration,
    request::{enforce, filters_response},
    response,
};
use axum::{
    extract::Request,
    http::header::ACCEPT_ENCODING,
    response::{IntoResponse, Response},
};
use libra_enforcement_member::{
    linked_join::{Answer, linked_join},
    unnarrowable::{Unnarrowable, refuse_unnarrowable},
};
use libra_entity_preflight::preflight::Preflight;
use libra_ngsi_ld_operation::{
    entity_map::names_entity_map,
    operation::{Mode, Operation},
    target::EntityTarget,
};
use libra_ngsi_ld_operation_layer::classified::operation;
use libra_ngsi_ld_query::entity_member::EntityMember;
use libra_policy_engine::decision::Decision;
use libra_policy_model::scope::ScopeRestriction;
use std::{
    convert::Infallible,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tower::{Layer, Service, ServiceExt};
use tracing::{error, warn};

/// Enforces a policy's scope restriction.
#[derive(Debug, Clone)]
pub struct ScopeEnforcementLayer {
    preflight: Arc<Preflight>,
    max_body_bytes: usize,
}

impl ScopeEnforcementLayer {
    /// Builds the layer.
    ///
    /// `preflight` asks the broker the request is about to be forwarded to. It is shared with the
    /// other layer that pre-flights, so the proxy holds one pool of connections to the broker for
    /// both. `max_body_bytes` bounds the upstream answers this layer reads, and should be the limit
    /// the payload-limit layer enforces; request bodies are read once, above it, by the context
    /// layer.
    #[must_use]
    pub const fn new(preflight: Arc<Preflight>, max_body_bytes: usize) -> Self {
        Self { preflight, max_body_bytes }
    }
}

impl<S> Layer<S> for ScopeEnforcementLayer {
    type Service = ScopeEnforcementService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ScopeEnforcementService {
            inner,
            preflight: Arc::clone(&self.preflight),
            max_body_bytes: self.max_body_bytes,
        }
    }
}

/// The service produced by [`ScopeEnforcementLayer`].
#[derive(Debug, Clone)]
pub struct ScopeEnforcementService<S> {
    inner: S,
    preflight: Arc<Preflight>,
    max_body_bytes: usize,
}

impl<S> Service<Request> for ScopeEnforcementService<S>
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

    fn call(&mut self, request: Request) -> Self::Future {
        let inner = self.inner.clone();
        let preflight = Arc::clone(&self.preflight);
        let max_body_bytes = self.max_body_bytes;

        Box::pin(async move {
            match apply(inner, request, &preflight, max_body_bytes).await {
                Ok(response) => Ok(response),
                Err(error) => {
                    warn!(error = %error, "scope enforcement refused the request");

                    Ok(error.to_problem().into_response())
                }
            }
        })
    }
}

/// Brings the request inside the allowed scopes, then forwards it.
async fn apply<S>(inner: S, request: Request, preflight: &Preflight, max_body_bytes: usize) -> Result<Response, ScopeError>
where
    S: Service<Request, Response = Response, Error = Infallible> + Send + 'static,
    S::Future: Send + 'static,
{
    let Some(decision) = request.extensions().get::<Decision>() else {
        // The authorization layer attaches a decision to every request it lets through, so one
        // arriving here without it is one nobody authorized.
        error!("a request reached scope enforcement without an authorization decision: the layer is wired above authorization");

        return Err(ScopeError::Undecided);
    };

    // A reference count, not a copy: the request that owns the decision is moved into the rewrite and forward steps while the restriction is still read.
    let Some(restriction) = decision.scope.clone() else {
        // The policy that allowed this request placed no scope condition on it.
        return Ok(forward(inner, request).await);
    };

    // `ScopeRestriction` refuses an empty allow list when the policy loads. It is checked again
    // because an empty list has no expression to emit, and `scopeQ=` is read by brokers as no
    // filter at all.
    if restriction.allowed.is_empty() {
        return Err(ScopeError::EmptyAllowList);
    }

    if names_entity_map(request.headers()) {
        // Whatever the request is, the broker answers it from the entities the map lists, which no
        // narrowing of the request's own `scopeQ` reaches.
        return Err(Unnarrowable::EntityMap.into());
    }

    // Cloned because the request it travels in is moved into the checks below while it is still read.
    let operation = operation(request.extensions())?.clone();

    if operation.resource.is_context_source_registration() {
        let request = registration::check_request(request, &operation, &restriction, preflight).await?;
        let response = forward(inner, request).await;

        return match operation.mode {
            Mode::Read => registration::filter_response(response, &operation.resource, &restriction.allowed, max_body_bytes).await,
            Mode::Write => Ok(response),
        };
    }

    refuse_unnarrowable(&operation)?;

    if !operation.resource.is_entity_shaped() && !operation.resource.is_subscription() {
        // Not a path that carries entity data or a subscription.
        return Ok(forward(inner, request).await);
    }

    enforce_entities(inner, request, &operation, &restriction, preflight, max_body_bytes).await
}

/// Narrows a request about entities or a subscription, forwards it, and judges the entities of the
/// answer.
async fn enforce_entities<S>(
    inner: S,
    request: Request,
    operation: &Operation,
    restriction: &ScopeRestriction,
    preflight: &Preflight,
    max_body_bytes: usize,
) -> Result<Response, ScopeError>
where
    S: Service<Request, Response = Response, Error = Infallible> + Send + 'static,
    S::Future: Send + 'static,
{
    let join = linked_join(request.extensions(), operation, EntityMember::Scope, answer(operation))?;

    let mut request = enforce(request, operation, restriction, preflight).await?;

    if !filters_response(operation) {
        return Ok(forward(inner, request).await);
    }

    // A compressed body cannot be rewritten, so the broker is asked for an identity encoding.
    request.headers_mut().remove(ACCEPT_ENCODING);

    let response = forward(inner, request).await;

    if EntityTarget::of(operation).answers_with_entities() {
        return response::filter_query_response(response, &restriction.allowed, join, max_body_bytes).await;
    }

    response::filter_response(response, &restriction.allowed, join, max_body_bytes).await
}

/// Whether the answer to an operation is judged entity by entity on the way back.
///
/// Every answer whose entities are filtered to the allowed scopes is, and the linked entities of a
/// join answer, in whatever scope their Relationships point into, are judged with them.
const fn answer(operation: &Operation) -> Answer {
    if filters_response(operation) { Answer::Judged } else { Answer::Unjudged }
}

/// Hands the request to the inner service.
async fn forward<S>(inner: S, request: Request) -> Response
where
    S: Service<Request, Response = Response, Error = Infallible> + Send + 'static,
    S::Future: Send + 'static,
{
    inner.oneshot(request).await.unwrap_or_else(|error| match error {})
}

#[cfg(test)]
mod tests {
    mod answers;
    mod refusals;
    mod stored_entities;

    use super::*;
    use axum::body::Body;
    use http::{
        HeaderValue,
        Method,
        StatusCode,
        header::{CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE},
    };
    use http_body_util::BodyExt;
    use jstrict::{Print, Value, json, object::Key};
    use libra_config::representation::RepresentationStrictness;
    use libra_json_body::{request_body::RequestBody, strict};
    use libra_linked_entity_layer::layer::LinkedEntityLayer;
    use libra_ngsi_ld_operation_layer::layer::{OperationLayer, classify};
    use libra_ngsi_ld_query::{parameter_name::ParameterName, parameters::QueryParameters};
    use libra_ngsi_ld_query_layer::layer::{QueryLayer, read_query};
    use libra_ngsi_ld_representation_layer::RepresentationLayer;
    use libra_policy_model::{
        effect::Effect,
        member_on_write::MemberOnWrite,
        scope::{ScopePattern, ScopeRestriction},
    };
    use pretty_assertions::assert_eq;
    use std::sync::{Mutex, PoisonError};
    use tower::util::BoxCloneService;
    use url::Url;
    use wiremock::{
        Mock,
        MockServer,
        ResponseTemplate,
        matchers::{any, header},
    };

    const ENTITY: &str = "urn:ngsi-ld:Vehicle:1";

    fn restriction(allowed: &[&str], scope_on_write: MemberOnWrite) -> ScopeRestriction {
        ScopeRestriction {
            allowed: allowed
                .iter()
                .map(|value| ScopePattern::new(*value).expect("the test pattern should be well formed"))
                .collect(),
            scope_on_write,
        }
    }

    fn decision(restriction: ScopeRestriction) -> Decision {
        Decision {
            effect: Effect::Allow,
            matched: None,
            scope: Some(Arc::new(restriction)),
            entity_type: None,
            time: None,
            attribute: None,
            aggregation: None,
        }
    }

    /// What the upstream saw, so a test can assert on the request that was forwarded.
    #[derive(Clone, Default)]
    struct Seen {
        uri: Arc<Mutex<Option<String>>>,
        body: Arc<Mutex<String>>,
        accept_encoding: Arc<Mutex<bool>>,
    }

    impl Seen {
        fn uri(&self) -> Option<String> {
            self.uri.lock().unwrap_or_else(PoisonError::into_inner).as_deref().map(str::to_owned)
        }

        fn body(&self) -> String {
            self.body.lock().unwrap_or_else(PoisonError::into_inner).to_owned()
        }

        fn accept_encoding_was_sent(&self) -> bool {
            *self.accept_encoding.lock().unwrap_or_else(PoisonError::into_inner)
        }

        fn scope_filter(&self) -> Option<String> {
            let uri = self.uri()?;
            let query = uri.split_once('?').map(|(_, query)| query).unwrap_or_default();

            QueryParameters::parse(query).ok()?.get(&ParameterName::SCOPE_Q).map(str::to_owned)
        }
    }

    /// What the stand-in upstream answers with.
    #[derive(Clone)]
    struct Reply {
        status: StatusCode,
        content_type: Option<&'static str>,
        content_encoding: Option<&'static str>,
        body: String,
    }

    impl Reply {
        fn json(body: &Value) -> Self {
            Self {
                status: StatusCode::OK,
                content_type: Some("application/json"),
                content_encoding: None,
                body: body.to_string(),
            }
        }
    }

    /// A stand-in for everything below this layer.
    fn upstream_replying(seen: &Seen, reply: Reply) -> BoxCloneService<Request, Response, Infallible> {
        let uri = Arc::clone(&seen.uri);
        let body = Arc::clone(&seen.body);
        let accept_encoding = Arc::clone(&seen.accept_encoding);
        BoxCloneService::new(tower::service_fn(move |request: Request| {
            let uri = Arc::clone(&uri);
            let body = Arc::clone(&body);
            let accept_encoding = Arc::clone(&accept_encoding);
            // Cloned per call because the service answers every request with the same reply.
            let reply = reply.clone();
            async move {
                *uri.lock().unwrap_or_else(PoisonError::into_inner) = Some(request.uri().to_string());
                *accept_encoding.lock().unwrap_or_else(PoisonError::into_inner) = request.headers().contains_key(ACCEPT_ENCODING);

                let bytes = request.into_body().collect().await.map(http_body_util::Collected::to_bytes).unwrap_or_default();
                *body.lock().unwrap_or_else(PoisonError::into_inner) = String::from_utf8_lossy(&bytes).into_owned();

                let mut builder = Response::builder().status(reply.status);
                if let Some(content_type) = reply.content_type {
                    builder = builder.header(CONTENT_TYPE, content_type);
                }
                if let Some(encoding) = reply.content_encoding {
                    builder = builder.header(CONTENT_ENCODING, encoding);
                }

                Ok(builder.body(Body::from(reply.body)).unwrap_or_else(|_| Response::new(Body::empty())))
            }
        }))
    }

    /// A request as the layers above leave it, with its body read once.
    fn request(method: Method, uri: &str, decision: Option<Decision>, body: &str) -> Request {
        let mut request = Request::builder()
            .method(method)
            .uri(uri)
            .header(CONTENT_TYPE, "application/json")
            .header("NGSILD-Tenant", "acme")
            .header("Link", "<https://example.test/context.jsonld>; rel=\"http://www.w3.org/ns/json-ld#context\"")
            .body(Body::from(body.to_owned()))
            .unwrap_or_else(|_| Request::new(Body::empty()));

        request
            .extensions_mut()
            .insert(RequestBody::read(body.as_bytes()).expect("the test body should read"));

        if let Some(decision) = decision {
            request.extensions_mut().insert(decision);
        }

        request
    }

    /// A broker that answers every pre-flight with the same entity document.
    async fn broker(body: Value) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(any()).respond_with(json_response(&body)).mount(&server).await;

        server
    }

    /// A broker that answers every pre-flight with a status and no usable entity.
    async fn failing_broker(status: u16) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(any()).respond_with(ResponseTemplate::new(status)).mount(&server).await;

        server
    }

    /// A broker answer carrying a JSON document.
    fn json_response(body: &Value) -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_raw(body.compact_print().to_string(), "application/json")
    }

    /// A member of an answer, read as the code under test reads it.
    fn member<'v>(document: &'v Value, name: &str) -> Option<&'v Value> {
        document.as_object()?.get_unique(name).ok()?
    }

    fn scoped(scope: Value) -> Value {
        json!({ "id": ENTITY, "type": "Vehicle", "scope": scope })
    }

    async fn run(broker_url: &str, request: Request, seen: &Seen) -> Response {
        run_replying(broker_url, request, seen, Reply::json(&json!([]))).await
    }

    /// The layer under the four that resolve, above authorization, what it reads.
    async fn run_replying(broker_url: &str, request: Request, seen: &Seen, reply: Reply) -> Response {
        let scope = ScopeEnforcementLayer::new(
            Arc::new(Preflight::new(Url::parse(broker_url).expect("a URL"), 64 * 1024).expect("the client should build")),
            64 * 1024,
        );
        let mut service = OperationLayer::new().layer(QueryLayer::new().layer(
            LinkedEntityLayer::new().layer(RepresentationLayer::new(RepresentationStrictness::default()).layer(scope.layer(upstream_replying(seen, reply)))),
        ));

        service.call(request).await.unwrap_or_else(|error| match error {})
    }

    async fn body_json(response: Response) -> Value {
        let bytes = response
            .into_body()
            .collect()
            .await
            .map(http_body_util::Collected::to_bytes)
            .unwrap_or_default();

        strict::parse(&bytes).expect("the response body should be JSON")
    }

    fn allow_decision() -> Decision {
        decision(restriction(&["/Madrid/#"], MemberOnWrite::Required))
    }

    /// The decision of a policy that placed no condition on the request.
    fn unrestricted() -> Decision {
        Decision {
            effect: Effect::Allow,
            matched: None,
            scope: None,
            entity_type: None,
            time: None,
            attribute: None,
            aggregation: None,
        }
    }

    fn by_id() -> String {
        format!("/ngsi-ld/v1/entities/{ENTITY}")
    }

    #[tokio::test]
    async fn a_request_with_no_restriction_passes_through_untouched() {
        let seen = Seen::default();
        let response = run(
            "http://127.0.0.1:1",
            request(Method::GET, "/ngsi-ld/v1/entities?type=Vehicle", Some(unrestricted()), ""),
            &seen,
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(seen.uri().as_deref(), Some("/ngsi-ld/v1/entities?type=Vehicle"));
    }

    #[tokio::test]
    async fn a_read_of_one_entity_by_id_is_checked_rather_than_filtered_by_a_parameter_the_broker_ignores() {
        // NGSI-LD defines no scope filter for retrieve-by-id, so appending `scopeQ=` to
        // `GET /entities/{id}` would be ignored by every broker and any entity would be readable by id
        // whatever its scope. The entity's scope is pre-flighted instead.
        let server = broker(scoped(json!("/Barcelona/Port"))).await;
        let seen = Seen::default();

        let response = run(
            &server.uri(),
            request(
                Method::GET,
                &format!("/ngsi-ld/v1/entities/{ENTITY}"),
                Some(decision(restriction(&["/Madrid/#"], MemberOnWrite::Required))),
                "",
            ),
            &seen,
        )
        .await;

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(seen.uri(), None, "the request must not reach the broker at all");
    }

    #[tokio::test]
    async fn a_read_of_one_entity_inside_the_restriction_is_forwarded_unchanged() {
        let server = broker(scoped(json!("/Madrid/Gardens/ParqueNorte"))).await;
        let seen = Seen::default();

        let response = run(
            &server.uri(),
            request(
                Method::GET,
                &format!("/ngsi-ld/v1/entities/{ENTITY}"),
                Some(decision(restriction(&["/Madrid/#"], MemberOnWrite::Required))),
                "",
            ),
            &seen,
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            seen.uri().as_deref(),
            Some(format!("/ngsi-ld/v1/entities/{ENTITY}").as_str()),
            "retrieve-by-id takes no scope filter, so nothing may be appended to it"
        );
    }

    #[tokio::test]
    async fn a_pre_flight_that_does_not_answer_usably_is_a_refusal_rather_than_permission() {
        // A non-2xx pre-flight refuses the request: letting it through would allow access to everything
        // whenever the broker is down, slow, or strict about the pre-flight URL.
        for status in [400, 404, 500, 503] {
            let server = failing_broker(status).await;
            let seen = Seen::default();

            let response = run(
                &server.uri(),
                request(
                    Method::DELETE,
                    &format!("/ngsi-ld/v1/entities/{ENTITY}"),
                    Some(decision(restriction(&["/Madrid/#"], MemberOnWrite::Required))),
                    "",
                ),
                &seen,
            )
            .await;

            // A 404 is the broker saying it holds no such entity, answered as the broker answers it.
            let expected = if status == 404 { StatusCode::NOT_FOUND } else { StatusCode::BAD_GATEWAY };
            assert_eq!(response.status(), expected, "a pre-flight answering {status} must not be a pass");
            assert_eq!(seen.uri(), None);
        }
    }

    #[tokio::test]
    async fn an_entity_carrying_no_scope_is_not_visible_to_a_scoped_reader() {
        let server = broker(json!({ "id": ENTITY, "type": "Vehicle" })).await;

        let response = run(
            &server.uri(),
            request(
                Method::GET,
                &format!("/ngsi-ld/v1/entities/{ENTITY}"),
                Some(decision(restriction(&["/Madrid/#"], MemberOnWrite::Required))),
                "",
            ),
            &Seen::default(),
        )
        .await;

        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "a scopeQ-filtered collection query would not return it either"
        );
    }

    #[tokio::test]
    async fn an_attribute_write_is_pre_flighted_rather_than_refused_for_carrying_no_scope() {
        // `PATCH /entities/{id}/attrs/{attr}` carries attributes and never a scope, so it is not held to
        // `scope-on-write` as a payload that left the scope out; doing so would refuse every attribute
        // write.
        let server = broker(scoped(json!("/Madrid/Gardens"))).await;
        let seen = Seen::default();

        let response = run(
            &server.uri(),
            request(
                Method::PATCH,
                &format!("/ngsi-ld/v1/entities/{ENTITY}/attrs/speed"),
                Some(decision(restriction(&["/Madrid/#"], MemberOnWrite::Required))),
                r#"{"type":"Property","value":42}"#,
            ),
            &seen,
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(seen.body(), r#"{"type":"Property","value":42}"#, "the body must reach the broker intact");
    }

    #[tokio::test]
    async fn a_sub_attribute_named_scope_in_an_attribute_value_does_not_move_the_entity() {
        let server = broker(scoped(json!("/Madrid/Gardens"))).await;
        let seen = Seen::default();
        let value = r#"{"type":"Property","value":42,"scope":{"type":"Property","value":"/Barcelona/Port"}}"#;

        let response = run(
            &server.uri(),
            request(
                Method::PATCH,
                &format!("/ngsi-ld/v1/entities/{ENTITY}/attrs/speed"),
                Some(decision(restriction(&["/Madrid/#"], MemberOnWrite::Required))),
                value,
            ),
            &seen,
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(seen.body(), value);
    }

    #[tokio::test]
    async fn a_join_on_an_entity_write_is_not_judged_as_a_linked_answer() {
        // A write answers with no entities and notifies nobody, so `join` there asks for nothing a
        // scope could be judged in; refusing it as an unservable join would refuse a valid write.
        let server = broker(scoped(json!("/Madrid/Gardens"))).await;
        let seen = Seen::default();

        let response = run(
            &server.uri(),
            request(
                Method::PATCH,
                &format!("/ngsi-ld/v1/entities/{ENTITY}/attrs/speed?join=inline&options=keyValues"),
                Some(decision(restriction(&["/Madrid/#"], MemberOnWrite::Required))),
                r#"{"type":"Property","value":42}"#,
            ),
            &seen,
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(seen.body(), r#"{"type":"Property","value":42}"#);
    }

    #[tokio::test]
    async fn a_write_that_would_move_an_entity_out_of_the_restriction_is_refused() {
        let server = broker(scoped(json!("/Madrid/Gardens"))).await;

        let response = run(
            &server.uri(),
            request(
                Method::PATCH,
                &format!("/ngsi-ld/v1/entities/{ENTITY}"),
                Some(decision(restriction(&["/Madrid/#"], MemberOnWrite::Required))),
                r#"{"scope":"/Barcelona/Port"}"#,
            ),
            &Seen::default(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn a_batch_delete_is_pre_flighted_rather_than_refused() {
        // Its body is an array of identifier strings, not entities, so it is not checked as entities,
        // which would find no `scope` on a string and refuse every batch delete under `scope-on-write`.
        let server = broker(scoped(json!("/Madrid/Gardens"))).await;
        let seen = Seen::default();

        let response = run(
            &server.uri(),
            request(
                Method::POST,
                "/ngsi-ld/v1/entityOperations/delete",
                Some(decision(restriction(&["/Madrid/#"], MemberOnWrite::Required))),
                r#"["urn:ngsi-ld:Vehicle:1","urn:ngsi-ld:Vehicle:2"]"#,
            ),
            &seen,
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(seen.body(), r#"["urn:ngsi-ld:Vehicle:1","urn:ngsi-ld:Vehicle:2"]"#);
    }

    #[tokio::test]
    async fn a_batch_delete_naming_an_entity_outside_the_restriction_is_refused() {
        let server = broker(scoped(json!("/Barcelona/Port"))).await;
        let seen = Seen::default();

        let response = run(
            &server.uri(),
            request(
                Method::POST,
                "/ngsi-ld/v1/entityOperations/delete",
                Some(decision(restriction(&["/Madrid/#"], MemberOnWrite::Required))),
                r#"["urn:ngsi-ld:Vehicle:1"]"#,
            ),
            &seen,
        )
        .await;

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(seen.uri(), None);
    }

    #[tokio::test]
    async fn a_scope_filter_in_a_query_body_is_inspected() {
        // `POST /entityOperations/query` carries its filter in the payload, so a layer that only read the
        // URL would be bypassed entirely.
        let server = broker(json!({})).await;
        let seen = Seen::default();

        let response = run(
            &server.uri(),
            request(
                Method::POST,
                "/ngsi-ld/v1/entityOperations/query",
                Some(decision(restriction(&["/Madrid/#"], MemberOnWrite::Required))),
                r#"{"type":"Query","scopeQ":"/Barcelona/Port"}"#,
            ),
            &seen,
        )
        .await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(seen.uri(), None);
    }

    #[tokio::test]
    async fn a_query_body_without_a_filter_is_given_the_policys_restriction() {
        let server = broker(json!({})).await;
        let seen = Seen::default();

        let response = run(
            &server.uri(),
            request(
                Method::POST,
                "/ngsi-ld/v1/temporal/entityOperations/query",
                Some(decision(restriction(&["/Madrid/#"], MemberOnWrite::Required))),
                r#"{"type":"Query"}"#,
            ),
            &seen,
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert!(seen.body().contains(r#""scopeQ":"/Madrid/#""#), "{}", seen.body());
    }

    #[tokio::test]
    async fn a_collection_read_without_a_filter_is_given_the_policys_restriction() {
        let seen = Seen::default();

        let response = run(
            "http://127.0.0.1:1",
            request(
                Method::GET,
                "/ngsi-ld/v1/entities?type=Vehicle",
                Some(decision(restriction(&["/Madrid/#", "/Barcelona/#"], MemberOnWrite::Required))),
                "",
            ),
            &seen,
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(seen.scope_filter().as_deref(), Some("/Madrid/#|/Barcelona/#"));
    }

    #[tokio::test]
    async fn the_scope_parameter_is_spelled_the_way_the_specification_spells_it() {
        let seen = Seen::default();

        let _response = run(
            "http://127.0.0.1:1",
            request(
                Method::GET,
                "/ngsi-ld/v1/entities",
                Some(decision(restriction(&["/Madrid/#"], MemberOnWrite::Required))),
                "",
            ),
            &seen,
        )
        .await;

        let uri = seen.uri().unwrap_or_default();

        assert!(uri.contains("scopeQ="), "the specification spells it with a capital Q: {uri}");
        assert!(
            !uri.contains("scopeq="),
            "a lowercase spelling is a parameter a case-sensitive broker ignores: {uri}"
        );
    }

    #[tokio::test]
    async fn a_conjunction_in_the_callers_filter_is_not_broadened_into_a_disjunction() {
        // Splitting on `[',', ';']` and re-joining with `,` would turn "in both of these" into "in
        // either of them", handing the caller entities they had not asked for and the proxy had not
        // authorised as a set.
        let seen = Seen::default();

        let _response = run(
            "http://127.0.0.1:1",
            request(
                Method::GET,
                "/ngsi-ld/v1/entities?scopeQ=%2FMadrid%2FGardens%3B%2FMadrid%2FParks",
                Some(decision(restriction(&["/Madrid/#"], MemberOnWrite::Required))),
                "",
            ),
            &seen,
        )
        .await;

        assert_eq!(seen.scope_filter().as_deref(), Some("/Madrid/Gardens;/Madrid/Parks"));
    }

    #[tokio::test]
    async fn a_disjunction_allowed_in_part_is_narrowed_to_that_part() {
        let seen = Seen::default();

        let response = run(
            "http://127.0.0.1:1",
            request(
                Method::GET,
                "/ngsi-ld/v1/entities?scopeQ=%2FMadrid%2F%23%7C%2FBerlin%2F%23",
                Some(decision(restriction(&["/Madrid/#"], MemberOnWrite::Required))),
                "",
            ),
            &seen,
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(seen.scope_filter().as_deref(), Some("/Madrid/#"));
    }

    #[tokio::test]
    async fn a_conjunction_with_an_disallowed_scope_is_refused() {
        let seen = Seen::default();

        let response = run(
            "http://127.0.0.1:1",
            request(
                Method::GET,
                "/ngsi-ld/v1/entities?scopeQ=%2FMadrid%2F%23%3B%2FBerlin%2F%23",
                Some(decision(restriction(&["/Madrid/#"], MemberOnWrite::Required))),
                "",
            ),
            &seen,
        )
        .await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(seen.uri(), None);
    }

    #[tokio::test]
    async fn an_empty_allow_list_never_becomes_an_empty_scope_parameter() {
        // `?scopeQ=` is read by brokers as no filter at all, which would turn a restriction
        // allowing nothing into one allowing everything.
        let seen = Seen::default();

        let response = run(
            "http://127.0.0.1:1",
            request(
                Method::GET,
                "/ngsi-ld/v1/entities",
                Some(decision(restriction(&[], MemberOnWrite::Required))),
                "",
            ),
            &seen,
        )
        .await;

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(seen.uri(), None, "nothing may be forwarded on a restriction that allows nothing");
    }

    #[tokio::test]
    async fn an_empty_scope_parameter_is_replaced_by_the_restriction_rather_than_forwarded() {
        // `?scopeQ=` is read by brokers as no filter at all, so it has to be treated as a filter
        // the caller never wrote, not refused, and above all not passed on as it stands.
        let seen = Seen::default();

        let response = run(
            "http://127.0.0.1:1",
            request(
                Method::GET,
                "/ngsi-ld/v1/entities?scopeQ=",
                Some(decision(restriction(&["/Madrid/#"], MemberOnWrite::Required))),
                "",
            ),
            &seen,
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(seen.scope_filter().as_deref(), Some("/Madrid/#"));
    }

    #[tokio::test]
    async fn two_spellings_of_the_scope_parameter_are_refused() {
        let seen = Seen::default();

        let response = run(
            "http://127.0.0.1:1",
            request(
                Method::GET,
                "/ngsi-ld/v1/entities?scopeQ=%2FMadrid&scopeq=%2FBarcelona",
                Some(decision(restriction(&["/#"], MemberOnWrite::Required))),
                "",
            ),
            &seen,
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(seen.uri(), None);
    }

    #[tokio::test]
    async fn the_pre_flight_carries_the_tenant_and_the_context_link() {
        // Without the tenant the pre-flight reads a different data set, and the entity it finds is
        // not the one the request is about. Without the Link the names in the answer mean
        // something other than what the request meant by them.
        let server = MockServer::start().await;
        Mock::given(any())
            .and(header("NGSILD-Tenant", "acme"))
            .and(header(
                "Link",
                "<https://example.test/context.jsonld>; rel=\"http://www.w3.org/ns/json-ld#context\"",
            ))
            .respond_with(json_response(&scoped(json!("/Madrid/Gardens"))))
            .mount(&server)
            .await;

        let response = run(
            &server.uri(),
            request(
                Method::GET,
                &format!("/ngsi-ld/v1/entities/{ENTITY}"),
                Some(decision(restriction(&["/Madrid/#"], MemberOnWrite::Required))),
                "",
            ),
            &Seen::default(),
        )
        .await;

        assert_eq!(
            response.status(),
            StatusCode::OK,
            "the pre-flight only matches when both headers are carried across"
        );
    }

    #[tokio::test]
    async fn a_create_without_a_scope_follows_the_policy_flag() {
        let seen = Seen::default();

        let refused = run(
            "http://127.0.0.1:1",
            request(
                Method::POST,
                "/ngsi-ld/v1/entities",
                Some(decision(restriction(&["/Madrid/#"], MemberOnWrite::Required))),
                r#"{"id":"urn:ngsi-ld:Vehicle:9","type":"Vehicle"}"#,
            ),
            &seen,
        )
        .await;

        assert_eq!(refused.status(), StatusCode::FORBIDDEN);

        let allowed = run(
            "http://127.0.0.1:1",
            request(
                Method::POST,
                "/ngsi-ld/v1/entities",
                Some(decision(restriction(&["/Madrid/#"], MemberOnWrite::Optional))),
                r#"{"id":"urn:ngsi-ld:Vehicle:9","type":"Vehicle"}"#,
            ),
            &seen,
        )
        .await;

        assert_eq!(allowed.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn a_path_this_layer_does_not_govern_is_left_alone() {
        let seen = Seen::default();

        let response = run(
            "http://127.0.0.1:1",
            request(
                Method::GET,
                "/ngsi-ld/v1/jsonldContexts",
                Some(decision(restriction(&["/Madrid/#"], MemberOnWrite::Required))),
                "",
            ),
            &seen,
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(seen.uri().as_deref(), Some("/ngsi-ld/v1/jsonldContexts"));
    }

    fn parking(name: &str, scope: Value) -> Value {
        json!({ "id": format!("urn:ngsi-ld:OffStreetParking:{name}"), "type": "OffStreetParking", "scope": scope,
            "name": { "type": "Property", "value": name } })
    }

    #[tokio::test]
    async fn a_linked_entity_outside_the_allowed_scopes_is_withheld_from_an_inline_answer() {
        // Linked Entity Retrieval (NGSI-LD 4.5.23) returns the entities a Relationship points at, in
        // whatever scope they are. The answer is judged linked entity by linked entity: the one in a
        // allowed scope is shown, the other is removed and the Relationship naming it stays.
        let seen = Seen::default();
        let answer = json!([{ "id": ENTITY, "type": "Vehicle", "scope": "/Madrid/Fleet",
            "isParked": { "type": "Relationship", "object": "urn:ngsi-ld:OffStreetParking:Berlin", "entity": parking("Berlin", json!("/Berlin/Centre")) },
            "seenAt": { "type": "Relationship", "object": "urn:ngsi-ld:OffStreetParking:Madrid", "entity": parking("Madrid", json!("/Madrid/Centre")) } }]);

        let response = run_replying(
            "http://127.0.0.1:1",
            request(Method::GET, "/ngsi-ld/v1/entities?type=Vehicle&join=inline", Some(allow_decision()), ""),
            &seen,
            Reply::json(&answer),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert!(!seen.accept_encoding_was_sent(), "a compressed join answer could not be judged");
        let body = body_json(response).await;
        let vehicle = body.as_array().and_then(<[Value]>::first);
        assert_eq!(
            vehicle.and_then(|entity| member(entity, "isParked")),
            Some(&json!({ "type": "Relationship", "object": "urn:ngsi-ld:OffStreetParking:Berlin" }))
        );
        assert_eq!(
            vehicle
                .and_then(|entity| member(entity, "seenAt"))
                .and_then(|seen_at| member(seen_at, "entity")),
            Some(&parking("Madrid", json!("/Madrid/Centre")))
        );
    }

    #[tokio::test]
    async fn a_linked_entity_in_a_flat_answer_keeps_only_its_allowed_scopes() {
        let seen = Seen::default();
        let answer = json!([
            { "id": ENTITY, "type": "Vehicle", "scope": "/Madrid/Fleet", "isParked": { "object": "urn:ngsi-ld:OffStreetParking:Both" } },
            parking("Both", json!(["/Madrid/A", "/Berlin/B"])),
            parking("Unscoped", Value::Null),
            parking("Berlin", json!("/Berlin/Centre"))
        ]);

        let response = run_replying(
            "http://127.0.0.1:1",
            request(Method::GET, "/ngsi-ld/v1/entities?type=Vehicle&join=flat", Some(allow_decision()), ""),
            &seen,
            Reply::json(&answer),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            body_json(response).await,
            json!([
                { "id": ENTITY, "type": "Vehicle", "scope": "/Madrid/Fleet", "isParked": { "object": "urn:ngsi-ld:OffStreetParking:Both" } },
                parking("Both", json!(["/Madrid/A"]))
            ])
        );
    }

    #[tokio::test]
    async fn a_join_answer_to_a_read_by_id_is_judged_after_the_pre_flight() {
        let server = broker(scoped(json!("/Madrid/Fleet"))).await;
        let seen = Seen::default();
        let answer = json!([scoped(json!("/Madrid/Fleet")), parking("Berlin", json!("/Berlin/Centre"))]);

        let response = run_replying(
            &server.uri(),
            request(Method::GET, &format!("{}?join=flat", by_id()), Some(allow_decision()), ""),
            &seen,
            Reply::json(&answer),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_json(response).await, json!([scoped(json!("/Madrid/Fleet"))]));
    }

    #[tokio::test]
    async fn a_join_in_a_query_body_is_served_and_judged() {
        let seen = Seen::default();
        let answer = json!([scoped(json!("/Madrid/Fleet")), parking("Berlin", json!("/Berlin/Centre"))]);

        let response = run_replying(
            "http://127.0.0.1:1",
            request(
                Method::POST,
                "/ngsi-ld/v1/entityOperations/query",
                Some(allow_decision()),
                r#"{"type": "Query", "entities": [{"type": "Vehicle"}], "join": "flat", "joinLevel": 1}"#,
            ),
            &seen,
            Reply::json(&answer),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_json(response).await, json!([scoped(json!("/Madrid/Fleet"))]));
    }

    #[tokio::test]
    async fn a_projection_that_removes_scope_is_refused_before_it_is_sent() {
        // With or without a join: every entity of the answer is judged by its scope.
        for query in [
            "omit=scope",
            "pick=id,type,name",
            "omit=scope&join=flat",
            "pick=id,type,name&join=inline",
            "join=inline&pick=id,type,scope,isParked{name}",
        ] {
            let seen = Seen::default();
            let response = run(
                "http://127.0.0.1:1",
                request(Method::GET, &format!("/ngsi-ld/v1/entities?type=Vehicle&{query}"), Some(allow_decision()), ""),
                &seen,
            )
            .await;

            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{query}");
            assert_eq!(seen.uri(), None, "{query}");
        }
    }

    #[tokio::test]
    async fn an_inline_join_in_key_values_is_refused() {
        // In `keyValues` the Relationship's value becomes the linked entity (NGSI-LD 4.5.4), so a
        // withheld one could not be told from data.
        let seen = Seen::default();
        let response = run(
            "http://127.0.0.1:1",
            request(
                Method::GET,
                "/ngsi-ld/v1/entities?type=Vehicle&join=inline&options=keyValues",
                Some(allow_decision()),
                "",
            ),
            &seen,
        )
        .await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(seen.uri(), None);
    }

    #[tokio::test]
    async fn a_join_answer_that_cannot_be_walked_is_withheld() {
        let seen = Seen::default();
        let answer = json!([{ "id": ENTITY, "scope": "/Madrid/Fleet", "isParked": { "object": "urn:a", "entity": "urn:a" } }]);

        let response = run_replying(
            "http://127.0.0.1:1",
            request(Method::GET, "/ngsi-ld/v1/entities?type=Vehicle&join=inline", Some(allow_decision()), ""),
            &seen,
            Reply::json(&answer),
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn a_join_level_without_a_join_is_refused_before_the_pre_flight() {
        // A single-entity read with a restriction ordinarily pre-flights the broker for the entity's
        // scope. A `joinLevel` with no `join` asks for an answer of no shape anyone named, and is
        // refused ahead of that, so no request is made at all.
        let seen = Seen::default();
        let response = run(
            "http://127.0.0.1:1",
            request(
                Method::GET,
                &format!("/ngsi-ld/v1/entities/{ENTITY}?joinLevel=3"),
                Some(decision(restriction(&["/Madrid/#"], MemberOnWrite::Required))),
                "",
            ),
            &seen,
        )
        .await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(seen.uri(), None);
    }

    #[tokio::test]
    async fn a_linked_entity_filter_is_refused_when_scopes_are_restricted() {
        // Clause 4.9: the vehicles are selected by an attribute of the entity `parkedIn` points at,
        // in whatever scope that is.
        let seen = Seen::default();
        let response = run(
            "http://127.0.0.1:1",
            request(
                Method::GET,
                "/ngsi-ld/v1/entities?type=Vehicle&q=parkedIn{name}==%22Downtown%22",
                Some(decision(restriction(&["/Madrid/#"], MemberOnWrite::Required))),
                "",
            ),
            &seen,
        )
        .await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(seen.uri(), None);
    }

    #[tokio::test]
    async fn unservable_linked_entity_retrieval_in_a_batch_query_body_is_refused_when_scopes_are_restricted() {
        // NGSI-LD 5.2.23 gives the Query body `join`, `joinLevel`, projections and `q` of its own,
        // and what no answer can be judged against is refused there as it is in the query string.
        for body in [
            r#"{"type": "Query", "entities": [{"type": "Vehicle"}], "joinLevel": 2}"#,
            r#"{"type": "Query", "entities": [{"type": "Vehicle"}], "omit": ["parkedIn{name}"]}"#,
            r#"{"type": "Query", "entities": [{"type": "Vehicle"}], "q": "parkedIn{name}==\"Downtown\""}"#,
        ] {
            let seen = Seen::default();
            let response = run(
                "http://127.0.0.1:1",
                request(
                    Method::POST,
                    "/ngsi-ld/v1/entityOperations/query",
                    Some(decision(restriction(&["/Madrid/#"], MemberOnWrite::Required))),
                    body,
                ),
                &seen,
            )
            .await;

            assert_eq!(response.status(), StatusCode::FORBIDDEN, "{body}");
            assert_eq!(seen.uri(), None, "{body}");
        }
    }

    #[tokio::test]
    async fn linked_entity_retrieval_in_a_subscription_is_refused_when_scopes_are_restricted() {
        // NGSI-LD 5.2.14: the notification carries `join` and `joinLevel`, and the linked entities
        // it delivers never pass back through Libra to be narrowed.
        for body in [
            r#"{"type": "Subscription", "entities": [{"type": "Vehicle"}], "notification": {"joinLevel": 1, "endpoint": {"uri": "http://sink.test"}}}"#,
            r#"{"type": "Subscription", "entities": [{"type": "Vehicle"}], "notification": {"attributes": ["parkedIn{name}"], "endpoint": {"uri": "http://sink.test"}}}"#,
            r#"{"type": "Subscription", "entities": [{"type": "Vehicle"}], "q": "parkedIn{name}==\"Downtown\"", "notification": {"endpoint": {"uri": "http://sink.test"}}}"#,
        ] {
            let seen = Seen::default();
            let response = run(
                "http://127.0.0.1:1",
                request(
                    Method::POST,
                    "/ngsi-ld/v1/subscriptions",
                    Some(decision(restriction(&["/Madrid/#"], MemberOnWrite::Required))),
                    body,
                ),
                &seen,
            )
            .await;

            assert_eq!(response.status(), StatusCode::FORBIDDEN, "{body}");
            assert_eq!(seen.uri(), None, "{body}");
        }
    }

    #[tokio::test]
    async fn a_join_read_passes_when_no_scope_restriction() {
        // The layer only runs when a scope restriction is attached; an unrestricted caller keeps
        // linked retrieval.
        let seen = Seen::default();
        let response = run(
            "http://127.0.0.1:1",
            request(Method::GET, "/ngsi-ld/v1/entities?type=Vehicle&join=inline", Some(unrestricted()), ""),
            &seen,
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert!(seen.uri().is_some(), "an unrestricted caller's linked retrieval reaches the broker");
    }

    #[tokio::test]
    async fn a_context_source_subscription_is_refused_when_scopes_are_restricted() {
        let seen = Seen::default();
        let response = run(
            "http://127.0.0.1:1",
            request(
                Method::GET,
                "/ngsi-ld/v1/csourceSubscriptions",
                Some(decision(restriction(&["/Madrid/#"], MemberOnWrite::Required))),
                "",
            ),
            &seen,
        )
        .await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(seen.uri(), None, "context source subscription request must not reach broker");
    }

    fn scoped_registration(id: &str, scope: Option<Value>) -> Value {
        let mut registration = json!({ "id": id, "type": "ContextSourceRegistration", "endpoint": "http://source.test",
            "information": [{ "entities": [{ "type": "Vehicle" }] }] });
        if let (Some(scope), Some(members)) = (scope, registration.as_object_mut()) {
            members.push(Key::from("scope"), scope);
        }

        registration
    }

    #[tokio::test]
    async fn a_registration_listing_shows_the_allowed_registrations_reduced_to_their_allowed_scopes() {
        let listing = json!([
            scoped_registration("urn:r:1", Some(json!("/Madrid/A"))),
            scoped_registration("urn:r:2", Some(json!("/Berlin/B"))),
            scoped_registration("urn:r:3", Some(json!(["/Madrid/A", "/Berlin/B"]))),
            scoped_registration("urn:r:4", None),
        ]);
        let seen = Seen::default();
        let response = run_replying(
            "http://127.0.0.1:1",
            request(
                Method::GET,
                "/ngsi-ld/v1/csourceRegistrations",
                Some(decision(restriction(&["/Madrid/#"], MemberOnWrite::Required))),
                "",
            ),
            &seen,
            Reply::json(&listing),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            body_json(response).await,
            json!([
                scoped_registration("urn:r:1", Some(json!("/Madrid/A"))),
                scoped_registration("urn:r:3", Some(json!(["/Madrid/A"]))),
            ])
        );
        assert!(!seen.accept_encoding_was_sent(), "the answer is filtered, so it is asked for unencoded");
    }

    #[tokio::test]
    async fn a_registration_read_by_id_outside_the_restriction_is_answered_as_absent() {
        let seen = Seen::default();
        let response = run_replying(
            "http://127.0.0.1:1",
            request(
                Method::GET,
                "/ngsi-ld/v1/csourceRegistrations/urn:r:2",
                Some(decision(restriction(&["/Madrid/#"], MemberOnWrite::Required))),
                "",
            ),
            &seen,
            Reply::json(&scoped_registration("urn:r:2", Some(json!("/Berlin/B")))),
        )
        .await;

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn a_registration_create_outside_the_restriction_or_without_a_required_scope_is_refused() {
        for (registration, expected) in [
            (scoped_registration("urn:r:2", Some(json!("/Berlin/B"))), StatusCode::FORBIDDEN),
            (scoped_registration("urn:r:5", None), StatusCode::FORBIDDEN),
            (scoped_registration("urn:r:1", Some(json!("/Madrid/A"))), StatusCode::OK),
        ] {
            let seen = Seen::default();
            let created = request(
                Method::POST,
                "/ngsi-ld/v1/csourceRegistrations",
                Some(decision(restriction(&["/Madrid/#"], MemberOnWrite::Required))),
                &registration.to_string(),
            );

            let response = run("http://127.0.0.1:1", created, &seen).await;

            assert_eq!(response.status(), expected, "{registration}");
            assert_eq!(seen.uri().is_some(), expected == StatusCode::OK, "{registration}");
        }
    }

    #[tokio::test]
    async fn a_registration_update_or_delete_needs_every_existing_scope_allowed() {
        for (scope, expected) in [(json!(["/Madrid/A", "/Berlin/B"]), StatusCode::FORBIDDEN), (json!("/Madrid/A"), StatusCode::OK)] {
            let server = broker(scoped_registration("urn:r:1", Some(scope.clone()))).await;

            for method in [Method::PATCH, Method::DELETE] {
                let seen = Seen::default();
                let body = if method == Method::PATCH {
                    r#"{"endpoint":"http://elsewhere.test"}"#
                } else {
                    ""
                };
                let response = run(
                    &server.uri(),
                    request(
                        method.clone(),
                        "/ngsi-ld/v1/csourceRegistrations/urn:r:1",
                        Some(decision(restriction(&["/Madrid/#"], MemberOnWrite::Required))),
                        body,
                    ),
                    &seen,
                )
                .await;

                assert_eq!(response.status(), expected, "{method} of a registration in {scope}");
            }
        }
    }

    #[tokio::test]
    async fn an_entity_map_read_is_refused_when_scopes_are_restricted() {
        let seen = Seen::default();
        let response = run(
            "http://127.0.0.1:1",
            request(
                Method::GET,
                "/ngsi-ld/v1/entityMaps",
                Some(decision(restriction(&["/Madrid/#"], MemberOnWrite::Required))),
                "",
            ),
            &seen,
        )
        .await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(seen.uri(), None, "entity map request must not reach broker");
    }

    #[tokio::test]
    async fn a_read_by_id_is_allowed_when_one_of_two_scopes_is_allowed_and_the_answer_shows_only_that_one() {
        let entity = scoped(json!(["/Madrid/A", "/Secret/X"]));
        // Cloned because the broker owns what it serves and the test still reads the entity.
        let server = broker(entity.clone()).await;

        let response = run_replying(
            &server.uri(),
            request(Method::GET, &by_id(), Some(allow_decision()), ""),
            &Seen::default(),
            Reply::json(&entity),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_json(response).await, scoped(json!(["/Madrid/A"])));
    }

    #[tokio::test]
    async fn a_read_by_id_is_refused_when_none_of_the_scopes_is_allowed() {
        let server = broker(scoped(json!(["/Secret/X", "/Secret/Y"]))).await;
        let seen = Seen::default();

        let response = run(&server.uri(), request(Method::GET, &by_id(), Some(allow_decision()), ""), &seen).await;

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(seen.uri(), None);
    }

    #[tokio::test]
    async fn a_read_by_id_of_an_unscoped_entity_is_refused() {
        let server = broker(json!({ "id": ENTITY, "type": "Vehicle" })).await;

        let response = run(&server.uri(), request(Method::GET, &by_id(), Some(allow_decision()), ""), &Seen::default()).await;

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn an_attribute_patch_is_refused_when_one_of_two_scopes_is_disallowed() {
        let server = broker(scoped(json!(["/Madrid/A", "/Secret/X"]))).await;
        let seen = Seen::default();

        let response = run(
            &server.uri(),
            request(
                Method::PATCH,
                &format!("{}/attrs", by_id()),
                Some(allow_decision()),
                r#"{"speed":{"type":"Property","value":1}}"#,
            ),
            &seen,
        )
        .await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(seen.uri(), None);
    }

    #[tokio::test]
    async fn a_delete_is_refused_when_one_of_two_scopes_is_disallowed() {
        let server = broker(scoped(json!(["/Madrid/A", "/Secret/X"]))).await;
        let seen = Seen::default();

        let response = run(&server.uri(), request(Method::DELETE, &by_id(), Some(allow_decision()), ""), &seen).await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(seen.uri(), None);
    }

    #[tokio::test]
    async fn a_collection_response_is_filtered_per_entity_and_an_unscoped_entity_is_withheld() {
        // `c` carries no scope, so the injected `scopeQ` could not have matched it: a broker that
        // returned it ignored the filter, and a read of it by identifier is refused.
        let reply = json!([
            { "id": "a", "scope": ["/Madrid/A", "/Secret/X"] },
            { "id": "b", "scope": ["/Madrid/B"] },
            { "id": "c" }
        ]);

        let response = run_replying(
            "http://127.0.0.1:1",
            request(Method::GET, "/ngsi-ld/v1/entities?type=Vehicle", Some(allow_decision()), ""),
            &Seen::default(),
            Reply::json(&reply),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            body_json(response).await,
            json!([{ "id": "a", "scope": ["/Madrid/A"] }, { "id": "b", "scope": ["/Madrid/B"] }])
        );
    }

    #[tokio::test]
    async fn a_normalised_property_scope_in_a_collection_response_is_filtered() {
        let reply = json!([{ "id": "a", "scope": { "type": "Property", "value": ["/Madrid/A", "/Secret/X"] } }]);

        let response = run_replying(
            "http://127.0.0.1:1",
            request(Method::GET, "/ngsi-ld/v1/entities", Some(allow_decision()), ""),
            &Seen::default(),
            Reply::json(&reply),
        )
        .await;

        assert_eq!(
            body_json(response).await,
            json!([{ "id": "a", "scope": { "type": "Property", "value": ["/Madrid/A"] } }])
        );
    }

    #[tokio::test]
    async fn a_temporal_read_by_id_has_its_scope_instances_filtered() {
        let entity = json!({ "id": ENTITY, "type": "Vehicle", "scope": [
            { "type": "Property", "value": ["/Madrid/A", "/Secret/X"] },
            { "type": "Property", "value": "/Secret/Y" }
        ] });
        // The pre-flight answers with the entity's scopes plainly; the temporal answer carries instances.
        let server = broker(scoped(json!(["/Madrid/A", "/Secret/X"]))).await;

        let response = run_replying(
            &server.uri(),
            request(Method::GET, &format!("/ngsi-ld/v1/temporal/entities/{ENTITY}"), Some(allow_decision()), ""),
            &Seen::default(),
            Reply::json(&entity),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            body_json(response).await,
            json!({ "id": ENTITY, "type": "Vehicle", "scope": [{ "type": "Property", "value": ["/Madrid/A"] }] })
        );
    }

    #[tokio::test]
    async fn a_collection_entity_with_nothing_allowed_left_is_withheld_rather_than_shown_without_its_scope() {
        let reply = json!([{ "id": "a", "scope": ["/Secret/X"] }]);

        let response = run_replying(
            "http://127.0.0.1:1",
            request(Method::GET, "/ngsi-ld/v1/entities", Some(allow_decision()), ""),
            &Seen::default(),
            Reply::json(&reply),
        )
        .await;

        assert_eq!(body_json(response).await, json!([]));
    }

    #[tokio::test]
    async fn geojson_feature_and_feature_collection_answers_are_filtered_under_properties() {
        let feature = json!({ "type": "Feature", "properties": { "scope": ["/Madrid/A", "/Secret/X"] } });
        // Cloned because the feature is also sent on its own below.
        let collection = json!({ "type": "FeatureCollection", "features": [feature.clone()] });

        for (reply, expected) in [
            (feature, json!({ "type": "Feature", "properties": { "scope": ["/Madrid/A"] } })),
            (
                collection,
                json!({ "type": "FeatureCollection", "features": [{ "type": "Feature", "properties": { "scope": ["/Madrid/A"] } }] }),
            ),
        ] {
            let response = run_replying(
                "http://127.0.0.1:1",
                request(Method::GET, "/ngsi-ld/v1/entities", Some(allow_decision()), ""),
                &Seen::default(),
                Reply {
                    content_type: Some("application/geo+json"),
                    ..Reply::json(&reply)
                },
            )
            .await;

            assert_eq!(body_json(response).await, expected);
        }
    }

    #[tokio::test]
    async fn an_entity_of_type_feature_under_application_json_is_not_mistaken_for_geojson() {
        let reply = json!([{ "type": "Feature", "properties": { "type": "Property", "value": 1 }, "scope": ["/Madrid/A", "/Secret/X"] }]);

        let response = run_replying(
            "http://127.0.0.1:1",
            request(Method::GET, "/ngsi-ld/v1/entities", Some(allow_decision()), ""),
            &Seen::default(),
            Reply::json(&reply),
        )
        .await;

        assert_eq!(
            body_json(response).await,
            json!([{ "type": "Feature", "properties": { "type": "Property", "value": 1 }, "scope": ["/Madrid/A"] }])
        );
    }

    #[tokio::test]
    async fn a_content_encoded_success_response_is_refused() {
        let response = run_replying(
            "http://127.0.0.1:1",
            request(Method::GET, "/ngsi-ld/v1/entities", Some(allow_decision()), ""),
            &Seen::default(),
            Reply {
                content_encoding: Some("gzip"),
                ..Reply::json(&json!([]))
            },
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn a_non_json_success_response_is_refused() {
        let response = run_replying(
            "http://127.0.0.1:1",
            request(Method::GET, "/ngsi-ld/v1/entities", Some(allow_decision()), ""),
            &Seen::default(),
            Reply {
                content_type: Some("text/plain"),
                ..Reply::json(&json!([]))
            },
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn a_not_found_problem_body_passes_through_untouched() {
        let problem = json!({ "type": "https://uri.etsi.org/ngsi-ld/errors/ResourceNotFound", "title": "gone", "scope": ["/Secret/X"] });

        let response = run_replying(
            "http://127.0.0.1:1",
            request(Method::GET, "/ngsi-ld/v1/entities", Some(allow_decision()), ""),
            &Seen::default(),
            Reply {
                status: StatusCode::NOT_FOUND,
                content_type: Some("application/problem+json"),
                ..Reply::json(&problem)
            },
        )
        .await;

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(body_json(response).await, problem);
    }

    #[tokio::test]
    async fn the_content_length_is_recomputed_after_filtering() {
        let reply = json!([{ "id": "a", "scope": ["/Madrid/A", "/Secret/X"] }]);

        let response = run_replying(
            "http://127.0.0.1:1",
            request(Method::GET, "/ngsi-ld/v1/entities", Some(allow_decision()), ""),
            &Seen::default(),
            Reply::json(&reply),
        )
        .await;

        let declared = response
            .headers()
            .get(CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<usize>().ok());
        let bytes = response
            .into_body()
            .collect()
            .await
            .map(http_body_util::Collected::to_bytes)
            .unwrap_or_default();

        assert_eq!(declared, Some(bytes.len()));
    }

    #[tokio::test]
    async fn the_outbound_read_carries_no_accept_encoding() {
        let seen = Seen::default();
        let mut outbound = request(Method::GET, "/ngsi-ld/v1/entities", Some(allow_decision()), "");
        outbound.headers_mut().insert(ACCEPT_ENCODING, HeaderValue::from_static("gzip"));

        let _response = run("http://127.0.0.1:1", outbound, &seen).await;

        assert!(!seen.accept_encoding_was_sent(), "a compressed body could not be filtered");
    }

    #[tokio::test]
    async fn a_batch_query_response_is_filtered() {
        let reply = json!([{ "id": "a", "scope": ["/Madrid/A", "/Secret/X"] }]);

        let response = run_replying(
            "http://127.0.0.1:1",
            request(
                Method::POST,
                "/ngsi-ld/v1/entityOperations/query",
                Some(allow_decision()),
                r#"{"type":"Query"}"#,
            ),
            &Seen::default(),
            Reply::json(&reply),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_json(response).await, json!([{ "id": "a", "scope": ["/Madrid/A"] }]));
    }

    #[tokio::test]
    async fn a_request_without_a_parsed_body_is_refused() {
        // A body this layer cannot see is one whose scopes it cannot check: forwarding it would be
        // forwarding a create nobody judged.
        let seen = Seen::default();
        let mut created = request(
            Method::POST,
            "/ngsi-ld/v1/entities",
            Some(allow_decision()),
            r#"{"id":"urn:ngsi-ld:Vehicle:1","type":"Vehicle","scope":"/Secret/X"}"#,
        );
        created.extensions_mut().remove::<RequestBody>();

        let response = run("http://127.0.0.1:1", created, &seen).await;

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(seen.uri(), None);
    }

    #[tokio::test]
    async fn a_batch_query_inside_the_restriction_is_forwarded_as_the_caller_wrote_it() {
        const QUERY: &str = r#"{ "type" : "Query", "scopeQ" : "/Madrid/Gardens/#", "q" : "speed>40" }"#;

        let seen = Seen::default();
        let response = run(
            "http://127.0.0.1:1",
            request(Method::POST, "/ngsi-ld/v1/entityOperations/query", Some(allow_decision()), QUERY),
            &seen,
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(seen.body(), QUERY, "a body nothing was narrowed out of keeps its bytes");
    }

    #[tokio::test]
    async fn a_temporal_entity_map_is_refused_when_scopes_are_restricted() {
        // NGSI-LD 6.35: an entity map built from a temporal query maps the identifiers of entities in
        // every scope, exactly as `/entityMaps` does.
        let seen = Seen::default();
        let response = run(
            "http://127.0.0.1:1",
            request(Method::POST, "/ngsi-ld/v1/temporal/entityMaps", Some(allow_decision()), r#"{"type":"Query"}"#),
            &seen,
        )
        .await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(seen.uri(), None, "temporal entity map request must not reach broker");
    }

    /// `request` as the operation and query layers above leave it, with `stored` as its parsed query.
    fn with_stored_query(request: Request, stored: &str) -> Request {
        let (mut parts, body) = request.into_parts();
        classify(&mut parts).unwrap();
        read_query(&mut parts).unwrap();
        parts.extensions.insert(QueryParameters::parse(stored).unwrap());

        Request::from_parts(parts, body)
    }

    #[tokio::test]
    async fn the_scope_filter_is_read_from_the_stored_query_not_from_the_request_target() {
        let seen = Seen::default();
        let request = with_stored_query(
            request(
                Method::GET,
                "/ngsi-ld/v1/entities?scopeQ=%2FMadrid%2F%23%7C%2FBerlin%2F%23",
                Some(decision(restriction(&["/Madrid/#"], MemberOnWrite::Required))),
                "",
            ),
            "scopeQ=%2FMadrid%2FParks",
        );
        let scope = ScopeEnforcementLayer::new(
            Arc::new(Preflight::new(Url::parse("http://127.0.0.1:1").unwrap(), 64 * 1024).unwrap()),
            64 * 1024,
        );
        let mut service = LinkedEntityLayer::new()
            .layer(RepresentationLayer::new(RepresentationStrictness::default()).layer(scope.layer(upstream_replying(&seen, Reply::json(&json!([]))))));

        let response = service.call(request).await.unwrap_or_else(|error| match error {});

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(seen.scope_filter().as_deref(), Some("/Madrid/Parks"));
    }
}
