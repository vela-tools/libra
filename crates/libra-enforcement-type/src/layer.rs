//! The Tower layer that keeps a request inside the entity types its policy allows.
//!
//! Four places name an entity type, and all four are covered:
//!
//! * A collection read names them in `type`, which is checked and, if the caller named none,
//!   filled in with the restriction.
//! * A batch query names them in the `entities` selectors of its body, which is checked as well as
//!   the query string.
//! * A create or a batch write names them in the entities it carries.
//! * A request that names one entity does not name a type at all. Those are pre-flighted, which is
//!   what makes a merge patch and a batch delete enforceable rather than refused or skipped.
//!
//! A context source registration names the types a source provides. Its answer is filtered, and a
//! write is checked against what it registers; see [`crate::registration`].
//!
//! Every name in the request is expanded against the request's own context before it is compared;
//! nothing here compares two strings. The policy's side was expanded when the policy loaded.
//!
//! A request whose decision carries no type restriction passes through untouched. That is safe only
//! because of where this layer sits: below `libra-policy-layer`, which has already refused anything
//! the policy set does not allow and attached its decision to everything else. A request carrying no
//! decision at all is one nobody authorized, and is refused as a wiring fault rather than passed
//! through.

use crate::{error::TypeError, names, registration, request, response};
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
use libra_jsonld_context_layer::RequestContextExtension;
use libra_jsonld_term_expansion::resolved::ResolvedContext;
use libra_ngsi_ld_operation::{
    entity_map::names_entity_map,
    operation::{Mode, Operation},
    resource::Resource,
    target::EntityTarget,
};
use libra_ngsi_ld_operation_layer::classified::operation;
use libra_ngsi_ld_query::entity_member::EntityMember;
use libra_policy_engine::decision::Decision;
use libra_policy_model::entity_type::CompiledTypeRestriction;
use std::{
    convert::Infallible,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tower::{Layer, Service, ServiceExt};
use tracing::{error, warn};

/// Enforces a policy's entity type restriction.
#[derive(Debug, Clone)]
pub struct TypeEnforcementLayer {
    preflight: Arc<Preflight>,
    max_body_bytes: usize,
}

impl TypeEnforcementLayer {
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

impl<S> Layer<S> for TypeEnforcementLayer {
    type Service = TypeEnforcementService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        TypeEnforcementService {
            inner,
            preflight: Arc::clone(&self.preflight),
            max_body_bytes: self.max_body_bytes,
        }
    }
}

/// The service produced by [`TypeEnforcementLayer`].
#[derive(Debug, Clone)]
pub struct TypeEnforcementService<S> {
    inner: S,
    preflight: Arc<Preflight>,
    max_body_bytes: usize,
}

impl<S> Service<Request> for TypeEnforcementService<S>
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
        let inner = self.inner.clone(); // the boxed future outlives `&mut self`
        let preflight = Arc::clone(&self.preflight);
        let max_body_bytes = self.max_body_bytes;

        Box::pin(async move {
            match apply(inner, request, &preflight, max_body_bytes).await {
                Ok(response) => Ok(response),
                Err(error) => {
                    warn!(error = %error, "entity type enforcement refused the request");

                    Ok(error.to_problem().into_response())
                }
            }
        })
    }
}

/// Brings the request inside the allowed types, then forwards it.
async fn apply<S>(inner: S, request: Request, preflight: &Preflight, max_body_bytes: usize) -> Result<Response, TypeError>
where
    S: Service<Request, Response = Response, Error = Infallible> + Send + 'static,
    S::Future: Send + 'static,
{
    let Some(decision) = request.extensions().get::<Decision>() else {
        // The authorization layer attaches a decision to every request it lets through, so one
        // arriving here without it is one nobody authorized.
        error!("a request reached entity type enforcement without an authorization decision: the layer is wired above authorization");

        return Err(TypeError::Undecided);
    };

    // A reference count, not a copy: the request that owns the decision is moved into the rewrite and forward steps while the restriction is still read.
    let Some(restriction) = decision.entity_type.clone() else {
        // The policy that allowed this request placed no entity type condition on it.
        return Ok(forward(inner, request).await);
    };

    // `TypeRestriction` refuses an empty allow list when the policy loads. It is checked again
    // because a request under one would be narrowed to a type nobody holds.
    names::allowed(&restriction)?;

    if names_entity_map(request.headers()) {
        // Whatever the request is, the broker answers it from the entities the map lists, which no
        // narrowing of the request's own `type` reaches.
        return Err(Unnarrowable::EntityMap.into());
    }

    let Some(context) = request.extensions().get::<RequestContextExtension>().map(|extension| Arc::clone(&extension.0)) else {
        // Every type name here is a term, and a term without a context is not a name. The context
        // layer runs above this one, so its absence is a wiring error rather than a request.
        return Err(TypeError::Unresolved);
    };

    // Cloned because the request it travels in is moved into the checks below while it is still read.
    let operation = operation(request.extensions())?.clone();

    if operation.resource.is_context_source_registration() {
        let request = registration::check_request(request, &operation, &restriction, &context, preflight).await?;
        let response = forward(inner, request).await;

        return match operation.mode {
            Mode::Read => registration::filter_response(response, &operation.resource, &restriction, &context, max_body_bytes).await,
            Mode::Write => Ok(response),
        };
    }

    refuse_unnarrowable(&operation)?;

    if operation.resource.is_entity_shaped() || operation.resource.is_subscription() {
        return enforce_entities(inner, request, &operation, &restriction, &context, preflight, max_body_bytes).await;
    }

    if operation.resource.is_metadata_index() && matches!(operation.mode, Mode::Read) {
        // The type/attribute index aggregates every instance's type; it is narrowed to the allowed
        // types on the way back, and a forbidden single type in the path is refused before the
        // request is sent.
        return enforce_metadata_index(inner, request, &operation, &restriction, &context, max_body_bytes).await;
    }

    Ok(forward(inner, request).await)
}

/// Narrows a request about entities or a subscription, forwards it, and judges the entities of the
/// answer.
async fn enforce_entities<S>(
    inner: S,
    request: Request,
    operation: &Operation,
    restriction: &CompiledTypeRestriction,
    context: &ResolvedContext,
    preflight: &Preflight,
    max_body_bytes: usize,
) -> Result<Response, TypeError>
where
    S: Service<Request, Response = Response, Error = Infallible> + Send + 'static,
    S::Future: Send + 'static,
{
    let join = linked_join(request.extensions(), operation, EntityMember::Type, answer(operation))?;
    let mut request = request::enforce(request, operation, restriction, context, preflight).await?;

    if EntityTarget::of(operation).answers_with_entities() {
        // Every entity of the answer is judged on the way back, and a compressed body cannot be
        // judged, so the broker is asked for an identity encoding.
        request.headers_mut().remove(ACCEPT_ENCODING);
        let response = forward(inner, request).await;

        return response::filter_query_response(response, restriction, context, join, max_body_bytes).await;
    }

    let Some(mode) = join else {
        return Ok(forward(inner, request).await);
    };

    // The linked entities of a join answer are of whatever type their Relationships point at, and
    // are judged on the way back, in an identity encoding for the same reason.
    request.headers_mut().remove(ACCEPT_ENCODING);
    let response = forward(inner, request).await;

    response::filter_join_response(response, restriction, context, mode, max_body_bytes).await
}

/// Refuses a forbidden single type, then narrows the metadata-index response to the allowed types.
///
/// `GET /types/{type}` names one type in the path (NGSI-LD 5.7.7); when the restriction does not allow it
/// the request is refused before it is sent, because the answer would be that type's attribute
/// schema and its instance count. The aggregates returned for `/types`, `/attributes` and their
/// detailed forms are narrowed in the response, so the request goes out without `Accept-Encoding`: a
/// compressed body cannot be filtered, and forwarding it whole is the disclosure this exists to
/// prevent.
async fn enforce_metadata_index<S>(
    inner: S,
    request: Request,
    operation: &Operation,
    restriction: &CompiledTypeRestriction,
    context: &ResolvedContext,
    max_body_bytes: usize,
) -> Result<Response, TypeError>
where
    S: Service<Request, Response = Response, Error = Infallible> + Send + 'static,
    S::Future: Send + 'static,
{
    if let Resource::EntityType { entity_type } = &operation.resource {
        // Each error owns its name, and the operation keeps its own, so the term is cloned into it.
        let expanded = context
            .expand(entity_type)
            .ok_or_else(|| TypeError::Unresolvable { name: entity_type.clone() })?;

        if !restriction.allows(&expanded) {
            return Err(TypeError::TypeDenied {
                entity_type: entity_type.clone(),
            });
        }
    }

    let (mut parts, body) = request.into_parts();
    parts.headers.remove(ACCEPT_ENCODING);

    let response = forward(inner, Request::from_parts(parts, body)).await;

    response::filter_index_response(response, restriction, context, max_body_bytes).await
}

/// Whether the answer to an operation is judged entity by entity on the way back.
///
/// Every read of entities is: the entities of a query answer by their types, and the linked
/// entities of a join answer, of whatever type their Relationships point at, with them.
fn answer(operation: &Operation) -> Answer {
    if operation.mode == Mode::Read && operation.resource.is_entity_shaped() {
        Answer::Judged
    } else {
        Answer::Unjudged
    }
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
    use http::{Method, StatusCode, header::CONTENT_TYPE};
    use http_body_util::BodyExt;
    use jstrict::{Print, Value, json};
    use libra_config::representation::RepresentationStrictness;
    use libra_json_body::{request_body::RequestBody, strict};
    use libra_jsonld_term_expansion::name::Term;
    use libra_linked_entity_layer::layer::LinkedEntityLayer;
    use libra_ngsi_ld_operation_layer::layer::{OperationLayer, classify};
    use libra_ngsi_ld_query::{parameter_name::ParameterName, parameters::QueryParameters};
    use libra_ngsi_ld_query_layer::layer::{QueryLayer, read_query};
    use libra_ngsi_ld_representation_layer::RepresentationLayer;
    use libra_policy_model::{effect::Effect, entity_type::TypeRestriction, member_on_write::MemberOnWrite, policy::PolicyId};
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
    const VEHICLE: &str = "https://uri.fiware.org/ns/data-models#Vehicle";

    const CONTEXT: &str = r#"{
        "@vocab": "https://uri.etsi.org/ngsi-ld/default-context/",
        "Vehicle": "https://uri.fiware.org/ns/data-models#Vehicle",
        "Car": "https://uri.fiware.org/ns/data-models#Vehicle",
        "Building": "https://uri.fiware.org/ns/data-models#Building"
    }"#;

    fn context() -> Arc<ResolvedContext> {
        Arc::new(ResolvedContext::from_json(CONTEXT).expect("the test context should process"))
    }

    fn restriction(allowed: &[&str], type_on_write: MemberOnWrite) -> CompiledTypeRestriction {
        TypeRestriction {
            allowed: allowed.iter().map(|name| Term::new(*name)).collect(),
            type_on_write,
        }
        .compile(&PolicyId::new("test").unwrap(), &context())
        .expect("the test restriction should compile")
    }

    fn decision(restriction: CompiledTypeRestriction) -> Decision {
        Decision {
            effect: Effect::Allow,
            matched: None,
            scope: None,
            entity_type: Some(Arc::new(restriction)),
            time: None,
            attribute: None,
            aggregation: None,
        }
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

    /// What the upstream saw, so a test can assert on the request that was forwarded.
    #[derive(Clone, Default)]
    struct Seen {
        uri: Arc<Mutex<Option<String>>>,
        body: Arc<Mutex<String>>,
    }

    impl Seen {
        fn uri(&self) -> Option<String> {
            self.uri.lock().unwrap_or_else(PoisonError::into_inner).as_deref().map(str::to_owned)
        }

        fn body(&self) -> String {
            self.body.lock().unwrap_or_else(PoisonError::into_inner).to_owned()
        }

        fn types(&self) -> Option<String> {
            let uri = self.uri()?;
            let query = uri.split_once('?').map(|(_, query)| query).unwrap_or_default();

            QueryParameters::parse(query).ok()?.get(&ParameterName::TYPE).map(str::to_owned)
        }
    }

    /// A stand-in for everything below this layer.
    fn upstream(seen: &Seen) -> BoxCloneService<Request, Response, Infallible> {
        let uri = Arc::clone(&seen.uri);
        let body = Arc::clone(&seen.body);
        BoxCloneService::new(tower::service_fn(move |request: Request| {
            let uri = Arc::clone(&uri);
            let body = Arc::clone(&body);
            async move {
                *uri.lock().unwrap_or_else(PoisonError::into_inner) = Some(request.uri().to_string());

                let bytes = request.into_body().collect().await.map(http_body_util::Collected::to_bytes).unwrap_or_default();
                *body.lock().unwrap_or_else(PoisonError::into_inner) = String::from_utf8_lossy(&bytes).into_owned();

                Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from("[]"))
                    .unwrap_or_else(|_| Response::new(Body::empty())))
            }
        }))
    }

    /// A request as the layers above leave it: its context resolved and its body read once.
    fn request(method: Method, uri: &str, decision: Option<Decision>, body: &str) -> Request {
        let mut request = Request::builder()
            .method(method)
            .uri(uri)
            .header(CONTENT_TYPE, "application/json")
            .header("NGSILD-Tenant", "acme")
            .header("Link", "<https://example.test/context.jsonld>; rel=\"http://www.w3.org/ns/json-ld#context\"")
            .body(Body::from(body.to_owned()))
            .unwrap_or_else(|_| Request::new(Body::empty()));

        request.extensions_mut().insert(RequestContextExtension(context()));
        request
            .extensions_mut()
            .insert(RequestBody::read(body.as_bytes()).expect("the test body should read"));
        if let Some(decision) = decision {
            request.extensions_mut().insert(decision);
        }

        request
    }

    /// A broker that answers every pre-flight with the same entity document.
    async fn broker(body: &Value) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(any()).respond_with(json_response(body)).mount(&server).await;

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

    /// The first entry of a list.
    fn first(document: &Value) -> Option<&Value> {
        document.as_array()?.first()
    }

    fn typed(entity_type: &str) -> Value {
        json!({ "id": ENTITY, "type": entity_type })
    }

    async fn run(broker_url: &str, request: Request, seen: &Seen) -> Response {
        run_with(broker_url, request, upstream(seen)).await
    }

    /// A stand-in broker returning a fixed metadata-index body, for the response-narrowing path.
    fn index_upstream(content_type: &'static str, body: impl Into<String>) -> BoxCloneService<Request, Response, Infallible> {
        let body: Arc<str> = Arc::from(body.into());

        BoxCloneService::new(tower::service_fn(move |_request: Request| {
            let body = Arc::clone(&body);
            async move {
                Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header(CONTENT_TYPE, content_type)
                    .body(Body::from(body.to_string()))
                    .unwrap_or_else(|_| Response::new(Body::empty())))
            }
        }))
    }

    /// The layer under the four that resolve, above authorization, what it reads.
    async fn run_with(broker_url: &str, request: Request, inner: BoxCloneService<Request, Response, Infallible>) -> Response {
        let types = TypeEnforcementLayer::new(
            Arc::new(Preflight::new(Url::parse(broker_url).expect("a URL"), 64 * 1024).expect("the client should build")),
            64 * 1024,
        );
        let mut service = OperationLayer::new().layer(
            QueryLayer::new().layer(LinkedEntityLayer::new().layer(RepresentationLayer::new(RepresentationStrictness::default()).layer(types.layer(inner)))),
        );

        service.call(request).await.unwrap_or_else(|error| match error {})
    }

    async fn body_of(response: Response) -> String {
        let bytes = response
            .into_body()
            .collect()
            .await
            .map(http_body_util::Collected::to_bytes)
            .unwrap_or_default();

        String::from_utf8_lossy(&bytes).into_owned()
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
    async fn the_restriction_is_written_out_rather_than_a_sentinel_standing_in_for_it() {
        // What goes out when the request names no type is the restriction itself, as IRIs; a restriction
        // that allows nothing cannot be built at all.
        let seen = Seen::default();
        let response = run(
            "http://127.0.0.1:1",
            request(
                Method::GET,
                "/ngsi-ld/v1/entities",
                Some(decision(restriction(&["Vehicle"], MemberOnWrite::Required))),
                "",
            ),
            &seen,
        )
        .await;

        let forwarded = seen.uri().unwrap_or_default();

        assert_ne!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(!forwarded.contains("FIWARE_UNAUTHORIZED"), "{forwarded}");
        assert!(forwarded.contains("data-models"), "the restriction goes out as an IRI: {forwarded}");
    }

    #[tokio::test]
    async fn a_pre_flight_that_does_not_answer_usably_is_a_refusal_rather_than_permission() {
        // The pre-flight asks for the entity itself: a URL of `?attrs=type&type=*` is not defined by
        // NGSI-LD, a broker may answer it with 400, and a non-2xx must never be read as permission or the
        // malformed request would itself allow access.
        for status in [400, 404, 500, 503] {
            let server = failing_broker(status).await;
            let seen = Seen::default();

            let response = run(
                &server.uri(),
                request(
                    Method::DELETE,
                    &format!("/ngsi-ld/v1/entities/{ENTITY}"),
                    Some(decision(restriction(&["Vehicle"], MemberOnWrite::Required))),
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
    async fn a_read_of_one_entity_outside_the_restriction_is_refused() {
        let server = broker(&typed("Building")).await;
        let seen = Seen::default();

        let response = run(
            &server.uri(),
            request(
                Method::GET,
                &format!("/ngsi-ld/v1/entities/{ENTITY}"),
                Some(decision(restriction(&["Vehicle"], MemberOnWrite::Required))),
                "",
            ),
            &seen,
        )
        .await;

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(seen.uri(), None);
    }

    #[tokio::test]
    async fn a_merge_patch_is_pre_flighted_rather_than_refused_for_carrying_no_type() {
        // `PATCH /entities/{id}` carries the members to merge and no type, so it is not held to
        // `type-on-write` as a payload with the type left out; doing so would refuse every merge.
        let server = broker(&typed("Vehicle")).await;
        let seen = Seen::default();

        let response = run(
            &server.uri(),
            request(
                Method::PATCH,
                &format!("/ngsi-ld/v1/entities/{ENTITY}"),
                Some(decision(restriction(&["Vehicle"], MemberOnWrite::Required))),
                r#"{"speed":{"type":"Property","value":42}}"#,
            ),
            &seen,
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            seen.body(),
            r#"{"speed":{"type":"Property","value":42}}"#,
            "the body must reach the broker intact"
        );
    }

    #[tokio::test]
    async fn an_attribute_value_is_not_judged_as_an_entity_of_type_property() {
        let server = broker(&typed("Vehicle")).await;

        for method in [Method::PATCH, Method::PUT] {
            let seen = Seen::default();
            let response = run(
                &server.uri(),
                request(
                    method.clone(),
                    &format!("/ngsi-ld/v1/entities/{ENTITY}/attrs/speed"),
                    Some(decision(restriction(&["Vehicle"], MemberOnWrite::Required))),
                    r#"{"type":"Property","value":42}"#,
                ),
                &seen,
            )
            .await;

            assert_eq!(response.status(), StatusCode::OK, "{method}");
            assert_eq!(seen.body(), r#"{"type":"Property","value":42}"#, "{method}");
        }
    }

    #[tokio::test]
    async fn an_attribute_write_to_an_entity_of_a_forbidden_type_is_still_refused() {
        let server = broker(&typed("Building")).await;

        let response = run(
            &server.uri(),
            request(
                Method::PATCH,
                &format!("/ngsi-ld/v1/entities/{ENTITY}/attrs/speed"),
                Some(decision(restriction(&["Vehicle"], MemberOnWrite::Required))),
                r#"{"type":"Property","value":42}"#,
            ),
            &Seen::default(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn a_join_on_an_entity_write_is_not_judged_as_a_linked_answer() {
        // A write answers with no entities and notifies nobody, so `join` there asks for nothing a
        // type could be judged in; refusing it as an unservable join would refuse a valid write.
        let server = broker(&typed("Vehicle")).await;
        let seen = Seen::default();

        let response = run(
            &server.uri(),
            request(
                Method::PATCH,
                &format!("/ngsi-ld/v1/entities/{ENTITY}?join=inline&options=keyValues"),
                Some(decision(restriction(&["Vehicle"], MemberOnWrite::Required))),
                r#"{"speed":{"type":"Property","value":42}}"#,
            ),
            &seen,
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(seen.body(), r#"{"speed":{"type":"Property","value":42}}"#);
    }

    #[tokio::test]
    async fn a_replace_that_would_change_the_type_to_one_outside_the_restriction_is_refused() {
        let server = broker(&typed("Vehicle")).await;

        let response = run(
            &server.uri(),
            request(
                Method::PUT,
                &format!("/ngsi-ld/v1/entities/{ENTITY}"),
                Some(decision(restriction(&["Vehicle"], MemberOnWrite::Required))),
                r#"{"id":"urn:ngsi-ld:Vehicle:1","type":"Building"}"#,
            ),
            &Seen::default(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn a_batch_delete_is_pre_flighted_rather_than_skipped() {
        // It is checked, not left to the broker: the broker is the thing the restriction exists to
        // constrain.
        let server = broker(&typed("Building")).await;
        let seen = Seen::default();

        let response = run(
            &server.uri(),
            request(
                Method::POST,
                "/ngsi-ld/v1/entityOperations/delete",
                Some(decision(restriction(&["Vehicle"], MemberOnWrite::Required))),
                r#"["urn:ngsi-ld:Vehicle:1"]"#,
            ),
            &seen,
        )
        .await;

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(seen.uri(), None);
    }

    #[tokio::test]
    async fn a_batch_delete_of_allowed_types_is_forwarded() {
        let server = broker(&typed("Vehicle")).await;
        let seen = Seen::default();

        let response = run(
            &server.uri(),
            request(
                Method::POST,
                "/ngsi-ld/v1/entityOperations/delete",
                Some(decision(restriction(&["Vehicle"], MemberOnWrite::Required))),
                r#"["urn:ngsi-ld:Vehicle:1","urn:ngsi-ld:Vehicle:2"]"#,
            ),
            &seen,
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(seen.body(), r#"["urn:ngsi-ld:Vehicle:1","urn:ngsi-ld:Vehicle:2"]"#);
    }

    #[tokio::test]
    async fn a_type_selector_in_a_query_body_is_inspected() {
        // `entities: [{"type": ...}]` in the payload is what decides what this endpoint returns, so the
        // payload is checked as well as the URL.
        let seen = Seen::default();

        let response = run(
            "http://127.0.0.1:1",
            request(
                Method::POST,
                "/ngsi-ld/v1/entityOperations/query",
                Some(decision(restriction(&["Vehicle"], MemberOnWrite::Required))),
                r#"{"type":"Query","entities":[{"type":"Building"}]}"#,
            ),
            &seen,
        )
        .await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(seen.uri(), None);
    }

    #[tokio::test]
    async fn a_query_body_without_selectors_is_given_the_restriction() {
        let seen = Seen::default();

        let response = run(
            "http://127.0.0.1:1",
            request(
                Method::POST,
                "/ngsi-ld/v1/temporal/entityOperations/query",
                Some(decision(restriction(&["Vehicle"], MemberOnWrite::Required))),
                r#"{"type":"Query"}"#,
            ),
            &seen,
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert!(seen.body().contains(VEHICLE), "{}", seen.body());
    }

    #[tokio::test]
    async fn a_collection_read_without_a_type_is_given_the_restriction_as_iris() {
        let seen = Seen::default();

        let response = run(
            "http://127.0.0.1:1",
            request(
                Method::GET,
                "/ngsi-ld/v1/entities?limit=10",
                Some(decision(restriction(&["Vehicle"], MemberOnWrite::Required))),
                "",
            ),
            &seen,
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(seen.types().as_deref(), Some(VEHICLE), "an IRI cannot be redefined by the caller's own context");
    }

    #[tokio::test]
    async fn a_caller_sending_the_expanded_iri_reaches_the_same_comparison() {
        // The bypass a proxy comparing words never sees: the caller writes the IRI instead of the
        // term, and the policy's word `Vehicle` does not match the string.
        let seen = Seen::default();

        let allowed = run(
            "http://127.0.0.1:1",
            request(
                Method::GET,
                "/ngsi-ld/v1/entities?type=https%3A%2F%2Furi.fiware.org%2Fns%2Fdata-models%23Vehicle",
                Some(decision(restriction(&["Vehicle"], MemberOnWrite::Required))),
                "",
            ),
            &seen,
        )
        .await;

        assert_eq!(allowed.status(), StatusCode::OK);

        let refused = run(
            "http://127.0.0.1:1",
            request(
                Method::GET,
                "/ngsi-ld/v1/entities?type=https%3A%2F%2Furi.fiware.org%2Fns%2Fdata-models%23Building",
                Some(decision(restriction(&["Vehicle"], MemberOnWrite::Required))),
                "",
            ),
            &seen,
        )
        .await;

        assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn an_aliased_type_is_recognised_as_the_type_it_expands_to() {
        let seen = Seen::default();

        let response = run(
            "http://127.0.0.1:1",
            request(
                Method::GET,
                "/ngsi-ld/v1/entities?type=Car",
                Some(decision(restriction(&["Vehicle"], MemberOnWrite::Required))),
                "",
            ),
            &seen,
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK, "Car and Vehicle are one type under the request's context");
    }

    #[tokio::test]
    async fn a_type_selection_expression_is_understood_rather_than_read_as_one_name() {
        let seen = Seen::default();

        let response = run(
            "http://127.0.0.1:1",
            request(
                Method::GET,
                "/ngsi-ld/v1/entities?type=Vehicle%7CCar",
                Some(decision(restriction(&["Vehicle"], MemberOnWrite::Required))),
                "",
            ),
            &seen,
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            seen.types().as_deref(),
            Some("Vehicle|Car"),
            "the caller's own expression is forwarded once it checks out"
        );
    }

    #[tokio::test]
    async fn a_type_selection_allowed_in_part_is_narrowed_to_that_part() {
        for (query, forwarded) in [("Vehicle,Building", "Vehicle"), ("(Vehicle%3BBuilding)%7CVehicle", "Vehicle")] {
            let seen = Seen::default();
            let response = run(
                "http://127.0.0.1:1",
                request(
                    Method::GET,
                    &format!("/ngsi-ld/v1/entities?type={query}"),
                    Some(decision(restriction(&["Vehicle"], MemberOnWrite::Required))),
                    "",
                ),
                &seen,
            )
            .await;

            assert_eq!(response.status(), StatusCode::OK, "{query}");
            assert_eq!(seen.types().as_deref(), Some(forwarded), "{query}");
        }
    }

    #[tokio::test]
    async fn a_conjunction_with_a_forbidden_type_is_refused() {
        // An entity of a forbidden type is not readable for also having an allowed one.
        let seen = Seen::default();
        let response = run(
            "http://127.0.0.1:1",
            request(
                Method::GET,
                "/ngsi-ld/v1/entities?type=Vehicle%3BBuilding",
                Some(decision(restriction(&["Vehicle"], MemberOnWrite::Required))),
                "",
            ),
            &seen,
        )
        .await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(seen.uri(), None);
    }

    #[tokio::test]
    async fn selectors_of_a_forbidden_type_are_dropped_from_a_batch_query_and_a_subscription() {
        for (path, body) in [
            (
                "/ngsi-ld/v1/entityOperations/query",
                r#"{"type":"Query","entities":[{"type":"Building"},{"type":"Vehicle"}]}"#,
            ),
            (
                "/ngsi-ld/v1/subscriptions",
                r#"{"type":"Subscription","entities":[{"type":"Building"},{"type":"Vehicle"}],"notification":{"endpoint":{"uri":"http://sink.test"}}}"#,
            ),
        ] {
            let seen = Seen::default();
            let response = run(
                "http://127.0.0.1:1",
                request(Method::POST, path, Some(decision(restriction(&["Vehicle"], MemberOnWrite::Optional))), body),
                &seen,
            )
            .await;

            assert_eq!(response.status(), StatusCode::OK, "{path}");
            let forwarded = strict::parse(seen.body().as_bytes()).unwrap_or(Value::Null);
            assert_eq!(member(&forwarded, "entities"), Some(&json!([{ "type": "Vehicle" }])), "{path}");
        }
    }

    #[tokio::test]
    async fn a_subscription_whose_every_selector_is_forbidden_is_refused() {
        let seen = Seen::default();
        let response = run(
            "http://127.0.0.1:1",
            request(
                Method::POST,
                "/ngsi-ld/v1/subscriptions",
                Some(decision(restriction(&["Vehicle"], MemberOnWrite::Optional))),
                r#"{"type":"Subscription","entities":[{"type":"Building"}],"notification":{"endpoint":{"uri":"http://sink.test"}}}"#,
            ),
            &seen,
        )
        .await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(seen.uri(), None);
    }

    #[tokio::test]
    async fn an_empty_type_parameter_is_replaced_by_the_restriction_rather_than_forwarded() {
        // `?type=` is read by brokers as no filter at all, so it has to be treated as a selection
        // the caller never wrote, not refused, and above all not passed on as it stands.
        let seen = Seen::default();

        let response = run(
            "http://127.0.0.1:1",
            request(
                Method::GET,
                "/ngsi-ld/v1/entities?type=",
                Some(decision(restriction(&["Vehicle"], MemberOnWrite::Required))),
                "",
            ),
            &seen,
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(seen.types().as_deref(), Some(VEHICLE));
    }

    #[tokio::test]
    async fn a_type_expression_that_cannot_be_parsed_is_refused_rather_than_passed_through() {
        let seen = Seen::default();

        let response = run(
            "http://127.0.0.1:1",
            request(
                Method::GET,
                "/ngsi-ld/v1/entities?type=Vehicle%3B",
                Some(decision(restriction(&["Vehicle"], MemberOnWrite::Required))),
                "",
            ),
            &seen,
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(seen.uri(), None, "an expression Libra cannot read must not reach the broker");
    }

    #[tokio::test]
    async fn a_create_without_a_type_follows_the_policy_flag() {
        let seen = Seen::default();

        let refused = run(
            "http://127.0.0.1:1",
            request(
                Method::POST,
                "/ngsi-ld/v1/entities",
                Some(decision(restriction(&["Vehicle"], MemberOnWrite::Required))),
                r#"{"id":"urn:ngsi-ld:Vehicle:9"}"#,
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
                Some(decision(restriction(&["Vehicle"], MemberOnWrite::Optional))),
                r#"{"id":"urn:ngsi-ld:Vehicle:9"}"#,
            ),
            &seen,
        )
        .await;

        assert_eq!(allowed.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn a_request_reaching_this_layer_without_a_resolved_context_is_refused() {
        let mut request = Request::builder()
            .method(Method::GET)
            .uri("/ngsi-ld/v1/entities")
            .body(Body::empty())
            .unwrap_or_else(|_| Request::new(Body::empty()));
        request.extensions_mut().insert(decision(restriction(&["Vehicle"], MemberOnWrite::Required)));

        let response = run("http://127.0.0.1:1", request, &Seen::default()).await;

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn the_pre_flight_carries_the_tenant_and_the_context_link() {
        let server = MockServer::start().await;
        Mock::given(any())
            .and(header("NGSILD-Tenant", "acme"))
            .and(header(
                "Link",
                "<https://example.test/context.jsonld>; rel=\"http://www.w3.org/ns/json-ld#context\"",
            ))
            .respond_with(json_response(&typed("Vehicle")))
            .mount(&server)
            .await;

        let response = run(
            &server.uri(),
            request(
                Method::GET,
                &format!("/ngsi-ld/v1/entities/{ENTITY}"),
                Some(decision(restriction(&["Vehicle"], MemberOnWrite::Required))),
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
    async fn the_pre_flight_states_the_representation_it_reads() {
        // The answer is read as a normalized entity, with `type` a member of the document. Left to
        // the broker's default that is an assumption rather than a fact, and a broker defaulting to
        // `application/geo+json` would put the members somewhere else entirely.
        let server = MockServer::start().await;
        Mock::given(any())
            .and(header("Accept", "application/ld+json"))
            .respond_with(json_response(&typed("Vehicle")))
            .mount(&server)
            .await;

        let response = run(
            &server.uri(),
            request(
                Method::GET,
                &format!("/ngsi-ld/v1/entities/{ENTITY}"),
                Some(decision(restriction(&["Vehicle"], MemberOnWrite::Required))),
                "",
            ),
            &Seen::default(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK, "the pre-flight only matches when it asks for ld+json");
    }

    #[tokio::test]
    async fn the_types_index_drops_a_forbidden_type() {
        // The metadata index (NGSI-LD 5.2.24) lists type names aggregated over every instance. A
        // type restriction is undone if the index still names a type the caller may not read, so the
        // response is narrowed to the allowed types.
        const INDEX: &str = r#"{"id":"urn:ngsi-ld:EntityTypeList:1","type":"EntityTypeList","typeList":["Vehicle","Building"]}"#;

        let response = run_with(
            "http://127.0.0.1:1",
            request(
                Method::GET,
                "/ngsi-ld/v1/types",
                Some(decision(restriction(&["Vehicle"], MemberOnWrite::Optional))),
                "",
            ),
            index_upstream("application/json", INDEX),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);

        let body = body_of(response).await;

        assert!(body.contains("Vehicle"), "{body}");
        assert!(!body.contains("Building"), "the index must not name a forbidden type: {body}");
    }

    #[tokio::test]
    async fn a_forbidden_single_type_index_is_refused_before_the_request_is_sent() {
        // `GET /types/{type}` (NGSI-LD 5.7.7) would answer with the type's attribute schema and its
        // instance count. A forbidden type is refused rather than narrowed.
        let response = run_with(
            "http://127.0.0.1:1",
            request(
                Method::GET,
                "/ngsi-ld/v1/types/Building",
                Some(decision(restriction(&["Vehicle"], MemberOnWrite::Optional))),
                "",
            ),
            index_upstream("application/json", "{}"),
        )
        .await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn a_path_this_layer_does_not_govern_is_left_alone() {
        let seen = Seen::default();

        let response = run(
            "http://127.0.0.1:1",
            request(
                Method::GET,
                "/ngsi-ld/v1/jsonldContexts",
                Some(decision(restriction(&["Vehicle"], MemberOnWrite::Required))),
                "",
            ),
            &seen,
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(seen.uri().as_deref(), Some("/ngsi-ld/v1/jsonldContexts"));
    }

    #[tokio::test]
    async fn a_read_this_layer_does_not_govern_is_not_narrowed_as_a_metadata_index() {
        let contexts = r#"["https://example.test/context.jsonld"]"#;

        let response = run_with(
            "http://127.0.0.1:1",
            request(
                Method::GET,
                "/ngsi-ld/v1/jsonldContexts",
                Some(decision(restriction(&["Vehicle"], MemberOnWrite::Required))),
                "",
            ),
            index_upstream("application/json", contexts),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_of(response).await, contexts);
    }

    fn building(id: &str) -> Value {
        json!({ "id": id, "type": "Building", "name": { "type": "Property", "value": "Depot" } })
    }

    async fn joined(uri: &str, answer: &Value) -> Response {
        run_with(
            "http://127.0.0.1:1",
            request(Method::GET, uri, Some(decision(restriction(&["Vehicle"], MemberOnWrite::Optional))), ""),
            index_upstream("application/json", answer.to_string()),
        )
        .await
    }

    #[tokio::test]
    async fn a_linked_entity_of_a_forbidden_type_is_withheld_from_an_inline_answer() {
        // Linked Entity Retrieval (NGSI-LD 4.5.23) returns the entities a Relationship points at, of
        // whatever type they are. The linked Building is removed; the Relationship naming it stays.
        let answer = json!([{ "id": ENTITY, "type": "Vehicle",
            "locatedIn": { "type": "Relationship", "object": "urn:ngsi-ld:Building:1", "entity": building("urn:ngsi-ld:Building:1") },
            "follows": { "type": "Relationship", "object": "urn:ngsi-ld:Vehicle:2", "entity": { "id": "urn:ngsi-ld:Vehicle:2", "type": "Car" } } }]);

        let response = joined("/ngsi-ld/v1/entities?type=Vehicle&join=inline", &answer).await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = strict::parse(body_of(response).await.as_bytes()).expect("JSON");
        let vehicle = first(&body);
        assert_eq!(
            vehicle.and_then(|entity| member(entity, "locatedIn")),
            Some(&json!({ "type": "Relationship", "object": "urn:ngsi-ld:Building:1" }))
        );
        assert_eq!(
            vehicle
                .and_then(|entity| member(entity, "follows"))
                .and_then(|follows| member(follows, "entity")),
            Some(&json!({ "id": "urn:ngsi-ld:Vehicle:2", "type": "Car" })),
            "Car is Vehicle here"
        );
    }

    #[tokio::test]
    async fn a_linked_entity_of_a_forbidden_type_or_of_no_type_is_withheld_from_a_flat_answer() {
        let answer = json!([{ "id": ENTITY, "type": "Vehicle" }, building("urn:ngsi-ld:Building:1"), { "id": "urn:ngsi-ld:Thing:1" }]);

        let response = joined("/ngsi-ld/v1/entities?type=Vehicle&join=flat", &answer).await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_of(response).await, json!([{ "id": ENTITY, "type": "Vehicle" }]).to_string());
    }

    #[tokio::test]
    async fn a_join_answer_to_a_read_by_id_is_judged_after_the_pre_flight() {
        let server = broker(&typed("Vehicle")).await;
        let answer = json!([typed("Vehicle"), building("urn:ngsi-ld:Building:1")]);

        let response = run_with(
            &server.uri(),
            request(
                Method::GET,
                &format!("/ngsi-ld/v1/entities/{ENTITY}?join=flat"),
                Some(decision(restriction(&["Vehicle"], MemberOnWrite::Optional))),
                "",
            ),
            index_upstream("application/json", answer.to_string()),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_of(response).await, json!([typed("Vehicle")]).to_string());
    }

    #[tokio::test]
    async fn a_projection_that_removes_type_is_refused_before_it_is_sent() {
        // With or without a join: every entity of the answer is judged by its type.
        for query in [
            "pick=speed",
            "omit=type",
            "pick=speed&join=inline",
            "join=flat&omit=type",
            "join=inline&pick=type,isParked{name}",
        ] {
            let seen = Seen::default();
            let response = run(
                "http://127.0.0.1:1",
                request(
                    Method::GET,
                    &format!("/ngsi-ld/v1/entities?type=Vehicle&{query}"),
                    Some(decision(restriction(&["Vehicle"], MemberOnWrite::Optional))),
                    "",
                ),
                &seen,
            )
            .await;

            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{query}");
            assert_eq!(seen.uri(), None, "{query}");
        }
    }

    #[tokio::test]
    async fn an_inline_join_in_key_values_is_refused() {
        let seen = Seen::default();
        let response = run(
            "http://127.0.0.1:1",
            request(
                Method::GET,
                "/ngsi-ld/v1/entities?type=Vehicle&join=inline&options=keyValues",
                Some(decision(restriction(&["Vehicle"], MemberOnWrite::Optional))),
                "",
            ),
            &seen,
        )
        .await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(seen.uri(), None);
    }

    #[tokio::test]
    async fn a_join_level_without_a_join_is_refused_before_the_pre_flight() {
        // A single-entity read with a restriction ordinarily pre-flights the broker for the entity's
        // type. A `joinLevel` with no `join` is refused ahead of that, so no request is made at all:
        // pinned by a broker address that would fail if it were contacted.
        let seen = Seen::default();
        let response = run(
            "http://127.0.0.1:1",
            request(
                Method::GET,
                &format!("/ngsi-ld/v1/entities/{ENTITY}?joinLevel=2"),
                Some(decision(restriction(&["Vehicle"], MemberOnWrite::Optional))),
                "",
            ),
            &seen,
        )
        .await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(seen.uri(), None);
    }

    #[tokio::test]
    async fn an_unrestricted_join_answer_is_forwarded_byte_for_byte() {
        const ANSWER: &str = r#"[ { "id" : "urn:ngsi-ld:Vehicle:1", "type" : "Vehicle" }, { "id" : "urn:b", "type" : "Building" } ]"#;

        let response = run_with(
            "http://127.0.0.1:1",
            request(Method::GET, "/ngsi-ld/v1/entities?type=Vehicle&join=flat", Some(unrestricted()), ""),
            index_upstream("application/json", ANSWER),
        )
        .await;

        assert_eq!(body_of(response).await, ANSWER);
    }

    #[tokio::test]
    async fn a_join_read_passes_when_no_type_restriction() {
        // The layer only runs when a type restriction is attached; an unrestricted caller keeps
        // linked retrieval, and the request reaches the broker unrefused.
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
    async fn a_linked_entity_filter_is_refused_when_types_are_restricted() {
        // Clause 4.9: the vehicles are selected by an attribute of the entity `parkedIn` points at,
        // of whatever type that is.
        let seen = Seen::default();
        let response = run(
            "http://127.0.0.1:1",
            request(
                Method::GET,
                "/ngsi-ld/v1/entities?type=Vehicle&q=parkedIn{name}==%22Downtown%22",
                Some(decision(restriction(&["Vehicle"], MemberOnWrite::Optional))),
                "",
            ),
            &seen,
        )
        .await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(seen.uri(), None);
    }

    #[tokio::test]
    async fn unservable_linked_entity_retrieval_in_a_batch_query_body_is_refused_when_types_are_restricted() {
        // NGSI-LD 5.2.23 gives the Query body `join`, `joinLevel`, projections and `q` of its own,
        // and what no answer can be judged against is refused there as it is in the query string.
        for body in [
            r#"{"type": "Query", "entities": [{"type": "Vehicle"}], "joinLevel": 2}"#,
            r#"{"type": "Query", "entities": [{"type": "Vehicle"}], "pick": ["type", "parkedIn{type,name}"]}"#,
            r#"{"type": "Query", "entities": [{"type": "Vehicle"}], "q": "parkedIn{name}==\"Downtown\""}"#,
        ] {
            let seen = Seen::default();
            let response = run(
                "http://127.0.0.1:1",
                request(
                    Method::POST,
                    "/ngsi-ld/v1/entityOperations/query",
                    Some(decision(restriction(&["Vehicle"], MemberOnWrite::Optional))),
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
    async fn a_batch_query_body_without_linked_retrieval_still_reaches_the_broker() {
        let seen = Seen::default();
        let response = run(
            "http://127.0.0.1:1",
            request(
                Method::POST,
                "/ngsi-ld/v1/entityOperations/query",
                Some(decision(restriction(&["Vehicle"], MemberOnWrite::Optional))),
                r#"{"type": "Query", "entities": [{"type": "Vehicle"}], "join": "@none", "pick": ["type", "speed|brand"]}"#,
            ),
            &seen,
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert!(seen.uri().is_some());
    }

    #[tokio::test]
    async fn linked_entity_retrieval_in_a_subscription_is_refused_when_types_are_restricted() {
        // NGSI-LD 5.2.14: the notification carries `join` and `joinLevel`, and the linked entities
        // it delivers never pass back through Libra to be narrowed.
        for body in [
            r#"{"type": "Subscription", "entities": [{"type": "Vehicle"}], "notification": {"join": "flat", "endpoint": {"uri": "http://sink.test"}}}"#,
            r#"{"type": "Subscription", "entities": [{"type": "Vehicle"}], "notification": {"pick": ["parkedIn{name}"], "endpoint": {"uri": "http://sink.test"}}}"#,
            r#"{"type": "Subscription", "entities": [{"type": "Vehicle"}], "q": "parkedIn{name}==\"Downtown\"", "notification": {"endpoint": {"uri": "http://sink.test"}}}"#,
        ] {
            let seen = Seen::default();
            let response = run(
                "http://127.0.0.1:1",
                request(
                    Method::POST,
                    "/ngsi-ld/v1/subscriptions",
                    Some(decision(restriction(&["Vehicle"], MemberOnWrite::Optional))),
                    body,
                ),
                &seen,
            )
            .await;

            assert_eq!(response.status(), StatusCode::FORBIDDEN, "{body}");
            assert_eq!(seen.uri(), None, "{body}");
        }
    }

    fn registration(id: &str, information: Value) -> Value {
        json!({ "id": id, "type": "ContextSourceRegistration", "endpoint": "http://source.test", "information": information })
    }

    fn registering(entity_type: &str) -> Value {
        registration(&format!("urn:r:{entity_type}"), json!([{ "entities": [{ "type": entity_type }] }]))
    }

    #[tokio::test]
    async fn a_registration_listing_shows_only_registrations_of_allowed_types() {
        let attributes_only = registration("urn:r:speed", json!([{ "propertyNames": ["speed"] }]));
        let listing = json!([registering("Vehicle"), registering("Building"), attributes_only]);

        let response = run_with(
            "http://127.0.0.1:1",
            request(
                Method::GET,
                "/ngsi-ld/v1/csourceRegistrations",
                Some(decision(restriction(&["Vehicle"], MemberOnWrite::Optional))),
                "",
            ),
            index_upstream("application/json", listing.to_string()),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        let shown = strict::parse(body_of(response).await.as_bytes()).unwrap_or(Value::Null);
        assert_eq!(shown, json!([registering("Vehicle")]));
    }

    #[tokio::test]
    async fn a_registration_read_by_id_of_a_forbidden_type_is_answered_as_absent() {
        let response = run_with(
            "http://127.0.0.1:1",
            request(
                Method::GET,
                "/ngsi-ld/v1/csourceRegistrations/urn:r:Building",
                Some(decision(restriction(&["Vehicle"], MemberOnWrite::Optional))),
                "",
            ),
            index_upstream("application/ld+json", registering("Building").to_string()),
        )
        .await;

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(!body_of(response).await.contains("source.test"), "nothing of the registration is disclosed");
    }

    #[tokio::test]
    async fn a_registration_create_is_checked_against_what_it_registers() {
        let attributes_only = registration("urn:r:speed", json!([{ "propertyNames": ["speed"] }])).to_string();

        for (body, expected) in [
            (registering("Vehicle").to_string(), StatusCode::OK),
            (registering("Building").to_string(), StatusCode::FORBIDDEN),
            (attributes_only, StatusCode::FORBIDDEN),
        ] {
            let seen = Seen::default();
            let created = request(
                Method::POST,
                "/ngsi-ld/v1/csourceRegistrations",
                Some(decision(restriction(&["Vehicle"], MemberOnWrite::Optional))),
                &body,
            );

            let response = run("http://127.0.0.1:1", created, &seen).await;

            assert_eq!(response.status(), expected, "{body}");
            assert_eq!(seen.uri().is_some(), expected == StatusCode::OK, "{body}");
        }
    }

    #[tokio::test]
    async fn a_registration_update_or_delete_is_judged_by_the_registration_that_exists() {
        for (existing, expected) in [("Building", StatusCode::NOT_FOUND), ("Vehicle", StatusCode::OK)] {
            let server = broker(&registering(existing)).await;

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
                        Some(decision(restriction(&["Vehicle"], MemberOnWrite::Optional))),
                        body,
                    ),
                    &seen,
                )
                .await;

                assert_eq!(response.status(), expected, "{method} of a {existing} registration");
                assert_eq!(seen.uri().is_some(), expected == StatusCode::OK, "{method} of a {existing} registration");
            }
        }
    }

    #[tokio::test]
    async fn a_registration_update_to_a_forbidden_type_is_refused() {
        let server = broker(&registering("Vehicle")).await;
        let seen = Seen::default();
        let response = run(
            &server.uri(),
            request(
                Method::PATCH,
                "/ngsi-ld/v1/csourceRegistrations/urn:r:1",
                Some(decision(restriction(&["Vehicle"], MemberOnWrite::Optional))),
                r#"{"information":[{"entities":[{"type":"Building"}]}]}"#,
            ),
            &seen,
        )
        .await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(seen.uri(), None);
    }

    #[tokio::test]
    async fn a_context_source_subscription_is_refused_when_types_are_restricted() {
        let seen = Seen::default();
        let response = run(
            "http://127.0.0.1:1",
            request(
                Method::GET,
                "/ngsi-ld/v1/csourceSubscriptions",
                Some(decision(restriction(&["Vehicle"], MemberOnWrite::Optional))),
                "",
            ),
            &seen,
        )
        .await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(seen.uri(), None, "context source subscription request must not reach broker");
    }

    #[tokio::test]
    async fn an_entity_map_read_is_refused_when_types_are_restricted() {
        let seen = Seen::default();
        let response = run(
            "http://127.0.0.1:1",
            request(
                Method::GET,
                "/ngsi-ld/v1/entityMaps",
                Some(decision(restriction(&["Vehicle"], MemberOnWrite::Optional))),
                "",
            ),
            &seen,
        )
        .await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(seen.uri(), None, "entity map request must not reach broker");
    }

    #[tokio::test]
    async fn a_request_without_a_parsed_body_is_refused() {
        // A body this layer cannot see is one whose types it cannot check: forwarding it would be
        // forwarding a create nobody judged.
        let seen = Seen::default();
        let mut created = request(
            Method::POST,
            "/ngsi-ld/v1/entities",
            Some(decision(restriction(&["Vehicle"], MemberOnWrite::Optional))),
            r#"{"id":"urn:ngsi-ld:Building:1","type":"Building"}"#,
        );
        created.extensions_mut().remove::<RequestBody>();

        let response = run("http://127.0.0.1:1", created, &seen).await;

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(seen.uri(), None);
    }

    #[tokio::test]
    async fn a_batch_query_inside_the_restriction_is_forwarded_as_the_caller_wrote_it() {
        const QUERY: &str = r#"{ "type" : "Query", "entities" : [ { "type" : "Vehicle" } ], "q" : "speed>40" }"#;

        let seen = Seen::default();
        let response = run(
            "http://127.0.0.1:1",
            request(
                Method::POST,
                "/ngsi-ld/v1/entityOperations/query",
                Some(decision(restriction(&["Vehicle"], MemberOnWrite::Optional))),
                QUERY,
            ),
            &seen,
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(seen.body(), QUERY, "a body nothing was narrowed out of keeps its bytes");
    }

    #[tokio::test]
    async fn a_temporal_entity_map_is_refused_when_types_are_restricted() {
        // NGSI-LD 6.35: an entity map built from a temporal query maps the identifiers of entities of
        // every type, exactly as `/entityMaps` does.
        let seen = Seen::default();
        let response = run(
            "http://127.0.0.1:1",
            request(
                Method::POST,
                "/ngsi-ld/v1/temporal/entityMaps",
                Some(decision(restriction(&["Vehicle"], MemberOnWrite::Optional))),
                r#"{"type":"Query"}"#,
            ),
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
    async fn the_type_selection_is_read_from_the_stored_query_not_from_the_request_target() {
        let seen = Seen::default();
        let request = with_stored_query(
            request(
                Method::GET,
                "/ngsi-ld/v1/entities?type=Building",
                Some(decision(restriction(&["Vehicle"], MemberOnWrite::Required))),
                "",
            ),
            "type=Vehicle",
        );
        let types = TypeEnforcementLayer::new(
            Arc::new(Preflight::new(Url::parse("http://127.0.0.1:1").unwrap(), 64 * 1024).unwrap()),
            64 * 1024,
        );
        let mut service = LinkedEntityLayer::new().layer(RepresentationLayer::new(RepresentationStrictness::default()).layer(types.layer(upstream(&seen))));

        let response = service.call(request).await.unwrap_or_else(|error| match error {});

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(seen.types().as_deref(), Some("Vehicle"));
    }
}
