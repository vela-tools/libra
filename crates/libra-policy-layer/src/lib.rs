//! The Tower adapter that evaluates a request against the policy set.
//!
//! This layer's job is assembly, not judgement. It gathers what a decision is made from: who the
//! caller is, which tenant they asked for, what the request does, and what its names mean, and
//! hands that to the policy engine. Every name it passes on was expanded by the context layer
//! above it, so the engine never resolves anything and there is no second resolution to disagree
//! with the first.
//!
//! Where it sits is part of the design. It runs **above** everything that enforces a restriction,
//! because those read the decision it produces; and it must run **above** any cache, because a
//! response served without reaching this layer is a response nobody authorised.

use axum::{
    extract::Request,
    response::{IntoResponse, Response},
};
use jiff::Timestamp;
use libra_audit::slot::AuditSlot;
use libra_jsonld_context_layer::RequestContextExtension;
use libra_jsonld_term_expansion::{name::ExpandedIri, resolved::ResolvedContext};
use libra_linked_entity_layer::servable::requested;
use libra_ngsi_ld_operation::operation::Operation as NgsiOperation;
use libra_ngsi_ld_operation_layer::classified::operation;
use libra_ngsi_ld_query::{canonical::canonicalise, parameter_name::ParameterName};
use libra_ngsi_ld_query_layer::parsed::parameters;
use libra_policy_engine::{
    engine::evaluate,
    registration_disclosure::RegistrationDisclosure,
    request::{EvaluationRequest, RequestedTypes},
};
use libra_policy_model::{identity::PolicyIdentity, operation::Operation, policy::PolicyId, query::CompiledQuerySelector, resource_family::ResourceFamily};
use libra_policy_store::store::PolicyStore;
use libra_problem_details::problem::Problem;
use libra_tenant::Tenant;
use std::{
    convert::Infallible,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tower::{Layer, Service, ServiceExt};
use tracing::{debug, warn};

/// Evaluates every request against the policy set.
#[derive(Clone)]
pub struct AuthzLayer {
    store: Arc<PolicyStore>,
}

impl AuthzLayer {
    /// Builds the layer over a loaded policy set.
    #[must_use]
    pub const fn new(store: Arc<PolicyStore>) -> Self {
        Self { store }
    }
}

impl<S> Layer<S> for AuthzLayer {
    type Service = AuthzService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AuthzService {
            inner,
            store: Arc::clone(&self.store),
        }
    }
}

/// The service produced by [`AuthzLayer`].
#[derive(Clone)]
pub struct AuthzService<S> {
    inner: S,
    store: Arc<PolicyStore>,
}

impl<S> Service<Request> for AuthzService<S>
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
        let store = Arc::clone(&self.store);

        Box::pin(async move {
            match authorize(&store, request) {
                Ok(request) => inner.oneshot(request).await,
                Err(problem) => Ok(problem.into_response()),
            }
        })
    }
}

/// Decides whether a request may proceed, and attaches the decision if it may.
fn authorize(store: &PolicyStore, mut request: Request) -> Result<Request, Problem> {
    let Some(context) = request.extensions().get::<RequestContextExtension>().map(|extension| Arc::clone(&extension.0)) else {
        // The context layer runs above this one, so this is a wiring error rather than a request.
        // Evaluating without a context would compare names that have no meaning.
        return Err(Problem::Internal("the request context was not resolved before authorization".to_owned()));
    };

    // The identity and tenant layers above insert both on every request they pass, an anonymous
    // caller and an untenanted request included. Absence is a wiring error, and reading it as an
    // anonymous caller in no tenant would decide a request nobody identified.
    let Some(identity) = request.extensions().get::<PolicyIdentity>().cloned() else {
        return Err(Problem::Internal("the caller was not established before authorization".to_owned()));
    };
    let Some(tenant) = request.extensions().get::<Tenant>().map(Tenant::as_selector) else {
        return Err(Problem::Internal("the tenant was not resolved before authorization".to_owned()));
    };
    let (classified, resource) = classify(&request)?;
    let named = NamedSelection::read(&request, &context)?;

    let snapshot = store.snapshot();
    let ask = |operation: Operation| {
        evaluate(
            &snapshot,
            &EvaluationRequest {
                name: identity.name.as_ref(),
                groups: &identity.groups,
                roles: &identity.roles,
                tenant: &tenant,
                operation,
                resource,
                entity_types: named.requested_types(),
                query: named.query.as_ref(),
                now: Timestamp::now(),
            },
        )
    };
    let decision = ask(Operation::from(classified.mode));

    let audit = request.extensions().get::<AuditSlot>();
    if let (Some(audit), Some(policy)) = (audit, decision.matched.as_ref()) {
        audit.record_policy(policy.clone()); // the decision keeps its own copy, which is attached to the request below
    }

    // The caller is named by the fingerprint of their credential, never by name: a name is a
    // personal identifier, and debug logging is switched on in deployments that never meant to keep
    // one. The audit record is where a name belongs.
    let credential = audit.and_then(AuditSlot::credential);
    let policy = decision.matched.as_ref().map_or("(default effect)", PolicyId::as_str);

    if decision.is_deny() {
        warn!(
            credential = credential.as_ref().map(display),
            tenant = %tenant,
            method = %request.method(),
            policy,
            "access denied"
        );

        return Err(Problem::Forbidden("access denied by policy".to_owned()));
    }

    debug!(credential = credential.as_ref().map(display), policy, "access allowed");

    // A registration read asks a second question of the same policy set: whether this caller could
    // also have written registrations. Only a writer is shown what a registration carries for its
    // source.
    if resource == ResourceFamily::Registrations && classified.is_read() {
        let disclosure = if ask(Operation::Write).is_deny() {
            RegistrationDisclosure::WithoutSourceInfo
        } else {
            RegistrationDisclosure::Whole
        };
        request.extensions_mut().insert(disclosure);
    }

    // Where the enforcement layers below read it.
    request.extensions_mut().insert(decision);

    Ok(request)
}

/// The request's operation, refusing a resource no policy can be about.
fn classify(request: &Request) -> Result<(NgsiOperation, ResourceFamily), Problem> {
    // Cloned because the evaluation owns its operation and the request keeps the classified one.
    let classified = operation(request.extensions()).map_err(|error| Problem::Internal(error.to_string()))?.clone();

    let Some(resource) = ResourceFamily::of(&classified.resource) else {
        // A resource no policy was written about. Brokers grow endpoints faster than proxies do,
        // and the safe answer to one Libra cannot name is to refuse rather than to let it past
        // every rule that names something else.
        warn!(path = %request.uri().path(), "refusing a request for a resource this version does not recognise");

        return Err(Problem::Forbidden(
            "this resource is not one Libra recognises, so no policy governs it".to_owned(),
        ));
    };

    Ok((classified, resource))
}

/// What the request's query string says about the entities it is after, expanded once.
struct NamedSelection {
    /// The types the query string names, as IRIs, or `None` when it names none.
    entity_types: Option<Vec<ExpandedIri>>,
    /// Which entities the answer may hold.
    reach: Reach,
    /// The query, canonicalised, if there is one.
    query: Option<CompiledQuerySelector>,
}

impl NamedSelection {
    fn read(request: &Request, context: &ResolvedContext) -> Result<Self, Problem> {
        let parameters = parameters(request.extensions()).map_err(|error| Problem::Internal(error.to_string()))?;

        // Expanded here, once, from the context the whole request shares. A policy's types were
        // expanded when the policy loaded; these are the other half of the same comparison.
        let entity_types = parameters
            .get(&ParameterName::TYPE)
            .map(|_| parameters.expanded_entity_types(context))
            .transpose()
            .map_err(|error| Problem::BadRequest(error.to_string()))?;
        // Linked Entity Retrieval (NGSI-LD 4.5.23) answers with the entities the matched ones link
        // to, of whatever type, so `?type=Vehicle&join=inline` touches more than `Vehicle`. Read as
        // naming only `Vehicle`, it would slip past a deny on the type its Relationships point at.
        // Resolved once, above this layer, from the query string and a `Query` body alike. A linked
        // `q` path (clause 4.9) reaches the linked entities' values just as a join does.
        let reach = match requested(request.extensions()) {
            Ok(linked) if linked.is_nothing() => Reach::QueriedOnly,
            Ok(_) => Reach::LinkedToo,
            Err(error) => return Err(Problem::Internal(error.to_string())),
        };

        let query = if parameters.is_empty() {
            None
        } else {
            Some(CompiledQuerySelector::from_canonical(
                canonicalise(parameters, context).map_err(|error| Problem::BadRequest(error.to_string()))?,
            ))
        };

        Ok(Self { entity_types, reach, query })
    }

    const fn requested_types(&self) -> RequestedTypes<'_> {
        match (&self.entity_types, self.reach) {
            (Some(named), Reach::QueriedOnly) => RequestedTypes::Named(named.as_slice()),
            (None, Reach::QueriedOnly | Reach::LinkedToo) | (Some(_), Reach::LinkedToo) => RequestedTypes::Unbounded,
        }
    }
}

/// Which entities a request's answer may hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reach {
    /// The queried entities only.
    QueriedOnly,
    /// The queried entities and the entities they link to, of any type.
    LinkedToo,
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Method, StatusCode},
    };
    use libra_audit::credential::FingerprintKey;
    use libra_config::jsonld::JsonLd;
    use libra_jsonld_context::resolver::ContextResolver;
    use libra_jsonld_term_expansion::resolved::ResolvedContext;
    use libra_log_capture::captured;
    use libra_ngsi_ld_operation_layer::layer::classify as classify_operation;
    use libra_ngsi_ld_query::parameters::QueryParameters;
    use libra_ngsi_ld_query_layer::layer::read_query;
    use libra_policy_engine::decision::Decision;
    use libra_policy_model::{
        effect::Effect,
        identity::{GroupName, IdentityName, RoleName, TenantId, Username},
        policy::PolicyId,
    };
    use pretty_assertions::assert_eq;
    use std::fs;
    use tempfile::TempDir;
    use tower::util::BoxCloneService;
    use tracing::Level;
    use url::Url;

    /// The context both the policies and the requests in these tests are written against.
    const CONTEXT: &str = r#"{
        "@vocab": "https://uri.etsi.org/ngsi-ld/default-context/",
        "Vehicle": "https://uri.fiware.org/ns/data-models#Vehicle",
        "Car": "https://uri.fiware.org/ns/data-models#Vehicle",
        "Building": "https://uri.fiware.org/ns/data-models#Building"
    }"#;

    fn context() -> Arc<ResolvedContext> {
        Arc::new(ResolvedContext::from_json(CONTEXT).expect("the test context should process"))
    }

    /// Where the shared context lives, for both the policy file and this test's requests.
    const CONTEXT_URL: &str = "https://example.test/fleet.jsonld";

    async fn store(policies: &str) -> Arc<PolicyStore> {
        let directory = TempDir::new().expect("a temporary directory");
        // Declared by the file, so the policy's terms mean what the requests' terms mean. A policy
        // compiled against a different context is a policy about different IRIs, and it would
        // silently match nothing.
        let declared = format!("context = [\"{CONTEXT_URL}\"]\n{policies}");
        fs::write(directory.path().join("policies.toml"), declared).expect("the file should be written");

        let mut resolver = ContextResolver::new(&JsonLd {
            allow_remote: false,
            allowed_contexts: Vec::new(),
            ..JsonLd::default()
        })
        .expect("the resolver should build");
        resolver
            .preload(
                Url::parse(CONTEXT_URL).expect("the test context address is a URL"),
                &format!("{{\"@context\": {CONTEXT}}}"),
            )
            .expect("the test context should preload");

        let store = PolicyStore::load(directory.path(), Effect::Deny, &resolver)
            .await
            .expect("the policies should load");

        Arc::new(store)
    }

    /// An inner service that records whether it was reached and what decision it saw.
    fn inner() -> BoxCloneService<Request, Response, Infallible> {
        BoxCloneService::new(tower::service_fn(|request: Request| async move {
            let matched = request
                .extensions()
                .get::<Decision>()
                .and_then(|decision| decision.matched.as_ref().map(|id| id.as_str().to_owned()))
                .unwrap_or_else(|| "(none)".to_owned());

            Ok(Response::builder()
                .status(StatusCode::OK)
                .body(Body::from(matched))
                .unwrap_or_else(|_| Response::new(Body::empty())))
        }))
    }

    /// A request carrying everything the layers above this one insert.
    fn request(method: Method, uri: &str, identity: PolicyIdentity, tenant: Tenant) -> Request {
        let (mut parts, body) = Request::builder().method(method).uri(uri).body(Body::empty()).unwrap().into_parts();
        classify_operation(&mut parts).unwrap();
        read_query(&mut parts).unwrap();

        parts.extensions.insert(RequestContextExtension(context()));
        // What the linked-entity layer above this one resolves from the query string.
        if let Ok(linked) = parameters(&parts.extensions).unwrap().linked_entity_request() {
            parts.extensions.insert(linked);
        }
        parts.extensions.insert(identity);
        parts.extensions.insert(tenant);

        Request::from_parts(parts, body)
    }

    async fn run(store: &Arc<PolicyStore>, request: Request) -> Response {
        let mut service = AuthzLayer::new(Arc::clone(store)).layer(inner());

        service.call(request).await.unwrap_or_else(|error| match error {})
    }

    async fn body_of(response: Response) -> String {
        use http_body_util::BodyExt;

        let bytes = response
            .into_body()
            .collect()
            .await
            .map(http_body_util::Collected::to_bytes)
            .unwrap_or_default();

        String::from_utf8_lossy(&bytes).into_owned()
    }

    fn operator() -> PolicyIdentity {
        PolicyIdentity {
            name: Some(IdentityName::Account(Username::new("alice").expect("a user"))),
            groups: vec![GroupName::new("fleet").expect("a group")],
            roles: vec![RoleName::new("fleet-operator").expect("a role")],
        }
    }

    const FLEET: &str = r#"
        [[policy]]
        id = "fleet-read"
        priority = 100

        [policy.condition]
        roles = ["fleet-operator"]
        operations = ["read"]

        [policy.access]
        effect = "allow"
    "#;

    #[tokio::test]
    async fn an_allowed_request_carries_its_decision_downstream() {
        let store = store(FLEET).await;
        let response = run(
            &store,
            request(Method::GET, "/ngsi-ld/v1/entities?type=Vehicle", operator(), Tenant::Untenanted),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_of(response).await, "fleet-read", "the enforcement layers below read this");
    }

    #[tokio::test]
    async fn a_request_no_policy_allows_is_refused() {
        let store = store(FLEET).await;
        let response = run(&store, request(Method::POST, "/ngsi-ld/v1/entities", operator(), Tenant::Untenanted)).await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN, "the policy allows reads only");
    }

    #[tokio::test]
    async fn a_decision_is_logged_by_credential_fingerprint_and_policy_and_never_by_caller_name() {
        let store = store(FLEET).await;
        let fingerprint = FingerprintKey::new(&[4_u8; 32]).fingerprint("alice's token");

        for (method, level, message, policy) in [
            (Method::GET, Level::DEBUG, "access allowed", "fleet-read"),
            (Method::POST, Level::WARN, "access denied", "(default effect)"),
        ] {
            let audit = AuditSlot::default();
            audit.record_credential(fingerprint.clone()); // the test keeps its own copy to compare against
            let mut request = request(method, "/ngsi-ld/v1/entities?type=Vehicle", operator(), Tenant::Untenanted);
            request.extensions_mut().insert(audit);

            let (_, records) = captured(run(&store, request)).await;

            let decision = records.iter().find(|record| record.message() == message).unwrap();
            assert_eq!(decision.level, level);
            assert_eq!(decision.field("credential"), Some(fingerprint.to_string().as_str()));
            assert_eq!(decision.field("policy"), Some(policy));
            for record in &records {
                assert!(!record.mentions("alice"), "{record:?}");
            }
        }
    }

    #[tokio::test]
    async fn an_anonymous_request_is_evaluated_as_anonymous() {
        let store = store(FLEET).await;
        let response = run(
            &store,
            request(Method::GET, "/ngsi-ld/v1/entities", PolicyIdentity::anonymous(), Tenant::Untenanted),
        )
        .await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn a_batch_query_is_authorised_as_a_read_despite_its_method() {
        // `POST /entityOperations/query` is a read wearing a write's method. A policy that allows
        // reads must cover it, or every batch query breaks.
        let store = store(FLEET).await;
        let response = run(
            &store,
            request(Method::POST, "/ngsi-ld/v1/entityOperations/query", operator(), Tenant::Untenanted),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn a_type_filter_is_matched_through_the_context_rather_than_the_word() {
        // The bypass, end to end: the policy names `Vehicle`, the caller writes `Car`, and under
        // the request's context those are one type.
        let store = store(
            r#"
            [[policy]]
            id = "vehicles"
            priority = 100

            [policy.condition]
            roles = ["fleet-operator"]
            entity-types = ["Vehicle"]

            [policy.access]
            effect = "allow"
            "#,
        )
        .await;

        let as_car = run(&store, request(Method::GET, "/ngsi-ld/v1/entities?type=Car", operator(), Tenant::Untenanted)).await;
        let as_building = run(
            &store,
            request(Method::GET, "/ngsi-ld/v1/entities?type=Building", operator(), Tenant::Untenanted),
        )
        .await;

        assert_eq!(as_car.status(), StatusCode::OK);
        assert_eq!(as_building.status(), StatusCode::FORBIDDEN);
    }

    const SECRET_DENY: &str = r#"
        [[policy]]
        id = "no-buildings"
        priority = 100

        [policy.condition]
        entity-types = ["Building"]

        [policy.access]
        effect = "deny"

        [[policy]]
        id = "allow-all"
        priority = 1

        [policy.access]
        effect = "allow"
    "#;

    #[tokio::test]
    async fn a_deny_on_a_type_cannot_be_dodged_with_a_type_expression() {
        // A type expression using `|`, `;`, parentheses or a trailing comma entry is parsed, not read as
        // one unknown type name that no deny matches while the broad allow wins.
        let store = store(SECRET_DENY).await;

        for query in [
            "type=Building|Vehicle",
            "type=(Building)",
            "type=Building;Vehicle",
            "type=Vehicle,Building",
            "type=Vehicle|(Building;Vehicle)",
        ] {
            let uri = format!("/ngsi-ld/v1/entities?{query}");
            let response = run(&store, request(Method::GET, &uri, operator(), Tenant::Untenanted)).await;

            assert_eq!(response.status(), StatusCode::FORBIDDEN, "{query}");
        }

        let vehicles = run(
            &store,
            request(Method::GET, "/ngsi-ld/v1/entities?type=Vehicle", operator(), Tenant::Untenanted),
        )
        .await;
        assert_eq!(vehicles.status(), StatusCode::OK, "a request for another type is not touched");
    }

    #[tokio::test]
    async fn a_deny_on_a_type_applies_to_requests_that_name_their_type_elsewhere() {
        // By id, in a batch query body, and on a create: none of them carries `?type=`.
        let store = store(SECRET_DENY).await;

        for (method, uri) in [
            (Method::GET, "/ngsi-ld/v1/entities/urn:ngsi-ld:Building:1"),
            (Method::POST, "/ngsi-ld/v1/entityOperations/query"),
            (Method::POST, "/ngsi-ld/v1/entities"),
        ] {
            let label = format!("{method} {uri}");
            let response = run(&store, request(method, uri, operator(), Tenant::Untenanted)).await;

            assert_eq!(response.status(), StatusCode::FORBIDDEN, "{label}");
        }
    }

    #[tokio::test]
    async fn a_deny_on_a_type_cannot_be_dodged_by_retrieving_it_as_a_linked_entity() {
        // `?type=Vehicle` with a join answers with the entities the vehicles link to, which may be
        // buildings. Read as naming only `Vehicle`, the request would slip past the deny on `Building`
        // and the broad allow below it would win.
        let store = store(SECRET_DENY).await;

        for query in [
            "type=Vehicle&join=inline",
            "type=Vehicle&join=flat",
            "type=Vehicle&joinLevel=2",
            "type=Vehicle&pick=parkedIn{name}",
            "type=Vehicle&q=parkedIn{name}==%22Downtown%22",
        ] {
            let uri = format!("/ngsi-ld/v1/entities?{query}");
            let response = run(&store, request(Method::GET, &uri, operator(), Tenant::Untenanted)).await;

            assert_eq!(response.status(), StatusCode::FORBIDDEN, "{query}");
        }

        let unlinked = run(
            &store,
            request(Method::GET, "/ngsi-ld/v1/entities?type=Vehicle&join=@none", operator(), Tenant::Untenanted),
        )
        .await;
        assert_eq!(unlinked.status(), StatusCode::OK, "the join default retrieves nothing linked");
    }

    #[tokio::test]
    async fn an_allow_for_a_type_does_not_cover_the_entities_it_links_to() {
        let store = store(
            r#"
            [[policy]]
            id = "vehicles"
            priority = 100

            [policy.condition]
            entity-types = ["Vehicle"]

            [policy.access]
            effect = "allow"
            "#,
        )
        .await;

        let joined = run(
            &store,
            request(Method::GET, "/ngsi-ld/v1/entities?type=Vehicle&join=inline", operator(), Tenant::Untenanted),
        )
        .await;

        assert_eq!(joined.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn a_linked_entity_filter_is_authorised_rather_than_refused_as_malformed() {
        // Clause 4.9 `LinkedEntityRelation` expands as a linked-entity path, not as one unknown term.
        let store = store(FLEET).await;
        let response = run(
            &store,
            request(
                Method::GET,
                "/ngsi-ld/v1/entities?type=Vehicle&q=parkedIn{name}==%22Downtown%22&pick=speed|brand",
                operator(),
                Tenant::Untenanted,
            ),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn an_allow_for_a_type_does_not_cover_a_list_that_also_names_another() {
        let store = store(
            r#"
            [[policy]]
            id = "vehicles"
            priority = 100

            [policy.condition]
            entity-types = ["Vehicle"]

            [policy.access]
            effect = "allow"
            "#,
        )
        .await;

        let both = run(
            &store,
            request(Method::GET, "/ngsi-ld/v1/entities?type=Vehicle,Building", operator(), Tenant::Untenanted),
        )
        .await;
        let only = run(
            &store,
            request(Method::GET, "/ngsi-ld/v1/entities?type=Vehicle", operator(), Tenant::Untenanted),
        )
        .await;

        assert_eq!(both.status(), StatusCode::FORBIDDEN);
        assert_eq!(only.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn the_deciding_policy_is_audited_for_a_restriction_and_for_a_refusal() {
        let store = store(SECRET_DENY).await;

        for (uri, expected) in [
            ("/ngsi-ld/v1/entities?type=Vehicle", "allow-all"),
            ("/ngsi-ld/v1/entities?type=Building", "no-buildings"),
        ] {
            let slot = AuditSlot::default();
            let mut request = request(Method::GET, uri, operator(), Tenant::Untenanted);
            // The slot is shared storage: the request carries one handle, the test reads the other.
            request.extensions_mut().insert(slot.clone());

            let _response = run(&store, request).await;

            assert_eq!(slot.contributions().policy.as_ref().map(PolicyId::as_str), Some(expected), "{uri}");
        }
    }

    #[tokio::test]
    async fn a_resource_this_version_does_not_recognise_is_refused() {
        // Brokers grow endpoints faster than proxies do. Letting an unnamed one past every rule
        // that names something else is how a new endpoint becomes an unguarded one.
        let store = store(
            r#"
            [[policy]]
            id = "allow-all"
            priority = 1

            [policy.access]
            effect = "allow"
            "#,
        )
        .await;

        let response = run(&store, request(Method::GET, "/ngsi-ld/v1/somethingNew", operator(), Tenant::Untenanted)).await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn a_request_that_reached_this_layer_unclassified_or_unparsed_is_refused() {
        let store = store(FLEET).await;

        let mut unclassified = request(Method::GET, "/ngsi-ld/v1/entities?type=Vehicle", operator(), Tenant::Untenanted);
        unclassified.extensions_mut().remove::<NgsiOperation>();
        assert_eq!(run(&store, unclassified).await.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let mut unparsed = request(Method::GET, "/ngsi-ld/v1/entities?type=Vehicle", operator(), Tenant::Untenanted);
        unparsed.extensions_mut().remove::<QueryParameters>();
        assert_eq!(run(&store, unparsed).await.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn the_decision_is_made_on_the_stored_operation_and_query_not_on_the_request_line() {
        // A read-only policy allows the stored read although the request line says POST.
        let store = store(FLEET).await;
        let mut request = request(Method::POST, "/ngsi-ld/v1/entities", operator(), Tenant::Untenanted);
        request
            .extensions_mut()
            .insert(NgsiOperation::classify(&Method::GET, "/ngsi-ld/v1/entities").unwrap().unwrap());

        assert_eq!(run(&store, request).await.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn a_request_that_reached_this_layer_without_a_context_is_refused() {
        // A wiring error. Evaluating without a context would compare names that have no meaning,
        // which is the same as not evaluating at all.
        let store = store(FLEET).await;
        let mut request = request(Method::GET, "/ngsi-ld/v1/entities", operator(), Tenant::Untenanted);
        request.extensions_mut().remove::<RequestContextExtension>();

        let response = run(&store, request).await;

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    /// Allows anyone, anonymous and untenanted callers included, so a refusal can only come from
    /// the layer itself.
    const ALLOW_EVERYONE: &str = r#"
        [[policy]]
        id = "everyone"
        priority = 1

        [policy.access]
        effect = "allow"
    "#;

    #[tokio::test]
    async fn a_request_that_reached_this_layer_without_a_caller_is_refused_rather_than_read_as_anonymous() {
        let store = store(ALLOW_EVERYONE).await;
        let mut request = request(Method::GET, "/ngsi-ld/v1/entities", operator(), Tenant::Untenanted);
        request.extensions_mut().remove::<PolicyIdentity>();

        let response = run(&store, request).await;

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn a_request_that_reached_this_layer_without_a_tenant_is_refused_rather_than_read_as_untenanted() {
        let store = store(ALLOW_EVERYONE).await;
        let mut request = request(Method::GET, "/ngsi-ld/v1/entities", operator(), Tenant::Untenanted);
        request.extensions_mut().remove::<Tenant>();

        let response = run(&store, request).await;

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn an_anonymous_untenanted_request_is_evaluated_when_both_are_present() {
        let store = store(ALLOW_EVERYONE).await;
        let response = run(
            &store,
            request(Method::GET, "/ngsi-ld/v1/entities", PolicyIdentity::anonymous(), Tenant::Untenanted),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn a_tenant_narrows_which_policies_apply() {
        let store = store(
            r#"
            [[policy]]
            id = "acme-read"
            priority = 100

            [policy.condition]
            tenants = ["acme"]

            [policy.access]
            effect = "allow"
            "#,
        )
        .await;

        let acme = Tenant::Named(TenantId::new("acme").expect("a tenant"));
        let other = Tenant::Named(TenantId::new("other").expect("a tenant"));

        let allowed = run(&store, request(Method::GET, "/ngsi-ld/v1/entities", operator(), acme)).await;
        let refused = run(&store, request(Method::GET, "/ngsi-ld/v1/entities", operator(), other)).await;
        let untenanted = run(&store, request(Method::GET, "/ngsi-ld/v1/entities", operator(), Tenant::Untenanted)).await;

        assert_eq!(allowed.status(), StatusCode::OK);
        assert_eq!(refused.status(), StatusCode::FORBIDDEN);
        assert_eq!(untenanted.status(), StatusCode::FORBIDDEN, "no tenant is not the same as any tenant");
    }

    #[tokio::test]
    async fn a_query_naming_something_the_context_cannot_resolve_is_refused() {
        let store = store(FLEET).await;
        let response = run(&store, request(Method::GET, "/ngsi-ld/v1/entities?type=@id", operator(), Tenant::Untenanted)).await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    /// An inner service that answers with the registration disclosure it was handed, if any.
    fn disclosed() -> BoxCloneService<Request, Response, Infallible> {
        BoxCloneService::new(tower::service_fn(|request: Request| async move {
            let disclosure = format!("{:?}", request.extensions().get::<RegistrationDisclosure>());

            Ok(Response::new(Body::from(disclosure)))
        }))
    }

    async fn disclosure(policies: &str, method: Method, uri: &str) -> String {
        let store = store(policies).await;
        let mut service = AuthzLayer::new(store).layer(disclosed());
        let response = service
            .call(request(method, uri, operator(), Tenant::Untenanted))
            .await
            .unwrap_or_else(|error| match error {});

        body_of(response).await
    }

    const REGISTRATION_READERS: &str = r#"
        [[policy]]
        id = "registration-readers"
        priority = 1
        [policy.condition]
        operations = ["read"]
        resources = ["registrations", "entities"]
        [policy.access]
        effect = "allow"
    "#;

    const REGISTRATION_WRITERS: &str = r#"
        [[policy]]
        id = "registration-writers"
        priority = 1
        [policy.condition]
        resources = ["registrations", "entities"]
        [policy.access]
        effect = "allow"
    "#;

    #[tokio::test]
    async fn a_registration_reader_who_may_not_write_them_is_shown_them_without_source_info() {
        assert_eq!(
            disclosure(REGISTRATION_READERS, Method::GET, "/ngsi-ld/v1/csourceRegistrations?type=Vehicle").await,
            "Some(WithoutSourceInfo)"
        );
    }

    #[tokio::test]
    async fn a_registration_reader_who_may_write_them_is_shown_them_whole() {
        assert_eq!(
            disclosure(REGISTRATION_WRITERS, Method::GET, "/ngsi-ld/v1/csourceRegistrations/urn:r:1").await,
            "Some(Whole)"
        );
    }

    #[tokio::test]
    async fn an_entity_read_asks_no_second_question() {
        assert_eq!(disclosure(REGISTRATION_WRITERS, Method::GET, "/ngsi-ld/v1/entities?type=Vehicle").await, "None");
    }

    #[tokio::test]
    async fn a_write_allow_naming_no_resources_cannot_write_a_registration() {
        let store = store(
            r#"
            [[policy]]
            id = "writers"
            priority = 1
            [policy.access]
            effect = "allow"
            "#,
        )
        .await;

        let response = run(
            &store,
            request(Method::POST, "/ngsi-ld/v1/csourceRegistrations", operator(), Tenant::Untenanted),
        )
        .await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn a_snapshot_is_refused_without_a_policy_naming_snapshots_and_allowed_with_one() {
        let unnamed = store(
            r#"
            [[policy]]
            id = "everything-by-default"
            priority = 1
            [policy.access]
            effect = "allow"
            "#,
        )
        .await;
        let named = store(
            r#"
            [[policy]]
            id = "snapshots"
            priority = 1
            [policy.condition]
            resources = ["snapshots"]
            [policy.access]
            effect = "allow"
            "#,
        )
        .await;

        let refused = run(&unnamed, request(Method::POST, "/ngsi-ld/v1/snapshots", operator(), Tenant::Untenanted)).await;
        let allowed = run(&named, request(Method::POST, "/ngsi-ld/v1/snapshots", operator(), Tenant::Untenanted)).await;

        assert_eq!(refused.status(), StatusCode::FORBIDDEN);
        assert_eq!(allowed.status(), StatusCode::OK);
    }
}
