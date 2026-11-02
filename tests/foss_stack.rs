#![expect(clippy::expect_used, reason = "panicking is how a test harness reports a failure")]

//! The request path, assembled and exercised end to end.
//!
//! Every crate in this stack has its own tests, and they all pass in isolation. What they cannot
//! show is that the layers are in the right order, and the order is where a cache or a deduplicator
//! above authentication would go wrong, serving a hit to a caller nobody had authorised.
//!
//! So this exercises the assembled stack: a request arrives with a tenant and an identity, its
//! context is resolved, a policy set compiled against the same context decides, and the attribute
//! restriction that decision carries is applied to both the request and the response before either
//! reaches anyone.

use axum::{
    body::{Body, to_bytes},
    extract::Request,
    http::{Method, StatusCode, header::CONTENT_TYPE},
    response::Response,
};
use libra_config::{
    jsonld::JsonLd,
    multitenancy::{MissingTenantHeaderPolicy, Multitenancy},
    representation::RepresentationStrictness,
};
use libra_enforcement_attribute::layer::AttributeFilterLayer;
use libra_enforcement_type::layer::TypeEnforcementLayer;
use libra_entity_preflight::preflight::Preflight;
use libra_jsonld_context::resolver::ContextResolver;
use libra_jsonld_context_layer::ContextLayer;
use libra_linked_entity_layer::layer::LinkedEntityLayer;
use libra_ngsi_ld_operation_layer::layer::OperationLayer;
use libra_ngsi_ld_query_layer::layer::QueryLayer;
use libra_ngsi_ld_representation_layer::RepresentationLayer;
use libra_policy_layer::AuthzLayer;
use libra_policy_model::{
    effect::Effect,
    identity::{IdentityName, PolicyIdentity, RoleName, Username},
};
use libra_policy_store::store::PolicyStore;
use libra_problem_details::layer::ErrorHandlerLayer;
use libra_tenant_layer::TenantLayer;
use std::{
    convert::Infallible,
    fs,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tempfile::TempDir;
use tower::{Layer, Service, ServiceExt, util::BoxCloneService};
use url::Url;

/// The context the deployment's clients and its policies share.
const CONTEXT_URL: &str = "https://example.test/fleet.jsonld";

/// A data-model context, the kind a real deployment uses. `Car` and `Vehicle` are one type.
const CONTEXT: &str = r#"{
    "@vocab": "https://uri.etsi.org/ngsi-ld/default-context/",
    "Vehicle": "https://uri.fiware.org/ns/data-models#Vehicle",
    "Car": "https://uri.fiware.org/ns/data-models#Vehicle",
    "speed": "https://uri.fiware.org/ns/data-models#speed",
    "location": "https://uri.etsi.org/ngsi-ld/location"
}"#;

/// Fleet operators may read vehicles, but not where they are.
const POLICIES: &str = r#"
context = ["https://example.test/fleet.jsonld"]

[[policy]]
id = "fleet-read"
priority = 100

[policy.condition]
roles = ["fleet-operator"]
operations = ["read"]
entity-types = ["Vehicle"]

[policy.access]
effect = "allow"

[policy.access.attribute]
action = "omit"
attributes = ["location"]
"#;

/// What a broker would answer with.
const ENTITY: &str = r#"{"id":"urn:ngsi-ld:Vehicle:1","type":"Vehicle","speed":42,"location":"Ljubljana"}"#;

/// Stands in for the identity layer, which needs a real signing key to be worth assembling here.
///
/// It puts the same [`PolicyIdentity`] into the request extensions that the identity layer builds
/// from a validated token, or the anonymous one it inserts where public access is allowed, which is
/// all anything below authentication ever sees of a caller.
#[derive(Clone)]
struct FixedIdentity<S> {
    inner: S,
    identity: PolicyIdentity,
}

impl<S> Service<Request> for FixedIdentity<S>
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
        let inner = self.inner.clone(); // Tower clone-and-swap: the clone made ready in poll_ready is not the one called
        let identity = self.identity.clone(); // the future owns its copy, and every later request needs the original

        Box::pin(async move {
            request.extensions_mut().insert(identity);

            inner.oneshot(request).await
        })
    }
}

/// The stand-in broker, which answers everything with one entity.
fn upstream() -> BoxCloneService<Request, Response, Infallible> {
    BoxCloneService::new(tower::service_fn(|_: Request| async {
        Ok(Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(ENTITY))
            .unwrap_or_else(|_| Response::new(Body::empty())))
    }))
}

/// Builds the stack over the fleet policies, outermost layer first.
async fn stack(identity: PolicyIdentity) -> (TempDir, BoxCloneService<Request, Response, Infallible>) {
    stack_over(identity, POLICIES).await
}

/// Builds the stack over a policy file, outermost layer first.
async fn stack_over(identity: PolicyIdentity, policies: &str) -> (TempDir, BoxCloneService<Request, Response, Infallible>) {
    let directory = TempDir::new().expect("a temporary directory");
    fs::write(directory.path().join("fleet.toml"), policies).expect("the policy file should be written");

    let mut resolver = ContextResolver::new(&JsonLd {
        allow_remote: false,
        allowed_contexts: Vec::new(),
        ..JsonLd::default()
    })
    .expect("the resolver should build");
    resolver
        .preload(
            Url::parse(CONTEXT_URL).expect("the shared context address is a URL"),
            &format!("{{\"@context\": {CONTEXT}}}"),
        )
        .expect("the shared context should preload");
    let resolver = Arc::new(resolver);

    let store = Arc::new(
        PolicyStore::load(directory.path(), Effect::Deny, &resolver)
            .await
            .expect("the policies should load"),
    );

    // Innermost outwards. The order is the point: the operation, the query and the context are
    // resolved before authorization needs them, authorization runs before the enforcement that reads its decision, and the error
    // handler is outermost so nothing below it has to know how to render a refusal.
    let preflight = Preflight::new(Url::parse("http://broker.invalid").expect("a URL"), 64 * 1024).expect("the pre-flight client should build");
    let entity_type = TypeEnforcementLayer::new(Arc::new(preflight), 64 * 1024);
    let service = entity_type.layer(upstream());
    let service = AttributeFilterLayer::new(64 * 1024).layer(BoxCloneService::new(service));
    let service = AuthzLayer::new(store).layer(BoxCloneService::new(service));
    let service = LinkedEntityLayer::new().layer(BoxCloneService::new(service));
    let service = RepresentationLayer::new(RepresentationStrictness::default()).layer(BoxCloneService::new(service));
    let service = ContextLayer::new(Arc::clone(&resolver), 64 * 1024).layer(BoxCloneService::new(service));
    let service = QueryLayer::new().layer(BoxCloneService::new(service));
    let service = OperationLayer::new().layer(BoxCloneService::new(service));
    let service = FixedIdentity {
        inner: BoxCloneService::new(service),
        identity,
    };
    let service = TenantLayer::new(Multitenancy {
        policy: MissingTenantHeaderPolicy::AllowPublic,
    })
    .layer(BoxCloneService::new(service));
    let service = ErrorHandlerLayer::new().layer(BoxCloneService::new(service));

    (directory, BoxCloneService::new(service))
}

fn operator() -> PolicyIdentity {
    PolicyIdentity {
        name: Some(IdentityName::Account(Username::new("alice").expect("a user"))),
        groups: Vec::new(),
        roles: vec![RoleName::new("fleet-operator").expect("a role")],
    }
}

async fn send(service: &mut BoxCloneService<Request, Response, Infallible>, method: Method, uri: &str) -> (StatusCode, String) {
    let request = Request::builder()
        .method(method)
        .uri(uri)
        .header("NGSILD-Tenant", "acme")
        .header(
            "Link",
            format!("<{CONTEXT_URL}>; rel=\"http://www.w3.org/ns/json-ld#context\"; type=\"application/ld+json\""),
        )
        .body(Body::empty())
        .unwrap_or_else(|_| Request::new(Body::empty()));

    let service = service.ready().await.unwrap_or_else(|error| match error {});
    let response = service.call(request).await.unwrap_or_else(|error| match error {});
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 64 * 1024).await.expect("the response body should be readable");

    (status, String::from_utf8_lossy(&bytes).into_owned())
}

#[tokio::test]
async fn an_authorised_read_is_answered_with_the_attribute_the_policy_hides_removed() {
    let (_directory, mut service) = stack(operator()).await;

    let (status, body) = send(&mut service, Method::GET, "/ngsi-ld/v1/entities?type=Vehicle").await;

    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("speed"), "{body}");
    assert!(
        !body.contains("Ljubljana"),
        "the policy omits location, so the response must not carry it: {body}"
    );
}

#[tokio::test]
async fn the_type_is_matched_through_the_context_the_caller_declared() {
    // Through the assembled stack: the policy is written about `Vehicle`, the caller writes `Car`,
    // and under the context both declare those are one type. A proxy comparing the words would
    // refuse this.
    let (_directory, mut service) = stack(operator()).await;

    let (status, body) = send(&mut service, Method::GET, "/ngsi-ld/v1/entities?type=Car").await;

    assert_eq!(status, StatusCode::OK);
    assert!(!body.contains("Ljubljana"), "and the restriction still applies: {body}");
}

#[tokio::test]
async fn a_caller_without_the_role_is_refused() {
    let (_directory, mut service) = stack(PolicyIdentity {
        name: Some(IdentityName::Account(Username::new("mallory").expect("a user"))),
        groups: Vec::new(),
        roles: Vec::new(),
    })
    .await;

    let (status, _) = send(&mut service, Method::GET, "/ngsi-ld/v1/entities?type=Vehicle").await;

    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn an_anonymous_request_is_refused_by_the_default_effect() {
    let (_directory, mut service) = stack(PolicyIdentity::anonymous()).await;

    let (status, _) = send(&mut service, Method::GET, "/ngsi-ld/v1/entities?type=Vehicle").await;

    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn a_write_is_refused_by_a_policy_that_allows_only_reads() {
    let (_directory, mut service) = stack(operator()).await;

    let (status, _) = send(&mut service, Method::POST, "/ngsi-ld/v1/entities").await;

    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn a_filter_reading_the_hidden_attribute_is_refused_rather_than_answered() {
    // `q=location` has no operator and is the specification's own "this attribute exists"
    // predicate. Answering it would tell the caller which vehicles have a location, which is most
    // of what the policy was hiding.
    let (_directory, mut service) = stack(operator()).await;

    let (status, _) = send(&mut service, Method::GET, "/ngsi-ld/v1/entities?type=Vehicle&q=location").await;

    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn a_resource_this_version_does_not_recognise_is_refused() {
    let (_directory, mut service) = stack(operator()).await;

    let (status, _) = send(&mut service, Method::GET, "/ngsi-ld/v1/somethingNew").await;

    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn a_request_naming_a_term_nothing_can_resolve_is_refused() {
    let (_directory, mut service) = stack(operator()).await;

    let (status, _) = send(&mut service, Method::GET, "/ngsi-ld/v1/entities?type=@id").await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn a_query_violating_an_entity_type_restriction_is_refused() {
    let policies = r#"
context = ["https://example.test/fleet.jsonld"]

[[policy]]
id = "vehicles-only"
priority = 100

[policy.condition]
roles = ["fleet-operator"]
operations = ["read"]

[policy.access]
effect = "allow"

[policy.access.entity-type]
allowed = ["Vehicle"]
"#;
    let (_directory, mut service) = stack_over(operator(), policies).await;

    let (status, _) = send(&mut service, Method::GET, "/ngsi-ld/v1/entities?type=Building").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}
