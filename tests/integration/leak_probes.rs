//! Leak surfaces, exercised end to end. Each test sends a request that could disclose something
//! the caller's policy withholds, and asserts what does and does not leave Libra.

use libra_test_harness::{
    broker::{create, unique_id},
    identity::token,
    origin::Origin,
    proxy::Proxy,
    proxy_settings::ProxySettings,
    stack::Endpoints,
    tenant_creation,
};
use reqwest::{StatusCode, blocking::Client};
use serde_json::{Value, json};

const TENANT: &str = "gardens";

/// The subscription bypass: a caller restricted to omit an attribute has that attribute added to
/// `notification.omit` and stripped from any allowlist before the subscription reaches the broker, so
/// the notifications the broker delivers out of band cannot carry it. This asserts the narrowing on
/// the body Libra actually forwarded.
#[test]
fn a_subscription_is_narrowed_to_the_attribute_restriction() {
    let stack = require_stack!();
    let origin = Origin::serving("application/json", r#"{"id":"urn:ngsi-ld:Subscription:1"}"#);

    let policies = r#"
[[policy]]
id = "write-omit-location"
priority = 100

[policy.condition]
resources = ["entities", "temporal", "discovery", "subscriptions", "registrations", "registration-subscriptions", "entity-maps", "contexts"]
users = ["writer"]
tenants = ["gardens"]
operations = ["write"]

[policy.access]
effect = "allow"

[policy.access.attribute]
action = "omit"
attributes = ["location"]
"#;

    let settings = ProxySettings {
        upstream: origin.address(),
        ..ProxySettings::new(&stack, policies)
    };
    let proxy = Proxy::start(&settings);

    let subscription = json!({
        "@context": "https://uri.etsi.org/ngsi-ld/v1/ngsi-ld-core-context.jsonld",
        "id": "urn:ngsi-ld:Subscription:probe",
        "type": "Subscription",
        "entities": [ { "type": "Vehicle" } ],
        "notification": { "attributes": ["location", "speed"], "endpoint": { "uri": "http://sink.test/notify" } }
    });

    let response = proxy
        .post("/ngsi-ld/v1/subscriptions")
        .header("NGSILD-Tenant", TENANT)
        .header("Content-Type", "application/ld+json")
        .bearer_auth(token("writer"))
        .json(&subscription)
        .send()
        .expect("the proxy should answer");
    let status = response.status();

    let recorded = origin
        .last_request()
        .unwrap_or_else(|| panic!("the subscription was not forwarded to the broker; status was {status}"));
    let forwarded: Value = serde_json::from_str(&recorded.body).expect("the forwarded subscription should be JSON");

    let omit: Vec<&str> = forwarded
        .pointer("/notification/omit")
        .and_then(Value::as_array)
        .map(|values| values.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    assert!(
        omit.contains(&"location"),
        "the hidden attribute must be added to notification.omit: {}",
        recorded.body
    );

    let attributes: Vec<&str> = forwarded
        .pointer("/notification/attributes")
        .and_then(Value::as_array)
        .map(|values| values.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    assert!(
        !attributes.contains(&"location"),
        "the hidden attribute must be dropped from the notification allowlist: {}",
        recorded.body
    );
}

/// Scope enforcement narrows the outbound query with `scopeQ`, and judges every entity of the answer
/// too, so a broker that ignores `scopeQ` still cannot hand the caller an entity outside the
/// restriction. This probe points Libra at an origin that does exactly that.
#[test]
fn a_collection_response_is_re_filtered_against_the_scope_restriction() {
    let stack = require_stack!();
    let collection = r#"[
        {"id":"urn:ngsi-ld:Garden:in","type":"Garden","scope":"/Madrid/Gardens/Retiro"},
        {"id":"urn:ngsi-ld:Garden:out","type":"Garden","scope":"/Barcelona/Parks/Guell"}
    ]"#;
    let origin = Origin::serving("application/json", collection);

    let policies = r#"
[[policy]]
id = "madrid-only"
priority = 100

[policy.condition]
resources = ["entities", "temporal", "discovery", "subscriptions", "registrations", "registration-subscriptions", "entity-maps", "contexts"]
users = ["writer"]
tenants = ["gardens"]
operations = ["read"]

[policy.access]
effect = "allow"

[policy.access.scope]
allowed = ["/Madrid/Gardens/#"]
"#;

    let settings = ProxySettings {
        upstream: origin.address(),
        ..ProxySettings::new(&stack, policies)
    };
    let proxy = Proxy::start(&settings);

    let response = proxy
        .get("/ngsi-ld/v1/entities?type=Garden")
        .header("NGSILD-Tenant", TENANT)
        .bearer_auth(token("writer"))
        .send()
        .expect("the proxy should answer");

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().unwrap_or_default();
    assert!(body.contains("Garden:in"), "the entity inside the restriction is shown: {body}");
    assert!(!body.contains("Garden:out"), "the entity outside the restriction is withheld: {body}");
}

/// A proxy allowing the writer subscription writes inside `/Madrid/Gardens/#` alone, in front of
/// `origin`.
fn madrid_subscriber(stack: &Endpoints, origin: &Origin) -> Proxy {
    let policies = r#"
[[policy]]
id = "madrid-only"
priority = 100

[policy.condition]
resources = ["entities", "temporal", "discovery", "subscriptions", "registrations", "registration-subscriptions", "entity-maps", "contexts"]
users = ["writer"]
tenants = ["gardens"]
operations = ["write"]

[policy.access]
effect = "allow"

[policy.access.scope]
allowed = ["/Madrid/Gardens/#"]
"#;

    Proxy::start(&ProxySettings {
        upstream: origin.address(),
        ..ProxySettings::new(stack, policies)
    })
}

/// Creates a Garden subscription through `proxy`, carrying `scope_q` when one is given, and reports
/// the status.
fn subscribe(proxy: &Proxy, scope_q: Option<&str>) -> StatusCode {
    let mut subscription = json!({
        "@context": "https://uri.etsi.org/ngsi-ld/v1/ngsi-ld-core-context.jsonld",
        "type": "Subscription",
        "entities": [ { "type": "Garden" } ],
        "notification": { "endpoint": { "uri": "http://sink.test/notify" } }
    });
    if let Some(scope_q) = scope_q {
        subscription["scopeQ"] = json!(scope_q);
    }

    proxy
        .post("/ngsi-ld/v1/subscriptions")
        .header("NGSILD-Tenant", TENANT)
        .header("Content-Type", "application/ld+json")
        .bearer_auth(token("writer"))
        .json(&subscription)
        .send()
        .expect("the proxy should answer")
        .status()
}

/// Every scope the `scopeQ` the broker received names, once its operators and grouping are taken
/// away (NGSI-LD clause 4.19).
fn forwarded_scopes(origin: &Origin, status: StatusCode) -> Vec<String> {
    let recorded = origin
        .last_request()
        .unwrap_or_else(|| panic!("the subscription was not forwarded to the broker; status was {status}"));
    let forwarded: Value = serde_json::from_str(&recorded.body).expect("the forwarded subscription should be JSON");
    let scope_q = forwarded
        .pointer("/scopeQ")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("the restriction must be written into the subscription's scopeQ: {}", recorded.body));

    scope_q
        .split([';', ',', '|', '(', ')'])
        .map(str::trim)
        .filter(|scope| !scope.is_empty())
        .map(str::to_owned)
        .collect()
}

/// The scope half of the subscription bypass: a subscription created under a scope restriction has
/// the restriction written into its own `scopeQ`, so the broker only matches entities inside the
/// restriction when it delivers notifications out of band. Every scope the forwarded `scopeQ` names
/// must lie inside the restriction: one that also names a broader scope in a disjunction would
/// notify on entities outside it.
#[test]
fn a_subscription_scope_is_narrowed_to_the_restriction() {
    let stack = require_stack!();
    let origin = Origin::serving("application/json", r#"{"id":"urn:ngsi-ld:Subscription:1"}"#);
    let proxy = madrid_subscriber(&stack, &origin);

    for asked in [None, Some("/Madrid/#"), Some("/Madrid/Gardens/A")] {
        let status = subscribe(&proxy, asked);
        let scopes = forwarded_scopes(&origin, status);

        assert!(!scopes.is_empty(), "{asked:?}: the forwarded scopeQ names no scope");
        assert!(
            scopes.iter().all(|scope| scope.starts_with("/Madrid/Gardens")),
            "{asked:?}: every forwarded scope must lie inside /Madrid/Gardens/#: {scopes:?}"
        );
    }
}

/// A subscription asking only for scopes outside the restriction is refused rather than forwarded
/// with the restriction added beside them.
#[test]
fn a_subscription_scope_outside_the_restriction_is_refused() {
    let stack = require_stack!();
    let origin = Origin::serving("application/json", r#"{"id":"urn:ngsi-ld:Subscription:1"}"#);
    let proxy = madrid_subscriber(&stack, &origin);

    assert_eq!(subscribe(&proxy, Some("/Barcelona/#")), StatusCode::FORBIDDEN);
    assert!(origin.last_request().is_none(), "the subscription must not reach the broker");
}

/// The type half of the subscription bypass: a subscription selecting a type outside
/// the restriction is refused rather than forwarded, so it can never notify on that type out of band.
#[test]
fn a_subscription_selecting_a_forbidden_type_is_refused() {
    let stack = require_stack!();
    let origin = Origin::serving("application/json", r#"{"id":"urn:ngsi-ld:Subscription:1"}"#);

    let policies = r#"
[[policy]]
id = "vehicles-only"
priority = 100

[policy.condition]
resources = ["entities", "temporal", "discovery", "subscriptions", "registrations", "registration-subscriptions", "entity-maps", "contexts"]
users = ["writer"]
tenants = ["gardens"]
operations = ["write"]

[policy.access]
effect = "allow"

[policy.access.entity-type]
allowed = ["Vehicle"]
"#;

    let settings = ProxySettings {
        upstream: origin.address(),
        ..ProxySettings::new(&stack, policies)
    };
    let proxy = Proxy::start(&settings);

    let subscription = json!({
        "@context": "https://uri.etsi.org/ngsi-ld/v1/ngsi-ld-core-context.jsonld",
        "type": "Subscription",
        "entities": [ { "type": "Device" } ],
        "notification": { "endpoint": { "uri": "http://sink.test/notify" } }
    });

    let response = proxy
        .post("/ngsi-ld/v1/subscriptions")
        .header("NGSILD-Tenant", TENANT)
        .header("Content-Type", "application/ld+json")
        .bearer_auth(token("writer"))
        .json(&subscription)
        .send()
        .expect("the proxy should answer");

    assert_eq!(response.status(), StatusCode::FORBIDDEN, "a subscription for a forbidden type must be refused");
    assert!(origin.last_request().is_none(), "a refused subscription must never reach the broker");
}

/// The `/types` enumeration under a type restriction: a caller restricted to one type does not
/// see a forbidden type's name in the tenant-wide type index. The type dimension of the
/// metadata-index narrowing in `libra-enforcement-type`.
#[test]
fn the_types_index_is_narrowed_to_the_restriction() {
    let stack = require_stack!();
    create(
        &stack,
        Some(TENANT),
        &json!({
            "@context": "https://uri.etsi.org/ngsi-ld/v1/ngsi-ld-core-context.jsonld",
            "id": unique_id("Vehicle"),
            "type": "Vehicle"
        }),
    );
    create(
        &stack,
        Some(TENANT),
        &json!({
            "@context": "https://uri.etsi.org/ngsi-ld/v1/ngsi-ld-core-context.jsonld",
            "id": unique_id("Device"),
            "type": "Device"
        }),
    );

    let policies = r#"
[[policy]]
id = "vehicles-only"
priority = 100

[policy.condition]
resources = ["entities", "temporal", "discovery", "subscriptions", "registrations", "registration-subscriptions", "entity-maps", "contexts"]
users = ["writer"]
tenants = ["gardens"]
operations = ["read"]

[policy.access]
effect = "allow"

[policy.access.entity-type]
allowed = ["Vehicle"]
"#;

    let proxy = Proxy::start(&ProxySettings::new(&stack, policies));

    let response = proxy
        .get("/ngsi-ld/v1/types")
        .header("NGSILD-Tenant", TENANT)
        .bearer_auth(token("writer"))
        .send()
        .expect("the proxy should answer");

    let status = response.status();
    let body = response.text().unwrap_or_default();
    assert!(status.is_success(), "the types index was not readable (status {status})");
    assert!(body.contains("Vehicle"), "the allowed type must remain in the index; body was: {body}");
    assert!(
        !body.contains("Device"),
        "a forbidden type must not appear in the narrowed index; body was: {body}"
    );
}

/// `GET /types/{type}` for a forbidden type is refused rather than narrowed: it would otherwise
/// answer with that type's attribute schema and instance count (NGSI-LD 5.7.7).
#[test]
fn a_forbidden_single_type_index_read_is_refused() {
    let stack = require_stack!();

    let policies = r#"
[[policy]]
id = "vehicles-only"
priority = 100

[policy.condition]
resources = ["entities", "temporal", "discovery", "subscriptions", "registrations", "registration-subscriptions", "entity-maps", "contexts"]
users = ["writer"]
tenants = ["gardens"]
operations = ["read"]

[policy.access]
effect = "allow"

[policy.access.entity-type]
allowed = ["Vehicle"]
"#;

    let proxy = Proxy::start(&ProxySettings::new(&stack, policies));

    let response = proxy
        .get("/ngsi-ld/v1/types/Device")
        .header("NGSILD-Tenant", TENANT)
        .bearer_auth(token("writer"))
        .send()
        .expect("the proxy should answer");

    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "a single-type index read outside the restriction must be refused"
    );
}

/// The `/attributes` enumeration: a caller whose policy omits an attribute does not see its name in
/// the tenant-wide attribute index, and still sees the names it may read. This seeds an entity
/// carrying a hidden and a visible attribute and reads the index back.
#[test]
fn the_attributes_index_omits_a_hidden_attribute_name() {
    let stack = require_stack!();
    let id = unique_id("Vehicle");
    create(
        &stack,
        Some(TENANT),
        &json!({
            "@context": "https://uri.etsi.org/ngsi-ld/v1/ngsi-ld-core-context.jsonld",
            "id": id,
            "type": "Vehicle",
            "speed": { "type": "Property", "value": 1 },
            "location": { "type": "GeoProperty", "value": { "type": "Point", "coordinates": [0.0, 0.0] } }
        }),
    );

    let policies = r#"
[[policy]]
id = "read-omit-location"
priority = 100

[policy.condition]
resources = ["entities", "temporal", "discovery", "subscriptions", "registrations", "registration-subscriptions", "entity-maps", "contexts"]
users = ["writer"]
tenants = ["gardens"]
operations = ["read"]

[policy.access]
effect = "allow"

[policy.access.attribute]
action = "omit"
attributes = ["location"]
"#;

    let proxy = Proxy::start(&ProxySettings::new(&stack, policies));

    let response = proxy
        .get("/ngsi-ld/v1/attributes")
        .header("NGSILD-Tenant", TENANT)
        .bearer_auth(token("writer"))
        .send()
        .expect("the proxy should answer");

    let status = response.status();
    let body = response.text().unwrap_or_default();
    assert!(status.is_success(), "the attributes index was not readable (status {status})");
    // The attribute the policy leaves visible proves the index was read and narrowed, not emptied.
    assert!(body.contains("speed"), "the visible attribute name must stay in the index; body was: {body}");
    assert!(
        !body.to_lowercase().contains("location"),
        "the hidden attribute name must not appear in the narrowed index; body was: {body}"
    );
}

/// An attribute restriction judges a registration by the attribute names it registers, not by its
/// structure. A registration that registers whole `Device` entities names no attribute the restriction
/// forbids, so it is shown, `endpoint` included; type and scope restrictions judge what such a
/// registration discloses and are tested separately.
///
/// This Scorpio image rejects a bare `GET /csourceRegistrations` (400) and requires a `type`
/// query; `?type=Device` returns the Device-source registration.
#[test]
fn a_registration_naming_no_forbidden_attribute_is_shown_to_an_attribute_restricted_caller() {
    let stack = require_stack!();
    // A tenant of its own: Scorpio forwards every retrieval by identifier in a tenant to each source
    // registered there that can retrieve, whatever type it registers, so this unreachable source in a
    // shared tenant would fail the reads and pre-flights of every other test in it.
    let tenant = "registration-probes";

    // A unique endpoint per run: this Scorpio derives the registration id from the endpoint, so a
    // fixed one collides (409) with a registration left by an earlier run.
    let endpoint = format!("http://other-source.test:9090/{}", unique_id("source"));
    let registration = json!({
        "@context": "https://uri.etsi.org/ngsi-ld/v1/ngsi-ld-core-context.jsonld",
        "type": "ContextSourceRegistration",
        "information": [ { "entities": [ { "type": "Device" } ] } ],
        "endpoint": endpoint
    });
    let seeded = tenant_creation::write_into(Some(tenant), || {
        Client::new()
            .post(stack.broker_endpoint("/ngsi-ld/v1/csourceRegistrations"))
            .header("NGSILD-Tenant", tenant)
            .header("Content-Type", "application/ld+json")
            .json(&registration)
            .send()
            .expect("the broker should accept the registration")
    });
    assert!(seeded.status().is_success(), "seeding the registration failed: {}", seeded.status());

    let policies = r#"
[[policy]]
id = "read-omit-location"
priority = 100

[policy.condition]
resources = ["entities", "temporal", "discovery", "subscriptions", "registrations", "registration-subscriptions", "entity-maps", "contexts"]
users = ["writer"]
tenants = ["registration-probes"]
operations = ["read"]

[policy.access]
effect = "allow"

[policy.access.attribute]
action = "omit"
attributes = ["location"]
"#;

    let proxy = Proxy::start(&ProxySettings::new(&stack, policies));

    let response = proxy
        .get("/ngsi-ld/v1/csourceRegistrations?type=Device")
        .header("NGSILD-Tenant", tenant)
        .bearer_auth(token("writer"))
        .send()
        .expect("the proxy should answer");

    let status = response.status();
    let body = response.text().unwrap_or_default();
    assert!(status.is_success(), "the registrations were not readable (status {status})");
    assert!(
        body.contains("other-source.test"),
        "the registration's structure is not an attribute and stays; body was: {body}"
    );
}

/// `/jsonldContexts` is gated by authorization alone. A restricted caller can read the
/// hosted-context index, because context documents are not tenant data.
#[test]
fn the_hosted_context_index_is_readable_by_a_restricted_caller() {
    let stack = require_stack!();

    let policies = r#"
[[policy]]
id = "read-omit-location"
priority = 100

[policy.condition]
resources = ["entities", "temporal", "discovery", "subscriptions", "registrations", "registration-subscriptions", "entity-maps", "contexts"]
users = ["writer"]
tenants = ["gardens"]
operations = ["read"]

[policy.access]
effect = "allow"

[policy.access.attribute]
action = "omit"
attributes = ["location"]
"#;

    let proxy = Proxy::start(&ProxySettings::new(&stack, policies));

    let response = proxy
        .get("/ngsi-ld/v1/jsonldContexts")
        .header("NGSILD-Tenant", TENANT)
        .bearer_auth(token("writer"))
        .send()
        .expect("the proxy should answer");

    assert!(
        response.status().is_success(),
        "the hosted-context index was not readable: {}",
        response.status()
    );
}
