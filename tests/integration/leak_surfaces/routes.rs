//! Obscure-API routes and authz-only contracts.
//!
//! Evaluates the authorization and disclosure characteristics of non-entity endpoints:
//! - `/entityMaps` (NGSI-LD 5.x / 1.8+ federated query maps): unverified on Scorpio; forwarded
//!   under authz-only for unrestricted callers, but refused (403 Forbidden) for type- or
//!   scope-restricted callers.
//! - `/csourceRegistrations` and `/csourceSubscriptions` (NGSI-LD 5.9 - 5.12): forwarded under
//!   authz-only without type/scope restrictions. A restricted caller's registrations are filtered
//!   and its registration writes checked; context source
//!   subscriptions are refused (403 Forbidden) for type- or scope-restricted callers.
//! - `/jsonldContexts` (NGSI-LD 5.13 hosted JSON-LD contexts): authz-gated.

use crate::parity::harness::unique_tenant;
use libra_test_harness::{broker::unique_id, identity::token, origin::Origin, proxy::Proxy, proxy_settings::ProxySettings};
use reqwest::{StatusCode, blocking::Client};
use serde_json::json;

/// `GET /entityMaps` is classified by Libra and forwarded to the broker under authz-only when no
/// type or scope restrictions apply.
///
/// The pinned Scorpio broker does not support `/entityMaps` and responds with 405 Method Not
/// Allowed. Against an Origin stand-in returning an entity map, Libra forwards the request.
#[test]
fn an_unrestricted_caller_forwards_entity_maps() {
    let stack = require_stack!();
    let tenant = unique_tenant("entity-maps-fwd");

    let policies = format!(
        r#"
[[policy]]
id = "allow-read"
priority = 100

[policy.condition]
resources = ["entities", "temporal", "discovery", "subscriptions", "registrations", "registration-subscriptions", "entity-maps", "contexts"]
users = ["writer"]
tenants = ["{tenant}"]
operations = ["read"]

[policy.access]
effect = "allow"
"#
    );

    let proxy = Proxy::start(&ProxySettings::new(&stack, &policies));

    // Scorpio route classification: verify Libra forwards the request and receives Scorpio's 405.
    let broker_response = proxy
        .get("/ngsi-ld/v1/entityMaps")
        .header("NGSILD-Tenant", &tenant)
        .bearer_auth(token("writer"))
        .send()
        .expect("proxy should answer");
    assert_eq!(
        broker_response.status(),
        StatusCode::METHOD_NOT_ALLOWED,
        "Scorpio rejects collection GET on /entityMaps with 405"
    );

    // Origin contract probe: an upstream entity map passes through for an unrestricted caller.
    let canned_map = r#"{
        "id": "urn:ngsi-ld:entityMap:1",
        "entityList": ["urn:ngsi-ld:Vehicle:in", "urn:ngsi-ld:Device:out"]
    }"#;
    let origin = Origin::serving("application/json", canned_map);
    let settings = ProxySettings {
        upstream: origin.address(),
        ..ProxySettings::new(&stack, &policies)
    };
    let mock_proxy = Proxy::start(&settings);

    let origin_response = mock_proxy
        .get("/ngsi-ld/v1/entityMaps/urn:ngsi-ld:entityMap:1")
        .header("NGSILD-Tenant", &tenant)
        .bearer_auth(token("writer"))
        .send()
        .expect("mock proxy should answer");

    let status = origin_response.status();
    let body = origin_response.text().unwrap_or_default();
    assert!(status.is_success(), "entity map read should succeed: {status}");
    assert!(body.contains("Device:out"), "expected body in forwarded entity map; body was: {body}");
}

/// An entity map read is refused with 403 for a type-restricted caller before reaching the broker.
#[test]
fn an_entity_map_read_is_refused_for_a_type_restricted_caller() {
    let stack = require_stack!();
    let tenant = unique_tenant("entity-map-type");
    let origin = Origin::serving("application/json", r#"{"id":"urn:ngsi-ld:entityMap:1"}"#);

    let policies = format!(
        r#"
[[policy]]
id = "vehicles-only"
priority = 100

[policy.condition]
resources = ["entities", "temporal", "discovery", "subscriptions", "registrations", "registration-subscriptions", "entity-maps", "contexts"]
users = ["writer"]
tenants = ["{tenant}"]
operations = ["read"]

[policy.access]
effect = "allow"

[policy.access.entity-type]
allowed = ["https://uri.etsi.org/ngsi-ld/default-context/Vehicle"]
"#
    );

    let settings = ProxySettings {
        upstream: origin.address(),
        ..ProxySettings::new(&stack, &policies)
    };
    let proxy = Proxy::start(&settings);

    let response = proxy
        .get("/ngsi-ld/v1/entityMaps/urn:ngsi-ld:entityMap:1")
        .header("NGSILD-Tenant", &tenant)
        .bearer_auth(token("writer"))
        .send()
        .expect("proxy should answer");

    assert_eq!(response.status(), StatusCode::FORBIDDEN, "entity map read must be refused with 403");
    let body = response.text().unwrap_or_default();
    assert!(
        body.contains("an entity map cannot be narrowed under an entity type restriction"),
        "expected type-denied detail; body was: {body}"
    );
    assert!(origin.last_request().is_none(), "upstream must not be contacted");
}

/// An entity map read is refused with 403 for a scope-restricted caller before reaching the broker.
#[test]
fn an_entity_map_read_is_refused_for_a_scope_restricted_caller() {
    let stack = require_stack!();
    let tenant = unique_tenant("entity-map-scope");
    let origin = Origin::serving("application/json", r#"{"id":"urn:ngsi-ld:entityMap:1"}"#);

    let policies = format!(
        r#"
[[policy]]
id = "eu-only"
priority = 100

[policy.condition]
resources = ["entities", "temporal", "discovery", "subscriptions", "registrations", "registration-subscriptions", "entity-maps", "contexts"]
users = ["writer"]
tenants = ["{tenant}"]
operations = ["read"]

[policy.access]
effect = "allow"

[policy.access.scope]
allowed = ["/eu/#"]
"#
    );

    let settings = ProxySettings {
        upstream: origin.address(),
        ..ProxySettings::new(&stack, &policies)
    };
    let proxy = Proxy::start(&settings);

    let response = proxy
        .get("/ngsi-ld/v1/entityMaps/urn:ngsi-ld:entityMap:1")
        .header("NGSILD-Tenant", &tenant)
        .bearer_auth(token("writer"))
        .send()
        .expect("proxy should answer");

    assert_eq!(response.status(), StatusCode::FORBIDDEN, "entity map read must be refused with 403");
    let body = response.text().unwrap_or_default();
    assert!(
        body.contains("an entity map cannot be narrowed under a scope restriction"),
        "expected scope-denied detail; body was: {body}"
    );
    assert!(origin.last_request().is_none(), "upstream must not be contacted");
}

/// `/csourceRegistrations` is governed only by an authz allow when the caller has no type or scope restrictions.
#[test]
fn a_registration_read_is_authz_only_without_type_or_scope_restrictions() {
    let stack = require_stack!();
    let tenant = unique_tenant("csource-authz");

    let endpoint = format!("http://source-leak.test:9090/{}", unique_id("endpoint"));
    let registration = json!({
        "@context": "https://uri.etsi.org/ngsi-ld/v1/ngsi-ld-core-context.jsonld",
        "type": "ContextSourceRegistration",
        "information": [ { "entities": [ { "type": "Device" } ] } ],
        "endpoint": endpoint
    });

    let client = Client::new();
    let seeded = client
        .post(stack.broker_endpoint("/ngsi-ld/v1/csourceRegistrations"))
        .header("NGSILD-Tenant", &tenant)
        .header("Content-Type", "application/ld+json")
        .json(&registration)
        .send()
        .expect("direct registration seeding should succeed");
    assert!(seeded.status().is_success(), "broker rejected registration: {}", seeded.status());

    let policies = format!(
        r#"
[[policy]]
id = "omit-location"
priority = 100

[policy.condition]
resources = ["entities", "temporal", "discovery", "subscriptions", "registrations", "registration-subscriptions", "entity-maps", "contexts"]
users = ["writer"]
tenants = ["{tenant}"]
operations = ["read"]

[policy.access]
effect = "allow"

[policy.access.attribute]
action = "omit"
attributes = ["location"]
"#
    );

    let proxy = Proxy::start(&ProxySettings::new(&stack, &policies));

    let response = proxy
        .get("/ngsi-ld/v1/csourceRegistrations?type=Device")
        .header("NGSILD-Tenant", &tenant)
        .bearer_auth(token("writer"))
        .send()
        .expect("proxy should answer");

    let status = response.status();
    let body = response.text().unwrap_or_default();
    assert!(status.is_success(), "csourceRegistrations was not readable (status {status})");
    assert!(
        body.contains("source-leak.test"),
        "foreign source endpoint disclosed under authz-only contract; body was: {body}"
    );
}

/// A context source subscription read is refused with 403 for a type-restricted caller.
#[test]
fn a_context_source_subscription_read_is_refused_for_a_type_restricted_caller() {
    let stack = require_stack!();
    let tenant = unique_tenant("csource-sub-type");

    let policies = format!(
        r#"
[[policy]]
id = "vehicles-only"
priority = 100

[policy.condition]
resources = ["entities", "temporal", "discovery", "subscriptions", "registrations", "registration-subscriptions", "entity-maps", "contexts"]
users = ["writer"]
tenants = ["{tenant}"]
operations = ["read"]

[policy.access]
effect = "allow"

[policy.access.entity-type]
allowed = ["https://uri.etsi.org/ngsi-ld/default-context/Vehicle"]
"#
    );

    let proxy = Proxy::start(&ProxySettings::new(&stack, &policies));

    let response = proxy
        .get("/ngsi-ld/v1/csourceSubscriptions")
        .header("NGSILD-Tenant", &tenant)
        .bearer_auth(token("writer"))
        .send()
        .expect("proxy should answer");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

/// A context source subscription read is refused with 403 for a scope-restricted caller.
#[test]
fn a_context_source_subscription_read_is_refused_for_a_scope_restricted_caller() {
    let stack = require_stack!();
    let tenant = unique_tenant("csource-sub-scope");

    let policies = format!(
        r#"
[[policy]]
id = "eu-only"
priority = 100

[policy.condition]
resources = ["entities", "temporal", "discovery", "subscriptions", "registrations", "registration-subscriptions", "entity-maps", "contexts"]
users = ["writer"]
tenants = ["{tenant}"]
operations = ["read"]

[policy.access]
effect = "allow"

[policy.access.scope]
allowed = ["/eu/#"]
"#
    );

    let proxy = Proxy::start(&ProxySettings::new(&stack, &policies));

    let response = proxy
        .get("/ngsi-ld/v1/csourceSubscriptions")
        .header("NGSILD-Tenant", &tenant)
        .bearer_auth(token("writer"))
        .send()
        .expect("proxy should answer");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

/// `GET /jsonldContexts/{id}` is gated by authorization: an authorized read succeeds, whereas an
/// unauthenticated or unauthorized read is rejected (NGSI-LD 5.13).
#[test]
fn a_hosted_context_read_is_authz_gated() {
    let stack = require_stack!();
    let tenant = unique_tenant("hosted-context");

    let client = Client::new();
    let list_response = client
        .get(stack.broker_endpoint("/ngsi-ld/v1/jsonldContexts"))
        .send()
        .expect("direct jsonldContexts fetch should succeed");
    assert!(list_response.status().is_success());

    let urls: Vec<String> = list_response.json().expect("context list should be JSON array");
    let first_url = urls.first().expect("broker should have at least one hosted context");
    let context_id = first_url.rsplit('/').next().expect("context url must have an id component");

    let policies = format!(
        r#"
[[policy]]
id = "allow-read"
priority = 100

[policy.condition]
resources = ["entities", "temporal", "discovery", "subscriptions", "registrations", "registration-subscriptions", "entity-maps", "contexts"]
users = ["writer"]
tenants = ["{tenant}"]
operations = ["read"]

[policy.access]
effect = "allow"
"#
    );

    let proxy = Proxy::start(&ProxySettings::new(&stack, &policies));

    let authorized = proxy
        .get(&format!("/ngsi-ld/v1/jsonldContexts/{context_id}"))
        .header("NGSILD-Tenant", &tenant)
        .bearer_auth(token("writer"))
        .send()
        .expect("proxy should answer");
    assert!(
        authorized.status().is_success(),
        "authorized context read should succeed: {}",
        authorized.status()
    );
    let body = authorized.text().unwrap_or_default();
    assert!(body.contains("@context"), "hosted context document must contain '@context'");

    let unauthenticated = proxy
        .get(&format!("/ngsi-ld/v1/jsonldContexts/{context_id}"))
        .header("NGSILD-Tenant", &tenant)
        .send()
        .expect("proxy should answer");
    assert_eq!(
        unauthenticated.status(),
        StatusCode::UNAUTHORIZED,
        "unauthenticated context read must be refused with 401"
    );
}
