//! Context source registrations under type, scope and attribute restrictions, against a broker that
//! really holds them.
//!
//! A registration (NGSI-LD 5.2.9) says which entity types and attributes a context source provides,
//! and in which scope. Each restriction judges it by the part it is about: a type restriction by the
//! types it registers, a scope restriction by its own `scope`, an attribute restriction by the names
//! in its `propertyNames` and `relationshipNames`. Scorpio refuses a registration query that names
//! no selector, so every listing here carries `type`.

use libra_test_harness::{broker::unique_id, identity::token, proxy::Proxy, proxy_settings::ProxySettings, stack::Endpoints, tenant_creation};
use reqwest::{StatusCode, blocking::Client};
use serde_json::{Value, json};

/// The tenant these registrations live in.
const TENANT: &str = "registry";

/// The registration query every listing sends: Scorpio refuses one without a selector.
const LISTING: &str = "/ngsi-ld/v1/csourceRegistrations?type=Vehicle,Building";

/// A policy allowing the writer reads and writes under one restriction.
fn policy_with(restriction: &str) -> String {
    format!(
        r#"
[[policy]]
id = "registry"
priority = 100

[policy.condition]
resources = ["entities", "temporal", "discovery", "subscriptions", "registrations", "registration-subscriptions", "entity-maps", "contexts"]
users = ["writer"]
tenants = ["registry"]

[policy.access]
effect = "allow"

{restriction}
"#
    )
}

/// A registration of `entity_type` in `scope`, carrying `speed` and `location`.
fn registration(id: &str, entity_type: &str, scope: &str) -> Value {
    json!({
        "id": id,
        "type": "ContextSourceRegistration",
        "endpoint": "http://source.test",
        "scope": scope,
        "information": [{ "entities": [{ "type": entity_type }], "propertyNames": ["speed", "location"] }]
    })
}

/// Creates a registration in the broker directly, around the proxy.
fn seed(stack: &Endpoints, registration: &Value) {
    let response = tenant_creation::write_into(Some(TENANT), || {
        Client::new()
            .post(stack.broker_endpoint("/ngsi-ld/v1/csourceRegistrations"))
            .header("Content-Type", "application/json")
            .header("NGSILD-Tenant", TENANT)
            .body(registration.to_string())
            .send()
            .expect("the broker should answer")
    });

    assert!(
        response.status().is_success(),
        "the broker refused the seed registration: {} {}",
        response.status(),
        response.text().unwrap_or_default()
    );
}

/// Seeds a Vehicle registration in `/Madrid/Gardens/A` and a Building registration in `/Berlin/B`,
/// and reports their identifiers.
fn seed_both(stack: &Endpoints) -> (String, String) {
    let vehicle = unique_id("ContextSourceRegistration");
    let building = unique_id("ContextSourceRegistration");
    seed(stack, &registration(&vehicle, "Vehicle", "/Madrid/Gardens/A"));
    seed(stack, &registration(&building, "Building", "/Berlin/B"));

    (vehicle, building)
}

/// The registrations of a listing among `seeded`, by identifier.
fn listed<'answer>(answer: &'answer Value, seeded: &[&str]) -> Vec<&'answer Value> {
    answer
        .as_array()
        .map(|registrations| {
            registrations
                .iter()
                .filter(|registration| registration.get("id").and_then(Value::as_str).is_some_and(|id| seeded.contains(&id)))
                .collect()
        })
        .unwrap_or_default()
}

/// Reads through the proxy and reports the status and the body.
fn read(proxy: &Proxy, path: &str) -> (StatusCode, Value) {
    let response = proxy
        .get(path)
        .header("NGSILD-Tenant", TENANT)
        .bearer_auth(token("writer"))
        .send()
        .expect("the proxy should answer");
    let status = response.status();

    (status, response.json().unwrap_or(Value::Null))
}

/// Creates a registration through the proxy and reports the status.
fn create_through(proxy: &Proxy, registration: &Value) -> StatusCode {
    proxy
        .post("/ngsi-ld/v1/csourceRegistrations")
        .header("NGSILD-Tenant", TENANT)
        .header("Content-Type", "application/json")
        .bearer_auth(token("writer"))
        .body(registration.to_string())
        .send()
        .expect("the proxy should answer")
        .status()
}

#[test]
fn a_type_restriction_shows_and_accepts_only_registrations_of_allowed_types() {
    let stack = require_stack!();
    let (vehicle, building) = seed_both(&stack);
    let proxy = Proxy::start(&ProxySettings::new(
        &stack,
        &policy_with("[policy.access.entity-type]\nallowed = [\"Vehicle\"]"),
    ));

    let (status, answer) = read(&proxy, LISTING);
    assert_eq!(status, StatusCode::OK, "{answer}");
    let shown = listed(&answer, &[&vehicle, &building]);
    assert_eq!(shown.len(), 1, "only the Vehicle registration is shown: {answer}");
    assert_eq!(shown[0].get("id").and_then(Value::as_str), Some(vehicle.as_str()));

    // A hidden registration is answered exactly as an absent one, so its identifier discloses nothing.
    let (status, _) = read(&proxy, &format!("/ngsi-ld/v1/csourceRegistrations/{building}"));
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (absent, _) = read(&proxy, &format!("/ngsi-ld/v1/csourceRegistrations/{}", unique_id("ContextSourceRegistration")));
    assert_eq!(absent, status);

    let allowed = registration(&unique_id("ContextSourceRegistration"), "Vehicle", "/Madrid/Gardens/A");
    let forbidden = registration(&unique_id("ContextSourceRegistration"), "Building", "/Madrid/Gardens/A");
    assert_eq!(create_through(&proxy, &allowed), StatusCode::CREATED);
    assert_eq!(create_through(&proxy, &forbidden), StatusCode::FORBIDDEN);
}

#[test]
fn a_scope_restriction_shows_and_accepts_only_registrations_in_allowed_scopes() {
    let stack = require_stack!();
    let (vehicle, building) = seed_both(&stack);
    let proxy = Proxy::start(&ProxySettings::new(
        &stack,
        &policy_with("[policy.access.scope]\nallowed = [\"/Madrid/Gardens/#\"]\nscope-on-write = \"required\""),
    ));

    let (status, answer) = read(&proxy, LISTING);
    assert_eq!(status, StatusCode::OK, "{answer}");
    let shown = listed(&answer, &[&vehicle, &building]);
    assert_eq!(shown.len(), 1, "only the Madrid registration is shown: {answer}");
    assert_eq!(shown[0].get("id").and_then(Value::as_str), Some(vehicle.as_str()));

    // A hidden registration is answered exactly as an absent one, so its identifier discloses nothing.
    let (status, _) = read(&proxy, &format!("/ngsi-ld/v1/csourceRegistrations/{building}"));
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (absent, _) = read(&proxy, &format!("/ngsi-ld/v1/csourceRegistrations/{}", unique_id("ContextSourceRegistration")));
    assert_eq!(absent, status);

    let allowed = registration(&unique_id("ContextSourceRegistration"), "Vehicle", "/Madrid/Gardens/B");
    let forbidden = registration(&unique_id("ContextSourceRegistration"), "Vehicle", "/Berlin/B");
    assert_eq!(create_through(&proxy, &allowed), StatusCode::CREATED);
    assert_eq!(create_through(&proxy, &forbidden), StatusCode::FORBIDDEN);
}

#[test]
fn an_attribute_restriction_narrows_the_names_a_registration_lists() {
    let stack = require_stack!();
    let (vehicle, _) = seed_both(&stack);
    let proxy = Proxy::start(&ProxySettings::new(
        &stack,
        &policy_with("[policy.access.attribute]\naction = \"pick\"\nattributes = [\"speed\"]"),
    ));

    let (status, answer) = read(&proxy, &format!("/ngsi-ld/v1/csourceRegistrations/{vehicle}"));

    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_eq!(
        answer.get("endpoint"),
        Some(&json!("http://source.test")),
        "the registration's structure stays: {answer}"
    );
    assert_eq!(answer.pointer("/information/0/propertyNames"), Some(&json!(["speed"])), "{answer}");
}
