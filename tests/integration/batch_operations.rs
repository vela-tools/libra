//! Enforcement across the `entityOperations` batch endpoints.
//!
//! A batch names its entities in the body, not the path, so every entity in the array has to be
//! judged on its own: one forbidden entity fails the batch. Write batches are checked entity by
//! entity (attribute, type, scope); a delete batch preflights every identifier; a query batch is a
//! read whose response array is filtered like any other collection. NGSI-LD 5.6.7 to 5.6.11.

use libra_test_harness::{
    broker::{create, unique_id},
    identity::token,
    origin::Origin,
    proxy::Proxy,
    proxy_settings::ProxySettings,
};
use reqwest::StatusCode;
use serde_json::json;

/// The tenant these batches name.
const TENANT: &str = "gardens";

/// The core context the seeded entities carry.
const CORE_CONTEXT: &str = "https://uri.etsi.org/ngsi-ld/v1/ngsi-ld-core-context.jsonld";

#[test]
fn a_batch_create_is_checked_entity_by_entity() {
    let stack = require_stack!();
    let policies = format!(
        r#"
[[policy]]
id = "write-omit-price"
priority = 100

[policy.condition]
users = ["writer"]
tenants = ["{TENANT}"]
operations = ["write"]

[policy.access]
effect = "allow"

[policy.access.attribute]
action = "omit"
attributes = ["price"]
"#
    );
    let proxy = Proxy::start(&ProxySettings::new(&stack, &policies));

    // The second entity carries the hidden attribute. One forbidden entity fails the whole batch,
    // and the refusal names the attribute it tripped on.
    let batch = json!([
        { "id": unique_id("Vehicle"), "type": "Vehicle", "speed": { "type": "Property", "value": 1 } },
        { "id": unique_id("Vehicle"), "type": "Vehicle", "price": { "type": "Property", "value": 100 } }
    ]);
    let response = proxy
        .post("/ngsi-ld/v1/entityOperations/create")
        .header("NGSILD-Tenant", TENANT)
        .header("Content-Type", "application/ld+json")
        .bearer_auth(token("writer"))
        .body(batch.to_string())
        .send()
        .expect("the proxy should answer");
    let status = response.status();
    let body = response.text().unwrap_or_default();

    assert_eq!(status, StatusCode::FORBIDDEN, "a batch carrying a hidden attribute must be refused");
    assert!(body.contains("price"), "the refusal should name the forbidden attribute: {body}");
}

#[test]
fn a_batch_query_response_is_attribute_filtered() {
    let stack = require_stack!();
    // The query returns entities carrying the hidden attribute; the response array is filtered on
    // the way back, the same as a GET collection.
    let origin = Origin::serving(
        "application/json",
        r#"[
            {"id":"urn:ngsi-ld:Vehicle:1","type":"Vehicle","speed":{"type":"Property","value":1},"location":{"type":"GeoProperty","value":{"type":"Point","coordinates":[0,0]}}},
            {"id":"urn:ngsi-ld:Vehicle:2","type":"Vehicle","speed":{"type":"Property","value":2},"location":{"type":"GeoProperty","value":{"type":"Point","coordinates":[1,1]}}}
        ]"#,
    );
    let policies = format!(
        r#"
[[policy]]
id = "read-omit-location"
priority = 100

[policy.condition]
users = ["writer"]
tenants = ["{TENANT}"]
operations = ["read"]

[policy.access]
effect = "allow"

[policy.access.attribute]
action = "omit"
attributes = ["location"]
"#
    );
    let settings = ProxySettings {
        upstream: origin.address(),
        ..ProxySettings::new(&stack, &policies)
    };
    let proxy = Proxy::start(&settings);

    let response = proxy
        .post("/ngsi-ld/v1/entityOperations/query")
        .header("NGSILD-Tenant", TENANT)
        .header("Content-Type", "application/json")
        .bearer_auth(token("writer"))
        .body(r#"{"type":"Query","entities":[{"type":"Vehicle"}]}"#)
        .send()
        .expect("the proxy should answer");

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().unwrap_or_default();
    assert!(body.contains("speed"), "an allowed attribute must survive: {body}");
    assert!(
        !body.contains("location"),
        "the hidden attribute must be stripped from every entity in the array: {body}"
    );
}

fn write_policy(restriction: &str) -> String {
    format!(
        r#"
[[policy]]
id = "batch-write"
priority = 100

[policy.condition]
users = ["writer"]
tenants = ["{TENANT}"]
operations = ["write"]

[policy.access]
effect = "allow"

{restriction}
"#
    )
}

#[test]
fn a_batch_upsert_with_one_forbidden_type_is_refused() {
    let stack = require_stack!();
    let policies = write_policy("[policy.access.entity-type]\nallowed = [\"Vehicle\"]");
    let proxy = Proxy::start(&ProxySettings::new(&stack, &policies));

    let batch = json!([
        { "id": unique_id("Vehicle"), "type": "Vehicle", "speed": { "type": "Property", "value": 1 } },
        { "id": unique_id("Device"), "type": "Device", "state": { "type": "Property", "value": "on" } }
    ]);
    let response = proxy
        .post("/ngsi-ld/v1/entityOperations/upsert")
        .header("NGSILD-Tenant", TENANT)
        .header("Content-Type", "application/ld+json")
        .bearer_auth(token("writer"))
        .body(batch.to_string())
        .send()
        .expect("the proxy should answer");

    assert_eq!(response.status(), StatusCode::FORBIDDEN, "a batch carrying a forbidden type must be refused");
}

#[test]
fn a_batch_update_outside_scope_is_refused() {
    let stack = require_stack!();
    let policies = write_policy("[policy.access.scope]\nallowed = [\"/Madrid/Gardens/#\"]");
    let proxy = Proxy::start(&ProxySettings::new(&stack, &policies));

    let batch = json!([
        { "id": unique_id("Garden"), "type": "Garden", "scope": "/Madrid/Gardens/Retiro", "note": { "type": "Property", "value": "in" } },
        { "id": unique_id("Garden"), "type": "Garden", "scope": "/Barcelona/Parks/Guell", "note": { "type": "Property", "value": "out" } }
    ]);
    let response = proxy
        .post("/ngsi-ld/v1/entityOperations/update")
        .header("NGSILD-Tenant", TENANT)
        .header("Content-Type", "application/ld+json")
        .bearer_auth(token("writer"))
        .body(batch.to_string())
        .send()
        .expect("the proxy should answer");

    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "a batch carrying an out-of-scope entity must be refused"
    );
}

#[test]
fn a_batch_delete_preflights_each_id() {
    let stack = require_stack!();
    let policies = write_policy("[policy.access.entity-type]\nallowed = [\"Vehicle\"]");
    let proxy = Proxy::start(&ProxySettings::new(&stack, &policies));

    let vehicle = unique_id("Vehicle");
    let device = unique_id("Device");
    create(
        &stack,
        Some(TENANT),
        &json!({ "@context": CORE_CONTEXT, "id": vehicle, "type": "Vehicle", "speed": { "type": "Property", "value": 1 } }),
    );
    create(
        &stack,
        Some(TENANT),
        &json!({ "@context": CORE_CONTEXT, "id": device, "type": "Device", "state": { "type": "Property", "value": "on" } }),
    );

    // One id preflights to a forbidden type; the whole batch is refused before anything is deleted.
    let refused = proxy
        .post("/ngsi-ld/v1/entityOperations/delete")
        .header("NGSILD-Tenant", TENANT)
        .header("Content-Type", "application/json")
        .bearer_auth(token("writer"))
        .body(json!([vehicle, device]).to_string())
        .send()
        .expect("the proxy should answer");
    assert_eq!(refused.status(), StatusCode::NOT_FOUND, "a delete batch with a forbidden id must be refused");

    let one = unique_id("Vehicle");
    let two = unique_id("Vehicle");
    create(
        &stack,
        Some(TENANT),
        &json!({ "@context": CORE_CONTEXT, "id": one, "type": "Vehicle", "speed": { "type": "Property", "value": 1 } }),
    );
    create(
        &stack,
        Some(TENANT),
        &json!({ "@context": CORE_CONTEXT, "id": two, "type": "Vehicle", "speed": { "type": "Property", "value": 2 } }),
    );
    let allowed = proxy
        .post("/ngsi-ld/v1/entityOperations/delete")
        .header("NGSILD-Tenant", TENANT)
        .header("Content-Type", "application/json")
        .bearer_auth(token("writer"))
        .body(json!([one, two]).to_string())
        .send()
        .expect("the proxy should answer");
    assert!(
        allowed.status().is_success(),
        "a delete batch entirely within the restriction must be forwarded: {}",
        allowed.status()
    );
}

#[test]
fn a_batch_delete_of_a_missing_id_is_not_permission() {
    let stack = require_stack!();
    let policies = write_policy("[policy.access.entity-type]\nallowed = [\"Vehicle\"]");
    let proxy = Proxy::start(&ProxySettings::new(&stack, &policies));

    // A nonexistent id cannot be preflighted, and an unusable preflight is a refusal, never a
    // default-allow.
    let missing = unique_id("Vehicle");
    let response = proxy
        .post("/ngsi-ld/v1/entityOperations/delete")
        .header("NGSILD-Tenant", TENANT)
        .header("Content-Type", "application/json")
        .bearer_auth(token("writer"))
        .body(json!([missing]).to_string())
        .send()
        .expect("the proxy should answer");

    assert!(
        !response.status().is_success(),
        "a preflight that could not confirm the entity must not become an allow: {}",
        response.status()
    );
}
