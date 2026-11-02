//! Restrictions applied to writes, not only reads.
//!
//! A policy that hides an attribute, a type or a scope on the way out must also refuse to let a
//! caller write it: otherwise a restriction is a read-only courtesy a caller edits around. The
//! attribute dimension is enforced from the request body (`libra-enforcement-attribute`); the type and
//! scope dimensions preflight the target entity so a write cannot move it past the restriction
//! (`libra-enforcement-type`, `libra-enforcement-scope`). NGSI-LD 5.6.2 to 5.6.4.

use libra_test_harness::{
    broker::{create, unique_id},
    identity::token,
    origin::Origin,
    proxy::Proxy,
    proxy_settings::ProxySettings,
    stack::Endpoints,
};
use reqwest::StatusCode;
use serde_json::json;

/// The tenant these entities live in.
const TENANT: &str = "gardens";

/// The core context every seeded entity and every write body carries.
const CORE_CONTEXT: &str = "https://uri.etsi.org/ngsi-ld/v1/ngsi-ld-core-context.jsonld";

/// A read-and-write policy for the writer under one restriction block.
fn policy_with(restriction: &str) -> String {
    format!(
        r#"
[[policy]]
id = "restricted"
priority = 100

[policy.condition]
users = ["writer"]
tenants = ["{TENANT}"]
operations = ["read", "write"]

[policy.access]
effect = "allow"

{restriction}
"#
    )
}

#[test]
fn a_patch_touching_an_omitted_attribute_is_refused() {
    let stack = require_stack!();
    let id = unique_id("Vehicle");
    create(
        &stack,
        Some(TENANT),
        &json!({
            "@context": CORE_CONTEXT,
            "id": id,
            "type": "Vehicle",
            "speed": { "type": "Property", "value": 42 },
            "brand": { "type": "Property", "value": "Example" }
        }),
    );
    let policies = policy_with("[policy.access.attribute]\naction = \"omit\"\nattributes = [\"speed\"]");
    let proxy = Proxy::start(&ProxySettings::new(&stack, &policies));

    // The hidden attribute in the body is refused: a caller who cannot read `speed` cannot set it.
    let refused = proxy
        .request(reqwest::Method::PATCH, &format!("/ngsi-ld/v1/entities/{id}/attrs"))
        .header("NGSILD-Tenant", TENANT)
        .header("Content-Type", "application/ld+json")
        .bearer_auth(token("writer"))
        .body(json!({ "@context": CORE_CONTEXT, "speed": { "type": "Property", "value": 99 } }).to_string())
        .send()
        .expect("the proxy should answer");
    assert_eq!(refused.status(), StatusCode::FORBIDDEN, "a write of the hidden attribute must be refused");

    let allowed = proxy
        .request(reqwest::Method::PATCH, &format!("/ngsi-ld/v1/entities/{id}/attrs"))
        .header("NGSILD-Tenant", TENANT)
        .header("Content-Type", "application/ld+json")
        .bearer_auth(token("writer"))
        .body(json!({ "@context": CORE_CONTEXT, "brand": { "type": "Property", "value": "Changed" } }).to_string())
        .send()
        .expect("the proxy should answer");
    assert!(
        allowed.status().is_success(),
        "a write touching only allowed attributes must be forwarded: {}",
        allowed.status()
    );
}

#[test]
fn a_post_to_attrs_adding_a_hidden_attribute_is_refused() {
    let stack = require_stack!();
    let id = unique_id("Vehicle");
    create(
        &stack,
        Some(TENANT),
        &json!({ "@context": CORE_CONTEXT, "id": id, "type": "Vehicle", "speed": { "type": "Property", "value": 42 } }),
    );
    let policies = policy_with("[policy.access.attribute]\naction = \"omit\"\nattributes = [\"location\"]");
    let proxy = Proxy::start(&ProxySettings::new(&stack, &policies));

    let response = proxy
        .post(&format!("/ngsi-ld/v1/entities/{id}/attrs"))
        .header("NGSILD-Tenant", TENANT)
        .header("Content-Type", "application/ld+json")
        .bearer_auth(token("writer"))
        .body(
            json!({
                "@context": CORE_CONTEXT,
                "location": { "type": "GeoProperty", "value": { "type": "Point", "coordinates": [0.0, 0.0] } }
            })
            .to_string(),
        )
        .send()
        .expect("the proxy should answer");

    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "appending a hidden attribute must be refused like updating one"
    );
}

#[test]
fn a_write_response_is_not_body_filtered() {
    let stack = require_stack!();
    // A write answers with the identifiers it touched, not attribute values, so its body must be
    // passed through untouched even under an attribute restriction. A broker stand-in returns a body
    // that mentions the hidden attribute name in a non-attribute position; filtering it would be
    // filtering the wrong kind of document.
    let origin = Origin::serving(
        "application/json",
        r#"{"success":["urn:ngsi-ld:Vehicle:1"],"note":"the marker location stays"}"#,
    );
    let policies = policy_with("[policy.access.attribute]\naction = \"omit\"\nattributes = [\"location\"]");
    let settings = ProxySettings {
        upstream: origin.address(),
        ..ProxySettings::new(&stack, &policies)
    };
    let proxy = Proxy::start(&settings);

    let response = proxy
        .post("/ngsi-ld/v1/entities")
        .header("NGSILD-Tenant", TENANT)
        .header("Content-Type", "application/ld+json")
        .bearer_auth(token("writer"))
        .body(json!({ "@context": CORE_CONTEXT, "id": unique_id("Vehicle"), "type": "Vehicle", "speed": { "type": "Property", "value": 1 } }).to_string())
        .send()
        .expect("the proxy should answer");
    let body = response.text().unwrap_or_default();

    assert!(
        body.contains("the marker location stays"),
        "a write response must reach the caller unfiltered: {body}"
    );
}

/// Seeds an entity of `entity_type` at `scope`, and reports its identifier.
fn seed_at(stack: &Endpoints, entity_type: &str, scope: &str) -> String {
    let id = unique_id(entity_type);
    create(
        stack,
        Some(TENANT),
        &json!({ "@context": CORE_CONTEXT, "id": id, "type": entity_type, "scope": scope, "note": { "type": "Property", "value": "seed" } }),
    );

    id
}

#[test]
fn a_put_replacing_an_entity_is_scope_checked() {
    let stack = require_stack!();
    let policies = policy_with("[policy.access.scope]\nallowed = [\"/Madrid/Gardens/#\"]");
    let proxy = Proxy::start(&ProxySettings::new(&stack, &policies));

    // The preflight reads the entity's current scope. An entity outside the restriction may not be
    // replaced, even by a body that would move it inside.
    let outside = seed_at(&stack, "Garden", "/Barcelona/Parks/Guell");
    let refused = proxy
        .request(reqwest::Method::PUT, &format!("/ngsi-ld/v1/entities/{outside}"))
        .header("NGSILD-Tenant", TENANT)
        .header("Content-Type", "application/ld+json")
        .bearer_auth(token("writer"))
        .body(json!({ "@context": CORE_CONTEXT, "id": outside, "type": "Garden", "scope": "/Madrid/Gardens/Retiro", "note": { "type": "Property", "value": "moved" } }).to_string())
        .send()
        .expect("the proxy should answer");
    assert_eq!(refused.status(), StatusCode::NOT_FOUND, "replacing an out-of-scope entity must be refused");

    let inside = seed_at(&stack, "Garden", "/Madrid/Gardens/Retiro");
    let allowed = proxy
        .request(reqwest::Method::PUT, &format!("/ngsi-ld/v1/entities/{inside}"))
        .header("NGSILD-Tenant", TENANT)
        .header("Content-Type", "application/ld+json")
        .bearer_auth(token("writer"))
        .body(json!({ "@context": CORE_CONTEXT, "id": inside, "type": "Garden", "scope": "/Madrid/Gardens/Retiro", "note": { "type": "Property", "value": "replaced" } }).to_string())
        .send()
        .expect("the proxy should answer");
    assert!(
        allowed.status().is_success(),
        "replacing an in-scope entity must be forwarded: {}",
        allowed.status()
    );
}

#[test]
fn a_patch_of_a_forbidden_type_is_refused() {
    let stack = require_stack!();
    let policies = policy_with("[policy.access.entity-type]\nallowed = [\"Vehicle\"]");
    let proxy = Proxy::start(&ProxySettings::new(&stack, &policies));

    // The preflight reads the entity's type. A caller allowed only `Vehicle` cannot patch a `Device`,
    // whatever the patch body says.
    let device = unique_id("Device");
    create(
        &stack,
        Some(TENANT),
        &json!({ "@context": CORE_CONTEXT, "id": device, "type": "Device", "state": { "type": "Property", "value": "on" } }),
    );
    let refused = proxy
        .request(reqwest::Method::PATCH, &format!("/ngsi-ld/v1/entities/{device}/attrs"))
        .header("NGSILD-Tenant", TENANT)
        .header("Content-Type", "application/ld+json")
        .bearer_auth(token("writer"))
        .body(json!({ "@context": CORE_CONTEXT, "state": { "type": "Property", "value": "off" } }).to_string())
        .send()
        .expect("the proxy should answer");
    assert_eq!(refused.status(), StatusCode::NOT_FOUND, "patching a forbidden type must be refused");

    let vehicle = unique_id("Vehicle");
    create(
        &stack,
        Some(TENANT),
        &json!({ "@context": CORE_CONTEXT, "id": vehicle, "type": "Vehicle", "speed": { "type": "Property", "value": 1 } }),
    );
    let allowed = proxy
        .request(reqwest::Method::PATCH, &format!("/ngsi-ld/v1/entities/{vehicle}/attrs"))
        .header("NGSILD-Tenant", TENANT)
        .header("Content-Type", "application/ld+json")
        .bearer_auth(token("writer"))
        .body(json!({ "@context": CORE_CONTEXT, "speed": { "type": "Property", "value": 2 } }).to_string())
        .send()
        .expect("the proxy should answer");
    assert!(
        allowed.status().is_success(),
        "patching an allowed type must be forwarded: {}",
        allowed.status()
    );
}

#[test]
fn a_delete_of_a_single_attribute_is_scope_checked() {
    let stack = require_stack!();
    let policies = policy_with("[policy.access.scope]\nallowed = [\"/Madrid/Gardens/#\"]");
    let proxy = Proxy::start(&ProxySettings::new(&stack, &policies));

    // Deleting one attribute is a write against the entity, and the entity's scope decides it.
    let outside = seed_at(&stack, "Garden", "/Barcelona/Parks/Guell");
    let refused = proxy
        .request(reqwest::Method::DELETE, &format!("/ngsi-ld/v1/entities/{outside}/attrs/note"))
        .header("NGSILD-Tenant", TENANT)
        .bearer_auth(token("writer"))
        .send()
        .expect("the proxy should answer");
    assert_eq!(
        refused.status(),
        StatusCode::NOT_FOUND,
        "deleting an attribute of an out-of-scope entity must be refused"
    );

    let inside = seed_at(&stack, "Garden", "/Madrid/Gardens/Retiro");
    let allowed = proxy
        .request(reqwest::Method::DELETE, &format!("/ngsi-ld/v1/entities/{inside}/attrs/note"))
        .header("NGSILD-Tenant", TENANT)
        .bearer_auth(token("writer"))
        .send()
        .expect("the proxy should answer");
    assert!(
        allowed.status().is_success(),
        "deleting an attribute of an in-scope entity must be forwarded: {}",
        allowed.status()
    );
}
