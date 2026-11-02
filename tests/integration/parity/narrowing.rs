//! Scope and type narrowing parity.
//!
//! Evaluates whether query narrowing enforced through Libra matches direct Scorpio queries
//! carrying the explicit narrowing query parameters (`scopeQ`, `type`).
//! Also includes fault-injection proving that Libra withholds an entity the broker returned outside
//! the allowed scope.

use crate::parity::harness::{assert_same_except, direct_get, proxied_get, unique_tenant};
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

const GARDENS_TENANT: &str = "gardens";

fn seed_scoped_garden(stack: &Endpoints, tenant: &str, scope: &str) -> String {
    let id = unique_id("Garden");
    create(
        stack,
        Some(tenant),
        &json!({
            "@context": "https://uri.etsi.org/ngsi-ld/v1/ngsi-ld-core-context.jsonld",
            "id": id,
            "type": "Garden",
            "scope": scope,
            "name": { "type": "Property", "value": "seeded" }
        }),
    );
    id
}

fn seed_typed_entity(stack: &Endpoints, tenant: &str, entity_type: &str) -> String {
    let id = unique_id(entity_type);
    create(
        stack,
        Some(tenant),
        &json!({
            "@context": "https://uri.etsi.org/ngsi-ld/v1/ngsi-ld-core-context.jsonld",
            "id": id,
            "type": entity_type,
            "name": { "type": "Property", "value": "seeded" }
        }),
    );
    id
}

#[test]
fn a_scoped_collection_matches_the_direct_scoped_query() {
    let stack = require_stack!();
    let tenant = unique_tenant("scoped");
    seed_scoped_garden(&stack, &tenant, "/A/1");
    seed_scoped_garden(&stack, &tenant, "/A/2");
    seed_scoped_garden(&stack, &tenant, "/B/1");

    let policies = format!(
        r#"
[[policy]]
id = "scoped-gardens"
priority = 100

[policy.condition]
users = ["writer"]
tenants = ["{tenant}"]
operations = ["read"]

[policy.access]
effect = "allow"

[policy.access.scope]
allowed = ["/A/#"]
"#
    );

    let proxy = Proxy::start(&ProxySettings::new(&stack, &policies));
    let bearer = token("writer");
    let headers = [("Accept", "application/json")];

    let direct_path = "/ngsi-ld/v1/entities?type=Garden&scopeQ=/A/%23";
    let (direct_status, direct) = direct_get(&stack, Some(&tenant), direct_path, &headers);

    let proxied_path = "/ngsi-ld/v1/entities?type=Garden";
    let (proxied_status, proxied) = proxied_get(&proxy, Some(&tenant), Some(&bearer), proxied_path, &headers);

    assert_eq!(direct_status, StatusCode::OK);
    assert_eq!(proxied_status, StatusCode::OK);

    assert_same_except(&direct, &proxied, &[]);

    let proxied_arr = proxied.as_array().expect("proxied collection is an array");
    assert_eq!(proxied_arr.len(), 2, "only the two /A/ gardens should be returned");
    for entity in proxied_arr {
        let scope = entity.get("scope").and_then(serde_json::Value::as_str).expect("entity has scope");
        assert!(scope.starts_with("/A/"), "unexpected scope in result: {scope}");
    }
}

#[test]
fn a_type_restricted_collection_matches_the_direct_typed_query() {
    let stack = require_stack!();
    let tenant = unique_tenant("typed");
    seed_typed_entity(&stack, &tenant, "Vehicle");
    seed_typed_entity(&stack, &tenant, "Building");

    let policies = format!(
        r#"
[[policy]]
id = "vehicles-only"
priority = 100

[policy.condition]
users = ["writer"]
tenants = ["{tenant}"]
operations = ["read"]

[policy.access]
effect = "allow"

[policy.access.entity-type]
allowed = ["Vehicle"]
"#
    );

    let proxy = Proxy::start(&ProxySettings::new(&stack, &policies));
    let bearer = token("writer");
    let headers = [("Accept", "application/json")];

    let path = "/ngsi-ld/v1/entities?type=Vehicle";
    let (direct_status, direct) = direct_get(&stack, Some(&tenant), path, &headers);
    let (proxied_status, proxied) = proxied_get(&proxy, Some(&tenant), Some(&bearer), path, &headers);

    assert_eq!(direct_status, StatusCode::OK);
    assert_eq!(proxied_status, StatusCode::OK);

    assert_same_except(&direct, &proxied, &[]);

    let proxied_arr = proxied.as_array().expect("proxied collection is an array");
    assert_eq!(proxied_arr.len(), 1, "only the Vehicle entity should be returned");
    assert_eq!(proxied_arr[0].get("type").and_then(serde_json::Value::as_str), Some("Vehicle"));
}

#[test]
fn a_broker_that_ignores_scopeq_does_not_leak() {
    let stack = require_stack!();
    let canned = r#"[
        {"id":"urn:ngsi-ld:Garden:1","type":"Garden","scope":"/A/1"},
        {"id":"urn:ngsi-ld:Garden:leak","type":"Garden","scope":"/B/leak"}
    ]"#;
    let origin = Origin::serving("application/json", canned);

    let policies = format!(
        r#"
[[policy]]
id = "scoped-gardens"
priority = 100

[policy.condition]
users = ["writer"]
tenants = ["{GARDENS_TENANT}"]
operations = ["read"]

[policy.access]
effect = "allow"

[policy.access.scope]
allowed = ["/A/#"]
"#
    );

    let settings = ProxySettings {
        upstream: origin.address(),
        ..ProxySettings::new(&stack, &policies)
    };
    let proxy = Proxy::start(&settings);
    let bearer = token("writer");

    let (status, proxied) = proxied_get(
        &proxy,
        Some(GARDENS_TENANT),
        Some(&bearer),
        "/ngsi-ld/v1/entities?type=Garden",
        &[("Accept", "application/json")],
    );

    assert_eq!(status, StatusCode::OK);

    let recorded = origin.last_request().expect("origin should have received a request");
    assert!(
        recorded.target.contains("scopeQ="),
        "Libra must narrow the forwarded query with scopeQ: target={}",
        recorded.target
    );

    // Every entity of the answer is judged against the restriction as well, so the entity the
    // broker should not have returned is withheld.
    let body_str = proxied.to_string();
    assert!(
        !body_str.contains("urn:ngsi-ld:Garden:leak"),
        "a broker ignoring scopeQ must not leak entities outside the allowed scope: {body_str}"
    );
}
