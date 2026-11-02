//! Types and attributes enumeration parity vs restriction.
//!
//! NGSI-LD 5.7.5 to 5.7.10 specify type and attribute catalog endpoints (`/types`, `/attributes`).
//! This module asserts parity between what a caller is allowed and what the enumeration endpoints
//! return through Libra: type and attribute dimensions are narrowed to the restriction, while scope
//! remains documented residue.

use crate::parity::harness::unique_tenant;
use libra_test_harness::{
    broker::{create, unique_id},
    identity::token,
    proxy::Proxy,
    proxy_settings::ProxySettings,
};
use reqwest::StatusCode;
use serde_json::json;

/// Under a type restriction, the `/types` enumeration lists only allowed entity types and single-type
/// detail requests for forbidden types are refused (NGSI-LD 5.7.5, 5.7.7).
#[test]
fn the_types_index_matches_the_type_restriction() {
    let stack = require_stack!();
    let tenant = unique_tenant("types-restriction");

    create(
        &stack,
        Some(&tenant),
        &json!({
            "@context": "https://uri.etsi.org/ngsi-ld/v1/ngsi-ld-core-context.jsonld",
            "id": unique_id("Vehicle"),
            "type": "Vehicle"
        }),
    );
    create(
        &stack,
        Some(&tenant),
        &json!({
            "@context": "https://uri.etsi.org/ngsi-ld/v1/ngsi-ld-core-context.jsonld",
            "id": unique_id("Device"),
            "type": "Device"
        }),
    );

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

    let response = proxy
        .get("/ngsi-ld/v1/types")
        .header("NGSILD-Tenant", &tenant)
        .bearer_auth(token("writer"))
        .send()
        .expect("proxy should answer");

    let status = response.status();
    let body = response.text().unwrap_or_default();
    assert!(status.is_success(), "types index read failed with status {status}");
    assert!(body.contains("Vehicle"), "allowed type Vehicle must appear in types index: {body}");
    assert!(!body.contains("Device"), "forbidden type Device must not appear in types index: {body}");

    let single_forbidden = proxy
        .get("/ngsi-ld/v1/types/Device")
        .header("NGSILD-Tenant", &tenant)
        .bearer_auth(token("writer"))
        .send()
        .expect("proxy should answer");
    assert_eq!(
        single_forbidden.status(),
        StatusCode::FORBIDDEN,
        "single-type detail read for forbidden type Device must be refused"
    );
}

/// Under an attribute omit restriction, the `/attributes` catalog excludes the hidden attribute name
/// and path access to that attribute is refused (NGSI-LD 5.7.8, 5.7.10).
#[test]
fn the_attributes_index_matches_the_attribute_restriction() {
    let stack = require_stack!();
    let tenant = unique_tenant("attrs-restriction");

    create(
        &stack,
        Some(&tenant),
        &json!({
            "@context": "https://uri.etsi.org/ngsi-ld/v1/ngsi-ld-core-context.jsonld",
            "id": unique_id("Vehicle"),
            "type": "Vehicle",
            "speed": { "type": "Property", "value": 55 },
            "location": { "type": "GeoProperty", "value": { "type": "Point", "coordinates": [1.0, 2.0] } }
        }),
    );

    let policies = format!(
        r#"
[[policy]]
id = "omit-location"
priority = 100

[policy.condition]
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
        .get("/ngsi-ld/v1/attributes")
        .header("NGSILD-Tenant", &tenant)
        .bearer_auth(token("writer"))
        .send()
        .expect("proxy should answer");

    let status = response.status();
    let body = response.text().unwrap_or_default();
    assert!(status.is_success(), "attributes index read failed with status {status}");
    assert!(body.contains("speed"), "allowed attribute 'speed' must appear in attributes index: {body}");
    assert!(
        !body.to_lowercase().contains("location"),
        "omitted attribute 'location' must not appear in attributes index: {body}"
    );

    let single_forbidden = proxy
        .get("/ngsi-ld/v1/attributes/location")
        .header("NGSILD-Tenant", &tenant)
        .bearer_auth(token("writer"))
        .send()
        .expect("proxy should answer");
    assert_eq!(
        single_forbidden.status().as_u16(),
        403,
        "single-attribute detail read for omitted attribute must be refused with 403"
    );
}

/// Under a scope-only restriction, `/types` returns the full aggregate index because NGSI-LD 5.7.5 does
/// not accept `scopeQ` and the response carries no scope to filter.
#[test]
fn the_types_index_under_a_scope_restriction_is_unscoped_residue() {
    let stack = require_stack!();
    let tenant = unique_tenant("scope-types-residue");

    create(
        &stack,
        Some(&tenant),
        &json!({
            "@context": "https://uri.etsi.org/ngsi-ld/v1/ngsi-ld-core-context.jsonld",
            "id": unique_id("Garden"),
            "type": "Garden",
            "scope": "/Madrid/Gardens/Retiro"
        }),
    );
    create(
        &stack,
        Some(&tenant),
        &json!({
            "@context": "https://uri.etsi.org/ngsi-ld/v1/ngsi-ld-core-context.jsonld",
            "id": unique_id("Park"),
            "type": "Park",
            "scope": "/Barcelona/Parks/Guell"
        }),
    );

    let policies = format!(
        r#"
[[policy]]
id = "madrid-only"
priority = 100

[policy.condition]
users = ["writer"]
tenants = ["{tenant}"]
operations = ["read"]

[policy.access]
effect = "allow"

[policy.access.scope]
allowed = ["/Madrid/Gardens/#"]
"#
    );

    let proxy = Proxy::start(&ProxySettings::new(&stack, &policies));

    let response = proxy
        .get("/ngsi-ld/v1/types")
        .header("NGSILD-Tenant", &tenant)
        .bearer_auth(token("writer"))
        .send()
        .expect("proxy should answer");

    let status = response.status();
    let body = response.text().unwrap_or_default();
    assert!(status.is_success(), "types index read failed with status {status}");
    // Documenting the residue: Park exists only in /Barcelona, but appears in unscoped /types.
    assert!(
        body.contains("Garden") && body.contains("Park"),
        "types index under scope restriction returns unscoped index; body was: {body}"
    );
}
