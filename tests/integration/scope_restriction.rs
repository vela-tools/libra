//! Scope restriction, enforced against entities a broker really holds.
//!
//! A by-id read carries no scope of its own, so the only way to know whether the entity is inside
//! the allowed scopes is to ask the broker what it is. That preflight is the part a unit test
//! cannot cover, and it must fail closed: a non-2xx answer from the broker is never read as
//! permission.

use libra_test_harness::{
    broker::{create, unique_id},
    identity::token,
    proxy::Proxy,
    proxy_settings::ProxySettings,
    stack::Endpoints,
};
use reqwest::StatusCode;
use serde_json::json;

/// The tenant these entities live in.
const TENANT: &str = "gardens";

/// Allows the writer reads inside one branch of the scope tree.
const POLICIES: &str = r#"
[[policy]]
id = "madrid-gardens"
priority = 100

[policy.condition]
users = ["writer"]
tenants = ["gardens"]
operations = ["read"]

[policy.access]
effect = "allow"

[policy.access.scope]
allowed = ["/Madrid/Gardens/#"]
"#;

/// Seeds an entity carrying `scope`, and reports its identifier.
fn seed_scoped(stack: &Endpoints, scope: &str) -> String {
    let id = unique_id("Garden");
    create(
        stack,
        Some(TENANT),
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

#[test]
fn an_entity_inside_the_allowed_scope_is_readable() {
    let stack = require_stack!();
    let id = seed_scoped(&stack, "/Madrid/Gardens/Retiro");
    let proxy = Proxy::start(&ProxySettings::new(&stack, POLICIES));

    let response = proxy
        .get(&format!("/ngsi-ld/v1/entities/{id}"))
        .header("NGSILD-Tenant", TENANT)
        .bearer_auth(token("writer"))
        .send()
        .expect("the proxy should answer");

    assert_eq!(response.status(), StatusCode::OK, "{}", response.text().unwrap_or_default());
}

#[test]
fn an_entity_outside_the_allowed_scope_is_refused() {
    let stack = require_stack!();
    let id = seed_scoped(&stack, "/Barcelona/Port");
    let proxy = Proxy::start(&ProxySettings::new(&stack, POLICIES));

    let response = proxy
        .get(&format!("/ngsi-ld/v1/entities/{id}"))
        .header("NGSILD-Tenant", TENANT)
        .bearer_auth(token("writer"))
        .send()
        .expect("the proxy should answer");

    assert_eq!(response.status(), StatusCode::NOT_FOUND, "the entity is outside every scope the policy allows");
}

#[test]
fn a_query_filtering_outside_the_allowed_scope_is_refused() {
    let stack = require_stack!();
    let proxy = Proxy::start(&ProxySettings::new(&stack, POLICIES));

    let response = proxy
        .get("/ngsi-ld/v1/entities?type=Garden&scopeQ=/Barcelona/%23")
        .header("NGSILD-Tenant", TENANT)
        .bearer_auth(token("writer"))
        .send()
        .expect("the proxy should answer");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[test]
fn a_query_filtering_inside_the_allowed_scope_is_answered() {
    let stack = require_stack!();
    seed_scoped(&stack, "/Madrid/Gardens/Retiro");
    let proxy = Proxy::start(&ProxySettings::new(&stack, POLICIES));

    let response = proxy
        .get("/ngsi-ld/v1/entities?type=Garden&scopeQ=/Madrid/Gardens/Retiro")
        .header("NGSILD-Tenant", TENANT)
        .bearer_auth(token("writer"))
        .send()
        .expect("the proxy should answer");

    assert_eq!(response.status(), StatusCode::OK, "{}", response.text().unwrap_or_default());
}

#[test]
fn a_query_naming_no_scope_at_all_is_narrowed_rather_than_refused() {
    let stack = require_stack!();
    seed_scoped(&stack, "/Madrid/Gardens/Retiro");
    let proxy = Proxy::start(&ProxySettings::new(&stack, POLICIES));

    // A caller who names no scope is asking for everything, and the policy allows a branch of it.
    // Refusing would make the restriction unusable; the request is held to the policy's own restriction.
    let response = proxy
        .get("/ngsi-ld/v1/entities?type=Garden")
        .header("NGSILD-Tenant", TENANT)
        .bearer_auth(token("writer"))
        .send()
        .expect("the proxy should answer");

    assert_eq!(response.status(), StatusCode::OK, "{}", response.text().unwrap_or_default());
}
