//! Entity-type restriction, including the by-id read that carries no type.
//!
//! `GET /entities/{id}` says nothing about what it is fetching, so the type has to come from the
//! broker. The restriction is therefore only as good as what that preflight does when the broker
//! answers something other than the entity, which must never let the request through.

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
const TENANT: &str = "fleet";

/// Allows the writer reads of one type and nothing else.
const POLICIES: &str = r#"
[[policy]]
id = "vehicles-only"
priority = 100

[policy.condition]
users = ["writer"]
tenants = ["fleet"]
operations = ["read"]

[policy.access]
effect = "allow"

[policy.access.entity-type]
allowed = ["Vehicle"]
"#;

/// Seeds an entity of `kind`, and reports its identifier.
fn seed(stack: &Endpoints, kind: &str) -> String {
    let id = unique_id(kind);
    create(
        stack,
        Some(TENANT),
        &json!({
            "@context": "https://uri.etsi.org/ngsi-ld/v1/ngsi-ld-core-context.jsonld",
            "id": id,
            "type": kind,
            "name": { "type": "Property", "value": "seeded" }
        }),
    );

    id
}

#[test]
fn a_query_for_the_allowed_type_is_answered() {
    let stack = require_stack!();
    seed(&stack, "Vehicle");
    let proxy = Proxy::start(&ProxySettings::new(&stack, POLICIES));

    let response = proxy
        .get("/ngsi-ld/v1/entities?type=Vehicle")
        .header("NGSILD-Tenant", TENANT)
        .bearer_auth(token("writer"))
        .send()
        .expect("the proxy should answer");

    assert_eq!(response.status(), StatusCode::OK, "{}", response.text().unwrap_or_default());
}

#[test]
fn a_query_for_another_type_is_refused() {
    let stack = require_stack!();
    let proxy = Proxy::start(&ProxySettings::new(&stack, POLICIES));

    let response = proxy
        .get("/ngsi-ld/v1/entities?type=Building")
        .header("NGSILD-Tenant", TENANT)
        .bearer_auth(token("writer"))
        .send()
        .expect("the proxy should answer");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[test]
fn a_by_id_read_of_the_allowed_type_is_answered() {
    let stack = require_stack!();
    let id = seed(&stack, "Vehicle");
    let proxy = Proxy::start(&ProxySettings::new(&stack, POLICIES));

    let response = proxy
        .get(&format!("/ngsi-ld/v1/entities/{id}"))
        .header("NGSILD-Tenant", TENANT)
        .bearer_auth(token("writer"))
        .send()
        .expect("the proxy should answer");

    assert_eq!(response.status(), StatusCode::OK, "{}", response.text().unwrap_or_default());
}

/// Reads one entity by identifier through `proxy` and reports the status and the body.
fn read_by_id(proxy: &Proxy, id: &str) -> (StatusCode, String) {
    let response = proxy
        .get(&format!("/ngsi-ld/v1/entities/{id}"))
        .header("NGSILD-Tenant", TENANT)
        .bearer_auth(token("writer"))
        .send()
        .expect("the proxy should answer");

    (response.status(), response.text().unwrap_or_default())
}

#[test]
fn a_by_id_read_of_another_type_is_refused() {
    let stack = require_stack!();
    let id = seed(&stack, "Building");
    let proxy = Proxy::start(&ProxySettings::new(&stack, POLICIES));

    // The request names no type at all. Only the broker knows what this identifier is, and the
    // answer decides whether the restriction allows the read.
    let (status, body) = read_by_id(&proxy, &id);

    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    // The identifier spells the type, so it is taken out before looking for the type in the refusal.
    let refusal = body.replace(&id, "ID");
    assert!(!refusal.contains("Building"), "the refusal names the stored type: {body}");
}

#[test]
fn an_entity_of_another_type_is_answered_exactly_as_one_that_does_not_exist() {
    let stack = require_stack!();
    let hidden = seed(&stack, "Building");
    let absent = unique_id("Building");
    let proxy = Proxy::start(&ProxySettings::new(&stack, POLICIES));

    let (hidden_status, hidden_body) = read_by_id(&proxy, &hidden);
    let (absent_status, absent_body) = read_by_id(&proxy, &absent);

    assert_eq!(hidden_status, absent_status);
    // The bodies differ only in the identifier the caller sent.
    assert_eq!(hidden_body.replace(&hidden, "ID"), absent_body.replace(&absent, "ID"));
}

#[test]
fn a_by_id_read_of_an_entity_that_is_not_there_is_not_permission() {
    let stack = require_stack!();
    let proxy = Proxy::start(&ProxySettings::new(&stack, POLICIES));

    // The preflight cannot establish the type, so the restriction cannot be applied. Reading a
    // failed lookup as permission would turn a missing entity into a bypass.
    let response = proxy
        .get(&format!("/ngsi-ld/v1/entities/{}", unique_id("Nothing")))
        .header("NGSILD-Tenant", TENANT)
        .bearer_auth(token("writer"))
        .send()
        .expect("the proxy should answer");

    assert_ne!(response.status(), StatusCode::OK, "an entity nothing could identify must not be served");
}
