//! Requests a restriction covers in part are narrowed to that part rather than refused.
//!
//! A type selection or a `scopeQ` disjunction that names one allowed and one forbidden branch asks
//! for the allowed branch too, and a `Query` body's projection naming one forbidden attribute asks
//! for the allowed ones too; each is forwarded as the part the restriction covers. A linked `q` path
//! under an attribute restriction is checked name by name and forwarded. Scorpio answers a linked
//! `q` path with an empty array whatever it matches, so that case is asserted against an origin.

use libra_test_harness::{
    broker::{create, unique_id},
    identity::token,
    origin::Origin,
    proxy::Proxy,
    proxy_settings::ProxySettings,
    stack::Endpoints,
};
use reqwest::StatusCode;
use serde_json::{Value, json};

/// The tenant these entities live in.
const TENANT: &str = "narrowing";

/// A policy allowing the writer reads under one restriction.
fn policy_with(restriction: &str) -> String {
    format!(
        r#"
[[policy]]
id = "narrowing"
priority = 100

[policy.condition]
users = ["writer"]
tenants = ["narrowing"]
operations = ["read"]

[policy.access]
effect = "allow"

{restriction}
"#
    )
}

/// Seeds an entity of `kind` in `scope`, with `speed` and `location`, and reports its identifier.
fn seed(stack: &Endpoints, kind: &str, scope: &str) -> String {
    let id = unique_id(kind);
    create(
        stack,
        Some(TENANT),
        &json!({
            "@context": "https://uri.etsi.org/ngsi-ld/v1/ngsi-ld-core-context.jsonld",
            "id": id,
            "type": kind,
            "scope": scope,
            "speed": { "type": "Property", "value": 42 },
            "location": { "type": "GeoProperty", "value": { "type": "Point", "coordinates": [0.0, 0.0] } }
        }),
    );

    id
}

/// The identifiers of the entities an answer holds.
fn identifiers(answer: &Value) -> Vec<&str> {
    answer
        .as_array()
        .map(|entities| entities.iter().filter_map(|entity| entity.get("id").and_then(Value::as_str)).collect())
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

#[test]
fn a_type_selection_allowed_in_part_answers_with_the_allowed_type_only() {
    let stack = require_stack!();
    let vehicle = seed(&stack, "Vehicle", "/Madrid/Gardens/A");
    let building = seed(&stack, "Building", "/Madrid/Gardens/A");
    let proxy = Proxy::start(&ProxySettings::new(
        &stack,
        &policy_with("[policy.access.entity-type]\nallowed = [\"Vehicle\"]"),
    ));

    // Selected by identifier as well: the tenant is shared and outlives the run, so a read of every
    // match would page past these two once the tenant holds enough of them.
    let (status, answer) = read(&proxy, &format!("/ngsi-ld/v1/entities?id={vehicle},{building}&type=Vehicle,Building"));

    assert_eq!(status, StatusCode::OK, "{answer}");
    let found = identifiers(&answer);
    assert!(found.contains(&vehicle.as_str()), "{answer}");
    assert!(!found.contains(&building.as_str()), "{answer}");
}

#[test]
fn a_scope_disjunction_allowed_in_part_answers_with_the_allowed_scope_only() {
    let stack = require_stack!();
    let madrid = seed(&stack, "Garden", "/Madrid/Gardens/Retiro");
    let berlin = seed(&stack, "Garden", "/Berlin/Tiergarten");
    let proxy = Proxy::start(&ProxySettings::new(
        &stack,
        &policy_with("[policy.access.scope]\nallowed = [\"/Madrid/Gardens/#\"]"),
    ));

    let (status, answer) = read(
        &proxy,
        &format!("/ngsi-ld/v1/entities?id={madrid},{berlin}&type=Garden&scopeQ=/Madrid/Gardens/%23%7C/Berlin/%23"),
    );

    assert_eq!(status, StatusCode::OK, "{answer}");
    let found = identifiers(&answer);
    assert!(found.contains(&madrid.as_str()), "{answer}");
    assert!(!found.contains(&berlin.as_str()), "{answer}");
}

#[test]
fn a_batch_query_body_projection_naming_a_forbidden_attribute_is_narrowed() {
    let stack = require_stack!();
    let id = seed(&stack, "Vehicle", "/Madrid/Gardens/A");
    let proxy = Proxy::start(&ProxySettings::new(
        &stack,
        &policy_with("[policy.access.attribute]\naction = \"omit\"\nattributes = [\"location\"]"),
    ));

    let response = proxy
        .post("/ngsi-ld/v1/entityOperations/query")
        .header("NGSILD-Tenant", TENANT)
        .header("Content-Type", "application/json")
        .bearer_auth(token("writer"))
        .body(json!({ "type": "Query", "entities": [{ "id": id, "type": "Vehicle" }], "attrs": ["speed", "location"] }).to_string())
        .send()
        .expect("the proxy should answer");

    assert_eq!(response.status(), StatusCode::OK);
    let answer: Value = response.json().unwrap_or(Value::Null);
    let entity = answer.as_array().and_then(|entities| entities.first()).cloned().unwrap_or(Value::Null);
    assert!(entity.get("speed").is_some(), "{answer}");
    assert!(entity.get("location").is_none(), "{answer}");
}

#[test]
fn a_linked_filter_path_is_forwarded_under_an_attribute_restriction_and_refused_under_a_type_restriction() {
    let stack = require_stack!();
    let upstream = Origin::serving("application/json", "[]");
    let path = "/ngsi-ld/v1/entities?type=Vehicle&q=isParked%7Bname%7D==%22Downtown%22";

    let picking = ProxySettings {
        upstream: upstream.address(),
        ..ProxySettings::new(
            &stack,
            &policy_with("[policy.access.attribute]\naction = \"pick\"\nattributes = [\"isParked\", \"name\", \"speed\"]"),
        )
    };
    let (status, _) = read(&Proxy::start(&picking), path);
    assert_eq!(status, StatusCode::OK);
    let forwarded = upstream.last_request().expect("the request should reach the origin");
    assert!(forwarded.target.contains("q=isParked"), "{}", forwarded.target);

    let refusing_origin = Origin::serving("application/json", "[]");
    let typed = ProxySettings {
        upstream: refusing_origin.address(),
        ..ProxySettings::new(&stack, &policy_with("[policy.access.entity-type]\nallowed = [\"Vehicle\"]"))
    };
    let (status, _) = read(&Proxy::start(&typed), path);
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(refusing_origin.last_request().is_none(), "a refused request never reaches the broker");
}
