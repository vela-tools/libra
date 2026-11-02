//! Attribute restrictions, applied to a real broker's answers.
//!
//! `attrs` is a hint the broker is free to ignore, and "everything except these" cannot be written
//! as a request selector at all, so the response is filtered whatever the request asked for. That
//! is the half a unit test cannot show, because it needs a broker that answers with the attributes
//! the policy is supposed to remove.

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
const TENANT: &str = "fleet";

/// Seeds a vehicle carrying three attributes, and reports its identifier.
fn seed_vehicle(stack: &Endpoints) -> String {
    let id = unique_id("Vehicle");
    create(
        stack,
        Some(TENANT),
        &json!({
            "@context": "https://uri.etsi.org/ngsi-ld/v1/ngsi-ld-core-context.jsonld",
            "id": id,
            "type": "Vehicle",
            "speed": { "type": "Property", "value": 42 },
            "brand": { "type": "Property", "value": "Example" },
            "location": { "type": "GeoProperty", "value": { "type": "Point", "coordinates": [0.0, 0.0] } }
        }),
    );

    id
}

/// A policy allowing the writer reads under one attribute restriction.
fn policy_with(restriction: &str) -> String {
    format!(
        r#"
[[policy]]
id = "restricted-read"
priority = 100

[policy.condition]
users = ["writer"]
tenants = ["{TENANT}"]
operations = ["read"]

[policy.access]
effect = "allow"

{restriction}
"#
    )
}

#[test]
fn an_omitted_attribute_is_absent_from_the_response() {
    let stack = require_stack!();
    let id = seed_vehicle(&stack);
    let policies = policy_with("[policy.access.attribute]\naction = \"omit\"\nattributes = [\"location\"]");
    let proxy = Proxy::start(&ProxySettings::new(&stack, &policies));

    let response = proxy
        .get(&format!("/ngsi-ld/v1/entities/{id}"))
        .header("NGSILD-Tenant", TENANT)
        .bearer_auth(token("writer"))
        .send()
        .expect("the proxy should answer");

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().unwrap_or_default();
    assert!(body.contains("speed"), "everything not omitted should still be there: {body}");
    assert!(!body.contains("location"), "the omitted attribute reached the caller: {body}");
}

#[test]
fn a_pick_list_removes_everything_else() {
    let stack = require_stack!();
    let id = seed_vehicle(&stack);
    let policies = policy_with("[policy.access.attribute]\naction = \"pick\"\nattributes = [\"speed\"]");
    let proxy = Proxy::start(&ProxySettings::new(&stack, &policies));

    let response = proxy
        .get(&format!("/ngsi-ld/v1/entities/{id}"))
        .header("NGSILD-Tenant", TENANT)
        .bearer_auth(token("writer"))
        .send()
        .expect("the proxy should answer");

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().unwrap_or_default();
    assert!(body.contains("speed"), "the picked attribute should be there: {body}");
    assert!(!body.contains("brand"), "an attribute the pick list does not name reached the caller: {body}");
    assert!(
        !body.contains("location"),
        "an attribute the pick list does not name reached the caller: {body}"
    );
    assert!(body.contains(&id), "the identifier is structural and is never filtered out: {body}");
}

#[test]
fn a_query_filtering_on_a_forbidden_attribute_is_refused() {
    let stack = require_stack!();
    let policies = policy_with("[policy.access.attribute]\naction = \"omit\"\nattributes = [\"location\"]");
    let proxy = Proxy::start(&ProxySettings::new(&stack, &policies));

    // Filtering by an attribute you cannot see still tells you its values, through which entities
    // come back and which do not.
    let response = proxy
        .get("/ngsi-ld/v1/entities?type=Vehicle&q=location!=null")
        .header("NGSILD-Tenant", TENANT)
        .bearer_auth(token("writer"))
        .send()
        .expect("the proxy should answer");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[test]
fn the_operator_free_existence_form_is_refused_too() {
    let stack = require_stack!();
    let policies = policy_with("[policy.access.attribute]\naction = \"omit\"\nattributes = [\"location\"]");
    let proxy = Proxy::start(&ProxySettings::new(&stack, &policies));

    // `q=location` is a legal filter meaning "entities that have this attribute", and a tokeniser
    // that only recognises a name when an operator follows it does not see it at all.
    let response = proxy
        .get("/ngsi-ld/v1/entities?type=Vehicle&q=location")
        .header("NGSILD-Tenant", TENANT)
        .bearer_auth(token("writer"))
        .send()
        .expect("the proxy should answer");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[test]
fn an_attrs_parameter_naming_a_forbidden_attribute_is_refused() {
    let stack = require_stack!();
    let policies = policy_with("[policy.access.attribute]\naction = \"pick\"\nattributes = [\"speed\"]");
    let proxy = Proxy::start(&ProxySettings::new(&stack, &policies));

    let response = proxy
        .get("/ngsi-ld/v1/entities?type=Vehicle&attrs=location")
        .header("NGSILD-Tenant", TENANT)
        .bearer_auth(token("writer"))
        .send()
        .expect("the proxy should answer");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[test]
fn an_attribute_the_policy_allows_is_selectable() {
    let stack = require_stack!();
    seed_vehicle(&stack);
    let policies = policy_with("[policy.access.attribute]\naction = \"pick\"\nattributes = [\"speed\", \"brand\"]");
    let proxy = Proxy::start(&ProxySettings::new(&stack, &policies));

    let response = proxy
        .get("/ngsi-ld/v1/entities?type=Vehicle&attrs=speed")
        .header("NGSILD-Tenant", TENANT)
        .bearer_auth(token("writer"))
        .send()
        .expect("the proxy should answer");

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "narrowing a request within what the policy allows is not a refusal"
    );
}

/// The same entity as a `GeoJSON` Feature: the geoproperty appears twice, once in `properties` and
/// once projected to a top-level `geometry`.
const FEATURE: &str = r#"{
    "type": "Feature",
    "id": "urn:ngsi-ld:Vehicle:1",
    "geometry": { "type": "Point", "coordinates": [13.4, 52.5] },
    "properties": {
        "type": "Vehicle",
        "speed": { "type": "Property", "value": 42 },
        "location": { "type": "GeoProperty", "value": { "type": "Point", "coordinates": [13.4, 52.5] } }
    }
}"#;

#[test]
fn the_geojson_representation_does_not_carry_the_omitted_attribute() {
    let stack = require_stack!();
    // A broker stand-in rather than the broker, because the point is the *shape* of the answer:
    // under `application/geo+json` an entity is a Feature, and a filter that walks an entity's
    // members finds `geometry` and `properties`, decides neither is `location`, and returns the
    // hidden attribute twice over.
    let upstream = Origin::serving("application/geo+json", FEATURE);
    let policies = policy_with("[policy.access.attribute]\naction = \"omit\"\nattributes = [\"location\"]");
    let settings = ProxySettings {
        upstream: upstream.address(),
        ..ProxySettings::new(&stack, &policies)
    };
    let proxy = Proxy::start(&settings);

    let response = proxy
        .get("/ngsi-ld/v1/entities/urn:ngsi-ld:Vehicle:1")
        .header("NGSILD-Tenant", TENANT)
        .header("Accept", "application/geo+json")
        .bearer_auth(token("writer"))
        .send()
        .expect("the proxy should answer");

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().unwrap_or_default();
    assert!(!body.contains("13.4"), "the geometry is the omitted attribute, projected: {body}");
    assert!(!body.contains("\"location\""), "and it is in properties as well: {body}");
    assert!(body.contains("speed"), "everything else survives: {body}");
}

#[test]
fn a_query_body_cannot_filter_on_an_attribute_the_policy_hides() {
    let stack = require_stack!();
    let policies = policy_with("[policy.access.attribute]\naction = \"omit\"\nattributes = [\"location\"]");
    let proxy = Proxy::start(&ProxySettings::new(&stack, &policies));
    let bearer = token("writer");

    // `POST /entityOperations/query` is the specification's own way to send a query too long for a
    // URL, and it carries the same selectors. A check that only reads the query string is a check
    // with a documented way around it.
    for body in [
        r#"{"type":"Query","entities":[{"type":"Vehicle"}],"q":"location!=null"}"#,
        r#"{"type":"Query","entities":[{"type":"Vehicle"}],"attrs":["location"]}"#,
        r#"{"type":"Query","entities":[{"type":"Vehicle"}],"geoQ":{"geometry":"Point","coordinates":[0,0],"georel":"near;maxDistance==2000"}}"#,
    ] {
        let response = proxy
            .post("/ngsi-ld/v1/entityOperations/query")
            .header("NGSILD-Tenant", TENANT)
            .header("Content-Type", "application/json")
            .bearer_auth(&bearer)
            .body(body)
            .send()
            .expect("the proxy should answer");

        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "the body form must be refused like the query string: {body}"
        );
    }
}

#[test]
fn a_geospatial_query_cannot_filter_on_an_attribute_the_policy_hides() {
    let stack = require_stack!();
    let policies = policy_with("[policy.access.attribute]\naction = \"omit\"\nattributes = [\"location\"]");
    let proxy = Proxy::start(&ProxySettings::new(&stack, &policies));
    let bearer = token("writer");

    // Named, and not named at all (the case every ordinary geo query uses), where `location` is
    // the default. Which entities come back tells the caller where they are.
    for query in [
        "type=Vehicle&geoproperty=location",
        "type=Vehicle&georel=near%3BmaxDistance%3D%3D2000&geometry=Point&coordinates=%5B0%2C0%5D",
    ] {
        let response = proxy
            .get(&format!("/ngsi-ld/v1/entities?{query}"))
            .header("NGSILD-Tenant", TENANT)
            .bearer_auth(&bearer)
            .send()
            .expect("the proxy should answer");

        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{query}");
    }
}
