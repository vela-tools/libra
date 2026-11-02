//! Pick restriction parity.
//!
//! A pick restriction keeps only the named attributes plus structural members
//! (`id`, `type`, `@context`), removing every other attribute. The retained
//! attributes must match the direct Scorpio response exactly.

use crate::parity::harness::{assert_same_except, attribute_policy, direct_get, proxied_get, unique_tenant};
use libra_test_harness::{
    broker::{create, unique_id},
    identity::token,
    proxy::Proxy,
    proxy_settings::ProxySettings,
    stack::Endpoints,
};
use reqwest::StatusCode;
use serde_json::{Value, json};
use std::collections::BTreeMap;

const TENANT: &str = "fleet";

fn seed_entity_with_name(stack: &Endpoints, tenant: Option<&str>, id: &str) {
    create(
        stack,
        tenant,
        &json!({
            "@context": "https://uri.etsi.org/ngsi-ld/v1/ngsi-ld-core-context.jsonld",
            "id": id,
            "type": "Vehicle",
            "name": { "type": "Property", "value": "Express" },
            "speed": { "type": "Property", "value": 50 },
            "brand": { "type": "Property", "value": "Volvo" },
            "location": { "type": "GeoProperty", "value": { "type": "Point", "coordinates": [13.4, 52.5] } }
        }),
    );
}

/// Asserts `proxied` is `entity` reduced to its structural members and `name`, comparing borrowed
/// members rather than building a projected copy.
fn assert_projected_to_structural_and_name(proxied: &Value, entity: &Value, message: &str) {
    let expected: BTreeMap<&str, &Value> = entity
        .as_object()
        .into_iter()
        .flatten()
        .filter(|(key, _)| matches!(key.as_str(), "id" | "type" | "@context" | "name"))
        .map(|(key, value)| (key.as_str(), value))
        .collect();
    let actual: BTreeMap<&str, &Value> = proxied.as_object().into_iter().flatten().map(|(key, value)| (key.as_str(), value)).collect();

    assert_eq!(actual, expected, "{message}");
}

#[test]
fn a_pick_keeps_only_the_named_attributes_plus_structural() {
    let stack = require_stack!();
    let id = unique_id("Vehicle");
    seed_entity_with_name(&stack, Some(TENANT), &id);

    let policies = attribute_policy(TENANT, "pick", &["name"]);
    let proxy = Proxy::start(&ProxySettings::new(&stack, &policies));
    let bearer = token("writer");
    let path = format!("/ngsi-ld/v1/entities/{id}");
    let headers = [("Accept", "application/json")];

    let (direct_status, direct) = direct_get(&stack, Some(TENANT), &path, &headers);
    let (proxied_status, proxied) = proxied_get(&proxy, Some(TENANT), Some(&bearer), &path, &headers);

    assert_eq!(direct_status, StatusCode::OK);
    assert_eq!(proxied_status, StatusCode::OK);

    assert_projected_to_structural_and_name(
        &proxied,
        &direct,
        "proxied entity must equal direct entity projected to structural + picked attributes",
    );

    assert_same_except(&direct, &proxied, &["speed", "brand", "location"]);
}

#[test]
fn a_pick_over_a_collection_keeps_only_the_named_attributes() {
    let stack = require_stack!();
    let tenant = unique_tenant("collpick");
    let id1 = unique_id("Vehicle");
    let id2 = unique_id("Vehicle");
    seed_entity_with_name(&stack, Some(&tenant), &id1);
    seed_entity_with_name(&stack, Some(&tenant), &id2);

    let policies = attribute_policy(&tenant, "pick", &["name"]);
    let proxy = Proxy::start(&ProxySettings::new(&stack, &policies));
    let bearer = token("writer");
    let path = "/ngsi-ld/v1/entities?type=Vehicle";
    let headers = [("Accept", "application/json")];

    let (direct_status, direct) = direct_get(&stack, Some(&tenant), path, &headers);
    let (proxied_status, proxied) = proxied_get(&proxy, Some(&tenant), Some(&bearer), path, &headers);

    assert_eq!(direct_status, StatusCode::OK);
    assert_eq!(proxied_status, StatusCode::OK);

    let direct_arr = direct.as_array().expect("direct collection is array");
    let proxied_arr = proxied.as_array().expect("proxied collection is array");
    assert_eq!(direct_arr.len(), 2);
    assert_eq!(proxied_arr.len(), 2);

    for (direct_entity, proxied_entity) in direct_arr.iter().zip(proxied_arr.iter()) {
        assert_projected_to_structural_and_name(
            proxied_entity,
            direct_entity,
            "each entity in proxied collection must match direct projected to structural + picked",
        );
    }

    assert_same_except(&direct, &proxied, &["speed", "brand", "location"]);
}

#[test]
fn a_pick_in_concise_and_key_values() {
    let stack = require_stack!();
    let id = unique_id("Vehicle");
    seed_entity_with_name(&stack, Some(TENANT), &id);

    let policies = attribute_policy(TENANT, "pick", &["name"]);
    let proxy = Proxy::start(&ProxySettings::new(&stack, &policies));
    let bearer = token("writer");

    for options in ["concise", "keyValues"] {
        let path = format!("/ngsi-ld/v1/entities/{id}?options={options}");
        let headers = [("Accept", "application/json")];

        let (direct_status, direct) = direct_get(&stack, Some(TENANT), &path, &headers);
        let (proxied_status, proxied) = proxied_get(&proxy, Some(TENANT), Some(&bearer), &path, &headers);

        assert_eq!(direct_status, StatusCode::OK);
        assert_eq!(proxied_status, StatusCode::OK);

        assert_projected_to_structural_and_name(
            &proxied,
            &direct,
            &format!("proxied {options} entity must equal direct entity projected to structural + picked"),
        );
        assert_same_except(&direct, &proxied, &["speed", "brand", "location"]);
    }
}
