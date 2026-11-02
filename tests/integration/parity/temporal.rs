//! Multi-instance and temporal parity.
//!
//! Evaluates parity across temporal and multi-instance attributes:
//! - An attribute with multiple `datasetId` instances is removed as a unit under omit.
//! - A temporal entity read matches direct Scorpio minus the omitted attribute's entire instance array.

use crate::parity::harness::{assert_same_except, attribute_policy, direct_get, proxied_get, seed_temporal_vehicle};
use libra_test_harness::{
    broker::{create, unique_id},
    identity::token,
    proxy::Proxy,
    proxy_settings::ProxySettings,
    stack::Endpoints,
};
use reqwest::StatusCode;
use serde_json::json;

const TENANT: &str = "fleet";

fn seed_multi_dataset_vehicle(stack: &Endpoints, tenant: Option<&str>, id: &str) {
    create(
        stack,
        tenant,
        &json!({
            "@context": "https://uri.etsi.org/ngsi-ld/v1/ngsi-ld-core-context.jsonld",
            "id": id,
            "type": "Vehicle",
            "brand": { "type": "Property", "value": "Volvo" },
            "speed": [
                {
                    "type": "Property",
                    "value": 50,
                    "datasetId": "urn:ngsi-ld:Dataset:raw"
                },
                {
                    "type": "Property",
                    "value": 48,
                    "datasetId": "urn:ngsi-ld:Dataset:calibrated"
                }
            ]
        }),
    );
}

#[test]
fn a_multi_dataset_attribute_is_removed_as_a_unit() {
    let stack = require_stack!();
    let id = unique_id("Vehicle");
    seed_multi_dataset_vehicle(&stack, Some(TENANT), &id);

    let policies = attribute_policy(TENANT, "omit", &["speed"]);
    let proxy = Proxy::start(&ProxySettings::new(&stack, &policies));
    let bearer = token("writer");
    let path = format!("/ngsi-ld/v1/entities/{id}");
    let headers = [("Accept", "application/json")];

    let (direct_status, direct) = direct_get(&stack, Some(TENANT), &path, &headers);
    let (proxied_status, proxied) = proxied_get(&proxy, Some(TENANT), Some(&bearer), &path, &headers);

    assert_eq!(direct_status, StatusCode::OK);
    assert_eq!(proxied_status, StatusCode::OK);

    let direct_speed = direct.get("speed").and_then(serde_json::Value::as_array).expect("direct speed is an array");
    assert_eq!(direct_speed.len(), 2, "direct entity should have 2 speed instances");

    assert!(proxied.get("speed").is_none(), "proxied entity must not have speed");
    assert_eq!(proxied.get("brand"), direct.get("brand"), "brand attribute should be untouched");

    assert_same_except(&direct, &proxied, &["speed"]);
}

#[test]
fn a_temporal_read_matches_direct_minus_the_omitted_instance_array() {
    let stack = require_stack!();
    let id = unique_id("Vehicle");
    seed_temporal_vehicle(&stack, Some(TENANT), &id);

    let policies = attribute_policy(TENANT, "omit", &["speed"]);
    let proxy = Proxy::start(&ProxySettings::new(&stack, &policies));
    let bearer = token("writer");
    let path = format!("/ngsi-ld/v1/temporal/entities/{id}");
    let headers = [("Accept", "application/json")];

    let (direct_status, direct) = direct_get(&stack, Some(TENANT), &path, &headers);
    let (proxied_status, proxied) = proxied_get(&proxy, Some(TENANT), Some(&bearer), &path, &headers);

    assert_eq!(direct_status, StatusCode::OK);
    assert_eq!(proxied_status, StatusCode::OK);

    let direct_speed = direct
        .get("speed")
        .and_then(serde_json::Value::as_array)
        .expect("direct temporal speed is an array");
    assert_eq!(direct_speed.len(), 2, "direct temporal entity should have 2 speed instances");

    assert!(proxied.get("speed").is_none(), "proxied temporal entity must not have speed");
    assert_eq!(proxied.get("brand"), direct.get("brand"), "brand attribute should match direct");

    assert_same_except(&direct, &proxied, &["speed"]);
}
