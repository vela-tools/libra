//! Omit restriction parity.
//!
//! An omit restriction removes precisely the named attribute from the returned
//! representation, while leaving every other member completely deep-equal to the
//! direct Scorpio response.

use crate::parity::harness::{assert_same_except, attribute_policy, direct_get, proxied_get, seed_standard_vehicle, unique_tenant};
use libra_test_harness::{broker::unique_id, identity::token, proxy::Proxy, proxy_settings::ProxySettings};
use reqwest::StatusCode;

const TENANT: &str = "fleet";

#[test]
fn an_omit_removes_exactly_the_named_attribute_normalized() {
    let stack = require_stack!();
    let id = unique_id("Vehicle");
    seed_standard_vehicle(&stack, Some(TENANT), &id);

    let policies = attribute_policy(TENANT, "omit", &["speed"]);
    let proxy = Proxy::start(&ProxySettings::new(&stack, &policies));
    let bearer = token("writer");
    let path = format!("/ngsi-ld/v1/entities/{id}");
    let headers = [("Accept", "application/json")];

    let (direct_status, direct) = direct_get(&stack, Some(TENANT), &path, &headers);
    let (proxied_status, proxied) = proxied_get(&proxy, Some(TENANT), Some(&bearer), &path, &headers);

    assert_eq!(direct_status, StatusCode::OK);
    assert_eq!(proxied_status, StatusCode::OK);
    assert!(direct.get("speed").is_some(), "direct entity must have speed");
    assert!(proxied.get("speed").is_none(), "proxied entity must not have speed");
    assert_same_except(&direct, &proxied, &["speed"]);
}

#[test]
fn an_omit_removes_exactly_the_named_attribute_concise() {
    let stack = require_stack!();
    let id = unique_id("Vehicle");
    seed_standard_vehicle(&stack, Some(TENANT), &id);

    let policies = attribute_policy(TENANT, "omit", &["speed"]);
    let proxy = Proxy::start(&ProxySettings::new(&stack, &policies));
    let bearer = token("writer");
    let path = format!("/ngsi-ld/v1/entities/{id}?options=concise");
    let headers = [("Accept", "application/json")];

    let (direct_status, direct) = direct_get(&stack, Some(TENANT), &path, &headers);
    let (proxied_status, proxied) = proxied_get(&proxy, Some(TENANT), Some(&bearer), &path, &headers);

    assert_eq!(direct_status, StatusCode::OK);
    assert_eq!(proxied_status, StatusCode::OK);
    assert!(direct.get("speed").is_some(), "direct entity must have speed");
    assert!(proxied.get("speed").is_none(), "proxied entity must not have speed");
    assert_same_except(&direct, &proxied, &["speed"]);
}

#[test]
fn an_omit_removes_exactly_the_named_attribute_key_values() {
    let stack = require_stack!();
    let id = unique_id("Vehicle");
    seed_standard_vehicle(&stack, Some(TENANT), &id);

    let policies = attribute_policy(TENANT, "omit", &["speed"]);
    let proxy = Proxy::start(&ProxySettings::new(&stack, &policies));
    let bearer = token("writer");
    let path = format!("/ngsi-ld/v1/entities/{id}?options=keyValues");
    let headers = [("Accept", "application/json")];

    let (direct_status, direct) = direct_get(&stack, Some(TENANT), &path, &headers);
    let (proxied_status, proxied) = proxied_get(&proxy, Some(TENANT), Some(&bearer), &path, &headers);

    assert_eq!(direct_status, StatusCode::OK);
    assert_eq!(proxied_status, StatusCode::OK);
    assert!(direct.get("speed").is_some(), "direct entity must have speed");
    assert!(proxied.get("speed").is_none(), "proxied entity must not have speed");
    assert_same_except(&direct, &proxied, &["speed"]);
}

#[test]
fn an_omit_in_geojson_removes_the_property_and_the_geometry() {
    let stack = require_stack!();
    let id = unique_id("Vehicle");
    seed_standard_vehicle(&stack, Some(TENANT), &id);

    let policies = attribute_policy(TENANT, "omit", &["location"]);
    let proxy = Proxy::start(&ProxySettings::new(&stack, &policies));
    let bearer = token("writer");
    let path = format!("/ngsi-ld/v1/entities/{id}");
    let headers = [("Accept", "application/geo+json")];

    let (direct_status, direct) = direct_get(&stack, Some(TENANT), &path, &headers);
    let (proxied_status, proxied) = proxied_get(&proxy, Some(TENANT), Some(&bearer), &path, &headers);

    assert_eq!(direct_status, StatusCode::OK);
    assert_eq!(proxied_status, StatusCode::OK);

    assert!(
        direct.get("properties").and_then(|p| p.get("location")).is_some(),
        "direct GeoJSON feature must have location in properties"
    );
    assert!(direct.get("geometry").is_some(), "direct GeoJSON feature must have geometry");
    assert!(
        proxied.get("properties").and_then(|p| p.get("location")).is_none(),
        "proxied GeoJSON feature must have location removed from properties"
    );
    assert!(
        proxied.get("geometry").is_none() || proxied.get("geometry") == Some(&serde_json::Value::Null),
        "proxied GeoJSON feature must have top-level geometry stripped"
    );

    assert_same_except(&direct, &proxied, &["location"]);
}

#[test]
fn an_omit_leaves_the_term_in_the_inline_context() {
    let stack = require_stack!();
    let id = unique_id("Vehicle");
    seed_standard_vehicle(&stack, Some(TENANT), &id);

    let policies = attribute_policy(TENANT, "omit", &["speed"]);
    let proxy = Proxy::start(&ProxySettings::new(&stack, &policies));
    let bearer = token("writer");
    let path = format!("/ngsi-ld/v1/entities/{id}");
    let headers = [("Accept", "application/ld+json")];

    let (direct_status, direct) = direct_get(&stack, Some(TENANT), &path, &headers);
    let (proxied_status, proxied) = proxied_get(&proxy, Some(TENANT), Some(&bearer), &path, &headers);

    assert_eq!(direct_status, StatusCode::OK);
    assert_eq!(proxied_status, StatusCode::OK);

    assert!(direct.get("speed").is_some());
    assert!(proxied.get("speed").is_none());

    let direct_context = direct.get("@context").expect("direct entity has @context");
    let proxied_context = proxied.get("@context").expect("proxied entity keeps @context");
    assert_eq!(
        direct_context, proxied_context,
        "an omit leaves @context untouched even when an attribute is filtered"
    );

    assert_same_except(&direct, &proxied, &["speed"]);
}

#[test]
fn an_omit_over_a_collection_removes_the_attribute_from_every_entity() {
    let stack = require_stack!();
    let tenant = unique_tenant("collomit");
    let id1 = unique_id("Vehicle");
    let id2 = unique_id("Vehicle");
    seed_standard_vehicle(&stack, Some(&tenant), &id1);
    seed_standard_vehicle(&stack, Some(&tenant), &id2);

    let policies = attribute_policy(&tenant, "omit", &["speed"]);
    let proxy = Proxy::start(&ProxySettings::new(&stack, &policies));
    let bearer = token("writer");
    let path = "/ngsi-ld/v1/entities?type=Vehicle";
    let headers = [("Accept", "application/json")];

    let (direct_status, direct) = direct_get(&stack, Some(&tenant), path, &headers);
    let (proxied_status, proxied) = proxied_get(&proxy, Some(&tenant), Some(&bearer), path, &headers);

    assert_eq!(direct_status, StatusCode::OK);
    assert_eq!(proxied_status, StatusCode::OK);

    let direct_arr = direct.as_array().expect("direct collection is an array");
    let proxied_arr = proxied.as_array().expect("proxied collection is an array");
    assert_eq!(direct_arr.len(), 2);
    assert_eq!(proxied_arr.len(), 2);

    for entity in direct_arr {
        assert!(entity.get("speed").is_some(), "direct entities must have speed");
    }
    for entity in proxied_arr {
        assert!(entity.get("speed").is_none(), "proxied entities must not have speed");
    }

    assert_same_except(&direct, &proxied, &["speed"]);
}
