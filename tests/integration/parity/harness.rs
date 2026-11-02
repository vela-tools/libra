//! Test harness for proxied-versus-direct parity assertions.

use libra_test_harness::{
    broker::{create, unique_id},
    proxy::Proxy,
    stack::Endpoints,
};
use reqwest::{StatusCode, blocking::Client, header::HeaderMap};
use serde_json::{Map, Value, json};
use std::{collections::BTreeMap, mem::take};

/// Generates a unique tenant identifier containing only characters allowed by Libra (`A-Z a-z 0-9 - . _ ~`).
pub fn unique_tenant(prefix: &str) -> String {
    let raw = unique_id(prefix);
    raw.replace(':', "-")
}

/// Reads a resource directly from the upstream broker, returning the status code and parsed JSON body.
pub fn direct_get(stack: &Endpoints, tenant: Option<&str>, path: &str, headers: &[(&str, &str)]) -> (StatusCode, Value) {
    let (status, _, bytes) = direct_get_raw(stack, tenant, path, headers);
    let value = serde_json::from_slice(&bytes)
        .unwrap_or_else(|error| panic!("failed to parse direct response as JSON: {error}; body: {}", String::from_utf8_lossy(&bytes)));
    (status, value)
}

/// Reads a resource directly from the upstream broker, returning status code, headers, and raw bytes.
pub fn direct_get_raw(stack: &Endpoints, tenant: Option<&str>, path: &str, headers: &[(&str, &str)]) -> (StatusCode, HeaderMap, Vec<u8>) {
    let mut request = Client::builder().build().expect("HTTP client should build").get(stack.broker_endpoint(path));

    if let Some(tenant) = tenant {
        request = request.header("NGSILD-Tenant", tenant);
    }
    for (name, value) in headers {
        request = request.header(*name, *value);
    }

    let mut response = request.send().expect("broker should answer");
    let status = response.status();
    let headers = take(response.headers_mut());
    let bytes = response.bytes().expect("response bytes should be readable").to_vec();
    (status, headers, bytes)
}

/// Reads a resource through the Libra proxy, returning the status code and parsed JSON body.
pub fn proxied_get(proxy: &Proxy, tenant: Option<&str>, token: Option<&str>, path: &str, headers: &[(&str, &str)]) -> (StatusCode, Value) {
    let (status, _, bytes) = proxied_get_raw(proxy, tenant, token, path, headers);
    let value = serde_json::from_slice(&bytes)
        .unwrap_or_else(|error| panic!("failed to parse proxied response as JSON: {error}; body: {}", String::from_utf8_lossy(&bytes)));
    (status, value)
}

/// Reads a resource through the Libra proxy, returning status code, headers, and raw bytes.
pub fn proxied_get_raw(proxy: &Proxy, tenant: Option<&str>, token: Option<&str>, path: &str, headers: &[(&str, &str)]) -> (StatusCode, HeaderMap, Vec<u8>) {
    let mut request = proxy.get(path);
    if let Some(tenant) = tenant {
        request = request.header("NGSILD-Tenant", tenant);
    }
    if let Some(token) = token {
        request = request.bearer_auth(token);
    }
    for (name, value) in headers {
        request = request.header(*name, *value);
    }

    let mut response = request.send().expect("proxy should answer");
    let status = response.status();
    let headers = take(response.headers_mut());
    let bytes = response.bytes().expect("response bytes should be readable").to_vec();
    (status, headers, bytes)
}

/// Compares two `GeoJSON` Features structurally, accounting for omitted attributes.
fn diff_geojson_feature(direct: &Map<String, Value>, proxied: &Map<String, Value>, removed: &[&str]) {
    assert_eq!(direct.get("id"), proxied.get("id"), "Feature id mismatch");
    assert_eq!(direct.get("type"), proxied.get("type"), "Feature type mismatch");

    if let Some(context) = direct.get("@context") {
        assert_eq!(proxied.get("@context"), Some(context));
    }

    let direct_props = direct
        .get("properties")
        .and_then(Value::as_object)
        .expect("direct properties should be an object");
    let proxied_props = proxied
        .get("properties")
        .and_then(Value::as_object)
        .expect("proxied properties should be an object");

    for (key, val) in direct_props {
        if removed.contains(&key.as_str()) {
            assert!(!proxied_props.contains_key(key), "proxied properties should not contain removed member: {key}");
        } else {
            let proxied_val = proxied_props.get(key).unwrap_or_else(|| {
                panic!("proxied properties missing member '{key}' present in direct");
            });
            assert_same_except(val, proxied_val, removed);
        }
    }
    for key in proxied_props.keys() {
        assert!(direct_props.contains_key(key), "proxied properties contains unexpected member: {key}");
    }

    let removed_geoproperty = removed.iter().any(|&rem| {
        direct_props.get(rem).and_then(|p| p.get("type")).and_then(Value::as_str) == Some("GeoProperty")
            || (direct_props.contains_key(rem) && direct.contains_key("geometry"))
    });

    if removed_geoproperty {
        assert!(
            proxied.get("geometry").is_none() || proxied.get("geometry") == Some(&Value::Null),
            "proxied geometry should be absent or null when GeoProperty is omitted"
        );
    } else if let Some(direct_geom) = direct.get("geometry") {
        assert_eq!(proxied.get("geometry"), Some(direct_geom), "proxied geometry does not match direct geometry");
    }

    for (key, val) in direct {
        if key == "properties" || key == "geometry" {
            continue;
        }
        assert_eq!(proxied.get(key), Some(val), "proxied top-level member '{key}' differs from direct");
    }
    for key in proxied.keys() {
        if key == "properties" || key == "geometry" {
            continue;
        }
        assert!(direct.contains_key(key), "proxied contains unexpected top-level member: {key}");
    }
}

/// Compares two `GeoJSON` `FeatureCollections` structurally, accounting for omitted attributes.
fn diff_geojson_feature_collection(direct: &Map<String, Value>, proxied: &Map<String, Value>, removed: &[&str]) {
    let direct_features = direct.get("features").expect("features array");
    let proxied_features = proxied.get("features").expect("features array");
    assert_same_except(direct_features, proxied_features, removed);
    if let Some(context) = direct.get("@context") {
        assert_eq!(proxied.get("@context"), Some(context));
    }
}

/// Compares two generic JSON objects or standard NGSI-LD entities structurally.
fn diff_json_object(direct: &Map<String, Value>, proxied: &Map<String, Value>, removed: &[&str]) {
    for (key, val) in direct {
        if removed.contains(&key.as_str()) {
            assert!(!proxied.contains_key(key), "proxied entity should not contain removed member: {key}");
        } else {
            let proxied_val = proxied.get(key).unwrap_or_else(|| {
                panic!("proxied entity missing member '{key}' present in direct");
            });
            assert_same_except(val, proxied_val, removed);
        }
    }
    for key in proxied.keys() {
        assert!(direct.contains_key(key), "proxied entity introduced unexpected member: {key}");
    }
}

/// Compares two JSON arrays structurally, matching entities by `id` when present.
fn diff_json_array(direct: &[Value], proxied: &[Value], removed: &[&str]) {
    let direct_has_ids = direct.iter().all(|item| item.is_object() && item.get("id").and_then(Value::as_str).is_some());
    let proxied_has_ids = proxied.iter().all(|item| item.is_object() && item.get("id").and_then(Value::as_str).is_some());

    if direct_has_ids && proxied_has_ids {
        let mut direct_by_id = BTreeMap::new();
        for item in direct {
            let id = item.get("id").and_then(Value::as_str).expect("entity has id");
            let prev = direct_by_id.insert(id, item);
            assert!(prev.is_none(), "duplicate id '{id}' in direct collection");
        }

        let mut proxied_by_id = BTreeMap::new();
        for item in proxied {
            let id = item.get("id").and_then(Value::as_str).expect("entity has id");
            let prev = proxied_by_id.insert(id, item);
            assert!(prev.is_none(), "duplicate id '{id}' in proxied collection");
        }

        assert_eq!(
            direct_by_id.len(),
            proxied_by_id.len(),
            "collection entity count mismatch: direct={}, proxied={}",
            direct_by_id.len(),
            proxied_by_id.len()
        );

        for (id, direct_entity) in direct_by_id {
            let proxied_entity = proxied_by_id.get(id).unwrap_or_else(|| {
                panic!("proxied collection missing entity with id '{id}'");
            });
            assert_same_except(direct_entity, proxied_entity, removed);
        }
    } else {
        assert_eq!(
            direct.len(),
            proxied.len(),
            "array length mismatch: direct={}, proxied={}",
            direct.len(),
            proxied.len()
        );
        for (d, p) in direct.iter().zip(proxied.iter()) {
            assert_same_except(d, p, removed);
        }
    }
}

/// Asserts that `proxied` has the exact same structure and values as `direct`,
/// except that members named in `removed` are absent from `proxied`.
///
/// Both sides are compared structurally as [`Value`]. For arrays of entities,
/// items are matched by `id` and diffed per entity. For `GeoJSON` Features, if a
/// removed attribute is a `GeoProperty`, top-level `geometry` is also asserted to
/// be absent from `proxied`.
pub fn assert_same_except(direct: &Value, proxied: &Value, removed: &[&str]) {
    match (direct, proxied) {
        (Value::Object(direct_map), Value::Object(proxied_map)) => {
            let is_direct_feature = direct_map.get("type").and_then(Value::as_str) == Some("Feature") && direct_map.contains_key("properties");
            let is_proxied_feature = proxied_map.get("type").and_then(Value::as_str) == Some("Feature") && proxied_map.contains_key("properties");

            if is_direct_feature || is_proxied_feature {
                assert!(is_direct_feature && is_proxied_feature, "one side is a GeoJSON Feature and the other is not");
                diff_geojson_feature(direct_map, proxied_map, removed);
                return;
            }

            let is_direct_fc = direct_map.get("type").and_then(Value::as_str) == Some("FeatureCollection") && direct_map.contains_key("features");
            let is_proxied_fc = proxied_map.get("type").and_then(Value::as_str) == Some("FeatureCollection") && proxied_map.contains_key("features");

            if is_direct_fc || is_proxied_fc {
                assert!(is_direct_fc && is_proxied_fc, "one side is a FeatureCollection and the other is not");
                diff_geojson_feature_collection(direct_map, proxied_map, removed);
                return;
            }

            diff_json_object(direct_map, proxied_map, removed);
        }
        (Value::Array(direct_arr), Value::Array(proxied_arr)) => {
            diff_json_array(direct_arr, proxied_arr, removed);
        }
        (other_direct, other_proxied) => {
            assert_eq!(
                other_direct, other_proxied,
                "primitive values mismatch: direct={other_direct}, proxied={other_proxied}"
            );
        }
    }
}

/// Seeds a standard vehicle entity with speed, brand, and location.
pub fn seed_standard_vehicle(stack: &Endpoints, tenant: Option<&str>, id: &str) {
    create(
        stack,
        tenant,
        &json!({
            "@context": "https://uri.etsi.org/ngsi-ld/v1/ngsi-ld-core-context.jsonld",
            "id": id,
            "type": "Vehicle",
            "speed": { "type": "Property", "value": 50 },
            "brand": { "type": "Property", "value": "Volvo" },
            "location": { "type": "GeoProperty", "value": { "type": "Point", "coordinates": [13.4, 52.5] } }
        }),
    );
}

/// Seeds a temporal entity with multiple speed instances and a brand.
pub fn seed_temporal_vehicle(stack: &Endpoints, tenant: Option<&str>, id: &str) {
    let mut request = Client::new()
        .post(stack.broker_endpoint("/ngsi-ld/v1/temporal/entities"))
        .header("Content-Type", "application/ld+json")
        .body(
            json!({
                "@context": "https://uri.etsi.org/ngsi-ld/v1/ngsi-ld-core-context.jsonld",
                "id": id,
                "type": "Vehicle",
                "brand": { "type": "Property", "value": "Example" },
                "speed": [
                    { "type": "Property", "value": 40, "observedAt": "2026-01-01T00:00:00Z" },
                    { "type": "Property", "value": 42, "observedAt": "2026-01-01T01:00:00Z" }
                ]
            })
            .to_string(),
        );

    if let Some(tenant) = tenant {
        request = request.header("NGSILD-Tenant", tenant);
    }

    let response = request.send().expect("broker should answer temporal seed");
    assert!(response.status().is_success(), "broker refused temporal seed: {}", response.status());
}

/// Creates a policy allowing unrestricted reads for the writer in `tenant`.
pub fn unrestricted_policy(tenant: &str) -> String {
    format!(
        r#"
[[policy]]
id = "unrestricted-read"
priority = 100

[policy.condition]
users = ["writer"]
tenants = ["{tenant}"]
operations = ["read"]

[policy.access]
effect = "allow"
"#
    )
}

/// Creates a policy allowing reads for the writer in `tenant` with an attribute restriction.
pub fn attribute_policy(tenant: &str, action: &str, attributes: &[&str]) -> String {
    let attrs = attributes.iter().map(|attr| format!("\"{attr}\"")).collect::<Vec<_>>().join(", ");
    format!(
        r#"
[[policy]]
id = "restricted-read"
priority = 100

[policy.condition]
users = ["writer"]
tenants = ["{tenant}"]
operations = ["read"]

[policy.access]
effect = "allow"

[policy.access.attribute]
action = "{action}"
attributes = [{attrs}]
"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assert_same_except_handles_matching_and_removed_fields() {
        let direct = json!({
            "id": "urn:ngsi-ld:T:1",
            "type": "T",
            "speed": { "type": "Property", "value": 42 },
            "brand": { "type": "Property", "value": "Test" }
        });
        let proxied = json!({
            "id": "urn:ngsi-ld:T:1",
            "type": "T",
            "brand": { "type": "Property", "value": "Test" }
        });

        assert_same_except(&direct, &proxied, &["speed"]);
    }

    #[test]
    fn assert_same_except_matches_arrays_by_id_regardless_of_order() {
        let direct = json!([
            { "id": "urn:ngsi-ld:T:1", "type": "T", "speed": 10 },
            { "id": "urn:ngsi-ld:T:2", "type": "T", "speed": 20 }
        ]);
        let proxied = json!([
            { "id": "urn:ngsi-ld:T:2", "type": "T" },
            { "id": "urn:ngsi-ld:T:1", "type": "T" }
        ]);

        assert_same_except(&direct, &proxied, &["speed"]);
    }

    #[test]
    fn assert_same_except_handles_geojson_features() {
        let direct = json!({
            "id": "urn:ngsi-ld:T:1",
            "type": "Feature",
            "geometry": { "type": "Point", "coordinates": [0.0, 0.0] },
            "properties": {
                "type": "T",
                "brand": "Test",
                "location": { "type": "GeoProperty", "value": { "type": "Point", "coordinates": [0.0, 0.0] } }
            }
        });
        let proxied = json!({
            "id": "urn:ngsi-ld:T:1",
            "type": "Feature",
            "properties": {
                "type": "T",
                "brand": "Test"
            }
        });

        assert_same_except(&direct, &proxied, &["location"]);
    }

    #[test]
    #[should_panic(expected = "proxied properties should not contain removed member: location")]
    fn assert_same_except_fails_if_removed_key_still_present() {
        let direct = json!({
            "id": "urn:ngsi-ld:T:1",
            "type": "Feature",
            "properties": {
                "location": 1
            }
        });
        let proxied = json!({
            "id": "urn:ngsi-ld:T:1",
            "type": "Feature",
            "properties": {
                "location": 1
            }
        });
        assert_same_except(&direct, &proxied, &["location"]);
    }
}
