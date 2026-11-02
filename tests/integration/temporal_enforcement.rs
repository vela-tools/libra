//! Enforcement across the temporal API, whose shapes differ from the ordinary one.
//!
//! A temporal entity keeps each attribute as an array of instances, and a temporal query carries
//! its window in `timeAt`/`endTimeAt` on the URL or in a `temporalQ` in the body. The attribute
//! filter removes a hidden attribute's whole instance array; the time layer narrows the window in
//! both the URL and the body to what the policy allows; a path that names an attribute is refused
//! before the request is sent. NGSI-LD 5.7.
//!
//! Reads use a broker stand-in so the temporal and `GeoJSON` shapes can be produced exactly, and so
//! the narrowed window the broker receives can be observed.

use jiff::{SignedDuration, Timestamp};
use libra_test_harness::{
    identity::token,
    origin::{Origin, address},
    proxy::Proxy,
    proxy_settings::ProxySettings,
};
use reqwest::StatusCode;

/// The tenant these operations name.
const TENANT: &str = "gardens";

/// A read restriction that hides `location`.
const OMIT_LOCATION: &str = r#"
[[policy]]
id = "read-omit-location"
priority = 100

[policy.condition]
users = ["writer"]
tenants = ["gardens"]
operations = ["read"]

[policy.access]
effect = "allow"

[policy.access.attribute]
action = "omit"
attributes = ["location"]
"#;

/// A temporal entity in normalized form: each attribute is an array of instances, not one value.
const TEMPORAL_ENTITY: &str = r#"{
    "id": "urn:ngsi-ld:Vehicle:1",
    "type": "Vehicle",
    "speed": [
        { "type": "Property", "value": 40, "observedAt": "2026-01-01T00:00:00Z" },
        { "type": "Property", "value": 42, "observedAt": "2026-01-01T01:00:00Z" }
    ],
    "location": [
        { "type": "GeoProperty", "value": { "type": "Point", "coordinates": [13.4, 52.5] }, "observedAt": "2026-01-01T00:00:00Z" }
    ]
}"#;

/// The same temporal entity as a `GeoJSON` Feature: the geoproperty is projected to `geometry` and
/// also kept under `properties`.
const TEMPORAL_FEATURE: &str = r#"{
    "type": "Feature",
    "id": "urn:ngsi-ld:Vehicle:1",
    "geometry": { "type": "Point", "coordinates": [13.4, 52.5] },
    "properties": {
        "type": "Vehicle",
        "speed": [ { "type": "Property", "value": 42, "observedAt": "2026-01-01T01:00:00Z" } ],
        "location": [ { "type": "GeoProperty", "value": { "type": "Point", "coordinates": [13.4, 52.5] }, "observedAt": "2026-01-01T00:00:00Z" } ]
    }
}"#;

#[test]
fn a_temporal_item_read_is_attribute_filtered() {
    let stack = require_stack!();
    let origin = Origin::serving("application/json", TEMPORAL_ENTITY);
    let settings = ProxySettings {
        upstream: origin.address(),
        ..ProxySettings::new(&stack, OMIT_LOCATION)
    };
    let proxy = Proxy::start(&settings);

    let response = proxy
        .get("/ngsi-ld/v1/temporal/entities/urn:ngsi-ld:Vehicle:1")
        .header("NGSILD-Tenant", TENANT)
        .bearer_auth(token("writer"))
        .send()
        .expect("the proxy should answer");

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().unwrap_or_default();
    // The whole instance array of the hidden attribute is gone; the allowed one's is intact.
    assert!(body.contains("speed"), "the allowed attribute's instances must survive: {body}");
    assert!(!body.contains("location"), "the hidden attribute's instance array must be removed: {body}");
    assert!(!body.contains("13.4"), "and with it the values inside those instances: {body}");
}

#[test]
fn a_temporal_read_in_geojson_strips_the_geometry() {
    let stack = require_stack!();
    let origin = Origin::serving("application/geo+json", TEMPORAL_FEATURE);
    let settings = ProxySettings {
        upstream: origin.address(),
        ..ProxySettings::new(&stack, OMIT_LOCATION)
    };
    let proxy = Proxy::start(&settings);

    let response = proxy
        .get("/ngsi-ld/v1/temporal/entities/urn:ngsi-ld:Vehicle:1")
        .header("NGSILD-Tenant", TENANT)
        .header("Accept", "application/geo+json")
        .bearer_auth(token("writer"))
        .send()
        .expect("the proxy should answer");

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().unwrap_or_default();
    // The geoproperty is hidden, so both its copies go: the projected geometry and the one under
    // properties. The allowed attribute stays.
    assert!(
        !body.contains("13.4"),
        "the projected geometry is the hidden attribute and must be gone: {body}"
    );
    assert!(!body.contains("\"location\""), "the hidden attribute must be gone from properties too: {body}");
    assert!(body.contains("speed"), "an allowed attribute must survive: {body}");
}

#[test]
fn a_temporal_attribute_instance_delete_is_path_checked() {
    let stack = require_stack!();
    let origin = Origin::serving("application/json", "{}");
    let settings = ProxySettings {
        upstream: origin.address(),
        ..ProxySettings::new(&stack, OMIT_LOCATION)
    };
    let proxy = Proxy::start(&settings);

    // The path names the hidden attribute. Deleting one of its instances is refused before the
    // request is sent, the same as reading it would be.
    let response = proxy
        .request(
            reqwest::Method::DELETE,
            "/ngsi-ld/v1/temporal/entities/urn:ngsi-ld:Vehicle:1/attrs/location/instance-7",
        )
        .header("NGSILD-Tenant", TENANT)
        .bearer_auth(token("writer"))
        .send()
        .expect("the proxy should answer");

    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "deleting an instance of a hidden attribute must be refused"
    );
    assert!(origin.last_request().is_none(), "the refused delete must not reach the broker");
}

/// A read restriction bounded to the month of January 2026, for the narrowing tests.
const JANUARY_ONLY: &str = r#"
[[policy]]
id = "january-only"
priority = 100

[policy.condition]
users = ["writer"]
tenants = ["gardens"]
operations = ["read"]

[policy.access]
effect = "allow"

[policy.access.time]
type = "absolute"
start = 2026-01-01T00:00:00Z
end = 2026-02-01T00:00:00Z
"#;

#[test]
fn a_temporal_item_read_is_time_narrowed() {
    let stack = require_stack!();
    let origin = Origin::serving("application/json", TEMPORAL_ENTITY);
    let settings = ProxySettings {
        upstream: origin.address(),
        ..ProxySettings::new(&stack, JANUARY_ONLY)
    };
    let proxy = Proxy::start(&settings);

    // The requested window runs from mid-2025 to mid-2026, wider than the restriction on both ends. What
    // reaches the broker is the intersection: the allowed January window.
    let response = proxy
        .get("/ngsi-ld/v1/temporal/entities?type=Vehicle&timerel=between&timeAt=2025-06-01T00:00:00Z&endTimeAt=2026-06-01T00:00:00Z")
        .header("NGSILD-Tenant", TENANT)
        .bearer_auth(token("writer"))
        .send()
        .expect("the proxy should answer");
    let status = response.status();

    let recorded = origin
        .last_request()
        .unwrap_or_else(|| panic!("the read was not forwarded; status was {status}"));
    assert!(
        (recorded.target.contains("2026-01-01T00:00:00") || recorded.target.contains("2026-01-01T00%3A00%3A00"))
            && (recorded.target.contains("2026-02-01T00:00:00") || recorded.target.contains("2026-02-01T00%3A00%3A00")),
        "the broker must receive the narrowed January window: {}",
        recorded.target
    );
    assert!(
        !recorded.target.contains("2025-06-01") && !recorded.target.contains("2026-06-01"),
        "the caller's wider bounds must not survive the narrowing: {}",
        recorded.target
    );
}

#[test]
fn a_temporal_batch_query_is_narrowed_and_filtered() {
    let stack = require_stack!();
    let origin = Origin::serving("application/json", &format!("[{TEMPORAL_ENTITY}]"));
    // Both a time restriction and an attribute restriction, so one request exercises the body-window narrowing and
    // the response-array filter together.
    let policies = format!("{JANUARY_ONLY}\n[policy.access.attribute]\naction = \"omit\"\nattributes = [\"location\"]");
    let settings = ProxySettings {
        upstream: origin.address(),
        ..ProxySettings::new(&stack, &policies)
    };
    let proxy = Proxy::start(&settings);

    let body = r#"{
        "type": "Query",
        "entities": [ { "type": "Vehicle" } ],
        "temporalQ": { "timerel": "between", "timeAt": "2025-06-01T00:00:00Z", "endTimeAt": "2026-06-01T00:00:00Z" }
    }"#;
    let response = proxy
        .post("/ngsi-ld/v1/temporal/entityOperations/query")
        .header("NGSILD-Tenant", TENANT)
        .header("Content-Type", "application/json")
        .bearer_auth(token("writer"))
        .body(body)
        .send()
        .expect("the proxy should answer");
    let status = response.status();

    let recorded = origin
        .last_request()
        .unwrap_or_else(|| panic!("the temporal query was not forwarded; status was {status}"));
    assert!(
        recorded.body.contains("2026-01-01T00:00:00") && recorded.body.contains("2026-02-01T00:00:00"),
        "the forwarded temporalQ must carry the narrowed January window: {}",
        recorded.body
    );
    assert!(
        !recorded.body.contains("2025-06-01"),
        "the caller's wider start must not survive the narrowing: {}",
        recorded.body
    );

    let answered = response.text().unwrap_or_default();
    assert!(answered.contains("speed"), "the allowed attribute must survive: {answered}");
    assert!(
        !answered.contains("location"),
        "the hidden attribute must be stripped from the response: {answered}"
    );
}

#[test]
fn a_temporal_write_is_scope_and_type_checked() {
    let stack = require_stack!();

    let type_policies = r#"
[[policy]]
id = "vehicles-only"
priority = 100

[policy.condition]
users = ["writer"]
tenants = ["gardens"]
operations = ["write"]

[policy.access]
effect = "allow"

[policy.access.entity-type]
allowed = ["Vehicle"]
"#;
    let type_proxy = Proxy::start(&ProxySettings::new(&stack, type_policies));
    let device = r#"{
        "@context": "https://uri.etsi.org/ngsi-ld/v1/ngsi-ld-core-context.jsonld",
        "id": "urn:ngsi-ld:Device:temporal-1",
        "type": "Device",
        "state": [ { "type": "Property", "value": "on", "observedAt": "2026-01-01T00:00:00Z" } ]
    }"#;
    let refused_type = type_proxy
        .post("/ngsi-ld/v1/temporal/entities")
        .header("NGSILD-Tenant", TENANT)
        .header("Content-Type", "application/ld+json")
        .bearer_auth(token("writer"))
        .body(device)
        .send()
        .expect("the proxy should answer");
    assert_eq!(
        refused_type.status(),
        StatusCode::FORBIDDEN,
        "a temporal create of a forbidden type must be refused"
    );

    let scope_policies = r#"
[[policy]]
id = "madrid-only"
priority = 100

[policy.condition]
users = ["writer"]
tenants = ["gardens"]
operations = ["write"]

[policy.access]
effect = "allow"

[policy.access.scope]
allowed = ["/Madrid/Gardens/#"]
"#;
    let scope_proxy = Proxy::start(&ProxySettings::new(&stack, scope_policies));
    let out_of_scope = r#"{
        "@context": "https://uri.etsi.org/ngsi-ld/v1/ngsi-ld-core-context.jsonld",
        "id": "urn:ngsi-ld:Garden:temporal-1",
        "type": "Garden",
        "scope": "/Barcelona/Parks/Guell",
        "note": [ { "type": "Property", "value": "seed", "observedAt": "2026-01-01T00:00:00Z" } ]
    }"#;
    let refused_scope = scope_proxy
        .post("/ngsi-ld/v1/temporal/entities")
        .header("NGSILD-Tenant", TENANT)
        .header("Content-Type", "application/ld+json")
        .bearer_auth(token("writer"))
        .body(out_of_scope)
        .send()
        .expect("the proxy should answer");
    assert_eq!(
        refused_scope.status(),
        StatusCode::FORBIDDEN,
        "a temporal create carrying an out-of-scope entity must be refused"
    );
}

/// Temporal write bounding is based on request-time membership, not
/// Under an absolute time restriction, an in-window request is forwarded even if its instances carry
/// `observedAt` outside the window: write bounding is request-time membership, not per-instance
/// timestamp inspection.
#[test]
fn a_temporal_write_under_an_in_window_restriction_forwards_out_of_window_instances() {
    let stack = require_stack!();
    let now = Timestamp::now();
    let start = now
        .checked_sub(SignedDuration::from_hours(1))
        .expect("an hour ago is representable")
        .to_string();
    let end = now
        .checked_add(SignedDuration::from_hours(1))
        .expect("an hour ahead is representable")
        .to_string();

    let policy = format!(
        r#"
[[policy]]
id = "in-window"
priority = 100

[policy.condition]
users = ["writer"]
tenants = ["gardens"]
operations = ["write"]

[policy.access]
effect = "allow"

[policy.access.time]
type = "absolute"
start = "{start}"
end = "{end}"
"#
    );

    let origin = Origin::serving("application/json", r#"{"id":"urn:ngsi-ld:Vehicle:1"}"#);
    let settings = ProxySettings {
        upstream: origin.address(),
        ..ProxySettings::new(&stack, &policy)
    };
    let proxy = Proxy::start(&settings);

    let body = r#"{
        "@context": "https://uri.etsi.org/ngsi-ld/v1/ngsi-ld-core-context.jsonld",
        "id": "urn:ngsi-ld:Vehicle:temporal-old",
        "type": "Vehicle",
        "speed": [ { "type": "Property", "value": 50, "observedAt": "2020-01-01T00:00:00Z" } ]
    }"#;

    let response = proxy
        .post("/ngsi-ld/v1/temporal/entities")
        .header("NGSILD-Tenant", TENANT)
        .header("Content-Type", "application/ld+json")
        .bearer_auth(token("writer"))
        .body(body)
        .send()
        .expect("the proxy should answer");
    assert!(response.status().is_success(), "in-window write should be accepted: {}", response.status());
    assert!(origin.last_request().is_some(), "in-window write must be forwarded to broker");
}

/// A temporal write attempted outside the allowed absolute window is refused with 403.
#[test]
fn a_temporal_write_outside_an_absolute_window_is_refused() {
    let stack = require_stack!();
    let policy = r#"
[[policy]]
id = "past-window"
priority = 100

[policy.condition]
users = ["writer"]
tenants = ["gardens"]
operations = ["write"]

[policy.access]
effect = "allow"

[policy.access.time]
type = "absolute"
start = "2020-01-01T00:00:00Z"
end = "2020-02-01T00:00:00Z"
"#;
    let settings = ProxySettings {
        upstream: address("http://unused.test"),
        ..ProxySettings::new(&stack, policy)
    };
    let proxy = Proxy::start(&settings);

    let body = r#"{
        "@context": "https://uri.etsi.org/ngsi-ld/v1/ngsi-ld-core-context.jsonld",
        "id": "urn:ngsi-ld:Vehicle:temporal-past",
        "type": "Vehicle",
        "speed": [ { "type": "Property", "value": 50, "observedAt": "2020-01-15T00:00:00Z" } ]
    }"#;

    let refused = proxy
        .post("/ngsi-ld/v1/temporal/entities")
        .header("NGSILD-Tenant", TENANT)
        .header("Content-Type", "application/ld+json")
        .bearer_auth(token("writer"))
        .body(body)
        .send()
        .expect("the proxy should answer");
    assert_eq!(refused.status(), StatusCode::FORBIDDEN, "out-of-window write must be refused with 403");
}

/// Under a relative time restriction, entity writes are refused as Unenforceable.
#[test]
fn a_temporal_write_under_a_relative_time_restriction_is_refused() {
    let stack = require_stack!();
    let policy = r#"
[[policy]]
id = "relative-window"
priority = 100

[policy.condition]
users = ["writer"]
tenants = ["gardens"]
operations = ["write"]

[policy.access]
effect = "allow"

[policy.access.time]
type = "relative"
duration = "PT1H"
direction = "past"
"#;
    let settings = ProxySettings {
        upstream: address("http://unused.test"),
        ..ProxySettings::new(&stack, policy)
    };
    let proxy = Proxy::start(&settings);

    let body = r#"{
        "@context": "https://uri.etsi.org/ngsi-ld/v1/ngsi-ld-core-context.jsonld",
        "id": "urn:ngsi-ld:Vehicle:temporal-rel",
        "type": "Vehicle",
        "speed": [ { "type": "Property", "value": 50, "observedAt": "2026-01-01T00:00:00Z" } ]
    }"#;

    let refused = proxy
        .post("/ngsi-ld/v1/temporal/entities")
        .header("NGSILD-Tenant", TENANT)
        .header("Content-Type", "application/ld+json")
        .bearer_auth(token("writer"))
        .body(body)
        .send()
        .expect("the proxy should answer");
    assert_eq!(
        refused.status(),
        StatusCode::FORBIDDEN,
        "write under relative time restriction must be refused with 403 (Unenforceable)"
    );
}
