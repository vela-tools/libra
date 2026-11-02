//! Subscription notifications and read-back leaks.
//!
//! Subscriptions cause the broker to push entity notifications out of band to a callback endpoint
//! that bypasses Libra. The tests here use a live [`NotificationSink`] to assert whether
//! out-of-band notifications are narrowed to the caller's attribute, scope, and type allows, and pin
//! whether reading back a subscription filters nested notification attribute lists.

use crate::{leak_surfaces::sink::NotificationSink, parity::harness::unique_tenant};
use libra_test_harness::{
    broker::{create, unique_id},
    identity::token,
    proxy::Proxy,
    proxy_settings::ProxySettings,
};
use reqwest::{
    StatusCode,
    blocking::{Client, Response},
};
use serde_json::{Value, json};
use std::time::Duration;

/// An attribute-restricted caller creating a subscription has the subscription narrowed so the
/// broker omits the hidden attribute when delivering notifications out of band.
#[test]
fn a_restricted_caller_cannot_subscribe_past_an_attribute_restriction() {
    let stack = require_stack!();
    let tenant = unique_tenant("sub-attr");
    let sink = NotificationSink::start();

    let policies = format!(
        r#"
[[policy]]
id = "write-omit-brand"
priority = 100

[policy.condition]
resources = ["entities", "temporal", "discovery", "subscriptions", "registrations", "registration-subscriptions", "entity-maps", "contexts"]
users = ["writer"]
tenants = ["{tenant}"]
operations = ["read", "write"]

[policy.access]
effect = "allow"

[policy.access.attribute]
action = "omit"
attributes = ["brand"]
"#
    );

    let proxy = Proxy::start(&ProxySettings::new(&stack, &policies));
    let sub_response = subscribe(&proxy, &tenant, &token("writer"), "Vehicle", &sink.endpoint_uri());
    assert!(
        sub_response.status().is_success(),
        "subscription creation failed with status: {}",
        sub_response.status()
    );

    let entity_id = unique_id("Vehicle");
    let entity = json!({
        "@context": "https://uri.etsi.org/ngsi-ld/v1/ngsi-ld-core-context.jsonld",
        "id": entity_id,
        "type": "Vehicle",
        "brand": { "type": "Property", "value": "Volvo" },
        "speed": { "type": "Property", "value": 75 }
    });

    create(&stack, Some(&tenant), &entity);

    let notification = sink
        .wait_for_notification(Duration::from_secs(5))
        .expect("broker should deliver a notification for the matching vehicle entity");

    let data = notification
        .get("data")
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .expect("notification should contain entity data");

    assert!(
        data.get("speed").is_some(),
        "allowed attribute 'speed' must be present in notification: {notification}"
    );
    assert!(
        data.get("brand").is_none(),
        "omitted attribute 'brand' must not be disclosed in out-of-band notification: {notification}"
    );
}

/// A scope-restricted caller has their restriction injected into the subscription's `scopeQ`, so the
/// broker never delivers notifications for entities outside the scope restriction.
#[test]
fn a_restricted_caller_cannot_subscribe_past_a_scope_restriction() {
    let stack = require_stack!();
    let tenant = unique_tenant("sub-scope");
    let sink = NotificationSink::start();

    let policies = format!(
        r#"
[[policy]]
id = "madrid-only"
priority = 100

[policy.condition]
resources = ["entities", "temporal", "discovery", "subscriptions", "registrations", "registration-subscriptions", "entity-maps", "contexts"]
users = ["writer"]
tenants = ["{tenant}"]
operations = ["read", "write"]

[policy.access]
effect = "allow"

[policy.access.scope]
allowed = ["/Madrid/Gardens/#"]
"#
    );

    let proxy = Proxy::start(&ProxySettings::new(&stack, &policies));
    let sub_response = subscribe(&proxy, &tenant, &token("writer"), "Garden", &sink.endpoint_uri());
    assert!(
        sub_response.status().is_success(),
        "subscription creation failed with status: {}",
        sub_response.status()
    );

    let out_id = unique_id("Garden");
    let out_of_scope = json!({
        "@context": "https://uri.etsi.org/ngsi-ld/v1/ngsi-ld-core-context.jsonld",
        "id": out_id,
        "type": "Garden",
        "scope": "/Barcelona/Parks/Guell",
        "name": { "type": "Property", "value": "Guell" }
    });
    create(&stack, Some(&tenant), &out_of_scope);

    let early_notification = sink.wait_for_notification(Duration::from_secs(2));
    assert!(
        early_notification.is_none(),
        "out-of-scope entity must not trigger notification: {early_notification:?}"
    );

    let in_id = unique_id("Garden");
    let in_scope = json!({
        "@context": "https://uri.etsi.org/ngsi-ld/v1/ngsi-ld-core-context.jsonld",
        "id": in_id,
        "type": "Garden",
        "scope": "/Madrid/Gardens/Retiro",
        "name": { "type": "Property", "value": "Retiro" }
    });
    create(&stack, Some(&tenant), &in_scope);

    let notification = sink
        .wait_for_notification(Duration::from_secs(5))
        .expect("in-scope entity must trigger notification");

    let data = notification
        .get("data")
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .expect("notification payload must contain entity");
    assert_eq!(
        data.get("id").and_then(Value::as_str),
        Some(in_id.as_str()),
        "notification should be for the in-scope entity"
    );
}

fn subscribe(proxy: &Proxy, tenant: &str, token: &str, entity_type: &str, endpoint_uri: &str) -> Response {
    let subscription = json!({
        "@context": "https://uri.etsi.org/ngsi-ld/v1/ngsi-ld-core-context.jsonld",
        "id": unique_id("Subscription"),
        "type": "Subscription",
        "entities": [ { "type": entity_type } ],
        "notification": {
            "endpoint": {
                "uri": endpoint_uri,
                "accept": "application/json"
            }
        }
    });

    proxy
        .post("/ngsi-ld/v1/subscriptions")
        .header("NGSILD-Tenant", tenant)
        .header("Content-Type", "application/ld+json")
        .bearer_auth(token)
        .json(&subscription)
        .send()
        .expect("the proxy should answer")
}

/// A type-restricted caller cannot create subscriptions selecting a forbidden type (refused 403),
/// preventing out-of-band notification leaks of forbidden types.
#[test]
fn a_restricted_caller_cannot_subscribe_past_a_type_restriction() {
    let stack = require_stack!();
    let tenant = unique_tenant("sub-type");
    let sink = NotificationSink::start();

    let policies = format!(
        r#"
[[policy]]
id = "vehicles-only"
priority = 100

[policy.condition]
resources = ["entities", "temporal", "discovery", "subscriptions", "registrations", "registration-subscriptions", "entity-maps", "contexts"]
users = ["writer"]
tenants = ["{tenant}"]
operations = ["read", "write"]

[policy.access]
effect = "allow"

[policy.access.entity-type]
allowed = ["Vehicle"]
"#
    );

    let proxy = Proxy::start(&ProxySettings::new(&stack, &policies));
    let writer_token = token("writer");

    let forbidden_response = subscribe(&proxy, &tenant, &writer_token, "Device", &sink.endpoint_uri());
    assert_eq!(
        forbidden_response.status(),
        StatusCode::FORBIDDEN,
        "subscription selecting forbidden type Device must be refused with 403"
    );

    let allowed_response = subscribe(&proxy, &tenant, &writer_token, "Vehicle", &sink.endpoint_uri());
    assert!(
        allowed_response.status().is_success(),
        "subscription for allowed Vehicle type should succeed: {}",
        allowed_response.status()
    );

    let device_id = unique_id("Device");
    create(
        &stack,
        Some(&tenant),
        &json!({
            "@context": "https://uri.etsi.org/ngsi-ld/v1/ngsi-ld-core-context.jsonld",
            "id": device_id,
            "type": "Device"
        }),
    );
    let early_notification = sink.wait_for_notification(Duration::from_secs(2));
    assert!(
        early_notification.is_none(),
        "forbidden type Device must not trigger notification: {early_notification:?}"
    );

    let vehicle_id = unique_id("Vehicle");
    create(
        &stack,
        Some(&tenant),
        &json!({
            "@context": "https://uri.etsi.org/ngsi-ld/v1/ngsi-ld-core-context.jsonld",
            "id": vehicle_id,
            "type": "Vehicle",
            "speed": { "type": "Property", "value": 60 }
        }),
    );
    let notification = sink
        .wait_for_notification(Duration::from_secs(5))
        .expect("allowed Vehicle entity must trigger notification");
    let data = notification
        .get("data")
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .expect("notification payload must contain entity");
    assert_eq!(
        data.get("id").and_then(Value::as_str),
        Some(vehicle_id.as_str()),
        "notification should be for the allowed vehicle entity"
    );
}

/// The broker answers a subscription read with any subscription of the tenant, whoever created it,
/// with its endpoint and the attributes it watches. Under a restriction, reading one is refused.
#[test]
fn a_restricted_caller_cannot_read_a_subscription_back() {
    let stack = require_stack!();
    let tenant = unique_tenant("sub-readback");
    let sub_id = unique_id("Subscription");

    let subscription = json!({
        "@context": "https://uri.etsi.org/ngsi-ld/v1/ngsi-ld-core-context.jsonld",
        "id": sub_id,
        "type": "Subscription",
        "entities": [ { "type": "Vehicle" } ],
        "notification": {
            "attributes": ["speed", "location"],
            "endpoint": {
                "uri": "http://sink.test/notify",
                "accept": "application/json"
            }
        }
    });

    let client = Client::new();
    let direct_create = client
        .post(stack.broker_endpoint("/ngsi-ld/v1/subscriptions"))
        .header("NGSILD-Tenant", &tenant)
        .header("Content-Type", "application/ld+json")
        .json(&subscription)
        .send()
        .expect("direct subscription seeding should succeed");
    assert!(
        direct_create.status().is_success(),
        "broker rejected subscription seeding: {}",
        direct_create.status()
    );

    let policies = format!(
        r#"
[[policy]]
id = "read-omit-location"
priority = 100

[policy.condition]
resources = ["entities", "temporal", "discovery", "subscriptions", "registrations", "registration-subscriptions", "entity-maps", "contexts"]
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
        .get(&format!("/ngsi-ld/v1/subscriptions/{sub_id}"))
        .header("NGSILD-Tenant", &tenant)
        .bearer_auth(token("writer"))
        .send()
        .expect("proxy should answer");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}
