//! Linked Entity Retrieval (`join`) enforcement.
//!
//! NGSI-LD 4.5.23 specifies Linked Entity Retrieval (`join=inline`/`join=flat`, `joinLevel`, and
//! `{...}` linked-entity terms in projections and in `q`). Linked entities are of whatever type and
//! scope a Relationship points at, so a restricted caller's join answer is judged linked entity by
//! linked entity on the way back: what the restriction covers is shown, the rest is withheld, and the
//! Relationship naming a withheld entity stays.
//!
//! The answers here are the broker's own. Scorpio follows a Relationship only when it carries an
//! `objectType` and the request names a `joinLevel`, so the seeded Relationships are annotated and
//! every join names a level. What cannot be judged is still refused: a join in `keyValues` inline, a
//! projection that removes the member a linked entity is judged by, and anything linked in a
//! subscription, whose notifications go straight from the broker to the endpoint.

use crate::parity::harness::{direct_get_raw, proxied_get_raw, unique_tenant};
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

/// The core context every seeded entity is written under.
const CORE_CONTEXT: &str = "https://uri.etsi.org/ngsi-ld/v1/ngsi-ld-core-context.jsonld";

/// The `[policy.access]` blocks that narrow a caller, one per enforcement layer, by name.
const RESTRICTIONS: [(&str, &str); 3] = [
    ("attribute", ATTRIBUTE_RESTRICTION),
    ("entity type", TYPE_RESTRICTION),
    ("scope", SCOPE_RESTRICTION),
];

/// Hides `location` on every entity of the answer.
const ATTRIBUTE_RESTRICTION: &str = "[policy.access.attribute]\naction = \"omit\"\nattributes = [\"location\"]";

/// Allows vehicles and car parks, not buildings.
const TYPE_RESTRICTION: &str = "[policy.access.entity-type]\nallowed = [\"Vehicle\", \"OffStreetParking\"]";

/// Allows Madrid's gardens, not Berlin.
const SCOPE_RESTRICTION: &str = "[policy.access.scope]\nallowed = [\"/Madrid/Gardens/#\"]";

/// The entities one test seeds: a vehicle and the three entities its Relationships point at.
struct Fleet {
    tenant: String,
    vehicle: String,
    /// An `OffStreetParking` in `/Berlin/Centre`: outside the scope restriction.
    berlin: String,
    /// An `OffStreetParking` in `/Madrid/Gardens/Sol`: inside every restriction.
    madrid: String,
    /// A `Building` in `/Madrid/Gardens/Depot`: outside the type restriction.
    building: String,
}

impl Fleet {
    /// Seeds the fleet in a tenant of its own.
    fn seed(stack: &Endpoints, prefix: &str) -> Self {
        let fleet = Self {
            tenant: unique_tenant(prefix),
            vehicle: unique_id("Vehicle"),
            berlin: unique_id("OffStreetParking"),
            madrid: unique_id("OffStreetParking"),
            building: unique_id("Building"),
        };

        fleet.place(stack, &fleet.berlin, "OffStreetParking", "/Berlin/Centre");
        fleet.place(stack, &fleet.madrid, "OffStreetParking", "/Madrid/Gardens/Sol");
        fleet.place(stack, &fleet.building, "Building", "/Madrid/Gardens/Depot");

        let relationship = |object: &str, object_type: &str| json!({ "type": "Relationship", "object": object, "objectType": object_type });
        create(
            stack,
            Some(&fleet.tenant),
            &json!({
                "@context": CORE_CONTEXT,
                "id": fleet.vehicle,
                "type": "Vehicle",
                "scope": "/Madrid/Gardens/Fleet",
                "speed": { "type": "Property", "value": 42 },
                "location": { "type": "GeoProperty", "value": { "type": "Point", "coordinates": [-3.7, 40.4] } },
                "isParked": relationship(&fleet.berlin, "OffStreetParking"),
                "parkedBefore": relationship(&fleet.madrid, "OffStreetParking"),
                "storedIn": relationship(&fleet.building, "Building")
            }),
        );

        fleet
    }

    /// Seeds one linked entity.
    fn place(&self, stack: &Endpoints, id: &str, entity_type: &str, scope: &str) {
        create(
            stack,
            Some(&self.tenant),
            &json!({
                "@context": CORE_CONTEXT,
                "id": id,
                "type": entity_type,
                "scope": scope,
                "name": { "type": "Property", "value": "seeded" },
                "location": { "type": "GeoProperty", "value": { "type": "Point", "coordinates": [13.4, 52.5] } }
            }),
        );
    }

    /// Reads `path` through `proxy` as the writer, and parses the answer.
    fn read(&self, proxy: &Proxy, path: &str) -> (StatusCode, Value) {
        let response = proxy
            .get(path)
            .header("NGSILD-Tenant", &self.tenant)
            .bearer_auth(token("writer"))
            .send()
            .expect("proxy should answer");
        let status = response.status();
        let body = response.text().expect("the answer should be readable");

        (status, serde_json::from_str(&body).unwrap_or(Value::String(body)))
    }

    /// The vehicle of an answer, which is an array of entities.
    fn vehicle_in<'a>(&self, answer: &'a Value) -> &'a Value {
        entity(answer, &self.vehicle).unwrap_or_else(|| panic!("the vehicle should be in the answer: {answer}"))
    }
}

/// The entity with `id` in an answer array, if it is there.
fn entity<'a>(answer: &'a Value, id: &str) -> Option<&'a Value> {
    answer.as_array()?.iter().find(|entity| entity.get("id").and_then(Value::as_str) == Some(id))
}

/// The linked entity an inline answer nests under a Relationship, if it nests one.
fn linked<'a>(linking: &'a Value, relationship: &str) -> Option<&'a Value> {
    linking.get(relationship)?.get("entity")
}

/// A policy file allowing `writer` the operation in the tenant, narrowed by `restriction`.
fn policies(tenant: &str, operation: &str, restriction: &str) -> String {
    format!(
        r#"
[[policy]]
id = "narrowed"
priority = 100

[policy.condition]
users = ["writer"]
tenants = ["{tenant}"]
operations = ["{operation}"]

[policy.access]
effect = "allow"

{restriction}
"#
    )
}

/// Starts a proxy in front of the broker under the given policies.
fn broker_proxy(stack: &Endpoints, policies: &str) -> Proxy {
    Proxy::start(&ProxySettings::new(stack, policies))
}

/// Starts a proxy in front of `origin` under the given policies.
fn origin_proxy(stack: &Endpoints, origin: &Origin, policies: &str) -> Proxy {
    let settings = ProxySettings {
        upstream: origin.address(),
        ..ProxySettings::new(stack, policies)
    };

    Proxy::start(&settings)
}

#[test]
fn a_type_restricted_join_withholds_the_linked_entity_of_another_type() {
    let stack = require_stack!();
    let fleet = Fleet::seed(&stack, "join-type");
    let proxy = broker_proxy(&stack, &policies(&fleet.tenant, "read", TYPE_RESTRICTION));

    let (status, inline) = fleet.read(&proxy, "/ngsi-ld/v1/entities?type=Vehicle&join=inline&joinLevel=1");
    assert_eq!(status, StatusCode::OK, "{inline}");
    let vehicle = fleet.vehicle_in(&inline);
    assert_eq!(linked(vehicle, "storedIn"), None, "the linked Building is withheld: {vehicle}");
    assert_eq!(vehicle["storedIn"]["object"], fleet.building.as_str(), "the Relationship naming it stays");
    assert_eq!(
        linked(vehicle, "parkedBefore").and_then(|parking| parking.get("id")),
        Some(&json!(fleet.madrid))
    );

    let (status, flat) = fleet.read(&proxy, "/ngsi-ld/v1/entities?type=Vehicle&join=flat&joinLevel=1");
    assert_eq!(status, StatusCode::OK, "{flat}");
    assert!(entity(&flat, &fleet.building).is_none(), "the linked Building is withheld: {flat}");
    assert!(entity(&flat, &fleet.madrid).is_some(), "a linked car park is shown: {flat}");
    assert!(entity(&flat, &fleet.vehicle).is_some());
}

#[test]
fn a_scope_restricted_join_withholds_the_linked_entity_in_another_scope() {
    let stack = require_stack!();
    let fleet = Fleet::seed(&stack, "join-scope");
    let proxy = broker_proxy(&stack, &policies(&fleet.tenant, "read", SCOPE_RESTRICTION));

    let (status, inline) = fleet.read(&proxy, "/ngsi-ld/v1/entities?type=Vehicle&join=inline&joinLevel=1");
    assert_eq!(status, StatusCode::OK, "{inline}");
    let vehicle = fleet.vehicle_in(&inline);
    assert_eq!(linked(vehicle, "isParked"), None, "the car park in Berlin is withheld: {vehicle}");
    assert_eq!(vehicle["isParked"]["object"], fleet.berlin.as_str(), "the Relationship naming it stays");
    assert_eq!(
        linked(vehicle, "parkedBefore").and_then(|parking| parking.get("scope")),
        Some(&json!("/Madrid/Gardens/Sol"))
    );

    let (status, flat) = fleet.read(&proxy, "/ngsi-ld/v1/entities?type=Vehicle&join=flat&joinLevel=1");
    assert_eq!(status, StatusCode::OK, "{flat}");
    assert!(entity(&flat, &fleet.berlin).is_none(), "the car park in Berlin is withheld: {flat}");
    assert!(entity(&flat, &fleet.madrid).is_some(), "the car park in Madrid is shown: {flat}");
}

#[test]
fn an_attribute_restricted_join_hides_the_attribute_on_linked_entities_too() {
    let stack = require_stack!();
    let fleet = Fleet::seed(&stack, "join-attribute");
    let proxy = broker_proxy(&stack, &policies(&fleet.tenant, "read", ATTRIBUTE_RESTRICTION));

    let (status, inline) = fleet.read(&proxy, "/ngsi-ld/v1/entities?type=Vehicle&join=inline&joinLevel=1");
    assert_eq!(status, StatusCode::OK, "{inline}");
    let vehicle = fleet.vehicle_in(&inline);
    let parking = linked(vehicle, "isParked").unwrap_or_else(|| panic!("the linked car park is shown: {vehicle}"));
    assert_eq!(parking.get("location"), None, "{parking}");
    assert_eq!(parking["name"]["value"], "seeded");
    assert_eq!(vehicle.get("location"), None);

    let (status, flat) = fleet.read(&proxy, "/ngsi-ld/v1/entities?type=Vehicle&join=flat&joinLevel=1");
    assert_eq!(status, StatusCode::OK, "{flat}");
    let parking = entity(&flat, &fleet.berlin).unwrap_or_else(|| panic!("the linked car park is shown: {flat}"));
    assert_eq!(parking.get("location"), None, "{parking}");
}

#[test]
fn a_join_in_a_batch_query_body_is_judged_like_one_in_the_query_string() {
    let stack = require_stack!();
    let fleet = Fleet::seed(&stack, "join-body");
    let proxy = broker_proxy(&stack, &policies(&fleet.tenant, "read", SCOPE_RESTRICTION));

    let response = proxy
        .post("/ngsi-ld/v1/entityOperations/query")
        .header("NGSILD-Tenant", &fleet.tenant)
        .bearer_auth(token("writer"))
        .json(&json!({ "type": "Query", "entities": [{ "type": "Vehicle" }], "join": "flat", "joinLevel": 1 }))
        .send()
        .expect("proxy should answer");

    assert_eq!(response.status(), StatusCode::OK);
    let answer: Value = response.json().expect("the answer should be JSON");
    assert!(entity(&answer, &fleet.berlin).is_none(), "the car park in Berlin is withheld: {answer}");
    assert!(entity(&answer, &fleet.madrid).is_some(), "the car park in Madrid is shown: {answer}");
}

#[test]
fn an_unrestricted_join_answer_is_the_brokers_byte_for_byte() {
    let stack = require_stack!();
    let fleet = Fleet::seed(&stack, "join-parity");
    let proxy = broker_proxy(&stack, &policies(&fleet.tenant, "read", ""));
    let writer = token("writer");

    for path in [
        "/ngsi-ld/v1/entities?type=Vehicle&join=inline&joinLevel=1",
        "/ngsi-ld/v1/entities?type=Vehicle&join=flat&joinLevel=1",
    ] {
        let (direct_status, _, direct) = direct_get_raw(&stack, Some(&fleet.tenant), path, &[]);
        let (proxied_status, _, proxied) = proxied_get_raw(&proxy, Some(&fleet.tenant), Some(&writer), path, &[]);

        assert_eq!(proxied_status, direct_status, "{path}");
        assert_eq!(String::from_utf8_lossy(&proxied), String::from_utf8_lossy(&direct), "{path}");
    }
}

#[test]
fn a_join_whose_projection_removes_what_linked_entities_are_judged_by_is_refused() {
    let stack = require_stack!();
    let origin = Origin::serving("application/json", "[]");

    for (restriction, query) in [
        (TYPE_RESTRICTION, "type=Vehicle&join=inline&joinLevel=1&pick=id,isParked"),
        (TYPE_RESTRICTION, "type=Vehicle&join=flat&joinLevel=1&omit=type"),
        (SCOPE_RESTRICTION, "type=Vehicle&join=flat&joinLevel=1&omit=scope"),
    ] {
        let tenant = unique_tenant("join-projection");
        let proxy = origin_proxy(&stack, &origin, &policies(&tenant, "read", restriction));

        let response = proxy
            .get(&format!("/ngsi-ld/v1/entities?{query}"))
            .header("NGSILD-Tenant", &tenant)
            .bearer_auth(token("writer"))
            .send()
            .expect("proxy should answer");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{query}");
    }

    assert!(origin.last_request().is_none(), "a refused join must never reach the broker");
}

#[test]
fn a_join_no_answer_can_be_judged_against_is_refused_for_a_restricted_caller() {
    let stack = require_stack!();

    for (dimension, restriction) in RESTRICTIONS {
        let tenant = unique_tenant("join-refused");
        let origin = Origin::serving("application/json", r#"[{"id":"urn:ngsi-ld:Vehicle:1","type":"Vehicle"}]"#);
        let proxy = origin_proxy(&stack, &origin, &policies(&tenant, "read", restriction));

        for query in [
            "type=Vehicle&join=inline&joinLevel=1&options=keyValues",
            "type=Vehicle&join=deep",
            "type=Vehicle&joinLevel=2",
            "type=Vehicle&pick=id,type,scope,parkedIn%7Btype,scope,name%7D",
            // A linked `q` path is refused outright under a type or scope restriction; an
            // attribute restriction checks every name in it, and `location` is hidden.
            "type=Vehicle&q=parkedIn%7Blocation%7D==%22Downtown%22",
        ] {
            let response = proxy
                .get(&format!("/ngsi-ld/v1/entities?{query}"))
                .header("NGSILD-Tenant", &tenant)
                .bearer_auth(token("writer"))
                .send()
                .expect("proxy should answer");

            assert_eq!(response.status(), StatusCode::FORBIDDEN, "{dimension} restriction, {query}");
        }

        assert!(
            origin.last_request().is_none(),
            "{dimension} restriction: a refused join must never reach the broker"
        );
    }
}

/// `Query` bodies that each reach linked entities in a way no answer can be judged against.
fn unservable_query_bodies() -> [Value; 3] {
    [
        json!({ "type": "Query", "entities": [{ "type": "Vehicle" }], "joinLevel": 2 }),
        json!({ "type": "Query", "entities": [{ "type": "Vehicle" }], "pick": ["id", "type", "scope", "parkedIn{type,scope,name}"] }),
        // Refused under the attribute restriction because the path ends in the hidden `location`.
        json!({ "type": "Query", "entities": [{ "type": "Vehicle" }], "q": "parkedIn{location}==\"Downtown\"" }),
    ]
}

#[test]
fn an_unservable_join_in_a_batch_query_body_is_refused_for_a_restricted_caller() {
    let stack = require_stack!();

    for (dimension, restriction) in RESTRICTIONS {
        let tenant = unique_tenant("join-body-refused");
        let origin = Origin::serving("application/json", "[]");
        let proxy = origin_proxy(&stack, &origin, &policies(&tenant, "read", restriction));

        for body in unservable_query_bodies() {
            let response = proxy
                .post("/ngsi-ld/v1/entityOperations/query")
                .header("NGSILD-Tenant", &tenant)
                .bearer_auth(token("writer"))
                .json(&body)
                .send()
                .expect("proxy should answer");

            assert_eq!(response.status(), StatusCode::FORBIDDEN, "{dimension} restriction, {body}");
        }

        assert!(
            origin.last_request().is_none(),
            "{dimension} restriction: a refused batch query must never reach the broker"
        );
    }
}

/// Subscriptions that each ask for Linked Entity Retrieval in a different member.
fn subscriptions() -> [Value; 4] {
    let endpoint = json!({ "uri": "http://sink.test/notify" });

    [
        json!({ "notification": { "endpoint": endpoint, "join": "inline" } }),
        json!({ "notification": { "endpoint": endpoint, "joinLevel": 1 } }),
        json!({ "notification": { "endpoint": endpoint, "pick": ["parkedIn{name}"] } }),
        // Refused under the attribute restriction because the path ends in the hidden `location`.
        json!({ "q": "parkedIn{location}==\"Downtown\"", "notification": { "endpoint": endpoint } }),
    ]
    .map(|mut subscription| {
        if let Some(members) = subscription.as_object_mut() {
            members.insert("@context".to_owned(), json!(CORE_CONTEXT));
            members.insert("type".to_owned(), json!("Subscription"));
            members.insert("entities".to_owned(), json!([{ "type": "Vehicle" }]));
        }
        subscription
    })
}

/// A subscription asking for Linked Entity Retrieval is refused under every restriction. Its
/// notifications go straight from the broker to the endpoint, so a forwarded `notification.join`
/// delivered linked entities no layer ever saw.
#[test]
fn a_join_in_a_subscription_is_refused_for_a_restricted_caller() {
    let stack = require_stack!();

    for (dimension, restriction) in RESTRICTIONS {
        let tenant = unique_tenant("join-sub-refused");
        let origin = Origin::serving("application/json", r#"{"id":"urn:ngsi-ld:Subscription:1"}"#);
        let proxy = origin_proxy(&stack, &origin, &policies(&tenant, "write", restriction));

        for subscription in subscriptions() {
            let response = proxy
                .post("/ngsi-ld/v1/subscriptions")
                .header("NGSILD-Tenant", &tenant)
                .header("Content-Type", "application/ld+json")
                .bearer_auth(token("writer"))
                .json(&subscription)
                .send()
                .expect("proxy should answer");

            assert_eq!(response.status(), StatusCode::FORBIDDEN, "{dimension} restriction, {subscription}");
        }

        assert!(
            origin.last_request().is_none(),
            "{dimension} restriction: a refused subscription must never reach the broker"
        );
    }
}

/// A caller no policy narrows keeps Linked Entity Retrieval: the body reaches the broker unchanged.
#[test]
fn a_join_in_a_batch_query_body_reaches_the_broker_for_an_unrestricted_caller() {
    let stack = require_stack!();
    let tenant = unique_tenant("join-body-allowed");
    let origin = Origin::serving("application/json", "[]");
    let proxy = origin_proxy(&stack, &origin, &policies(&tenant, "read", ""));

    let response = proxy
        .post("/ngsi-ld/v1/entityOperations/query")
        .header("NGSILD-Tenant", &tenant)
        .bearer_auth(token("writer"))
        .json(&json!({ "type": "Query", "entities": [{ "type": "Vehicle" }], "join": "inline" }))
        .send()
        .expect("proxy should answer");

    assert!(
        response.status().is_success(),
        "an unrestricted batch query should be forwarded: {}",
        response.status()
    );

    let recorded = origin.last_request().expect("the batch query should reach the broker");
    let forwarded: Value = serde_json::from_str(&recorded.body).expect("the forwarded body should be JSON");
    assert_eq!(forwarded.get("join").and_then(Value::as_str), Some("inline"));
}
