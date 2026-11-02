//! Ways around a restriction that the layers close, end to end.
//!
//! Each asks for something a restriction withholds by a route the restriction's own check did not
//! cover: ranking by a hidden attribute, mapping a hidden `GeoProperty` to the answer's geometry,
//! dating instances by when they were written, destroying a whole entity the caller sees only part
//! of, reusing an entity map built for somebody else, overwriting an entity stored under another
//! type, and an answer carrying an entity of two types. An origin stands in for the broker, so a
//! refusal shows as a request that never arrived.

use libra_test_harness::{identity::token, origin::Origin, proxy::Proxy, proxy_settings::ProxySettings, stack::Endpoints};
use reqwest::{Method, StatusCode, blocking::Response};

/// The writer reads and writes, with `location` hidden.
const OMIT_LOCATION: &str = r#"
[[policy]]
id = "omit-location"
priority = 100

[policy.condition]
users = ["writer"]

[policy.access]
effect = "allow"

[policy.access.attribute]
action = "omit"
attributes = ["location"]
"#;

/// The writer reads and writes vehicles only.
const VEHICLES: &str = r#"
[[policy]]
id = "vehicles"
priority = 100

[policy.condition]
users = ["writer"]

[policy.access]
effect = "allow"

[policy.access.entity-type]
allowed = ["Vehicle"]
"#;

/// The writer reads the last day only.
const LAST_DAY: &str = r#"
[[policy]]
id = "last-day"
priority = 100

[policy.condition]
users = ["writer"]

[policy.access]
effect = "allow"

[policy.access.time]
type = "relative"
duration = "PT24H"
direction = "past"
"#;

fn proxy(stack: &Endpoints, origin: &Origin, policies: &str) -> Proxy {
    Proxy::start(&ProxySettings {
        upstream: origin.address(),
        ..ProxySettings::new(stack, policies)
    })
}

fn status(proxy: &Proxy, method: Method, path: &str, body: Option<&str>) -> StatusCode {
    answer(proxy, method, path, body).0
}

/// Sends a request as the writer and reports the status and the body of the answer.
fn answer(proxy: &Proxy, method: Method, path: &str, body: Option<&str>) -> (StatusCode, String) {
    let mut request = proxy.request(method, path).bearer_auth(token("writer"));
    if let Some(body) = body {
        request = request.header("Content-Type", "application/json").body(body.to_owned());
    }

    let response = request.send().expect("the proxy should answer");
    (response.status(), response.text().unwrap_or_default())
}

#[test]
fn ordering_by_a_hidden_attribute_is_refused() {
    let stack = require_stack!();
    let origin = Origin::serving("application/json", "[]");
    let proxy = proxy(&stack, &origin, OMIT_LOCATION);

    // NGSI-LD clause 4.23.3: ranking by distance from a chosen point locates the hidden position,
    // and ranking by the attribute itself orders entities by its hidden value.
    for path in [
        "/ngsi-ld/v1/entities?type=Vehicle&orderBy=location;dist-asc&orderFrom=%5B8,40%5D",
        "/ngsi-ld/v1/entities?type=Vehicle&orderBy=location",
    ] {
        assert_eq!(status(&proxy, Method::GET, path, None), StatusCode::FORBIDDEN, "{path}");
        assert!(origin.last_request().is_none(), "{path}");
    }
}

#[test]
fn a_hidden_geometry_property_is_refused() {
    let stack = require_stack!();
    let origin = Origin::serving("application/geo+json", "{}");
    let proxy = proxy(&stack, &origin, OMIT_LOCATION);

    let path = "/ngsi-ld/v1/entities?type=Vehicle&geometryProperty=location";

    assert_eq!(status(&proxy, Method::GET, path, None), StatusCode::FORBIDDEN);
    assert!(origin.last_request().is_none());
}

#[test]
fn an_omit_restricted_caller_cannot_delete_a_whole_entity() {
    let stack = require_stack!();
    let origin = Origin::serving("application/json", "{}");
    let proxy = proxy(&stack, &origin, OMIT_LOCATION);

    // The entity's `location` would go with it, and the caller may not even see it.
    assert_eq!(
        status(&proxy, Method::DELETE, "/ngsi-ld/v1/entities/urn:ngsi-ld:Vehicle:1", None),
        StatusCode::FORBIDDEN
    );
    assert!(origin.last_request().is_none());
}

#[test]
fn a_temporal_read_by_creation_time_is_refused_under_a_time_restriction() {
    let stack = require_stack!();
    let origin = Origin::serving("application/json", "[]");
    let proxy = proxy(&stack, &origin, LAST_DAY);

    // Instances observed years ago but written today would otherwise fall inside the window.
    let path = "/ngsi-ld/v1/temporal/entities?type=Vehicle&timerel=after&timeAt=2020-01-01T00:00:00Z&timeproperty=createdAt";

    assert_eq!(status(&proxy, Method::GET, path, None), StatusCode::FORBIDDEN);
    assert!(origin.last_request().is_none());
}

#[test]
fn a_type_restricted_caller_cannot_page_through_an_entity_map() {
    let stack = require_stack!();
    let origin = Origin::serving("application/json", "[]");
    let proxy = proxy(&stack, &origin, VEHICLES);

    let response = proxy
        .get("/ngsi-ld/v1/entities?type=Vehicle")
        .header("NGSILD-EntityMap", "urn:ngsi-ld:EntityMap:someone-elses")
        .bearer_auth(token("writer"))
        .send()
        .expect("the proxy should answer");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(origin.last_request().is_none());
}

#[test]
fn a_batch_update_cannot_overwrite_an_entity_of_a_forbidden_type() {
    let stack = require_stack!();
    // Whatever is asked, the origin answers with an entity stored as `Secret`, as the broker would
    // answer the pre-flight for the entity the batch names.
    // The identifier does not spell the type, so a refusal that names `Secret` can only have read it
    // from the stored entity.
    let origin = Origin::serving("application/ld+json", r#"{"id":"urn:ngsi-ld:Thing:1","type":"Secret"}"#);
    let proxy = proxy(&stack, &origin, VEHICLES);

    let body = r#"[{"id":"urn:ngsi-ld:Thing:1","type":"Vehicle","speed":{"type":"Property","value":1}}]"#;

    let (status, refusal) = answer(&proxy, Method::POST, "/ngsi-ld/v1/entityOperations/update", Some(body));
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(!refusal.contains("Secret"), "the refusal names the stored type: {refusal}");
    let last = origin.last_request().expect("the pre-flight reached the broker");
    assert_eq!(last.method, "GET", "only the pre-flight did; the update did not");
}

#[test]
fn a_broker_answer_with_an_entity_of_two_types_is_judged_per_entity() {
    let stack = require_stack!();
    let answer = r#"[{"id":"urn:ngsi-ld:Vehicle:1","type":"Vehicle"},{"id":"urn:ngsi-ld:Vehicle:2","type":["Vehicle","Secret"]}]"#;
    let origin = Origin::serving("application/json", answer);
    let proxy = proxy(&stack, &origin, VEHICLES);

    let body = proxy
        .get("/ngsi-ld/v1/entities?type=Vehicle")
        .bearer_auth(token("writer"))
        .send()
        .and_then(Response::text)
        .expect("the proxy should answer");

    assert!(body.contains("urn:ngsi-ld:Vehicle:1"), "{body}");
    assert!(!body.contains("urn:ngsi-ld:Vehicle:2"), "an entity that is also a Secret is withheld: {body}");
}
