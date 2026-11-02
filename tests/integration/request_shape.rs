//! Requests whose shape two readers could take apart differently.
//!
//! Each of these is a request Libra would judge one way and a broker could act on another: a member
//! written twice, a body nested past what anything here walks, a path segment a server cuts short,
//! a header asking for another method. They are refused before anything reaches the broker, which
//! an origin standing in for it shows.

use libra_test_harness::{identity::token, origin::Origin, proxy::Proxy, proxy_settings::ProxySettings, stack::Endpoints};
use reqwest::{StatusCode, blocking::Body};

/// The writer may read and write entities.
const WRITERS: &str = r#"
[[policy]]
id = "writers"
priority = 100

[policy.condition]
users = ["writer"]

[policy.access]
effect = "allow"
"#;

fn proxy_to(stack: &Endpoints, origin: &Origin) -> Proxy {
    Proxy::start(&ProxySettings {
        upstream: origin.address(),
        ..ProxySettings::new(stack, WRITERS)
    })
}

fn create(proxy: &Proxy, body: impl Into<Body>) -> StatusCode {
    proxy
        .post("/ngsi-ld/v1/entities")
        .header("Content-Type", "application/json")
        .bearer_auth(token("writer"))
        .body(body)
        .send()
        .expect("the proxy should answer")
        .status()
}

#[test]
fn a_body_repeating_the_type_member_is_refused() {
    let stack = require_stack!();
    let origin = Origin::serving("application/json", "{}");
    let proxy = proxy_to(&stack, &origin);

    // RFC 8259 section 4 leaves a repeated name to each parser: Libra could check one `type` while
    // the broker stores the other.
    let status = create(&proxy, r#"{"id":"urn:ngsi-ld:Vehicle:1","type":"Secret","type":"Vehicle"}"#);

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(origin.last_request().is_none());
}

#[test]
fn a_deeply_nested_body_is_refused_and_the_proxy_keeps_serving() {
    let stack = require_stack!();
    let origin = Origin::serving("application/json", "{}");
    let proxy = proxy_to(&stack, &origin);

    let nested = format!("{}{}", "[".repeat(200_000), "]".repeat(200_000));

    assert_eq!(create(&proxy, nested), StatusCode::BAD_REQUEST);
    assert!(origin.last_request().is_none());
    assert!(
        create(&proxy, r#"{"id":"urn:ngsi-ld:Vehicle:1","type":"Vehicle"}"#).is_success(),
        "the process is still there to answer the next request"
    );
}

#[test]
fn an_unrestricted_body_reaches_the_broker_byte_for_byte() {
    let stack = require_stack!();
    let origin = Origin::serving("application/json", "{}");
    let proxy = proxy_to(&stack, &origin);

    // Members out of alphabetical order, and numbers no `f64` holds as written.
    let body = r#"{"type":"Vehicle","id":"urn:ngsi-ld:Vehicle:1","speed":{"type":"Property","value":1.0},"odometer":{"type":"Property","value":12345678901234567890123}}"#;

    assert!(create(&proxy, body).is_success());

    let forwarded = origin.last_request().expect("the request should have reached the broker");
    assert_eq!(forwarded.body, body);
}

#[test]
fn a_method_override_header_is_refused() {
    let stack = require_stack!();
    let origin = Origin::serving("application/json", "{}");
    let proxy = proxy_to(&stack, &origin);

    let response = proxy
        .get("/ngsi-ld/v1/entities?type=Vehicle")
        .header("X-HTTP-Method-Override", "DELETE")
        .bearer_auth(token("writer"))
        .send()
        .expect("the proxy should answer");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(origin.last_request().is_none());
}

#[test]
fn a_path_segment_a_server_could_cut_short_is_refused() {
    let stack = require_stack!();
    let origin = Origin::serving("application/json", "{}");
    let proxy = proxy_to(&stack, &origin);

    for path in [
        "/ngsi-ld/v1/entities/urn:ngsi-ld:Vehicle:1;jsessionid=x",
        "/ngsi-ld/v1/entities/urn:ngsi-ld:Vehicle:1%00.json",
        "/ngsi-ld/v1/entities//urn:ngsi-ld:Vehicle:1",
    ] {
        let response = proxy.get(path).bearer_auth(token("writer")).send().expect("the proxy should answer");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{path}");
    }
    assert!(origin.last_request().is_none());
}

#[test]
fn two_content_types_are_refused() {
    let stack = require_stack!();
    let origin = Origin::serving("application/json", "{}");
    let proxy = proxy_to(&stack, &origin);

    let response = proxy
        .post("/ngsi-ld/v1/entities")
        .header("Content-Type", "application/json")
        .header("Content-Type", "application/ld+json")
        .bearer_auth(token("writer"))
        .body(r#"{"id":"urn:ngsi-ld:Vehicle:1","type":"Vehicle"}"#)
        .send()
        .expect("the proxy should answer");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(origin.last_request().is_none());
}

#[test]
fn an_anonymous_request_naming_no_tenant_is_refused_when_the_deployment_authenticates() {
    let stack = require_stack!();
    let origin = Origin::serving("application/json", "{}");
    let anyone = r#"
[[policy]]
id = "anyone-reads"
priority = 100

[policy.condition]
operations = ["read"]

[policy.access]
effect = "allow"
"#;
    let proxy = Proxy::start(&ProxySettings {
        upstream: origin.address(),
        tenant_policy: "authenticate",
        ..ProxySettings::new(&stack, anyone)
    });

    let response = proxy.get("/ngsi-ld/v1/entities?type=Vehicle").send().expect("the proxy should answer");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(origin.last_request().is_none());
}
