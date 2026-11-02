//! Which resources a policy covers.
//!
//! A write allow does not cover everything the API exposes: registering a context source decides
//! where the broker sends other callers' requests, so it needs a policy that names it. These run
//! against an origin standing in for the broker, so a refusal is visible as a request that never
//! arrived.

use libra_test_harness::{identity::token, origin::Origin, proxy::Proxy, proxy_settings::ProxySettings, stack::Endpoints};
use reqwest::{Method, StatusCode, blocking::Response};

/// The writer may read and write, naming no resources.
const ENTITY_WRITERS: &str = r#"
[[policy]]
id = "entity-writers"
priority = 100

[policy.condition]
users = ["writer"]

[policy.access]
effect = "allow"
"#;

/// The writer may write registrations; the reader may only read them.
const REGISTRARS: &str = r#"
[[policy]]
id = "registrars"
priority = 100

[policy.condition]
users = ["writer"]
resources = ["registrations"]

[policy.access]
effect = "allow"

[[policy]]
id = "registration-readers"
priority = 100

[policy.condition]
users = ["reader"]
operations = ["read"]
resources = ["registrations"]

[policy.access]
effect = "allow"
"#;

/// The writer may read `/info`.
const INFO_READERS: &str = r#"
[[policy]]
id = "info-readers"
priority = 100

[policy.condition]
users = ["writer"]
operations = ["read"]
resources = ["info"]

[policy.access]
effect = "allow"
"#;

/// A registration whose source needs a credential.
const REGISTRATION: &str = r#"[{"id":"urn:ngsi-ld:ContextSourceRegistration:1","type":"ContextSourceRegistration","endpoint":"http://source.test","contextSourceInfo":[{"key":"Authorization","value":"Bearer source-secret"}]}]"#;

fn proxy_to(stack: &Endpoints, origin: &Origin, policies: &str) -> Proxy {
    Proxy::start(&ProxySettings {
        upstream: origin.address(),
        ..ProxySettings::new(stack, policies)
    })
}

fn send(proxy: &Proxy, method: Method, path: &str, user: &str) -> StatusCode {
    proxy
        .request(method, path)
        .header("Content-Type", "application/json")
        .bearer_auth(token(user))
        .body("{}")
        .send()
        .expect("the proxy should answer")
        .status()
}

#[test]
fn a_write_allow_naming_no_resources_cannot_create_a_registration() {
    let stack = require_stack!();
    let origin = Origin::serving("application/json", "{}");
    let proxy = proxy_to(&stack, &origin, ENTITY_WRITERS);

    assert_eq!(send(&proxy, Method::POST, "/ngsi-ld/v1/csourceRegistrations", "writer"), StatusCode::FORBIDDEN);
    assert!(origin.last_request().is_none(), "nothing reaches the broker");
}

#[test]
fn a_write_allow_naming_registrations_creates_one() {
    let stack = require_stack!();
    let origin = Origin::serving("application/json", "{}");
    let proxy = proxy_to(&stack, &origin, REGISTRARS);

    assert!(send(&proxy, Method::POST, "/ngsi-ld/v1/csourceRegistrations", "writer").is_success());
    assert!(origin.last_request().is_some());
}

#[test]
fn a_write_allow_cannot_evict_a_hosted_context() {
    let stack = require_stack!();
    let origin = Origin::serving("application/json", "{}");
    let proxy = proxy_to(&stack, &origin, ENTITY_WRITERS);

    // NGSI-LD clause 5.13.5: the broker's context cache is shared by every tenant.
    let status = send(&proxy, Method::DELETE, "/ngsi-ld/v1/jsonldContexts/urn:context:1?reload=true", "writer");

    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(origin.last_request().is_none());
}

#[test]
fn the_source_identity_is_served_only_to_a_policy_naming_info() {
    let stack = require_stack!();
    let origin = Origin::serving("application/json", "{}");
    let named = proxy_to(&stack, &origin, INFO_READERS);
    let unnamed = proxy_to(&stack, &origin, ENTITY_WRITERS);

    assert!(send(&named, Method::GET, "/ngsi-ld/v1/info/sourceIdentity", "writer").is_success());
    assert_eq!(send(&unnamed, Method::GET, "/ngsi-ld/v1/info/sourceIdentity", "writer"), StatusCode::FORBIDDEN);
}

#[test]
fn a_snapshot_request_is_refused_without_a_policy_naming_snapshots() {
    let stack = require_stack!();
    let origin = Origin::serving("application/json", "{}");
    let proxy = proxy_to(&stack, &origin, ENTITY_WRITERS);

    assert_eq!(send(&proxy, Method::POST, "/ngsi-ld/v1/snapshots", "writer"), StatusCode::FORBIDDEN);
    assert!(origin.last_request().is_none());
}

#[test]
fn a_registration_reader_who_may_not_write_them_does_not_see_context_source_info() {
    let stack = require_stack!();
    let origin = Origin::serving("application/json", REGISTRATION);
    let proxy = proxy_to(&stack, &origin, REGISTRARS);

    for path in [
        "/ngsi-ld/v1/csourceRegistrations?type=Vehicle",
        "/ngsi-ld/v1/csourceRegistrations/urn:ngsi-ld:ContextSourceRegistration:1",
    ] {
        let body = proxy
            .get(path)
            .bearer_auth(token("reader"))
            .send()
            .and_then(Response::text)
            .expect("the proxy should answer");

        assert!(!body.contains("source-secret"), "{path}: {body}");
        assert!(body.contains("http://source.test"), "{path}: the rest of the registration is shown");
    }
}

#[test]
fn a_registration_writer_sees_context_source_info() {
    let stack = require_stack!();
    let origin = Origin::serving("application/json", REGISTRATION);
    let proxy = proxy_to(&stack, &origin, REGISTRARS);

    let body = proxy
        .get("/ngsi-ld/v1/csourceRegistrations?type=Vehicle")
        .bearer_auth(token("writer"))
        .send()
        .and_then(Response::text)
        .expect("the proxy should answer");

    assert!(body.contains("source-secret"));
}
