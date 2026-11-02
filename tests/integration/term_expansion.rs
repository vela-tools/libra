//! The reason the whole JSON-LD layer exists, exercised through the running proxy.
//!
//! In NGSI-LD an entity type is a term, and what it means depends on the `@context` the request
//! carried. A policy that matches the *string* `Vehicle` is therefore not enforcing anything a
//! caller cannot rename: Scorpio stores an entity under a caller-chosen IRI, and the same query
//! finds it by IRI and not by term.
//!
//! So the policy is compiled to IRIs against the context it declares, the request is expanded
//! against the context it declares, and the comparison is IRI against IRI. These tests send the
//! shapes that defeat the string version.
//!
//! The upstream here is an origin of the test's own rather than the broker. The claim being tested
//! is what Libra decides, and a broker that cannot itself reach a context served from a test
//! process would answer 503 to a request the proxy correctly allowed.

use libra_test_harness::{identity::token, origin::Origin, proxy::Proxy, proxy_settings::ProxySettings, stack::Endpoints};
use reqwest::StatusCode;

/// The deployment's context: `Car` and `Vehicle` are two spellings of one type.
const CONTEXT: &str = r#"{
    "@context": {
        "Vehicle": "https://uri.fiware.org/ns/data-models#Vehicle",
        "Car": "https://uri.fiware.org/ns/data-models#Vehicle",
        "speed": "https://uri.fiware.org/ns/data-models#speed"
    }
}"#;

/// The relation an NGSI-LD context link is carried under.
const LINK_RELATION: &str = "http://www.w3.org/ns/json-ld#context";

/// A proxy whose policy allows reads of `Vehicle`, written against the context `host` serves, and
/// which forwards to `host` as well.
fn proxy_for(stack: &Endpoints, host: &Origin) -> Proxy {
    let context = format!("{}/context.jsonld", host.url());
    let policies = format!(
        r#"
context = ["{context}"]

[[policy]]
id = "vehicles-only"
priority = 100

[policy.condition]
users = ["writer"]
operations = ["read"]
entity-types = ["Vehicle"]

[policy.access]
effect = "allow"
"#
    );
    let settings = ProxySettings {
        allowed_contexts: vec![host.address()],
        upstream: host.address(),
        ..ProxySettings::new(stack, &policies)
    };

    Proxy::start(&settings)
}

/// A proxy trusting `host` for contexts, forwarding to `upstream`, under a policy of the test's own.
fn proxy_with(stack: &Endpoints, host: &Origin, upstream: &Origin, policies: &str) -> Proxy {
    let settings = ProxySettings {
        allowed_contexts: vec![host.address()],
        upstream: upstream.address(),
        ..ProxySettings::new(stack, policies)
    };

    Proxy::start(&settings)
}

/// The `Link` header a request uses to name that same context.
fn context_link(host: &Origin) -> String {
    format!("<{}/context.jsonld>; rel=\"{LINK_RELATION}\"; type=\"application/ld+json\"", host.url())
}

#[test]
fn an_alias_for_the_restricted_type_is_still_the_restricted_type() {
    let stack = require_stack!();
    let host = Origin::serving("application/ld+json", CONTEXT);
    let proxy = proxy_for(&stack, &host);

    // The policy names `Vehicle`. The request names `Car`. Under this context they are one IRI,
    // and a policy engine comparing strings would have refused a request it was written to allow.
    let response = proxy
        .get("/ngsi-ld/v1/entities?type=Car")
        .header("Link", context_link(&host))
        .bearer_auth(token("writer"))
        .send()
        .expect("the proxy should answer");

    assert_eq!(response.status(), StatusCode::OK, "an alias of the allowed type is the allowed type");
}

#[test]
fn the_expanded_iri_reaches_the_same_decision_as_the_term() {
    let stack = require_stack!();
    let host = Origin::serving("application/ld+json", CONTEXT);
    let proxy = proxy_for(&stack, &host);

    // Legal wire form, and the form an attacker would use against a proxy that only ever sees
    // terms. It has to reach the same comparison.
    let response = proxy
        .get("/ngsi-ld/v1/entities?type=https%3A%2F%2Furi.fiware.org%2Fns%2Fdata-models%23Vehicle")
        .header("Link", context_link(&host))
        .bearer_auth(token("writer"))
        .send()
        .expect("the proxy should answer");

    assert_eq!(response.status(), StatusCode::OK);
}

#[test]
fn a_caller_supplied_context_cannot_rename_its_way_into_a_restriction() {
    let stack = require_stack!();
    let host = Origin::serving("application/ld+json", CONTEXT);
    let proxy = proxy_for(&stack, &host);

    // The caller redefines `Vehicle` as something of their own. The string matches the policy; the
    // IRI does not, and the IRI is what decides. Nothing allows the type they actually asked for.
    let attacker = Origin::serving("application/ld+json", r#"{ "@context": { "Vehicle": "https://attacker.test/ns#Vehicle" } }"#);
    let settings_link = format!("<{}/context.jsonld>; rel=\"{LINK_RELATION}\"; type=\"application/ld+json\"", attacker.url());

    let response = proxy
        .get("/ngsi-ld/v1/entities?type=Vehicle")
        .header("Link", settings_link)
        .bearer_auth(token("writer"))
        .send()
        .expect("the proxy should answer");

    assert_ne!(
        response.status(),
        StatusCode::OK,
        "a renamed type must not inherit the restriction written for the real one"
    );
}

#[test]
fn a_context_nothing_allows_fails_the_request_closed() {
    let stack = require_stack!();
    let host = Origin::serving("application/ld+json", CONTEXT);
    let proxy = proxy_for(&stack, &host);

    // Not on the allow list, so it is never fetched. Degrading to "match nothing" here would turn
    // an unreachable context into an authorization bypass, so the request fails instead.
    let response = proxy
        .get("/ngsi-ld/v1/entities?type=Vehicle")
        .header(
            "Link",
            format!("<https://elsewhere.test/context.jsonld>; rel=\"{LINK_RELATION}\"; type=\"application/ld+json\""),
        )
        .bearer_auth(token("writer"))
        .send()
        .expect("the proxy should answer");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[test]
fn a_type_no_policy_names_is_refused() {
    let stack = require_stack!();
    let host = Origin::serving("application/ld+json", CONTEXT);
    let proxy = proxy_for(&stack, &host);

    let response = proxy
        .get("/ngsi-ld/v1/entities?type=Building")
        .header("Link", context_link(&host))
        .bearer_auth(token("writer"))
        .send()
        .expect("the proxy should answer");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[test]
fn an_inline_body_context_decides_what_a_written_attribute_is() {
    let stack = require_stack!();
    let host = Origin::serving("application/ld+json", CONTEXT);
    let upstream = Origin::serving("application/json", "{}");
    let policies = format!(
        r#"
context = ["{host}/context.jsonld"]

[[policy]]
id = "speed-only"
priority = 100

[policy.condition]
users = ["writer"]
operations = ["write"]

[policy.access]
effect = "allow"

[policy.access.attribute]
action = "pick"
attributes = ["speed"]
"#,
        host = host.url()
    );
    let proxy = proxy_with(&stack, &host, &upstream, &policies);
    let bearer = token("writer");

    // The body names `velocity`, which nothing in the policy mentions. Its own `@context` makes it
    // the IRI the policy picked, so the write is of the attribute the policy allows under a name
    // the policy never saw.
    let allowed = proxy
        .post("/ngsi-ld/v1/entities")
        .header("Content-Type", "application/ld+json")
        .bearer_auth(&bearer)
        .body(
            r#"{"id":"urn:ngsi-ld:Vehicle:aliased","type":"Vehicle",
                "velocity":{"type":"Property","value":42},
                "@context":{"velocity":"https://uri.fiware.org/ns/data-models#speed"}}"#,
        )
        .send()
        .expect("the proxy should answer");
    assert!(
        allowed.status().is_success(),
        "an alias of an allowed attribute is that attribute: {}",
        allowed.status()
    );

    // And the reverse: a name the policy *does* mention, redefined by the caller to mean something
    // else. Under string matching this would have passed as the picked attribute.
    let refused = proxy
        .post("/ngsi-ld/v1/entities")
        .header("Content-Type", "application/ld+json")
        .bearer_auth(&bearer)
        .body(
            r#"{"id":"urn:ngsi-ld:Vehicle:renamed","type":"Vehicle",
                "speed":{"type":"Property","value":42},
                "@context":{"speed":"https://attacker.test/ns#speed"}}"#,
        )
        .send()
        .expect("the proxy should answer");
    assert_eq!(
        refused.status(),
        StatusCode::FORBIDDEN,
        "a renamed attribute must not inherit the restriction written for the real one"
    );
}

#[test]
fn an_attribute_restriction_survives_a_response_compacted_under_another_term() {
    let stack = require_stack!();
    let host = Origin::serving("application/ld+json", CONTEXT);
    // What a broker returns when the caller's context compacts the restricted IRI under a term the
    // policy never names. A filter matching response keys as strings finds nothing to remove here.
    let upstream = Origin::serving(
        "application/ld+json",
        r#"{"id":"urn:ngsi-ld:Vehicle:1","type":"Vehicle",
            "velocity":{"type":"Property","value":42},
            "brand":{"type":"Property","value":"Example"}}"#,
    );
    let policies = format!(
        r#"
context = ["{host}/context.jsonld"]

[[policy]]
id = "no-speed"
priority = 100

[policy.condition]
users = ["writer"]
operations = ["read"]

[policy.access]
effect = "allow"

[policy.access.attribute]
action = "omit"
attributes = ["speed"]
"#,
        host = host.url()
    );
    let proxy = proxy_with(&stack, &host, &upstream, &policies);

    let aliasing = Origin::serving(
        "application/ld+json",
        r#"{"@context":{"velocity":"https://uri.fiware.org/ns/data-models#speed"}}"#,
    );
    let settings = ProxySettings {
        allowed_contexts: vec![host.address(), aliasing.address()],
        upstream: upstream.address(),
        ..ProxySettings::new(&stack, &policies)
    };
    drop(proxy);
    let proxy = Proxy::start(&settings);

    let response = proxy
        .get("/ngsi-ld/v1/entities/urn:ngsi-ld:Vehicle:1")
        .header(
            "Link",
            format!("<{}/context.jsonld>; rel=\"{LINK_RELATION}\"; type=\"application/ld+json\"", aliasing.url()),
        )
        .bearer_auth(token("writer"))
        .send()
        .expect("the proxy should answer");

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().unwrap_or_default();
    assert!(
        !body.contains("velocity"),
        "the omitted attribute reached the caller under another name: {body}"
    );
    assert!(body.contains("brand"), "everything the policy did not omit should still be there: {body}");
}

/// A policy written against the core context alone, omitting `location`.
const NO_LOCATION: &str = r#"
[[policy]]
id = "no-location"
priority = 100

[policy.condition]
users = ["writer"]
operations = ["read"]

[policy.access]
effect = "allow"

[policy.access.attribute]
action = "omit"
attributes = ["location"]
"#;

/// An entity carrying `location` under the member name `member`, and an attribute nobody omits.
fn entity_with_location(member: &str) -> String {
    format!(
        r#"{{"id":"urn:ngsi-ld:Vehicle:1","type":"Vehicle",
            "{member}":{{"type":"GeoProperty","value":{{"type":"Point","coordinates":[0,0]}}}},
            "brand":{{"type":"Property","value":"Example"}}}}"#
    )
}

#[test]
fn a_context_writing_location_in_the_core_namespace_over_http_is_accepted_and_still_restricted() {
    let stack = require_stack!();
    // The Smart Data Models context maps `location` this way. Read literally it redefines a core
    // term and every request sending it would be refused; it names the core `location`.
    let host = Origin::serving("application/ld+json", r#"{"@context":{"location":"http://uri.etsi.org/ngsi-ld/location"}}"#);
    let upstream = Origin::serving("application/ld+json", &entity_with_location("location"));
    let proxy = proxy_with(&stack, &host, &upstream, NO_LOCATION);

    let response = proxy
        .get("/ngsi-ld/v1/entities/urn:ngsi-ld:Vehicle:1")
        .header("Link", context_link(&host))
        .bearer_auth(token("writer"))
        .send()
        .expect("the proxy should answer");

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().unwrap_or_default();
    assert!(!body.contains("location"), "the omitted core attribute reached the caller: {body}");
    assert!(body.contains("brand"), "everything the policy did not omit should still be there: {body}");
}

#[test]
fn a_core_attribute_named_by_its_iri_over_http_is_still_omitted() {
    let stack = require_stack!();
    let host = Origin::serving("application/ld+json", CONTEXT);
    // What a broker that stored the attribute under the caller's `http` spelling returns to a
    // caller that sent no context: the member is the full IRI.
    let upstream = Origin::serving("application/ld+json", &entity_with_location("http://uri.etsi.org/ngsi-ld/location"));
    let proxy = proxy_with(&stack, &host, &upstream, NO_LOCATION);

    let response = proxy
        .get("/ngsi-ld/v1/entities/urn:ngsi-ld:Vehicle:1")
        .bearer_auth(token("writer"))
        .send()
        .expect("the proxy should answer");

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().unwrap_or_default();
    assert!(!body.contains("location"), "the omitted core attribute reached the caller over http: {body}");
    assert!(body.contains("brand"), "everything the policy did not omit should still be there: {body}");
}
