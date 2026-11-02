//! How a request's `@context` arrives, and what happens when it cannot.
//!
//! There are exactly two channels: an inline `@context` in an `application/ld+json` body, and an
//! RFC 8288 `Link` header on an `application/json` request. Which one applies is decided by
//! the content type. Getting that decision wrong is not a parsing bug: it changes which context is
//! in force, and therefore what every name in the request means to the policy engine.
//!
//! The parsing itself is covered exhaustively by `libra-jsonld-context`'s own tests. What is here
//! is the same rules seen from outside, where the consequence of resolving the wrong context is an
//! authorization decision about the wrong thing.

use libra_test_harness::{
    identity::token,
    origin::{Origin, address},
    proxy::Proxy,
    proxy_settings::ProxySettings,
    stack::Endpoints,
};
use reqwest::StatusCode;

/// The relation an NGSI-LD context link is carried under.
const LINK_RELATION: &str = "http://www.w3.org/ns/json-ld#context";

/// The deployment's context. `Vehicle` is a data-model type, not a default-context one.
const CONTEXT: &str = r#"{
    "@context": {
        "Vehicle": "https://uri.fiware.org/ns/data-models#Vehicle",
        "speed": "https://uri.fiware.org/ns/data-models#speed"
    }
}"#;

/// Allows the writer reads and writes of `Vehicle`, written against the context below.
fn policies(context: &str) -> String {
    format!(
        r#"
context = ["{context}"]

[[policy]]
id = "vehicles"
priority = 100

[policy.condition]
users = ["writer"]
entity-types = ["Vehicle"]

[policy.access]
effect = "allow"

[[policy]]
id = "untyped-writes"
priority = 90

[policy.condition]
users = ["writer"]
operations = ["write"]

[policy.access]
effect = "allow"
"#
    )
}

/// A proxy that trusts `host` for contexts and forwards to `upstream`.
fn proxy_for(stack: &Endpoints, host: &Origin, upstream: &Origin) -> Proxy {
    let settings = ProxySettings {
        allowed_contexts: vec![host.address()],
        upstream: upstream.address(),
        ..ProxySettings::new(stack, &policies(&format!("{}/context.jsonld", host.url())))
    };

    Proxy::start(&settings)
}

/// The `Link` header naming the context `host` serves.
fn context_link(host: &Origin) -> String {
    format!("<{}/context.jsonld>; rel=\"{LINK_RELATION}\"; type=\"application/ld+json\"", host.url())
}

#[test]
fn a_plain_json_body_carrying_a_context_is_refused() {
    let stack = require_stack!();
    let host = Origin::serving("application/ld+json", CONTEXT);
    let upstream = Origin::serving("application/json", "{}");
    let proxy = proxy_for(&stack, &host, &upstream);

    // The broker refuses this combination, and Libra refuses it for the same reason: picking a
    // winner means guessing which context the broker would have used, and a guess here decides an
    // authorization question on the wrong data.
    let response = proxy
        .post("/ngsi-ld/v1/entities")
        .header("Content-Type", "application/json")
        .bearer_auth(token("writer"))
        .body(r#"{"id":"urn:ngsi-ld:Vehicle:1","type":"Vehicle","@context":{"Vehicle":"https://example.test/ns#Vehicle"}}"#)
        .send()
        .expect("the proxy should answer");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[test]
fn an_ld_json_request_carrying_a_context_link_is_refused() {
    let stack = require_stack!();
    let host = Origin::serving("application/ld+json", CONTEXT);
    let upstream = Origin::serving("application/json", "{}");
    let proxy = proxy_for(&stack, &host, &upstream);

    let response = proxy
        .post("/ngsi-ld/v1/entities")
        .header("Content-Type", "application/ld+json")
        .header("Link", context_link(&host))
        .bearer_auth(token("writer"))
        .body(r#"{"id":"urn:ngsi-ld:Vehicle:1","type":"Vehicle"}"#)
        .send()
        .expect("the proxy should answer");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[test]
fn media_type_parameters_do_not_change_the_channel() {
    let stack = require_stack!();
    let host = Origin::serving("application/ld+json", CONTEXT);
    let upstream = Origin::serving("application/json", "{}");
    let proxy = proxy_for(&stack, &host, &upstream);
    let bearer = token("writer");

    // Brokers disagree here. One truncates at `;` before comparing, one exact-matches the literal
    // and answers 415, and one compares the parsed media type including its parameters, which
    // handles a charset-bearing `application/json` under the *ld+json* rules and accepts an inline
    // context where the specification says it must be refused.
    let charset = proxy
        .post("/ngsi-ld/v1/entities")
        .header("Content-Type", "application/json; charset=UTF-8")
        .header("Link", context_link(&host))
        .bearer_auth(&bearer)
        .body(r#"{"id":"urn:ngsi-ld:Vehicle:1","type":"Vehicle"}"#)
        .send()
        .expect("the proxy should answer");
    assert!(
        charset.status().is_success(),
        "a charset parameter must not change which channel applies: {}",
        charset.status()
    );

    // And the same for the other channel: a parameter does not make a Link header legal.
    let refused = proxy
        .post("/ngsi-ld/v1/entities")
        .header("Content-Type", "application/ld+json; charset=UTF-8")
        .header("Link", context_link(&host))
        .bearer_auth(&bearer)
        .body(r#"{"id":"urn:ngsi-ld:Vehicle:1","type":"Vehicle"}"#)
        .send()
        .expect("the proxy should answer");
    assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
}

#[test]
fn a_context_link_folded_with_other_links_is_still_found() {
    let stack = require_stack!();
    let host = Origin::serving("application/ld+json", CONTEXT);
    let upstream = Origin::serving("application/json", "{}");
    let proxy = proxy_for(&stack, &host, &upstream);

    // RFC 8288 allows several link-values in one header, so a context link legitimately arrives
    // beside `next` and `prev`. Taking the first link-value, or ignoring `rel`, picks the wrong
    // context on a perfectly legal request.
    let folded = format!(
        "<https://example.test/page/2>; rel=\"next\", {}, <https://example.test/page/1>; rel=\"prev\"",
        context_link(&host)
    );

    let response = proxy
        .get("/ngsi-ld/v1/entities?type=Vehicle")
        .header("Link", folded)
        .bearer_auth(token("writer"))
        .send()
        .expect("the proxy should answer");

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "the context link is the one with the context relation, wherever it sits"
    );
}

#[test]
fn a_link_without_the_context_relation_is_not_a_context() {
    let stack = require_stack!();
    let host = Origin::serving("application/ld+json", CONTEXT);
    let upstream = Origin::serving("application/json", "{}");
    let proxy = proxy_for(&stack, &host, &upstream);

    // Same URL, wrong relation. The request resolves against the core context alone, so its
    // `Vehicle` is the default-context IRI and not the data-model one the policy was compiled
    // against, and nothing allows that.
    let response = proxy
        .get("/ngsi-ld/v1/entities?type=Vehicle")
        .header("Link", format!("<{}/context.jsonld>; rel=\"describedby\"", host.url()))
        .bearer_auth(token("writer"))
        .send()
        .expect("the proxy should answer");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[test]
fn a_context_that_is_not_a_json_document_fails_the_request_closed() {
    let stack = require_stack!();
    let host = Origin::serving("application/ld+json", CONTEXT);
    let upstream = Origin::serving("application/json", "{}");
    let proxy = proxy_for(&stack, &host, &upstream);

    // Allow-listed and reachable, but not a context. Reading that as "no context" would leave the
    // request expanding against the core context and matching whatever happens to line up.
    let rubbish = Origin::serving("text/plain", "this is not a context");
    let settings = ProxySettings {
        allowed_contexts: vec![host.address(), rubbish.address()],
        upstream: upstream.address(),
        ..ProxySettings::new(&stack, &policies(&format!("{}/context.jsonld", host.url())))
    };
    drop(proxy);
    let proxy = Proxy::start(&settings);

    let response = proxy
        .get("/ngsi-ld/v1/entities?type=Vehicle")
        .header(
            "Link",
            format!("<{}/context.jsonld>; rel=\"{LINK_RELATION}\"; type=\"application/ld+json\"", rubbish.url()),
        )
        .bearer_auth(token("writer"))
        .send()
        .expect("the proxy should answer");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[test]
fn a_preloaded_context_works_with_no_outbound_network_at_all() {
    let stack = require_stack!();
    let upstream = Origin::serving("application/json", "{}");
    let url = "https://example.test/fleet.jsonld";

    // The air-gapped deployment: fetching is off entirely, and the context the policies and the
    // clients share is read from disk at startup. Without this, `allow-remote = false` leaves only
    // the built-in core context and every policy written against a data model matches nothing.
    let settings = ProxySettings {
        allow_remote: false,
        preloaded_contexts: vec![(address(url), CONTEXT.to_owned())],
        upstream: upstream.address(),
        ..ProxySettings::new(&stack, &policies(url))
    };
    let proxy = Proxy::start(&settings);

    let allowed = proxy
        .get("/ngsi-ld/v1/entities?type=Vehicle")
        .header("Link", format!("<{url}>; rel=\"{LINK_RELATION}\"; type=\"application/ld+json\""))
        .bearer_auth(token("writer"))
        .send()
        .expect("the proxy should answer");
    assert_eq!(allowed.status(), StatusCode::OK, "a preloaded context needs no allow-list entry and no fetch");

    // And nothing else has become reachable: a context that is not preloaded still fails closed.
    let refused = proxy
        .get("/ngsi-ld/v1/entities?type=Vehicle")
        .header(
            "Link",
            format!("<https://elsewhere.test/other.jsonld>; rel=\"{LINK_RELATION}\"; type=\"application/ld+json\""),
        )
        .bearer_auth(token("writer"))
        .send()
        .expect("the proxy should answer");
    assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
}

/// Posts an `application/ld+json` body through a proxy whose policy uses the deployment context.
fn post_ld(proxy: &Proxy, body: &str) -> StatusCode {
    proxy
        .post("/ngsi-ld/v1/entities")
        .header("Content-Type", "application/ld+json")
        .bearer_auth(token("writer"))
        .body(body.to_owned())
        .send()
        .expect("the proxy should answer")
        .status()
}

#[test]
fn a_type_scoped_context_in_a_body_is_refused() {
    let stack = require_stack!();
    let host = Origin::serving("application/ld+json", CONTEXT);
    let upstream = Origin::serving("application/json", "{}");
    let proxy = proxy_for(&stack, &host, &upstream);

    // A JSON-LD 1.1 broker applies the context inside every `Vehicle`; Libra resolves one context
    // per request and would judge `speed` as the attribute it publicly names.
    let body = r#"{"id":"urn:ngsi-ld:Vehicle:1","type":"Vehicle","speed":{"type":"Property","value":1},"@context":{"Vehicle":{"@id":"https://example.test/ns#Vehicle","@context":{"speed":"https://example.test/ns#secret"}}}}"#;

    assert_eq!(post_ld(&proxy, body), StatusCode::BAD_REQUEST);
    assert!(upstream.last_request().is_none());
}

#[test]
fn a_caller_context_redefining_location_is_refused() {
    let stack = require_stack!();
    let host = Origin::serving("application/ld+json", CONTEXT);
    let upstream = Origin::serving("application/json", "{}");
    let proxy = proxy_for(&stack, &host, &upstream);

    let body = r#"{"id":"urn:ngsi-ld:Vehicle:1","type":"Vehicle","@context":{"location":"https://example.test/ns#not-the-location"}}"#;

    assert_eq!(post_ld(&proxy, body), StatusCode::BAD_REQUEST);
    assert!(upstream.last_request().is_none());
}

#[test]
fn two_context_links_are_refused() {
    let stack = require_stack!();
    let host = Origin::serving("application/ld+json", CONTEXT);
    let upstream = Origin::serving("application/json", "{}");
    let proxy = proxy_for(&stack, &host, &upstream);

    // Stellio reads only the first context link, so a request with two is refused rather than resolved either way.
    let response = proxy
        .get("/ngsi-ld/v1/entities?type=Vehicle")
        .header("Link", context_link(&host))
        .header("Link", context_link(&host))
        .bearer_auth(token("writer"))
        .send()
        .expect("the proxy should answer");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(upstream.last_request().is_none());
}
