//! Getting one filter past Libra while showing the broker another.
//!
//! A filtering proxy is only as good as its reading of the request: if a duplicate parameter, a
//! percent-encoded name or an ambiguous encoding lets the caller mean one thing to Libra and
//! another to the broker, the policy is enforced against a request nobody sent. These drive the
//! smuggling shapes that a query-parameter parser has to get right.

use libra_test_harness::{identity::token, origin::Origin, proxy::Proxy, proxy_settings::ProxySettings};
use reqwest::StatusCode;

/// The tenant these reads name.
const TENANT: &str = "gardens";

/// A policy allowing the writer reads with one attribute hidden. A restriction has to be in force
/// for the attribute filter to parse the query at all, which is where the smuggling defences live.
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

/// A policy allowing the writer unrestricted reads, so the request is forwarded byte for byte.
const ALLOW_READ: &str = r#"
[[policy]]
id = "allow-read"
priority = 100

[policy.condition]
users = ["writer"]
tenants = ["gardens"]
operations = ["read"]

[policy.access]
effect = "allow"
"#;

#[test]
fn a_duplicate_query_parameter_is_refused() {
    let stack = require_stack!();
    let proxy = Proxy::start(&ProxySettings::new(&stack, OMIT_LOCATION));

    // Two values for one parameter is the classic smuggle: a last-wins parser shows Libra the first
    // and the broker the second. The query parser refuses the duplicate outright rather than
    // choosing one, so there is no gap to aim the second value through.
    let response = proxy
        .get("/ngsi-ld/v1/entities?type=Vehicle&type=Device")
        .header("NGSILD-Tenant", TENANT)
        .bearer_auth(token("writer"))
        .send()
        .expect("the proxy should answer");

    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "a duplicate query parameter must be refused, not resolved to one value"
    );
}

#[test]
fn an_encoded_attribute_name_cannot_evade_the_filter() {
    let stack = require_stack!();
    let proxy = Proxy::start(&ProxySettings::new(&stack, OMIT_LOCATION));

    // `%6c` is `l`, so `%6cocation` is `location` once decoded. Decoding happens before the name is
    // expanded and compared to the restriction, so a request for exactly the hidden attribute is refused
    // whether it is spelled out or encoded.
    let response = proxy
        .get("/ngsi-ld/v1/entities?type=Vehicle&attrs=%6cocation")
        .header("NGSILD-Tenant", TENANT)
        .bearer_auth(token("writer"))
        .send()
        .expect("the proxy should answer");

    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "a percent-encoded attribute name must be caught by the filter like a plain one"
    );
}

#[test]
fn a_plus_in_a_value_reaches_the_broker_percent_encoded() {
    let stack = require_stack!();
    let origin = Origin::serving("application/json", "[]");
    let settings = ProxySettings {
        upstream: origin.address(),
        ..ProxySettings::new(&stack, ALLOW_READ)
    };
    let proxy = Proxy::start(&settings);

    // A `+` in a query value is a legitimate timezone offset, and form decoding reads a literal
    // `+` as a space, which moves the instant by the offset. Forwarded as `%2B`, every reader that
    // percent-decodes gets the offset the caller wrote.
    let response = proxy
        .get("/ngsi-ld/v1/entities?type=Vehicle&timeAt=2026-01-01T00:00:00+01:00")
        .header("NGSILD-Tenant", TENANT)
        .bearer_auth(token("writer"))
        .send()
        .expect("the proxy should answer");
    let status = response.status();

    let recorded = origin
        .last_request()
        .unwrap_or_else(|| panic!("the read was not forwarded to the broker; status was {status}"));
    assert!(
        recorded.target.contains("timeAt=2026-01-01T00:00:00%2B01:00"),
        "the offset must reach the broker encoded as %2B, not as a literal plus that form decoding reads as a space: {}",
        recorded.target
    );
}

#[test]
fn a_semicolon_hidden_in_a_value_reaches_the_broker_percent_encoded() {
    let stack = require_stack!();
    let origin = Origin::serving("application/json", "[]");
    let settings = ProxySettings {
        upstream: origin.address(),
        ..ProxySettings::new(&stack, ALLOW_READ)
    };
    let proxy = Proxy::start(&settings);

    // `;` splits a query for servlet containers and Netty-family decoders before percent-decoding,
    // so `q=Vehicle;speed` could read to the broker as two filters where Libra read one value.
    // Forwarded as `%3B`, no decoder sees a separator Libra did not. An unrestricted read isolates
    // the forwarding contract.
    let response = proxy
        .get("/ngsi-ld/v1/entities?q=Vehicle;speed")
        .header("NGSILD-Tenant", TENANT)
        .bearer_auth(token("writer"))
        .send()
        .expect("the proxy should answer");
    let status = response.status();

    let recorded = origin
        .last_request()
        .unwrap_or_else(|| panic!("the read was not forwarded to the broker; status was {status}"));
    assert!(
        recorded.target.contains("q=Vehicle%3Bspeed"),
        "the semicolon must reach the broker encoded as %3B: {}",
        recorded.target
    );
}
