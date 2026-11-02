//! Ambiguous or unproducible representation requests, and the filter's indifference to shape.
//!
//! Two separate concerns share this file. First, when an operator has asked Libra to resolve the
//! response representation strictly (`[representation]` set to `refuse`), a request that names two
//! shapes at once, disagrees with itself, misspells a token or asks for a media type Libra cannot
//! produce is answered at the gateway rather than forwarded (RFC 9110 12.5.1). Second, whatever
//! shape an allowed read is rendered in, an attribute the policy hides stays hidden: the filter
//! works on names in the body, not on the representation.
//!
//! The gateway-refusal tests run the proxy with strictness on; the filtering tests run it with the
//! default (forward) config, because filtering does not depend on the strictness setting.

use libra_test_harness::{
    broker::{create, unique_id},
    identity::token,
    proxy::Proxy,
    proxy_settings::ProxySettings,
    stack::Endpoints,
};
use reqwest::StatusCode;
use serde_json::json;

/// The tenant these reads name.
const TENANT: &str = "gardens";

/// The core context every seeded entity carries.
const CORE_CONTEXT: &str = "https://uri.etsi.org/ngsi-ld/v1/ngsi-ld-core-context.jsonld";

/// An unrestricted read restriction, which is all the gateway-refusal tests need: the refusal happens
/// while resolving the representation, before any restriction would apply.
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

/// A read restriction that hides `speed`, for the representation-agnostic filtering tests.
const OMIT_SPEED: &str = r#"
[[policy]]
id = "read-omit-speed"
priority = 100

[policy.condition]
users = ["writer"]
tenants = ["gardens"]
operations = ["read"]

[policy.access]
effect = "allow"

[policy.access.attribute]
action = "omit"
attributes = ["speed"]
"#;

/// A proxy that answers an unresolvable representation at the gateway instead of forwarding it.
fn strict_proxy(stack: &Endpoints) -> Proxy {
    let settings = ProxySettings {
        unsatisfiable_accept: "refuse",
        contradictory_options: "refuse",
        ..ProxySettings::new(stack, ALLOW_READ)
    };

    Proxy::start(&settings)
}

/// Seeds a vehicle carrying two ordinary attributes and reports its identifier.
fn seed_vehicle(stack: &Endpoints) -> String {
    let id = unique_id("Vehicle");
    create(
        stack,
        Some(TENANT),
        &json!({
            "@context": CORE_CONTEXT,
            "id": id,
            "type": "Vehicle",
            "speed": { "type": "Property", "value": 42 },
            "brand": { "type": "Property", "value": "Example" }
        }),
    );

    id
}

#[test]
fn contradictory_options_shape_tokens_are_refused() {
    let stack = require_stack!();
    let proxy = strict_proxy(&stack);

    // `concise` and `keyValues` are two different shapes; naming both is not a request Libra can
    // resolve, and under strictness it is refused rather than silently picking one.
    let response = proxy
        .get("/ngsi-ld/v1/entities?type=Vehicle&options=concise,keyValues")
        .header("NGSILD-Tenant", TENANT)
        .bearer_auth(token("writer"))
        .send()
        .expect("the proxy should answer");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST, "two shape tokens at once must be refused");
}

#[test]
fn options_and_format_disagreement_is_refused() {
    let stack = require_stack!();
    let proxy = strict_proxy(&stack);

    let response = proxy
        .get("/ngsi-ld/v1/entities?type=Vehicle&options=concise&format=keyValues")
        .header("NGSILD-Tenant", TENANT)
        .bearer_auth(token("writer"))
        .send()
        .expect("the proxy should answer");

    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "`options` and `format` naming different shapes must be refused"
    );
}

#[test]
fn a_misspelled_option_is_refused_not_ignored() {
    let stack = require_stack!();
    let proxy = strict_proxy(&stack);

    // `keyvalues` is not `keyValues`. A parser that ignores a token it does not recognise would
    // serve the default shape and call it success; strictness refuses the misspelling.
    let response = proxy
        .get("/ngsi-ld/v1/entities?type=Vehicle&options=keyvalues")
        .header("NGSILD-Tenant", TENANT)
        .bearer_auth(token("writer"))
        .send()
        .expect("the proxy should answer");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST, "a misspelled option token must be refused");
}

#[test]
fn an_unproducible_accept_is_406() {
    let stack = require_stack!();
    let proxy = strict_proxy(&stack);

    // Libra produces JSON, JSON-LD and GeoJSON. An `Accept` that names none of them cannot be
    // satisfied, and under strictness the answer is 406 rather than a forward to the broker.
    let response = proxy
        .get("/ngsi-ld/v1/entities?type=Vehicle")
        .header("NGSILD-Tenant", TENANT)
        .header("Accept", "application/xml")
        .bearer_auth(token("writer"))
        .send()
        .expect("the proxy should answer");

    assert_eq!(response.status(), StatusCode::NOT_ACCEPTABLE, "an unproducible Accept must be 406");
}

#[test]
fn a_restricted_read_is_filtered_in_every_representation() {
    let stack = require_stack!();
    let id = seed_vehicle(&stack);
    let proxy = Proxy::start(&ProxySettings::new(&stack, OMIT_SPEED));

    // The filter works on the attribute name in the body, which is present whatever shape the body
    // takes. `normalized`, `concise` and `keyValues` render the value differently; none of them may
    // carry the hidden attribute.
    for options in ["normalized", "concise", "keyValues"] {
        let response = proxy
            .get(&format!("/ngsi-ld/v1/entities/{id}?options={options}"))
            .header("NGSILD-Tenant", TENANT)
            .bearer_auth(token("writer"))
            .send()
            .expect("the proxy should answer");

        assert_eq!(response.status(), StatusCode::OK, "the read should succeed under {options}");
        let body = response.text().unwrap_or_default();
        assert!(!body.contains("speed"), "the hidden attribute reached the caller under {options}: {body}");
        assert!(body.contains("brand"), "an allowed attribute must survive under {options}: {body}");
    }
}

#[test]
fn sys_attrs_do_not_reintroduce_a_hidden_attribute() {
    let stack = require_stack!();
    let id = seed_vehicle(&stack);
    let proxy = Proxy::start(&ProxySettings::new(&stack, OMIT_SPEED));

    // `sysAttrs` asks the broker to add `createdAt`/`modifiedAt`. It is a separate concern from the
    // attribute filter, which strips by name regardless: the system timestamps come through and the
    // hidden attribute does not.
    let response = proxy
        .get(&format!("/ngsi-ld/v1/entities/{id}?options=sysAttrs"))
        .header("NGSILD-Tenant", TENANT)
        .bearer_auth(token("writer"))
        .send()
        .expect("the proxy should answer");

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().unwrap_or_default();
    assert!(!body.contains("speed"), "sysAttrs must not reintroduce the hidden attribute: {body}");
    assert!(body.contains("createdAt"), "the system timestamps should be present under sysAttrs: {body}");
}
