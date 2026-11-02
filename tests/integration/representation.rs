//! What Libra does with a request whose response representation it cannot decide.
//!
//! Reading the `Accept` header and the `options` parameter is what lets the cache, the
//! deduplicator and the attribute filter agree about the shape of an answer. It is deliberately not
//! a new refusal: by default a header naming nothing Libra can produce is forwarded untouched and
//! the broker answers it, exactly as it did before anything read the header. A deployment that
//! wants the gateway to refuse says so in `[representation]`.

use libra_test_harness::{identity::token, origin::Origin, proxy::Proxy, proxy_settings::ProxySettings};
use reqwest::StatusCode;

/// The tenant the policy below allows reads in.
const TENANT: &str = "fleet";

/// A policy allowing the writer unrestricted reads, so nothing but the representation is in play.
const POLICIES: &str = r#"
[[policy]]
id = "unrestricted-read"
priority = 100

[policy.condition]
users = ["writer"]
tenants = ["fleet"]
operations = ["read"]

[policy.access]
effect = "allow"
"#;

#[test]
fn an_unsatisfiable_accept_is_forwarded_to_the_broker() {
    let stack = require_stack!();
    // An origin rather than the broker, so the test can see what the proxy actually sent and can
    // assert on an answer no broker had to be persuaded to give.
    let upstream = Origin::serving("application/json", r#"[{"id":"urn:ngsi-ld:Vehicle:1","type":"Vehicle"}]"#);
    let settings = ProxySettings {
        upstream: upstream.address(),
        ..ProxySettings::new(&stack, POLICIES)
    };
    let proxy = Proxy::start(&settings);

    let response = proxy
        .get("/ngsi-ld/v1/entities?type=Vehicle")
        .header("NGSILD-Tenant", TENANT)
        .header("Accept", "text/csv")
        .bearer_auth(token("writer"))
        .send()
        .expect("the proxy should answer");

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "the default configuration must not manufacture a 406 the broker never sent"
    );

    let recorded = upstream.last_request().expect("the request should have reached the upstream");

    assert_eq!(
        recorded.header("accept"),
        Some("text/csv"),
        "the header is forwarded as written, so the broker decides"
    );
}
