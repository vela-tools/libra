//! What the broker is actually sent.
//!
//! The broker behind Libra has no authentication of its own: it trusts what arrives. So the
//! headers Libra injects are the caller's identity as far as everything downstream is concerned,
//! and a caller who can set one of those names has become whoever they wrote. That is only
//! observable from the other side, which is why these tests put an origin of their own where the
//! broker would be.

use libra_test_harness::{identity::token, origin::Origin, proxy::Proxy, proxy_settings::ProxySettings, stack::Endpoints};

/// Whatever the origin is asked for, it answers with this.
const ANSWER: &str = r#"{"answered":true}"#;

/// Allows the writer reads on a named tenant, and anyone reads on none.
const POLICIES: &str = r#"
[[policy]]
id = "named-tenant-read"
priority = 100

[policy.condition]
users = ["writer"]
tenants = ["fleet"]
operations = ["read"]

[policy.access]
effect = "allow"

[[policy]]
id = "untenanted-read"
priority = 100

[policy.condition]
tenants = ["*untenanted"]
operations = ["read"]

[policy.access]
effect = "allow"
"#;

/// Allows the group `operations` reads on a named tenant.
const OPERATIONS_READ: &str = r#"
[[policy]]
id = "operations-read"
priority = 100

[policy.condition]
groups = ["operations"]
tenants = ["fleet"]
operations = ["read"]

[policy.access]
effect = "allow"
"#;

/// A proxy forwarding to `origin` instead of to the broker.
fn proxy_to(stack: &Endpoints, origin: &Origin) -> Proxy {
    let settings = ProxySettings {
        upstream: origin.address(),
        ..ProxySettings::new(stack, POLICIES)
    };

    Proxy::start(&settings)
}

#[test]
fn the_caller_reaches_the_broker_in_the_identity_headers() {
    let stack = require_stack!();
    let origin = Origin::serving("application/json", ANSWER);
    let proxy = proxy_to(&stack, &origin);

    let response = proxy
        .get("/ngsi-ld/v1/entities?type=Vehicle")
        .header("NGSILD-Tenant", "fleet")
        .bearer_auth(token("writer"))
        .send()
        .expect("the proxy should answer");
    assert!(response.status().is_success(), "the policy allows this read");

    let forwarded = origin.last_request().expect("the request should have reached the broker");
    assert_eq!(forwarded.method, "GET", "the method reaches the broker unchanged");
    assert_eq!(
        forwarded.target, "/ngsi-ld/v1/entities?type=Vehicle",
        "the path and query reach the broker unchanged"
    );
    assert_eq!(
        forwarded.header("x-auth-subject"),
        Some("writer"),
        "the subject identifies the caller in the broker's own logs"
    );
}

#[test]
fn a_jwt_caller_is_described_by_what_its_token_says_and_nothing_else() {
    let stack = require_stack!();
    let origin = Origin::serving("application/json", ANSWER);
    let settings = ProxySettings {
        upstream: origin.address(),
        ..ProxySettings::new(&stack, OPERATIONS_READ)
    };
    let proxy = Proxy::start(&settings);

    // `operator` is in the group `operations` and holds no role. A token carries no claim Libra
    // reads that names a username, an email address or a machine, so none of those is sent.
    let response = proxy
        .get("/ngsi-ld/v1/entities?type=Vehicle")
        .header("NGSILD-Tenant", "fleet")
        .header("X-Auth-Username", "admin")
        .header("X-Auth-Machine", "true")
        .bearer_auth(token("operator"))
        .send()
        .expect("the proxy should answer");
    assert!(response.status().is_success(), "the policy allows this read");

    let forwarded = origin.last_request().expect("the request should have reached the broker");
    assert_eq!(forwarded.header("x-auth-subject"), Some("operator"));
    assert_eq!(forwarded.header("x-auth-groups"), Some("operations"));
    assert_eq!(forwarded.header("x-auth-roles"), None, "the token lists no role");
    assert_eq!(forwarded.header("x-auth-username"), None, "a forged username must not survive either");
    assert_eq!(forwarded.header("x-auth-email"), None);
    assert_eq!(forwarded.header("x-auth-machine"), None, "only an API key principal is said to be a machine");
}

#[test]
fn an_inbound_identity_header_is_replaced_rather_than_forwarded() {
    let stack = require_stack!();
    let origin = Origin::serving("application/json", ANSWER);
    let proxy = proxy_to(&stack, &origin);

    // The caller claims to be somebody else. Libra strips every name it injects before it injects
    // anything, so what arrives is the identity the token established and not the one asserted.
    proxy
        .get("/ngsi-ld/v1/entities?type=Vehicle")
        .header("NGSILD-Tenant", "fleet")
        .header("X-Auth-Username", "admin")
        .bearer_auth(token("writer"))
        .send()
        .expect("the proxy should answer");

    let forwarded = origin.last_request().expect("the request should have reached the broker");
    assert_eq!(forwarded.header("x-auth-subject"), Some("writer"));
    assert_eq!(forwarded.header("x-auth-username"), None, "the caller's own value must not survive");
}

#[test]
fn an_inbound_identity_header_is_removed_when_there_is_nothing_to_replace_it_with() {
    let stack = require_stack!();
    let origin = Origin::serving("application/json", ANSWER);
    let proxy = proxy_to(&stack, &origin);

    // An anonymous request establishes no identity, so nothing is injected. The strip list and the
    // inject list being one list is what makes this a removal rather than a pass-through: the
    // header the caller wrote would otherwise be the only one the broker ever saw.
    proxy
        .get("/ngsi-ld/v1/entities?type=Vehicle")
        .header("X-Auth-Username", "admin")
        .header("X-Auth-Tenant-State", "trusted")
        .send()
        .expect("the proxy should answer");

    let forwarded = origin.last_request().expect("the request should have reached the broker");
    assert_eq!(forwarded.header("x-auth-username"), None, "an unauthenticated caller must not name themselves");
    // The tenant state is Libra's own answer about the request rather than anything the token
    // said, so an anonymous request still carries one. What must not survive is the caller's:
    // every propagated name is stripped on the way in, then re-established from what Libra knows.
    assert_eq!(
        forwarded.header("x-auth-tenant-state"),
        Some("none"),
        "the tenant state must be the one Libra determined, not the one the caller asserted"
    );
}

#[test]
fn a_hop_by_hop_header_does_not_reach_the_broker() {
    let stack = require_stack!();
    let origin = Origin::serving("application/json", ANSWER);
    let proxy = proxy_to(&stack, &origin);
    let bearer = token("writer");

    // `Connection` names the headers that belong to this hop alone, and a proxy is required to
    // drop them rather than pass them on. Written in raw bytes because an HTTP client rewrites
    // exactly these headers.
    // What the proxy answers is not the point; what it forwarded is.
    let _answer = proxy.raw(&format!(
        "GET /ngsi-ld/v1/entities?type=Vehicle HTTP/1.1\r\nHost: localhost\r\nNGSILD-Tenant: fleet\r\nX-Hop-Secret: value\r\nConnection: X-Hop-Secret, close\r\nAuthorization: Bearer {bearer}\r\n\r\n"
    ));

    let forwarded = origin.last_request().expect("the request should have reached the broker");
    assert_eq!(forwarded.header("x-hop-secret"), None, "a header named by Connection is for this hop only");
}

#[test]
fn the_hop_is_recorded_for_the_broker() {
    let stack = require_stack!();
    let origin = Origin::serving("application/json", ANSWER);
    let proxy = proxy_to(&stack, &origin);

    proxy
        .get("/ngsi-ld/v1/entities?type=Vehicle")
        .header("NGSILD-Tenant", "fleet")
        .bearer_auth(token("writer"))
        .send()
        .expect("the proxy should answer");

    let forwarded = origin.last_request().expect("the request should have reached the broker");
    assert!(forwarded.header("via").is_some(), "a proxied request should say it was proxied");
}

#[test]
fn the_broker_never_sees_the_callers_credential() {
    let stack = require_stack!();
    let origin = Origin::serving("application/json", ANSWER);
    let proxy = proxy_to(&stack, &origin);

    // A context source registration can ask the broker to copy `Authorization` to its endpoint
    // (NGSI-LD clause 4.3.6.5), so a credential that reached the broker could reach anyone.
    let response = proxy
        .get("/ngsi-ld/v1/entities?type=Vehicle")
        .header("NGSILD-Tenant", "fleet")
        .bearer_auth(token("writer"))
        .send()
        .expect("the proxy should answer");
    assert!(response.status().is_success(), "the policy allows this read");

    let forwarded = origin.last_request().expect("the request should have reached the broker");
    assert_eq!(forwarded.header("authorization"), None);
}

#[test]
fn two_authorization_headers_are_refused_before_anything_is_forwarded() {
    let stack = require_stack!();
    let origin = Origin::serving("application/json", ANSWER);
    let proxy = proxy_to(&stack, &origin);
    let credential = format!("Bearer {}", token("writer"));

    let response = proxy
        .get("/ngsi-ld/v1/entities?type=Vehicle")
        .header("NGSILD-Tenant", "fleet")
        .header("Authorization", &credential)
        .header("Authorization", &credential)
        .send()
        .expect("the proxy should answer");

    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert!(origin.last_request().is_none());
}
