//! The tenant a request is about, and what it takes to change it.
//!
//! Every policy decision is scoped to a tenant, so the tenant header is an input to authorization
//! rather than a routing detail. Anything that lets a caller change or remove it after the decision
//! has been made is an escalation, which is why the last test here is written in raw bytes.

use libra_test_harness::{identity::token, proxy::Proxy, proxy_settings::ProxySettings};
use reqwest::StatusCode;

/// A plain entity query.
const QUERY: &str = "/ngsi-ld/v1/entities?type=Vehicle";

/// Allows the writer reads on one tenant and nothing anywhere else.
const ONE_TENANT: &str = r#"
[[policy]]
id = "fleet-only"
priority = 100

[policy.condition]
users = ["writer"]
tenants = ["fleet"]
operations = ["read"]

[policy.access]
effect = "allow"
"#;

#[test]
fn a_policy_for_one_tenant_does_not_allow_another() {
    let stack = require_stack!();
    let proxy = Proxy::start(&ProxySettings::new(&stack, ONE_TENANT));
    let bearer = token("writer");

    let allowed = proxy
        .get(QUERY)
        .header("NGSILD-Tenant", "fleet")
        .bearer_auth(&bearer)
        .send()
        .expect("the proxy should answer");
    assert_eq!(allowed.status(), StatusCode::OK);

    let other = proxy
        .get(QUERY)
        .header("NGSILD-Tenant", "depot")
        .bearer_auth(&bearer)
        .send()
        .expect("the proxy should answer");
    assert_eq!(other.status(), StatusCode::FORBIDDEN);
}

#[test]
fn naming_no_tenant_does_not_satisfy_a_tenant_condition() {
    let stack = require_stack!();
    let proxy = Proxy::start(&ProxySettings::new(&stack, ONE_TENANT));

    let response = proxy.get(QUERY).bearer_auth(token("writer")).send().expect("the proxy should answer");

    assert_eq!(response.status(), StatusCode::FORBIDDEN, "an absent tenant is not the tenant the policy names");
}

#[test]
fn the_untenanted_selector_matches_a_request_that_names_no_tenant() {
    let stack = require_stack!();
    let policies = r#"
[[policy]]
id = "untenanted-read"
priority = 100

[policy.condition]
tenants = ["*untenanted"]
operations = ["read"]

[policy.access]
effect = "allow"
"#;
    let proxy = Proxy::start(&ProxySettings::new(&stack, policies));

    let untenanted = proxy.get(QUERY).send().expect("the proxy should answer");
    assert_eq!(untenanted.status(), StatusCode::OK);

    let named = proxy
        .get(QUERY)
        .header("NGSILD-Tenant", "fleet")
        .bearer_auth(token("writer"))
        .send()
        .expect("the proxy should answer");
    assert_eq!(named.status(), StatusCode::FORBIDDEN, "the untenanted selector is not a wildcard");
}

#[test]
fn an_empty_tenant_header_is_refused() {
    let stack = require_stack!();
    let proxy = Proxy::start(&ProxySettings::new(&stack, ONE_TENANT));

    let response = proxy
        .get(QUERY)
        .header("NGSILD-Tenant", "")
        .bearer_auth(token("writer"))
        .send()
        .expect("the proxy should answer");

    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "a request that says its tenant is nothing is not a request that said nothing"
    );
}

#[test]
fn a_repeated_tenant_header_is_refused() {
    let stack = require_stack!();
    let proxy = Proxy::start(&ProxySettings::new(&stack, ONE_TENANT));

    // Two values, one of which a policy allows. Whichever the proxy picked, something downstream
    // could pick the other, so neither is picked.
    let response = proxy
        .get(QUERY)
        .header("NGSILD-Tenant", "fleet")
        .header("NGSILD-Tenant", "depot")
        .bearer_auth(token("writer"))
        .send()
        .expect("the proxy should answer");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[test]
fn a_request_with_no_tenant_is_refused_when_the_header_is_required() {
    let stack = require_stack!();
    let settings = ProxySettings {
        tenant_policy: "require-header",
        ..ProxySettings::new(&stack, ONE_TENANT)
    };
    let proxy = Proxy::start(&settings);

    let response = proxy.get(QUERY).bearer_auth(token("writer")).send().expect("the proxy should answer");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[test]
fn a_connection_header_cannot_remove_the_tenant_from_the_request() {
    let stack = require_stack!();
    let proxy = Proxy::start(&ProxySettings::new(&stack, ONE_TENANT));
    let bearer = token("writer");

    // `Connection` lists headers that are hop-by-hop for this connection, and a proxy is required
    // to drop them. Naming the tenant header there asks Libra to authorize against a tenant and
    // then forward a request that does not mention it: the broker would answer on its default
    // tenant, which is not the one the decision was about. The header is guarded, so the tenant
    // survives and the policy that allows only `fleet` still refuses `depot`.
    let refused = proxy.raw(&format!(
        "GET /ngsi-ld/v1/entities?type=Vehicle HTTP/1.1\r\nHost: localhost\r\nAccept: application/ld+json\r\nNGSILD-Tenant: depot\r\nConnection: NGSILD-Tenant, close\r\nAuthorization: Bearer {bearer}\r\n\r\n"
    ));
    assert!(refused.starts_with("HTTP/1.1 403"), "the tenant must still govern the decision:\n{refused}");

    let allowed = proxy.raw(&format!(
        "GET /ngsi-ld/v1/entities?type=Vehicle HTTP/1.1\r\nHost: localhost\r\nAccept: application/ld+json\r\nNGSILD-Tenant: fleet\r\nConnection: NGSILD-Tenant, close\r\nAuthorization: Bearer {bearer}\r\n\r\n"
    ));
    assert!(
        allowed.starts_with("HTTP/1.1 200"),
        "the same request on the allowed tenant should be answered:\n{allowed}"
    );
}
