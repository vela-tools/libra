//! What the policy set allows, decided on signed tokens carrying the claims a standard identity
//! provider issues.
//!
//! The point of doing this end to end rather than against a constructed identity is that the claims
//! travel the whole way: signed, verified, read, matched. Every step is a place where a policy could
//! match something the token does not actually say.

use libra_test_harness::{
    identity::{claims, sign, token},
    proxy::Proxy,
    proxy_settings::ProxySettings,
};
use reqwest::{Method, StatusCode};
use serde_json::json;

/// A plain entity query, on a named tenant.
const QUERY: &str = "/ngsi-ld/v1/entities?type=Vehicle";

/// Reads a query through the proxy as `user`, and reports what came back.
fn read_as(proxy: &Proxy, user_token: String) -> StatusCode {
    proxy
        .get(QUERY)
        .header("NGSILD-Tenant", "fleet")
        .bearer_auth(user_token)
        .send()
        .expect("the proxy should answer")
        .status()
}

#[test]
fn a_policy_naming_the_user_allows_the_read() {
    let stack = require_stack!();
    let policies = r#"
[[policy]]
id = "writer-reads"
priority = 100

[policy.condition]
users = ["writer"]
operations = ["read"]

[policy.access]
effect = "allow"
"#;
    let proxy = Proxy::start(&ProxySettings::new(&stack, policies));

    assert_eq!(read_as(&proxy, token("writer")), StatusCode::OK);
    assert_eq!(
        read_as(&proxy, token("restricted")),
        StatusCode::FORBIDDEN,
        "the policy names one user, and only that user"
    );
}

#[test]
fn a_read_nothing_allows_is_refused() {
    let stack = require_stack!();
    // No policy at all. The default effect decides, and it is deny: an empty policy directory is
    // a gateway that refuses everything rather than one that has not been configured yet.
    let proxy = Proxy::start(&ProxySettings::new(&stack, ""));

    assert_eq!(read_as(&proxy, token("writer")), StatusCode::FORBIDDEN);
}

#[test]
fn a_deny_beats_an_allow_at_the_same_priority() {
    let stack = require_stack!();
    // Both match, both are priority 50, and the identifiers are ordered so that a store sorting by
    // name alone would put the allow first. The tiebreak is towards refusing.
    let policies = r#"
[[policy]]
id = "a-allow"
priority = 50

[policy.condition]
users = ["writer"]

[policy.access]
effect = "allow"

[[policy]]
id = "z-deny"
priority = 50

[policy.condition]
users = ["writer"]

[policy.access]
effect = "deny"
"#;
    let proxy = Proxy::start(&ProxySettings::new(&stack, policies));

    assert_eq!(read_as(&proxy, token("writer")), StatusCode::FORBIDDEN);
}

#[test]
fn the_higher_priority_policy_decides() {
    let stack = require_stack!();
    let policies = r#"
[[policy]]
id = "broad-deny"
priority = 10

[policy.condition]

[policy.access]
effect = "deny"

[[policy]]
id = "narrow-allow"
priority = 90

[policy.condition]
users = ["writer"]
operations = ["read"]

[policy.access]
effect = "allow"
"#;
    let proxy = Proxy::start(&ProxySettings::new(&stack, policies));

    assert_eq!(read_as(&proxy, token("writer")), StatusCode::OK);
    assert_eq!(read_as(&proxy, token("restricted")), StatusCode::FORBIDDEN);
}

#[test]
fn a_role_condition_matches_the_token() {
    let stack = require_stack!();
    let policies = r#"
[[policy]]
id = "fleet-operators-read"
priority = 100

[policy.condition]
roles = ["fleet-operator"]
operations = ["read"]

[policy.access]
effect = "allow"
"#;
    let proxy = Proxy::start(&ProxySettings::new(&stack, policies));

    assert_eq!(read_as(&proxy, token("fleet-reader")), StatusCode::OK);
    assert_eq!(read_as(&proxy, token("writer")), StatusCode::FORBIDDEN, "the writer holds no realm role");
}

#[test]
fn a_role_nested_where_one_identity_provider_puts_it_is_not_a_role() {
    let stack = require_stack!();
    // Keycloak's default layout. A build that reads standard claims does not look there, so a
    // deployment cannot be handed a role by a claim it was never told to read.
    let policies = r#"
[[policy]]
id = "fleet-operators-read"
priority = 100

[policy.condition]
roles = ["fleet-operator"]
operations = ["read"]

[policy.access]
effect = "allow"
"#;
    let proxy = Proxy::start(&ProxySettings::new(&stack, policies));

    let mut nested = claims("writer");
    if let Some(object) = nested.as_object_mut() {
        object.insert("realm_access".to_owned(), json!({ "roles": ["fleet-operator"] }));
        object.insert("resource_access".to_owned(), json!({ "ngsi-client": { "roles": ["fleet-operator"] } }));
    }

    assert_eq!(read_as(&proxy, sign(&nested)), StatusCode::FORBIDDEN);
}

#[test]
fn a_group_condition_matches_the_token() {
    let stack = require_stack!();
    let policies = r#"
[[policy]]
id = "operations-read"
priority = 100

[policy.condition]
groups = ["operations"]
operations = ["read"]

[policy.access]
effect = "allow"
"#;
    let proxy = Proxy::start(&ProxySettings::new(&stack, policies));

    assert_eq!(read_as(&proxy, token("operator")), StatusCode::OK);
    assert_eq!(read_as(&proxy, token("writer")), StatusCode::FORBIDDEN, "the writer is in no group");
}

#[test]
fn a_write_is_refused_by_a_read_only_policy() {
    let stack = require_stack!();
    let policies = r#"
[[policy]]
id = "read-only"
priority = 100

[policy.condition]
users = ["writer"]
operations = ["read"]

[policy.access]
effect = "allow"
"#;
    let proxy = Proxy::start(&ProxySettings::new(&stack, policies));

    let response = proxy
        .post("/ngsi-ld/v1/entities")
        .header("NGSILD-Tenant", "fleet")
        .header("Content-Type", "application/ld+json")
        .bearer_auth(token("writer"))
        .body(r#"{"id":"urn:ngsi-ld:Vehicle:refused","type":"Vehicle"}"#)
        .send()
        .expect("the proxy should answer");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[test]
fn a_delete_is_a_write_whatever_the_route_looks_like() {
    let stack = require_stack!();
    let policies = r#"
[[policy]]
id = "read-only"
priority = 100

[policy.condition]
users = ["writer"]
operations = ["read"]

[policy.access]
effect = "allow"
"#;
    let proxy = Proxy::start(&ProxySettings::new(&stack, policies));

    // Classified from the method and the path rather than from a prefix match, which is what stops
    // a delete on an entity route being read as the read the route name suggests.
    let response = proxy
        .request(Method::DELETE, "/ngsi-ld/v1/entities/urn:ngsi-ld:Vehicle:nothing")
        .header("NGSILD-Tenant", "fleet")
        .bearer_auth(token("writer"))
        .send()
        .expect("the proxy should answer");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

/// Allows reads of the default tenant to the kind of caller `callers` names.
fn reads_for(callers: &str) -> String {
    format!(
        r#"
[[policy]]
id = "reads-by-kind"
priority = 100

[policy.condition]
callers = "{callers}"
tenants = ["*untenanted"]
operations = ["read"]

[policy.access]
effect = "allow"
"#
    )
}

/// Reads the default tenant, with `user`'s token or with no credential at all.
fn read_untenanted(proxy: &Proxy, user: Option<&str>) -> StatusCode {
    let request = proxy.get(QUERY);
    let request = match user {
        Some(user) => request.bearer_auth(token(user)),
        None => request,
    };

    request.send().expect("the proxy should answer").status()
}

#[test]
fn a_policy_for_anonymous_callers_does_not_match_an_authenticated_one() {
    let stack = require_stack!();
    // The suite runs under `allow-public`, so the anonymous read reaches the policy set.
    let proxy = Proxy::start(&ProxySettings::new(&stack, &reads_for("anonymous")));

    assert_eq!(read_untenanted(&proxy, None), StatusCode::OK);
    assert_eq!(
        read_untenanted(&proxy, Some("writer")),
        StatusCode::FORBIDDEN,
        "a public allow must not also cover a caller who presented a credential"
    );
}

#[test]
fn a_policy_for_authenticated_callers_does_not_match_an_anonymous_one() {
    let stack = require_stack!();
    let proxy = Proxy::start(&ProxySettings::new(&stack, &reads_for("authenticated")));

    assert_eq!(read_untenanted(&proxy, Some("writer")), StatusCode::OK);
    assert_eq!(read_untenanted(&proxy, None), StatusCode::FORBIDDEN);
}
