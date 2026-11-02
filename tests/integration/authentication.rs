//! Which tokens the proxy accepts, signed by the suite's own issuer against the key set it serves.
//!
//! Every refusal here is a 401 rather than a 403: the caller was never established, so there is no
//! identity for a policy to be about. The policy in force would allow the request if it were
//! authenticated, which is what makes each of these tests about authentication alone.

use libra_test_harness::{
    identity::{claims, sign, token},
    proxy::Proxy,
    proxy_settings::ProxySettings,
};
use reqwest::StatusCode;
use serde_json::{Value, json};

/// Allows the reads below to anyone the issuer authenticates, so that a refusal is never about
/// what the policy says.
const ANY_AUTHENTICATED_READ: &str = r#"
[[policy]]
id = "authenticated-read"
description = "Anyone the issuer authenticates may read"
priority = 100

[policy.condition]
operations = ["read"]

[policy.access]
effect = "allow"
"#;

/// The request every test here makes: a plain entity query, on a named tenant.
const QUERY: &str = "/ngsi-ld/v1/entities?type=Vehicle";

/// The status of [`QUERY`] carrying `bearer`.
fn status_with(proxy: &Proxy, bearer: &str) -> StatusCode {
    proxy
        .get(QUERY)
        .header("NGSILD-Tenant", "fleet")
        .bearer_auth(bearer)
        .send()
        .expect("the proxy should answer")
        .status()
}

/// The claims of a token for `writer`, with `name` replaced by `value`, or removed when `value` is
/// `null`.
fn writer_claims_with(name: &str, value: Value) -> Value {
    let mut changed = claims("writer");
    if let Some(object) = changed.as_object_mut() {
        if value.is_null() {
            object.remove(name);
        } else {
            object.insert(name.to_owned(), value);
        }
    }

    changed
}

#[test]
fn a_request_naming_a_tenant_must_authenticate() {
    let stack = require_stack!();
    // `allow-public` decides only what happens to a request that names no tenant. A request that
    // names one is a request about somebody's data, and it authenticates whatever this is set to.
    let proxy = Proxy::start(&ProxySettings::new(&stack, ANY_AUTHENTICATED_READ));

    let response = proxy.get(QUERY).header("NGSILD-Tenant", "fleet").send().expect("the proxy should answer");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[test]
fn a_token_the_issuer_did_not_sign_is_refused() {
    let stack = require_stack!();
    let proxy = Proxy::start(&ProxySettings::new(&stack, ANY_AUTHENTICATED_READ));

    assert_eq!(
        status_with(&proxy, "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhdHRhY2tlciJ9.not-a-signature"),
        StatusCode::UNAUTHORIZED
    );
}

#[test]
fn an_authorization_header_that_is_not_a_bearer_token_is_refused() {
    let stack = require_stack!();
    let proxy = Proxy::start(&ProxySettings::new(&stack, ANY_AUTHENTICATED_READ));

    let response = proxy
        .get(QUERY)
        .header("NGSILD-Tenant", "fleet")
        .header("Authorization", "Basic YWRtaW46YWRtaW4=")
        .send()
        .expect("the proxy should answer");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[test]
fn a_token_issued_for_another_client_is_refused() {
    let stack = require_stack!();
    let proxy = Proxy::start(&ProxySettings::new(&stack, ANY_AUTHENTICATED_READ));

    // The same issuer, the same user, the same signing key. The only difference is who the token
    // was issued for, which is the whole of what an audience check is.
    let elsewhere = sign(&writer_claims_with("aud", json!("other-client")));

    assert_eq!(
        status_with(&proxy, &elsewhere),
        StatusCode::UNAUTHORIZED,
        "a token minted for another client must not be accepted"
    );
}

#[test]
fn a_token_from_another_issuer_is_refused() {
    let stack = require_stack!();
    let proxy = Proxy::start(&ProxySettings::new(&stack, ANY_AUTHENTICATED_READ));

    // The keys still validate the signature; only the `iss` claim disagrees.
    let elsewhere = sign(&writer_claims_with("iss", json!("https://elsewhere.test/realms/libra")));

    assert_eq!(status_with(&proxy, &elsewhere), StatusCode::UNAUTHORIZED);
}

#[test]
fn a_token_that_names_no_subject_is_refused() {
    let stack = require_stack!();
    let proxy = Proxy::start(&ProxySettings::new(&stack, ANY_AUTHENTICATED_READ));

    // Signed, unexpired, for this audience by this issuer, and about nobody. Accepting it would
    // authenticate an anonymous caller holding whatever roles the token lists.
    let nobody = sign(&writer_claims_with("sub", Value::Null));

    assert_eq!(status_with(&proxy, &nobody), StatusCode::UNAUTHORIZED);
}

#[test]
fn a_token_the_issuer_signed_is_accepted() {
    let stack = require_stack!();
    let proxy = Proxy::start(&ProxySettings::new(&stack, ANY_AUTHENTICATED_READ));

    let response = proxy
        .get(QUERY)
        .header("NGSILD-Tenant", "fleet")
        .bearer_auth(token("writer"))
        .send()
        .expect("the proxy should answer");

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "the request should reach the broker: {}",
        response.text().unwrap_or_default()
    );
}

#[test]
fn a_deployment_that_accepts_no_credential_refuses_to_start() {
    let stack = require_stack!();
    let settings = ProxySettings {
        jwt: None,
        key_store: None,
        ..ProxySettings::new(&stack, ANY_AUTHENTICATED_READ)
    };

    let refusal = Proxy::start_expecting_failure(&settings);

    assert!(refusal.contains("[jwt]") && refusal.contains("[key-store]"), "{refusal}");
}

#[test]
fn the_former_keycloak_section_stops_startup() {
    let stack = require_stack!();
    // A `[keycloak]` section is claimed by no build, so it stops startup instead of being ignored.
    let settings = ProxySettings {
        extra_sections: "[keycloak]\njwks-url = \"https://idp.test/certs\"\n".to_owned(),
        ..ProxySettings::new(&stack, ANY_AUTHENTICATED_READ)
    };

    let refusal = Proxy::start_expecting_failure(&settings);

    assert!(refusal.contains("keycloak"), "{refusal}");
}
