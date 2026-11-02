//! Live JWKS behaviour: a rotated key is honoured, an unknown one is refused, a retired one stops
//! working.
//!
//! The static token attacks (bad signature, wrong audience, wrong issuer) use the suite's issuer,
//! whose key never changes. These change the key set
//! itself while the proxy is running: each test serves a JWKS from an origin of its own (which the
//! proxy is pointed at) and signs tokens with the matching keys. The cache duration is set low so
//! the proxy's scheduled refresh picks up a change within the test's lifetime. RFC 7517.

use libra_test_harness::{
    identity::claims,
    origin::{CannedResponse, Origin},
    proxy::Proxy,
    proxy_settings::{JwtSettings, ProxySettings},
    signing_key::SigningKey,
    stack::Endpoints,
};
use reqwest::{StatusCode, blocking::Response};
use std::{thread::sleep, time::Duration};

/// A read restriction for the signed subject, with no tenant condition so no tenant header is needed.
const ALLOW_READ: &str = r#"
[[policy]]
id = "allow-read"
priority = 100

[policy.condition]
users = ["writer"]
operations = ["read"]

[policy.access]
effect = "allow"
"#;

/// A proxy that fetches its keys from `jwks_origin`, forwards to `broker_origin`, and refreshes its
/// key set every second.
fn rotating_proxy(stack: &Endpoints, jwks_origin: &Origin, broker_origin: &Origin) -> Proxy {
    let settings = ProxySettings {
        upstream: broker_origin.address(),
        jwt: Some(JwtSettings {
            jwks_url: jwks_origin.endpoint("/certs"),
            jwks_cache_duration: 1,
            ..JwtSettings::suite()
        }),
        ..ProxySettings::new(stack, ALLOW_READ)
    };

    Proxy::start(&settings)
}

/// A read carrying `bearer`.
fn read_with(proxy: &Proxy, bearer: &str) -> Response {
    proxy
        .get("/ngsi-ld/v1/entities?type=Vehicle")
        .bearer_auth(bearer)
        .send()
        .expect("the proxy should answer")
}

/// Polls a read with `bearer` until its status satisfies `done`, or gives up. Rotation is picked up
/// by a background refresh, so the first read after a swap may still see the old key set.
fn poll_until(proxy: &Proxy, bearer: &str, done: impl Fn(StatusCode) -> bool) -> StatusCode {
    for _ in 0..30 {
        let status = read_with(proxy, bearer).status();
        if done(status) {
            return status;
        }
        sleep(Duration::from_millis(500));
    }

    read_with(proxy, bearer).status()
}

#[test]
fn a_token_signed_by_a_freshly_rotated_key_is_accepted_after_refresh() {
    let stack = require_stack!();
    let current = SigningKey::generate("key-a");
    let rotated = SigningKey::generate("key-b");
    let jwks = Origin::serving("application/json", &SigningKey::jwks(&[&current]));
    let broker = Origin::serving("application/json", "[]");
    let proxy = rotating_proxy(&stack, &jwks, &broker);

    // The proxy starts trusting only key-a. A token under key-b is not yet verifiable.
    let before = read_with(&proxy, &rotated.sign(&claims("writer"))).status();
    assert_eq!(before, StatusCode::UNAUTHORIZED, "the rotated key is not trusted before the refresh");

    // Rotate the advertised key set to include key-b, then wait for the scheduled refresh to see it.
    jwks.set_response(&CannedResponse::ok("application/json", &SigningKey::jwks(&[&current, &rotated])));
    let after = poll_until(&proxy, &rotated.sign(&claims("writer")), |status| status != StatusCode::UNAUTHORIZED);

    assert_ne!(
        after,
        StatusCode::UNAUTHORIZED,
        "a token under the rotated key must be accepted after the refresh"
    );
}

#[test]
fn a_token_with_an_unknown_kid_is_refused_without_a_broker_hit() {
    let stack = require_stack!();
    let trusted = SigningKey::generate("key-a");
    let ghost = SigningKey::generate("ghost");
    let jwks = Origin::serving("application/json", &SigningKey::jwks(&[&trusted]));
    let broker = Origin::serving("application/json", "[]");
    let proxy = rotating_proxy(&stack, &jwks, &broker);

    // The token's key is not in the JWKS and never will be; even a refresh cannot find it.
    let response = read_with(&proxy, &ghost.sign(&claims("writer")));

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "a token under an unknown key must be refused");
    assert!(broker.last_request().is_none(), "authentication must fail before the broker is ever reached");
}

#[test]
fn a_retired_key_no_longer_validates() {
    let stack = require_stack!();
    let retiring = SigningKey::generate("key-a");
    let replacement = SigningKey::generate("key-b");
    let jwks = Origin::serving("application/json", &SigningKey::jwks(&[&retiring]));
    let broker = Origin::serving("application/json", "[]");
    let proxy = rotating_proxy(&stack, &jwks, &broker);

    let before = read_with(&proxy, &retiring.sign(&claims("writer"))).status();
    assert_ne!(before, StatusCode::UNAUTHORIZED, "the initial key should validate");

    // Replace the key set entirely; key-a is not advertised.
    jwks.set_response(&CannedResponse::ok("application/json", &SigningKey::jwks(&[&replacement])));
    let retired = poll_until(&proxy, &retiring.sign(&claims("writer")), |status| status == StatusCode::UNAUTHORIZED);

    assert_eq!(
        retired,
        StatusCode::UNAUTHORIZED,
        "a token under the retired key must stop validating after the refresh"
    );

    // And the replacement is honoured, which confirms the refresh happened rather than the key set
    // simply becoming unreadable.
    let replacement_status = read_with(&proxy, &replacement.sign(&claims("writer"))).status();
    assert_ne!(
        replacement_status,
        StatusCode::UNAUTHORIZED,
        "the replacement key must validate after the refresh"
    );
}
