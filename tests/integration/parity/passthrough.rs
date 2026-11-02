//! Non-restricted pass-through parity.
//!
//! When no restriction is attached to a request, Libra executes `oneshot` untouched.
//! Parity here is byte-identical: the raw response bytes received from direct Scorpio
//! must match the proxied bytes bit for bit, across representations and media types.

use crate::parity::harness::{direct_get_raw, proxied_get_raw, seed_standard_vehicle, unrestricted_policy};
use libra_test_harness::{
    broker::unique_id,
    identity::token,
    origin::{CannedResponse, Origin},
    proxy::Proxy,
    proxy_settings::ProxySettings,
};
use reqwest::{StatusCode, blocking::Client};

const TENANT: &str = "fleet";

#[test]
fn an_unrestricted_entity_read_is_byte_identical() {
    let stack = require_stack!();
    let id = unique_id("Vehicle");
    seed_standard_vehicle(&stack, Some(TENANT), &id);

    let proxy = Proxy::start(&ProxySettings::new(&stack, &unrestricted_policy(TENANT)));
    let bearer = token("writer");
    let path = format!("/ngsi-ld/v1/entities/{id}");
    let headers = [("Accept", "application/ld+json")];

    let (direct_status, _, direct_bytes) = direct_get_raw(&stack, Some(TENANT), &path, &headers);
    let (proxied_status, _, proxied_bytes) = proxied_get_raw(&proxy, Some(TENANT), Some(&bearer), &path, &headers);

    assert_eq!(direct_status, StatusCode::OK);
    assert_eq!(proxied_status, StatusCode::OK);
    assert_eq!(direct_bytes, proxied_bytes, "unrestricted entity read should return identical raw bytes");
}

#[test]
fn an_unrestricted_collection_read_is_byte_identical() {
    let stack = require_stack!();
    let id = unique_id("Vehicle");
    seed_standard_vehicle(&stack, Some(TENANT), &id);

    let proxy = Proxy::start(&ProxySettings::new(&stack, &unrestricted_policy(TENANT)));
    let bearer = token("writer");
    // Selected by identifier: the tenant is shared with tests running at the same time, and two reads
    // of every `Vehicle` in it would differ whenever one of them seeded another between the reads.
    let path = format!("/ngsi-ld/v1/entities?type=Vehicle&id={id}");
    let headers = [("Accept", "application/json")];

    let (direct_status, _, direct_bytes) = direct_get_raw(&stack, Some(TENANT), &path, &headers);
    let (proxied_status, _, proxied_bytes) = proxied_get_raw(&proxy, Some(TENANT), Some(&bearer), &path, &headers);

    assert_eq!(direct_status, StatusCode::OK);
    assert_eq!(proxied_status, StatusCode::OK);
    assert_eq!(direct_bytes, proxied_bytes, "unrestricted collection read should return identical raw bytes");
}

#[test]
fn an_unrestricted_read_is_byte_identical_across_representations() {
    let stack = require_stack!();
    let id = unique_id("Vehicle");
    seed_standard_vehicle(&stack, Some(TENANT), &id);

    let proxy = Proxy::start(&ProxySettings::new(&stack, &unrestricted_policy(TENANT)));
    let bearer = token("writer");

    let cases = [
        // normalized across media types
        (format!("/ngsi-ld/v1/entities/{id}"), "application/json"),
        (format!("/ngsi-ld/v1/entities/{id}"), "application/ld+json"),
        (format!("/ngsi-ld/v1/entities/{id}"), "application/geo+json"),
        // concise across media types
        (format!("/ngsi-ld/v1/entities/{id}?options=concise"), "application/json"),
        (format!("/ngsi-ld/v1/entities/{id}?options=concise"), "application/ld+json"),
        // keyValues across media types
        (format!("/ngsi-ld/v1/entities/{id}?options=keyValues"), "application/json"),
        (format!("/ngsi-ld/v1/entities/{id}?options=keyValues"), "application/ld+json"),
    ];

    for (path, media_type) in cases {
        let headers = [("Accept", media_type)];
        let (direct_status, _, direct_bytes) = direct_get_raw(&stack, Some(TENANT), &path, &headers);
        let (proxied_status, _, proxied_bytes) = proxied_get_raw(&proxy, Some(TENANT), Some(&bearer), &path, &headers);

        assert_eq!(direct_status, StatusCode::OK, "direct read failed for {path} ({media_type})");
        assert_eq!(proxied_status, StatusCode::OK, "proxied read failed for {path} ({media_type})");
        assert_eq!(direct_bytes, proxied_bytes, "raw bytes mismatch for {path} under {media_type}");
    }
}

#[test]
fn an_unrestricted_response_keeps_broker_compression() {
    let stack = require_stack!();
    let canned_body = r#"{"id":"urn:ngsi-ld:Vehicle:canned","type":"Vehicle","speed":100}"#;
    let origin = Origin::replying(&CannedResponse {
        status: 200,
        content_type: "application/json".to_owned(),
        content_encoding: Some("gzip".to_owned()),
        body: canned_body.to_owned(),
    });

    let settings = ProxySettings {
        upstream: origin.address(),
        ..ProxySettings::new(&stack, &unrestricted_policy(TENANT))
    };
    let proxy = Proxy::start(&settings);
    let bearer = token("writer");
    let path = "/ngsi-ld/v1/entities/urn:ngsi-ld:Vehicle:canned";
    let headers = [("Accept", "application/json"), ("Accept-Encoding", "gzip")];

    let mut direct_request = Client::new().get(format!("{}{path}", origin.url())).header("NGSILD-Tenant", TENANT);
    for (name, val) in headers {
        direct_request = direct_request.header(name, val);
    }
    let direct_response = direct_request.send().expect("origin should answer");
    let direct_encoding = direct_response.headers().get("content-encoding").cloned();
    let direct_bytes = direct_response.bytes().expect("bytes should read").to_vec();

    let (proxied_status, proxied_headers, proxied_bytes) = proxied_get_raw(&proxy, Some(TENANT), Some(&bearer), path, &headers);

    assert_eq!(proxied_status, StatusCode::OK);
    assert_eq!(
        proxied_headers.get("content-encoding"),
        direct_encoding.as_ref(),
        "proxied response must preserve the upstream Content-Encoding"
    );
    assert_eq!(direct_bytes, proxied_bytes, "proxied compressed bytes must be byte-identical to upstream");
}
