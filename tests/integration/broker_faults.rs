//! What Libra does when the thing it fronts answers badly.
//!
//! Fail closed is the whole point of a filtering proxy: a response the filter cannot walk must not
//! reach the caller, because "could not filter" and "nothing to hide" look identical from the
//! outside. These drive a controllable origin in place of the broker so the awkward answers (a
//! server error, a non-JSON body, a compressed body, unparseable JSON) can be produced on demand,
//! and assert that a restricted read either sees the fault or is withheld, never the hidden data.
//!
//! Every test here runs under an attribute restriction, because a response is only filtered when
//! one is in force (`libra-enforcement-attribute`); without it the proxy is a pass-through and none of
//! these guards apply.

use libra_test_harness::{
    identity::token,
    origin::{CannedResponse, Origin, address},
    proxy::Proxy,
    proxy_settings::ProxySettings,
    stack::Endpoints,
};
use reqwest::{StatusCode, blocking::Response};

/// The tenant these reads name.
const TENANT: &str = "gardens";

/// A policy allowing the writer reads with one attribute hidden, which is what puts the response
/// filter in the request path.
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

/// Starts a proxy whose upstream is `origin` rather than the broker, under [`OMIT_LOCATION`].
fn proxy_fronting(stack: &Endpoints, origin: &Origin) -> Proxy {
    let settings = ProxySettings {
        upstream: origin.address(),
        ..ProxySettings::new(stack, OMIT_LOCATION)
    };

    Proxy::start(&settings)
}

/// The read every test issues: a restricted collection read, so the response filter runs.
fn restricted_read(proxy: &Proxy) -> Response {
    proxy
        .get("/ngsi-ld/v1/entities?type=Vehicle")
        .header("NGSILD-Tenant", TENANT)
        .bearer_auth(token("writer"))
        .send()
        .expect("the proxy should answer")
}

#[test]
fn a_broker_5xx_is_not_masked_as_success() {
    let stack = require_stack!();
    // A broker that is unwell answers 503. The filter must not turn that into a 200 with an empty
    // body: a caller that asked for data and got an empty success would read it as "there is none".
    let origin = Origin::replying(&CannedResponse {
        status: 503,
        content_type: "application/json".to_owned(),
        content_encoding: None,
        body: r#"{"error":"unavailable"}"#.to_owned(),
    });
    let proxy = proxy_fronting(&stack, &origin);

    let response = restricted_read(&proxy);

    assert_eq!(
        response.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "an upstream error must reach the caller as an error, never as a filtered success"
    );
}

#[test]
fn a_non_json_success_body_under_a_restriction_is_refused() {
    let stack = require_stack!();
    // A 200 whose body is not JSON cannot be filtered as an entity. Forwarding it would hand the
    // caller a body the policy was never applied to.
    let origin = Origin::replying(&CannedResponse {
        status: 200,
        content_type: "text/html".to_owned(),
        content_encoding: None,
        body: "<html><body>not an entity</body></html>".to_owned(),
    });
    let proxy = proxy_fronting(&stack, &origin);

    let response = restricted_read(&proxy);

    assert_eq!(
        response.status(),
        StatusCode::BAD_GATEWAY,
        "a non-JSON success under a restriction must be withheld, not forwarded unfiltered"
    );
}

#[test]
fn a_content_encoded_success_under_a_restriction_is_refused() {
    let stack = require_stack!();
    // Libra strips `Accept-Encoding` on the way out precisely so it never has to filter a
    // compressed body. A broker that compresses anyway produces one the filter cannot walk, and it
    // must be withheld rather than passed through.
    let origin = Origin::replying(&CannedResponse {
        status: 200,
        content_type: "application/json".to_owned(),
        content_encoding: Some("gzip".to_owned()),
        body: r#"[{"id":"urn:ngsi-ld:Vehicle:1","type":"Vehicle"}]"#.to_owned(),
    });
    let proxy = proxy_fronting(&stack, &origin);

    let response = restricted_read(&proxy);

    assert_eq!(
        response.status(),
        StatusCode::BAD_GATEWAY,
        "a content-encoded success under a restriction must be withheld"
    );
}

#[test]
fn an_unparseable_json_success_under_a_restriction_is_refused() {
    let stack = require_stack!();
    // The content type claims JSON but the bytes are not. The filter cannot walk what it cannot
    // parse, so the body is withheld rather than forwarded on the strength of its header alone.
    let origin = Origin::replying(&CannedResponse {
        status: 200,
        content_type: "application/json".to_owned(),
        content_encoding: None,
        body: r#"[{"id":"urn:ngsi-ld:Vehicle:1", broken"#.to_owned(),
    });
    let proxy = proxy_fronting(&stack, &origin);

    let response = restricted_read(&proxy);

    assert_eq!(
        response.status(),
        StatusCode::BAD_GATEWAY,
        "an unparseable JSON success under a restriction must be withheld"
    );
}

#[test]
fn an_error_body_is_passed_through_unfiltered() {
    let stack = require_stack!();
    // A problem-details error carries a description, not attribute values, and the caller needs to
    // see it to know what went wrong. The filter must leave both the status and the body alone.
    let problem = r#"{"type":"https://uri.etsi.org/ngsi-ld/errors/BadRequestData","title":"Bad Request","detail":"the marker phrase brokentype is preserved"}"#;
    let origin = Origin::replying(&CannedResponse {
        status: 400,
        content_type: "application/problem+json".to_owned(),
        content_encoding: None,
        body: problem.to_owned(),
    });
    let proxy = proxy_fronting(&stack, &origin);

    let response = restricted_read(&proxy);
    let status = response.status();
    let body = response.text().unwrap_or_default();

    assert_eq!(status, StatusCode::BAD_REQUEST, "the upstream error status must be preserved");
    assert!(
        body.contains("brokentype is preserved"),
        "the error body must reach the caller unfiltered: {body}"
    );
}

#[test]
fn a_proxy_at_its_in_flight_ceiling_refuses_the_next_request() {
    use std::{io, net::TcpListener, thread, time::Duration};

    let stack = require_stack!();
    // An origin that accepts and never answers pins the one slot the ceiling allows. The refusal
    // must be a real 503 answer rather than a transport failure, so the audit layer records it as
    // an answer and the caller can tell a full proxy from a broken one.
    let stalled = TcpListener::bind("127.0.0.1:0").expect("a port to hold open");
    let stalled_address = stalled.local_addr().expect("the bound address");
    thread::spawn(move || {
        for stream in stalled.incoming() {
            match stream {
                Ok(connection) => {
                    thread::spawn(move || {
                        // The connection is held open, read from and written to by nobody. It has
                        // to stay bound for the loop's lifetime: a wildcard binding would drop it
                        // and close the connection the stall depends on.
                        let held_open = connection;
                        let _held_open = &held_open;
                        loop {
                            thread::sleep(Duration::from_secs(3600));
                        }
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => return,
            }
        }
    });

    let settings = ProxySettings {
        upstream: address(&format!("http://{stalled_address}")),
        extra_sections: "[limits]\nmax-in-flight-requests = 1\n".to_owned(),
        ..ProxySettings::new(&stack, OMIT_LOCATION)
    };
    let proxy = Proxy::start(&settings);

    // Two probes overlap. Whichever of the pair reaches the stalled origin first parks there
    // holding the one slot, and the other must be refused while the slot is held. A probe refused
    // earlier than that, for anything the proxy will not forward, comes back fast with its own
    // status; a probe that times out was admitted and parked, and its caller leaving is what
    // releases the slot again.
    let first = proxy
        .get("/ngsi-ld/v1/entities?type=Vehicle")
        .header("NGSILD-Tenant", TENANT)
        .bearer_auth(token("writer"))
        .timeout(Duration::from_secs(3));
    let first = thread::spawn(move || first.send());

    thread::sleep(Duration::from_millis(300));

    let second = proxy
        .get("/ngsi-ld/v1/entities?type=Vehicle")
        .header("NGSILD-Tenant", TENANT)
        .bearer_auth(token("writer"))
        .timeout(Duration::from_secs(3))
        .send()
        .expect("the proxy should answer the second probe");

    assert_eq!(
        second.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "the request meeting the held ceiling must be refused, not queued or forwarded"
    );
    assert_eq!(
        second.headers().get("content-type").map(|value| value.to_str().unwrap_or_default()),
        Some("application/problem+json"),
        "the refusal must be a problem-details response"
    );
    // The renderer keeps detail text generic for a 503, so the body names the type and the status.
    let body = second.text().unwrap_or_default();
    assert!(body.contains("ServiceUnavailable"), "{body}");
    assert!(body.contains("\"status\":503"), "{body}");

    // The first probe stays parked on the origin until its own client timeout; joining it is the
    // test's way of waiting out the connection it holds.
    let _ = first.join();
}
