//! Checks Libra's context rules against a real broker.
//!
//! These are the assumptions the whole term layer rests on: what a caller-supplied context does to
//! a term, what an undefined term expands to, and which context channels a request may use. They
//! were established by probing a live broker, and they are only worth anything if they keep being
//! true: a broker upgrade that changes one of them silently changes what Libra's policies mean.
//!
//! Skipped unless a parity broker is configured, so an ordinary `cargo test` does not need one.

// An integration test is not a `#[cfg(test)]` module, so the workspace's test lint exemptions do
// not reach it. A harness that panics on a broken broker is behaving correctly: the failure is the
// report.
#![expect(clippy::unwrap_used, clippy::expect_used, reason = "panicking is how a test harness reports a failure")]

use iri_rs::IriRefBuf;
use jstrict::Parse;
use libra_jsonld_context::{
    channel::{ContextChannel, channel_for},
    core_context::DEFAULT_CONTEXT_VOCABULARY,
    error::ContextError,
    resolver::CONTEXT_RELATION,
};
use reqwest::blocking::Client;
use serde_json::{Value, json};
use std::{
    env,
    time::{SystemTime, UNIX_EPOCH},
};

fn broker() -> Option<String> {
    env::var("LIBRA_PARITY_BROKER").ok().filter(|value| !value.trim().is_empty())
}

/// Unique per run, so a shared broker does not fail the suite on a leftover entity.
fn entity_id(name: &str) -> String {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    format!("urn:ngsi-ld:LibraParity:{name}:{nanos}")
}

fn post_entity(client: &Client, broker: &str, body: &Value, content_type: &str, link: Option<&str>) -> (u16, String) {
    let mut request = client
        .post(format!("{broker}/ngsi-ld/v1/entities"))
        .header("Content-Type", content_type)
        .body(serde_json::to_string(body).unwrap());

    if let Some(link) = link {
        request = request.header("Link", link);
    }

    let response = request.send().expect("the broker should answer");
    let status = response.status().as_u16();

    (status, response.text().unwrap_or_default())
}

fn get_json(client: &Client, url: &str) -> Value {
    client
        .get(url)
        .header("Accept", "application/json")
        .send()
        .expect("the broker should answer")
        .json()
        .expect("the broker should return JSON")
}

#[test]
fn a_caller_supplied_context_changes_what_a_term_means() {
    let Some(broker) = broker() else {
        eprintln!("skipping: set LIBRA_PARITY_BROKER to run the parity harness");
        return;
    };
    let client = Client::new();

    let id = entity_id("aliased");
    let alias = "https://example.test/probe#Vehicle";
    let body = json!({
        "id": id,
        "type": "Vehicle",
        "@context": { "Vehicle": alias },
    });

    let (status, response) = post_entity(&client, &broker, &body, "application/ld+json", None);
    assert_eq!(status, 201, "creating the aliased entity failed: {response}");

    let stored = get_json(&client, &format!("{broker}/ngsi-ld/v1/entities/{id}"));
    assert_eq!(
        stored["type"], alias,
        "the broker stored the alias target, not the term. If this changes, every policy that names an entity type changes meaning."
    );

    // The bypass itself: the term the request used does not find the entity the request created.
    let by_term = get_json(&client, &format!("{broker}/ngsi-ld/v1/entities?type=Vehicle"));
    assert!(
        by_term
            .as_array()
            .is_some_and(|entities| entities.iter().all(|entity| entity["id"] != id.as_str())),
        "querying the bare term must not find an entity created under an aliased context"
    );

    let escaped = alias.replace('#', "%23");
    let by_iri = get_json(&client, &format!("{broker}/ngsi-ld/v1/entities?type={escaped}"));
    assert!(
        by_iri
            .as_array()
            .is_some_and(|entities| entities.iter().any(|entity| entity["id"] == id.as_str())),
        "the expanded IRI is legal in a query parameter and must find the entity"
    );
}

#[test]
fn an_undefined_term_expands_against_the_default_context() {
    let Some(broker) = broker() else {
        eprintln!("skipping: set LIBRA_PARITY_BROKER to run the parity harness");
        return;
    };
    let client = Client::new();

    let id = entity_id("undefined");
    let body = json!({ "id": id, "type": "LibraParityWidget" });

    let (status, response) = post_entity(&client, &broker, &body, "application/json", None);
    assert_eq!(status, 201, "creating the entity failed: {response}");

    for query in [
        format!("{broker}/ngsi-ld/v1/entities?type=LibraParityWidget"),
        format!("{broker}/ngsi-ld/v1/entities?type={DEFAULT_CONTEXT_VOCABULARY}LibraParityWidget"),
    ] {
        let found = get_json(&client, &query);
        assert!(
            found
                .as_array()
                .is_some_and(|entities| entities.iter().any(|entity| entity["id"] == id.as_str())),
            "a term and its default-context IRI must be two spellings of one thing: {query}"
        );
    }
}

/// The `@context` the channel tests carry in a body.
fn context_document() -> jstrict::Value {
    jstrict::Value::parse_str(r#"{ "Thing": "https://example.test/probe#Thing" }"#).unwrap().0
}

/// The context the channel tests name in a `Link` header.
fn context_link() -> IriRefBuf {
    IriRefBuf::new("https://example.test/context.jsonld".to_owned()).unwrap()
}

#[test]
fn the_broker_refuses_the_channel_combinations_libra_refuses() {
    let Some(broker) = broker() else {
        eprintln!("skipping: set LIBRA_PARITY_BROKER to run the parity harness");
        return;
    };
    let client = Client::new();
    let link = format!("<https://example.test/context.jsonld>; rel=\"{CONTEXT_RELATION}\"; type=\"application/ld+json\"");

    let body = json!({ "id": entity_id("body-context"), "type": "Thing", "@context": { "Thing": "https://example.test/probe#Thing" } });
    let (status, response) = post_entity(&client, &broker, &body, "application/json", None);
    assert_eq!(status, 400, "the broker should refuse a body @context on application/json: {response}");
    assert!(
        matches!(
            channel_for(Some("application/json"), Some(&context_document()), &[]),
            Err(ContextError::BodyContextNotAllowed)
        ),
        "Libra must refuse it too"
    );

    let body = json!({ "id": entity_id("link-and-body"), "type": "Thing", "@context": { "Thing": "https://example.test/probe#Thing" } });
    let (status, response) = post_entity(&client, &broker, &body, "application/ld+json", Some(&link));
    assert_eq!(status, 400, "the broker should refuse a Link header on application/ld+json: {response}");
    assert!(
        matches!(
            channel_for(Some("application/ld+json"), Some(&context_document()), &[context_link()]),
            Err(ContextError::LinkHeaderNotAllowed)
        ),
        "Libra must refuse it too"
    );

    assert_eq!(
        channel_for(Some("application/json"), None, &[context_link()]).unwrap(),
        ContextChannel::LinkHeader
    );
}
