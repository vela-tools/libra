//! Writes judged by the scopes of the entities they would change, and the bounds on pre-flighting
//! them.

use crate::layer::tests::*;
use libra_entity_preflight::batch::MAX_BATCH_ENTITIES;
use pretty_assertions::assert_eq;
use wiremock::matchers::{method, path};

/// A broker holding one entity in `/Berlin/x`, at the endpoint `collection` names, and nothing else.
async fn holding_berlin(collection: &str) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/ngsi-ld/v1/{collection}/{ENTITY}")))
        .respond_with(json_response(&scoped(json!("/Berlin/x"))))
        .mount(&server)
        .await;
    Mock::given(any()).respond_with(ResponseTemplate::new(404)).mount(&server).await;

    server
}

/// How many pre-flights a broker was asked.
async fn asked(server: &MockServer) -> usize {
    server.received_requests().await.unwrap_or_default().len()
}

/// One entity declaring `/Madrid/x`, as a batch.
fn declared_in_madrid() -> String {
    format!(r#"[{{"id":"{ENTITY}","type":"Vehicle","scope":"/Madrid/x"}}]"#)
}

#[tokio::test]
async fn a_batch_update_of_an_entity_stored_in_a_forbidden_scope_is_refused() {
    let server = holding_berlin("entities").await;
    let seen = Seen::default();

    let response = run(
        &server.uri(),
        request(
            Method::POST,
            "/ngsi-ld/v1/entityOperations/update",
            Some(allow_decision()),
            &declared_in_madrid(),
        ),
        &seen,
    )
    .await;

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(seen.uri(), None);
}

#[tokio::test]
async fn a_batch_upsert_of_an_entity_the_broker_does_not_hold_is_forwarded() {
    let server = failing_broker(404).await;
    let seen = Seen::default();

    let response = run(
        &server.uri(),
        request(
            Method::POST,
            "/ngsi-ld/v1/entityOperations/upsert",
            Some(allow_decision()),
            &declared_in_madrid(),
        ),
        &seen,
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(seen.uri().as_deref(), Some("/ngsi-ld/v1/entityOperations/upsert"));
    assert_eq!(asked(&server).await, 1);
}

#[tokio::test]
async fn a_batch_upsert_declaring_a_forbidden_scope_is_refused_without_a_pre_flight() {
    let server = failing_broker(404).await;

    let response = run(
        &server.uri(),
        request(
            Method::POST,
            "/ngsi-ld/v1/entityOperations/upsert",
            Some(allow_decision()),
            &format!(r#"[{{"id":"{ENTITY}","type":"Vehicle","scope":"/Berlin/x"}}]"#),
        ),
        &Seen::default(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(asked(&server).await, 0, "the body is judged before the broker is asked");
}

#[tokio::test]
async fn a_batch_merge_of_an_allowed_entity_is_forwarded() {
    let server = broker(scoped(json!("/Madrid/x"))).await;
    let seen = Seen::default();

    let response = run(
        &server.uri(),
        request(
            Method::POST,
            "/ngsi-ld/v1/entityOperations/merge",
            Some(allow_decision()),
            &declared_in_madrid(),
        ),
        &seen,
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(seen.uri().as_deref(), Some("/ngsi-ld/v1/entityOperations/merge"));
}

#[tokio::test]
async fn a_temporal_create_on_an_entity_stored_in_a_forbidden_scope_is_refused() {
    // NGSI-LD 5.6.11: the create adds to the stored temporal evolution of an entity of that id.
    let server = holding_berlin("temporal/entities").await;
    let seen = Seen::default();

    let response = run(
        &server.uri(),
        request(
            Method::POST,
            "/ngsi-ld/v1/temporal/entities",
            Some(allow_decision()),
            &format!(r#"{{"id":"{ENTITY}","type":"Vehicle","scope":"/Madrid/x"}}"#),
        ),
        &seen,
    )
    .await;

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(seen.uri(), None);
}

#[tokio::test]
async fn a_batch_create_is_not_pre_flighted() {
    // A create never overwrites, so there is nothing stored to judge it by.
    let server = failing_broker(500).await;
    let seen = Seen::default();

    for (uri, body) in [
        ("/ngsi-ld/v1/entityOperations/create", declared_in_madrid()),
        ("/ngsi-ld/v1/entities", format!(r#"{{"id":"{ENTITY}","type":"Vehicle","scope":"/Madrid/x"}}"#)),
    ] {
        let response = run(&server.uri(), request(Method::POST, uri, Some(allow_decision()), &body), &seen).await;

        assert_eq!(response.status(), StatusCode::OK, "{uri}");
    }
    assert_eq!(asked(&server).await, 0);
}

#[tokio::test]
async fn a_batch_delete_of_an_entity_the_broker_does_not_hold_is_refused_as_one_outside_the_restriction() {
    let server = failing_broker(404).await;

    let response = run(
        &server.uri(),
        request(
            Method::POST,
            "/ngsi-ld/v1/entityOperations/delete",
            Some(allow_decision()),
            &format!(r#"["{ENTITY}"]"#),
        ),
        &Seen::default(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn repeated_identifiers_in_a_batch_delete_are_pre_flighted_once() {
    let server = broker(scoped(json!("/Madrid/x"))).await;

    let response = run(
        &server.uri(),
        request(
            Method::POST,
            "/ngsi-ld/v1/entityOperations/delete",
            Some(allow_decision()),
            r#"["urn:ngsi-ld:Vehicle:1","urn:ngsi-ld:Vehicle:2","urn:ngsi-ld:Vehicle:1"]"#,
        ),
        &Seen::default(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(asked(&server).await, 2);
}

/// A batch body naming one more distinct entity than the bound, each as `shape` writes it.
fn past_the_limit(shape: impl Fn(usize) -> String) -> String {
    let items: Vec<String> = (0..=MAX_BATCH_ENTITIES).map(shape).collect();

    format!("[{}]", items.join(","))
}

#[tokio::test]
async fn a_batch_past_the_limit_is_refused_before_any_pre_flight() {
    let server = broker(scoped(json!("/Madrid/x"))).await;

    for (uri, body) in [
        ("/ngsi-ld/v1/entityOperations/delete", past_the_limit(|n| format!(r#""urn:e:{n}""#))),
        (
            "/ngsi-ld/v1/entityOperations/merge",
            past_the_limit(|n| format!(r#"{{"id":"urn:e:{n}","type":"Vehicle","scope":"/Madrid/x"}}"#)),
        ),
    ] {
        let seen = Seen::default();
        let response = run(&server.uri(), request(Method::POST, uri, Some(allow_decision()), &body), &seen).await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{uri}");
        assert_eq!(seen.uri(), None, "{uri}");
    }
    assert_eq!(asked(&server).await, 0);
}
