//! Writes judged by the types of the entities they would change, and the bounds on pre-flighting
//! them.

use crate::layer::tests::*;
use libra_entity_preflight::batch::MAX_BATCH_ENTITIES;
use pretty_assertions::assert_eq;
use wiremock::matchers::{method, path};

/// A broker holding one entity under `stored`, at the endpoint `collection` names, and nothing else.
async fn holding(collection: &str, stored: &str) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/ngsi-ld/v1/{collection}/{ENTITY}")))
        .respond_with(json_response(&typed(stored)))
        .mount(&server)
        .await;
    Mock::given(any()).respond_with(ResponseTemplate::new(404)).mount(&server).await;

    server
}

/// How many pre-flights a broker was asked.
async fn asked(server: &MockServer) -> usize {
    server.received_requests().await.unwrap_or_default().len()
}

fn vehicles() -> Decision {
    decision(restriction(&["Vehicle"], MemberOnWrite::Required))
}

#[tokio::test]
async fn a_batch_update_of_an_entity_stored_under_a_forbidden_type_is_refused() {
    // The body declares an allowed type; the entity it would change is stored under another.
    let server = holding("entities", "Secret").await;
    let seen = Seen::default();

    let response = run(
        &server.uri(),
        request(
            Method::POST,
            "/ngsi-ld/v1/entityOperations/update",
            Some(vehicles()),
            &format!(r#"[{{"id":"{ENTITY}","type":"Vehicle","speed":{{"type":"Property","value":1}}}}]"#),
        ),
        &seen,
    )
    .await;

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(seen.uri(), None, "nothing reaches the broker's write endpoint");
}

#[tokio::test]
async fn a_batch_upsert_of_an_entity_the_broker_does_not_hold_is_forwarded() {
    // The broker answers 404, so the upsert creates the entity with the type its body declares.
    let server = failing_broker(404).await;
    let seen = Seen::default();

    let response = run(
        &server.uri(),
        request(
            Method::POST,
            "/ngsi-ld/v1/entityOperations/upsert",
            Some(vehicles()),
            r#"[{"id":"urn:ngsi-ld:Vehicle:new","type":"Vehicle"}]"#,
        ),
        &seen,
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(seen.uri().as_deref(), Some("/ngsi-ld/v1/entityOperations/upsert"));
    assert_eq!(asked(&server).await, 1);
}

#[tokio::test]
async fn a_batch_upsert_declaring_a_forbidden_type_is_refused_without_a_pre_flight() {
    let server = failing_broker(404).await;

    let response = run(
        &server.uri(),
        request(
            Method::POST,
            "/ngsi-ld/v1/entityOperations/upsert",
            Some(vehicles()),
            r#"[{"id":"urn:ngsi-ld:Vehicle:new","type":"Building"}]"#,
        ),
        &Seen::default(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(asked(&server).await, 0, "the body is judged before the broker is asked");
}

#[tokio::test]
async fn a_batch_merge_of_an_allowed_entity_is_forwarded() {
    let server = holding("entities", "Vehicle").await;
    let seen = Seen::default();

    let response = run(
        &server.uri(),
        request(
            Method::POST,
            "/ngsi-ld/v1/entityOperations/merge",
            Some(vehicles()),
            &format!(r#"[{{"id":"{ENTITY}","type":"Vehicle","speed":{{"type":"Property","value":1}}}}]"#),
        ),
        &seen,
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(seen.uri().as_deref(), Some("/ngsi-ld/v1/entityOperations/merge"));
}

#[tokio::test]
async fn a_temporal_create_on_an_entity_stored_under_a_forbidden_type_is_refused() {
    // NGSI-LD 5.6.11: the create adds to the stored temporal evolution of an entity of that id.
    let server = holding("temporal/entities", "Secret").await;
    let seen = Seen::default();

    let response = run(
        &server.uri(),
        request(
            Method::POST,
            "/ngsi-ld/v1/temporal/entities",
            Some(vehicles()),
            &format!(r#"{{"id":"{ENTITY}","type":"Vehicle","speed":[{{"type":"Property","value":1}}]}}"#),
        ),
        &seen,
    )
    .await;

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(seen.uri(), None);
}

#[tokio::test]
async fn a_temporal_create_of_an_entity_with_no_history_is_forwarded() {
    let server = failing_broker(404).await;
    let seen = Seen::default();

    let response = run(
        &server.uri(),
        request(
            Method::POST,
            "/ngsi-ld/v1/temporal/entities",
            Some(vehicles()),
            &format!(r#"{{"id":"{ENTITY}","type":"Vehicle"}}"#),
        ),
        &seen,
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(seen.uri().as_deref(), Some("/ngsi-ld/v1/temporal/entities"));
}

#[tokio::test]
async fn a_batch_create_is_not_pre_flighted() {
    // A create never overwrites, so there is nothing stored to judge it by.
    let server = failing_broker(500).await;
    let seen = Seen::default();

    for (uri, body) in [
        ("/ngsi-ld/v1/entityOperations/create", format!(r#"[{{"id":"{ENTITY}","type":"Vehicle"}}]"#)),
        ("/ngsi-ld/v1/entities", format!(r#"{{"id":"{ENTITY}","type":"Vehicle"}}"#)),
    ] {
        let response = run(&server.uri(), request(Method::POST, uri, Some(vehicles()), &body), &seen).await;

        assert_eq!(response.status(), StatusCode::OK, "{uri}");
    }
    assert_eq!(asked(&server).await, 0);
}

#[tokio::test]
async fn a_pre_flight_that_fails_other_than_not_found_refuses_a_batch_write() {
    let server = failing_broker(503).await;

    let response = run(
        &server.uri(),
        request(
            Method::POST,
            "/ngsi-ld/v1/entityOperations/upsert",
            Some(vehicles()),
            &format!(r#"[{{"id":"{ENTITY}","type":"Vehicle"}}]"#),
        ),
        &Seen::default(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
}

#[tokio::test]
async fn a_batch_write_entity_without_an_identifier_is_refused() {
    let response = run(
        "http://127.0.0.1:1",
        request(Method::POST, "/ngsi-ld/v1/entityOperations/update", Some(vehicles()), r#"[{"type":"Vehicle"}]"#),
        &Seen::default(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn a_batch_delete_of_an_entity_the_broker_does_not_hold_is_refused_as_one_of_a_forbidden_type() {
    // Unlike an upsert, a delete creates nothing: an entity whose type cannot be established is
    // one the restriction cannot be shown to cover, and it is refused exactly as one it does not.
    let server = failing_broker(404).await;

    let response = run(
        &server.uri(),
        request(
            Method::POST,
            "/ngsi-ld/v1/entityOperations/delete",
            Some(vehicles()),
            &format!(r#"["{ENTITY}"]"#),
        ),
        &Seen::default(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn repeated_identifiers_in_a_batch_delete_are_pre_flighted_once() {
    let server = broker(&typed("Vehicle")).await;

    let response = run(
        &server.uri(),
        request(
            Method::POST,
            "/ngsi-ld/v1/entityOperations/delete",
            Some(vehicles()),
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
    let server = broker(&typed("Vehicle")).await;

    for (uri, body) in [
        ("/ngsi-ld/v1/entityOperations/delete", past_the_limit(|n| format!(r#""urn:e:{n}""#))),
        (
            "/ngsi-ld/v1/entityOperations/upsert",
            past_the_limit(|n| format!(r#"{{"id":"urn:e:{n}","type":"Vehicle"}}"#)),
        ),
    ] {
        let seen = Seen::default();
        let response = run(&server.uri(), request(Method::POST, uri, Some(vehicles()), &body), &seen).await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{uri}");
        assert_eq!(seen.uri(), None, "{uri}");
    }
    assert_eq!(asked(&server).await, 0);
}
