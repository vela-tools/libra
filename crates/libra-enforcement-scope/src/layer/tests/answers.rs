//! Query answers judged entity by entity, as reads by identifier are.

use crate::layer::tests::*;
use pretty_assertions::assert_eq;

/// The answer a caller restricted to `/Madrid/#` is given when the broker answers `answer`.
async fn answered(method: Method, uri: &str, body: &str, answer: &Value) -> Value {
    let response = run_replying(
        "http://127.0.0.1:1",
        request(method, uri, Some(allow_decision()), body),
        &Seen::default(),
        Reply::json(answer),
    )
    .await;

    body_json(response).await
}

#[tokio::test]
async fn a_collection_answer_withholds_an_entity_outside_the_allowed_scopes() {
    // A broker that ignored the injected `scopeQ` answers with an entity in another scope; it is
    // withheld rather than shown with its `scope` member removed.
    let answer = json!([{ "id": "urn:1", "scope": "/Berlin/x" }, { "id": "urn:2", "scope": "/Madrid/x" }]);

    assert_eq!(
        answered(Method::GET, "/ngsi-ld/v1/entities", "", &answer).await,
        json!([{ "id": "urn:2", "scope": "/Madrid/x" }])
    );
}

#[tokio::test]
async fn a_collection_answer_withholds_an_entity_without_a_scope() {
    let answer = json!([{ "id": "urn:1", "type": "Vehicle" }, { "id": "urn:2", "scope": ["/Madrid/x"] }]);

    assert_eq!(
        answered(Method::GET, "/ngsi-ld/v1/entities", "", &answer).await,
        json!([{ "id": "urn:2", "scope": ["/Madrid/x"] }])
    );
}

#[tokio::test]
async fn a_collection_answer_reduces_the_scopes_of_an_entity_in_two() {
    let answer = json!([{ "id": "urn:1", "scope": ["/Berlin/x", "/Madrid/x"] }]);

    assert_eq!(
        answered(Method::GET, "/ngsi-ld/v1/entities", "", &answer).await,
        json!([{ "id": "urn:1", "scope": ["/Madrid/x"] }])
    );
}

#[tokio::test]
async fn a_batch_query_and_a_temporal_answer_are_judged_per_entity() {
    let answer = json!([{ "id": "urn:1", "scope": "/Berlin/x" }, { "id": "urn:2" }, { "id": "urn:3", "scope": "/Madrid/x" }]);

    for (method, uri, body) in [
        (Method::POST, "/ngsi-ld/v1/entityOperations/query", r#"{"type":"Query","scopeQ":"/Madrid/#"}"#),
        (Method::GET, "/ngsi-ld/v1/temporal/entities?timerel=after&timeAt=2020-01-01T00:00:00Z", ""),
        (
            Method::POST,
            "/ngsi-ld/v1/temporal/entityOperations/query",
            r#"{"type":"Query","scopeQ":"/Madrid/#"}"#,
        ),
    ] {
        assert_eq!(
            answered(method, uri, body, &answer).await,
            json!([{ "id": "urn:3", "scope": "/Madrid/x" }]),
            "{uri}"
        );
    }
}

#[tokio::test]
async fn a_geo_json_feature_collection_is_judged_per_feature() {
    let answer = json!({ "type": "FeatureCollection", "features": [
        { "type": "Feature", "properties": { "scope": "/Berlin/x" } },
        { "type": "Feature", "properties": { "scope": "/Madrid/x" } }
    ] });

    let response = run_replying(
        "http://127.0.0.1:1",
        request(Method::GET, "/ngsi-ld/v1/entities", Some(allow_decision()), ""),
        &Seen::default(),
        Reply {
            content_type: Some("application/geo+json"),
            ..Reply::json(&answer)
        },
    )
    .await;

    assert_eq!(
        body_json(response).await,
        json!({ "type": "FeatureCollection", "features": [{ "type": "Feature", "properties": { "scope": "/Madrid/x" } }] })
    );
}

#[tokio::test]
async fn a_single_entity_answering_a_query_outside_the_allowed_scopes_is_withheld_whole() {
    let response = run_replying(
        "http://127.0.0.1:1",
        request(Method::GET, "/ngsi-ld/v1/entities", Some(allow_decision()), ""),
        &Seen::default(),
        Reply::json(&json!({ "id": "urn:1", "scope": "/Berlin/x" })),
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
}

#[tokio::test]
async fn an_unrestricted_collection_answer_is_forwarded_byte_for_byte() {
    const ANSWER: &str = r#"[ { "id" : "urn:1", "scope" : "/Berlin/x", "speed" : 1.0 }, { "id" : "urn:2" } ]"#;

    let response = run_replying(
        "http://127.0.0.1:1",
        request(Method::GET, "/ngsi-ld/v1/entities", Some(unrestricted()), ""),
        &Seen::default(),
        Reply {
            body: ANSWER.to_owned(),
            ..Reply::json(&json!([]))
        },
    )
    .await;

    let bytes = response
        .into_body()
        .collect()
        .await
        .map(http_body_util::Collected::to_bytes)
        .unwrap_or_default();
    assert_eq!(String::from_utf8_lossy(&bytes), ANSWER);
}
