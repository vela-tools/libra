//! Query answers judged entity by entity, as reads by identifier are.

use crate::layer::tests::*;
use pretty_assertions::assert_eq;

/// The answer a type-restricted caller is given when the broker answers `answer` labelled
/// `content_type`.
async fn answered(method: Method, uri: &str, body: &str, content_type: &'static str, answer: &Value) -> Response {
    run_with(
        "http://127.0.0.1:1",
        request(method, uri, Some(decision(restriction(&["Vehicle"], MemberOnWrite::Optional))), body),
        index_upstream(content_type, answer.to_string()),
    )
    .await
}

async fn answer_of(response: Response) -> Value {
    strict::parse(body_of(response).await.as_bytes()).expect("JSON")
}

#[tokio::test]
async fn a_collection_answer_withholds_an_entity_with_a_type_outside_the_restriction() {
    // A broker matches `type=Vehicle` against any one of an entity's types (NGSI-LD 4.17), so an
    // entity that is also a `Secret` comes back. A read of it by identifier is refused.
    let answer = json!([{ "id": "urn:1", "type": ["Vehicle", "Secret"] }, { "id": "urn:2", "type": "Vehicle" }]);

    let response = answered(Method::GET, "/ngsi-ld/v1/entities?type=Vehicle", "", "application/json", &answer).await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(answer_of(response).await, json!([{ "id": "urn:2", "type": "Vehicle" }]));
}

#[tokio::test]
async fn a_collection_answer_keeps_entities_of_allowed_types() {
    let answer = json!([{ "id": "urn:1", "type": "Vehicle" }, { "id": "urn:2", "type": ["Car", VEHICLE] }]);

    let response = answered(Method::GET, "/ngsi-ld/v1/entities?type=Vehicle", "", "application/json", &answer).await;

    assert_eq!(answer_of(response).await, answer);
}

#[tokio::test]
async fn an_answer_entity_without_a_readable_type_is_withheld() {
    let answer = json!([{ "id": "urn:none" }, { "id": "urn:number", "type": 7 }, { "id": "urn:v", "type": "Vehicle" }]);

    let response = answered(Method::GET, "/ngsi-ld/v1/entities?type=Vehicle", "", "application/json", &answer).await;

    assert_eq!(answer_of(response).await, json!([{ "id": "urn:v", "type": "Vehicle" }]));
}

#[tokio::test]
async fn a_batch_query_answer_is_judged_per_entity() {
    let answer = json!([{ "id": "urn:1", "type": "Building" }, { "id": "urn:2", "type": "Vehicle" }]);

    let response = answered(
        Method::POST,
        "/ngsi-ld/v1/entityOperations/query",
        r#"{"type":"Query","entities":[{"type":"Vehicle"}]}"#,
        "application/json",
        &answer,
    )
    .await;

    assert_eq!(answer_of(response).await, json!([{ "id": "urn:2", "type": "Vehicle" }]));
}

#[tokio::test]
async fn a_temporal_answer_is_judged_per_entity() {
    let answer = json!([
        { "id": "urn:1", "type": ["Vehicle", "Building"], "speed": [{ "type": "Property", "value": 1 }] },
        { "id": "urn:2", "type": "Vehicle", "speed": [{ "type": "Property", "value": 2 }] }
    ]);

    for (method, uri, body) in [
        (
            Method::GET,
            "/ngsi-ld/v1/temporal/entities?type=Vehicle&timerel=after&timeAt=2020-01-01T00:00:00Z",
            "",
        ),
        (
            Method::POST,
            "/ngsi-ld/v1/temporal/entityOperations/query",
            r#"{"type":"Query","entities":[{"type":"Vehicle"}]}"#,
        ),
    ] {
        let response = answered(method, uri, body, "application/json", &answer).await;

        assert_eq!(
            answer_of(response).await,
            json!([{ "id": "urn:2", "type": "Vehicle", "speed": [{ "type": "Property", "value": 2 }] }]),
            "{uri}"
        );
    }
}

#[tokio::test]
async fn a_geo_json_feature_collection_is_judged_per_feature() {
    let answer = json!({ "type": "FeatureCollection", "features": [
        { "id": "urn:1", "type": "Feature", "properties": { "type": "Building" }, "geometry": null },
        { "id": "urn:2", "type": "Feature", "properties": { "type": "Vehicle" }, "geometry": null }
    ] });

    let response = answered(Method::GET, "/ngsi-ld/v1/entities?type=Vehicle", "", "application/geo+json", &answer).await;

    assert_eq!(
        answer_of(response).await,
        json!({ "type": "FeatureCollection", "features": [{ "id": "urn:2", "type": "Feature", "properties": { "type": "Vehicle" }, "geometry": null }] })
    );
}

#[tokio::test]
async fn an_unrestricted_collection_answer_is_forwarded_byte_for_byte() {
    const ANSWER: &str = r#"[ { "id" : "urn:1", "type" : [ "Vehicle", "Secret" ], "speed" : 1.0 } ]"#;

    let response = run_with(
        "http://127.0.0.1:1",
        request(Method::GET, "/ngsi-ld/v1/entities?type=Vehicle", Some(unrestricted()), ""),
        index_upstream("application/json", ANSWER),
    )
    .await;

    assert_eq!(body_of(response).await, ANSWER);
}
