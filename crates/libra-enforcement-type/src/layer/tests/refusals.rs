//! What a type-restricted caller is refused whole, and what reaches this layer without a decision.

use crate::layer::tests::*;
use pretty_assertions::assert_eq;

fn vehicles() -> Decision {
    decision(restriction(&["Vehicle"], MemberOnWrite::Optional))
}

/// A request carrying `NGSILD-EntityMap`.
fn naming_an_entity_map(decision: Option<Decision>) -> Request {
    let mut request = request(Method::GET, "/ngsi-ld/v1/entities?type=Vehicle", decision, "");
    request
        .headers_mut()
        .insert("NGSILD-EntityMap", http::HeaderValue::from_static("urn:ngsi-ld:EntityMap:1"));

    request
}

#[tokio::test]
async fn an_entity_map_header_is_refused_under_a_restriction() {
    // NGSI-LD table 6.4.3.2-2: the broker answers from the entities the map lists, whatever the
    // `type` the request carries.
    let seen = Seen::default();

    let response = run("http://127.0.0.1:1", naming_an_entity_map(Some(vehicles())), &seen).await;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(seen.uri(), None);
}

#[tokio::test]
async fn an_entity_map_header_is_forwarded_without_one() {
    let seen = Seen::default();

    let response = run("http://127.0.0.1:1", naming_an_entity_map(Some(unrestricted())), &seen).await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(seen.uri().as_deref(), Some("/ngsi-ld/v1/entities?type=Vehicle"));
}

#[tokio::test]
async fn a_request_without_a_decision_is_refused() {
    let seen = Seen::default();

    let response = run("http://127.0.0.1:1", request(Method::GET, "/ngsi-ld/v1/entities?type=Vehicle", None, ""), &seen).await;

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(seen.uri(), None);
}

#[tokio::test]
async fn reading_subscriptions_is_refused_under_a_restriction() {
    for uri in ["/ngsi-ld/v1/subscriptions", "/ngsi-ld/v1/subscriptions/urn:ngsi-ld:Subscription:1"] {
        let seen = Seen::default();

        let response = run("http://127.0.0.1:1", request(Method::GET, uri, Some(vehicles()), ""), &seen).await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{uri}");
        assert_eq!(seen.uri(), None, "{uri}");
    }
}

#[tokio::test]
async fn updating_a_subscription_is_refused_under_a_restriction() {
    let seen = Seen::default();

    let response = run(
        "http://127.0.0.1:1",
        request(
            Method::PATCH,
            "/ngsi-ld/v1/subscriptions/urn:ngsi-ld:Subscription:1",
            Some(vehicles()),
            r#"{"entities":[{"type":"Vehicle"}]}"#,
        ),
        &seen,
    )
    .await;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(seen.uri(), None);
}

#[tokio::test]
async fn deleting_a_subscription_is_refused_under_a_restriction() {
    let seen = Seen::default();

    let response = run(
        "http://127.0.0.1:1",
        request(Method::DELETE, "/ngsi-ld/v1/subscriptions/urn:ngsi-ld:Subscription:1", Some(vehicles()), ""),
        &seen,
    )
    .await;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(seen.uri(), None);
}

#[tokio::test]
async fn creating_a_subscription_is_still_narrowed() {
    let seen = Seen::default();

    let response = run(
        "http://127.0.0.1:1",
        request(
            Method::POST,
            "/ngsi-ld/v1/subscriptions",
            Some(vehicles()),
            r#"{"type":"Subscription","entities":[{"type":"Vehicle"},{"type":"Building"}]}"#,
        ),
        &seen,
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    assert!(seen.body().contains("Vehicle"), "{}", seen.body());
    assert!(!seen.body().contains("Building"), "{}", seen.body());
}

#[tokio::test]
async fn subscriptions_are_forwarded_without_a_restriction() {
    for (method, uri) in [
        (Method::GET, "/ngsi-ld/v1/subscriptions"),
        (Method::DELETE, "/ngsi-ld/v1/subscriptions/urn:ngsi-ld:Subscription:1"),
    ] {
        let seen = Seen::default();

        let response = run("http://127.0.0.1:1", request(method, uri, Some(unrestricted()), ""), &seen).await;

        assert_eq!(response.status(), StatusCode::OK, "{uri}");
        assert_eq!(seen.uri().as_deref(), Some(uri));
    }
}
