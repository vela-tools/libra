//! Temporal window enforcement: which instants a caller may read.
//!
//! Distinct from the recurring interval in a policy condition, which decides *when* a caller may
//! ask. This decides *what* they may ask about, by intersecting the window the request names with
//! the window the policy allows and refusing when the intersection is empty.

use jiff::{SignedDuration, Timestamp};
use libra_test_harness::{
    broker::{create, unique_id},
    identity::token,
    proxy::Proxy,
    proxy_settings::ProxySettings,
};
use reqwest::StatusCode;
use serde_json::{Value, json};

/// Allows the writer the last day of history and no more.
const POLICIES: &str = r#"
[[policy]]
id = "last-day"
priority = 100

[policy.condition]
users = ["writer"]
operations = ["read"]

[policy.access]
effect = "allow"

[policy.access.time]
type = "relative"
duration = "PT24H"
direction = "past"
"#;

/// Allows the writer the last day, with current-state reads answered from inside it.
const VALUES_IN_WINDOW: &str = r#"
[[policy]]
id = "last-day-values"
priority = 100

[policy.condition]
users = ["writer"]
operations = ["read"]

[policy.access]
effect = "allow"

[policy.access.time]
type = "relative"
duration = "PT24H"
direction = "past"
current-state = "values-in-window"
"#;

/// An RFC 3339 instant `hours` before now.
fn hours_ago(hours: i64) -> String {
    let instant = Timestamp::now()
        .checked_sub(SignedDuration::from_hours(hours))
        .expect("the offset should be representable");

    instant.strftime("%Y-%m-%dT%H:%M:%SZ").to_string()
}

#[test]
fn a_temporal_query_inside_the_allowed_window_is_answered() {
    let stack = require_stack!();
    let proxy = Proxy::start(&ProxySettings::new(&stack, POLICIES));

    let response = proxy
        .get(&format!(
            "/ngsi-ld/v1/temporal/entities?type=Vehicle&timerel=between&timeAt={}&endTimeAt={}",
            hours_ago(2),
            hours_ago(1)
        ))
        .bearer_auth(token("writer"))
        .send()
        .expect("the proxy should answer");

    assert_ne!(
        response.status(),
        StatusCode::FORBIDDEN,
        "the window is inside the allowed one: {}",
        response.text().unwrap_or_default()
    );
}

#[test]
fn a_temporal_query_wholly_outside_the_allowed_window_is_refused() {
    let stack = require_stack!();
    let proxy = Proxy::start(&ProxySettings::new(&stack, POLICIES));

    let response = proxy
        .get(&format!(
            "/ngsi-ld/v1/temporal/entities?type=Vehicle&timerel=between&timeAt={}&endTimeAt={}",
            hours_ago(72),
            hours_ago(48)
        ))
        .bearer_auth(token("writer"))
        .send()
        .expect("the proxy should answer");

    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "the requested window and the allowed window do not meet"
    );
}

#[test]
fn a_malformed_instant_is_reported_rather_than_quietly_replaced() {
    let stack = require_stack!();
    let proxy = Proxy::start(&ProxySettings::new(&stack, POLICIES));

    // Reading an unparseable bound as the policy's own bound would be safe with respect to the policy
    // but tells the caller nothing about the timestamp they got wrong.
    let response = proxy
        .get("/ngsi-ld/v1/temporal/entities?type=Vehicle&timerel=after&timeAt=yesterday")
        .bearer_auth(token("writer"))
        .send()
        .expect("the proxy should answer");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[test]
fn a_request_carrying_no_window_cannot_be_narrowed_and_is_refused() {
    let stack = require_stack!();
    let proxy = Proxy::start(&ProxySettings::new(&stack, POLICIES));

    // A plain entity query has no window to intersect with, so a relative restriction has nothing
    // to act on. Serving it would answer with the whole of history under a policy that allows a
    // day of it.
    let response = proxy
        .get("/ngsi-ld/v1/entities?type=Vehicle")
        .bearer_auth(token("writer"))
        .send()
        .expect("the proxy should answer");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[test]
fn values_in_window_answers_a_current_state_read_with_the_recent_observations_only() {
    let stack = require_stack!();
    let id = unique_id("Vehicle");
    create(
        &stack,
        None,
        &json!({
            "@context": "https://uri.etsi.org/ngsi-ld/v1/ngsi-ld-core-context.jsonld",
            "id": id,
            "type": "Vehicle",
            "speed": { "type": "Property", "value": 42, "observedAt": hours_ago(1) },
            "temperature": { "type": "Property", "value": 20, "observedAt": hours_ago(48) }
        }),
    );
    let proxy = Proxy::start(&ProxySettings::new(&stack, VALUES_IN_WINDOW));

    let response = proxy
        .get(&format!("/ngsi-ld/v1/entities/{id}"))
        .bearer_auth(token("writer"))
        .send()
        .expect("the proxy should answer");

    assert_eq!(response.status(), StatusCode::OK);
    let answer: Value = response.json().unwrap_or(Value::Null);
    assert_eq!(answer.pointer("/speed/value"), Some(&json!(42)), "{answer}");
    assert!(answer.get("temperature").is_none(), "the observation two days old is withheld: {answer}");
    assert!(
        answer.get("createdAt").is_none(),
        "the system attributes Libra asked for are stripped: {answer}"
    );
    assert!(answer.pointer("/speed/modifiedAt").is_none(), "{answer}");
}

#[test]
fn values_in_window_refuses_key_values_which_carry_nothing_to_date_a_value_by() {
    let stack = require_stack!();
    let proxy = Proxy::start(&ProxySettings::new(&stack, VALUES_IN_WINDOW));

    let response = proxy
        .get("/ngsi-ld/v1/entities?type=Vehicle&options=keyValues")
        .bearer_auth(token("writer"))
        .send()
        .expect("the proxy should answer");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}
