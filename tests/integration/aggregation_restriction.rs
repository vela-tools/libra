//! Aggregation restrictions on temporal reads.
//!
//! A policy can insist that history is only ever read in aggregate: an average per hour rather than
//! every instant that made it. The restriction is worth nothing unless the method and the period
//! are both checked, because either one alone lets the caller reconstruct what the other hides.

use jiff::Timestamp;
use libra_test_harness::{identity::token, proxy::Proxy, proxy_settings::ProxySettings};
use reqwest::StatusCode;

/// Allows the writer aggregated reads only, by one method, at no finer than an hour.
const POLICIES: &str = r#"
[[policy]]
id = "hourly-averages"
priority = 100

[policy.condition]
users = ["writer"]
operations = ["read"]

[policy.access]
effect = "allow"

[policy.access.aggregation]
unaggregated = "disallowed"
allowed-methods = ["avg"]
min-period-duration = "PT1H"
"#;

/// A temporal query for the last two hours, with whatever aggregation the test is about.
fn query(aggregation: &str) -> String {
    // A closed window on the hour grid, two periods long: under a minimum period of `PT1H` an
    // aggregated read is answered only on that grid, so a test about the method or the period is
    // not refused for its window first.
    let hour = 3600;
    let start = Timestamp::from_second((Timestamp::now().as_second() / hour - 3) * hour).expect("the hour should be representable");
    let end = Timestamp::from_second(start.as_second() + 2 * hour).expect("the hour should be representable");
    let format = |instant: Timestamp| instant.strftime("%Y-%m-%dT%H:%M:%SZ");

    format!(
        "/ngsi-ld/v1/temporal/entities?type=Vehicle&timerel=between&timeAt={}&endTimeAt={}{aggregation}",
        format(start),
        format(end)
    )
}

#[test]
fn a_temporal_query_asking_for_no_aggregation_is_refused() {
    let stack = require_stack!();
    let proxy = Proxy::start(&ProxySettings::new(&stack, POLICIES));

    let response = proxy.get(&query("")).bearer_auth(token("writer")).send().expect("the proxy should answer");

    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "reading every instant is what the policy exists to prevent"
    );
}

#[test]
fn methods_without_aggregated_values_are_refused() {
    let stack = require_stack!();
    let proxy = Proxy::start(&ProxySettings::new(&stack, POLICIES));

    // Without `aggregatedValues` the broker ignores the methods and answers with every instance.
    let response = proxy
        .get(&query("&aggrMethods=avg&aggrPeriodDuration=PT1H"))
        .bearer_auth(token("writer"))
        .send()
        .expect("the proxy should answer");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[test]
fn a_method_the_policy_does_not_allow_is_refused() {
    let stack = require_stack!();
    let proxy = Proxy::start(&ProxySettings::new(&stack, POLICIES));

    let response = proxy
        .get(&query("&options=aggregatedValues&aggrMethods=max&aggrPeriodDuration=PT1H"))
        .bearer_auth(token("writer"))
        .send()
        .expect("the proxy should answer");

    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "a maximum is not an average, and the policy names one of them"
    );
}

#[test]
fn a_period_finer_than_the_minimum_is_refused() {
    let stack = require_stack!();
    let proxy = Proxy::start(&ProxySettings::new(&stack, POLICIES));

    // Per-minute averages over a slow-moving series are the series. The minimum period is the
    // half of the restriction that stops the aggregate being a reconstruction.
    let response = proxy
        .get(&query("&options=aggregatedValues&aggrMethods=avg&aggrPeriodDuration=PT1M"))
        .bearer_auth(token("writer"))
        .send()
        .expect("the proxy should answer");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[test]
fn an_aggregation_the_policy_allows_is_answered() {
    let stack = require_stack!();
    let proxy = Proxy::start(&ProxySettings::new(&stack, POLICIES));

    let response = proxy
        .get(&query("&options=aggregatedValues&aggrMethods=avg&aggrPeriodDuration=PT1H"))
        .bearer_auth(token("writer"))
        .send()
        .expect("the proxy should answer");

    assert_ne!(
        response.status(),
        StatusCode::FORBIDDEN,
        "the method and the period are both within the restriction: {}",
        response.text().unwrap_or_default()
    );
}
