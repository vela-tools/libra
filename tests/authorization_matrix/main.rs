#![expect(clippy::expect_used, clippy::panic, reason = "panicking is how a test harness reports a failure")]

//! Every NGSI-LD operation against every policy outcome: a deny, an unrestricted allow, and an allow
//! carrying each restriction.
//!
//! The rows are the operations clause 6 of ETSI GS CIM 009 v1.9.1 binds, and the columns are built
//! from the policy model itself, so an operation Libra learns to classify, or a restriction a policy
//! learns to carry, does not compile or does not pass until the matrix says what it expects of it.
//!
//! The binary runs against an origin standing in for the broker, so a refusal is visible as a
//! request that never arrived, and nothing here needs a broker.

mod columns;
mod routes;

use crate::{
    columns::{Column, RestrictionKind, USER},
    routes::{Outcome, Route},
};
use jiff::{SignedDuration, Timestamp};
use libra_test_harness::{
    identity::token,
    origin::{CannedResponse, Origin, Recorded},
    proxy::Proxy,
    proxy_settings::ProxySettings,
    stack::Endpoints,
};
use reqwest::StatusCode;
use std::iter::from_fn;
use strum::IntoEnumIterator;

/// What a column expects of a route.
const fn expected(column: Column, route: &Route) -> Outcome {
    match column {
        Column::Deny => Outcome::Refused(StatusCode::FORBIDDEN),
        Column::Allow => route.allowed,
        Column::Restricted(kind) => route.restricted.under(kind),
    }
}

/// Sends every route through a proxy running under `column` and reports each one that did not do
/// what the matrix expects.
fn run(column: Column) {
    let origin = Origin::serving("application/json", "{}");
    let proxy = Proxy::start(&ProxySettings {
        upstream: origin.address(),
        ..ProxySettings::new(&Endpoints { broker: origin.address() }, &column.policies())
    });
    let caller = token(USER);
    let recent = Timestamp::now()
        .checked_sub(SignedDuration::from_hours(1))
        .expect("an hour ago is an instant")
        .to_string();

    let mismatches: Vec<String> = routes::all()
        .iter()
        .filter_map(|route| {
            let (observed, answer) = send(&proxy, &origin, &caller, &recent, route);
            let expected = expected(column, route);

            (observed != Some(expected)).then(|| {
                format!(
                    "{} {} {}: expected {expected:?}, observed {observed:?}: {answer}",
                    route.clause, route.method, route.target
                )
            })
        })
        .collect();

    assert!(mismatches.is_empty(), "{column:?}:\n{}", mismatches.join("\n"));
}

/// Sends one route and reads what the proxy did with it, with the body it answered.
///
/// Forwarded is the broker's answer to this method on this path, returned; refused is a client
/// error with no such request sent; withheld is a client error after one was. Anything else, a
/// server error above all, is no outcome the matrix expects.
fn send(proxy: &Proxy, origin: &Origin, caller: &str, recent: &str, route: &Route) -> (Option<Outcome>, String) {
    drain(origin);
    origin.set_response(&CannedResponse::ok("application/json", route.answer));

    let mut request = proxy
        .request(route.method.clone(), &route.target.replace("{recent}", recent))
        .bearer_auth(caller); // the builder owns its method, the route keeps its own
    if let Some(body) = route.body {
        request = request.header("Content-Type", body.media_type).body(body.text.replace("{recent}", recent));
    }
    let response = request.send().expect("the proxy should answer");
    let status = response.status();
    let answer = response.text().expect("the answer should be readable");
    let forwarded = drain(origin)
        .iter()
        .any(|seen| seen.method == route.method.as_str() && seen.target.split('?').next() == Some(route.path()));

    let outcome = match (forwarded, status) {
        (true, StatusCode::OK) => Some(Outcome::Forwarded),
        (false, status) if status.is_client_error() => Some(Outcome::Refused(status)),
        (true, status) if status.is_client_error() => Some(Outcome::Withheld(status)),
        (true | false, _) => None,
    };

    (outcome, answer)
}

/// Every request the origin has recorded, oldest first, leaving it empty.
fn drain(origin: &Origin) -> Vec<Recorded> {
    let mut seen: Vec<Recorded> = from_fn(|| origin.last_request()).collect();
    seen.reverse();

    seen
}

#[test]
fn a_deny_refuses_every_operation_before_the_broker() {
    run(Column::Deny);
}

#[test]
fn an_unrestricted_allow_forwards_every_operation_the_binding_names() {
    run(Column::Allow);
}

/// One test per restriction kind, and a test that no kind is left without one.
macro_rules! restricted_columns {
    ($($name:ident => $kind:ident),* $(,)?) => {
        $(
            #[test]
            fn $name() {
                run(Column::Restricted(RestrictionKind::$kind));
            }
        )*

        #[test]
        fn every_restriction_kind_has_a_column() {
            assert_eq!(vec![$(RestrictionKind::$kind),*], RestrictionKind::iter().collect::<Vec<_>>());
        }
    };
}

restricted_columns! {
    a_scope_restriction_forwards_or_refuses_each_operation_as_the_matrix_says => Scope,
    an_entity_type_restriction_forwards_or_refuses_each_operation_as_the_matrix_says => EntityType,
    a_time_restriction_forwards_or_refuses_each_operation_as_the_matrix_says => Time,
    an_attribute_restriction_forwards_or_refuses_each_operation_as_the_matrix_says => Attribute,
    an_aggregation_restriction_forwards_or_refuses_each_operation_as_the_matrix_says => Aggregation,
}
