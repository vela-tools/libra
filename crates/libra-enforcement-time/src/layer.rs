//! The Tower layer that holds a request to the window its policy allows.
//!
//! Placement: below authorization, so a decision exists by the time this runs, and above the
//! proxy, so the narrowed request is the one the broker sees and the filtered answer the one the
//! caller sees. A temporal query's bounds are decided entirely by what was asked for, so its answer
//! is not consulted; a current-state read under `current-state = "values-in-window"` names no
//! bounds, so its answer is what is held to the window. A request without a decision is refused as
//! a wiring fault.
//!
//! That placement is also what makes the first line of `apply` safe. A request whose decision
//! carries no time restriction is forwarded untouched, which reads like a hole and is not one:
//! authorization has already refused anything unauthorized, so the absence of a restriction here
//! means the policy that allowed the request attached none.

use crate::{
    error::TimeError,
    membership::{Membership, check_membership},
    temporal_query::{WindowPlace, judge_time_property, narrow_body, narrow_query},
    values_in_window::{self, ValuesInWindow},
};
use axum::{
    extract::Request,
    http::request::Parts,
    response::{IntoResponse, Response},
};
use jiff::Timestamp;
use libra_linked_entity_layer::servable::requested;
use libra_ngsi_ld_operation::{resource::Resource, target::EntityTarget};
use libra_ngsi_ld_operation_layer::classified::operation;
use libra_ngsi_ld_query::temporal_selector::TemporalSelector;
use libra_ngsi_ld_query_layer::parsed::parameters;
use libra_ngsi_ld_representation::representation::TemporalRepresentation;
use libra_ngsi_ld_representation_layer::RequestRepresentation;
use libra_policy_engine::decision::Decision;
use libra_policy_model::{aggregation::AggregationRestriction, aggregation_grid::AggregationGrid, time::TimeRestriction};
use std::{
    convert::Infallible,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
use tower::{Layer, Service, ServiceExt};
use tracing::warn;

/// Applies time restrictions.
#[derive(Debug, Clone, Copy)]
pub struct TimeEnforcementLayer {
    max_body_bytes: usize,
}

impl TimeEnforcementLayer {
    /// Builds the layer.
    ///
    /// `max_body_bytes` bounds the current-state answer read to hold it to the window under
    /// `current-state = "values-in-window"`. A request body is never read here: the context layer
    /// above reads it once, and the `temporalQ` of a temporal batch query is narrowed in that parse.
    #[must_use]
    pub const fn new(max_body_bytes: usize) -> Self {
        Self { max_body_bytes }
    }
}

impl<S> Layer<S> for TimeEnforcementLayer {
    type Service = TimeEnforcementService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        TimeEnforcementService {
            inner,
            max_body_bytes: self.max_body_bytes,
        }
    }
}

/// The service produced by [`TimeEnforcementLayer`].
#[derive(Debug, Clone)]
pub struct TimeEnforcementService<S> {
    inner: S,
    max_body_bytes: usize,
}

impl<S> Service<Request> for TimeEnforcementService<S>
where
    S: Service<Request, Response = Response, Error = Infallible> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = Response;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Response, Infallible>> + Send>>;

    /// Always ready. The inner service's readiness is driven by `oneshot` in [`Self::call`], on
    /// the clone that actually serves the request.
    fn poll_ready(&mut self, _context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request) -> Self::Future {
        let inner = self.inner.clone();
        let max_body_bytes = self.max_body_bytes;

        Box::pin(async move {
            match apply(inner, request, max_body_bytes).await {
                Ok(response) => Ok(response),
                Err(error) => {
                    warn!(error = %error, "time enforcement refused the request");

                    Ok(error.to_problem().into_response())
                }
            }
        })
    }
}

/// Narrows the request, then forwards it.
async fn apply<S>(inner: S, request: Request, max_body_bytes: usize) -> Result<Response, TimeError>
where
    S: Service<Request, Response = Response, Error = Infallible> + Send + 'static,
    S::Future: Send + 'static,
{
    let decision = request.extensions().get::<Decision>().ok_or(TimeError::Undecided)?;

    // A reference count, not a copy: the request that owns the decision is moved into the rewrite and forward steps while the restriction is still read.
    let Some(restriction) = decision.time.clone() else {
        // The policy that allowed the request attached no time restriction.
        return Ok(forward(inner, request).await);
    };

    let grid = decision.aggregation.as_deref().and_then(AggregationRestriction::grid);

    // One reading of the clock per request, passed down. Two readings could put the URL's bounds
    // and the body's bounds in different windows on a relative restriction.
    let (narrowed, plan) = narrow(request, &restriction, grid, Timestamp::now())?;

    let response = forward(inner, narrowed).await;

    match plan {
        ResponsePlan::Passthrough => Ok(response),
        ResponsePlan::ValuesInWindow(plan) => values_in_window::filter_response(response, plan, max_body_bytes).await,
    }
}

/// What becomes of the answer to a request once it is narrowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResponsePlan {
    /// The answer is forwarded as the broker sent it.
    Passthrough,
    /// A current-state answer, held to the window on its way back.
    ValuesInWindow(ValuesInWindow),
}

/// Hands the request to the inner service.
async fn forward<S>(inner: S, request: Request) -> Response
where
    S: Service<Request, Response = Response, Error = Infallible> + Send + 'static,
    S::Future: Send + 'static,
{
    inner.oneshot(request).await.unwrap_or_else(|error| match error {})
}

/// Applies the restriction to one request.
///
/// `grid` is the grid of the decision's aggregation minimum period, if it sets one.
fn narrow(request: Request, restriction: &TimeRestriction, grid: Option<AggregationGrid>, now: Timestamp) -> Result<(Request, ResponsePlan), TimeError> {
    let (mut parts, body) = request.into_parts();

    // Cloned, with the query below, because both travel in the parts that are narrowed and moved
    // while they are still read.
    let operation = operation(&parts.extensions)?.clone();

    // The broker answers a listing with every subscription of the tenant, and changing one changes
    // what its notifications disclose to an endpoint Libra never sees.
    if EntityTarget::of(&operation) == EntityTarget::ExistingSubscriptions {
        return Err(TimeError::SubscriptionsRefused);
    }

    let parameters = parameters(&parts.extensions)?.clone();

    // A temporal filter on a current-state read (NGSI-LD clause 4.11) names a temporal property
    // too, so the property is judged wherever a query string names one.
    judge_time_property(TemporalSelector::of_parameters(&parameters))?;

    // A temporal *write* carries no window to narrow (it supplies instants rather than selecting
    // them), so it is held to the same membership rule as a current-state request.
    if !(operation.is_read() && operation.resource.is_temporal()) {
        return match check_membership(&operation, restriction, now)? {
            Membership::Forward => Ok((Request::from_parts(parts, body), ResponsePlan::Passthrough)),
            Membership::FilterValues(window) => {
                let (request, plan) = values_in_window::prepare(parts, body, parameters, &operation.resource, window)?;
                Ok((request, ResponsePlan::ValuesInWindow(plan)))
            }
        };
    }

    // A join answer's linked entities are not narrowed to the window, and a linked `q` path is
    // evaluated against linked entities no window reaches, so a temporal read that asks for either,
    // in its query string or its `Query` body, is refused.
    if !requested(&parts.extensions)?.is_nothing() {
        return Err(TimeError::TemporalJoin);
    }

    // An aggregated read's window is rounded to the grid of its minimum period; a read that does
    // not aggregate has no buckets to align. A representation that was not resolved is rounded too:
    // aggregation enforcement above refuses one under a minimum period, so rounding it is the
    // fail-closed reading rather than a reachable case.
    let grid = grid.filter(|_| aggregates(&parts));

    // `/temporal/entityOperations/query` is reached through `Resource::is_temporal`, not through a
    // path prefix it does not begin with.
    if !matches!(operation.resource, Resource::TemporalBatchQuery) {
        narrow_query(&mut parts, parameters, restriction, now, grid, WindowPlace::QueryString)?;

        return Ok((Request::from_parts(parts, body), ResponsePlan::Passthrough));
    }

    narrow_query(&mut parts, parameters, restriction, now, grid, WindowPlace::QueryStringOrBody)?;
    let narrowed = narrow_body(&mut parts, restriction, now, grid)?;

    Ok((Request::from_parts(parts, narrowed), ResponsePlan::Passthrough))
}

/// Whether the read answers with aggregated values.
fn aggregates(parts: &Parts) -> bool {
    match parts.extensions.get::<RequestRepresentation>() {
        Some(RequestRepresentation::Resolved(representation)) => representation.temporal() == TemporalRepresentation::Aggregated,
        Some(RequestRepresentation::Unresolvable(_)) | None => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use http::{Method, StatusCode, header::CONTENT_TYPE};
    use http_body_util::BodyExt;
    use jstrict::{Value, json};
    use libra_config::representation::RepresentationStrictness;
    use libra_json_body::{request_body::RequestBody, strict::parse};
    use libra_linked_entity_layer::layer::LinkedEntityLayer;
    use libra_ngsi_ld_operation::operation::Operation;
    use libra_ngsi_ld_operation_layer::layer::{OperationLayer, classify};
    use libra_ngsi_ld_query::{linked_entity::LinkedEntityRequest, parameter_name::ParameterName, parameters::QueryParameters};
    use libra_ngsi_ld_query_layer::layer::{QueryLayer, read_query};
    use libra_ngsi_ld_representation::selection::ResponseRepresentation;
    use libra_ngsi_ld_representation_layer::RepresentationLayer;
    use libra_policy_model::{
        duration::IsoDuration,
        effect::Effect,
        time::{CurrentState, Direction},
    };
    use pretty_assertions::assert_eq;
    use std::sync::{Arc, Mutex, PoisonError};
    use tower::util::BoxCloneService;

    /// What the upstream saw, and what it answers with.
    #[derive(Clone, Default)]
    struct Seen {
        uri: Arc<Mutex<String>>,
        body: Arc<Mutex<String>>,
        answer: Arc<Mutex<Option<String>>>,
    }

    impl Seen {
        fn uri(&self) -> String {
            self.uri.lock().unwrap_or_else(PoisonError::into_inner).to_owned()
        }

        fn body(&self) -> String {
            self.body.lock().unwrap_or_else(PoisonError::into_inner).to_owned()
        }

        /// A stand-in broker that answers with `answer` as JSON.
        fn answering(answer: &Value) -> Self {
            let seen = Self::default();
            *seen.answer.lock().unwrap_or_else(PoisonError::into_inner) = Some(answer.to_string());

            seen
        }
    }

    fn upstream(seen: &Seen) -> BoxCloneService<Request, Response, Infallible> {
        let uri = Arc::clone(&seen.uri);
        let body = Arc::clone(&seen.body);
        let answer = Arc::clone(&seen.answer);
        BoxCloneService::new(tower::service_fn(move |request: Request| {
            let uri = Arc::clone(&uri);
            let body = Arc::clone(&body);
            let answer = answer.lock().unwrap_or_else(PoisonError::into_inner).clone();
            async move {
                *uri.lock().unwrap_or_else(PoisonError::into_inner) = request.uri().to_string();

                let bytes = request.into_body().collect().await.map(http_body_util::Collected::to_bytes).unwrap_or_default();
                *body.lock().unwrap_or_else(PoisonError::into_inner) = String::from_utf8_lossy(&bytes).into_owned();

                Ok(match answer {
                    Some(answer) => Response::builder()
                        .header(CONTENT_TYPE, "application/json")
                        .body(Body::from(answer))
                        .unwrap_or_else(|_| Response::new(Body::empty())),
                    None => Response::new(Body::empty()),
                })
            }
        }))
    }

    fn decision(time: Option<TimeRestriction>) -> Decision {
        Decision {
            effect: Effect::Allow,
            matched: None,
            scope: None,
            entity_type: None,
            time: time.map(Arc::new),
            attribute: None,
            aggregation: None,
        }
    }

    fn absolute() -> TimeRestriction {
        TimeRestriction::Absolute {
            start: "2026-01-01T00:00:00Z".parse().unwrap(),
            end: "2026-12-31T23:59:59Z".parse().unwrap(),
            current_state: CurrentState::RequestInWindow,
        }
    }

    fn past_day() -> TimeRestriction {
        past_day_with(CurrentState::Refuse)
    }

    fn past_day_with(current_state: CurrentState) -> TimeRestriction {
        TimeRestriction::Relative {
            duration: IsoDuration::parse("PT24H").unwrap(),
            direction: Direction::Past,
            current_state,
        }
    }

    /// An instant `hours` before now, as an `observedAt` is written.
    fn hours_ago(hours: i64) -> String {
        Timestamp::now()
            .checked_sub(jiff::SignedDuration::from_hours(hours))
            .unwrap_or(Timestamp::MIN)
            .to_string()
    }

    async fn body_json(response: Response) -> Value {
        let bytes = response
            .into_body()
            .collect()
            .await
            .map(http_body_util::Collected::to_bytes)
            .unwrap_or_default();

        parse(&bytes).unwrap_or(Value::Null)
    }

    async fn run(method: Method, uri: &str, body: &'static str, restriction: Option<TimeRestriction>, seen: &Seen) -> Response {
        // The body the context layer above would have read from the request.
        let parsed = RequestBody::read(body.as_bytes()).expect("the test body is readable");

        serve(request(method, uri, body.to_owned(), Some(parsed), restriction), seen).await
    }

    /// A request carrying `body`, and `parsed` as the body the context layer read from it.
    fn request(method: Method, uri: &str, body: String, parsed: Option<RequestBody>, restriction: Option<TimeRestriction>) -> Request {
        let mut request = Request::builder()
            .method(method)
            .uri(uri)
            .body(Body::from(body))
            .unwrap_or_else(|_| Request::new(Body::empty()));
        request.extensions_mut().insert(decision(restriction));
        if let Some(parsed) = parsed {
            request.extensions_mut().insert(parsed);
        }

        request
    }

    /// Serves a request under the layers that resolve, above authorization, what a join and the
    /// answer's representation are.
    async fn serve(request: Request, seen: &Seen) -> Response {
        let mut service = OperationLayer::new().layer(
            QueryLayer::new().layer(
                LinkedEntityLayer::new()
                    .layer(RepresentationLayer::new(RepresentationStrictness::default()).layer(TimeEnforcementLayer::new(64 * 1024).layer(upstream(seen)))),
            ),
        );

        service.call(request).await.unwrap_or_else(|error| match error {})
    }

    /// `document`, which may repeat a member, as the body the context layer would have read; the
    /// strict read refuses a repeated member, so a test of one builds the parse directly.
    fn parsed_request(method: Method, uri: &str, document: Value, restriction: Option<TimeRestriction>) -> Request {
        request(method, uri, document.to_string(), Some(RequestBody::Json(document)), restriction)
    }

    async fn get(uri: &str, restriction: Option<TimeRestriction>, seen: &Seen) -> Response {
        run(Method::GET, uri, "", restriction, seen).await
    }

    #[tokio::test]
    async fn a_request_with_no_time_restriction_passes_through_untouched() {
        let seen = Seen::default();
        let response = get("/ngsi-ld/v1/temporal/entities?type=Vehicle", None, &seen).await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(seen.uri(), "/ngsi-ld/v1/temporal/entities?type=Vehicle");
    }

    #[tokio::test]
    async fn a_temporal_query_is_narrowed_to_the_allowed_window() {
        let seen = Seen::default();
        let response = get(
            "/ngsi-ld/v1/temporal/entities?type=Vehicle&timerel=between&timeAt=2020-01-01T00:00:00Z&endTimeAt=2030-01-01T00:00:00Z",
            Some(absolute()),
            &seen,
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert!(seen.uri().contains("timeAt=2026-01-01T00%3A00%3A00.000Z"), "{}", seen.uri());
        assert!(seen.uri().contains("endTimeAt=2026-12-31T23%3A59%3A59.000Z"), "{}", seen.uri());
        assert!(seen.uri().contains("timerel=between"), "{}", seen.uri());
        assert!(seen.uri().contains("type=Vehicle"), "the rest of the query survives: {}", seen.uri());
    }

    #[tokio::test]
    async fn a_temporal_batch_query_is_matched_by_its_resource_not_by_a_path_prefix() {
        // `/temporal/entityOperations/query` does not begin with `/ngsi-ld/v1/temporal/entities`,
        // so a prefix check never fires on it.
        let seen = Seen::default();
        let response = run(
            Method::POST,
            "/ngsi-ld/v1/temporal/entityOperations/query",
            r#"{"type":"Query","entities":[{"type":"Vehicle"}],"temporalQ":{"timerel":"between","timeAt":"2020-01-01T00:00:00Z","endTimeAt":"2030-01-01T00:00:00Z"}}"#,
            Some(absolute()),
            &seen,
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert!(seen.body().contains(r#""timeAt":"2026-01-01T00:00:00.000Z""#), "{}", seen.body());
        assert!(seen.body().contains(r#""endTimeAt":"2026-12-31T23:59:59.000Z""#), "{}", seen.body());
    }

    #[tokio::test]
    async fn the_temporal_query_in_a_batch_query_body_is_read_rather_than_ignored() {
        // The `temporalQ` in the body is what decides the window, so it is what is narrowed.
        let seen = Seen::default();
        let response = run(
            Method::POST,
            "/ngsi-ld/v1/temporal/entityOperations/query",
            r#"{"type":"Query","temporalQ":{"timerel":"after","timeAt":"2019-01-01T00:00:00Z"}}"#,
            Some(absolute()),
            &seen,
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert!(seen.body().contains(r#""timerel":"between""#), "{}", seen.body());
        assert!(seen.body().contains(r#""timeAt":"2026-01-01T00:00:00.000Z""#), "{}", seen.body());
        assert!(!seen.body().contains("2019"), "the caller's bound must not survive: {}", seen.body());
    }

    #[tokio::test]
    async fn a_batch_query_body_with_no_temporal_query_gains_one() {
        // No `temporalQ` is a query over all of history, which is the case a window matters most
        // for.
        let seen = Seen::default();
        let response = run(
            Method::POST,
            "/ngsi-ld/v1/temporal/entityOperations/query",
            r#"{"type":"Query","entities":[{"type":"Vehicle"}]}"#,
            Some(absolute()),
            &seen,
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert!(seen.body().contains(r#""temporalQ""#), "{}", seen.body());
        assert!(seen.body().contains(r#""timeAt":"2026-01-01T00:00:00.000Z""#), "{}", seen.body());
    }

    #[tokio::test]
    async fn a_batch_query_body_that_is_not_a_json_object_is_refused() {
        let response = run(
            Method::POST,
            "/ngsi-ld/v1/temporal/entityOperations/query",
            "not json at all",
            Some(absolute()),
            &Seen::default(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn a_relative_restriction_refuses_a_current_state_read_rather_than_ignoring_it() {
        // A request-time check against a relative window can never fail, so without a refusal a
        // policy saying "the past 24 hours only" would leave `GET /entities` unrestricted.
        let response = get("/ngsi-ld/v1/entities?type=Vehicle", Some(past_day()), &Seen::default()).await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn a_relative_restriction_leaves_resources_that_carry_no_entity_data_alone() {
        // `/types` and `/attributes` describe the shape of the data, not its values, so there is
        // nothing for a window to be about.
        let seen = Seen::default();

        for uri in ["/ngsi-ld/v1/types", "/ngsi-ld/v1/attributes"] {
            let response = get(uri, Some(past_day()), &seen).await;

            assert_eq!(response.status(), StatusCode::OK, "{uri} carries no entity data");
        }
    }

    #[tokio::test]
    async fn a_relative_restriction_still_narrows_a_temporal_query() {
        let seen = Seen::default();
        let response = get("/ngsi-ld/v1/temporal/entities?type=Vehicle", Some(past_day()), &seen).await;

        assert_eq!(response.status(), StatusCode::OK);
        assert!(seen.uri().contains("timerel=between"), "{}", seen.uri());
    }

    #[tokio::test]
    async fn an_absolute_restriction_refuses_a_current_state_read_outside_its_window() {
        let response = get(
            "/ngsi-ld/v1/entities/urn:ngsi-ld:Vehicle:1",
            Some(TimeRestriction::Absolute {
                start: "2020-01-01T00:00:00Z".parse().unwrap(),
                end: "2020-12-31T00:00:00Z".parse().unwrap(),
                current_state: CurrentState::RequestInWindow,
            }),
            &Seen::default(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn an_unknown_timerel_is_refused_at_the_layer_too() {
        let response = get(
            "/ngsi-ld/v1/temporal/entities?timerel=whenever&timeAt=2026-06-01T00:00:00Z",
            Some(absolute()),
            &Seen::default(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn an_unparseable_bound_is_a_bad_request_at_the_layer_too() {
        let response = get(
            "/ngsi-ld/v1/temporal/entities?timerel=between&timeAt=yesterday&endTimeAt=2026-06-01T00:00:00Z",
            Some(absolute()),
            &Seen::default(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn a_window_the_policy_does_not_reach_is_refused() {
        let response = get(
            "/ngsi-ld/v1/temporal/entities?timerel=between&timeAt=2019-01-01T00:00:00Z&endTimeAt=2019-06-01T00:00:00Z",
            Some(absolute()),
            &Seen::default(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn a_bound_written_with_a_timezone_offset_is_not_mangled_on_the_way_through() {
        // Form decoding reads `+` as a space, which would turn `2026-06-01T00:00:00+01:00` into a
        // timestamp an hour and a timezone away from the one asked for, and any other `+` likewise.
        let seen = Seen::default();
        let response = get(
            "/ngsi-ld/v1/temporal/entities?timerel=after&timeAt=2026-06-01T00:00:00%2B01:00&q=name==%22a+b%22",
            Some(absolute()),
            &seen,
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert!(seen.uri().contains("timeAt=2026-05-31T23%3A00%3A00.000Z"), "{}", seen.uri());
        assert!(seen.uri().contains("a%2Bb"), "a literal plus survives re-encoding: {}", seen.uri());
    }

    #[tokio::test]
    async fn a_narrowed_window_leaves_last_n_alone() {
        // `lastN` selects inside the window rather than reaching outside it, so it is a page size
        // and not a bound. Pinned so that removing it later is a deliberate act.
        let seen = Seen::default();
        let response = get("/ngsi-ld/v1/temporal/entities?lastN=1000", Some(absolute()), &seen).await;

        assert_eq!(response.status(), StatusCode::OK);
        assert!(seen.uri().contains("lastN=1000"), "{}", seen.uri());
    }

    #[tokio::test]
    async fn a_repeated_bound_is_refused_rather_than_resolved() {
        // Two `timeAt` values are two requests; which one wins differs between implementations,
        // and the one this layer narrowed might not be the one the broker reads.
        let response = get(
            "/ngsi-ld/v1/temporal/entities?timerel=after&timeAt=2026-06-01T00:00:00Z&timeAt=2019-01-01T00:00:00Z",
            Some(absolute()),
            &Seen::default(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn a_temporal_write_is_not_given_a_query_window() {
        // Adding `timerel` to a write would be inventing a parameter the operation does not take.
        let seen = Seen::default();
        let response = run(
            Method::POST,
            "/ngsi-ld/v1/temporal/entities",
            r#"{"id":"urn:ngsi-ld:Vehicle:1"}"#,
            Some(absolute()),
            &seen,
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(seen.uri(), "/ngsi-ld/v1/temporal/entities");
    }

    #[tokio::test]
    async fn a_temporal_join_is_refused_under_a_time_restriction() {
        // The window narrows the queried entities' instances, not the linked entities': a join on
        // a temporal endpoint would let a linked entity's history outside the window through.
        for (method, uri, body) in [
            (Method::GET, "/ngsi-ld/v1/temporal/entities?type=Vehicle&join=inline", ""),
            (Method::GET, "/ngsi-ld/v1/temporal/entities/urn:ngsi-ld:Vehicle:1?join=flat&joinLevel=1", ""),
            (Method::POST, "/ngsi-ld/v1/temporal/entityOperations/query", r#"{"type":"Query","join":"flat"}"#),
            (Method::GET, "/ngsi-ld/v1/temporal/entities?type=Vehicle&joinLevel=2", ""),
        ] {
            let seen = Seen::default();
            let response = run(method, uri, body, Some(absolute()), &seen).await;

            assert_eq!(response.status(), StatusCode::FORBIDDEN, "{uri}");
            assert_eq!(seen.uri(), "", "{uri}");
        }
    }

    #[tokio::test]
    async fn a_temporal_join_passes_without_a_time_restriction() {
        let seen = Seen::default();
        let response = get("/ngsi-ld/v1/temporal/entities?type=Vehicle&join=inline", None, &seen).await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(seen.uri(), "/ngsi-ld/v1/temporal/entities?type=Vehicle&join=inline");
    }

    #[tokio::test]
    async fn current_state_allow_forwards_a_current_state_read_untouched() {
        let seen = Seen::default();
        let response = get("/ngsi-ld/v1/entities?type=Vehicle", Some(past_day_with(CurrentState::Allow)), &seen).await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(seen.uri(), "/ngsi-ld/v1/entities?type=Vehicle");
    }

    #[tokio::test]
    async fn values_in_window_keeps_the_attributes_observed_inside_the_window() {
        let observed = hours_ago(1);
        // Cloned because the expected answer below names the same instant.
        let seen = Seen::answering(&json!([{ "id": "urn:v:1", "type": "Vehicle",
            "speed": { "type": "Property", "value": 42, "observedAt": observed.clone(), "createdAt": hours_ago(100), "modifiedAt": hours_ago(1) },
            "temperature": { "type": "Property", "value": 20, "observedAt": hours_ago(48), "createdAt": hours_ago(100), "modifiedAt": hours_ago(48) } }]));

        let response = get("/ngsi-ld/v1/entities?type=Vehicle", Some(past_day_with(CurrentState::ValuesInWindow)), &seen).await;

        assert_eq!(response.status(), StatusCode::OK);
        assert!(seen.uri().contains("options=sysAttrs"), "sysAttrs is asked for upstream: {}", seen.uri());
        // The recent observation stays, the old one goes, and the system attributes Libra added are
        // stripped.
        assert_eq!(
            body_json(response).await,
            json!([{ "id": "urn:v:1", "type": "Vehicle", "speed": { "type": "Property", "value": 42, "observedAt": observed } }])
        );
    }

    #[tokio::test]
    async fn values_in_window_keeps_system_attributes_the_caller_asked_for() {
        let answer = json!({ "id": "urn:v:1", "type": "Vehicle", "createdAt": hours_ago(100),
            "speed": { "type": "Property", "value": 42, "createdAt": hours_ago(100), "modifiedAt": hours_ago(2) } });
        let seen = Seen::answering(&answer);

        let response = get(
            "/ngsi-ld/v1/entities/urn:v:1?options=sysAttrs",
            Some(past_day_with(CurrentState::ValuesInWindow)),
            &seen,
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(seen.uri(), "/ngsi-ld/v1/entities/urn:v:1?options=sysAttrs");
        assert_eq!(body_json(response).await, answer);
    }

    #[tokio::test]
    async fn values_in_window_refuses_what_it_cannot_date() {
        for uri in [
            "/ngsi-ld/v1/entities?type=Vehicle&options=keyValues",
            "/ngsi-ld/v1/entities?type=Vehicle&format=keyValues",
            "/ngsi-ld/v1/entities?type=Vehicle&q=speed%3E40",
            "/ngsi-ld/v1/entities?type=Vehicle&georel=near%3BmaxDistance==10&geometry=Point&coordinates=%5B0,0%5D",
            "/ngsi-ld/v1/entities?type=Vehicle&orderBy=speed",
            "/ngsi-ld/v1/entities?type=Vehicle&orderBy=dist-asc&geometry=Point&coordinates=%5B0,0%5D",
        ] {
            let seen = Seen::default();
            let response = get(uri, Some(past_day_with(CurrentState::ValuesInWindow)), &seen).await;

            assert_eq!(response.status(), StatusCode::FORBIDDEN, "{uri}");
            assert_eq!(seen.uri(), "", "{uri}");
        }

        let seen = Seen::default();
        let response = run(
            Method::POST,
            "/ngsi-ld/v1/entityOperations/query",
            r#"{"type":"Query","entities":[{"type":"Vehicle"}],"q":"speed>40"}"#,
            Some(past_day_with(CurrentState::ValuesInWindow)),
            &seen,
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "a filter in a batch query body");

        for body in [
            r#"{"type":"Query","entities":[{"type":"Vehicle"}],"ordering":{"orderBy":"speed"}}"#,
            r#"{"type":"Query","entities":[{"type":"Vehicle"}],"orderBy":"speed"}"#,
        ] {
            let seen = Seen::default();
            let response = run(
                Method::POST,
                "/ngsi-ld/v1/entityOperations/query",
                body,
                Some(past_day_with(CurrentState::ValuesInWindow)),
                &seen,
            )
            .await;
            assert_eq!(response.status(), StatusCode::FORBIDDEN, "{body}");
            assert_eq!(seen.uri(), "", "{body}");
        }
    }

    #[tokio::test]
    async fn writes_keep_the_request_time_rule_whatever_the_current_state_rule() {
        for rule in [CurrentState::Allow, CurrentState::ValuesInWindow] {
            let seen = Seen::default();
            let response = run(
                Method::POST,
                "/ngsi-ld/v1/entities",
                r#"{"id":"urn:v:1","type":"Vehicle"}"#,
                Some(past_day_with(rule)),
                &seen,
            )
            .await;

            assert_eq!(response.status(), StatusCode::FORBIDDEN, "{rule:?}");
            assert_eq!(seen.uri(), "", "{rule:?}");
        }
    }

    #[tokio::test]
    async fn the_window_is_read_from_the_stored_query_not_from_the_request_target() {
        // The stored window is the one narrowed: a stored `timeAt` the policy's window never reaches
        // is refused, though the request target names none at all.
        let seen = Seen::default();
        let (mut parts, body) = request(
            Method::GET,
            "/ngsi-ld/v1/temporal/entities?type=Vehicle",
            String::new(),
            Some(RequestBody::Empty),
            Some(absolute()),
        )
        .into_parts();
        classify(&mut parts).unwrap();
        parts
            .extensions
            .insert(QueryParameters::parse("type=Vehicle&timerel=before&timeAt=2000-01-01T00:00:00Z").unwrap());
        parts
            .extensions
            .insert(RequestRepresentation::Resolved(ResponseRepresentation::parse(None, None, None).unwrap()));
        parts.extensions.insert(LinkedEntityRequest::NOTHING);

        let response = TimeEnforcementLayer::new(64 * 1024)
            .layer(upstream(&seen))
            .oneshot(Request::from_parts(parts, body))
            .await
            .unwrap_or_else(|never| match never {});

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(seen.uri(), "", "nothing reached the broker");
    }

    #[tokio::test]
    async fn a_request_that_reached_this_layer_unclassified_or_unparsed_is_refused() {
        for missing in [Missing::Operation, Missing::Query] {
            let seen = Seen::default();
            let (mut parts, body) = request(
                Method::GET,
                "/ngsi-ld/v1/temporal/entities?type=Vehicle",
                String::new(),
                Some(RequestBody::Empty),
                Some(absolute()),
            )
            .into_parts();
            classify(&mut parts).unwrap();
            read_query(&mut parts).unwrap();
            match missing {
                Missing::Operation => drop(parts.extensions.remove::<Operation>()),
                Missing::Query => drop(parts.extensions.remove::<QueryParameters>()),
            }

            let response = TimeEnforcementLayer::new(64 * 1024)
                .layer(upstream(&seen))
                .oneshot(Request::from_parts(parts, body))
                .await
                .unwrap_or_else(|never| match never {});

            assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR, "{missing:?}");
            assert_eq!(seen.uri(), "", "{missing:?}");
        }
    }

    /// Which stored value a wiring test leaves out.
    #[derive(Debug, Clone, Copy)]
    enum Missing {
        Operation,
        Query,
    }

    #[tokio::test]
    async fn a_request_without_a_parsed_body_is_refused() {
        // A wiring error: the context layer above reads every body. A `temporalQ` that is never
        // narrowed would reach the broker exactly as the caller wrote it.
        let seen = Seen::default();
        let time = TimeEnforcementLayer::new(64 * 1024).layer(upstream(&seen));
        // Between the layers that need the parsed body and this one, so the refusal is this layer's.
        let unread = tower::service_fn(move |mut request: Request| {
            request.extensions_mut().remove::<RequestBody>();
            time.clone().oneshot(request)
        });
        let mut service = OperationLayer::new()
            .layer(QueryLayer::new().layer(LinkedEntityLayer::new().layer(RepresentationLayer::new(RepresentationStrictness::default()).layer(unread))));

        let response = service
            .call(request(
                Method::POST,
                "/ngsi-ld/v1/temporal/entityOperations/query",
                r#"{"type":"Query","temporalQ":{"timerel":"after","timeAt":"2019-01-01T00:00:00Z"}}"#.to_owned(),
                RequestBody::read(br#"{"type":"Query","temporalQ":{"timerel":"after","timeAt":"2019-01-01T00:00:00Z"}}"#).ok(),
                Some(absolute()),
            ))
            .await
            .unwrap_or_else(|error| match error {});

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(seen.uri(), "", "nothing reached the broker");
    }

    #[tokio::test]
    async fn a_batch_query_body_that_repeats_its_temporal_query_is_refused() {
        // Narrowing one `temporalQ` and forwarding the other is forwarding a window nobody checked.
        let seen = Seen::default();
        let document = json!({ "type": "Query",
            "temporalQ": { "timerel": "between", "timeAt": "2026-02-01T00:00:00Z", "endTimeAt": "2026-03-01T00:00:00Z" },
            "temporalQ": { "timerel": "after", "timeAt": "2019-01-01T00:00:00Z" } });

        let response = serve(
            parsed_request(Method::POST, "/ngsi-ld/v1/temporal/entityOperations/query", document, Some(absolute())),
            &seen,
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(seen.uri(), "", "nothing reached the broker");
    }

    #[tokio::test]
    async fn a_temporal_query_that_repeats_a_bound_is_refused() {
        let seen = Seen::default();
        let document = json!({ "type": "Query", "temporalQ": { "timerel": "after", "timeAt": "2026-02-01T00:00:00Z", "timeAt": "2019-01-01T00:00:00Z" } });

        let response = serve(
            parsed_request(Method::POST, "/ngsi-ld/v1/temporal/entityOperations/query", document, Some(absolute())),
            &seen,
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(seen.uri(), "", "nothing reached the broker");
    }

    #[tokio::test]
    async fn a_time_property_other_than_observed_at_is_refused() {
        for property in ["createdAt", "modifiedAt", "deletedAt"] {
            let seen = Seen::default();
            let response = get(
                &format!("/ngsi-ld/v1/temporal/entities?type=Vehicle&timerel=after&timeAt=2026-02-01T00:00:00Z&timeproperty={property}"),
                Some(absolute()),
                &seen,
            )
            .await;

            assert_eq!(response.status(), StatusCode::FORBIDDEN, "{property}");
            assert_eq!(seen.uri(), "", "{property}");
        }
    }

    #[tokio::test]
    async fn a_time_property_on_a_current_state_read_is_judged_too() {
        let seen = Seen::default();
        let response = get(
            "/ngsi-ld/v1/entities?type=Vehicle&timerel=after&timeAt=2026-02-01T00:00:00Z&timeproperty=modifiedAt",
            Some(absolute()),
            &seen,
        )
        .await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(seen.uri(), "");
    }

    #[tokio::test]
    async fn observed_at_named_explicitly_is_forwarded() {
        let seen = Seen::default();
        let response = get(
            "/ngsi-ld/v1/temporal/entities?type=Vehicle&timerel=after&timeAt=2026-02-01T00:00:00Z&timeproperty=observedAt",
            Some(absolute()),
            &seen,
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert!(seen.uri().contains("timeproperty=observedAt"), "{}", seen.uri());
    }

    #[tokio::test]
    async fn an_absent_time_property_stays_absent() {
        let seen = Seen::default();
        let response = get("/ngsi-ld/v1/temporal/entities?type=Vehicle", Some(absolute()), &seen).await;

        assert_eq!(response.status(), StatusCode::OK);
        assert!(!seen.uri().contains("timeproperty"), "{}", seen.uri());
    }

    #[tokio::test]
    async fn a_time_property_in_a_temporal_query_body_is_judged() {
        let refused_seen = Seen::default();
        let refused = run(
            Method::POST,
            "/ngsi-ld/v1/temporal/entityOperations/query",
            r#"{"type":"Query","temporalQ":{"timerel":"after","timeAt":"2026-02-01T00:00:00Z","timeproperty":"createdAt"}}"#,
            Some(absolute()),
            &refused_seen,
        )
        .await;
        assert_eq!(refused.status(), StatusCode::FORBIDDEN);
        assert_eq!(refused_seen.uri(), "");

        let seen = Seen::default();
        let allowed = run(
            Method::POST,
            "/ngsi-ld/v1/temporal/entityOperations/query",
            r#"{"type":"Query","temporalQ":{"timerel":"after","timeAt":"2026-02-01T00:00:00Z","timeproperty":"observedAt"}}"#,
            Some(absolute()),
            &seen,
        )
        .await;
        assert_eq!(allowed.status(), StatusCode::OK);
        assert!(seen.body().contains(r#""timeproperty":"observedAt""#), "{}", seen.body());
    }

    #[tokio::test]
    async fn reading_subscriptions_is_refused_under_a_restriction() {
        for uri in ["/ngsi-ld/v1/subscriptions", "/ngsi-ld/v1/subscriptions/urn:ngsi-ld:Subscription:1"] {
            let seen = Seen::default();
            let response = get(uri, Some(absolute()), &seen).await;

            assert_eq!(response.status(), StatusCode::FORBIDDEN, "{uri}");
            assert_eq!(seen.uri(), "", "{uri}");
        }
    }

    #[tokio::test]
    async fn updating_a_subscription_is_refused_under_a_restriction() {
        let seen = Seen::default();
        let response = run(
            Method::PATCH,
            "/ngsi-ld/v1/subscriptions/urn:ngsi-ld:Subscription:1",
            r#"{"type":"Subscription","isActive":false}"#,
            Some(absolute()),
            &seen,
        )
        .await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(seen.uri(), "");
    }

    #[tokio::test]
    async fn deleting_a_subscription_is_refused_under_a_restriction() {
        let seen = Seen::default();
        let response = run(
            Method::DELETE,
            "/ngsi-ld/v1/subscriptions/urn:ngsi-ld:Subscription:1",
            "",
            Some(past_day()),
            &seen,
        )
        .await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(seen.uri(), "");
    }

    #[tokio::test]
    async fn creating_a_subscription_is_still_narrowed() {
        // Creating one keeps the request-time rule: allowed inside an absolute window, refused
        // outside it.
        let body = r#"{"type":"Subscription","entities":[{"type":"Vehicle"}]}"#;
        let seen = Seen::default();
        let inside = run(Method::POST, "/ngsi-ld/v1/subscriptions", body, Some(past_day()), &seen).await;

        assert_eq!(inside.status(), StatusCode::OK);
        assert_eq!(seen.body(), body);

        let outside = run(
            Method::POST,
            "/ngsi-ld/v1/subscriptions",
            body,
            Some(TimeRestriction::Absolute {
                start: "2020-01-01T00:00:00Z".parse().unwrap(),
                end: "2020-12-31T00:00:00Z".parse().unwrap(),
                current_state: CurrentState::RequestInWindow,
            }),
            &Seen::default(),
        )
        .await;
        assert_eq!(outside.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn subscriptions_are_forwarded_without_a_restriction() {
        for (method, uri) in [
            (Method::GET, "/ngsi-ld/v1/subscriptions"),
            (Method::PATCH, "/ngsi-ld/v1/subscriptions/urn:ngsi-ld:Subscription:1"),
            (Method::DELETE, "/ngsi-ld/v1/subscriptions/urn:ngsi-ld:Subscription:1"),
        ] {
            let seen = Seen::default();
            let response = run(method, uri, "", None, &seen).await;

            assert_eq!(response.status(), StatusCode::OK, "{uri}");
            assert_eq!(seen.uri(), uri);
        }
    }

    #[tokio::test]
    async fn a_request_without_a_decision_is_refused() {
        // A wiring fault: authorization attaches a decision to everything it lets through.
        let seen = Seen::default();
        let mut undecided = request(Method::GET, "/ngsi-ld/v1/temporal/entities?type=Vehicle", String::new(), None, None);
        undecided.extensions_mut().remove::<Decision>();

        let response = serve(undecided, &seen).await;

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(seen.uri(), "", "nothing reached the broker");
    }

    /// A decision carrying `time` and an hourly aggregation minimum.
    fn hourly_aggregation(time: TimeRestriction) -> Decision {
        Decision {
            aggregation: Some(toml::from_str("allowed-methods = [\"avg\"]\nmin-period-duration = \"PT1H\"").unwrap()),
            ..decision(Some(time))
        }
    }

    /// The `timeAt` and `endTimeAt` the broker was sent.
    fn forwarded_window(seen: &Seen) -> (Timestamp, Timestamp) {
        let uri = seen.uri();
        let parameters = QueryParameters::parse(uri.split_once('?').map_or("", |(_, query)| query)).unwrap();
        let bound = |name: &ParameterName| parameters.get(name).and_then(|value| value.parse().ok()).unwrap_or(Timestamp::MIN);

        (bound(&ParameterName::TIME_AT), bound(&ParameterName::END_TIME_AT))
    }

    async fn aggregated_read(uri: &str, decision: Decision, seen: &Seen) -> Response {
        let mut request = request(Method::GET, uri, String::new(), Some(RequestBody::Empty), None);
        request.extensions_mut().insert(decision);

        serve(request, seen).await
    }

    #[tokio::test]
    async fn a_relative_narrowing_rounds_inward_to_the_grid() {
        // The past 24 hours, measured from a moment that is almost never on the hour, rounded to
        // the hours inside it.
        let seen = Seen::default();
        let response = aggregated_read(
            "/ngsi-ld/v1/temporal/entities?type=Vehicle&options=aggregatedValues&aggrMethods=avg&aggrPeriodDuration=PT1H",
            hourly_aggregation(past_day()),
            &seen,
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        let (start, end) = forwarded_window(&seen);
        assert_eq!(start.as_second() % 3600, 0, "{start}");
        assert_eq!(end.as_second() % 3600, 0, "{end}");
        assert_eq!(start.subsec_nanosecond(), 0, "{start}");
        assert!(end <= Timestamp::now() && end.as_second() - start.as_second() >= 23 * 3600, "{start} to {end}");
    }

    #[tokio::test]
    async fn an_absolute_narrowing_rounds_a_moved_boundary_inward_and_keeps_one_on_the_grid() {
        let policy = TimeRestriction::Absolute {
            start: "2026-01-01T00:20:00Z".parse().unwrap(),
            end: "2026-12-31T23:59:59Z".parse().unwrap(),
            current_state: CurrentState::RequestInWindow,
        };
        let seen = Seen::default();
        let response = aggregated_read(
            "/ngsi-ld/v1/temporal/entities?options=aggregatedValues&aggrMethods=avg&timerel=between&timeAt=2025-01-01T00:00:00Z&endTimeAt=2026-03-01T10:00:00Z",
            hourly_aggregation(policy),
            &seen,
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            forwarded_window(&seen),
            ("2026-01-01T01:00:00Z".parse().unwrap(), "2026-03-01T10:00:00Z".parse().unwrap())
        );
    }

    #[tokio::test]
    async fn a_narrowed_window_holding_no_whole_period_is_refused() {
        let policy = TimeRestriction::Absolute {
            start: "2026-03-01T10:20:00Z".parse().unwrap(),
            end: "2026-03-01T11:10:00Z".parse().unwrap(),
            current_state: CurrentState::RequestInWindow,
        };
        let seen = Seen::default();
        let response = aggregated_read(
            "/ngsi-ld/v1/temporal/entities?options=aggregatedValues&aggrMethods=avg",
            hourly_aggregation(policy),
            &seen,
        )
        .await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(seen.uri(), "");
    }

    #[tokio::test]
    async fn an_unaggregated_read_is_not_rounded_to_the_grid() {
        let policy = TimeRestriction::Absolute {
            start: "2026-01-01T00:20:00Z".parse().unwrap(),
            end: "2026-12-31T23:59:59Z".parse().unwrap(),
            current_state: CurrentState::RequestInWindow,
        };
        let seen = Seen::default();
        let response = aggregated_read("/ngsi-ld/v1/temporal/entities?type=Vehicle", hourly_aggregation(policy), &seen).await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(forwarded_window(&seen).0, "2026-01-01T00:20:00Z".parse().unwrap());
    }

    #[tokio::test]
    async fn a_narrowed_batch_query_body_is_the_one_every_layer_below_reads() {
        // The bytes and the parse are written together, so a layer below this one judges the body
        // the broker receives.
        let seen = Seen::default();
        let parsed = Arc::new(Mutex::new(None));
        let recorded = Arc::clone(&parsed);
        let upstream = upstream(&seen);
        let recording = tower::service_fn(move |request: Request| {
            *recorded.lock().unwrap_or_else(PoisonError::into_inner) = request.extensions().get::<RequestBody>().cloned();
            upstream.clone().oneshot(request)
        });
        let mut service = OperationLayer::new().layer(
            QueryLayer::new().layer(
                LinkedEntityLayer::new()
                    .layer(RepresentationLayer::new(RepresentationStrictness::default()).layer(TimeEnforcementLayer::new(64 * 1024).layer(recording))),
            ),
        );
        let body = r#"{"type":"Query","temporalQ":{"timerel":"after","timeAt":"2019-01-01T00:00:00Z"}}"#;

        let response = service
            .call(request(
                Method::POST,
                "/ngsi-ld/v1/temporal/entityOperations/query",
                body.to_owned(),
                RequestBody::read(body.as_bytes()).ok(),
                Some(absolute()),
            ))
            .await
            .unwrap_or_else(|error| match error {});

        assert_eq!(response.status(), StatusCode::OK);
        let forwarded = parse(seen.body().as_bytes()).expect("the forwarded body is JSON");
        assert_eq!(
            parsed.lock().unwrap_or_else(PoisonError::into_inner).take(),
            Some(RequestBody::Json(forwarded)),
            "the parse below is the body forwarded"
        );
    }
}
