//! The Tower layer that holds a temporal read to the aggregation its policy requires.
//!
//! Placement: below authorization, so a decision exists by the time this runs, and above the
//! proxy, so the request the broker sees is the one that was checked. A request without a decision
//! is refused as a wiring fault.
//!
//! That placement is also what makes the first line of `apply` safe. A request whose decision
//! carries no aggregation restriction is forwarded untouched, which reads like a hole and is not
//! one: authorization has already refused anything unauthorized, so the absence of a restriction
//! here means the policy that allowed the request attached none.

use crate::{
    enforce::{Enforcement, RequestedAggregation, enforce},
    error::AggregationError,
    query_body,
    raise::{QueryChange, raise_period, raise_windows},
    raw_values::RawValues,
    window::{OpenEnds, WindowChecks, WindowShortfall, check_windows},
};
use axum::{
    body::Body,
    extract::Request,
    http::request::Parts,
    response::{IntoResponse, Response},
};
use jstrict::Value;
use libra_config::aggregation::{Aggregation, ShortPeriod};
use libra_json_body::request_body::RequestBody;
use libra_ngsi_ld_operation::{resource::Resource, target::EntityTarget};
use libra_ngsi_ld_operation_layer::classified::operation;
use libra_ngsi_ld_query::{parameters::QueryParameters, temporal_selector::TemporalSelector};
use libra_ngsi_ld_query_layer::parsed::{parameters, replace_query};
use libra_ngsi_ld_representation::representation::TemporalRepresentation;
use libra_ngsi_ld_representation_layer::RequestRepresentation;
use libra_policy_engine::decision::Decision;
use libra_policy_model::{
    aggregation::{AggregationRestriction, UnaggregatedReads},
    aggregation_grid::AggregationGrid,
    duration::IsoDuration,
};
use std::{
    convert::Infallible,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
use tower::{Layer, Service, ServiceExt};
use tracing::{debug, warn};

/// Applies aggregation restrictions.
#[derive(Debug, Clone, Copy)]
pub struct AggregationEnforcementLayer {
    short_period: ShortPeriod,
}

impl AggregationEnforcementLayer {
    /// Builds the layer from the `[aggregation]` configuration section.
    ///
    /// `POST /temporal/entityOperations/query` carries its aggregation parameters in a payload
    /// rather than a query string; that body is read, and bounded, once by the context layer above.
    #[must_use]
    pub const fn new(config: &Aggregation) -> Self {
        Self {
            short_period: config.short_period,
        }
    }
}

impl<S> Layer<S> for AggregationEnforcementLayer {
    type Service = AggregationEnforcementService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AggregationEnforcementService {
            inner,
            short_period: self.short_period,
        }
    }
}

/// The service produced by [`AggregationEnforcementLayer`].
#[derive(Debug, Clone)]
pub struct AggregationEnforcementService<S> {
    inner: S,
    short_period: ShortPeriod,
}

impl<S> Service<Request> for AggregationEnforcementService<S>
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
        let short_period = self.short_period;

        Box::pin(async move {
            match apply(inner, request, short_period).await {
                Ok(response) => Ok(response),
                Err(error) => {
                    warn!(error = %error, "aggregation enforcement refused the request");

                    Ok(error.to_problem().into_response())
                }
            }
        })
    }
}

/// Checks the request, then forwards it.
async fn apply<S>(inner: S, request: Request, short_period: ShortPeriod) -> Result<Response, AggregationError>
where
    S: Service<Request, Response = Response, Error = Infallible> + Send + 'static,
    S::Future: Send + 'static,
{
    let decision = request.extensions().get::<Decision>().ok_or(AggregationError::Undecided)?;

    // A reference count, not a copy: the request that owns the decision is moved into the check below.
    let Some(restriction) = decision.aggregation.clone() else {
        // The policy that allowed the request attached no aggregation restriction.
        return Ok(forward(inner, request).await);
    };

    let open_ends = if decision.time.is_some() { OpenEnds::ClosedBelow } else { OpenEnds::Refused };
    let checked = check(request, &restriction, short_period, open_ends)?;

    Ok(forward(inner, checked).await)
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
fn check(request: Request, restriction: &AggregationRestriction, short_period: ShortPeriod, open_ends: OpenEnds) -> Result<Request, AggregationError> {
    let (parts, body) = request.into_parts();

    // Cloned because the operation travels in the parts that the temporal check takes by value.
    let operation = operation(&parts.extensions)?.clone();

    // The broker answers a listing with every subscription of the tenant, and changing one changes
    // what its notifications disclose to an endpoint Libra never sees.
    if EntityTarget::of(&operation) == EntityTarget::ExistingSubscriptions {
        return Err(AggregationError::SubscriptionsRefused);
    }

    if !operation.resource.is_temporal() {
        return match (restriction.unaggregated(), RawValues::of(&operation)) {
            (UnaggregatedReads::Disallowed, RawValues::Returned) => Err(AggregationError::RawValues),
            (UnaggregatedReads::Disallowed, RawValues::NotReturned) | (UnaggregatedReads::Allowed, RawValues::Returned | RawValues::NotReturned) => {
                Ok(Request::from_parts(parts, body))
            }
        };
    }

    // A temporal write supplies instances rather than reading them: it carries no `aggrMethods`,
    // returns no values, and holding it to an aggregation restriction would refuse every write to a
    // temporal resource in the name of a rule about what may be read.
    if !operation.is_read() {
        return Ok(Request::from_parts(parts, body));
    }

    check_temporal_read(parts, body, &operation.resource, restriction, short_period, open_ends)
}

/// What a temporal read falls short of, once every check has run.
struct Shortfalls<'r> {
    /// What the period check decided.
    period: Enforcement,
    /// The first window off the grid, with the minimum that lays the grid and every window's check.
    windows: Option<(&'r IsoDuration, WindowShortfall, WindowChecks)>,
}

/// Checks a temporal read's aggregation, wherever it is written, and forwards it unchanged when
/// nothing falls short.
fn check_temporal_read(
    mut parts: Parts,
    body: Body,
    resource: &Resource,
    restriction: &AggregationRestriction,
    short_period: ShortPeriod,
    open_ends: OpenEnds,
) -> Result<Request, AggregationError> {
    // Cloned because a raised read is written back through its own copy, while the parts the
    // stored parameters travel in are edited.
    let parameters = parameters(&parts.extensions)?.clone();

    let mut requested = RequestedAggregation {
        representation: temporal_representation(&parts)?,
        methods: parameters.aggregation_methods()?,
        periods: parameters.aggregation_period()?.into_iter().collect(),
    };

    // Only the batch query carries a payload worth reading; every other temporal read writes its
    // parameters in the query string, and its body, if it somehow has one, is passed on as it
    // arrived.
    let document = if matches!(resource, Resource::TemporalBatchQuery) {
        let document = query_body::take(&mut parts)?;
        query_body::collect(&document, &mut requested)?;
        Some(document)
    } else {
        None
    };

    let period = enforce(restriction, &requested)?;
    let windows = match (requested.representation, restriction.min_period_duration()) {
        (TemporalRepresentation::Aggregated, Some(minimum)) => Some((minimum, windows(minimum, &parameters, document.as_ref(), open_ends)?)),
        (TemporalRepresentation::Aggregated | TemporalRepresentation::Instances | TemporalRepresentation::Simplified, None)
        | (TemporalRepresentation::Instances | TemporalRepresentation::Simplified, Some(_)) => None,
    };

    let windows = windows.and_then(|(minimum, checks)| checks.shortfall().map(|shortfall| (minimum, shortfall, checks)));

    if matches!(period, Enforcement::Allowed) && windows.is_none() {
        // Unchanged, so the bytes go on as they arrived and the document goes back where the
        // layers below read it.
        if let Some(document) = document {
            RequestBody::restore(&mut parts, document);
        }

        return Ok(Request::from_parts(parts, body));
    }

    raise(parts, body, parameters, document, Shortfalls { period, windows }, short_period)
}

/// Refuses a read that falls short, or raises it where the deployment raises, writing every raised
/// value into every place the read carries it.
fn raise(
    mut parts: Parts,
    body: Body,
    mut parameters: QueryParameters,
    mut document: Option<Value>,
    shortfalls: Shortfalls<'_>,
    short_period: ShortPeriod,
) -> Result<Request, AggregationError> {
    let mut query = QueryChange::Untouched;

    if let Enforcement::RaisePeriod { minimum, shortfall } = shortfalls.period {
        match short_period {
            ShortPeriod::Refuse => return Err(shortfall.refusal(minimum)),
            ShortPeriod::Raise => {
                query = raise_period(&mut parameters, document.as_mut(), &minimum)?;
                debug!(minimum = %minimum, "raised the aggregation period to the policy minimum");
            }
        }
    }

    if let Some((minimum, shortfall, checks)) = shortfalls.windows {
        match short_period {
            // Cloned because the refusal owns the minimum and the restriction keeps its own.
            ShortPeriod::Refuse => return Err(shortfall.refusal(minimum.clone())),
            ShortPeriod::Raise => {
                if raise_windows(&mut parameters, document.as_mut(), checks)? == QueryChange::Rewritten {
                    query = QueryChange::Rewritten;
                }
                debug!(minimum = %minimum, "moved the aggregated window out to the grid of the policy minimum");
            }
        }
    }

    if query == QueryChange::Rewritten {
        replace_query(&mut parts, parameters).map_err(|_| AggregationError::Unrewritable)?;
    }

    // The document, its bytes and `Content-Length` are written together, so the body forwarded is
    // the one every layer below reads.
    let body = document.map_or(body, |document| RequestBody::replace(&mut parts, document));

    Ok(Request::from_parts(parts, body))
}

/// Checks every window an aggregated read names against the grid of the policy minimum.
fn windows(minimum: &IsoDuration, parameters: &QueryParameters, document: Option<&Value>, open_ends: OpenEnds) -> Result<WindowChecks, AggregationError> {
    let body = document.map(query_body::temporal_query).transpose()?;

    check_windows(AggregationGrid::new(minimum), TemporalSelector::of_parameters(parameters), body, open_ends)
}

/// The temporal representation the request resolved to.
fn temporal_representation(parts: &Parts) -> Result<TemporalRepresentation, AggregationError> {
    match parts.extensions.get::<RequestRepresentation>() {
        Some(RequestRepresentation::Resolved(representation)) => Ok(representation.temporal()),
        Some(RequestRepresentation::Unresolvable(_)) => Err(AggregationError::UnresolvableRepresentation),
        None => Err(AggregationError::Unresolved),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use http::{Method, StatusCode};
    use http_body_util::BodyExt;
    use libra_config::representation::RepresentationStrictness;
    use libra_ngsi_ld_operation::operation::Operation;
    use libra_ngsi_ld_operation_layer::layer::{OperationLayer, classify};
    use libra_ngsi_ld_query_layer::layer::QueryLayer;
    use libra_ngsi_ld_representation_layer::RepresentationLayer;
    use libra_policy_model::{
        effect::Effect,
        time::{CurrentState, TimeRestriction},
    };
    use pretty_assertions::assert_eq;
    use std::sync::{Arc, Mutex, PoisonError};
    use tower::util::BoxCloneService;

    /// What the upstream saw.
    #[derive(Clone, Default)]
    struct Seen {
        uri: Arc<Mutex<Option<String>>>,
        body: Arc<Mutex<String>>,
    }

    impl Seen {
        /// The URI the broker was sent, or `None` if the request never reached it.
        fn uri(&self) -> Option<String> {
            self.uri.lock().unwrap_or_else(PoisonError::into_inner).clone()
        }

        fn body(&self) -> String {
            self.body.lock().unwrap_or_else(PoisonError::into_inner).clone()
        }
    }

    fn upstream(seen: &Seen) -> BoxCloneService<Request, Response, Infallible> {
        let seen = seen.clone(); // the stand-in broker records into the test's handles
        BoxCloneService::new(tower::service_fn(move |request: Request| {
            let seen = seen.clone(); // one handle per request
            async move {
                *seen.uri.lock().unwrap_or_else(PoisonError::into_inner) = Some(request.uri().to_string());

                let bytes = request.into_body().collect().await.map(http_body_util::Collected::to_bytes).unwrap_or_default();
                *seen.body.lock().unwrap_or_else(PoisonError::into_inner) = String::from_utf8_lossy(&bytes).into_owned();

                Ok(Response::new(Body::empty()))
            }
        }))
    }

    fn decision(restriction: Option<&str>) -> Decision {
        Decision {
            effect: Effect::Allow,
            matched: None,
            scope: None,
            entity_type: None,
            time: None,
            attribute: None,
            aggregation: restriction.map(|source| toml::from_str(source).unwrap()),
        }
    }

    async fn run(method: Method, uri: &str, body: &'static str, policy: Option<&str>, short_period: ShortPeriod, seen: &Seen) -> Response {
        let mut request = Request::builder()
            .method(method)
            .uri(uri)
            .body(Body::from(body))
            .unwrap_or_else(|_| Request::new(Body::empty()));
        request.extensions_mut().insert(decision(policy));
        // The body the context layer above would have read from the request.
        request
            .extensions_mut()
            .insert(RequestBody::read(body.as_bytes()).expect("the test body is readable"));

        serve(request, short_period, seen).await
    }

    /// Serves a request under the layer that resolves, above authorization, the answer's
    /// representation.
    async fn serve(request: Request, short_period: ShortPeriod, seen: &Seen) -> Response {
        let mut service = OperationLayer::new().layer(
            QueryLayer::new().layer(
                RepresentationLayer::new(RepresentationStrictness::default())
                    .layer(AggregationEnforcementLayer::new(&Aggregation { short_period }).layer(upstream(seen))),
            ),
        );

        service.call(request).await.unwrap_or_else(|error| match error {})
    }

    async fn get(uri: &str, policy: Option<&str>, seen: &Seen) -> Response {
        run(Method::GET, uri, "", policy, ShortPeriod::Refuse, seen).await
    }

    async fn batch_query(uri: &str, body: &'static str, policy: &str, short_period: ShortPeriod, seen: &Seen) -> Response {
        run(Method::POST, uri, body, Some(policy), short_period, seen).await
    }

    const AVERAGES_ONLY: &str = "unaggregated = \"disallowed\"\nallowed-methods = [\"avg\"]";
    const ONLY_AVG: &str = "allowed-methods = [\"avg\"]";
    const HOURLY_AVG: &str = "allowed-methods = [\"avg\"]\nmin-period-duration = \"PT1H\"";
    const BATCH: &str = "/ngsi-ld/v1/temporal/entityOperations/query?options=aggregatedValues";

    #[tokio::test]
    async fn a_request_with_no_aggregation_restriction_passes_through_untouched() {
        let seen = Seen::default();
        let response = get("/ngsi-ld/v1/temporal/entities?type=Vehicle", None, &seen).await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(seen.uri().as_deref(), Some("/ngsi-ld/v1/temporal/entities?type=Vehicle"));
    }

    #[tokio::test]
    async fn an_allowed_aggregated_read_reaches_the_broker_as_written() {
        let seen = Seen::default();
        let uri = "/ngsi-ld/v1/temporal/entities?type=Vehicle&options=aggregatedValues&aggrMethods=avg&aggrPeriodDuration=PT2H&timerel=between&timeAt=2026-03-01T10:00:00Z&endTimeAt=2026-03-01T12:00:00Z";
        let response = get(uri, Some(HOURLY_AVG), &seen).await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(seen.uri().as_deref(), Some(uri));
    }

    #[tokio::test]
    async fn methods_without_aggregated_values_are_refused_when_unaggregated_reads_are_disallowed() {
        // NGSI-LD clause 6.18.3.2: without `aggregatedValues` the broker ignores `aggrMethods` and
        // answers with every instance.
        let seen = Seen::default();
        let response = get(
            "/ngsi-ld/v1/temporal/entities?type=Vehicle&aggrMethods=avg&aggrPeriodDuration=PT1H",
            Some(AVERAGES_ONLY),
            &seen,
        )
        .await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(seen.uri(), None);
    }

    #[tokio::test]
    async fn a_method_outside_the_specification_is_a_bad_request_whatever_the_policy_lists() {
        let response = get(
            "/ngsi-ld/v1/temporal/entities?options=aggregatedValues&aggrMethods=whatever",
            Some(r#"min-period-duration = "PT1H""#),
            &Seen::default(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn a_disallowed_method_in_any_place_of_a_batch_query_body_is_refused() {
        for body in [
            r#"{"type":"Query","aggrParams":{"aggrMethods":"max"}}"#,
            r#"{"type":"Query","temporalQ":{"timerel":"after","timeAt":"2020-01-01T00:00:00Z","aggrMethods":["max"]}}"#,
            r#"{"type":"Query","aggrMethods":"max"}"#,
        ] {
            let seen = Seen::default();
            let response = batch_query(BATCH, body, ONLY_AVG, ShortPeriod::Refuse, &seen).await;

            assert_eq!(response.status(), StatusCode::FORBIDDEN, "{body}");
            assert_eq!(seen.uri(), None, "{body}");
        }
    }

    #[tokio::test]
    async fn an_allowed_method_in_the_aggregation_params_of_a_batch_query_is_served() {
        let seen = Seen::default();
        let response = batch_query(
            BATCH,
            r#"{"type":"Query","aggrParams":{"aggrMethods":"avg"}}"#,
            ONLY_AVG,
            ShortPeriod::Refuse,
            &seen,
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert!(seen.body().contains(r#""aggrMethods":"avg""#), "{}", seen.body());
    }

    #[tokio::test]
    async fn a_raised_period_replaces_every_finer_one_in_the_query_string_and_the_body() {
        let seen = Seen::default();
        let response = batch_query(
            "/ngsi-ld/v1/temporal/entityOperations/query?options=aggregatedValues&aggrMethods=avg&aggrPeriodDuration=PT5M",
            r#"{"type":"Query","temporalQ":{"timerel":"between","timeAt":"2026-03-01T10:00:00Z","endTimeAt":"2026-03-01T12:00:00Z","aggrPeriodDuration":"PT5M"},"aggrParams":{"aggrMethods":"avg","aggrPeriodDuration":"PT5M"}}"#,
            HOURLY_AVG,
            ShortPeriod::Raise,
            &seen,
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert!(seen.uri().is_some_and(|uri| uri.contains("aggrPeriodDuration=PT1H")), "{:?}", seen.uri());
        assert!(!seen.body().contains("PT5M"), "{}", seen.body());
        assert_eq!(seen.body().matches(r#""aggrPeriodDuration":"PT1H""#).count(), 2, "{}", seen.body());
    }

    #[tokio::test]
    async fn a_batch_query_body_that_is_not_a_json_object_is_a_bad_request() {
        for body in ["type=Query", "[1, 2]"] {
            let response = batch_query(BATCH, body, AVERAGES_ONLY, ShortPeriod::Refuse, &Seen::default()).await;

            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{body}");
        }
    }

    #[tokio::test]
    async fn a_finer_period_is_refused_unless_the_deployment_raises_it() {
        let uri = "/ngsi-ld/v1/temporal/entities?options=aggregatedValues&aggrMethods=avg&aggrPeriodDuration=PT5M&timerel=between&timeAt=2026-03-01T10:00:00Z&endTimeAt=2026-03-01T12:00:00Z";

        let refused = get(uri, Some(HOURLY_AVG), &Seen::default()).await;
        assert_eq!(refused.status(), StatusCode::FORBIDDEN);

        let seen = Seen::default();
        let raised = run(Method::GET, uri, "", Some(HOURLY_AVG), ShortPeriod::Raise, &seen).await;
        assert_eq!(raised.status(), StatusCode::OK);
        assert!(seen.uri().is_some_and(|uri| uri.contains("aggrPeriodDuration=PT1H")), "{:?}", seen.uri());
    }

    #[tokio::test]
    async fn disallowing_unaggregated_reads_leaves_the_schema_endpoints_alone() {
        for uri in ["/ngsi-ld/v1/types", "/ngsi-ld/v1/attributes", "/ngsi-ld/v1/types/Vehicle"] {
            let response = get(uri, Some(AVERAGES_ONLY), &Seen::default()).await;

            assert_eq!(response.status(), StatusCode::OK, "{uri} returns schema, not values");
        }
    }

    #[tokio::test]
    async fn disallowing_unaggregated_reads_refuses_current_state_reads() {
        for uri in [
            "/ngsi-ld/v1/entities?type=Vehicle",
            "/ngsi-ld/v1/entities/urn:ngsi-ld:Vehicle:1",
            "/ngsi-ld/v1/entities/urn:ngsi-ld:Vehicle:1/attrs/speed",
        ] {
            let response = get(uri, Some(AVERAGES_ONLY), &Seen::default()).await;

            assert_eq!(response.status(), StatusCode::FORBIDDEN, "{uri} returns raw values");
        }

        let batch = run(
            Method::POST,
            "/ngsi-ld/v1/entityOperations/query",
            r#"{"type":"Query"}"#,
            Some(AVERAGES_ONLY),
            ShortPeriod::Refuse,
            &Seen::default(),
        )
        .await;
        assert_eq!(batch.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn disallowing_unaggregated_reads_refuses_a_new_subscription_and_reading_one_back() {
        // A subscription's notifications go from the broker to a callback without passing through
        // Libra, so nothing could hold them to the restriction, and a listing holds every
        // subscription of the tenant.
        let created = run(
            Method::POST,
            "/ngsi-ld/v1/subscriptions",
            r#"{"type":"Subscription"}"#,
            Some(AVERAGES_ONLY),
            ShortPeriod::Refuse,
            &Seen::default(),
        )
        .await;
        assert_eq!(created.status(), StatusCode::FORBIDDEN);

        let listed = get("/ngsi-ld/v1/subscriptions", Some(AVERAGES_ONLY), &Seen::default()).await;
        assert_eq!(listed.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn reading_subscriptions_is_refused_under_a_restriction() {
        for uri in ["/ngsi-ld/v1/subscriptions", "/ngsi-ld/v1/subscriptions/urn:ngsi-ld:Subscription:1"] {
            let seen = Seen::default();
            let response = get(uri, Some(ONLY_AVG), &seen).await;

            assert_eq!(response.status(), StatusCode::FORBIDDEN, "{uri}");
            assert_eq!(seen.uri(), None, "{uri}");
        }
    }

    #[tokio::test]
    async fn updating_a_subscription_is_refused_under_a_restriction() {
        let seen = Seen::default();
        let response = run(
            Method::PATCH,
            "/ngsi-ld/v1/subscriptions/urn:ngsi-ld:Subscription:1",
            r#"{"type":"Subscription","isActive":false}"#,
            Some(ONLY_AVG),
            ShortPeriod::Refuse,
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
            Method::DELETE,
            "/ngsi-ld/v1/subscriptions/urn:ngsi-ld:Subscription:1",
            "",
            Some(ONLY_AVG),
            ShortPeriod::Refuse,
            &seen,
        )
        .await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(seen.uri(), None);
    }

    #[tokio::test]
    async fn creating_a_subscription_is_still_narrowed() {
        // Creating one is refused only where unaggregated reads are: what it discloses is
        // governed by the rule about unaggregated values.
        let body = r#"{"type":"Subscription","entities":[{"type":"Vehicle"}]}"#;
        let seen = Seen::default();
        let allowed = run(Method::POST, "/ngsi-ld/v1/subscriptions", body, Some(ONLY_AVG), ShortPeriod::Refuse, &seen).await;

        assert_eq!(allowed.status(), StatusCode::OK);
        assert_eq!(seen.body(), body);

        let refused = run(
            Method::POST,
            "/ngsi-ld/v1/subscriptions",
            body,
            Some(AVERAGES_ONLY),
            ShortPeriod::Refuse,
            &Seen::default(),
        )
        .await;
        assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn subscriptions_are_forwarded_without_a_restriction() {
        for (method, uri) in [
            (Method::GET, "/ngsi-ld/v1/subscriptions"),
            (Method::GET, "/ngsi-ld/v1/subscriptions/urn:ngsi-ld:Subscription:1"),
            (Method::DELETE, "/ngsi-ld/v1/subscriptions/urn:ngsi-ld:Subscription:1"),
        ] {
            let seen = Seen::default();
            let response = run(method, uri, "", None, ShortPeriod::Refuse, &seen).await;

            assert_eq!(response.status(), StatusCode::OK, "{uri}");
            assert_eq!(seen.uri().as_deref(), Some(uri));
        }
    }

    #[tokio::test]
    async fn a_request_without_a_decision_is_refused() {
        // A wiring fault: authorization attaches a decision to everything it lets through.
        let seen = Seen::default();
        let request = Request::builder()
            .method(Method::GET)
            .uri("/ngsi-ld/v1/temporal/entities?type=Vehicle")
            .body(Body::empty())
            .unwrap_or_else(|_| Request::new(Body::empty()));

        let response = serve(request, ShortPeriod::Refuse, &seen).await;

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(seen.uri(), None, "nothing reached the broker");
    }

    const AGGREGATED: &str = "/ngsi-ld/v1/temporal/entities?type=Vehicle&options=aggregatedValues&aggrMethods=avg&aggrPeriodDuration=PT1H";

    #[tokio::test]
    async fn an_aggregated_read_on_the_grid_is_forwarded() {
        let uri = format!("{AGGREGATED}&timerel=between&timeAt=2026-03-01T10:00:00Z&endTimeAt=2026-03-01T13:00:00Z");
        let seen = Seen::default();
        let response = get(&uri, Some(HOURLY_AVG), &seen).await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(seen.uri(), Some(uri));
    }

    #[tokio::test]
    async fn an_aggregated_read_off_the_grid_is_refused() {
        for window in [
            "timerel=between&timeAt=2026-03-01T10:20:00Z&endTimeAt=2026-03-01T13:00:00Z",
            "timerel=between&timeAt=2026-03-01T10:00:00Z&endTimeAt=2026-03-01T13:00:00.001Z",
            // An hour on a clock half an hour off UTC is not a grid point.
            "timerel=between&timeAt=2026-03-01T10:00:00%2B00:30&endTimeAt=2026-03-01T13:00:00Z",
        ] {
            let seen = Seen::default();
            let response = get(&format!("{AGGREGATED}&{window}"), Some(HOURLY_AVG), &seen).await;

            assert_eq!(response.status(), StatusCode::FORBIDDEN, "{window}");
            assert_eq!(seen.uri(), None, "{window}");
        }
    }

    #[tokio::test]
    async fn an_aggregated_read_off_the_grid_is_raised_to_it() {
        let uri = format!("{AGGREGATED}&timerel=between&timeAt=2026-03-01T10:20:00Z&endTimeAt=2026-03-01T12:10:00Z");
        let seen = Seen::default();
        let response = run(Method::GET, &uri, "", Some(HOURLY_AVG), ShortPeriod::Raise, &seen).await;

        assert_eq!(response.status(), StatusCode::OK);
        let forwarded = seen.uri().unwrap_or_default();
        assert!(forwarded.contains("timeAt=2026-03-01T10%3A00%3A00.000Z"), "{forwarded}");
        assert!(forwarded.contains("endTimeAt=2026-03-01T13%3A00%3A00.000Z"), "{forwarded}");
    }

    #[tokio::test]
    async fn a_window_shorter_than_one_period_is_refused() {
        let uri = format!("{AGGREGATED}&timerel=between&timeAt=2026-03-01T10:00:00Z&endTimeAt=2026-03-01T10:00:00Z");
        let seen = Seen::default();
        let response = get(&uri, Some(HOURLY_AVG), &seen).await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(seen.uri(), None);
    }

    #[tokio::test]
    async fn an_aggregated_window_in_a_batch_query_body_is_held_to_the_grid() {
        let body = r#"{"type":"Query","temporalQ":{"timerel":"between","timeAt":"2026-03-01T10:20:00Z","endTimeAt":"2026-03-01T12:00:00Z"},"aggrParams":{"aggrMethods":"avg","aggrPeriodDuration":"PT1H"}}"#;

        let refused = batch_query(BATCH, body, HOURLY_AVG, ShortPeriod::Refuse, &Seen::default()).await;
        assert_eq!(refused.status(), StatusCode::FORBIDDEN);

        let seen = Seen::default();
        let raised = batch_query(BATCH, body, HOURLY_AVG, ShortPeriod::Raise, &seen).await;
        assert_eq!(raised.status(), StatusCode::OK);
        assert!(seen.body().contains(r#""timeAt":"2026-03-01T10:00:00.000Z""#), "{}", seen.body());
    }

    #[tokio::test]
    async fn an_open_aggregated_window_is_refused_unless_a_time_restriction_closes_it() {
        let uri = format!("{AGGREGATED}&timerel=after&timeAt=2026-03-01T10:00:00Z");

        let refused = get(&uri, Some(HOURLY_AVG), &Seen::default()).await;
        assert_eq!(refused.status(), StatusCode::FORBIDDEN);

        let seen = Seen::default();
        let mut request = Request::builder()
            .method(Method::GET)
            .uri(&uri)
            .body(Body::empty())
            .unwrap_or_else(|_| Request::new(Body::empty()));
        request.extensions_mut().insert(Decision {
            time: Some(Arc::new(TimeRestriction::Absolute {
                start: "2026-01-01T00:00:00Z".parse().unwrap(),
                end: "2026-12-31T00:00:00Z".parse().unwrap(),
                current_state: CurrentState::RequestInWindow,
            })),
            ..decision(Some(HOURLY_AVG))
        });
        request.extensions_mut().insert(RequestBody::Empty);

        let closed = serve(request, ShortPeriod::Refuse, &seen).await;
        assert_eq!(closed.status(), StatusCode::OK);
        assert_eq!(seen.uri(), Some(uri));
    }

    #[tokio::test]
    async fn a_period_that_is_not_a_whole_number_of_minimum_periods_is_refused() {
        let uri = "/ngsi-ld/v1/temporal/entities?options=aggregatedValues&aggrMethods=avg&aggrPeriodDuration=PT90M&timerel=between&timeAt=2026-03-01T10:00:00Z&endTimeAt=2026-03-01T13:00:00Z";

        let response = get(uri, Some(HOURLY_AVG), &Seen::default()).await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn disallowing_unaggregated_reads_refuses_a_path_this_version_cannot_name() {
        let response = get("/ngsi-ld/v1/somethingNew", Some(AVERAGES_ONLY), &Seen::default()).await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn a_temporal_retrieve_by_id_is_held_to_the_same_restriction_as_a_query() {
        // A temporal retrieve-by-id returns the whole history of one entity, which is the raw data
        // the restriction exists to withhold, in a more concentrated form.
        let response = get("/ngsi-ld/v1/temporal/entities/urn:ngsi-ld:Vehicle:1", Some(AVERAGES_ONLY), &Seen::default()).await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn a_temporal_write_is_not_held_to_the_restriction() {
        // It supplies instances rather than reading them.
        let posted = run(
            Method::POST,
            "/ngsi-ld/v1/temporal/entities",
            r#"{"id":"urn:ngsi-ld:Vehicle:1"}"#,
            Some(AVERAGES_ONLY),
            ShortPeriod::Refuse,
            &Seen::default(),
        )
        .await;
        assert_eq!(posted.status(), StatusCode::OK);

        let deleted = run(
            Method::DELETE,
            "/ngsi-ld/v1/temporal/entities/urn:ngsi-ld:Vehicle:1/attrs/speed/instance-7",
            "",
            Some(AVERAGES_ONLY),
            ShortPeriod::Refuse,
            &Seen::default(),
        )
        .await;
        assert_eq!(deleted.status(), StatusCode::OK);
    }

    /// A request as the operation and query layers above leave it, with `parameters` stored in
    /// place of the query its target carries.
    fn stored(uri: &str, parameters: &str, policy: &str) -> Request {
        let (mut parts, body) = Request::builder().uri(uri).body(Body::empty()).unwrap().into_parts();
        classify(&mut parts).unwrap();
        parts.extensions.insert(QueryParameters::parse(parameters).unwrap());
        parts.extensions.insert(decision(Some(policy)));
        parts.extensions.insert(RequestBody::Empty);

        Request::from_parts(parts, body)
    }

    /// Serves a request that already carries what the operation and query layers store.
    async fn serve_stored(request: Request, seen: &Seen) -> Response {
        let mut service = RepresentationLayer::new(RepresentationStrictness::default()).layer(
            AggregationEnforcementLayer::new(&Aggregation {
                short_period: ShortPeriod::Refuse,
            })
            .layer(upstream(seen)),
        );

        service.call(request).await.unwrap_or_else(|error| match error {})
    }

    #[tokio::test]
    async fn the_methods_are_read_from_the_stored_query_not_from_the_request_target() {
        let seen = Seen::default();
        let request = stored(
            "/ngsi-ld/v1/temporal/entities?options=aggregatedValues&aggrMethods=avg",
            "options=aggregatedValues&aggrMethods=max",
            AVERAGES_ONLY,
        );

        assert_eq!(serve_stored(request, &seen).await.status(), StatusCode::FORBIDDEN);
        assert_eq!(seen.uri(), None, "nothing reached the broker");
    }

    #[tokio::test]
    async fn a_request_that_reached_this_layer_unclassified_or_unparsed_is_refused() {
        let seen = Seen::default();
        let uri = "/ngsi-ld/v1/temporal/entities?options=aggregatedValues&aggrMethods=avg";

        let mut unclassified = stored(uri, "options=aggregatedValues&aggrMethods=avg", AVERAGES_ONLY);
        unclassified.extensions_mut().remove::<Operation>();
        assert_eq!(serve_stored(unclassified, &seen).await.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let mut unparsed = stored(uri, "options=aggregatedValues&aggrMethods=avg", AVERAGES_ONLY);
        unparsed.extensions_mut().remove::<QueryParameters>();
        assert_eq!(serve_stored(unparsed, &seen).await.status(), StatusCode::INTERNAL_SERVER_ERROR);

        assert_eq!(seen.uri(), None, "nothing reached the broker");
    }

    #[tokio::test]
    async fn a_temporal_read_whose_representation_cannot_be_resolved_is_refused() {
        // Whether the answer aggregates is exactly what cannot be told.
        let response = get(
            "/ngsi-ld/v1/temporal/entities?options=temporalValues,aggregatedValues&aggrMethods=avg",
            Some(ONLY_AVG),
            &Seen::default(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn a_request_without_a_parsed_body_is_refused() {
        // A wiring error: the context layer above reads every body. A batch query's aggregation is
        // in its body, and forwarding it unread is forwarding it unchecked.
        let seen = Seen::default();
        let mut request = Request::builder()
            .method(Method::POST)
            .uri(BATCH)
            .body(Body::from(r#"{"type":"Query","aggrMethods":"max"}"#))
            .unwrap_or_else(|_| Request::new(Body::empty()));
        request.extensions_mut().insert(decision(Some(ONLY_AVG)));

        let response = serve(request, ShortPeriod::Refuse, &seen).await;

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(seen.uri(), None, "nothing reached the broker");
    }

    #[tokio::test]
    async fn an_allowed_batch_query_body_is_forwarded_as_it_arrived() {
        // Nothing was changed, so nothing is rewritten: member order and the lexical form of every
        // number reach the broker as the caller wrote them.
        let body = r#"{"type":"Query","aggrParams":{"aggrMethods":"avg"},"entities":[{"type":"Vehicle"}],"limit":1.0}"#;
        let seen = Seen::default();
        let response = batch_query(BATCH, body, ONLY_AVG, ShortPeriod::Refuse, &seen).await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(seen.body(), body);
    }

    #[tokio::test]
    async fn a_batch_query_that_names_an_aggregation_member_twice_is_a_bad_request() {
        let seen = Seen::default();
        let mut request = Request::builder()
            .method(Method::POST)
            .uri(BATCH)
            .body(Body::empty())
            .unwrap_or_else(|_| Request::new(Body::empty()));
        request.extensions_mut().insert(decision(Some(ONLY_AVG)));
        // The strict read refuses a repeated member, so the parse is built directly.
        request
            .extensions_mut()
            .insert(RequestBody::Json(jstrict::json!({"type": "Query", "aggrMethods": "avg", "aggrMethods": "max"})));

        let response = serve(request, ShortPeriod::Refuse, &seen).await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(seen.uri(), None, "nothing reached the broker");
    }
}
