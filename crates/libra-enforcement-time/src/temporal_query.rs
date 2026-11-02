//! Narrowing the window a temporal read names, where it names it.
//!
//! A temporal query writes its window in the query string; `POST /temporal/entityOperations/query`
//! writes it in the `temporalQ` of its body (NGSI-LD clause 5.2.23). Both are narrowed to the
//! policy's window by [`narrow_window`], and both are written back as a `between` window, so the
//! broker is never left to fill in an open end.

use crate::{error::TimeError, narrowing::narrow_window, window::Window};
use axum::{body::Body, http::request::Parts};
use jiff::Timestamp;
use jstrict::{Value, object::Object};
use libra_json_body::request_body::RequestBody;
use libra_ngsi_ld_query::{
    error::QueryError,
    parameter_name::ParameterName,
    parameters::QueryParameters,
    temporal_selector::{TEMPORAL_QUERY_MEMBER, TemporalSelector, TimeRelation},
};
use libra_ngsi_ld_query_layer::parsed::replace_query;
use libra_policy_model::{aggregation_grid::AggregationGrid, time::TimeRestriction};
use tracing::debug;

/// The temporal property a time restriction's window is a window of (NGSI-LD clause 4.11 default).
const OBSERVED_AT: &str = "observedAt";

/// Whether a request carries its window only in its query string or may carry it in a body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WindowPlace {
    /// The query string is the only place: a window is put there whether or not the caller wrote one.
    QueryString,
    /// A `Query` body carries the window, so a query string that names none is left alone rather
    /// than having a second window appended to it.
    QueryStringOrBody,
}

/// Refuses a temporal query evaluated against a temporal property other than `observedAt`.
///
/// Absent means `observedAt` (NGSI-LD clause 4.11) and is left absent.
///
/// # Errors
///
/// Returns [`TimeError::TimePropertyRefused`] for any other temporal property.
pub(crate) fn judge_time_property(selector: TemporalSelector<'_>) -> Result<(), TimeError> {
    match selector.timeproperty {
        None | Some(OBSERVED_AT) => Ok(()),
        Some(other) => Err(TimeError::TimePropertyRefused { property: other.to_owned() }),
    }
}

/// Narrows the bounds written in the query string.
///
/// `grid` is the grid of an aggregation minimum period when the read aggregates under one, and the
/// narrowed window is then rounded inward to it.
pub(crate) fn narrow_query(
    parts: &mut Parts,
    mut parameters: QueryParameters,
    restriction: &TimeRestriction,
    now: Timestamp,
    grid: Option<AggregationGrid>,
    place: WindowPlace,
) -> Result<(), TimeError> {
    let selector = TemporalSelector::of_parameters(&parameters);

    if place == WindowPlace::QueryStringOrBody && !selector.bounds_anything() {
        return Ok(());
    }

    let window = narrowed(selector, restriction, now, grid)?;

    parameters.set(ParameterName::TIMEREL, TimeRelation::Between.to_string());
    parameters.set(ParameterName::TIME_AT, window.start_text());
    parameters.set(ParameterName::END_TIME_AT, window.end_text());

    // A variant rather than an `unwrap`: the URI is rebuilt from a caller-supplied path.
    replace_query(parts, parameters).map_err(|_| TimeError::Unrewritable)?;

    debug!(uri = %parts.uri, "narrowed a temporal query to the allowed window");

    Ok(())
}

/// Narrows the `temporalQ` a temporal batch query carries in its body.
///
/// The narrowed document goes back through [`RequestBody::replace`], which writes it, its bytes
/// and `Content-Length` together; the returned body is the one to forward.
pub(crate) fn narrow_body(parts: &mut Parts, restriction: &TimeRestriction, now: Timestamp, grid: Option<AggregationGrid>) -> Result<Body, TimeError> {
    let mut document = RequestBody::take_document(parts)?.ok_or(TimeError::MalformedBody {
        reason: "it is not a JSON document",
    })?;

    let query = document.as_object_mut().ok_or(TimeError::MalformedBody {
        reason: "it is not a JSON object",
    })?;

    // Absent means "every instant the broker holds", which is the case that most needs a window
    // put on it, so the member is created rather than skipped.
    if query.get_unique(TEMPORAL_QUERY_MEMBER).map_err(|_| repeated())?.is_none() {
        query.push(TEMPORAL_QUERY_MEMBER.into(), Value::Object(Object::new()));
    }

    let temporal = query
        .get_unique_mut(TEMPORAL_QUERY_MEMBER)
        .map_err(|_| repeated())?
        .and_then(Value::as_object_mut)
        .ok_or(TimeError::MalformedBody {
            reason: "its temporalQ member is not an object",
        })?;

    let selector = TemporalSelector::of_temporal_query(temporal).map_err(|error| unreadable(&error))?;
    judge_time_property(selector)?;
    let window = narrowed(selector, restriction, now, grid)?;

    temporal.insert(ParameterName::TIMEREL.as_str().into(), Value::String(TimeRelation::Between.to_string().into()));
    temporal.insert(ParameterName::TIME_AT.as_str().into(), Value::from(window.start_text()));
    temporal.insert(ParameterName::END_TIME_AT.as_str().into(), Value::from(window.end_text()));

    debug!("narrowed the temporal query in a batch query body to the allowed window");

    Ok(RequestBody::replace(parts, document))
}

/// The window a selector is narrowed to, rounded inward to the grid when there is one.
///
/// Rounding inward is what keeps a boundary the policy moved on the grid an aggregated window has
/// to sit on. A boundary the policy did not move was already on it: aggregation enforcement above
/// refuses or raises one that is not.
fn narrowed(selector: TemporalSelector<'_>, restriction: &TimeRestriction, now: Timestamp, grid: Option<AggregationGrid>) -> Result<Window, TimeError> {
    let window = narrow_window(selector, restriction, now)?;

    let Some(grid) = grid else {
        return Ok(window);
    };

    grid.inward(window.start(), window.end()).map(Window::from).ok_or(TimeError::NoWholePeriod)
}

/// The refusal of a member named more than once: the occurrence narrowed here need not be the one
/// the broker reads.
const fn repeated() -> TimeError {
    TimeError::MalformedBody {
        reason: "it names a temporal query member more than once",
    }
}

/// The refusal of a `temporalQ` whose members cannot be read one way only.
fn unreadable(error: &QueryError) -> TimeError {
    TimeError::MalformedQuery { reason: error.to_string() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libra_policy_model::{duration::IsoDuration, time::CurrentState};
    use pretty_assertions::assert_eq;

    fn at(text: &str) -> Timestamp {
        text.parse().unwrap()
    }

    fn property(timeproperty: Option<&str>) -> TemporalSelector<'_> {
        TemporalSelector {
            timeproperty,
            ..TemporalSelector::default()
        }
    }

    fn year() -> TimeRestriction {
        TimeRestriction::Absolute {
            start: at("2026-01-01T00:20:00Z"),
            end: at("2026-12-31T23:59:59Z"),
            current_state: CurrentState::RequestInWindow,
        }
    }

    #[test]
    fn only_observed_at_or_no_time_property_passes() {
        assert_eq!(judge_time_property(property(None)), Ok(()));
        assert_eq!(judge_time_property(property(Some("observedAt"))), Ok(()));
        assert_eq!(
            judge_time_property(property(Some("modifiedAt"))),
            Err(TimeError::TimePropertyRefused {
                property: "modifiedAt".to_owned()
            })
        );
        assert!(judge_time_property(property(Some("ObservedAt"))).is_err(), "names are case-sensitive");
    }

    #[test]
    fn a_window_is_rounded_inward_only_under_a_grid() {
        let hourly = AggregationGrid::new(&IsoDuration::parse("PT1H").unwrap());

        let raw = narrowed(TemporalSelector::default(), &year(), at("2026-06-01T12:00:00Z"), None).unwrap();
        assert_eq!(raw.start(), at("2026-01-01T00:20:00Z"));

        let rounded = narrowed(TemporalSelector::default(), &year(), at("2026-06-01T12:00:00Z"), Some(hourly)).unwrap();
        assert_eq!(rounded, Window::new(at("2026-01-01T01:00:00Z"), at("2026-12-31T23:00:00Z")));
    }

    #[test]
    fn a_window_holding_no_whole_period_is_refused() {
        let daily = AggregationGrid::new(&IsoDuration::parse("P1D").unwrap());
        let short = TimeRestriction::Absolute {
            start: at("2026-03-01T10:00:00Z"),
            end: at("2026-03-02T09:00:00Z"),
            current_state: CurrentState::RequestInWindow,
        };

        assert_eq!(
            narrowed(TemporalSelector::default(), &short, at("2026-03-01T12:00:00Z"), Some(daily)),
            Err(TimeError::NoWholePeriod)
        );
    }

    /// The query string a batch query's URI carries once [`narrow_query`] has run on it.
    fn narrowed_query_string(query: &str) -> Option<String> {
        let (mut parts, ()) = http::Request::builder()
            .uri(format!("/ngsi-ld/v1/temporal/entityOperations/query?{query}"))
            .body(())
            .unwrap()
            .into_parts();
        let parameters = QueryParameters::parse(query).unwrap();

        narrow_query(
            &mut parts,
            parameters,
            &year(),
            at("2026-06-01T12:00:00Z"),
            None,
            WindowPlace::QueryStringOrBody,
        )
        .unwrap();

        parts.uri.query().map(str::to_owned)
    }

    #[test]
    fn beside_a_body_a_query_string_window_is_narrowed_and_one_that_names_none_is_left_alone() {
        assert_eq!(
            narrowed_query_string("timerel=after&timeAt=2025-01-01T00:00:00Z").as_deref(),
            Some("endTimeAt=2026-12-31T23%3A59%3A59.000Z&timeAt=2026-01-01T00%3A20%3A00.000Z&timerel=between")
        );
        assert_eq!(narrowed_query_string("options=sysAttrs").as_deref(), Some("options=sysAttrs"));
    }
}
