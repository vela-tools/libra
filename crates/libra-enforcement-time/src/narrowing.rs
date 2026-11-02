//! Narrowing the window a temporal query asked for to the one a policy allows.

use crate::{error::TimeError, window::Window};
use jiff::Timestamp;
use libra_ngsi_ld_query::temporal_selector::{TemporalSelector, TimeRelation};
use libra_policy_model::time::TimeRestriction;
use std::str::FromStr;

/// Narrows what the caller asked for to what the policy allows.
///
/// A query writes its bounds in the query string or in the `temporalQ` of its body; both arrive
/// here as the same [`TemporalSelector`], so there is one narrowing rule rather than one per place
/// the caller could have written them.
///
/// `now` is a parameter rather than a call to the clock so that the decision is a pure function of
/// its inputs: a relative window is defined against the instant the request arrived, and a test
/// that had to arrange for wall time to be a particular value could not pin one.
///
/// `lastN` is deliberately not touched. It selects the most recent instances *within* the window
/// the query names, so a narrowed window with `lastN=1000` returns at most a thousand instances
/// from inside the allowed window and cannot reach an instant outside it. It is a page size, not
/// a bound, and policing it would be a quota rather than a time restriction.
///
/// # Errors
///
/// Returns [`TimeError::UnknownRelation`], [`TimeError::MalformedInstant`],
/// [`TimeError::MissingBound`] or [`TimeError::BackwardsWindow`] when the request cannot be read,
/// and [`TimeError::OutsideWindow`] when what it asks for and what the policy allows do not meet.
pub fn narrow_window(selector: TemporalSelector<'_>, restriction: &TimeRestriction, now: Timestamp) -> Result<Window, TimeError> {
    let allowed = Window::from(restriction.window(now));
    let requested = requested_window(selector)?;

    if requested.is_backwards() {
        return Err(TimeError::BackwardsWindow);
    }

    allowed.intersect(requested).ok_or(TimeError::OutsideWindow)
}

/// The window the caller asked for, before the policy is applied.
fn requested_window(selector: TemporalSelector<'_>) -> Result<Window, TimeError> {
    let Some(written) = selector.timerel else {
        // No relation is a query over everything the broker holds. Intersecting that with the
        // policy's window gives the policy's window, which is what the caller then receives.
        return Ok(Window::unbounded());
    };

    let relation = TimeRelation::from_str(written).map_err(|_| TimeError::UnknownRelation { relation: written.to_owned() })?;

    // Both bounds are parsed whether or not the relation reads them. A malformed `endTimeAt` on a
    // `before` query is still a malformed request, and telling the caller so beats forwarding a
    // value the broker will reject with less context.
    let time_at = instant("timeAt", selector.time_at)?;
    let end_time_at = instant("endTimeAt", selector.end_time_at)?;

    let window = match relation {
        TimeRelation::Before => Window::new(Window::unbounded().start(), required(time_at, "timeAt", relation)?),
        TimeRelation::After => Window::new(required(time_at, "timeAt", relation)?, Window::unbounded().end()),
        TimeRelation::Between => Window::new(required(time_at, "timeAt", relation)?, required(end_time_at, "endTimeAt", relation)?),
    };

    Ok(window)
}

/// Reads one bound.
fn instant(parameter: &'static str, value: Option<&str>) -> Result<Option<Timestamp>, TimeError> {
    let Some(written) = value else {
        return Ok(None);
    };

    // Refused rather than replaced by the policy's own bound: a caller who mistyped a timestamp
    // would otherwise receive a window they never asked for and no indication why.
    written.parse::<Timestamp>().map(Some).map_err(|_| TimeError::MalformedInstant {
        parameter,
        value: written.to_owned(),
    })
}

/// Insists on a bound the relation cannot do without.
fn required(instant: Option<Timestamp>, parameter: &'static str, relation: TimeRelation) -> Result<Timestamp, TimeError> {
    instant.ok_or(TimeError::MissingBound { parameter, relation })
}

#[cfg(test)]
mod tests {
    use super::*;
    use libra_policy_model::{
        duration::IsoDuration,
        time::{CurrentState, Direction},
    };
    use pretty_assertions::assert_eq;

    fn at(text: &str) -> Timestamp {
        text.parse().unwrap()
    }

    fn absolute(start: &str, end: &str) -> TimeRestriction {
        TimeRestriction::Absolute {
            start: at(start),
            end: at(end),
            current_state: CurrentState::RequestInWindow,
        }
    }

    fn past(duration: &str) -> TimeRestriction {
        TimeRestriction::Relative {
            duration: IsoDuration::parse(duration).unwrap(),
            direction: Direction::Past,
            current_state: CurrentState::Refuse,
        }
    }

    fn selector<'a>(timerel: Option<&'a str>, time_at: Option<&'a str>, end_time_at: Option<&'a str>) -> TemporalSelector<'a> {
        TemporalSelector {
            timerel,
            time_at,
            end_time_at,
            timeproperty: None,
        }
    }

    const NOW: &str = "2026-06-01T12:00:00Z";

    #[test]
    fn a_window_wider_than_the_policys_is_narrowed_to_the_policys() {
        let narrowed = narrow_window(
            selector(Some("between"), Some("2025-01-01T00:00:00Z"), Some("2027-01-01T00:00:00Z")),
            &absolute("2026-01-01T00:00:00Z", "2026-12-31T23:59:59Z"),
            at(NOW),
        )
        .unwrap();

        assert_eq!(narrowed.start_text(), "2026-01-01T00:00:00.000Z");
        assert_eq!(narrowed.end_text(), "2026-12-31T23:59:59.000Z");
    }

    #[test]
    fn a_window_inside_the_policys_is_left_where_it_is() {
        let narrowed = narrow_window(
            selector(Some("between"), Some("2026-03-01T00:00:00Z"), Some("2026-04-01T00:00:00Z")),
            &absolute("2026-01-01T00:00:00Z", "2026-12-31T23:59:59Z"),
            at(NOW),
        )
        .unwrap();

        assert_eq!(narrowed, Window::new(at("2026-03-01T00:00:00Z"), at("2026-04-01T00:00:00Z")));
    }

    #[test]
    fn a_window_entirely_outside_the_policys_is_refused() {
        let refused = narrow_window(
            selector(Some("between"), Some("2024-01-01T00:00:00Z"), Some("2024-06-01T00:00:00Z")),
            &absolute("2026-01-01T00:00:00Z", "2026-12-31T23:59:59Z"),
            at(NOW),
        );

        assert_eq!(refused, Err(TimeError::OutsideWindow));
    }

    #[test]
    fn a_before_query_is_open_at_the_start_and_an_after_query_at_the_end() {
        let policy = absolute("2026-01-01T00:00:00Z", "2026-12-31T00:00:00Z");

        let before = narrow_window(selector(Some("before"), Some("2026-06-01T00:00:00Z"), None), &policy, at(NOW)).unwrap();
        assert_eq!(before, Window::new(at("2026-01-01T00:00:00Z"), at("2026-06-01T00:00:00Z")));

        let after = narrow_window(selector(Some("after"), Some("2026-06-01T00:00:00Z"), None), &policy, at(NOW)).unwrap();
        assert_eq!(after, Window::new(at("2026-06-01T00:00:00Z"), at("2026-12-31T00:00:00Z")));
    }

    #[test]
    fn an_unknown_timerel_is_refused_rather_than_treated_as_between() {
        // Read as `between`, a relation the policy layer has never heard of would still be served.
        let refused = narrow_window(
            selector(Some("sometime"), Some("2026-03-01T00:00:00Z"), Some("2026-04-01T00:00:00Z")),
            &absolute("2026-01-01T00:00:00Z", "2026-12-31T00:00:00Z"),
            at(NOW),
        );

        assert_eq!(
            refused,
            Err(TimeError::UnknownRelation {
                relation: "sometime".to_owned()
            })
        );
    }

    #[test]
    fn an_unparseable_bound_is_a_bad_request_rather_than_the_policy_bound() {
        // Replaced by the policy's own bound, a mistyped timestamp would return a window the caller
        // never asked for, with no error.
        let refused = narrow_window(
            selector(Some("between"), Some("last tuesday"), Some("2026-04-01T00:00:00Z")),
            &absolute("2026-01-01T00:00:00Z", "2026-12-31T00:00:00Z"),
            at(NOW),
        );

        assert_eq!(
            refused,
            Err(TimeError::MalformedInstant {
                parameter: "timeAt",
                value: "last tuesday".to_owned()
            })
        );
    }

    #[test]
    fn a_malformed_second_bound_is_reported_even_when_the_relation_ignores_it() {
        let refused = narrow_window(
            selector(Some("before"), Some("2026-06-01T00:00:00Z"), Some("nonsense")),
            &absolute("2026-01-01T00:00:00Z", "2026-12-31T00:00:00Z"),
            at(NOW),
        );

        assert_eq!(
            refused,
            Err(TimeError::MalformedInstant {
                parameter: "endTimeAt",
                value: "nonsense".to_owned()
            })
        );
    }

    #[test]
    fn a_relation_without_the_bound_it_needs_is_refused() {
        let policy = absolute("2026-01-01T00:00:00Z", "2026-12-31T00:00:00Z");

        assert_eq!(
            narrow_window(selector(Some("between"), Some("2026-03-01T00:00:00Z"), None), &policy, at(NOW)),
            Err(TimeError::MissingBound {
                parameter: "endTimeAt",
                relation: TimeRelation::Between
            })
        );
        assert_eq!(
            narrow_window(selector(Some("after"), None, None), &policy, at(NOW)),
            Err(TimeError::MissingBound {
                parameter: "timeAt",
                relation: TimeRelation::After
            })
        );
    }

    #[test]
    fn a_query_with_no_relation_at_all_is_bounded_to_the_policy_window() {
        // The case that decides whether the restriction is a restriction: a temporal query with no
        // `timerel` asks for all of history, and must come back with the policy's bounds on it.
        let narrowed = narrow_window(selector(None, None, None), &absolute("2026-01-01T00:00:00Z", "2026-02-01T00:00:00Z"), at(NOW)).unwrap();

        assert_eq!(narrowed, Window::new(at("2026-01-01T00:00:00Z"), at("2026-02-01T00:00:00Z")));
    }

    #[test]
    fn a_backwards_window_is_a_bad_request_rather_than_a_refusal() {
        let refused = narrow_window(
            selector(Some("between"), Some("2026-04-01T00:00:00Z"), Some("2026-03-01T00:00:00Z")),
            &absolute("2026-01-01T00:00:00Z", "2026-12-31T00:00:00Z"),
            at(NOW),
        );

        assert_eq!(refused, Err(TimeError::BackwardsWindow));
    }

    #[test]
    fn a_relative_window_is_measured_from_the_clock_the_caller_supplies() {
        // The clock is an argument precisely so this can be asserted: the same request narrows to a
        // different window at a different instant, and neither depends on wall time.
        let policy = past("PT24H");

        let noon = narrow_window(selector(None, None, None), &policy, at("2026-06-02T12:00:00Z")).unwrap();
        assert_eq!(noon, Window::new(at("2026-06-01T12:00:00Z"), at("2026-06-02T12:00:00Z")));

        let midnight = narrow_window(selector(None, None, None), &policy, at("2026-06-03T00:00:00Z")).unwrap();
        assert_eq!(midnight, Window::new(at("2026-06-02T00:00:00Z"), at("2026-06-03T00:00:00Z")));
    }

    #[test]
    fn a_request_reaching_back_past_a_relative_window_is_pulled_forward_to_its_start() {
        let narrowed = narrow_window(
            selector(Some("after"), Some("2020-01-01T00:00:00Z"), None),
            &past("PT24H"),
            at("2026-06-02T12:00:00Z"),
        )
        .unwrap();

        assert_eq!(narrowed.start_text(), "2026-06-01T12:00:00.000Z");
    }
}
