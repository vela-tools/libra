//! Writing what a deployment raises into every place a request carries it.
//!
//! Under `short-period = "raise"` a period finer than the policy minimum is replaced by the
//! minimum, and a window off the grid is moved out to the enclosing grid points. Each is written
//! everywhere the request names it: raising it in one place while leaving the caller's value in
//! another produces a request that still asks for what the policy refuses, depending on which place
//! the broker reads.

use crate::{
    error::AggregationError,
    query_body::{self, Raised},
    window::{WindowCheck, WindowChecks},
};
use jstrict::Value;
use libra_ngsi_ld_query::{parameter_name::ParameterName, parameters::QueryParameters, temporal_selector::render_instant};
use libra_policy_model::duration::IsoDuration;

/// Whether raising changed the query string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryChange {
    /// A parameter was written, so the request target has to be rebuilt.
    Rewritten,
    /// The query string is as it arrived.
    Untouched,
}

/// Writes the policy minimum into every place the request carries aggregation.
///
/// When neither the query string nor the body names an aggregation parameter there is no place to
/// match, and the query string is where a period goes by default.
///
/// `document` is the batch query's body, when the request carries one.
///
/// # Errors
///
/// Returns [`AggregationError::MalformedBody`] if the body names an object that carries aggregation
/// twice.
pub fn raise_period(parameters: &mut QueryParameters, document: Option<&mut Value>, minimum: &IsoDuration) -> Result<QueryChange, AggregationError> {
    let in_query = parameters.contains(&ParameterName::AGGR_METHODS) || parameters.contains(&ParameterName::AGGR_PERIOD_DURATION);

    let in_body = match document {
        Some(document) => query_body::raise_period(document, minimum)?,
        None => Raised::Nowhere,
    };

    if in_query || in_body == Raised::Nowhere {
        parameters.set(ParameterName::AGGR_PERIOD_DURATION, minimum.as_str());
        return Ok(QueryChange::Rewritten);
    }

    Ok(QueryChange::Untouched)
}

/// Writes every window moved to the grid back where it was read.
///
/// # Errors
///
/// Returns [`AggregationError::MalformedBody`] if the body's window cannot be written back.
pub fn raise_windows(parameters: &mut QueryParameters, document: Option<&mut Value>, checks: WindowChecks) -> Result<QueryChange, AggregationError> {
    if let (WindowCheck::Raise { time_at, end_time_at, .. }, Some(document)) = (checks.body, document) {
        query_body::write_window(document, time_at, end_time_at)?;
    }

    let WindowCheck::Raise { time_at, end_time_at, .. } = checks.query else {
        return Ok(QueryChange::Untouched);
    };

    parameters.set(ParameterName::TIME_AT, render_instant(time_at));
    if let Some(end_time_at) = end_time_at {
        parameters.set(ParameterName::END_TIME_AT, render_instant(end_time_at));
    }

    Ok(QueryChange::Rewritten)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::window::WindowShortfall;
    use jstrict::json;
    use pretty_assertions::assert_eq;

    #[test]
    fn a_window_moved_in_the_query_string_rewrites_both_bounds() {
        let mut parameters = QueryParameters::parse("timerel=between&timeAt=2026-03-01T10:20:00Z&endTimeAt=2026-03-01T12:10:00Z").unwrap();
        let checks = WindowChecks {
            query: WindowCheck::Raise {
                shortfall: WindowShortfall::OffGrid,
                time_at: "2026-03-01T10:00:00Z".parse().unwrap(),
                end_time_at: Some("2026-03-01T13:00:00Z".parse().unwrap()),
            },
            body: WindowCheck::OnGrid,
        };

        assert_eq!(raise_windows(&mut parameters, None, checks), Ok(QueryChange::Rewritten));
        assert_eq!(parameters.get(&ParameterName::TIME_AT), Some("2026-03-01T10:00:00.000Z"));
        assert_eq!(parameters.get(&ParameterName::END_TIME_AT), Some("2026-03-01T13:00:00.000Z"));
    }

    #[test]
    fn a_window_moved_in_the_body_leaves_the_query_string_alone() {
        let mut parameters = QueryParameters::parse("options=aggregatedValues").unwrap();
        let mut document = json!({"type": "Query", "temporalQ": {"timerel": "after", "timeAt": "2026-03-01T10:20:00Z"}});
        let checks = WindowChecks {
            query: WindowCheck::OnGrid,
            body: WindowCheck::Raise {
                shortfall: WindowShortfall::OffGrid,
                time_at: "2026-03-01T10:00:00Z".parse().unwrap(),
                end_time_at: None,
            },
        };

        assert_eq!(raise_windows(&mut parameters, Some(&mut document), checks), Ok(QueryChange::Untouched));
        assert_eq!(
            document,
            json!({"type": "Query", "temporalQ": {"timerel": "after", "timeAt": "2026-03-01T10:00:00.000Z"}})
        );
    }

    #[test]
    fn a_period_goes_into_the_query_string_when_nothing_names_one() {
        let mut parameters = QueryParameters::parse("options=aggregatedValues").unwrap();

        assert_eq!(
            raise_period(&mut parameters, None, &IsoDuration::parse("PT1H").unwrap()),
            Ok(QueryChange::Rewritten)
        );
        assert_eq!(parameters.get(&ParameterName::AGGR_PERIOD_DURATION), Some("PT1H"));
    }

    #[test]
    fn aggregation_named_in_both_the_query_string_and_the_body_has_its_period_raised_in_both() {
        // The query string names a method and no period: naming either is naming aggregation.
        let mut parameters = QueryParameters::parse("aggrMethods=avg").unwrap();
        let mut document = json!({"type": "Query", "aggrMethods": ["avg"], "aggrPeriodDuration": "PT1M"});

        assert_eq!(
            raise_period(&mut parameters, Some(&mut document), &IsoDuration::parse("PT1H").unwrap()),
            Ok(QueryChange::Rewritten)
        );
        assert_eq!(parameters.get(&ParameterName::AGGR_PERIOD_DURATION), Some("PT1H"));
        assert_eq!(document, json!({"type": "Query", "aggrMethods": ["avg"], "aggrPeriodDuration": "PT1H"}));
    }

    #[test]
    fn a_period_named_only_in_the_body_leaves_the_query_string_alone() {
        let mut parameters = QueryParameters::parse("options=aggregatedValues").unwrap();
        let mut document = json!({"type": "Query", "aggrMethods": ["avg"], "aggrPeriodDuration": "PT1M"});

        assert_eq!(
            raise_period(&mut parameters, Some(&mut document), &IsoDuration::parse("PT1H").unwrap()),
            Ok(QueryChange::Untouched)
        );
        assert_eq!(parameters.get(&ParameterName::AGGR_PERIOD_DURATION), None);
        assert_eq!(document, json!({"type": "Query", "aggrMethods": ["avg"], "aggrPeriodDuration": "PT1H"}));
    }
}
