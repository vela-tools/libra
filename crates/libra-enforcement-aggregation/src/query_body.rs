//! The aggregation parameters of a `Query` body, for `POST /temporal/entityOperations/query`.
//!
//! NGSI-LD clause 5.2.23 carries a query's aggregation in its `aggrParams` member, an
//! `AggregationParams` (clause 5.2.44). Brokers have also read `aggrMethods` and
//! `aggrPeriodDuration` from `temporalQ` and from the top level of the document. All three places
//! are read and all three are rewritten, because a value in the place Libra did not look is a value
//! nothing checked.

use crate::{enforce::RequestedAggregation, error::AggregationError};
use axum::http::request::Parts;
use jiff::Timestamp;
use jstrict::{Value, object::Object};
use libra_json_body::request_body::RequestBody;
use libra_ngsi_ld_query::{
    aggregation::{AggregationMethod, AggregationPeriod},
    error::QueryError,
    parameter_name::ParameterName,
    temporal_selector::{TEMPORAL_QUERY_MEMBER, TemporalSelector, render_instant},
};
use libra_policy_model::duration::IsoDuration;
use std::str::FromStr;

/// The member naming the aggregation methods, wherever it is written.
const METHODS: &str = "aggrMethods";
/// The member naming the aggregation period, wherever it is written.
const PERIOD: &str = "aggrPeriodDuration";
/// The `AggregationParams` member of a `Query` (clause 5.2.23).
const AGGREGATION_PARAMS: &str = "aggrParams";

/// Whether a raised period was written into the body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Raised {
    /// At least one member of the body carried aggregation and now carries the minimum.
    InBody,
    /// No member of the body carried aggregation, so nothing was written.
    Nowhere,
}

/// Takes the parsed body of a temporal batch query out of the request extensions.
///
/// The context layer above reads every body once; this takes that document so it can be checked
/// and, if the period is raised, rewritten. A document taken here goes back into the extensions
/// before the request is forwarded, through [`RequestBody::replace`] when it changed.
///
/// Refused rather than skipped when it is not a JSON object. The endpoint takes a JSON payload and
/// nothing else, so a body Libra cannot parse is a body it cannot check, and forwarding one because
/// it looked unfamiliar is how the parameters in it would go unexamined.
///
/// # Errors
///
/// Returns [`AggregationError::Body`] if no layer above read the body or it is not JSON, and
/// [`AggregationError::MalformedBody`] if it is empty or is not an object.
pub fn take(parts: &mut Parts) -> Result<Value, AggregationError> {
    let document = RequestBody::take_document(parts)?.ok_or(AggregationError::MalformedBody {
        reason: "it is not a JSON document",
    })?;

    if document.is_object() {
        Ok(document)
    } else {
        Err(AggregationError::MalformedBody {
            reason: "it is not a JSON object",
        })
    }
}

/// Adds every aggregation parameter in the body to `requested`.
///
/// # Errors
///
/// Returns [`AggregationError::MalformedBody`] if a member that carries aggregation is not shaped
/// as one or is named twice in one object, and [`AggregationError::UnreadableParameter`] for a
/// method or a period that is not one.
pub fn collect(document: &Value, requested: &mut RequestedAggregation) -> Result<(), AggregationError> {
    let Some(root) = document.as_object() else {
        return Ok(());
    };

    collect_object(root, requested)?;

    for nested in [TEMPORAL_QUERY_MEMBER, AGGREGATION_PARAMS] {
        if let Some(object) = nested_object(root, nested)? {
            collect_object(object, requested)?;
        }
    }

    Ok(())
}

/// Writes the policy minimum into every member of the body that carries aggregation.
///
/// Every member, rather than the one Libra happened to read: raising the period in one place while
/// leaving a finer one in another produces a request that still asks for what the policy refuses,
/// depending on which place the broker prefers.
///
/// # Errors
///
/// Returns [`AggregationError::MalformedBody`] if `temporalQ` or `aggrParams` is named twice: the
/// occurrence raised here need not be the one the broker reads.
pub fn raise_period(document: &mut Value, minimum: &IsoDuration) -> Result<Raised, AggregationError> {
    let Some(root) = document.as_object_mut() else {
        return Ok(Raised::Nowhere);
    };

    let mut raised = raise_in(root, minimum);

    for nested in [TEMPORAL_QUERY_MEMBER, AGGREGATION_PARAMS] {
        if let Some(object) = root.get_unique_mut(nested).map_err(|_| repeated())?.and_then(Value::as_object_mut)
            && raise_in(object, minimum) == Raised::InBody
        {
            raised = Raised::InBody;
        }
    }

    Ok(raised)
}

/// The temporal query of a `Query` body, if it carries one (clause 5.2.21).
///
/// # Errors
///
/// Returns [`AggregationError::MalformedBody`] if `temporalQ` is not an object or is named twice,
/// and [`AggregationError::UnreadableParameter`] if one of its members is named twice or is not a
/// string.
pub fn temporal_query(document: &Value) -> Result<Option<TemporalSelector<'_>>, AggregationError> {
    let Some(root) = document.as_object() else {
        return Ok(None);
    };

    Ok(nested_object(root, TEMPORAL_QUERY_MEMBER)?
        .map(TemporalSelector::of_temporal_query)
        .transpose()?)
}

/// Writes a window moved to the grid into the body's `temporalQ`.
///
/// Called only for a body whose `temporalQ` was read as an object, so there is always one to write
/// into.
///
/// # Errors
///
/// Returns [`AggregationError::MalformedBody`] if `temporalQ` is named twice or is not an object.
pub fn write_window(document: &mut Value, time_at: Timestamp, end_time_at: Option<Timestamp>) -> Result<(), AggregationError> {
    let temporal = document
        .as_object_mut()
        .and_then(|root| root.get_unique_mut(TEMPORAL_QUERY_MEMBER).ok().flatten())
        .and_then(Value::as_object_mut)
        .ok_or(AggregationError::MalformedBody {
            reason: "its temporalQ member is not one object",
        })?;

    temporal.insert(ParameterName::TIME_AT.as_str().into(), Value::String(render_instant(time_at).into()));
    if let Some(end_time_at) = end_time_at {
        temporal.insert(ParameterName::END_TIME_AT.as_str().into(), Value::String(render_instant(end_time_at).into()));
    }

    Ok(())
}

/// Writes the minimum into one object, if it carries aggregation.
///
/// Inserting replaces every member already called `aggrPeriodDuration`, so the minimum is the only
/// period the object is left naming.
fn raise_in(object: &mut Object, minimum: &IsoDuration) -> Raised {
    if object.contains_key(METHODS) || object.contains_key(PERIOD) {
        object.insert(PERIOD.into(), Value::String(minimum.as_str().into()));
        Raised::InBody
    } else {
        Raised::Nowhere
    }
}

/// A member of the query document that has to be an object when it is present.
fn nested_object<'a>(root: &'a Object, name: &'static str) -> Result<Option<&'a Object>, AggregationError> {
    match member(root, name)? {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Object(object)) => Ok(Some(object)),
        Some(Value::Boolean(_) | Value::Number(_) | Value::String(_) | Value::Array(_)) => Err(AggregationError::MalformedBody {
            reason: "its temporalQ or aggrParams member is not an object",
        }),
    }
}

/// Reads the aggregation parameters out of one JSON object.
fn collect_object(object: &Object, requested: &mut RequestedAggregation) -> Result<(), AggregationError> {
    if let Some(methods) = member(object, METHODS)? {
        for method in method_names(methods)? {
            requested
                .methods
                .push(AggregationMethod::from_str(method).map_err(|_| QueryError::UnknownValue {
                    name: ParameterName::AGGR_METHODS,
                    value: method.to_owned(),
                })?);
        }
    }

    if let Some(period) = member(object, PERIOD)? {
        let period = period.as_str().ok_or(AggregationError::MalformedBody {
            reason: "its aggrPeriodDuration is not a string",
        })?;
        requested.periods.push(AggregationPeriod::from_str(period)?);
    }

    Ok(())
}

/// The one member of `object` called `name`, if it has one.
///
/// A member named twice is refused: RFC 8259 section 4 leaves its meaning unpredictable, and the
/// occurrence checked here need not be the one the broker applies.
fn member<'a>(object: &'a Object, name: &str) -> Result<Option<&'a Value>, AggregationError> {
    object.get_unique(name).map_err(|_| repeated())
}

/// The refusal of a member named more than once.
const fn repeated() -> AggregationError {
    AggregationError::MalformedBody {
        reason: "it names an aggregation member more than once",
    }
}

/// The method names in an `aggrMethods` value written in JSON.
///
/// Clause 5.2.44 writes them as one comma-separated string. A list of strings is read too, because
/// it is what a JSON payload would naturally carry, and a caller who wrote one has still named
/// methods that must be checked.
fn method_names(value: &Value) -> Result<Vec<&str>, AggregationError> {
    if let Some(written) = value.as_str() {
        return Ok(written.split(',').map(str::trim).filter(|piece| !piece.is_empty()).collect());
    }

    let Some(list) = value.as_array() else {
        return Err(AggregationError::MalformedBody {
            reason: "its aggrMethods is neither a string nor a list of strings",
        });
    };

    list.iter()
        .map(|entry| {
            entry.as_str().ok_or(AggregationError::MalformedBody {
                reason: "its aggrMethods contains something that is not a string",
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;
    use jstrict::json;
    use libra_json_body::error::DocumentError;
    use pretty_assertions::assert_eq;

    fn collected(document: &Value) -> Result<(Vec<AggregationMethod>, usize), AggregationError> {
        let mut requested = RequestedAggregation::default();
        collect(document, &mut requested)?;

        Ok((requested.methods, requested.periods.len()))
    }

    #[test]
    fn the_aggregation_params_member_is_read_where_the_specification_puts_it() {
        let document = json!({"type": "Query", "aggrParams": {"aggrMethods": "avg,max", "aggrPeriodDuration": "PT1H"}});

        assert_eq!(collected(&document), Ok((vec![AggregationMethod::Avg, AggregationMethod::Max], 1)));
    }

    #[test]
    fn every_place_a_broker_might_read_is_collected() {
        let document = json!({
            "type": "Query",
            "aggrMethods": "sum",
            "temporalQ": {"aggrMethods": ["min"], "aggrPeriodDuration": "PT5M"},
            "aggrParams": {"aggrMethods": "avg", "aggrPeriodDuration": "PT1H"}
        });

        assert_eq!(
            collected(&document),
            Ok((vec![AggregationMethod::Sum, AggregationMethod::Min, AggregationMethod::Avg], 2))
        );
    }

    #[test]
    fn a_method_or_a_period_that_is_not_one_is_unreadable() {
        assert!(matches!(
            collected(&json!({"aggrParams": {"aggrMethods": "median"}})),
            Err(AggregationError::UnreadableParameter(_))
        ));
        assert!(matches!(
            collected(&json!({"aggrParams": {"aggrMethods": "avg", "aggrPeriodDuration": "1 hour"}})),
            Err(AggregationError::UnreadableParameter(_))
        ));
    }

    #[test]
    fn a_member_of_the_wrong_shape_is_a_malformed_body() {
        for document in [
            json!({"aggrParams": "avg"}),
            json!({"temporalQ": ["avg"]}),
            json!({"aggrMethods": 3}),
            json!({"aggrParams": {"aggrPeriodDuration": 3600}}),
        ] {
            assert!(matches!(collected(&document), Err(AggregationError::MalformedBody { .. })), "{document}");
        }
    }

    #[test]
    fn a_raised_period_is_written_into_every_member_that_carries_aggregation_and_nowhere_else() {
        let mut document = json!({
            "type": "Query",
            "temporalQ": {"timerel": "after", "aggrPeriodDuration": "PT5M"},
            "aggrParams": {"aggrMethods": "avg"}
        });

        assert_eq!(raise_period(&mut document, &IsoDuration::parse("PT1H").unwrap()), Ok(Raised::InBody));
        assert_eq!(
            document,
            json!({
                "type": "Query",
                "temporalQ": {"timerel": "after", "aggrPeriodDuration": "PT1H"},
                "aggrParams": {"aggrMethods": "avg", "aggrPeriodDuration": "PT1H"}
            })
        );
    }

    #[test]
    fn the_temporal_query_of_a_body_is_read_where_the_specification_puts_it() {
        let document = json!({"type": "Query", "temporalQ": {"timerel": "between", "timeAt": "2026-03-01T10:00:00Z", "endTimeAt": "2026-03-01T12:00:00Z"}});

        assert_eq!(
            temporal_query(&document).map(|selector| selector.and_then(|selector| selector.end_time_at)),
            Ok(Some("2026-03-01T12:00:00Z"))
        );
        assert_eq!(temporal_query(&json!({"type": "Query"})), Ok(None));
        assert!(temporal_query(&json!({"temporalQ": "between"})).is_err());
        assert!(temporal_query(&json!({"temporalQ": {"timeAt": "a", "timeAt": "b"}})).is_err());
    }

    #[test]
    fn a_window_moved_to_the_grid_is_written_into_the_temporal_query() {
        let mut document = json!({"type": "Query", "temporalQ": {"timerel": "between", "timeAt": "2026-03-01T10:20:00Z", "endTimeAt": "2026-03-01T12:10:00Z"}});

        assert_eq!(
            write_window(
                &mut document,
                "2026-03-01T10:00:00Z".parse().unwrap(),
                Some("2026-03-01T13:00:00Z".parse().unwrap())
            ),
            Ok(())
        );
        assert_eq!(
            document,
            json!({"type": "Query", "temporalQ": {"timerel": "between", "timeAt": "2026-03-01T10:00:00.000Z", "endTimeAt": "2026-03-01T13:00:00.000Z"}})
        );
    }

    #[test]
    fn a_body_that_carries_no_aggregation_is_left_alone() {
        let mut document = json!({"type": "Query", "temporalQ": {"timerel": "after"}});
        let before = document.clone();

        assert_eq!(raise_period(&mut document, &IsoDuration::parse("PT1H").unwrap()), Ok(Raised::Nowhere));
        assert_eq!(document, before);
    }

    #[test]
    fn a_member_named_twice_is_a_malformed_body_wherever_it_is() {
        let repeated = AggregationError::MalformedBody {
            reason: "it names an aggregation member more than once",
        };

        for document in [
            json!({"aggrMethods": "avg", "aggrMethods": "max"}),
            json!({"aggrParams": {"aggrMethods": "avg", "aggrPeriodDuration": "PT1H", "aggrPeriodDuration": "PT1M"}}),
            json!({"aggrParams": {"aggrMethods": "avg"}, "aggrParams": {"aggrMethods": "max"}}),
        ] {
            assert_eq!(collected(&document), Err(repeated.clone()), "{document}");
        }
    }

    #[test]
    fn a_period_is_not_raised_in_one_of_two_nested_members() {
        let mut document = json!({"aggrParams": {"aggrMethods": "avg"}, "aggrParams": {"aggrPeriodDuration": "PT1M"}});

        assert!(matches!(
            raise_period(&mut document, &IsoDuration::parse("PT1H").unwrap()),
            Err(AggregationError::MalformedBody { .. })
        ));
    }

    #[test]
    fn a_raised_period_replaces_every_period_an_object_names() {
        let mut document = json!({"aggrMethods": "avg", "aggrPeriodDuration": "PT1M", "aggrPeriodDuration": "PT2M"});

        assert_eq!(raise_period(&mut document, &IsoDuration::parse("PT1H").unwrap()), Ok(Raised::InBody));
        assert_eq!(document, json!({"aggrMethods": "avg", "aggrPeriodDuration": "PT1H"}));
    }

    fn parts(body: Option<RequestBody>) -> Parts {
        let (mut parts, ()) = Request::new(()).into_parts();
        if let Some(body) = body {
            parts.extensions.insert(body);
        }
        parts
    }

    #[test]
    fn a_query_object_is_taken_out_of_the_extensions() {
        let mut query = parts(Some(RequestBody::Json(json!({"type": "Query"}))));

        assert_eq!(take(&mut query), Ok(json!({"type": "Query"})));
        assert_eq!(RequestBody::of(&query), None);
    }

    #[test]
    fn a_body_that_is_not_a_query_object_or_was_not_read_is_refused() {
        assert_eq!(take(&mut parts(None)), Err(AggregationError::Body(DocumentError::Unread)));
        assert_eq!(
            take(&mut parts(Some(RequestBody::NotJson))),
            Err(AggregationError::Body(DocumentError::NotJson))
        );

        for body in [RequestBody::Empty, RequestBody::Json(json!(["avg"]))] {
            assert!(matches!(take(&mut parts(Some(body))), Err(AggregationError::MalformedBody { .. })));
        }
    }
}
