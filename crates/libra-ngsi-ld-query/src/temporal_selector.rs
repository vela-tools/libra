//! The members that say which instants a temporal query selects (NGSI-LD clauses 4.11 and 5.2.21).
//!
//! A temporal query writes `timerel`, `timeAt`, `endTimeAt` and `timeproperty` in its query string;
//! `POST /temporal/entityOperations/query` writes the same four in the `temporalQ` member of its
//! `Query` body (clause 5.2.23). Both are read here into one shape, so every layer that judges the
//! window a query selects reads it from the same place in the same way.

use crate::{error::QueryError, parameter_name::ParameterName, parameters::QueryParameters};
use jiff::Timestamp;
use jstrict::{Value, object::Object};
use strum::{Display, EnumString};

/// The member of a `Query` body that carries its temporal query (NGSI-LD clause 5.2.23).
pub const TEMPORAL_QUERY_MEMBER: &str = "temporalQ";

/// The relation a temporal query names its bounds with (NGSI-LD clause 4.11).
///
/// A closed set, so an unrecognised relation is a refusal rather than a default: reading anything
/// else as `between` would take a caller's single bound for the start of a window and invent the
/// other end.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Display, EnumString)]
#[strum(serialize_all = "lowercase")]
pub enum TimeRelation {
    /// Everything up to `timeAt`.
    Before,
    /// Everything from `timeAt` onwards.
    After,
    /// Everything from `timeAt` to `endTimeAt`.
    Between,
}

/// The four members of a temporal query, as written, wherever they were written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TemporalSelector<'a> {
    /// The relation the bounds are read with.
    pub timerel: Option<&'a str>,
    /// The first bound.
    pub time_at: Option<&'a str>,
    /// The second bound, used only by `between`.
    pub end_time_at: Option<&'a str>,
    /// The temporal property the query is evaluated against; absent means `observedAt`.
    pub timeproperty: Option<&'a str>,
}

impl<'a> TemporalSelector<'a> {
    /// The temporal query a query string carries.
    #[must_use]
    pub fn of_parameters(parameters: &'a QueryParameters) -> Self {
        Self {
            timerel: parameters.get(&ParameterName::TIMEREL),
            time_at: parameters.get(&ParameterName::TIME_AT),
            end_time_at: parameters.get(&ParameterName::END_TIME_AT),
            timeproperty: parameters.get(&ParameterName::TIMEPROPERTY),
        }
    }

    /// The temporal query a `temporalQ` object carries (NGSI-LD clause 5.2.21).
    ///
    /// A member written `null` is read as absent.
    ///
    /// # Errors
    ///
    /// Returns [`QueryError::RepeatedMember`] for a member named twice, since the occurrence read
    /// here need not be the one the broker reads, and [`QueryError::NotAString`] for a member that
    /// is neither a string nor `null`.
    pub fn of_temporal_query(temporal: &'a Object) -> Result<Self, QueryError> {
        Ok(Self {
            timerel: member(temporal, &ParameterName::TIMEREL)?,
            time_at: member(temporal, &ParameterName::TIME_AT)?,
            end_time_at: member(temporal, &ParameterName::END_TIME_AT)?,
            timeproperty: member(temporal, &ParameterName::TIMEPROPERTY)?,
        })
    }

    /// Whether any of the three members that bound the window is written.
    #[must_use]
    pub const fn bounds_anything(&self) -> bool {
        self.timerel.is_some() || self.time_at.is_some() || self.end_time_at.is_some()
    }
}

/// Writes an instant the way NGSI-LD writes a `DateTime`.
///
/// Milliseconds and a `Z`, never an offset: the specification's `DateTime` is UTC, and a rewritten
/// bound that carried an offset would be re-encoded by every hop that touched it.
#[must_use]
pub fn render_instant(instant: Timestamp) -> String {
    instant.strftime("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

/// Reads one string member of a `temporalQ`.
fn member<'a>(temporal: &'a Object, name: &ParameterName) -> Result<Option<&'a str>, QueryError> {
    let written = temporal.get_unique(name.as_str()).map_err(|_| QueryError::RepeatedMember {
        member: name.as_str().to_owned(),
    })?;

    match written {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.as_str())),
        Some(Value::Boolean(_) | Value::Number(_) | Value::Array(_) | Value::Object(_)) => Err(QueryError::NotAString {
            // Cloned because the error owns the name; a static name is borrowed, not copied.
            member: name.clone(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jstrict::json;
    use pretty_assertions::assert_eq;
    use std::str::FromStr;

    fn object(value: &Value) -> &Object {
        value.as_object().expect("the test value is an object")
    }

    #[test]
    fn a_relation_is_read_only_as_the_specification_spells_it() {
        assert_eq!(TimeRelation::from_str("between"), Ok(TimeRelation::Between));
        assert_eq!(TimeRelation::from_str("before"), Ok(TimeRelation::Before));
        assert_eq!(TimeRelation::from_str("after"), Ok(TimeRelation::After));
        assert!(TimeRelation::from_str("Between").is_err());
        assert!(TimeRelation::from_str("after ").is_err());
        assert!(TimeRelation::from_str("since").is_err());
        assert_eq!(TimeRelation::Between.to_string(), "between");
    }

    #[test]
    fn the_query_string_members_are_read_by_their_parameter_names() {
        let parameters = QueryParameters::parse("timerel=after&timeAt=2026-01-01T00:00:00Z&timeproperty=modifiedAt").expect("parses");

        assert_eq!(
            TemporalSelector::of_parameters(&parameters),
            TemporalSelector {
                timerel: Some("after"),
                time_at: Some("2026-01-01T00:00:00Z"),
                end_time_at: None,
                timeproperty: Some("modifiedAt"),
            }
        );
    }

    #[test]
    fn a_temporal_query_object_is_read_with_null_as_absent() {
        let temporal = json!({"timerel": "between", "timeAt": "2026-01-01T00:00:00Z", "endTimeAt": null, "timeproperty": "observedAt"});

        assert_eq!(
            TemporalSelector::of_temporal_query(object(&temporal)),
            Ok(TemporalSelector {
                timerel: Some("between"),
                time_at: Some("2026-01-01T00:00:00Z"),
                end_time_at: None,
                timeproperty: Some("observedAt"),
            })
        );
    }

    #[test]
    fn a_temporal_query_member_named_twice_or_not_a_string_is_refused() {
        let repeated = json!({"timeAt": "2026-01-01T00:00:00Z", "timeAt": "2019-01-01T00:00:00Z"});
        let numeric = json!({"timeproperty": 3});

        assert_eq!(
            TemporalSelector::of_temporal_query(object(&repeated)),
            Err(QueryError::RepeatedMember { member: "timeAt".to_owned() })
        );
        assert_eq!(
            TemporalSelector::of_temporal_query(object(&numeric)),
            Err(QueryError::NotAString {
                member: ParameterName::TIMEPROPERTY
            })
        );
    }

    #[test]
    fn only_the_three_bounding_members_bound_a_window() {
        assert!(!TemporalSelector::default().bounds_anything());
        assert!(
            !TemporalSelector {
                timeproperty: Some("createdAt"),
                ..TemporalSelector::default()
            }
            .bounds_anything()
        );
        assert!(
            TemporalSelector {
                time_at: Some("2026-01-01T00:00:00Z"),
                ..TemporalSelector::default()
            }
            .bounds_anything()
        );
    }

    #[test]
    fn an_instant_is_rendered_in_utc_with_milliseconds() {
        let instant: Timestamp = "2026-02-01T12:30:45.123+01:00".parse().expect("parses");

        assert_eq!(render_instant(instant), "2026-02-01T11:30:45.123Z");
    }
}
