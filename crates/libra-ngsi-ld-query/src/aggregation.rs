//! What an aggregated temporal query asks for (NGSI-LD clause 4.5.19).

use crate::{error::QueryError, parameter_name::ParameterName, parameters::QueryParameters};
use jiff::{Span, fmt::temporal::SpanParser};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use strum::{Display, EnumString};

/// Reads ISO 8601 durations in the designator format only.
///
/// `Span`'s own `FromStr` also accepts Jiff's "friendly" format (`1 hour`), which is not an
/// ISO 8601 duration; this parser does not, and it refuses the combined date and time alternative
/// (`P0001-02-03T04:05:06`) that NGSI-LD clause 4.5.19.1 excludes, as well as trailing text.
static PERIOD_PARSER: SpanParser = SpanParser::new();

/// An aggregation method (NGSI-LD clause 4.5.19.1), spelled as the specification spells it.
///
/// A policy names methods with the same spelling, so the serde form is the specification's too.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Display, EnumString, Serialize, Deserialize)]
#[strum(serialize_all = "camelCase")]
#[serde(rename_all = "camelCase")]
pub enum AggregationMethod {
    /// `avg`, the average of the values inside the period.
    Avg,
    /// `distinctCount`, the number of distinct values inside the period.
    DistinctCount,
    /// `max`, the largest value inside the period.
    Max,
    /// `min`, the smallest value inside the period.
    Min,
    /// `stddev`, the standard deviation of the values inside the period.
    #[strum(serialize = "stddev")]
    #[serde(rename = "stddev")]
    StdDev,
    /// `sum`, the sum of the values inside the period.
    Sum,
    /// `sumsq`, the sum of the squares of the values inside the period.
    #[strum(serialize = "sumsq")]
    #[serde(rename = "sumsq")]
    SumSq,
    /// `totalCount`, the number of times the value was updated inside the period.
    TotalCount,
}

/// An `aggrPeriodDuration` value (NGSI-LD clause 4.5.19.1): a non-negative ISO 8601 duration in the
/// designator format.
///
/// The same value can arrive in a query string or in the `AggregationParams` of a `Query` body
/// (clause 5.2.44), and both are read by this one parser, so the two places cannot disagree about
/// what a period is.
#[derive(Debug, Clone, Copy)]
pub struct AggregationPeriod(Span);

impl AggregationPeriod {
    /// The period as a span, in the units it was written in.
    #[must_use]
    pub const fn span(self) -> Span {
        self.0
    }
}

// Not derivable: the value is read by `PERIOD_PARSER`, not by `Span`'s own `FromStr`, which also
// accepts the friendly format.
impl FromStr for AggregationPeriod {
    type Err = QueryError;

    /// Reads one `aggrPeriodDuration` value.
    ///
    /// A negative span is refused: a period is a length of time, and clause 4.5.19.1 gives it no
    /// sign.
    fn from_str(value: &str) -> Result<Self, QueryError> {
        match PERIOD_PARSER.parse_span(value) {
            Ok(span) if !span.is_negative() => Ok(Self(span)),
            Ok(_) | Err(_) => Err(QueryError::UnknownValue {
                name: ParameterName::AGGR_PERIOD_DURATION,
                value: value.to_owned(),
            }),
        }
    }
}

impl QueryParameters {
    /// The aggregation methods the query asks for.
    ///
    /// # Errors
    ///
    /// Returns [`QueryError::UnknownValue`] for a method NGSI-LD clause 4.5.19.1 does not define.
    /// A method Libra cannot name is one no aggregation restriction can be checked against.
    pub fn aggregation_methods(&self) -> Result<Vec<AggregationMethod>, QueryError> {
        let Some(value) = self.get(&ParameterName::AGGR_METHODS) else {
            return Ok(Vec::new());
        };

        value
            .split(',')
            .map(str::trim)
            .filter(|piece| !piece.is_empty())
            .map(|piece| {
                AggregationMethod::from_str(piece).map_err(|_| QueryError::UnknownValue {
                    name: ParameterName::AGGR_METHODS,
                    value: piece.to_owned(),
                })
            })
            .collect()
    }

    /// The aggregation period the query asks for.
    ///
    /// # Errors
    ///
    /// Returns [`QueryError::UnknownValue`] for a value that is not an ISO 8601 duration in the
    /// format NGSI-LD clause 4.5.19.1 allows, including trailing text after one.
    pub fn aggregation_period(&self) -> Result<Option<AggregationPeriod>, QueryError> {
        self.get(&ParameterName::AGGR_PERIOD_DURATION).map(AggregationPeriod::from_str).transpose()
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        aggregation::{AggregationMethod, AggregationPeriod},
        error::QueryError,
        parameter_name::ParameterName,
        parameters::QueryParameters,
    };
    use jiff::{SpanFieldwise, ToSpan};
    use pretty_assertions::assert_eq;
    use std::str::FromStr;

    fn query(source: &str) -> QueryParameters {
        QueryParameters::parse(source).expect("the test query should parse")
    }

    #[test]
    fn every_method_is_read_by_its_specification_spelling() {
        let methods = query("aggrMethods=avg,distinctCount,max,min,stddev,sum,sumsq,totalCount").aggregation_methods();

        assert_eq!(
            methods,
            Ok(vec![
                AggregationMethod::Avg,
                AggregationMethod::DistinctCount,
                AggregationMethod::Max,
                AggregationMethod::Min,
                AggregationMethod::StdDev,
                AggregationMethod::Sum,
                AggregationMethod::SumSq,
                AggregationMethod::TotalCount,
            ])
        );
    }

    #[test]
    fn a_method_displays_as_the_specification_spells_it() {
        assert_eq!(AggregationMethod::DistinctCount.to_string(), "distinctCount");
        assert_eq!(AggregationMethod::SumSq.to_string(), "sumsq");
    }

    #[test]
    fn an_unknown_method_is_refused_rather_than_dropped() {
        assert_eq!(
            query("aggrMethods=max,median").aggregation_methods(),
            Err(QueryError::UnknownValue {
                name: ParameterName::AGGR_METHODS,
                value: "median".to_owned()
            })
        );
    }

    #[test]
    fn no_methods_is_an_empty_list_and_empty_pieces_are_not_methods() {
        assert_eq!(query("type=T").aggregation_methods(), Ok(Vec::new()));
        assert_eq!(
            query("aggrMethods=max,,min").aggregation_methods(),
            Ok(vec![AggregationMethod::Max, AggregationMethod::Min])
        );
    }

    #[test]
    fn a_designated_duration_is_read() {
        let period = |source: &str| {
            query(source)
                .aggregation_period()
                .map(|period| period.map(|period| SpanFieldwise(period.span())))
        };

        assert_eq!(period("aggrPeriodDuration=P2W"), Ok(Some(2.weeks().fieldwise())));
        assert_eq!(period("aggrPeriodDuration=PT4M"), Ok(Some(4.minutes().fieldwise())));
        assert_eq!(
            period("aggrPeriodDuration=P1Y2M3DT4H5M6S"),
            Ok(Some(1.year().months(2).days(3).hours(4).minutes(5).seconds(6).fieldwise()))
        );
    }

    #[test]
    fn a_zero_duration_is_valid() {
        // Clause 4.5.19.1: a duration of zero spans the whole time range of the temporal query.
        assert!(query("aggrPeriodDuration=PT0S").aggregation_period().is_ok_and(|period| period.is_some()));
    }

    #[test]
    fn the_combined_date_and_time_form_is_refused() {
        for value in ["P0001-02-03T04:05:06", "P00010203T040506"] {
            assert!(query(&format!("aggrPeriodDuration={value}")).aggregation_period().is_err(), "{value}");
        }
    }

    #[test]
    fn trailing_text_after_a_duration_is_refused() {
        assert!(query("aggrPeriodDuration=PT1Hx").aggregation_period().is_err());
        assert!(query("aggrPeriodDuration=4M").aggregation_period().is_err());
    }

    #[test]
    fn the_friendly_format_is_not_an_iso_duration() {
        assert!(query("aggrPeriodDuration=1%20hour").aggregation_period().is_err());
    }

    #[test]
    fn a_negative_period_is_refused() {
        assert!(query("aggrPeriodDuration=-PT1H").aggregation_period().is_err());
    }

    #[test]
    fn no_period_is_none() {
        assert!(query("type=T").aggregation_period().is_ok_and(|period| period.is_none()));
    }

    #[test]
    fn a_period_written_in_a_body_is_read_by_the_query_string_parser() {
        let fieldwise = |source: &str| AggregationPeriod::from_str(source).map(|period| SpanFieldwise(period.span()));

        assert_eq!(fieldwise("PT1H"), Ok(1.hour().fieldwise()));
        assert_eq!(fieldwise("P2W"), Ok(2.weeks().fieldwise()));

        for refused in ["1 hour", "-PT1H", "P0001-02-03T04:05:06", "PT1Hx"] {
            assert_eq!(
                fieldwise(refused),
                Err(QueryError::UnknownValue {
                    name: ParameterName::AGGR_PERIOD_DURATION,
                    value: refused.to_owned()
                }),
                "{refused}"
            );
        }
    }

    #[test]
    fn a_method_is_read_from_a_policy_by_its_specification_spelling() {
        let methods: Vec<AggregationMethod> =
            serde_json::from_str(r#"["avg","distinctCount","max","min","stddev","sum","sumsq","totalCount"]"#).expect("the methods should parse");

        assert_eq!(methods.len(), 8);
        assert!(serde_json::from_str::<AggregationMethod>(r#""median""#).is_err());
        assert!(serde_json::from_str::<AggregationMethod>(r#""TotalCount""#).is_err());
        assert!(serde_json::from_str::<AggregationMethod>(r#""stdDev""#).is_err());
    }
}
