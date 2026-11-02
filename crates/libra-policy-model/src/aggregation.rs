//! Aggregation restrictions on temporal reads.
//!
//! The privacy control behind this is "you may see trends, not readings". It only holds if the
//! aggregation the caller asks for is one of a known set and the period is at least as coarse as
//! the policy says, so the method is the specification's own vocabulary rather than a string, and
//! the period is a duration rather than text.

use crate::{aggregation_grid::AggregationGrid, duration::IsoDuration, error::ValueError};
use libra_ngsi_ld_query::aggregation::AggregationMethod;
use serde::{Deserialize, Serialize};

/// Whether a temporal read under the restriction may return unaggregated values.
///
/// Written `allowed` or `disallowed` in a policy file; the default is `allowed`, so a restriction
/// that only lists methods or sets a minimum period governs the reads that do aggregate and leaves
/// the others alone.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UnaggregatedReads {
    /// A temporal read may return instances or simplified values.
    #[default]
    Allowed,
    /// A temporal read must ask for `aggregatedValues`, and a resource that returns entity values
    /// without aggregating them is refused.
    Disallowed,
}

/// What a policy requires of a temporal read's aggregation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields, try_from = "AuthoredAggregationRestriction")]
pub struct AggregationRestriction {
    /// Whether a temporal read may return unaggregated values.
    unaggregated: UnaggregatedReads,

    /// The methods allowed. Empty means every method.
    allowed_methods: Vec<AggregationMethod>,

    /// The finest period an aggregated read may ask for, if the policy sets one.
    min_period_duration: Option<IsoDuration>,
}

impl AggregationRestriction {
    /// Whether a temporal read under this restriction may return unaggregated values.
    #[must_use]
    pub const fn unaggregated(&self) -> UnaggregatedReads {
        self.unaggregated
    }

    /// Whether `method` is one this restriction allows.
    #[must_use]
    pub fn allows(&self, method: AggregationMethod) -> bool {
        self.allowed_methods.is_empty() || self.allowed_methods.contains(&method)
    }

    /// The finest period an aggregated read may ask for, if the policy sets one.
    #[must_use]
    pub const fn min_period_duration(&self) -> Option<&IsoDuration> {
        self.min_period_duration.as_ref()
    }

    /// The grid an aggregated read's window boundaries have to sit on, when the policy sets a
    /// minimum period.
    #[must_use]
    pub fn grid(&self) -> Option<AggregationGrid> {
        self.min_period_duration.as_ref().map(AggregationGrid::new)
    }
}

/// The shape as written, before the cross-field checks.
#[derive(Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct AuthoredAggregationRestriction {
    #[serde(default)]
    unaggregated: UnaggregatedReads,
    #[serde(default)]
    allowed_methods: Vec<AggregationMethod>,
    #[serde(default)]
    min_period_duration: Option<IsoDuration>,
}

impl TryFrom<AuthoredAggregationRestriction> for AggregationRestriction {
    type Error = ValueError;

    fn try_from(authored: AuthoredAggregationRestriction) -> Result<Self, Self::Error> {
        let AuthoredAggregationRestriction {
            unaggregated,
            allowed_methods,
            min_period_duration,
        } = authored;

        match (unaggregated, allowed_methods.is_empty(), min_period_duration.is_none()) {
            // `min` and `max` answer with a reading, not a trend, so "aggregated reads only, by any
            // method" still hands out readings. A policy that disallows unaggregated reads names
            // the methods it means.
            (UnaggregatedReads::Disallowed, true, _) => Err(ValueError::EmptyAllowList {
                restriction: "an aggregation restriction that disallows unaggregated reads",
            }),
            // Every field at its default. The restriction is present, so enforcement runs, and it
            // restricts nothing: a policy that reads as a control and is not one.
            (UnaggregatedReads::Allowed, true, true) => Err(ValueError::EmptyAllowList {
                restriction: "an aggregation restriction with no method list, no minimum period and unaggregated reads allowed",
            }),
            (UnaggregatedReads::Disallowed | UnaggregatedReads::Allowed, false, _) | (UnaggregatedReads::Allowed, true, false) => Ok(Self {
                unaggregated,
                allowed_methods,
                min_period_duration,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn restriction(source: &str) -> AggregationRestriction {
        toml::from_str(source).unwrap()
    }

    #[test]
    fn every_specification_method_is_read_by_its_specification_spelling() {
        let all = restriction(r#"allowed-methods = ["totalCount", "distinctCount", "sum", "avg", "min", "max", "stddev", "sumsq"]"#);

        for method in [
            AggregationMethod::TotalCount,
            AggregationMethod::DistinctCount,
            AggregationMethod::Sum,
            AggregationMethod::Avg,
            AggregationMethod::Min,
            AggregationMethod::Max,
            AggregationMethod::StdDev,
            AggregationMethod::SumSq,
        ] {
            assert!(all.allows(method), "{method}");
        }
    }

    #[test]
    fn a_method_outside_the_specification_or_spelled_differently_is_refused() {
        assert!(toml::from_str::<AggregationRestriction>(r#"allowed-methods = ["median"]"#).is_err());
        assert!(toml::from_str::<AggregationRestriction>(r#"allowed-methods = ["TotalCount"]"#).is_err());
    }

    #[test]
    fn a_method_list_allows_only_what_it_lists() {
        let averages = restriction(r#"allowed-methods = ["avg", "max"]"#);

        assert!(averages.allows(AggregationMethod::Avg));
        assert!(averages.allows(AggregationMethod::Max));
        assert!(!averages.allows(AggregationMethod::Sum));
    }

    #[test]
    fn no_method_list_allows_every_method() {
        let any = restriction(r#"min-period-duration = "PT1H""#);

        assert!(any.allows(AggregationMethod::Min));
        assert!(any.allows(AggregationMethod::SumSq));
    }

    #[test]
    fn disallowing_unaggregated_reads_without_a_method_list_is_refused() {
        // Any method would include `min` and `max`, which answer with a reading.
        assert!(toml::from_str::<AggregationRestriction>(r#"unaggregated = "disallowed""#).is_err());
        assert!(toml::from_str::<AggregationRestriction>("unaggregated = \"disallowed\"\nmin-period-duration = \"PT1H\"").is_err());
    }

    #[test]
    fn a_restriction_that_restricts_nothing_is_refused() {
        // Present, so enforcement runs; empty, so it restricts nothing.
        assert!(toml::from_str::<AggregationRestriction>("").is_err());
        assert!(toml::from_str::<AggregationRestriction>(r#"unaggregated = "allowed""#).is_err());
    }

    #[test]
    fn unaggregated_reads_are_allowed_unless_the_policy_says_otherwise() {
        assert_eq!(restriction(r#"allowed-methods = ["avg"]"#).unaggregated(), UnaggregatedReads::Allowed);
        assert_eq!(
            restriction("unaggregated = \"disallowed\"\nallowed-methods = [\"avg\"]").unaggregated(),
            UnaggregatedReads::Disallowed
        );
    }

    #[test]
    fn a_minimum_period_is_a_duration_by_the_time_it_is_stored() {
        let hourly = restriction(r#"min-period-duration = "PT1H""#);

        assert_eq!(hourly.min_period_duration().map(IsoDuration::as_secs), Some(3600));
        assert!(toml::from_str::<AggregationRestriction>(r#"min-period-duration = "1 hour""#).is_err());
    }

    #[test]
    fn a_minimum_period_in_months_fails_to_load() {
        // A month has no fixed length, so it lays no grid an aggregated read's window could sit on.
        for calendar in ["P1M", "P1Y", "P1Y2M", "P1MT1H"] {
            let source = format!("min-period-duration = \"{calendar}\"");

            assert!(toml::from_str::<AggregationRestriction>(&source).is_err(), "{calendar}");
        }
    }

    #[test]
    fn a_minimum_period_lays_a_grid_of_its_own_length() {
        assert_eq!(
            restriction(r#"min-period-duration = "PT1H""#).grid().map(AggregationGrid::period_seconds),
            Some(3600)
        );
        assert_eq!(restriction(r#"allowed-methods = ["avg"]"#).grid(), None);
    }

    #[test]
    fn a_value_or_a_key_the_restriction_does_not_define_is_refused() {
        assert!(toml::from_str::<AggregationRestriction>("unaggregated = \"refused\"\nallowed-methods = [\"avg\"]").is_err());
        assert!(toml::from_str::<AggregationRestriction>("unaggregated = \"disallowed\"\nallowed-method = [\"avg\"]").is_err());
        assert!(toml::from_str::<AggregationRestriction>("require-aggregation = true\nallowed-methods = [\"avg\"]").is_err());
    }
}
