//! Deciding whether a temporal read aggregates the way its policy requires.

use crate::error::AggregationError;
use jiff::SpanRelativeTo;
use libra_ngsi_ld_query::aggregation::{AggregationMethod, AggregationPeriod};
use libra_ngsi_ld_representation::representation::TemporalRepresentation;
use libra_policy_model::{
    aggregation::{AggregationRestriction, UnaggregatedReads},
    aggregation_grid::AggregationGrid,
    duration::IsoDuration,
};

/// The aggregation a temporal read asked for, gathered from every place it could have written it.
///
/// A temporal query writes `aggrMethods` and `aggrPeriodDuration` in its query string;
/// `POST /temporal/entityOperations/query` writes them in its body. Which of the places a broker
/// reads is the broker's business, so every value found in any of them has to satisfy the policy.
/// Checking only the one Libra would have read is how a value in another place becomes a way round
/// the method list.
#[derive(Debug, Clone, Default)]
pub struct RequestedAggregation {
    /// The temporal representation the read resolved to.
    pub representation: TemporalRepresentation,
    /// Every method named, from every place one was named.
    pub methods: Vec<AggregationMethod>,
    /// Every period named, from every place one was named.
    pub periods: Vec<AggregationPeriod>,
}

/// What enforcement decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Enforcement {
    /// The read meets the restriction as it stands.
    Allowed,
    /// The read would meet the restriction with its period raised to the minimum.
    ///
    /// Whether it is raised or refused is the deployment's choice, not this function's: see
    /// `short-period` in the `[aggregation]` configuration section.
    RaisePeriod {
        /// The period to write, as the policy wrote it.
        minimum: IsoDuration,
        /// What was wrong with the period the caller named.
        shortfall: PeriodShortfall,
    },
}

/// Why a period did not satisfy the policy minimum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeriodShortfall {
    /// The caller named no period at all.
    Missing,
    /// The caller named a period finer than the minimum.
    TooShort,
    /// The caller named a period at least as coarse as the minimum but not a whole number of
    /// minimum periods.
    OffGrid,
}

impl PeriodShortfall {
    /// The refusal this shortfall becomes when the period is not raised.
    #[must_use]
    pub const fn refusal(self, minimum: IsoDuration) -> AggregationError {
        match self {
            Self::Missing => AggregationError::PeriodMissing { minimum },
            Self::TooShort => AggregationError::PeriodTooShort { minimum },
            Self::OffGrid => AggregationError::PeriodOffGrid { minimum },
        }
    }
}

/// Checks one temporal read against the aggregation restriction it is under.
///
/// Three questions, in order: is every method the caller named one the restriction allows, does
/// the read aggregate when the restriction says it must, and is an aggregated read's period at
/// least as coarse as the restriction's minimum. The methods are checked even on a read that does
/// not aggregate, because a broker that reads them anyway is not one Libra can rule out.
///
/// # Errors
///
/// Returns the [`AggregationError`] describing the first requirement the read fails.
pub fn enforce(restriction: &AggregationRestriction, requested: &RequestedAggregation) -> Result<Enforcement, AggregationError> {
    if let Some(method) = requested.methods.iter().copied().find(|method| !restriction.allows(*method)) {
        return Err(AggregationError::MethodDisallowed { method });
    }

    match requested.representation {
        TemporalRepresentation::Aggregated => {}
        TemporalRepresentation::Instances | TemporalRepresentation::Simplified => {
            return match restriction.unaggregated() {
                UnaggregatedReads::Allowed => Ok(Enforcement::Allowed),
                UnaggregatedReads::Disallowed => Err(AggregationError::UnaggregatedDisallowed),
            };
        }
    }

    if requested.methods.is_empty() {
        return Err(AggregationError::MethodsMissing);
    }

    let Some(minimum) = restriction.min_period_duration() else {
        // No minimum to compare against, so the caller's period is the broker's business.
        return Ok(Enforcement::Allowed);
    };

    check_periods(minimum, &requested.periods)
}

/// Checks every period named against the policy minimum.
///
/// A missing period and `PT0S` both mean "the whole time range of the query" (NGSI-LD clause
/// 4.5.19.1). Neither is credited as coarse: the caller chooses that range, and a range no longer
/// than one reading makes the whole-range aggregate that reading.
///
/// A period has to be a whole number of minimum periods as well as long enough. Buckets are laid
/// from a window start on the grid, so a period of one and a half minimum periods ends every other
/// bucket between two grid points, and that bucket differenced with one on the grid isolates the
/// half period between them.
fn check_periods(minimum: &IsoDuration, periods: &[AggregationPeriod]) -> Result<Enforcement, AggregationError> {
    if periods.is_empty() {
        return Ok(Enforcement::RaisePeriod {
            minimum: minimum.clone(), // the decision outlives the restriction it was read from
            shortfall: PeriodShortfall::Missing,
        });
    }

    for period in periods {
        // Weeks and days are 7 and 1 times 24 hours, as they are in the policy's own minimum.
        // Years and months have no fixed length, so they cannot be compared at all.
        let length = period
            .span()
            .to_duration(SpanRelativeTo::days_are_24_hours())
            .map_err(|_| AggregationError::IncomparablePeriod {
                period: period.span().to_string(),
            })?;

        let shortfall = match u64::try_from(length.as_secs()) {
            Ok(seconds) if seconds < minimum.as_secs() => Some(PeriodShortfall::TooShort),
            Err(_) => Some(PeriodShortfall::TooShort),
            Ok(seconds) if length.subsec_nanos() != 0 || !AggregationGrid::new(minimum).divides(seconds) => Some(PeriodShortfall::OffGrid),
            Ok(_) => None,
        };

        if let Some(shortfall) = shortfall {
            return Ok(Enforcement::RaisePeriod {
                minimum: minimum.clone(), // the decision outlives the restriction it was read from
                shortfall,
            });
        }
    }

    Ok(Enforcement::Allowed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use std::str::FromStr;

    fn restriction(source: &str) -> AggregationRestriction {
        toml::from_str(source).unwrap()
    }

    fn aggregated(methods: &[AggregationMethod], periods: &[&str]) -> RequestedAggregation {
        RequestedAggregation {
            representation: TemporalRepresentation::Aggregated,
            methods: methods.to_vec(),
            periods: periods.iter().map(|period| AggregationPeriod::from_str(period).unwrap()).collect(),
        }
    }

    fn unaggregated(representation: TemporalRepresentation, methods: &[AggregationMethod]) -> RequestedAggregation {
        RequestedAggregation {
            representation,
            methods: methods.to_vec(),
            periods: Vec::new(),
        }
    }

    const HOURLY_AVERAGES: &str = "unaggregated = \"disallowed\"\nallowed-methods = [\"avg\"]\nmin-period-duration = \"PT1H\"";

    #[test]
    fn an_allowed_method_with_a_coarse_enough_period_is_allowed() {
        assert_eq!(
            enforce(&restriction(HOURLY_AVERAGES), &aggregated(&[AggregationMethod::Avg], &["PT2H"])),
            Ok(Enforcement::Allowed)
        );
    }

    #[test]
    fn a_method_the_policy_does_not_list_is_refused() {
        assert_eq!(
            enforce(&restriction(HOURLY_AVERAGES), &aggregated(&[AggregationMethod::Max], &["PT2H"])),
            Err(AggregationError::MethodDisallowed {
                method: AggregationMethod::Max
            })
        );
    }

    #[test]
    fn every_method_named_is_checked_not_just_the_first() {
        let policy = restriction(r#"allowed-methods = ["avg", "sum"]"#);

        assert_eq!(
            enforce(&policy, &aggregated(&[AggregationMethod::Avg, AggregationMethod::Sum], &[])),
            Ok(Enforcement::Allowed)
        );
        assert_eq!(
            enforce(&policy, &aggregated(&[AggregationMethod::Avg, AggregationMethod::Max], &[])),
            Err(AggregationError::MethodDisallowed {
                method: AggregationMethod::Max
            })
        );
    }

    #[test]
    fn an_unaggregated_read_is_refused_when_unaggregated_reads_are_disallowed() {
        // Methods named without `aggregatedValues` are ignored by the broker, so naming them does
        // not make the read aggregate.
        for representation in [TemporalRepresentation::Instances, TemporalRepresentation::Simplified] {
            assert_eq!(
                enforce(&restriction(HOURLY_AVERAGES), &unaggregated(representation, &[AggregationMethod::Avg])),
                Err(AggregationError::UnaggregatedDisallowed),
                "{representation}"
            );
        }
    }

    #[test]
    fn an_unaggregated_read_is_allowed_when_unaggregated_reads_are() {
        // The minimum period governs aggregated reads; a policy that allows raw reads has said
        // nothing about their period.
        for policy in [r#"allowed-methods = ["avg"]"#, r#"min-period-duration = "PT1H""#] {
            assert_eq!(
                enforce(&restriction(policy), &unaggregated(TemporalRepresentation::Instances, &[])),
                Ok(Enforcement::Allowed),
                "{policy}"
            );
        }
    }

    #[test]
    fn an_aggregated_read_naming_no_method_is_a_bad_request() {
        assert_eq!(
            enforce(&restriction(r#"min-period-duration = "PT1H""#), &aggregated(&[], &["PT1H"])),
            Err(AggregationError::MethodsMissing)
        );
    }

    #[test]
    fn a_missing_period_under_a_minimum_asks_for_the_minimum() {
        assert_eq!(
            enforce(&restriction(HOURLY_AVERAGES), &aggregated(&[AggregationMethod::Avg], &[])),
            Ok(Enforcement::RaisePeriod {
                minimum: IsoDuration::parse("PT1H").unwrap(),
                shortfall: PeriodShortfall::Missing,
            })
        );
    }

    #[test]
    fn a_period_finer_than_the_minimum_and_a_zero_period_ask_for_the_minimum() {
        for period in ["PT5M", "PT0S"] {
            assert_eq!(
                enforce(&restriction(HOURLY_AVERAGES), &aggregated(&[AggregationMethod::Avg], &[period])),
                Ok(Enforcement::RaisePeriod {
                    minimum: IsoDuration::parse("PT1H").unwrap(),
                    shortfall: PeriodShortfall::TooShort,
                }),
                "{period}"
            );
        }
    }

    #[test]
    fn periods_are_compared_by_length_rather_than_by_spelling() {
        let policy = restriction(HOURLY_AVERAGES);

        assert_eq!(enforce(&policy, &aggregated(&[AggregationMethod::Avg], &["PT60M"])), Ok(Enforcement::Allowed));
        assert_eq!(enforce(&policy, &aggregated(&[AggregationMethod::Avg], &["P1D"])), Ok(Enforcement::Allowed));
        assert!(matches!(
            enforce(&policy, &aggregated(&[AggregationMethod::Avg], &["PT59M"])),
            Ok(Enforcement::RaisePeriod { .. })
        ));
    }

    #[test]
    fn a_period_that_is_not_a_whole_number_of_minimum_periods_is_off_the_grid() {
        let policy = restriction(HOURLY_AVERAGES);

        for period in ["PT90M", "PT1H30S"] {
            assert_eq!(
                enforce(&policy, &aggregated(&[AggregationMethod::Avg], &[period])),
                Ok(Enforcement::RaisePeriod {
                    minimum: IsoDuration::parse("PT1H").unwrap(),
                    shortfall: PeriodShortfall::OffGrid,
                }),
                "{period}"
            );
        }
        assert_eq!(enforce(&policy, &aggregated(&[AggregationMethod::Avg], &["PT3H"])), Ok(Enforcement::Allowed));
    }

    #[test]
    fn a_period_in_years_or_months_is_a_bad_request() {
        for period in ["P1M", "P1Y"] {
            assert!(
                matches!(
                    enforce(&restriction(HOURLY_AVERAGES), &aggregated(&[AggregationMethod::Avg], &[period])),
                    Err(AggregationError::IncomparablePeriod { .. })
                ),
                "{period}"
            );
        }
    }

    #[test]
    fn every_period_named_has_to_meet_the_minimum() {
        // Two places named a period and only one of them is coarse enough. Which one the broker
        // reads is not Libra's decision, so both have to satisfy the policy.
        assert!(matches!(
            enforce(&restriction(HOURLY_AVERAGES), &aggregated(&[AggregationMethod::Avg], &["PT2H", "PT1M"])),
            Ok(Enforcement::RaisePeriod {
                shortfall: PeriodShortfall::TooShort,
                ..
            })
        ));
    }

    #[test]
    fn a_shortfall_carries_the_policys_own_spelling_of_the_minimum() {
        let minimum = IsoDuration::parse("PT60M").unwrap();

        assert_eq!(
            PeriodShortfall::TooShort.refusal(minimum).to_string(),
            "aggrPeriodDuration is finer than the minimum of 'PT60M' this policy requires"
        );
    }
}
