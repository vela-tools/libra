//! `[aggregation]`: how aggregation enforcement treats a period finer than a policy allows.

use serde::{Deserialize, Serialize};

/// What to do with an aggregated temporal read whose `aggrPeriodDuration` is missing or finer
/// than the minimum its policy sets.
#[derive(Deserialize, Serialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum ShortPeriod {
    /// Answer 403 and tell the caller the minimum. The default: the caller learns that the answer
    /// they asked for is not one they may have.
    #[default]
    Refuse,
    /// Rewrite the period to the policy minimum and forward the request. Friendlier and quieter,
    /// and quieter is the reason it is not the default: the caller is served a coarser answer than
    /// they asked for and may not notice.
    Raise,
}

/// Aggregation enforcement configuration.
#[derive(Deserialize, Serialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[serde(default, rename_all = "kebab-case", deny_unknown_fields)]
pub struct Aggregation {
    /// What to do with a period finer than the policy minimum.
    pub short_period: ShortPeriod,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pending::PendingConfig;
    use pretty_assertions::assert_eq;

    fn section(text: &str) -> Option<Aggregation> {
        PendingConfig::from_toml_with_broker(text).ok().map(|pending| pending.config().aggregation)
    }

    #[test]
    fn a_short_period_is_refused_rather_than_raised_by_default() {
        assert_eq!(section("").map(|aggregation| aggregation.short_period), Some(ShortPeriod::Refuse));
    }

    #[test]
    fn the_aggregation_section_turns_raising_on() {
        assert_eq!(
            section("[aggregation]\nshort-period = \"raise\"").map(|aggregation| aggregation.short_period),
            Some(ShortPeriod::Raise)
        );
    }

    #[test]
    fn the_boolean_spelling_and_a_mistyped_key_are_refused() {
        assert_eq!(section("[aggregation]\nperiod-autorewrite = true"), None);
        assert_eq!(section("[aggregation]\nshort_period = \"raise\""), None);
        assert_eq!(section("[aggregation]\nshort-period = \"rewrite\""), None);
    }
}
