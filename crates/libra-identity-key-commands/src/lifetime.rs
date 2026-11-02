//! How long a key is to be accepted, as written on the command line.

use jiff::{SignedDuration, Span, SpanRelativeTo};
use std::str::FromStr;
use thiserror::Error;

/// A key's lifetime: a positive duration, written as a jiff span (`90d`, `12h`, `P30D`).
///
/// Days count as 24 hours. Years and months are refused, because they have no fixed length and an
/// expiry should not depend on which month the key was issued in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lifetime(SignedDuration);

/// Why a lifetime was refused.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum LifetimeError {
    /// Not a duration jiff reads.
    #[error("'{0}' is not a duration such as 90d, 12h or P30D")]
    Unreadable(String),
    /// Written in years or months.
    #[error("'{0}' uses years or months, which have no fixed length; write it in days")]
    Calendar(String),
    /// Zero or negative.
    #[error("'{0}' is not a positive duration")]
    NotPositive(String),
}

impl Lifetime {
    /// The lifetime as a duration.
    #[must_use]
    pub const fn duration(self) -> SignedDuration {
        self.0
    }
}

/// Written by hand: the span is read, measured with 24-hour days, and checked to be positive, none
/// of which a derive expresses.
impl FromStr for Lifetime {
    type Err = LifetimeError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let span = Span::from_str(text).map_err(|_| LifetimeError::Unreadable(text.to_owned()))?;
        let duration = span
            .to_duration(SpanRelativeTo::days_are_24_hours())
            .map_err(|_| LifetimeError::Calendar(text.to_owned()))?;

        if duration.is_positive() {
            Ok(Self(duration))
        } else {
            Err(LifetimeError::NotPositive(text.to_owned()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn friendly_and_iso_durations_are_read_with_24_hour_days() {
        assert_eq!(Lifetime::from_str("90d").map(Lifetime::duration), Ok(SignedDuration::from_hours(90 * 24)));
        assert_eq!(Lifetime::from_str("P30D").map(Lifetime::duration), Ok(SignedDuration::from_hours(30 * 24)));
        assert_eq!(Lifetime::from_str("12h").map(Lifetime::duration), Ok(SignedDuration::from_hours(12)));
    }

    #[test]
    fn calendar_units_zero_negative_and_nonsense_are_refused() {
        assert!(matches!(Lifetime::from_str("P1M"), Err(LifetimeError::Calendar(_))));
        assert!(matches!(Lifetime::from_str("1y"), Err(LifetimeError::Calendar(_))));
        assert!(matches!(Lifetime::from_str("0s"), Err(LifetimeError::NotPositive(_))));
        assert!(matches!(Lifetime::from_str("-5d"), Err(LifetimeError::NotPositive(_))));
        assert!(matches!(Lifetime::from_str("forever"), Err(LifetimeError::Unreadable(_))));
    }
}
