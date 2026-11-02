//! ISO 8601 durations, parsed when the policy loads rather than when a request arrives.
//!
//! Two things go wrong when a duration stays a string until it is needed. The first is that a
//! typo becomes a runtime surprise: the parse fails on the request path, the failure degrades to
//! zero, and the policy quietly enforces a window of no width: no error, no log line, just empty
//! results. The second is that a duration expressed in calendar units cannot be compared with one
//! expressed in fixed units, because a month is not a number of seconds. Both are refused here,
//! at load, where the file and the line are still known.

use crate::error::ValueError;
use derive_more::Display;
use jiff::{SpanRelativeTo, fmt::temporal::SpanParser};
use serde::{Deserialize, Serialize};
use std::{num::NonZeroU64, time::Duration};

/// A duration written in ISO 8601 and usable as a fixed number of seconds.
///
/// Accepts `PnW`, and `PnDTnHnMnS` with any component omitted. Years and months are refused: they
/// are the two units whose length depends on when they start, so a policy that compares against
/// one is comparing against a different amount of time depending on the request.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Display)]
#[display("{written}")]
#[serde(try_from = "String", into = "String")]
pub struct IsoDuration {
    written: String,
    seconds: NonZeroU64,
}

impl IsoDuration {
    /// Parses an ISO 8601 duration.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError::Duration`] if the value is not an ISO 8601 duration, uses a calendar
    /// unit, or is zero.
    pub fn parse(value: impl Into<String>) -> Result<Self, ValueError> {
        let written = value.into();
        let seconds = match seconds_of(&written) {
            Ok(seconds) => seconds,
            Err(reason) => return Err(ValueError::Duration { value: written, reason }),
        };

        Ok(Self { written, seconds })
    }

    /// The duration in seconds.
    #[must_use]
    pub const fn as_secs(&self) -> u64 {
        self.seconds.get()
    }

    /// The duration in seconds, which is never zero: a zero duration does not parse.
    #[must_use]
    pub const fn as_nonzero_secs(&self) -> NonZeroU64 {
        self.seconds
    }

    /// The duration as a [`Duration`].
    #[must_use]
    pub const fn as_duration(&self) -> Duration {
        Duration::from_secs(self.seconds.get())
    }

    /// The duration as the policy wrote it.
    ///
    /// A request rewritten to the policy minimum should carry the operator's own spelling, not a
    /// normalised one, so the two can be matched up by eye.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.written
    }
}

impl TryFrom<String> for IsoDuration {
    type Error = ValueError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

impl From<IsoDuration> for String {
    fn from(duration: IsoDuration) -> Self {
        duration.written
    }
}

/// Reads ISO 8601 durations in the designator format, and nothing else.
///
/// `Span`'s own `FromStr` also reads Jiff's "friendly" format (`24 hours`), which a policy must not
/// be able to use: it is not ISO 8601, and the same text would not mean the same thing anywhere
/// else a policy is read.
static PARSER: SpanParser = SpanParser::new();

/// Parses an ISO 8601 duration into seconds, or says why it cannot.
fn seconds_of(source: &str) -> Result<NonZeroU64, &'static str> {
    // The parser is lenient where a policy should not be: it reads lowercase designators, which
    // ISO 8601 does not define, and it carries a fraction down into smaller units. Both are
    // refused before it sees the text.
    if source.bytes().any(|byte| byte.is_ascii_lowercase()) {
        return Err("designators are written in capitals, as in PT1H");
    }
    if source.contains(['.', ',']) {
        return Err("fractional components are not supported");
    }

    let span = PARSER.parse_span(source).map_err(|_| "it is not an ISO 8601 duration, as in PT1H or P2D")?;

    if span.is_negative() {
        return Err("it is negative");
    }

    // The two refusals that matter. Both parse in ISO 8601 and neither is a fixed number of
    // seconds, so a minimum written in one is a different minimum in February.
    if span.get_years() != 0 || span.get_months() != 0 {
        return Err("years and months are not a fixed length; use days, hours, minutes or seconds");
    }

    if span.is_zero() {
        // A zero minimum period and no minimum period are two ways of writing the same thing, and
        // only one of them looks like a restriction. Refusing the one that looks like a
        // restriction leaves no way to write a policy that reads as enforcement and enforces nothing.
        return Err("it is zero; omit the setting instead");
    }

    // Weeks and days are 7 and 1 times 24 hours here, which is what a window measured from the
    // moment of a request means by them: no calendar is involved.
    let duration = span
        .to_duration(SpanRelativeTo::days_are_24_hours())
        .map_err(|_| "it is too long to represent")?;

    let seconds = u64::try_from(duration.as_secs()).map_err(|_| "it is negative")?;

    // Fractions are refused above, so a span that is not zero is a whole number of seconds and at
    // least one; the conversion states that rather than relying on it.
    NonZeroU64::new(seconds).ok_or("it is shorter than one second")
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn secs(source: &str) -> u64 {
        IsoDuration::parse(source)
            .unwrap_or_else(|error| panic!("{source} should parse: {error}"))
            .as_secs()
    }

    #[test]
    fn the_fixed_units_all_parse() {
        assert_eq!(secs("PT1H"), 3600);
        assert_eq!(secs("PT30M"), 1800);
        assert_eq!(secs("PT45S"), 45);
        assert_eq!(secs("P1D"), 86_400);
        assert_eq!(secs("P2W"), 1_209_600);
    }

    #[test]
    fn components_combine() {
        assert_eq!(secs("P1DT2H30M15S"), 86_400 + 7200 + 1800 + 15);
        assert_eq!(secs("PT1H30M"), 5400);
    }

    #[test]
    fn m_means_months_before_the_t_and_minutes_after_it() {
        // The single most confusable pair in the format. `P1M` is a month and is refused; `PT1M`
        // is a minute and is not.
        assert_eq!(secs("PT1M"), 60);
        assert!(IsoDuration::parse("P1M").is_err());
    }

    #[test]
    fn calendar_units_are_refused_rather_than_approximated() {
        // Treating a year as 365 days would make a policy's minimum period silently wrong in a
        // leap year, and a month is worse: four possible lengths.
        for calendar in ["P1Y", "P1M", "P1Y6M"] {
            let refused = IsoDuration::parse(calendar);

            assert!(refused.is_err(), "{calendar} must be refused, got {refused:?}");
        }
    }

    #[test]
    fn a_zero_duration_is_refused() {
        // The failure mode: a restriction that is present, looks enforced, and allows everything.
        for zero in ["PT0S", "P0D", "PT0H0M0S"] {
            assert!(IsoDuration::parse(zero).is_err(), "{zero} must be refused");
        }
    }

    #[test]
    fn a_malformed_duration_fails_at_load_rather_than_becoming_zero() {
        // Read on the request path and degraded to zero seconds, each of these would produce a
        // window of no width with no error anywhere.
        for malformed in [
            "",
            "1H",
            "PT",
            "P",
            "PTH",
            "P1",
            "PT1.5H",
            "PT1,5H",
            "24 hours",
            "1 hour",
            "PT1X",
            "pt1h",
            "-PT1H",
            "PT1H junk",
        ] {
            assert!(IsoDuration::parse(malformed).is_err(), "{malformed:?} must be refused");
        }
    }

    #[test]
    fn the_operators_own_spelling_survives() {
        // A request rewritten to the policy minimum carries this back to the caller, so it should
        // read the way the policy reads.
        let duration = IsoDuration::parse("PT1H").unwrap();

        assert_eq!(duration.as_str(), "PT1H");
        assert_eq!(duration.to_string(), "PT1H");
    }

    #[test]
    fn durations_compare_by_length() {
        assert!(IsoDuration::parse("PT1H").unwrap().as_secs() > IsoDuration::parse("PT59M").unwrap().as_secs());
    }

    #[test]
    fn a_calendar_unit_is_refused_for_being_a_calendar_unit() {
        // Each of these has to meet the refusal that names the reason, not a later one that happens
        // to fail for another: a year alone or a month alone is as variable as both together.
        for calendar in ["P1Y", "P1M", "P1Y6M", "P1YT1H"] {
            let refused = IsoDuration::parse(calendar).unwrap_err().to_string();

            assert!(refused.contains("not a fixed length"), "{calendar}: {refused}");
        }
    }

    #[test]
    fn a_duration_is_written_back_in_the_operators_spelling() {
        assert_eq!(String::from(IsoDuration::parse("P1DT2H").unwrap()), "P1DT2H");
    }
}
