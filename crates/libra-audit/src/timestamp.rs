//! When a record was completed.

use derive_more::{Display, From};
use jiff::Timestamp as Instant;
use libra_policy_model::datetime::rfc3339;

/// An instant, written as RFC 3339 with a numeric offset (`2026-01-15T12:00:00.123456789+00:00`).
///
/// The spelling is the one the audit record has always used and log queries match on, which is
/// not the one `jiff` gives a `Timestamp` by default: that ends in `Z`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Display, From)]
#[display("{}", rfc3339(*_0))]
pub struct Timestamp(Instant);

impl Timestamp {
    /// The current instant.
    #[must_use]
    pub fn now() -> Self {
        Self(Instant::now())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn written(text: &str) -> String {
        Timestamp::from(text.parse::<Instant>().unwrap()).to_string()
    }

    #[test]
    fn an_instant_is_written_as_rfc_3339_with_a_numeric_offset() {
        assert_eq!(written("2026-01-15T12:00:00Z"), "2026-01-15T12:00:00+00:00");
    }

    #[test]
    fn a_fraction_is_written_in_whole_milli_micro_or_nanoseconds() {
        assert_eq!(written("2026-01-15T12:00:00.12Z"), "2026-01-15T12:00:00.120+00:00");
        assert_eq!(written("2026-01-15T12:00:00.1234Z"), "2026-01-15T12:00:00.123400+00:00");
        assert_eq!(written("2026-01-15T12:00:00.123456789Z"), "2026-01-15T12:00:00.123456789+00:00");
    }
}
