//! Reading the two spellings a policy file may use for an instant.
//!
//! Policy files are TOML, and TOML has a datetime of its own: `2026-01-01T00:00:00Z`, unquoted.
//! The management API carries the same policies as JSON, where the only spelling is a quoted
//! string. Both have to reach the same value, or a policy would mean one thing on disk and another
//! through the API, and the difference would be a time window, which is a restriction.

use jiff::{Timestamp, civil::Time};
use serde::{Deserialize, Deserializer, Serializer, de::Error as DeError};
use toml::Value;

/// How a time of day is written: hours, minutes and seconds, with an optional fraction.
const TIME_OF_DAY: &str = "%H:%M:%S%.f";

/// Reduces either spelling to the text both share.
///
/// `toml::Value` is the intermediate because it is the one type that knows TOML's native datetime
/// and still reads a plain string, which is all JSON can offer.
fn written_form<'de, D>(deserializer: D, expected: &str) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    match Value::deserialize(deserializer)? {
        Value::Datetime(datetime) => Ok(datetime.to_string()),
        Value::String(text) => Ok(text),
        Value::Integer(_) | Value::Float(_) | Value::Boolean(_) | Value::Array(_) | Value::Table(_) => Err(DeError::custom(format!("expected {expected}"))),
    }
}

/// Reads an instant written either as a TOML datetime or as an RFC 3339 string.
///
/// # Errors
///
/// Fails if the value is neither, or if it carries no date.
pub fn deserialize_instant<'de, D>(deserializer: D) -> Result<Timestamp, D::Error>
where
    D: Deserializer<'de>,
{
    let written = written_form(deserializer, "an instant, as in 2026-01-01T00:00:00Z")?;

    written.parse::<Timestamp>().map_err(|_| {
        DeError::custom(format!(
            "'{written}' is not an instant; write a date, a time and an offset, as in 2026-01-01T00:00:00Z"
        ))
    })
}

/// Writes an instant as RFC 3339, which both spellings read back.
///
/// # Errors
///
/// Propagates the serializer's own failure.
pub fn serialize_instant<S>(instant: &Timestamp, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&rfc3339(*instant))
}

/// Writes an instant as RFC 3339 in UTC with a numeric offset, as in `2026-01-15T12:00:00+00:00`.
///
/// The fraction, when there is one, is written in whole milliseconds, microseconds or nanoseconds,
/// whichever is the shortest that loses nothing. That is the spelling policies and audit records
/// have always been written in, and what anything matching on them expects.
#[must_use]
pub fn rfc3339(instant: Timestamp) -> String {
    let nanoseconds = instant.subsec_nanosecond();

    let format = if nanoseconds == 0 {
        "%Y-%m-%dT%H:%M:%S%:z"
    } else if nanoseconds % 1_000_000 == 0 {
        "%Y-%m-%dT%H:%M:%S%.3f%:z"
    } else if nanoseconds % 1_000 == 0 {
        "%Y-%m-%dT%H:%M:%S%.6f%:z"
    } else {
        "%Y-%m-%dT%H:%M:%S%.9f%:z"
    };

    instant.strftime(format).to_string()
}

/// Reads a time of day written either as a TOML local time or as a string.
///
/// # Errors
///
/// Fails if the value is neither, or if it carries a date as well.
pub fn deserialize_time_of_day<'de, D>(deserializer: D) -> Result<Time, D::Error>
where
    D: Deserializer<'de>,
{
    let written = written_form(deserializer, "a time of day, as in 09:00:00")?;

    Time::strptime(TIME_OF_DAY, &written).map_err(|_| DeError::custom(format!("'{written}' is not a time of day; write it as 09:00:00")))
}

/// Writes a time of day in the form both spellings read back, with its fraction when it has one.
///
/// The fraction is kept because a window bound read back without it is a different bound, and a
/// policy carried through the management API would then mean a different window than on disk.
///
/// # Errors
///
/// Propagates the serializer's own failure.
pub fn serialize_time_of_day<S>(time: &Time, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&time.strftime(TIME_OF_DAY).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use jiff::civil::time;
    use pretty_assertions::assert_eq;
    use serde::Serialize;

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct Window {
        #[serde(deserialize_with = "deserialize_instant", serialize_with = "serialize_instant")]
        start: Timestamp,
        #[serde(deserialize_with = "deserialize_time_of_day", serialize_with = "serialize_time_of_day")]
        opens: Time,
    }

    #[test]
    fn the_native_toml_spelling_is_accepted() {
        let window: Window = toml::from_str("start = 2026-01-01T00:00:00Z\nopens = 09:00:00").unwrap();

        assert_eq!(rfc3339(window.start), "2026-01-01T00:00:00+00:00");
        assert_eq!(window.opens, time(9, 0, 0, 0));
    }

    #[test]
    fn the_quoted_spelling_reaches_the_same_value() {
        // The management API carries policies as JSON, where this is the only spelling. A policy
        // that meant a different window through the API than on disk would be a different restriction.
        let quoted: Window = toml::from_str("start = \"2026-01-01T00:00:00Z\"\nopens = \"09:00:00\"").unwrap();
        let native: Window = toml::from_str("start = 2026-01-01T00:00:00Z\nopens = 09:00:00").unwrap();

        assert_eq!(quoted, native);
    }

    #[test]
    fn an_offset_other_than_utc_is_carried_to_utc() {
        let window: Window = toml::from_str("start = 2026-01-01T01:00:00+01:00\nopens = 09:00:00").unwrap();

        assert_eq!(rfc3339(window.start), "2026-01-01T00:00:00+00:00");
    }

    #[test]
    fn an_instant_with_no_offset_is_refused() {
        // A local datetime means a different instant in every zone, and nothing in the policy says
        // which one. Refusing is the only reading that is not a guess.
        assert!(toml::from_str::<Window>("start = 2026-01-01T00:00:00\nopens = 09:00:00").is_err());
    }

    #[test]
    fn a_date_where_a_time_of_day_belongs_is_refused() {
        assert!(toml::from_str::<Window>("start = 2026-01-01T00:00:00Z\nopens = 2026-01-01T09:00:00Z").is_err());
    }

    #[test]
    fn a_time_of_day_without_seconds_is_refused() {
        assert!(toml::from_str::<Window>("start = 2026-01-01T00:00:00Z\nopens = \"09:00\"").is_err());
    }

    #[test]
    fn a_fractional_time_of_day_is_read_and_written_back_with_the_fraction() {
        let window: Window = toml::from_str("start = 2026-01-01T00:00:00Z\nopens = \"09:00:00.250\"").unwrap();

        assert_eq!(window.opens, time(9, 0, 0, 250_000_000));
        assert_eq!(serde_json::to_value(&window).unwrap()["opens"], "09:00:00.25");
    }

    #[test]
    fn a_whole_time_of_day_is_written_without_a_fraction() {
        let window: Window = toml::from_str("start = 2026-01-01T00:00:00Z\nopens = 09:00:00").unwrap();

        assert_eq!(serde_json::to_value(&window).unwrap()["opens"], "09:00:00");
    }

    #[test]
    fn a_written_time_of_day_reads_back_as_the_same_value() {
        let window: Window = toml::from_str("start = 2026-01-01T00:00:00Z\nopens = \"23:59:59.999999999\"").unwrap();
        let written = serde_json::to_string(&window).unwrap();

        assert_eq!(serde_json::from_str::<Window>(&written).unwrap(), window);
    }

    #[test]
    fn an_instant_is_written_with_the_shortest_whole_fraction() {
        let written = |text: &str| rfc3339(text.parse().unwrap());

        assert_eq!(written("2026-01-15T12:00:00Z"), "2026-01-15T12:00:00+00:00");
        assert_eq!(written("2026-01-15T12:00:00.5Z"), "2026-01-15T12:00:00.500+00:00");
        assert_eq!(written("2026-01-15T12:00:00.000250Z"), "2026-01-15T12:00:00.000250+00:00");
        assert_eq!(written("2026-01-15T12:00:00.000000001Z"), "2026-01-15T12:00:00.000000001+00:00");
    }
}
