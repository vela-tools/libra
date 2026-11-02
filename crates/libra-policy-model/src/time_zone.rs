//! The zone a recurring interval is read in.

use jiff::{
    Timestamp,
    civil::DateTime,
    tz::{TimeZone, TimeZoneDatabase},
};
use serde::{Deserialize, Serialize, Serializer, ser::Error as SerError};
use std::sync::LazyLock;
use thiserror::Error;

/// The time zone database every policy is read against: the copy compiled into the binary.
///
/// Not the host's `/usr/share/zoneinfo`. A time-of-day condition is an authorization rule, and the
/// same policy must make the same decision on every host that loads it, whatever tzdata release the
/// image happens to carry or whether it carries one at all.
static BUNDLED: LazyLock<TimeZoneDatabase> = LazyLock::new(TimeZoneDatabase::bundled);

/// A zone name that is not in the IANA time zone database.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("'{name}' is not an IANA time zone, as in Europe/Madrid")]
pub struct UnknownTimeZone {
    /// The name as written.
    pub name: String,
}

/// An IANA time zone, named the way a policy names it.
///
/// Only IANA names are accepted. A fixed offset or a POSIX TZ string would also describe a zone,
/// but neither follows the daylight-saving rules of the place a policy author has in mind, and a
/// window that drifts by an hour twice a year is a different restriction than the one written.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub struct PolicyTimeZone(TimeZone);

impl PolicyTimeZone {
    /// The zone with this IANA name.
    ///
    /// # Errors
    ///
    /// Returns [`UnknownTimeZone`] if the bundled database has no zone by that name.
    pub fn named(name: &str) -> Result<PolicyTimeZone, UnknownTimeZone> {
        BUNDLED.get(name).map(PolicyTimeZone).map_err(|_| UnknownTimeZone { name: name.to_owned() })
    }

    /// The civil date and time `instant` falls on in this zone.
    #[must_use]
    pub fn to_datetime(&self, instant: Timestamp) -> DateTime {
        self.0.to_datetime(instant)
    }
}

impl TryFrom<String> for PolicyTimeZone {
    type Error = UnknownTimeZone;

    fn try_from(name: String) -> Result<PolicyTimeZone, UnknownTimeZone> {
        PolicyTimeZone::named(&name)
    }
}

// Not derived: the name is read out of the zone rather than stored beside it, so the zone and the
// name it is written back under cannot disagree.
impl Serialize for PolicyTimeZone {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.0.iana_name() {
            Some(name) => serializer.serialize_str(name),
            None => Err(S::Error::custom("a time zone read from the bundled database carries no IANA name")),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::time_zone::{PolicyTimeZone, UnknownTimeZone};
    use jiff::{Timestamp, civil::date};
    use pretty_assertions::assert_eq;

    fn instant(text: &str) -> Timestamp {
        text.parse().expect("the test instant parses")
    }

    #[test]
    fn an_iana_name_is_read_and_written_back_unchanged() {
        let zone: PolicyTimeZone = serde_json::from_str(r#""Europe/Madrid""#).expect("an IANA name");

        assert_eq!(serde_json::to_string(&zone).ok().as_deref(), Some(r#""Europe/Madrid""#));
    }

    #[test]
    fn a_zone_follows_daylight_saving_time() {
        let madrid = PolicyTimeZone::named("Europe/Madrid").expect("an IANA name");

        assert_eq!(madrid.to_datetime(instant("2026-01-15T12:00:00Z")), date(2026, 1, 15).at(13, 0, 0, 0));
        assert_eq!(madrid.to_datetime(instant("2026-07-15T12:00:00Z")), date(2026, 7, 15).at(14, 0, 0, 0));
    }

    #[test]
    fn a_name_the_database_does_not_hold_is_refused() {
        assert_eq!(
            PolicyTimeZone::named("Mars/Olympus_Mons"),
            Err(UnknownTimeZone {
                name: "Mars/Olympus_Mons".to_owned()
            })
        );
    }

    #[test]
    fn a_fixed_offset_or_posix_string_is_not_a_zone_name() {
        for written in ["+01:00", "CET-1CEST,M3.5.0,M10.5.0/3"] {
            assert!(PolicyTimeZone::named(written).is_err(), "{written} must be refused");
        }
    }
}
