//! Temporal window restrictions.
//!
//! A time restriction narrows *which instants* a caller may read, which is a different question
//! from the recurring interval in a condition, which decides *when* a caller may make the request
//! at all. Both exist; they are not interchangeable.

use crate::{
    datetime::{deserialize_instant, serialize_instant},
    duration::IsoDuration,
};
use jiff::{SignedDuration, Timestamp};
use serde::{Deserialize, Deserializer, Serialize, de::Error as DeError};

/// Which side of now a relative window falls on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Direction {
    /// The window ends at the moment of the request.
    #[default]
    Past,
    /// The window starts at the moment of the request.
    Future,
}

/// What a time restriction makes of a current-state read: one of `/entities`, `/entities/{id}` or a
/// batch query, which answers with entities as they are now rather than with a window of instants.
///
/// A temporal query names a window, and the restriction narrows it. A current-state read names
/// none, so the restriction has to say what it means for one. Writes are not governed by this:
/// they keep the request-time rule of the window's kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CurrentState {
    /// Every current-state read is refused. The default for a relative window.
    Refuse,
    /// A current-state read is allowed while the moment of the request lies inside the window. The
    /// default for an absolute window; refused at load for a relative one, which by construction
    /// always contains the request.
    RequestInWindow,
    /// Current state is readable; the window bounds temporal reads only.
    Allow,
    /// Current state is readable, and every attribute instance whose `observedAt` (or
    /// `modifiedAt`, when it has none) lies outside the window is removed from the answer.
    ValuesInWindow,
}

/// The current-state rule of an absolute window that names none.
const fn absolute_current_state() -> CurrentState {
    CurrentState::RequestInWindow
}

/// The current-state rule of a relative window that names none.
const fn relative_current_state() -> CurrentState {
    CurrentState::Refuse
}

/// Reads a relative window's current-state rule, refusing the one that is vacuous for it.
///
/// A relative window is measured from the moment of the request, so the request always lies inside
/// it: `request-in-window` would read as a restriction and place none.
fn deserialize_relative_current_state<'de, D>(deserializer: D) -> Result<CurrentState, D::Error>
where
    D: Deserializer<'de>,
{
    match CurrentState::deserialize(deserializer)? {
        CurrentState::RequestInWindow => Err(D::Error::custom(
            "current-state = \"request-in-window\" is vacuous on a relative window, which always contains the request",
        )),
        rule @ (CurrentState::Refuse | CurrentState::Allow | CurrentState::ValuesInWindow) => Ok(rule),
    }
}

/// The window of instants a policy allows access to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum TimeRestriction {
    /// A fixed window, the same for every request.
    Absolute {
        /// First instant allowed.
        #[serde(deserialize_with = "deserialize_instant", serialize_with = "serialize_instant")]
        start: Timestamp,
        /// Last instant allowed.
        #[serde(deserialize_with = "deserialize_instant", serialize_with = "serialize_instant")]
        end: Timestamp,
        /// What a current-state read is allowed.
        #[serde(rename = "current-state", default = "absolute_current_state")]
        current_state: CurrentState,
    },
    /// A window measured from the moment of the request.
    Relative {
        /// How wide the window is.
        duration: IsoDuration,
        /// Which side of now it falls on.
        #[serde(default)]
        direction: Direction,
        /// What a current-state read is allowed.
        #[serde(
            rename = "current-state",
            default = "relative_current_state",
            deserialize_with = "deserialize_relative_current_state"
        )]
        current_state: CurrentState,
    },
}

/// The longest relative window a policy may name: one hundred years.
///
/// A window wider than a century is a typo rather than a restriction. Refused at load by
/// [`TimeRestriction::is_satisfiable`].
const MAX_RELATIVE_SECONDS: u64 = 100 * 366 * 24 * 3600;

impl TimeRestriction {
    /// The window this restriction allows at `now`.
    ///
    /// Total: the duration was checked when the policy loaded, so there is no parse here that
    /// could fail and collapse the window to nothing, and the arithmetic saturates at the ends of
    /// the representable range rather than panicking on a duration that slipped past the load check.
    #[must_use]
    pub fn window(&self, now: Timestamp) -> (Timestamp, Timestamp) {
        match self {
            Self::Absolute { start, end, .. } => (*start, *end),
            Self::Relative { duration, direction, .. } => {
                let offset = SignedDuration::try_from(duration.as_duration()).unwrap_or(SignedDuration::MAX);

                match direction {
                    Direction::Past => (now.checked_sub(offset).unwrap_or(Timestamp::MIN), now),
                    Direction::Future => (now, now.checked_add(offset).unwrap_or(Timestamp::MAX)),
                }
            }
        }
    }

    /// What a current-state read is allowed under this restriction.
    #[must_use]
    pub const fn current_state(&self) -> CurrentState {
        match self {
            Self::Absolute { current_state, .. } | Self::Relative { current_state, .. } => *current_state,
        }
    }

    /// Whether the restriction has a usable window at all.
    ///
    /// An absolute start after its end allows nothing, which is a policy that reads as an allow
    /// and is not one. A relative window wider than a century is a typo. The store refuses both
    /// at load.
    #[must_use]
    pub fn is_satisfiable(&self) -> bool {
        match self {
            Self::Absolute { start, end, .. } => start <= end,
            Self::Relative { duration, .. } => duration.as_secs() <= MAX_RELATIVE_SECONDS,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn at(text: &str) -> Timestamp {
        text.parse().unwrap()
    }

    fn restriction(source: &str) -> TimeRestriction {
        toml::from_str(source).unwrap()
    }

    #[test]
    fn an_absolute_window_is_the_one_written() {
        let time = restriction(
            r#"
            type = "absolute"
            start = 2026-01-01T00:00:00Z
            end = 2026-02-01T00:00:00Z
            "#,
        );

        assert_eq!(
            time.window(at("2026-01-15T12:00:00Z")),
            (at("2026-01-01T00:00:00Z"), at("2026-02-01T00:00:00Z"))
        );
    }

    #[test]
    fn a_relative_window_defaults_to_looking_backwards() {
        let time = restriction("type = \"relative\"\nduration = \"PT24H\"");
        let now = at("2026-01-15T12:00:00Z");

        assert_eq!(time.window(now), (at("2026-01-14T12:00:00Z"), now));
    }

    #[test]
    fn a_future_window_starts_now() {
        let time = restriction("type = \"relative\"\nduration = \"PT2H\"\ndirection = \"future\"");
        let now = at("2026-01-15T12:00:00Z");

        assert_eq!(time.window(now), (now, at("2026-01-15T14:00:00Z")));
    }

    #[test]
    fn a_malformed_duration_never_reaches_a_window() {
        // A malformed duration does not load: parsed at request time it would fail, degrade to zero seconds
        // and produce a window of no width, with empty results, no error and no log line.
        assert!(toml::from_str::<TimeRestriction>("type = \"relative\"\nduration = \"24 hours\"").is_err());
        assert!(toml::from_str::<TimeRestriction>("type = \"relative\"\nduration = \"1h30m\"").is_err());
    }

    #[test]
    fn a_backwards_absolute_window_is_recognised_as_unsatisfiable() {
        let backwards = restriction(
            r#"
            type = "absolute"
            start = 2026-02-01T00:00:00Z
            end = 2026-01-01T00:00:00Z
            "#,
        );

        assert!(!backwards.is_satisfiable());
        assert!(restriction("type = \"relative\"\nduration = \"PT1H\"").is_satisfiable());
    }

    #[test]
    fn a_relative_window_wider_than_a_century_is_refused_at_load() {
        assert!(!restriction("type = \"relative\"\nduration = \"P40000D\"").is_satisfiable());
        assert!(restriction("type = \"relative\"\nduration = \"P36000D\"").is_satisfiable());
    }

    #[test]
    fn an_enormous_duration_is_refused_at_load() {
        // A duration past what a timestamp can be moved by does not load, so it can never reach the
        // window arithmetic on the request path.
        assert!(toml::from_str::<TimeRestriction>("type = \"relative\"\nduration = \"PT99999999999999H\"").is_err());
    }

    #[test]
    fn a_window_reaching_past_the_representable_range_saturates() {
        // A century is far inside the range, so this only shows the arithmetic cannot fail: the
        // window ends at the edge of what a timestamp can hold rather than panicking.
        let past = restriction("type = \"relative\"\nduration = \"P36000D\"");
        let future = restriction("type = \"relative\"\nduration = \"P36000D\"\ndirection = \"future\"");

        assert_eq!(past.window(Timestamp::MIN), (Timestamp::MIN, Timestamp::MIN));
        assert_eq!(future.window(Timestamp::MAX), (Timestamp::MAX, Timestamp::MAX));
    }

    #[test]
    fn the_current_state_rule_defaults_to_what_each_window_did_before_it_could_be_named() {
        let absolute = restriction(
            r#"
            type = "absolute"
            start = 2026-01-01T00:00:00Z
            end = 2026-02-01T00:00:00Z
            "#,
        );

        assert_eq!(absolute.current_state(), CurrentState::RequestInWindow);
        assert_eq!(restriction("type = \"relative\"\nduration = \"PT24H\"").current_state(), CurrentState::Refuse);
    }

    #[test]
    fn every_current_state_rule_is_read_in_kebab_case() {
        for (written, rule) in [
            ("refuse", CurrentState::Refuse),
            ("allow", CurrentState::Allow),
            ("values-in-window", CurrentState::ValuesInWindow),
        ] {
            let relative = restriction(&format!("type = \"relative\"\nduration = \"PT24H\"\ncurrent-state = \"{written}\""));
            assert_eq!(relative.current_state(), rule, "{written}");
        }

        let absolute = restriction(
            r#"
            type = "absolute"
            start = 2026-01-01T00:00:00Z
            end = 2026-02-01T00:00:00Z
            current-state = "request-in-window"
            "#,
        );
        assert_eq!(absolute.current_state(), CurrentState::RequestInWindow);
    }

    #[test]
    fn request_in_window_on_a_relative_window_does_not_load() {
        // The request is always inside a window measured from it, so the rule would place no
        // restriction while reading as one.
        let refused = toml::from_str::<TimeRestriction>("type = \"relative\"\nduration = \"PT24H\"\ncurrent-state = \"request-in-window\"");

        assert!(refused.is_err());
        assert!(toml::from_str::<TimeRestriction>("type = \"relative\"\nduration = \"PT24H\"\ncurrent-state = \"Allow\"").is_err());
    }

    #[test]
    fn an_unknown_restriction_shape_is_refused() {
        assert!(toml::from_str::<TimeRestriction>("type = \"rolling\"\nduration = \"PT1H\"").is_err());
        assert!(toml::from_str::<TimeRestriction>("type = \"relative\"\nduration = \"PT1H\"\nwidth = 3").is_err());
    }
}
