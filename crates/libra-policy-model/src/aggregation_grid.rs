//! The grid an aggregation minimum period lays over time.
//!
//! A minimum period alone does not keep single readings out of reach. Two aggregated reads whose
//! windows are shifted against each other by less than one period produce buckets that partially
//! overlap, and differencing two overlapping buckets isolates the readings in the part where they
//! differ. Fixing every bucket boundary to one grid closes that: buckets are then either the same
//! bucket or disjoint, and no difference of two of them is finer than the grid.
//!
//! The grid is the period counted from the Unix epoch in UTC. That needs a period of a fixed number
//! of seconds, which [`IsoDuration`] already is: years and months do not parse, so a minimum period
//! in calendar units fails to load rather than laying a grid whose spacing changes with the month.

use crate::duration::IsoDuration;
use jiff::Timestamp;
use std::num::NonZeroU64;

/// Nanoseconds in one second, as the timestamp arithmetic counts them.
const NANOSECONDS_PER_SECOND: i128 = 1_000_000_000;

/// The instants a minimum aggregation period allows a window boundary to sit on: every whole
/// multiple of the period since the Unix epoch, in UTC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AggregationGrid {
    period: NonZeroU64,
}

impl AggregationGrid {
    /// The grid of a minimum period.
    #[must_use]
    pub const fn new(period: &IsoDuration) -> AggregationGrid {
        AggregationGrid {
            period: period.as_nonzero_secs(),
        }
    }

    /// The spacing of the grid, in seconds.
    #[must_use]
    pub const fn period_seconds(self) -> u64 {
        self.period.get()
    }

    /// Whether `instant` is a grid point.
    #[must_use]
    pub fn is_on(self, instant: Timestamp) -> bool {
        instant.as_nanosecond().rem_euclid(self.spacing()) == 0
    }

    /// Whether `seconds` is a whole number of grid periods, so that buckets of that length laid from
    /// a grid point end on grid points too.
    #[must_use]
    pub const fn divides(self, seconds: u64) -> bool {
        seconds.is_multiple_of(self.period.get())
    }

    /// The last grid point at or before `instant`, or `None` past the representable range.
    #[must_use]
    pub fn floor(self, instant: Timestamp) -> Option<Timestamp> {
        let nanoseconds = instant.as_nanosecond();

        grid_point(nanoseconds - nanoseconds.rem_euclid(self.spacing()))
    }

    /// The first grid point at or after `instant`, or `None` past the representable range.
    #[must_use]
    pub fn ceil(self, instant: Timestamp) -> Option<Timestamp> {
        let nanoseconds = instant.as_nanosecond();
        let past = nanoseconds.rem_euclid(self.spacing());

        if past == 0 {
            return Some(instant);
        }

        grid_point(nanoseconds - past + self.spacing())
    }

    /// Whether the closed window from `start` to `end` spans at least one whole period.
    #[must_use]
    pub fn spans_a_period(self, start: Timestamp, end: Timestamp) -> bool {
        end.as_nanosecond() - start.as_nanosecond() >= self.spacing()
    }

    /// The smallest window on the grid that holds `start` to `end` and spans at least one period:
    /// the start moved back and the end moved forward to grid points, and the end moved one period
    /// further when the two meet.
    ///
    /// `None` when a moved boundary falls past the representable range.
    #[must_use]
    pub fn outward(self, start: Timestamp, end: Timestamp) -> Option<(Timestamp, Timestamp)> {
        let start = self.floor(start)?;
        let end = self.ceil(end)?;

        if self.spans_a_period(start, end) {
            return Some((start, end));
        }

        Some((start, grid_point(start.as_nanosecond() + self.spacing())?))
    }

    /// The largest window on the grid inside `start` to `end`: the start moved forward and the end
    /// moved back to grid points.
    ///
    /// `None` when what is left spans less than one period, so no whole bucket fits inside.
    #[must_use]
    pub fn inward(self, start: Timestamp, end: Timestamp) -> Option<(Timestamp, Timestamp)> {
        let start = self.ceil(start)?;
        let end = self.floor(end)?;

        self.spans_a_period(start, end).then_some((start, end))
    }

    /// The period in nanoseconds, the unit the timestamp arithmetic is done in.
    fn spacing(self) -> i128 {
        i128::from(self.period.get()) * NANOSECONDS_PER_SECOND
    }
}

/// The instant `nanoseconds` after the epoch, which is a whole second because every grid point is,
/// or `None` past the representable range.
fn grid_point(nanoseconds: i128) -> Option<Timestamp> {
    let seconds = i64::try_from(nanoseconds / NANOSECONDS_PER_SECOND).ok()?;

    Timestamp::from_second(seconds).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn at(text: &str) -> Timestamp {
        text.parse().unwrap()
    }

    fn grid(period: &str) -> AggregationGrid {
        AggregationGrid::new(&IsoDuration::parse(period).unwrap())
    }

    #[test]
    fn grid_points_are_whole_periods_since_the_epoch_in_utc() {
        let hourly = grid("PT1H");

        assert!(hourly.is_on(at("2026-03-01T10:00:00Z")));
        assert!(hourly.is_on(at("1969-12-31T23:00:00Z")), "before the epoch too");
        assert!(!hourly.is_on(at("2026-03-01T10:30:00Z")));
        assert!(!hourly.is_on(at("2026-03-01T10:00:00.001Z")), "a millisecond off is off the grid");
        // A UTC offset of half an hour moves the instant off the hour.
        assert!(!hourly.is_on(at("2026-03-01T10:00:00+00:30")));
    }

    #[test]
    fn a_daily_grid_counts_days_of_24_hours_from_the_epoch() {
        let daily = grid("P1D");

        assert!(daily.is_on(at("2026-03-01T00:00:00Z")));
        assert!(!daily.is_on(at("2026-03-01T00:00:00+01:00")));
    }

    #[test]
    fn floor_and_ceil_move_to_the_enclosing_grid_points() {
        let hourly = grid("PT1H");

        assert_eq!(hourly.floor(at("2026-03-01T10:20:00Z")), Some(at("2026-03-01T10:00:00Z")));
        assert_eq!(hourly.ceil(at("2026-03-01T10:20:00Z")), Some(at("2026-03-01T11:00:00Z")));
        assert_eq!(hourly.floor(at("1969-12-31T23:20:00Z")), Some(at("1969-12-31T23:00:00Z")));
        assert_eq!(hourly.ceil(at("2026-03-01T10:00:00Z")), Some(at("2026-03-01T10:00:00Z")));
    }

    #[test]
    fn outward_encloses_the_window_and_spans_at_least_one_period() {
        let hourly = grid("PT1H");

        assert_eq!(
            hourly.outward(at("2026-03-01T10:20:00Z"), at("2026-03-01T12:10:00Z")),
            Some((at("2026-03-01T10:00:00Z"), at("2026-03-01T13:00:00Z")))
        );
        assert_eq!(
            hourly.outward(at("2026-03-01T10:00:00Z"), at("2026-03-01T10:00:00Z")),
            Some((at("2026-03-01T10:00:00Z"), at("2026-03-01T11:00:00Z")))
        );
    }

    #[test]
    fn inward_keeps_only_whole_periods_inside_the_window() {
        let hourly = grid("PT1H");

        assert_eq!(
            hourly.inward(at("2026-03-01T10:20:00Z"), at("2026-03-01T12:10:00Z")),
            Some((at("2026-03-01T11:00:00Z"), at("2026-03-01T12:00:00Z")))
        );
        assert_eq!(hourly.inward(at("2026-03-01T10:20:00Z"), at("2026-03-01T11:10:00Z")), None);
    }

    #[test]
    fn a_length_divides_the_grid_only_in_whole_periods() {
        let hourly = grid("PT1H");

        assert!(hourly.divides(7200));
        assert!(!hourly.divides(5400));
    }

    #[test]
    fn the_ends_of_the_representable_range_do_not_wrap() {
        let weekly = grid("P1W");

        assert_eq!(weekly.floor(Timestamp::MIN), None);
        assert_eq!(weekly.ceil(Timestamp::MAX), None);
    }
}
