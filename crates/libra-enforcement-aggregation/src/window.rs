//! Holding an aggregated read's window to the grid of its policy's minimum period.
//!
//! A minimum period stops one bucket from being finer than the policy allows, and says nothing about
//! where buckets start. Two windows shifted against each other by less than a period give buckets
//! that partially overlap, and the difference of two of them is the readings in the part where they
//! differ. With every boundary on the grid the policy's period lays from the Unix epoch, two buckets
//! are either the same bucket or disjoint.
//!
//! The rule is a pure function of the grid and the window as written. Where the window is written,
//! and what is done with a window that misses the grid, belong to the layer.

use crate::error::AggregationError;
use jiff::Timestamp;
use libra_ngsi_ld_query::temporal_selector::{TemporalSelector, TimeRelation};
use libra_policy_model::{aggregation_grid::AggregationGrid, duration::IsoDuration};
use std::str::FromStr;

/// What closes a window an aggregated read leaves open at one end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenEnds {
    /// The decision carries a time restriction, whose enforcement below closes every window at the
    /// policy's bounds and rounds them inward to the grid.
    ClosedBelow,
    /// Nothing does, so an open end is refused.
    Refused,
}

/// What the grid makes of one window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowCheck {
    /// Every boundary written is a grid point, and a closed window spans at least one period.
    OnGrid,
    /// The window misses the grid, and these are the boundaries it would have when moved out to the
    /// enclosing grid points.
    Raise {
        /// Why the window as written does not satisfy the grid.
        shortfall: WindowShortfall,
        /// The `timeAt` to write.
        time_at: Timestamp,
        /// The `endTimeAt` to write, for a `between` window.
        end_time_at: Option<Timestamp>,
    },
}

/// Why a window did not satisfy the grid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowShortfall {
    /// A boundary is not a grid point.
    OffGrid,
    /// Both boundaries are grid points and the window spans less than one period.
    TooShort,
}

impl WindowShortfall {
    /// The refusal this shortfall becomes when the window is not raised.
    #[must_use]
    pub const fn refusal(self, minimum: IsoDuration) -> AggregationError {
        match self {
            Self::OffGrid => AggregationError::WindowOffGrid { minimum },
            Self::TooShort => AggregationError::WindowTooShort { minimum },
        }
    }
}

/// Checks one window an aggregated read names against the grid of its minimum period.
///
/// A `before` or `after` window, or one that names no relation at all, has an end that moves with
/// the moment of the request; it is allowed only when something below closes it.
///
/// # Errors
///
/// Returns [`AggregationError::OpenWindow`] for an open end nothing closes, and
/// [`AggregationError::MalformedWindow`] for a relation, a bound or a moved bound that cannot be read
/// or represented.
pub fn check_window(grid: AggregationGrid, selector: TemporalSelector<'_>, open_ends: OpenEnds) -> Result<WindowCheck, AggregationError> {
    let Some(written) = selector.timerel else {
        return open(open_ends).map(|()| WindowCheck::OnGrid);
    };

    let relation = TimeRelation::from_str(written).map_err(|_| malformed("timerel is not before, after or between"))?;
    let time_at = instant(selector.time_at)?.ok_or(malformed("timeAt is required by timerel"))?;

    match relation {
        TimeRelation::Between => {
            let end_time_at = instant(selector.end_time_at)?.ok_or(malformed("endTimeAt is required when timerel is between"))?;

            between(grid, time_at, end_time_at)
        }
        TimeRelation::Before => {
            open(open_ends)?;
            one_bound(time_at, grid.ceil(time_at))
        }
        TimeRelation::After => {
            open(open_ends)?;
            one_bound(time_at, grid.floor(time_at))
        }
    }
}

/// What the grid makes of every window one aggregated read names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowChecks {
    /// The window in the query string.
    pub query: WindowCheck,
    /// The window in the `temporalQ` of a `Query` body.
    pub body: WindowCheck,
}

impl WindowChecks {
    /// Why the first window that misses the grid misses it, if one does.
    #[must_use]
    pub const fn shortfall(&self) -> Option<WindowShortfall> {
        match (self.query, self.body) {
            (WindowCheck::Raise { shortfall, .. }, _) | (WindowCheck::OnGrid, WindowCheck::Raise { shortfall, .. }) => Some(shortfall),
            (WindowCheck::OnGrid, WindowCheck::OnGrid) => None,
        }
    }
}

/// Checks every window an aggregated read names, wherever it names one.
///
/// `body` is `None` for a read without a `Query` body, and `Some(None)` for a body without a
/// `temporalQ`. A query string that bounds nothing beside a body is not a window of its own: the
/// body's is the one the read names. A read that bounds nothing anywhere names an open window.
///
/// # Errors
///
/// Returns what [`check_window`] returns for the first window that cannot stand.
pub fn check_windows(
    grid: AggregationGrid,
    query: TemporalSelector<'_>,
    body: Option<Option<TemporalSelector<'_>>>,
    open_ends: OpenEnds,
) -> Result<WindowChecks, AggregationError> {
    let query_bounds = query.bounds_anything();

    let query = if query_bounds || body.is_none() {
        check_window(grid, query, open_ends)?
    } else {
        WindowCheck::OnGrid
    };

    let body = match body {
        Some(Some(temporal)) => check_window(grid, temporal, open_ends)?,
        Some(None) if !query_bounds => check_window(grid, TemporalSelector::default(), open_ends)?,
        Some(None) | None => WindowCheck::OnGrid,
    };

    Ok(WindowChecks { query, body })
}

/// A `between` window: both boundaries on the grid and at least one period apart.
fn between(grid: AggregationGrid, start: Timestamp, end: Timestamp) -> Result<WindowCheck, AggregationError> {
    let shortfall = if !grid.is_on(start) || !grid.is_on(end) {
        WindowShortfall::OffGrid
    } else if grid.spans_a_period(start, end) {
        return Ok(WindowCheck::OnGrid);
    } else {
        WindowShortfall::TooShort
    };

    let (time_at, end_time_at) = grid.outward(start, end).ok_or(malformed("the window cannot be moved to the grid"))?;

    Ok(WindowCheck::Raise {
        shortfall,
        time_at,
        end_time_at: Some(end_time_at),
    })
}

/// A window with one written boundary, which `moved` would put on the grid.
fn one_bound(written: Timestamp, moved: Option<Timestamp>) -> Result<WindowCheck, AggregationError> {
    let moved = moved.ok_or(malformed("the window cannot be moved to the grid"))?;

    if moved == written {
        return Ok(WindowCheck::OnGrid);
    }

    Ok(WindowCheck::Raise {
        shortfall: WindowShortfall::OffGrid,
        time_at: moved,
        end_time_at: None,
    })
}

/// Whether an open end may stand.
const fn open(open_ends: OpenEnds) -> Result<(), AggregationError> {
    match open_ends {
        OpenEnds::ClosedBelow => Ok(()),
        OpenEnds::Refused => Err(AggregationError::OpenWindow),
    }
}

/// Reads one written bound.
fn instant(written: Option<&str>) -> Result<Option<Timestamp>, AggregationError> {
    written
        .map(|value| {
            value
                .parse::<Timestamp>()
                .map_err(|_| malformed("timeAt or endTimeAt is not an RFC 3339 timestamp"))
        })
        .transpose()
}

/// The refusal of a window that cannot be read.
const fn malformed(reason: &'static str) -> AggregationError {
    AggregationError::MalformedWindow { reason }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn hourly() -> AggregationGrid {
        AggregationGrid::new(&IsoDuration::parse("PT1H").unwrap())
    }

    fn at(text: &str) -> Timestamp {
        text.parse().unwrap()
    }

    fn selector<'a>(timerel: Option<&'a str>, time_at: Option<&'a str>, end_time_at: Option<&'a str>) -> TemporalSelector<'a> {
        TemporalSelector {
            timerel,
            time_at,
            end_time_at,
            timeproperty: None,
        }
    }

    #[test]
    fn a_between_window_on_the_grid_spanning_a_period_is_on_the_grid() {
        assert_eq!(
            check_window(
                hourly(),
                selector(Some("between"), Some("2026-03-01T10:00:00Z"), Some("2026-03-01T12:00:00Z")),
                OpenEnds::Refused
            ),
            Ok(WindowCheck::OnGrid)
        );
    }

    #[test]
    fn a_between_window_off_the_grid_is_moved_out_to_the_enclosing_grid_points() {
        assert_eq!(
            check_window(
                hourly(),
                selector(Some("between"), Some("2026-03-01T10:20:00Z"), Some("2026-03-01T12:10:00Z")),
                OpenEnds::Refused
            ),
            Ok(WindowCheck::Raise {
                shortfall: WindowShortfall::OffGrid,
                time_at: at("2026-03-01T10:00:00Z"),
                end_time_at: Some(at("2026-03-01T13:00:00Z")),
            })
        );
    }

    #[test]
    fn a_window_on_the_grid_shorter_than_a_period_is_too_short() {
        assert_eq!(
            check_window(
                hourly(),
                selector(Some("between"), Some("2026-03-01T10:00:00Z"), Some("2026-03-01T10:00:00Z")),
                OpenEnds::Refused
            ),
            Ok(WindowCheck::Raise {
                shortfall: WindowShortfall::TooShort,
                time_at: at("2026-03-01T10:00:00Z"),
                end_time_at: Some(at("2026-03-01T11:00:00Z")),
            })
        );
    }

    #[test]
    fn an_open_window_is_refused_unless_a_time_restriction_closes_it() {
        for open in [
            selector(None, None, None),
            selector(Some("after"), Some("2026-03-01T10:00:00Z"), None),
            selector(Some("before"), Some("2026-03-01T10:00:00Z"), None),
        ] {
            assert_eq!(check_window(hourly(), open, OpenEnds::Refused), Err(AggregationError::OpenWindow), "{open:?}");
            assert_eq!(check_window(hourly(), open, OpenEnds::ClosedBelow), Ok(WindowCheck::OnGrid), "{open:?}");
        }
    }

    #[test]
    fn the_written_bound_of_an_open_window_still_sits_on_the_grid() {
        assert_eq!(
            check_window(hourly(), selector(Some("after"), Some("2026-03-01T10:20:00Z"), None), OpenEnds::ClosedBelow),
            Ok(WindowCheck::Raise {
                shortfall: WindowShortfall::OffGrid,
                time_at: at("2026-03-01T10:00:00Z"),
                end_time_at: None,
            })
        );
        assert_eq!(
            check_window(hourly(), selector(Some("before"), Some("2026-03-01T10:20:00Z"), None), OpenEnds::ClosedBelow),
            Ok(WindowCheck::Raise {
                shortfall: WindowShortfall::OffGrid,
                time_at: at("2026-03-01T11:00:00Z"),
                end_time_at: None,
            })
        );
    }

    #[test]
    fn a_window_that_cannot_be_read_is_malformed() {
        for unreadable in [
            selector(Some("sometime"), Some("2026-03-01T10:00:00Z"), None),
            selector(Some("between"), Some("yesterday"), Some("2026-03-01T10:00:00Z")),
            selector(Some("between"), Some("2026-03-01T10:00:00Z"), None),
            selector(Some("after"), None, None),
        ] {
            assert!(
                matches!(
                    check_window(hourly(), unreadable, OpenEnds::Refused),
                    Err(AggregationError::MalformedWindow { .. })
                ),
                "{unreadable:?}"
            );
        }
    }

    #[test]
    fn a_body_window_is_the_one_a_batch_query_names_when_its_query_string_bounds_nothing() {
        let off = selector(Some("between"), Some("2026-03-01T10:20:00Z"), Some("2026-03-01T12:00:00Z"));
        let checks = check_windows(hourly(), TemporalSelector::default(), Some(Some(off)), OpenEnds::Refused).unwrap();

        assert_eq!(checks.query, WindowCheck::OnGrid);
        assert_eq!(checks.shortfall(), Some(WindowShortfall::OffGrid));
    }

    #[test]
    fn a_read_that_bounds_nothing_anywhere_names_an_open_window() {
        assert_eq!(
            check_windows(hourly(), TemporalSelector::default(), Some(None), OpenEnds::Refused),
            Err(AggregationError::OpenWindow)
        );
        assert_eq!(
            check_windows(hourly(), TemporalSelector::default(), None, OpenEnds::Refused),
            Err(AggregationError::OpenWindow)
        );
    }

    #[test]
    fn every_window_named_has_to_sit_on_the_grid() {
        let on = selector(Some("between"), Some("2026-03-01T10:00:00Z"), Some("2026-03-01T12:00:00Z"));
        let off = selector(Some("between"), Some("2026-03-01T10:20:00Z"), Some("2026-03-01T12:00:00Z"));

        assert_eq!(
            check_windows(hourly(), on, Some(Some(off)), OpenEnds::Refused).map(|checks| checks.shortfall()),
            Ok(Some(WindowShortfall::OffGrid))
        );
        assert_eq!(
            check_windows(hourly(), on, Some(Some(on)), OpenEnds::Refused).map(|checks| checks.shortfall()),
            Ok(None)
        );
    }

    #[test]
    fn a_shortfall_becomes_its_own_refusal() {
        let minimum = IsoDuration::parse("PT1H").unwrap();

        assert!(matches!(
            WindowShortfall::OffGrid.refusal(minimum.clone()),
            AggregationError::WindowOffGrid { .. }
        ));
        assert!(matches!(WindowShortfall::TooShort.refusal(minimum), AggregationError::WindowTooShort { .. }));
    }

    #[test]
    fn a_body_without_a_temporal_query_reads_the_window_its_query_string_bounds() {
        let on = selector(Some("between"), Some("2026-03-01T10:00:00Z"), Some("2026-03-01T12:00:00Z"));

        assert_eq!(
            check_windows(hourly(), on, Some(None), OpenEnds::Refused),
            Ok(WindowChecks {
                query: WindowCheck::OnGrid,
                body: WindowCheck::OnGrid,
            })
        );
    }
}
