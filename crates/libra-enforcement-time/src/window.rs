//! An interval of instants.

use jiff::Timestamp;
use libra_ngsi_ld_query::temporal_selector::render_instant;

/// A closed interval of instants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Window {
    start: Timestamp,
    end: Timestamp,
}

impl Window {
    /// An interval running from `start` to `end`, both included.
    #[must_use]
    pub const fn new(start: Timestamp, end: Timestamp) -> Self {
        Self { start, end }
    }

    /// The interval that excludes nothing.
    ///
    /// What a caller asked for when they named no relation at all: every instant the broker
    /// holds. It is never the answer to a narrowing, because intersecting it with a policy's window
    /// gives that policy's own bounds.
    #[must_use]
    pub const fn unbounded() -> Self {
        Self {
            start: Timestamp::MIN,
            end: Timestamp::MAX,
        }
    }

    /// The first instant in the interval.
    #[must_use]
    pub const fn start(self) -> Timestamp {
        self.start
    }

    /// The last instant in the interval.
    #[must_use]
    pub const fn end(self) -> Timestamp {
        self.end
    }

    /// Whether `instant` falls inside the interval.
    #[must_use]
    pub fn contains(self, instant: Timestamp) -> bool {
        self.start <= instant && instant <= self.end
    }

    /// Whether the interval ends before it begins, and so contains nothing.
    #[must_use]
    pub fn is_backwards(self) -> bool {
        self.start > self.end
    }

    /// The overlap of two intervals, or `None` when they do not meet.
    #[must_use]
    pub fn intersect(self, other: Self) -> Option<Self> {
        let start = self.start.max(other.start);
        let end = self.end.min(other.end);

        (start <= end).then_some(Self { start, end })
    }

    /// The start, written the way a `timeAt` is written.
    #[must_use]
    pub fn start_text(self) -> String {
        render_instant(self.start)
    }

    /// The end, written the way an `endTimeAt` is written.
    #[must_use]
    pub fn end_text(self) -> String {
        render_instant(self.end)
    }
}

impl From<(Timestamp, Timestamp)> for Window {
    fn from((start, end): (Timestamp, Timestamp)) -> Self {
        Self { start, end }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn at(text: &str) -> Timestamp {
        text.parse().unwrap()
    }

    #[test]
    fn two_windows_that_overlap_intersect_to_the_overlap() {
        let first = Window::new(at("2026-01-01T00:00:00Z"), at("2026-03-01T00:00:00Z"));
        let second = Window::new(at("2026-02-01T00:00:00Z"), at("2026-04-01T00:00:00Z"));

        assert_eq!(
            first.intersect(second),
            Some(Window::new(at("2026-02-01T00:00:00Z"), at("2026-03-01T00:00:00Z")))
        );
    }

    #[test]
    fn two_windows_that_do_not_meet_have_no_intersection() {
        let first = Window::new(at("2026-01-01T00:00:00Z"), at("2026-02-01T00:00:00Z"));
        let second = Window::new(at("2026-03-01T00:00:00Z"), at("2026-04-01T00:00:00Z"));

        assert_eq!(first.intersect(second), None);
    }

    #[test]
    fn windows_that_touch_at_one_instant_still_meet() {
        // The bounds are inclusive, so a single shared instant is a window, not an empty one.
        let instant = at("2026-02-01T00:00:00Z");
        let first = Window::new(at("2026-01-01T00:00:00Z"), instant);
        let second = Window::new(instant, at("2026-03-01T00:00:00Z"));

        assert_eq!(first.intersect(second), Some(Window::new(instant, instant)));
    }

    #[test]
    fn an_unbounded_window_narrows_to_whatever_it_meets() {
        let allowed = Window::new(at("2026-01-01T00:00:00Z"), at("2026-02-01T00:00:00Z"));

        assert_eq!(Window::unbounded().intersect(allowed), Some(allowed));
    }

    #[test]
    fn a_bound_is_rendered_the_way_ngsi_ld_writes_one() {
        let window = Window::new(at("2026-01-01T00:00:00Z"), at("2026-02-01T12:30:45.123Z"));

        assert_eq!(window.start_text(), "2026-01-01T00:00:00.000Z");
        assert_eq!(window.end_text(), "2026-02-01T12:30:45.123Z");
    }

    #[test]
    fn a_window_of_one_instant_is_not_backwards_and_one_ending_before_it_starts_is() {
        let instant = at("2026-02-01T00:00:00Z");

        assert!(!Window::new(instant, instant).is_backwards());
        assert!(Window::new(instant, at("2026-01-31T23:59:59Z")).is_backwards());
    }
}
