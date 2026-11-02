//! Holding a request to the window of instants its policy allows.
//!
//! A temporal query names a window; a policy names another. The interesting operation is the
//! intersection, and the interesting failure is what happens when it is empty: the request is
//! refused rather than served from a window nobody asked for.
//!
//! The rule itself lives in [`narrow_window`](narrowing::narrow_window), which is a pure function of the request, the restriction
//! and the clock. Everything HTTP-shaped (finding the bounds in a query string or in a
//! `temporalQ`, putting the narrowed ones back, refusing what cannot be narrowed) lives in
//! [`layer`].
//!
//! A current-state read names no window. What the restriction makes of one is its `current-state`
//! rule; under `values-in-window` the answer is held to the window instead of the request, by
//! [`current_state`] on the documents and [`values_in_window`] around them.

pub mod current_state;
pub mod error;
pub mod layer;
mod membership;
pub mod narrowing;
mod temporal_query;
pub mod values_in_window;
pub mod window;
