//! Holding a temporal read to the aggregation its policy requires.
//!
//! The privacy control is "you may see trends, not readings". It holds only if three things are
//! true at once: the read aggregates when the policy says it must, the method it aggregates with is
//! one the policy lists, and the period is coarse enough that individual readings do not stand out
//! of the buckets. Any one of them missing gives back the raw data by another route.
//!
//! A minimum period also lays a grid every aggregated window has to sit on, so that shifted windows
//! cannot be differenced into single readings.
//!
//! The rules live in [`enforce()`](enforce::enforce) and [`check_window`](window::check_window),
//! which are pure functions of the restriction and what the caller asked for. Finding the
//! parameters in a query string or in a `Query` body, raising what the deployment raises, and
//! deciding which resources return entity values at all live in [`layer`], [`query_body`],
//! [`raise`] and [`raw_values`].

pub mod enforce;
pub mod error;
pub mod layer;
pub mod query_body;
pub mod raise;
pub mod raw_values;
pub mod window;
