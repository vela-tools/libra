//! Loading, compiling and holding the authorization policy set.
//!
//! Everything that can be decided once is decided here: terms are expanded against the context the
//! policy file declares, durations and time zones are parsed, and the restrictions each policy
//! needs are checked against what the running build says it can enforce. A policy that fails any
//! of those stops the process rather than joining a set that is quietly weaker than it reads.

pub mod error;
pub mod snapshot;
pub mod store;
