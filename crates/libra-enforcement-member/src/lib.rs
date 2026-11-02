//! Enforcement of a restriction on one entity member, scope or type: the steps both share.
//!
//! A scope restriction and an entity type restriction each judge an entity by one of its members,
//! and most of what they do around that judgement is the same: they refuse the same routes no
//! narrowing reaches, pre-flight a batch the same way, take one spelling of their query parameter,
//! decide alike when a join answer is judged, and refuse an answer they cannot filter for the same
//! reasons. Those steps live here once. What differs, the member itself and how one entity is
//! judged by it, stays with each restriction.

pub mod batch;
pub mod linked_join;
pub mod location;
pub mod query_parameter;
pub mod unfilterable;
pub mod unnarrowable;
