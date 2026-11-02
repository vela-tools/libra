//! The NGSI-LD query parameter model.
//!
//! A query is parsed once, into a form where the parameters that carry names are separated from
//! the ones that do not. Everything that compares a query (a policy condition, an attribute
//! restriction, a cache key) works from that form, so no two of them can disagree about what the
//! caller asked for. A `Query` body and a subscription's notification parameters carry the same
//! selectors as members, and are read by the same parsers.

pub mod aggregation;
pub mod attribute_path;
pub mod canonical;
mod control_character;
mod cursor;
pub mod entity_member;
pub mod error;
mod expansion;
pub mod filter;
pub mod key_path;
pub mod linked_entity;
pub mod ordering;
pub mod parameter_name;
pub mod parameters;
mod parser;
pub mod projection;
pub mod query_attribute;
pub mod selector;
pub mod temporal_selector;
pub mod type_selection;
