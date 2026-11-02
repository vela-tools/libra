//! The NGSI-LD response representation model, from ETSI GS CIM 009 clauses 4.5 and 6.3.
//!
//! Two independent questions decide what a response looks like, and this crate answers both from
//! the request alone: which *shape* entities take (normalized, concise, or simplified) and which
//! *media type* the body is written in. They are independent because a simplified entity can be
//! serialised as JSON, JSON-LD or `GeoJSON` (`application/geo+json`), and because the media type alone decides where the
//! JSON-LD context lives.
//!
//! Both answers are refusals when the request is ambiguous. A request naming two representations
//! is not resolved by picking one: brokers resolve `options=keyValues,concise` differently from
//! each other, so a proxy that picked would end up reasoning about a response the broker never
//! sent. That is the rule the rest of Libra follows: never guess at a reading the next hop might
//! not share.
//!
//! This crate is a pure model. It holds no Tower layer and touches no request: the crates that
//! rewrite bodies and headers consume it.

pub mod accept;
pub mod error;
pub mod representation;
pub mod selection;
