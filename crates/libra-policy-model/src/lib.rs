//! The authorization policy schema.
//!
//! Policies are authored in terms and compared as IRIs. This crate holds both forms: the authored
//! one, which a policy file deserializes into, and the compiled one, which is what an evaluation
//! ever sees. The two are separate types, so there is no way to reach a comparison without having
//! gone through expansion first.
//!
//! Every restriction is defined here: scope, entity type, time, attribute and aggregation. A policy
//! that carries any other key is refused at load, because a restriction that is silently dropped
//! has turned a policy into an unrestricted allow.

pub mod access;
pub mod aggregation;
pub mod aggregation_grid;
pub mod attribute;
pub mod condition;
pub mod datetime;
pub mod duration;
pub mod effect;
pub mod entity_type;
pub mod error;
pub mod identity;
pub mod member_on_write;
pub mod operation;
pub mod policy;
pub mod principal_id;
pub mod query;
pub mod resource_family;
pub mod scope;
pub mod time;
pub mod time_zone;
