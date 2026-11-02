//! Entity type restrictions and their enforcement.
//!
//! An entity type is a name, and a name means whatever the request's `@context` says it means.
//! That is the whole difficulty: a policy naming `Vehicle` and a request naming `Vehicle` govern
//! the same entities only if both expand to the same IRI, and it is the caller who chooses the
//! context that decides. A proxy that compares the words is bypassed by sending the expanded IRI
//! or by aliasing the term.
//!
//! Half of that is already solved before this crate runs.
//! [`CompiledTypeRestriction`](libra_policy_model::entity_type::CompiledTypeRestriction) holds IRIs, expanded
//! against the policy's own context when the policy loaded. What is left here is the request's
//! half: [`names`] expands every name the request carries and compares IRIs, the query crate parses
//! the type selection expression (`libra_ngsi_ld_query::type_selection`) rather than splitting it on commas, [`document`] reads types out
//! of the JSON bodies that carry them, and `libra-entity-preflight` asks the broker when the request
//! names an entity but no type, which is every merge patch, every attribute write, and every delete.

pub mod document;
pub mod error;
pub mod index;
pub mod layer;
pub mod names;
pub mod registration;
pub mod request;
pub mod response;
