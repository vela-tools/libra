//! Resolves what a request asks for in Linked Entity Retrieval (NGSI-LD clause 4.5.23) once, and
//! says whether a restricted caller can be served it.
//!
//! A join is asked for in the query string, in a `Query` body, or in a subscription's notification,
//! and authorization and every enforcement layer below it need the same answer. Reading it once,
//! here, and placing [`LinkedEntityRequest`](libra_ngsi_ld_query::linked_entity::LinkedEntityRequest)
//! in the request extensions is what keeps two layers from reading one request two ways. This layer
//! refuses nothing but a selector it cannot read: whether a join can be served depends on the
//! restriction a layer below enforces, and [`servable`] is the rule each of them applies.

pub mod layer;
pub mod servable;
