//! Parses a request's query string once, and keeps the parse and the URI the broker is sent in step.
//!
//! Authorization canonicalises the query, the representation layer reads `options` and `format`
//! from it, the linked-entity layer reads its joins and projections, and the enforcement layers
//! narrow it. Each parsing the query string for itself is how two layers come to disagree about one
//! request, so it is parsed here and [`QueryParameters`](libra_ngsi_ld_query::parameters::QueryParameters)
//! is read from the request extensions below. A layer that narrows the query writes it back through
//! [`parsed::replace_query`], which replaces the stored parameters and the request target together, so
//! the layer below reads exactly the query the broker will be sent.

pub mod layer;
pub mod parsed;
