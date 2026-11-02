//! Resolves the JSON-LD `@context` that applies to an NGSI-LD request.
//!
//! Every policy-relevant name in NGSI-LD is a term, and a term means nothing without a context.
//! This crate answers one question (which context applies to this request) and answers it the
//! same way the broker behind Libra would. Divergence between the two is directly exploitable: if
//! the proxy resolves `Vehicle` differently from the broker, a policy about vehicles is enforced
//! against something else.
//!
//! Resolution fails closed.

pub mod channel;
pub mod core_context;
pub mod core_redefinition;
pub mod error;
pub mod link_header;
pub mod loader;
pub mod resolver;
pub mod scoped;
