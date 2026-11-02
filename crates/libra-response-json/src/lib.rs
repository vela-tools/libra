//! Reading, editing and restating a broker's JSON answer on its way back to the caller.
//!
//! Every layer that narrows a response (to the allowed scopes, the allowed attributes, the allowed
//! entity types) does the same five things around its own edit: lets an error or an empty answer
//! through, refuses a body it cannot read, parses it as what the broker says it is, writes it back,
//! and restates its length. They are done here once, so the checks that make a rewrite fail closed
//! cannot drift apart between the layers that depend on them. What a layer removes stays with the
//! layer.

pub mod error;
pub mod rewrite;
