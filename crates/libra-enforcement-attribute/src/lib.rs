//! Applying a policy's attribute restriction to a request and to the response it produces.
//!
//! Both halves are needed and neither is sufficient. Narrowing the request is what stops a caller
//! asking for what they may not see; filtering the response is what stops the broker returning it
//! anyway, because `attrs` is a hint a broker may ignore, and because "everything except these"
//! cannot be written as a request selector at all without knowing every attribute that exists.
//!
//! This crate owns its Tower layer, because rewriting a response body is HTTP-shaped work. The
//! rule it applies is not: that comes from `libra-policy-model`, and is decided by
//! `libra-policy-engine` before this ever runs.

pub mod document;
pub mod error;
pub mod filters;
#[cfg(test)]
mod fixtures;
pub mod index;
pub mod layer;
mod member;
pub mod names;
mod narrowing;
#[cfg(test)]
mod pointer;
pub mod query_body;
pub mod registration;
pub mod request;
mod route;
pub mod subscription;
