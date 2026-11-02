//! Evaluating a request against the compiled policy set.
//!
//! The engine compares IRIs against IRIs and nothing else. Every name it sees was expanded once
//! (a policy's when the policy loaded, a request's when the request arrived), so there is no
//! context here and no way for one to be applied twice.

pub mod decision;
pub mod engine;
pub mod matching;
pub mod registration_disclosure;
pub mod request;
