//! NGSI-LD hierarchical scope restrictions and their enforcement.
//!
//! A scope is a path, not a name: `/Madrid/Gardens/ParqueNorte`. It is never resolved against a
//! JSON-LD context and never becomes an IRI, so, unlike an entity type or an attribute, a scope
//! is compared exactly as written. What makes it interesting is the wildcards. NGSI-LD borrows
//! MQTT 5.0 topic-filter semantics (ETSI GS CIM 009 clause 4.18), and both sides of a comparison
//! may carry them: the policy allows `/Madrid/#`, and the caller may ask for `/Madrid/+`.
//!
//! The crate is in two halves, deliberately. [`matching`] is the algorithm and knows nothing about
//! HTTP; [`layer`] is the enforcement and knows nothing about subsumption, with [`request`] holding the
//! request-side checks it applies. Between them sit
//! [`expression`], which parses the `scopeQ` grammar rather than splitting it on punctuation,
//! and [`document`], which reads scopes out of the JSON bodies that carry them. When nothing in the
//! request says what an entity's scope is, `libra-entity-preflight` asks the broker.
//!
//! The schema this enforces, [`ScopeRestriction`](libra_policy_model::scope::ScopeRestriction),
//! lives in `libra-policy-model`.

pub mod document;
pub mod error;
pub mod expression;
pub mod filtering;
pub mod layer;
pub mod matching;
pub mod registration;
pub mod request;
pub mod response;
