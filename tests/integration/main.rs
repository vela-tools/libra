#![expect(clippy::expect_used, clippy::panic, reason = "panicking is how a test harness reports a failure")]

//! Libra end to end: the binary cargo just built, a real context broker, and signed tokens.
//!
//! Every crate here has its own tests and they all pass in isolation. What they cannot show is that
//! the assembled thing enforces what the policy file says: that a signed token's roles are the
//! roles a policy really matches, that a context the broker really applied is the one
//! the policy was compiled against, and that the layers run in an order where the cache cannot
//! answer for the authorizer. So this suite runs the real binary and asserts on what a client and a
//! broker can actually see.
//!
//! The proxy is not run in a container on purpose: it is spawned from the binary cargo just built,
//! with no image in between for the binary and its tests to drift apart in.

#[macro_use]
extern crate libra_test_harness;

mod aggregation_restriction;
mod api_keys;
mod attribute_restriction;
mod authentication;
mod authorization;
mod batch_operations;
mod broker_faults;
mod context_channels;
mod csource_registration;
mod entity_type_restriction;
mod identity_propagation;
mod jwks_rotation;
mod leak_probes;
mod leak_surfaces;
mod narrowing;
mod parameter_smuggling;
mod parity;
mod probes;
mod representation;
mod representation_abuse;
mod request_shape;
mod resource_families;
mod restriction_bypasses;
mod temporal_enforcement;
mod tenant_isolation;
mod term_expansion;
mod unclaimed;
mod write_enforcement;

mod scope_restriction;
mod time_restriction;
