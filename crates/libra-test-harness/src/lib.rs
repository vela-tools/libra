#![expect(clippy::expect_used, clippy::panic, reason = "panicking is how a test harness reports a failure")]

//! The harness the integration suites run on: where the broker under test is, how the Libra binary
//! is started against it, and the identity provider the suite runs itself to sign its tokens.
//!
//! It is a crate rather than a module of one suite so that every suite runs on one copy of it. The
//! binary it starts is the one named by `CARGO_BIN_EXE_libra`, which Cargo sets for an integration
//! test of the package that builds the `libra` binary, so a suite starts the binary it was built
//! with and no image sits between the two to drift apart in.
//!
//! This crate is test support. It panics where a test would assert, because a harness that cannot
//! do what it was asked has nothing to report but a failed test.

pub mod broker;
pub mod identity;
pub mod origin;
pub mod proxy;
pub mod proxy_settings;
pub mod signing_key;
pub mod stack;
pub mod tenant_creation;
