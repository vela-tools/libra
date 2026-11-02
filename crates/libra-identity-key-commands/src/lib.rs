//! The `libra key` and `libra principal` commands.
//!
//! They write to the same key store the running proxy reads, so a key issued or revoked here is
//! accepted or refused on the proxy's next request. Whoever can run them against the store's file
//! is an administrator; there is no other credential to present.

pub mod command;
pub mod error;
mod key;
pub mod lifetime;
mod principal;
