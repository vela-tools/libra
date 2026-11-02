//! The store of principals, API key verifiers and the instance lease.
//!
//! An SQLite database in WAL mode, which the running proxy reads on every request carrying a key
//! and the command line writes to while it runs, so issuing or revoking a key takes effect on the
//! next request with nothing reloaded. Whoever can open the database file is an administrator: the
//! trust boundary is filesystem access, as it is for the policy files.
//!
//! The store holds no secret. A key is stored as its verifier, and a principal is a name with the
//! groups and roles a policy matches.

pub mod error;
pub mod key;
pub mod lease;
pub mod principal;
pub mod store;
#[cfg(test)]
mod test_store;
mod timestamp;
