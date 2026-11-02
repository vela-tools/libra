//! Forwarding an NGSI-LD request to the upstream broker.
//!
//! A small, explicit reverse proxy rather than a general one. It exists because a proxy in front of
//! an authorization decision cannot get three things wrong:
//!
//! - One HTTP client, with one connection pool, serves **every registered route**.
//! - Connection-specific headers are not forwarded.
//! - `Via` and `X-Forwarded-*` tell the broker the request has been through a proxy.
//! - The answer neither describes the broker nor addresses it: its address stays the operator's.
//!
//! What it deliberately does not do: time out. A slow broker is a decision for the layer that owns
//! the deadline, which can then answer 504 while this crate answers 502 only for a broker it could
//! not reach. Conflating the two in one place makes both untrue.

pub mod client;
pub mod error;
pub mod forwarded;
pub mod hop_by_hop;
pub mod layer;
pub(crate) mod query;
pub mod response_headers;
pub mod settings;
pub mod upstream_base;
