//! Asking the broker what an entity or a context source registration is, before deciding whether a
//! request about it may proceed.
//!
//! A request that names one entity carries neither its type nor its scope anywhere Libra can see
//! it: not in the path, not in the query, and, for an attribute write, a merge patch or a delete,
//! not in the body either. The only way to enforce a type or scope restriction on such a request is
//! to fetch the entity first. That is one extra round trip per by-id request, and it is the price
//! of the restriction being enforced at all rather than only where it happened to be easy.
//!
//! Three rules follow:
//!
//! * One client for the layer's lifetime, so connection reuse and the pool actually apply, instead of
//!   a fresh `reqwest::Client` per pre-flight discarding the pool every time.
//! * The entity is fetched as an entity. `?attrs=scope` asks for an attribute called `scope`, and
//!   `?attrs=type&type=*` is not a request NGSI-LD defines: `scope` and `type` are system members
//!   rather than attributes, and brokers that take the selector literally answer without them.
//! * Anything but a usable entity document is an error, and the layers turn every error into a
//!   refusal. A pre-flight that failed, timed out or answered with something unusable is never
//!   treated as permission.

pub mod batch;
pub mod batch_delete;
pub mod batch_write;
pub mod error;
pub mod preflight;
