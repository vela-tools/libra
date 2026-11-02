//! Method and path to a typed NGSI-LD operation.
//!
//! One place decides what a request addresses. Every layer that needs to know (authorization,
//! caching, enforcement, audit) reads the answer instead of matching on the path itself, so
//! there is no way for two of them to disagree about which resource a request touched.

pub mod entity_map;
pub mod error;
pub mod operation;
pub mod path;
pub mod resource;
pub mod target;
