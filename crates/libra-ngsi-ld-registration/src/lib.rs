//! The document an NGSI-LD context source registration is written in.
//!
//! A `CSourceRegistration` (NGSI-LD 5.2.9) says which entities and attributes a context source
//! provides: its `information` member is a list of `RegistrationInfo` objects (5.2.10), each naming
//! entity selectors (`EntityInfo`, 5.2.8), property names and relationship names. Every layer that
//! enforces a restriction on registrations reads the same shape, so it is read here once. What a
//! restriction allows stays with the layer that enforces it.
//!
//! What cannot be read as a registration is reported rather than passed over: a registration
//! nobody could read is one nobody could show was allowed.

pub mod attribute_names;
pub mod coverage;
pub mod error;
pub mod registration;
pub mod source_info;
