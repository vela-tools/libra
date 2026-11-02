//! The documents the NGSI-LD type and attribute metadata index answers with.
//!
//! `/types`, `/types/{type}`, `/attributes` and `/attributes/{attr}` (NGSI-LD 5.7.5 to 5.7.10)
//! answer with five document shapes (5.2.24 to 5.2.28), each named by its `type` member. Every layer
//! that narrows the index to a restriction reads the same shapes and edits the same name lists, so both
//! live here once. What a restriction allows stays with the layer that enforces it.
//!
//! A document that is not one of the five shapes is not something a layer can show it has
//! narrowed, so recognising a shape is the first step of every narrowing, not an afterthought.

pub mod index_member;
pub mod index_type;
pub mod name_list;
pub mod repeated_member;
