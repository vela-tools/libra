//! Walking the entities of an NGSI-LD response document, linked entities included.
//!
//! A response holds its entities in one of several places (an array, a single object, the
//! `properties` of a `GeoJSON` Feature, the `features` of a `FeatureCollection`) and, under Linked
//! Entity Retrieval (NGSI-LD clause 4.5.23), inside the Relationships of other entities or appended
//! after them. Every layer that edits a response has to find the same entities in the same places,
//! so finding them lives here once, free of HTTP and of any policy: what a layer does to an entity
//! it is handed stays with the layer.

pub mod entities;
pub mod geojson;
pub mod linked;
pub mod unwalkable;
