//! Telling the two `GeoJSON` documents NGSI-LD answers with apart (clause 6.3.15).
//!
//! Asked only of a body the broker labelled `application/geo+json`. `type` and `properties` are
//! ordinary things for an NGSI-LD entity to carry: an entity whose type is literally `Feature`, with
//! an attribute named `properties`, is indistinguishable from a `GeoJSON` Feature by shape alone, so
//! the media type decides whether the question is asked at all.

use crate::unwalkable::{Unwalkable, repeated};
use jstrict::{Value, object::Object};

/// The member of a `GeoJSON` Feature that holds the entity's members.
pub const PROPERTIES_MEMBER: &str = "properties";

/// The member of a `GeoJSON` `FeatureCollection` that holds its Features.
pub const FEATURES_MEMBER: &str = "features";

/// The member of a `GeoJSON` Feature that holds the geometry projected from the entity.
pub const GEOMETRY_MEMBER: &str = "geometry";

/// Which `GeoJSON` shape a document is, if it is one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeoJson {
    /// One entity, its members under `properties`.
    Feature,
    /// Several entities, each a Feature under `features`.
    FeatureCollection,
}

impl GeoJson {
    /// The shape of an object from a body labelled `application/geo+json`.
    ///
    /// # Errors
    ///
    /// Returns [`Unwalkable::RepeatedMember`] when `type` occurs more than once: which shape the
    /// object is would depend on which occurrence was read.
    pub fn of(object: &Object) -> Result<Option<Self>, Unwalkable> {
        Ok(match object.get_unique("type").map_err(repeated)?.and_then(Value::as_str) {
            Some("Feature") if object.contains_key(PROPERTIES_MEMBER) => Some(Self::Feature),
            Some("FeatureCollection") if object.contains_key(FEATURES_MEMBER) => Some(Self::FeatureCollection),
            Some(_) | None => None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jstrict::{json, object::Key};
    use pretty_assertions::assert_eq;

    fn shape(document: &Value) -> Option<GeoJson> {
        GeoJson::of(document.as_object().unwrap()).unwrap()
    }

    #[test]
    fn a_feature_and_a_feature_collection_are_told_apart_by_type_and_member() {
        assert_eq!(shape(&json!({ "type": "Feature", "properties": {} })), Some(GeoJson::Feature));
        assert_eq!(shape(&json!({ "type": "FeatureCollection", "features": [] })), Some(GeoJson::FeatureCollection));
    }

    #[test]
    fn a_type_without_its_member_is_not_geojson() {
        assert_eq!(shape(&json!({ "type": "Feature" })), None);
        assert_eq!(shape(&json!({ "type": "FeatureCollection", "properties": {} })), None);
        assert_eq!(shape(&json!({ "type": "Vehicle", "properties": {} })), None);
    }

    #[test]
    fn a_repeated_type_is_refused_rather_than_one_occurrence_read() {
        let mut object = Object::new();
        object.push(Key::from("type"), json!("Vehicle"));
        object.push(Key::from("type"), json!("FeatureCollection"));
        object.push(Key::from(FEATURES_MEMBER), json!([]));

        assert_eq!(GeoJson::of(&object), Err(Unwalkable::RepeatedMember));
    }
}
