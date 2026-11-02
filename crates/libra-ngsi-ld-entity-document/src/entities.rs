//! Finding the entities of a response document.

use crate::{
    geojson::{FEATURES_MEMBER, GeoJson, PROPERTIES_MEMBER},
    linked::Visibility,
    unwalkable::{Unwalkable, repeated},
};
use jstrict::{Array, Value, object::Object};
use libra_ngsi_ld_representation::accept::MediaType;

/// One entity of a response, in whichever shape it arrived.
#[derive(Debug)]
pub enum Entity<'d> {
    /// An NGSI-LD entity: its members are the object's members.
    Plain(&'d mut Object),
    /// A `GeoJSON` Feature: its members are under `properties`, and `geometry` holds a copy of one
    /// of them.
    Feature(&'d mut Object),
}

impl Entity<'_> {
    /// The entity's own members: `id` aside under `GeoJSON`, they are its attributes, `type` and
    /// `scope`.
    ///
    /// `None` for a Feature whose `properties` is not an object, which carries no members to read.
    ///
    /// # Errors
    ///
    /// Returns [`Unwalkable::RepeatedMember`] for a Feature whose `properties` occurs more than
    /// once: which members are the entity's would depend on which occurrence was read.
    pub fn members(&mut self) -> Result<Option<&mut Object>, Unwalkable> {
        match self {
            Self::Plain(members) => Ok(Some(&mut **members)),
            Self::Feature(feature) => Ok(feature.get_unique_mut(PROPERTIES_MEMBER).map_err(repeated)?.and_then(Value::as_object_mut)),
        }
    }

    /// The entity read from an object of a document labelled `media_type`.
    pub(crate) fn of(object: &mut Object, media_type: MediaType) -> Result<Entity<'_>, Unwalkable> {
        Ok(match media_type {
            MediaType::GeoJson if GeoJson::of(object)? == Some(GeoJson::Feature) => Entity::Feature(object),
            MediaType::GeoJson | MediaType::Json | MediaType::JsonLd => Entity::Plain(object),
        })
    }
}

/// Calls `visit` on every top-level entity of a response document.
///
/// A query answers with an array of entities and a retrieval with one; under `GeoJSON` a
/// `FeatureCollection` holds Features. `media_type` is what the broker actually answered with, and
/// it alone decides whether an object is read as `GeoJSON`. Scalars are not entities: batch results
/// and error documents land there and are passed over.
///
/// Entities nested inside others by an inline join are not top-level and are not visited here.
///
/// # Errors
///
/// Returns [`Unwalkable::RepeatedMember`] when a member that says where the entities are, a
/// `GeoJSON` object's `type` or a `FeatureCollection`'s `features`, occurs more than once. The walk
/// stops there; entities visited before it may already have been edited.
pub fn for_each_entity<F>(document: &mut Value, media_type: MediaType, mut visit: F) -> Result<(), Unwalkable>
where
    F: FnMut(Entity<'_>),
{
    walk(document, media_type, &mut visit)
}

/// One level of [`for_each_entity`].
fn walk<F>(document: &mut Value, media_type: MediaType, visit: &mut F) -> Result<(), Unwalkable>
where
    F: FnMut(Entity<'_>),
{
    match document {
        Value::Array(items) => items.iter_mut().try_for_each(|item| walk(item, media_type, visit)),
        Value::Object(object) => {
            if media_type == MediaType::GeoJson && GeoJson::of(object)? == Some(GeoJson::FeatureCollection) {
                return match object.get_unique_mut(FEATURES_MEMBER).map_err(repeated)? {
                    Some(features) => walk(features, media_type, visit),
                    None => Ok(()),
                };
            }

            visit(Entity::of(object, media_type)?);
            Ok(())
        }
        Value::Null | Value::Boolean(_) | Value::Number(_) | Value::String(_) => Ok(()),
    }
}

/// Hands every top-level entity of a response document to `judge`, and removes those it withholds.
///
/// The entities are the ones [`for_each_entity`] visits: the items of an array, or the Features of
/// a `FeatureCollection` under `GeoJSON`. Returns how many were withheld. Entities nested inside
/// others by an inline join are not top-level and are neither judged nor removed here.
///
/// # Errors
///
/// As [`for_each_entity`], and [`Unwalkable::SoleEntityWithheld`] when the document is one entity
/// rather than a list of them and `judge` withholds it: an entity cannot be removed from a document
/// it is the whole of, so the caller withholds the document instead.
pub fn retain_entities<J>(document: &mut Value, media_type: MediaType, mut judge: J) -> Result<usize, Unwalkable>
where
    J: FnMut(Entity<'_>) -> Visibility,
{
    retain(document, media_type, &mut judge)
}

/// One level of [`retain_entities`].
fn retain<J>(document: &mut Value, media_type: MediaType, judge: &mut J) -> Result<usize, Unwalkable>
where
    J: FnMut(Entity<'_>) -> Visibility,
{
    match document {
        Value::Array(items) => retain_items(items, media_type, judge),
        Value::Object(object) => {
            if media_type == MediaType::GeoJson && GeoJson::of(object)? == Some(GeoJson::FeatureCollection) {
                return match object.get_unique_mut(FEATURES_MEMBER).map_err(repeated)? {
                    Some(features) => retain(features, media_type, judge),
                    None => Ok(0),
                };
            }

            match judge(Entity::of(object, media_type)?) {
                Visibility::Show => Ok(0),
                Visibility::Withhold => Err(Unwalkable::SoleEntityWithheld),
            }
        }
        Value::Null | Value::Boolean(_) | Value::Number(_) | Value::String(_) => Ok(0),
    }
}

/// Judges every object of a list, removes those withheld, and descends into nested lists.
fn retain_items<J>(items: &mut Array, media_type: MediaType, judge: &mut J) -> Result<usize, Unwalkable>
where
    J: FnMut(Entity<'_>) -> Visibility,
{
    let mut withheld = 0;
    let mut kept = Array::with_capacity(items.len());

    for mut item in items.drain(..) {
        match &mut item {
            Value::Object(object) => {
                if judge(Entity::of(object, media_type)?) == Visibility::Withhold {
                    withheld += 1;
                    continue;
                }
            }
            Value::Array(nested) => withheld += retain_items(nested, media_type, judge)?,
            Value::Null | Value::Boolean(_) | Value::Number(_) | Value::String(_) => {}
        }
        kept.push(item);
    }

    *items = kept;

    Ok(withheld)
}

#[cfg(test)]
mod tests {
    use super::*;
    use jstrict::{json, object::Key};
    use pretty_assertions::assert_eq;

    /// The `id` of every visited entity, read from its members, prefixed with its shape.
    fn visited(mut document: Value, media_type: MediaType) -> Vec<String> {
        let mut seen = Vec::new();

        for_each_entity(&mut document, media_type, |mut entity| {
            let shape = match entity {
                Entity::Plain(_) => "plain",
                Entity::Feature(_) => "feature",
            };
            let id = entity
                .members()
                .unwrap()
                .and_then(|members| members.get_unique("name").unwrap())
                .and_then(Value::as_str)
                .unwrap_or("-")
                .to_owned();
            seen.push(format!("{shape}:{id}"));
        })
        .unwrap();

        seen
    }

    #[test]
    fn an_array_and_a_single_object_are_entities() {
        assert_eq!(visited(json!([{ "name": "a" }, { "name": "b" }]), MediaType::Json), ["plain:a", "plain:b"]);
        assert_eq!(visited(json!({ "name": "a" }), MediaType::JsonLd), ["plain:a"]);
    }

    #[test]
    fn a_feature_keeps_its_members_under_properties() {
        let feature = json!({ "type": "Feature", "properties": { "name": "a" }, "name": "not this" });

        assert_eq!(visited(feature, MediaType::GeoJson), ["feature:a"]);
    }

    #[test]
    fn a_feature_collection_is_its_features() {
        let collection = json!({ "type": "FeatureCollection", "features": [
            { "type": "Feature", "properties": { "name": "a" } },
            { "type": "Feature", "properties": { "name": "b" } }
        ] });

        assert_eq!(visited(collection, MediaType::GeoJson), ["feature:a", "feature:b"]);
    }

    #[test]
    fn an_entity_of_type_feature_under_plain_json_is_an_entity() {
        let entity = json!({ "type": "Feature", "properties": { "type": "Property", "value": 1 }, "name": "a" });

        assert_eq!(visited(entity, MediaType::Json), ["plain:a"]);
    }

    /// Withholds every entity whose `name` member is `secret`, and returns what is left.
    fn retained(mut document: Value, media_type: MediaType) -> (Result<usize, Unwalkable>, Value) {
        let outcome = retain_entities(&mut document, media_type, |mut entity| {
            let secret = entity
                .members()
                .ok()
                .flatten()
                .and_then(|members| members.get_unique("name").ok().flatten())
                .and_then(Value::as_str)
                == Some("secret");
            if secret { Visibility::Withhold } else { Visibility::Show }
        });

        (outcome, document)
    }

    #[test]
    fn a_withheld_entity_is_removed_from_a_list_and_the_others_kept_in_order() {
        let (outcome, document) = retained(json!([{ "name": "a" }, { "name": "secret" }, { "name": "b" }, "urn:scalar"]), MediaType::Json);

        assert_eq!(outcome, Ok(1));
        assert_eq!(document, json!([{ "name": "a" }, { "name": "b" }, "urn:scalar"]));
    }

    #[test]
    fn a_withheld_feature_is_removed_from_its_collection() {
        let (outcome, document) = retained(
            json!({ "type": "FeatureCollection", "features": [
                { "type": "Feature", "properties": { "name": "secret" } },
                { "type": "Feature", "properties": { "name": "a" } }
            ] }),
            MediaType::GeoJson,
        );

        assert_eq!(outcome, Ok(1));
        assert_eq!(
            document,
            json!({ "type": "FeatureCollection", "features": [{ "type": "Feature", "properties": { "name": "a" } }] })
        );
    }

    #[test]
    fn a_single_withheld_entity_withholds_the_document() {
        assert_eq!(retained(json!({ "name": "secret" }), MediaType::Json).0, Err(Unwalkable::SoleEntityWithheld));
        assert_eq!(retained(json!({ "name": "a" }), MediaType::Json).0, Ok(0));
    }

    #[test]
    fn nothing_withheld_leaves_the_document_as_it_was() {
        let document = json!([{ "name": "a", "type": "T" }, { "name": "b" }]);

        assert_eq!(retained(document.clone(), MediaType::JsonLd), (Ok(0), document));
    }

    #[test]
    fn scalars_are_not_entities() {
        assert_eq!(visited(json!(["urn:a", 1, null]), MediaType::Json), Vec::<String>::new());
    }

    fn repeating(name: &str, first: Value, second: Value) -> Object {
        let mut object = Object::new();
        object.push(Key::from(name), first);
        object.push(Key::from(name), second);
        object
    }

    #[test]
    fn a_repeated_member_that_says_where_the_entities_are_is_refused() {
        let mut features = repeating(FEATURES_MEMBER, json!([]), json!([{ "type": "Feature", "properties": { "name": "a" } }]));
        features.push(Key::from("type"), json!("FeatureCollection"));
        let mut collection = Value::Object(features);

        assert_eq!(for_each_entity(&mut collection, MediaType::GeoJson, |_| {}), Err(Unwalkable::RepeatedMember));

        let mut feature = repeating(PROPERTIES_MEMBER, json!({ "name": "a" }), json!({ "name": "b" }));
        feature.push(Key::from("type"), json!("Feature"));
        let mut document = Value::Object(feature);
        let mut readings = Vec::new();

        for_each_entity(&mut document, MediaType::GeoJson, |mut entity| {
            readings.push(entity.members().map(|members| members.is_some()));
        })
        .unwrap();

        assert_eq!(readings, [Err(Unwalkable::RepeatedMember)]);
    }
}
