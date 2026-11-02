//! Judging the linked entities of a join answer (NGSI-LD clause 4.5.23).
//!
//! An inline answer (clause 4.5.23.2) nests each linked entity under the Relationship that points at
//! it: in an `entity` sub-attribute of a Relationship (an object, or an array when the
//! Relationship's `object` is an array) and in `entityList` on a `ListRelationship` (clauses 4.5.3.2
//! and 4.5.22, annex C.2.2). A flat answer (clause 4.5.23.3) appends the linked entities to the
//! response array, or to the `features` of a `FeatureCollection` under `application/geo+json`.
//!
//! Every linked entity is handed to a judge, which says whether the caller may see it and may edit
//! it on the way. A withheld entity is removed; the Relationship that pointed at it stays, so its
//! `object` still names the target, as a read without the join would have. A kept entity is walked
//! in turn, because a deeper `joinLevel` nests linked entities inside linked entities.
//!
//! What cannot be recognised as a join answer is refused rather than passed over: a linked member
//! holding something other than entity objects, or nesting deeper than [`MAX_DEPTH`]. Passing it
//! over would forward a linked entity nobody judged.

use crate::{
    entities::{Entity, for_each_entity},
    geojson::{FEATURES_MEMBER, GeoJson},
    unwalkable::{Unwalkable, repeated},
};
use jstrict::{Array, Value, object::Object};
use libra_ngsi_ld_query::linked_entity::JoinMode;
use libra_ngsi_ld_representation::accept::MediaType;

/// How deeply entities and their attributes may nest before an answer is refused.
///
/// Walking recurses over the document, and the document is whatever the broker sent; the bound is
/// what keeps a hostile or broken answer from deciding how deep the stack goes.
pub const MAX_DEPTH: usize = 32;

/// The members of an entity that are not attributes, and so carry no Relationship.
pub const ENTITY_STRUCTURE: [&str; 4] = ["id", "type", "scope", "@context"];

/// The members of a Relationship instance that hold its linked entities.
///
/// `entity` and `entityList` are the specification's (clauses 4.5.3.2 and 4.5.22). `EntityTypeList`
/// is what Scorpio writes in place of `entityList`, as a JSON-LD list object: a `ListRelationship`'s
/// linked entities arrive under it, and an answer from that broker is judged like any other rather
/// than forwarded with them unread.
pub const LINKED_MEMBERS: [&str; 3] = ["entity", "entityList", "EntityTypeList"];

/// The members of an attribute instance that hold its value rather than a sub-attribute.
///
/// Their contents are data, and data that happens to look like a Relationship is not one.
pub const VALUE_MEMBERS: [&str; 16] = [
    "value",
    "object",
    "objectList",
    "valueList",
    "languageMap",
    "json",
    "vocab",
    "vocabList",
    "previousValue",
    "previousObject",
    "previousObjectList",
    "previousValueList",
    "previousLanguageMap",
    "previousJson",
    "previousVocab",
    "previousVocabList",
];

/// The member of a JSON-LD list object that holds the list.
const LIST_MEMBER: &str = "@list";

/// What a judge decides about one linked entity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Visibility {
    /// The caller may see the entity, as the judge left it.
    Show,
    /// The caller may not see the entity, and it is removed.
    Withhold,
}

/// Hands every linked entity of a join answer to `judge`, and removes those it withholds.
///
/// `mode` is the join the request asked for, and decides where the linked entities are: nested
/// under Relationships for [`JoinMode::Inline`], every item of the response array for
/// [`JoinMode::Flat`]. A flat answer that is a single object is the addressed entity itself, which
/// the request side already judged; only what is nested in it is walked. `media_type` is what the
/// broker answered with.
///
/// Returns how many linked entities were withheld.
///
/// # Errors
///
/// Returns [`Unwalkable`] when a linked member holds something other than entity objects, the
/// answer nests deeper than [`MAX_DEPTH`], or a member the walk reads occurs twice in one object.
pub fn judge_linked<J>(document: &mut Value, media_type: MediaType, mode: JoinMode, judge: J) -> Result<usize, Unwalkable>
where
    J: FnMut(Entity<'_>) -> Visibility,
{
    let mut walker = Walker { judge, withheld: 0 };

    match mode {
        JoinMode::Inline => walker.walk_top_level(document, media_type)?,
        JoinMode::Flat => walker.judge_flat(document, media_type)?,
    }

    Ok(walker.withheld)
}

/// Whether anything of a judged list is left.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Remaining {
    Some,
    None,
}

/// The state of one walk: the judge, and what it withheld.
struct Walker<J> {
    judge: J,
    withheld: usize,
}

impl<J> Walker<J>
where
    J: FnMut(Entity<'_>) -> Visibility,
{
    /// Walks the members of every top-level entity, without judging the entities themselves.
    fn walk_top_level(&mut self, document: &mut Value, media_type: MediaType) -> Result<(), Unwalkable> {
        let mut outcome = Ok(());

        for_each_entity(document, media_type, |mut entity| {
            if outcome.is_ok() {
                outcome = match entity.members() {
                    Ok(Some(members)) => self.walk_members(members, 0),
                    Ok(None) => Ok(()),
                    Err(unwalkable) => Err(unwalkable),
                };
            }
        })?;

        outcome
    }

    /// Judges every item of a flat answer, and walks the members of those it keeps.
    fn judge_flat(&mut self, document: &mut Value, media_type: MediaType) -> Result<(), Unwalkable> {
        match document {
            Value::Array(items) => self.judge_items(items, media_type, 0).map(|_| ()),
            Value::Object(object) if media_type == MediaType::GeoJson && GeoJson::of(object)? == Some(GeoJson::FeatureCollection) => {
                match object.get_unique_mut(FEATURES_MEMBER).map_err(repeated)? {
                    Some(Value::Array(features)) => self.judge_items(features, media_type, 0).map(|_| ()),
                    Some(Value::Null | Value::Boolean(_) | Value::Number(_) | Value::String(_) | Value::Object(_)) | None => Ok(()),
                }
            }
            Value::Object(_) => self.walk_top_level(document, media_type),
            Value::Null | Value::Boolean(_) | Value::Number(_) | Value::String(_) => Ok(()),
        }
    }

    /// Judges each object of a list of entities, removes those withheld, and walks those kept.
    ///
    /// A scalar in a flat answer's array is not an entity and is left alone; a scalar where a linked
    /// member promised entities is refused by the caller, which knows which of the two it is.
    fn judge_items(&mut self, items: &mut Array, media_type: MediaType, depth: usize) -> Result<Remaining, Unwalkable> {
        let mut kept = Array::with_capacity(items.len());

        for mut item in items.drain(..) {
            if let Value::Object(object) = &mut item
                && self.judge_entity(Entity::of(object, media_type)?, depth)? == Visibility::Withhold
            {
                continue;
            }
            kept.push(item);
        }

        *items = kept;

        Ok(if items.is_empty() { Remaining::None } else { Remaining::Some })
    }

    /// Judges one linked entity and, if it is kept, walks what is nested in it.
    fn judge_entity(&mut self, mut entity: Entity<'_>, depth: usize) -> Result<Visibility, Unwalkable> {
        // The judge sees the entity before anything nested in it is walked, so an attribute it
        // removes takes whatever was nested under that attribute with it.
        let visibility = (self.judge)(match &mut entity {
            Entity::Plain(members) => Entity::Plain(members),
            Entity::Feature(feature) => Entity::Feature(feature),
        });

        match visibility {
            Visibility::Withhold => self.withheld += 1,
            Visibility::Show => {
                if let Some(members) = entity.members()? {
                    self.walk_members(members, depth + 1)?;
                }
            }
        }

        Ok(visibility)
    }

    /// Walks the attributes of one entity.
    fn walk_members(&mut self, members: &mut Object, depth: usize) -> Result<(), Unwalkable> {
        if depth > MAX_DEPTH {
            return Err(Unwalkable::TooDeep);
        }

        for (name, value) in members.iter_mut() {
            if !ENTITY_STRUCTURE.contains(&name.as_str()) {
                self.walk_attribute(value, depth)?;
            }
        }

        Ok(())
    }

    /// Walks one attribute: an instance, or an array of instances (one per `datasetId`, or one per
    /// point in time in a temporal answer).
    fn walk_attribute(&mut self, value: &mut Value, depth: usize) -> Result<(), Unwalkable> {
        match value {
            Value::Object(instance) => self.walk_instance(instance, depth),
            Value::Array(instances) => instances.iter_mut().try_for_each(|instance| match instance {
                Value::Object(instance) => self.walk_instance(instance, depth),
                Value::Null | Value::Boolean(_) | Value::Number(_) | Value::String(_) | Value::Array(_) => Ok(()),
            }),
            Value::Null | Value::Boolean(_) | Value::Number(_) | Value::String(_) => Ok(()),
        }
    }

    /// Judges the linked entities of one attribute instance, then walks its sub-attributes.
    fn walk_instance(&mut self, instance: &mut Object, depth: usize) -> Result<(), Unwalkable> {
        if depth > MAX_DEPTH {
            return Err(Unwalkable::TooDeep);
        }

        if is_relationship(instance)? {
            for member in LINKED_MEMBERS {
                self.judge_member(instance, member, depth)?;
            }
        }

        for (name, value) in instance.iter_mut() {
            let name = name.as_str();
            if !VALUE_MEMBERS.contains(&name) && !LINKED_MEMBERS.contains(&name) {
                self.walk_attribute(value, depth + 1)?;
            }
        }

        Ok(())
    }

    /// Judges what one linked member of a Relationship instance holds, removing the member once
    /// nothing in it is left.
    fn judge_member(&mut self, instance: &mut Object, member: &str, depth: usize) -> Result<(), Unwalkable> {
        let Some(linked) = instance.get_unique_mut(member).map_err(repeated)? else {
            return Ok(());
        };

        // Inline linked entities are plain NGSI-LD entities under every media type: a `GeoJSON`
        // answer nests them inside the Feature's `properties` as they are.
        let remaining = match linked {
            Value::Object(list) if list.contains_key(LIST_MEMBER) => match list.get_unique_mut(LIST_MEMBER).map_err(repeated)? {
                Some(Value::Array(items)) => self.judge_linked_items(items, depth)?,
                Some(Value::Null | Value::Boolean(_) | Value::Number(_) | Value::String(_) | Value::Object(_)) | None => {
                    return Err(Unwalkable::NotAnEntity);
                }
            },
            Value::Object(entity) => match self.judge_entity(Entity::Plain(entity), depth)? {
                Visibility::Show => Remaining::Some,
                Visibility::Withhold => Remaining::None,
            },
            Value::Array(items) => self.judge_linked_items(items, depth)?,
            Value::Null | Value::Boolean(_) | Value::Number(_) | Value::String(_) => return Err(Unwalkable::NotAnEntity),
        };

        if remaining == Remaining::None {
            instance.remove_unique(member).map_err(repeated)?;
        }

        Ok(())
    }

    /// Judges a list of linked entities, every one of which must be an entity object.
    fn judge_linked_items(&mut self, items: &mut Array, depth: usize) -> Result<Remaining, Unwalkable> {
        if !items.iter().all(Value::is_object) {
            return Err(Unwalkable::NotAnEntity);
        }

        self.judge_items(items, MediaType::Json, depth)
    }
}

/// Whether an attribute instance is a Relationship or a `ListRelationship`.
///
/// The concise representation (clause 4.5.5) drops `type` where `object` or `objectList` says what
/// the attribute is, so either member is enough.
fn is_relationship(instance: &Object) -> Result<bool, Unwalkable> {
    Ok(instance.contains_key("object")
        || instance.contains_key("objectList")
        || matches!(
            instance.get_unique("type").map_err(repeated)?.and_then(Value::as_str),
            Some("Relationship" | "ListRelationship")
        ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use jstrict::{json, object::Key};
    use pretty_assertions::assert_eq;

    const PARKING: &str = "urn:ngsi-ld:OffStreetParking:P1";

    /// A judge that withholds every entity whose type is `OffStreetParking` and whose name is in
    /// `withheld`, and shows everything else.
    fn withholding(withheld: &[&'static str]) -> impl FnMut(Entity<'_>) -> Visibility {
        move |mut entity| {
            let name = entity
                .members()
                .unwrap()
                .and_then(|members| members.get_unique("name").unwrap())
                .and_then(|name| member(name, "value").or(Some(name)))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();

            if withheld.contains(&name.as_str()) {
                Visibility::Withhold
            } else {
                Visibility::Show
            }
        }
    }

    fn parking(name: &str) -> Value {
        json!({ "id": format!("urn:ngsi-ld:OffStreetParking:{name}"), "type": "OffStreetParking", "name": { "type": "Property", "value": name } })
    }

    /// The parking `name`, with an `operator` Relationship holding `linked`.
    fn operated_parking(name: &str, linked: Value) -> Value {
        json!({ "id": format!("urn:ngsi-ld:OffStreetParking:{name}"), "type": "OffStreetParking", "name": { "type": "Property", "value": name },
            "operator": { "object": "urn:ngsi-ld:Company:1", "entity": linked } })
    }

    /// The member `name` of `value`, if `value` is an object that has it.
    fn member<'v>(value: &'v Value, name: &str) -> Option<&'v Value> {
        value.as_object()?.get_unique(name).unwrap()
    }

    /// The value at `path` of member names in `document`.
    fn at<'v>(document: &'v Value, path: &[&str]) -> &'v Value {
        path.iter().fold(document, |value, name| member(value, name).unwrap())
    }

    fn repeating(name: &str, first: Value, second: Value) -> Object {
        let mut object = Object::new();
        object.push(Key::from(name), first);
        object.push(Key::from(name), second);
        object
    }

    fn judge(document: &mut Value, mode: JoinMode, withheld: &[&'static str]) -> Result<usize, Unwalkable> {
        judge_linked(document, MediaType::Json, mode, withholding(withheld))
    }

    #[test]
    fn a_withheld_inline_entity_is_removed_and_its_relationship_kept() {
        let mut document = json!([{ "id": "urn:ngsi-ld:Vehicle:V1", "type": "Vehicle",
            "isParked": { "type": "Relationship", "object": PARKING, "entity": parking("Berlin") } }]);

        assert_eq!(judge(&mut document, JoinMode::Inline, &["Berlin"]), Ok(1));
        assert_eq!(
            document,
            json!([{ "id": "urn:ngsi-ld:Vehicle:V1", "type": "Vehicle", "isParked": { "type": "Relationship", "object": PARKING } }])
        );
    }

    #[test]
    fn a_shown_inline_entity_is_left_as_it_is() {
        let mut document = json!({ "id": "urn:ngsi-ld:Vehicle:V1", "isParked": { "object": PARKING, "entity": parking("Madrid") } });
        let original = document.clone();

        assert_eq!(judge(&mut document, JoinMode::Inline, &["Berlin"]), Ok(0));
        assert_eq!(document, original);
    }

    #[test]
    fn an_inline_entity_array_keeps_what_is_shown() {
        // A Relationship whose `object` is an array carries an array of linked entities.
        let mut document = json!({ "seenAt": { "type": "Relationship", "object": ["a", "b"], "entity": [parking("Berlin"), parking("Madrid")] } });

        assert_eq!(judge(&mut document, JoinMode::Inline, &["Berlin"]), Ok(1));
        assert_eq!(
            document,
            json!({ "seenAt": { "type": "Relationship", "object": ["a", "b"], "entity": [parking("Madrid")] } })
        );

        assert_eq!(judge(&mut document, JoinMode::Inline, &["Madrid"]), Ok(1));
        assert_eq!(document, json!({ "seenAt": { "type": "Relationship", "object": ["a", "b"] } }));
    }

    #[test]
    fn an_entity_list_keeps_what_is_shown_in_order_and_leaves_the_object_list_alone() {
        let object_list = json!([{ "object": "a" }, { "object": "b" }, { "object": "c" }]);
        // `json!` takes its interpolations by value, and the list is needed again for the expectation.
        let mut document = json!({ "parkedBefore": { "type": "ListRelationship", "objectList": object_list.clone(),
            "entityList": [parking("A"), parking("Berlin"), parking("C")] } });

        assert_eq!(judge(&mut document, JoinMode::Inline, &["Berlin"]), Ok(1));
        assert_eq!(
            document,
            json!({ "parkedBefore": { "type": "ListRelationship", "objectList": object_list, "entityList": [parking("A"), parking("C")] } })
        );
    }

    #[test]
    fn the_list_scorpio_writes_for_an_entity_list_is_judged_like_one() {
        // Scorpio writes a ListRelationship's linked entities as `EntityTypeList: {"@list": [...]}`.
        let mut document = json!({ "parkedBefore": { "objectList": [{ "object": "a" }, { "object": "b" }],
            "EntityTypeList": { "@list": [parking("Berlin"), parking("Madrid")] } } });

        assert_eq!(judge(&mut document, JoinMode::Inline, &["Berlin"]), Ok(1));
        assert_eq!(
            document,
            json!({ "parkedBefore": { "objectList": [{ "object": "a" }, { "object": "b" }], "EntityTypeList": { "@list": [parking("Madrid")] } } })
        );

        assert_eq!(judge(&mut document, JoinMode::Inline, &["Madrid"]), Ok(1));
        assert_eq!(document, json!({ "parkedBefore": { "objectList": [{ "object": "a" }, { "object": "b" }] } }));
    }

    #[test]
    fn each_instance_of_a_multi_instance_relationship_is_judged_on_its_own() {
        let mut document = json!({ "seenAt": [
            { "type": "Relationship", "object": "a", "datasetId": "urn:ngsi-ld:Dataset:a", "entity": parking("Berlin") },
            { "type": "Relationship", "object": "b", "datasetId": "urn:ngsi-ld:Dataset:b", "entity": parking("Madrid") }
        ] });

        assert_eq!(judge(&mut document, JoinMode::Inline, &["Berlin"]), Ok(1));
        assert_eq!(
            document,
            json!({ "seenAt": [
                { "type": "Relationship", "object": "a", "datasetId": "urn:ngsi-ld:Dataset:a" },
                { "type": "Relationship", "object": "b", "datasetId": "urn:ngsi-ld:Dataset:b", "entity": parking("Madrid") }
            ] })
        );
    }

    #[test]
    fn a_linked_entity_nested_in_a_linked_entity_is_judged_too() {
        let level_one = operated_parking("Madrid", parking("Berlin"));
        let mut document = json!({ "isParked": { "object": PARKING, "entity": level_one } });

        assert_eq!(judge(&mut document, JoinMode::Inline, &["Berlin"]), Ok(1));
        assert_eq!(
            at(&document, &["isParked", "entity", "operator"]),
            &json!({ "object": "urn:ngsi-ld:Company:1" })
        );
        assert_eq!(at(&document, &["isParked", "entity", "name", "value"]), &json!("Madrid"));
    }

    #[test]
    fn a_withheld_entity_takes_what_is_nested_in_it_unjudged() {
        let level_one = operated_parking("Berlin", parking("Madrid"));
        let mut document = json!({ "isParked": { "object": PARKING, "entity": level_one } });

        assert_eq!(judge(&mut document, JoinMode::Inline, &["Berlin"]), Ok(1));
        assert_eq!(document, json!({ "isParked": { "object": PARKING } }));
    }

    #[test]
    fn a_relationship_of_a_relationship_is_walked() {
        let mut document = json!({ "isParked": { "type": "Relationship", "object": PARKING,
            "providedBy": { "type": "Relationship", "object": "urn:ngsi-ld:Device:1", "entity": parking("Berlin") } } });

        assert_eq!(judge(&mut document, JoinMode::Inline, &["Berlin"]), Ok(1));
        assert_eq!(
            document,
            json!({ "isParked": { "type": "Relationship", "object": PARKING, "providedBy": { "type": "Relationship", "object": "urn:ngsi-ld:Device:1" } } })
        );
    }

    #[test]
    fn a_property_value_that_looks_like_a_relationship_is_data() {
        let mut document = json!({ "note": { "type": "Property", "value": { "object": "x", "entity": "not an entity" } } });
        let original = document.clone();

        assert_eq!(judge(&mut document, JoinMode::Inline, &[]), Ok(0));
        assert_eq!(document, original);
    }

    #[test]
    fn a_flat_answer_has_every_item_judged() {
        let mut document = json!([
            { "id": "urn:ngsi-ld:Vehicle:V1", "type": "Vehicle", "isParked": { "object": PARKING } },
            parking("Berlin"),
            parking("Madrid")
        ]);

        assert_eq!(judge(&mut document, JoinMode::Flat, &["Berlin"]), Ok(1));
        assert_eq!(
            document,
            json!([{ "id": "urn:ngsi-ld:Vehicle:V1", "type": "Vehicle", "isParked": { "object": PARKING } }, parking("Madrid")])
        );
    }

    #[test]
    fn a_flat_feature_collection_has_every_feature_judged() {
        let feature = |name: &str| json!({ "id": name, "type": "Feature", "geometry": null, "properties": { "type": "OffStreetParking", "name": name } });
        let mut document = json!({ "type": "FeatureCollection", "features": [feature("Madrid"), feature("Berlin")], "@context": [] });

        let withheld = judge_linked(&mut document, MediaType::GeoJson, JoinMode::Flat, withholding(&["Berlin"]));

        assert_eq!(withheld, Ok(1));
        assert_eq!(
            document,
            json!({ "type": "FeatureCollection", "features": [feature("Madrid")], "@context": [] })
        );
    }

    #[test]
    fn an_inline_answer_under_geojson_is_walked_inside_properties() {
        let mut document = json!({ "type": "FeatureCollection", "features": [{ "type": "Feature", "geometry": null,
            "properties": { "type": "Vehicle", "isParked": { "object": PARKING, "entity": parking("Berlin") } } }] });

        let withheld = judge_linked(&mut document, MediaType::GeoJson, JoinMode::Inline, withholding(&["Berlin"]));

        assert_eq!(withheld, Ok(1));
        let feature = &member(&document, "features").and_then(Value::as_array).unwrap()[0];
        assert_eq!(at(feature, &["properties", "isParked"]), &json!({ "object": PARKING }));
    }

    #[test]
    fn a_flat_answer_that_is_one_object_has_only_its_nested_entities_judged() {
        let mut document = parking("Berlin");
        let original = document.clone();

        assert_eq!(judge(&mut document, JoinMode::Flat, &["Berlin"]), Ok(0));
        assert_eq!(document, original);
    }

    #[test]
    fn a_linked_member_that_holds_no_entity_is_refused() {
        for entity in [
            json!("urn:ngsi-ld:OffStreetParking:P1"),
            json!([parking("A"), "b"]),
            json!(null),
            json!({ "@list": "x" }),
        ] {
            let label = entity.to_string();
            let mut document = json!({ "isParked": { "object": PARKING, "entity": entity } });

            assert_eq!(judge(&mut document, JoinMode::Inline, &[]), Err(Unwalkable::NotAnEntity), "{label}");
        }
    }

    #[test]
    fn an_answer_nested_past_the_limit_is_refused() {
        let nested = |levels: usize| {
            let mut entity = parking("Madrid");
            for _ in 0..levels {
                let mut outer = parking("Madrid").into_object().unwrap();
                outer.push(Key::from("isParked"), json!({ "object": PARKING, "entity": entity }));
                entity = Value::Object(outer);
            }
            entity
        };

        assert_eq!(judge(&mut nested(MAX_DEPTH), JoinMode::Inline, &[]), Ok(0));
        assert_eq!(judge(&mut nested(MAX_DEPTH + 1), JoinMode::Inline, &[]), Err(Unwalkable::TooDeep));
    }

    #[test]
    fn the_judge_may_edit_what_it_shows() {
        let mut document = json!({ "isParked": { "object": PARKING, "entity": parking("Madrid") } });

        let edited = judge_linked(&mut document, MediaType::Json, JoinMode::Inline, |mut entity| {
            if let Some(members) = entity.members().unwrap() {
                members.remove_unique("name").unwrap();
            }
            Visibility::Show
        });

        assert_eq!(edited, Ok(0));
        assert_eq!(
            document,
            json!({ "isParked": { "object": PARKING, "entity": { "id": "urn:ngsi-ld:OffStreetParking:Madrid", "type": "OffStreetParking" } } })
        );
    }

    #[test]
    fn a_repeated_member_the_walk_reads_is_refused() {
        // Two `entity` members: judging one and forwarding the other would leak it unjudged.
        let mut relationship = repeating("entity", parking("Madrid"), parking("Berlin"));
        relationship.push(Key::from("object"), json!(PARKING));
        let mut document = json!({ "isParked": Value::Object(relationship) });
        assert_eq!(judge(&mut document, JoinMode::Inline, &[]), Err(Unwalkable::RepeatedMember));

        // Two `type` members: whether the instance is a Relationship would depend on which was read.
        let mut instance = repeating("type", json!("Property"), json!("Relationship"));
        instance.push(Key::from("entity"), parking("Berlin"));
        let mut document = json!({ "isParked": Value::Object(instance) });
        assert_eq!(judge(&mut document, JoinMode::Inline, &[]), Err(Unwalkable::RepeatedMember));

        let mut list = repeating("@list", json!([]), json!([parking("Berlin")]));
        list.push(Key::from("extra"), json!(null));
        let mut document = json!({ "parkedBefore": { "objectList": [], "EntityTypeList": Value::Object(list) } });
        assert_eq!(judge(&mut document, JoinMode::Inline, &[]), Err(Unwalkable::RepeatedMember));

        let mut collection = repeating(FEATURES_MEMBER, json!([]), json!([parking("Berlin")]));
        collection.push(Key::from("type"), json!("FeatureCollection"));
        let withheld = judge_linked(&mut Value::Object(collection), MediaType::GeoJson, JoinMode::Flat, withholding(&[]));
        assert_eq!(withheld, Err(Unwalkable::RepeatedMember));
    }
}
