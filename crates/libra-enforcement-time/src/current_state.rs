//! Removing from a current-state entity every attribute instance outside the allowed window.
//!
//! Under `current-state = "values-in-window"` a current-state read is answered, and what the
//! answer holds is bounded instead of the request. An attribute instance is dated by its
//! `observedAt` (NGSI-LD 4.8), the instant the value was observed, or by its `modifiedAt` when it
//! has none, the instant the value was last written. An instance with neither cannot be shown to be
//! inside the window, and is removed with the ones that are outside it. An attribute left with no
//! instance is removed whole.
//!
//! The system attributes `createdAt` and `modifiedAt` are asked for upstream whenever the caller did
//! not ask for them, because without them an instance with no `observedAt` could not be dated. They
//! are then taken out again at every level they were added at, so the caller gets the
//! representation they asked for.

use crate::window::Window;
use jiff::Timestamp;
use jstrict::{Value, object::Object};
use libra_ngsi_ld_entity_document::linked::{ENTITY_STRUCTURE, LINKED_MEMBERS, MAX_DEPTH, VALUE_MEMBERS};
use std::mem;
use thiserror::Error;

/// The member that dates an attribute instance by when its value was observed (NGSI-LD 4.8).
const OBSERVED_AT: &str = "observedAt";

/// The system attribute that dates a value by when it was last written (NGSI-LD 4.8).
const MODIFIED_AT: &str = "modifiedAt";

/// The system attributes `options=sysAttrs` adds to entities and attributes.
const SYSTEM_ATTRIBUTES: [&str; 2] = ["createdAt", MODIFIED_AT];

/// The members of an entity that are system members rather than attributes.
const SYSTEM_MEMBERS: [&str; 3] = ["createdAt", MODIFIED_AT, "deletedAt"];

/// Whether the system attributes in an answer were asked for by Libra rather than by the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddedSystemAttributes {
    /// Libra asked for them; they are removed once the instances are dated.
    Strip,
    /// The caller asked for them; they stay.
    Keep,
}

/// An entity nested deeper than [`MAX_DEPTH`] levels, which is not walked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("the entity nests deeper than the walk is bounded to")]
pub struct TooDeep;

/// Removes every attribute instance of an entity that lies outside `window`, and returns how many
/// were removed.
///
/// Only the entity's own attributes are dated. A linked entity nested under a Relationship by an
/// inline join is an entity of its own and is left to be filtered as one. Every occurrence of a
/// repeated attribute is dated on its own, so no occurrence outside the window survives.
///
/// # Errors
///
/// Returns [`TooDeep`] when stripping the system attributes would recurse past [`MAX_DEPTH`].
pub fn filter_entity(entity: &mut Object, window: Window, added: AddedSystemAttributes) -> Result<usize, TooDeep> {
    let mut removed = 0;

    *entity = mem::take(entity)
        .into_iter()
        .filter_map(|mut entry| {
            if ENTITY_STRUCTURE.contains(&entry.key.as_str()) || SYSTEM_MEMBERS.contains(&entry.key.as_str()) {
                return Some(entry);
            }

            removed += retain_instances(&mut entry.value, window);
            has_instances(&entry.value).then_some(entry)
        })
        .collect();

    match added {
        AddedSystemAttributes::Strip => strip_system_attributes(entity, 0)?,
        AddedSystemAttributes::Keep => {}
    }

    Ok(removed)
}

/// Keeps the instances of one attribute that lie inside the window, and returns how many were
/// removed.
///
/// An attribute is one instance object, or an array of them when it has several `datasetId`s. An
/// instance that is not an object carries no metadata to date it by.
fn retain_instances(attribute: &mut Value, window: Window) -> usize {
    match attribute {
        Value::Array(instances) => {
            let before = instances.len();
            instances.retain(|instance| instance.as_object().is_some_and(|instance| dated_inside(instance, window)));
            before - instances.len()
        }
        Value::Object(instance) => {
            if dated_inside(instance, window) {
                0
            } else {
                *attribute = Value::Null;
                1
            }
        }
        Value::Null | Value::Boolean(_) | Value::Number(_) | Value::String(_) => {
            *attribute = Value::Null;
            1
        }
    }
}

/// Whether an attribute holds any instance after narrowing.
const fn has_instances(attribute: &Value) -> bool {
    match attribute {
        Value::Array(instances) => !instances.is_empty(),
        Value::Object(_) => true,
        Value::Null | Value::Boolean(_) | Value::Number(_) | Value::String(_) => false,
    }
}

/// Whether an instance is dated, by `observedAt` or else `modifiedAt`, inside the window.
///
/// An instance whose date cannot be read is not shown to be inside it, and neither is one that
/// repeats the member it would be dated by: a caller may read either occurrence. A repeated
/// `observedAt` is not passed over for `modifiedAt`, which dates a different event.
fn dated_inside(instance: &Object, window: Window) -> bool {
    let date = instance
        .get_unique(OBSERVED_AT)
        .and_then(|observed| observed.map_or_else(|| instance.get_unique(MODIFIED_AT), |observed| Ok(Some(observed))));

    date.ok()
        .flatten()
        .and_then(Value::as_str)
        .and_then(|text| text.parse::<Timestamp>().ok())
        .is_some_and(|instant| window.contains(instant))
}

/// Removes `createdAt` and `modifiedAt` from an object and from every attribute and sub-attribute
/// nested in it.
///
/// Values are data and are not walked, and neither are linked entities: an inline join's linked
/// entities are filtered, and stripped, as entities of their own. `@context` is not walked either,
/// since a term definition may be named `createdAt`.
fn strip_system_attributes(object: &mut Object, depth: usize) -> Result<(), TooDeep> {
    if depth > MAX_DEPTH {
        return Err(TooDeep);
    }

    // Every occurrence goes: a repeated system attribute is still one the caller did not ask for.
    for name in SYSTEM_ATTRIBUTES {
        object.remove(name).for_each(drop);
    }

    for (member, value) in object.iter_mut() {
        if VALUE_MEMBERS.contains(&member.as_str()) || LINKED_MEMBERS.contains(&member.as_str()) || ENTITY_STRUCTURE.contains(&member.as_str()) {
            continue;
        }

        match value {
            Value::Object(nested) => strip_system_attributes(nested, depth + 1)?,
            Value::Array(items) => {
                for nested in items.iter_mut().filter_map(Value::as_object_mut) {
                    strip_system_attributes(nested, depth + 1)?;
                }
            }
            Value::Null | Value::Boolean(_) | Value::Number(_) | Value::String(_) => {}
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use jstrict::json;
    use pretty_assertions::assert_eq;

    /// The past twenty-four hours, ending at noon on the first of June.
    fn past_day() -> Window {
        Window::new("2026-05-31T12:00:00Z".parse().unwrap(), "2026-06-01T12:00:00Z".parse().unwrap())
    }

    fn filtered(mut entity: Value, added: AddedSystemAttributes) -> (Value, usize) {
        let removed = filter_entity(entity.as_object_mut().expect("the test entity is an object"), past_day(), added).expect("it should filter");

        (entity, removed)
    }

    #[test]
    fn an_attribute_observed_inside_the_window_stays_and_one_outside_it_goes() {
        let (entity, removed) = filtered(
            json!({ "id": "urn:v:1", "type": "Vehicle",
                "speed": { "type": "Property", "value": 42, "observedAt": "2026-06-01T11:00:00Z" },
                "temperature": { "type": "Property", "value": 20, "observedAt": "2026-05-30T12:00:00Z" } }),
            AddedSystemAttributes::Keep,
        );

        assert_eq!(removed, 1);
        assert_eq!(
            entity,
            json!({ "id": "urn:v:1", "type": "Vehicle", "speed": { "type": "Property", "value": 42, "observedAt": "2026-06-01T11:00:00Z" } })
        );
    }

    #[test]
    fn a_multi_instance_attribute_keeps_only_its_instances_inside_the_window() {
        let (entity, removed) = filtered(
            json!({ "id": "urn:v:1", "speed": [
                { "type": "Property", "value": 1, "datasetId": "urn:d:a", "observedAt": "2026-06-01T10:00:00Z" },
                { "type": "Property", "value": 2, "datasetId": "urn:d:b", "observedAt": "2026-01-01T00:00:00Z" }
            ] }),
            AddedSystemAttributes::Keep,
        );

        assert_eq!(removed, 1);
        assert_eq!(
            entity,
            json!({ "id": "urn:v:1", "speed": [{ "type": "Property", "value": 1, "datasetId": "urn:d:a", "observedAt": "2026-06-01T10:00:00Z" }] })
        );
    }

    #[test]
    fn an_instance_without_observed_at_is_dated_by_modified_at_and_one_with_neither_goes() {
        let (entity, removed) = filtered(
            json!({ "id": "urn:v:1",
                "brand": { "type": "Property", "value": "x", "modifiedAt": "2026-06-01T09:00:00Z" },
                "colour": { "type": "Property", "value": "red", "modifiedAt": "2025-06-01T09:00:00Z" },
                "owner": { "type": "Relationship", "object": "urn:p:1" },
                "bare": 3 }),
            AddedSystemAttributes::Keep,
        );

        assert_eq!(removed, 3);
        assert_eq!(
            entity,
            json!({ "id": "urn:v:1", "brand": { "type": "Property", "value": "x", "modifiedAt": "2026-06-01T09:00:00Z" } })
        );
    }

    #[test]
    fn system_attributes_libra_added_are_stripped_at_every_level() {
        let (entity, _) = filtered(
            json!({ "id": "urn:v:1", "type": "Vehicle", "createdAt": "2026-01-01T00:00:00Z", "modifiedAt": "2026-06-01T09:00:00Z",
                "speed": { "type": "Property", "value": { "modifiedAt": "data" }, "createdAt": "2026-01-01T00:00:00Z", "modifiedAt": "2026-06-01T09:00:00Z",
                    "accuracy": { "type": "Property", "value": 0.5, "createdAt": "2026-01-01T00:00:00Z", "modifiedAt": "2026-06-01T09:00:00Z" } } }),
            AddedSystemAttributes::Strip,
        );

        assert_eq!(
            entity,
            json!({ "id": "urn:v:1", "type": "Vehicle",
                "speed": { "type": "Property", "value": { "modifiedAt": "data" }, "accuracy": { "type": "Property", "value": 0.5 } } })
        );
    }

    #[test]
    fn system_attributes_the_caller_asked_for_are_kept() {
        let original = json!({ "id": "urn:v:1", "createdAt": "2026-01-01T00:00:00Z",
            "speed": { "type": "Property", "value": 1, "createdAt": "2026-01-01T00:00:00Z", "modifiedAt": "2026-06-01T09:00:00Z" } });

        assert_eq!(filtered(original.clone(), AddedSystemAttributes::Keep), (original, 0));
    }

    #[test]
    fn a_linked_entity_under_a_relationship_is_left_to_be_filtered_as_an_entity() {
        let original = json!({ "id": "urn:v:1", "isParked": { "type": "Relationship", "object": "urn:p:1", "observedAt": "2026-06-01T10:00:00Z",
            "entity": { "id": "urn:p:1", "modifiedAt": "2020-01-01T00:00:00Z", "name": { "type": "Property", "value": "Old" } } } });

        let (entity, _) = filtered(original.clone(), AddedSystemAttributes::Strip);

        assert_eq!(entity, original, "the linked entity is not walked here");
    }

    #[test]
    fn every_occurrence_of_a_repeated_attribute_is_dated_on_its_own() {
        let (entity, removed) = filtered(
            json!({ "id": "urn:v:1",
                "speed": { "type": "Property", "value": 1, "observedAt": "2026-06-01T10:00:00Z" },
                "speed": { "type": "Property", "value": 2, "observedAt": "2026-01-01T00:00:00Z" } }),
            AddedSystemAttributes::Keep,
        );

        assert_eq!(removed, 1);
        assert_eq!(
            entity,
            json!({ "id": "urn:v:1", "speed": { "type": "Property", "value": 1, "observedAt": "2026-06-01T10:00:00Z" } })
        );
    }

    #[test]
    fn an_instance_that_repeats_its_date_is_not_shown_to_be_inside_the_window() {
        // One `observedAt` is inside the window and one is not, and `modifiedAt` is no tiebreaker:
        // it dates the write, not the observation.
        let (entity, removed) = filtered(
            json!({ "id": "urn:v:1",
                "speed": { "type": "Property", "value": 1, "observedAt": "2026-06-01T10:00:00Z", "observedAt": "2026-01-01T00:00:00Z",
                    "modifiedAt": "2026-06-01T10:00:00Z" } }),
            AddedSystemAttributes::Keep,
        );

        assert_eq!(removed, 1);
        assert_eq!(entity, json!({ "id": "urn:v:1" }));
    }

    #[test]
    fn a_repeated_system_attribute_libra_added_is_stripped_whole() {
        let (entity, _) = filtered(
            json!({ "id": "urn:v:1", "modifiedAt": "2026-06-01T09:00:00Z", "modifiedAt": "2026-06-01T10:00:00Z" }),
            AddedSystemAttributes::Strip,
        );

        assert_eq!(entity, json!({ "id": "urn:v:1" }));
    }

    /// How a nested sub-attribute is held by the one above it.
    #[derive(Clone, Copy)]
    enum Holding {
        Object,
        Array,
    }

    /// `innermost` nested `levels` sub-attributes below the top-level object.
    fn nested(levels: usize, holding: Holding, innermost: Value) -> Value {
        (0..levels).fold(innermost, |inner, _| match holding {
            Holding::Object => json!({ "sub": inner }),
            Holding::Array => json!({ "sub": [inner] }),
        })
    }

    fn stripped(mut document: Value) -> Result<Value, TooDeep> {
        strip_system_attributes(document.as_object_mut().expect("the test document is an object"), 0)?;

        Ok(document)
    }

    #[test]
    fn system_attributes_nested_exactly_as_deep_as_the_walk_reaches_are_stripped() {
        for holding in [Holding::Object, Holding::Array] {
            assert_eq!(
                stripped(nested(MAX_DEPTH, holding, json!({ "createdAt": "2026-01-01T00:00:00Z", "value": 1 }))),
                Ok(nested(MAX_DEPTH, holding, json!({ "value": 1 })))
            );
        }
    }

    #[test]
    fn a_document_nested_one_level_past_the_walk_is_too_deep() {
        for holding in [Holding::Object, Holding::Array] {
            assert_eq!(
                stripped(nested(MAX_DEPTH + 1, holding, json!({ "createdAt": "2026-01-01T00:00:00Z" }))),
                Err(TooDeep)
            );
        }
    }
}
