//! Reducing the `scope` member of a response to the scopes a restriction covers.
//!
//! A read of an entity is allowed when any one of its scopes is allowed, so the answer may still
//! name scopes the restriction excludes. They are removed here, from an entity's own `scope` member and
//! nowhere deeper: an attribute named `scope` is an attribute, not the entity's scope. An entity of
//! a query answer, and a linked entity of a join answer (NGSI-LD clause 4.5.23), is judged the same
//! way, and one with no allowed scope left is withheld whole.

use crate::document::allows;
use jstrict::{Value, object::Object};
use libra_ngsi_ld_entity_document::{
    entities::{Entity, for_each_entity},
    linked::Visibility,
    unwalkable::Unwalkable,
};
use libra_ngsi_ld_representation::accept::MediaType;
use libra_policy_model::scope::ScopePattern;

/// The member an entity declares its scopes in.
const SCOPE_MEMBER: &str = "scope";

/// The member a normalised NGSI-LD property carries its value in.
const VALUE_MEMBER: &str = "value";

/// Whether a piece of a `scope` member survived filtering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Remainder {
    /// Something allowed is left, so the piece stays.
    Allowed,
    /// Nothing allowed is left, so the piece is removed.
    Empty,
}

/// Reduces every entity's `scope` member in a response document to what `allowed` covers.
///
/// `media_type` is what the broker actually answered with. It, not the body, decides whether a
/// document is a `GeoJSON` encoding: an entity whose `type` is literally `Feature` is an ordinary
/// entity under `application/json`. An entity with no `scope` member is left alone, because a
/// projection can omit the member from an entity that has one.
///
/// # Errors
///
/// Returns [`Unwalkable::RepeatedMember`] when the entities cannot be found, or an entity's own
/// `scope` member occurs more than once, without picking one of two occurrences: the answer is
/// then withheld rather than shown with a scope nobody reduced.
pub fn filter_document(document: &mut Value, allowed: &[ScopePattern], media_type: MediaType) -> Result<(), Unwalkable> {
    let mut outcome = Ok(());

    for_each_entity(document, media_type, |mut entity| {
        if outcome.is_ok() {
            outcome = match entity.members() {
                Ok(Some(members)) => filter_entity(members, allowed),
                Ok(None) => Ok(()),
                Err(unwalkable) => Err(unwalkable),
            };
        }
    })?;

    outcome
}

/// Judges one entity of a query answer, or one linked entity of a join answer: shown, with its
/// `scope` reduced to the allowed scopes, when any of them is allowed, and withheld otherwise.
///
/// An entity with no `scope` member is withheld. A query is narrowed by an injected `scopeQ`
/// (clause 4.19), which an unscoped entity cannot match, so one in the answer is one the broker
/// returned regardless; a read of it by identifier is refused. A linked entity is not one a
/// projection emptied either: a join whose projection removes `scope` is refused before it is sent.
/// So is one whose members or `scope` cannot be read without picking one of two occurrences.
#[must_use]
pub fn judge_entity(mut entity: Entity<'_>, allowed: &[ScopePattern]) -> Visibility {
    let Ok(Some(members)) = entity.members() else {
        return Visibility::Withhold;
    };

    match filter_entity(members, allowed) {
        Ok(()) if members.contains_key(SCOPE_MEMBER) => Visibility::Show,
        Ok(()) | Err(_) => Visibility::Withhold,
    }
}

/// Reduces the `scope` member of one entity, removing it if nothing allowed remains.
fn filter_entity(entity: &mut Object, allowed: &[ScopePattern]) -> Result<(), Unwalkable> {
    let Some(member) = entity.get_unique_mut(SCOPE_MEMBER).map_err(|_| Unwalkable::RepeatedMember)? else {
        return Ok(());
    };

    if filter_value(member, allowed) == Remainder::Empty {
        entity.remove_unique(SCOPE_MEMBER).map_err(|_| Unwalkable::RepeatedMember)?;
    }

    Ok(())
}

/// Reduces a bare string, an array, or a property object to its allowed scopes.
///
/// A shape that is not one of those, or a string that is not a usable scope, is removed: a scope
/// that cannot be compared cannot be shown to be allowed, and so is a property whose `value` occurs
/// twice.
fn filter_value(value: &mut Value, allowed: &[ScopePattern]) -> Remainder {
    match value {
        Value::String(scope) => {
            if is_allowed(scope, allowed) {
                Remainder::Allowed
            } else {
                Remainder::Empty
            }
        }
        Value::Array(items) => {
            items.retain_mut(|item| filter_value(item, allowed) == Remainder::Allowed);
            if items.is_empty() { Remainder::Empty } else { Remainder::Allowed }
        }
        Value::Object(property) => match property.get_unique_mut(VALUE_MEMBER) {
            Ok(Some(inner)) => filter_value(inner, allowed),
            Ok(None) | Err(_) => Remainder::Empty,
        },
        Value::Null | Value::Boolean(_) | Value::Number(_) => Remainder::Empty,
    }
}

/// Whether a scope as written is covered by the restriction.
fn is_allowed(scope: &str, allowed: &[ScopePattern]) -> bool {
    ScopePattern::new(scope).is_ok_and(|scope| allows(allowed, &scope))
}

#[cfg(test)]
mod tests {
    use super::*;
    use jstrict::{json, object::Key};
    use libra_ngsi_ld_entity_document::linked::judge_linked;
    use libra_ngsi_ld_query::linked_entity::JoinMode;
    use pretty_assertions::assert_eq;

    fn allowed() -> Vec<ScopePattern> {
        vec![ScopePattern::new("/Madrid/#").expect("the test pattern should be well formed")]
    }

    #[test]
    fn an_array_of_scopes_keeps_only_the_allowed_ones_in_every_entity() {
        let mut document = json!([
            { "id": "a", "scope": ["/Madrid/A", "/Secret/X"] },
            { "id": "b", "scope": ["/Madrid/B"] },
            { "id": "c" }
        ]);

        assert_eq!(filter_document(&mut document, &allowed(), MediaType::Json), Ok(()));

        assert_eq!(
            document,
            json!([{ "id": "a", "scope": ["/Madrid/A"] }, { "id": "b", "scope": ["/Madrid/B"] }, { "id": "c" }])
        );
    }

    #[test]
    fn a_bare_string_scope_outside_the_restriction_removes_the_member() {
        let mut document = json!({ "id": "a", "scope": "/Secret/X" });

        assert_eq!(filter_document(&mut document, &allowed(), MediaType::Json), Ok(()));

        assert_eq!(document, json!({ "id": "a" }));
    }

    #[test]
    fn a_bare_string_scope_inside_the_restriction_is_kept() {
        let mut document = json!({ "id": "a", "scope": "/Madrid/A" });

        assert_eq!(filter_document(&mut document, &allowed(), MediaType::Json), Ok(()));

        assert_eq!(document, json!({ "id": "a", "scope": "/Madrid/A" }));
    }

    #[test]
    fn a_normalised_property_scope_is_reduced_in_its_value() {
        let mut document = json!({ "scope": { "type": "Property", "value": ["/Madrid/A", "/Secret/X"] } });

        assert_eq!(filter_document(&mut document, &allowed(), MediaType::JsonLd), Ok(()));

        assert_eq!(document, json!({ "scope": { "type": "Property", "value": ["/Madrid/A"] } }));
    }

    #[test]
    fn a_normalised_property_scope_with_nothing_allowed_removes_the_member() {
        let mut document = json!({ "scope": { "type": "Property", "value": "/Secret/X" } });

        assert_eq!(filter_document(&mut document, &allowed(), MediaType::Json), Ok(()));

        assert_eq!(document, json!({}));
    }

    #[test]
    fn temporal_instances_are_filtered_and_an_emptied_instance_is_dropped() {
        let mut document = json!({ "scope": [
            { "type": "Property", "value": ["/Madrid/A", "/Secret/X"], "instanceId": "1" },
            { "type": "Property", "value": "/Secret/Y", "instanceId": "2" }
        ] });

        assert_eq!(filter_document(&mut document, &allowed(), MediaType::Json), Ok(()));

        assert_eq!(
            document,
            json!({ "scope": [{ "type": "Property", "value": ["/Madrid/A"], "instanceId": "1" }] })
        );
    }

    #[test]
    fn a_scope_array_with_nothing_allowed_removes_the_member() {
        let mut document = json!({ "id": "a", "scope": ["/Secret/X", "/Secret/Y"] });

        assert_eq!(filter_document(&mut document, &allowed(), MediaType::Json), Ok(()));

        assert_eq!(document, json!({ "id": "a" }));
    }

    #[test]
    fn a_geojson_feature_is_filtered_under_its_properties() {
        let mut document = json!({ "type": "Feature", "properties": { "scope": ["/Madrid/A", "/Secret/X"] }, "scope": ["/Secret/X"] });

        assert_eq!(filter_document(&mut document, &allowed(), MediaType::GeoJson), Ok(()));

        assert_eq!(
            document,
            json!({ "type": "Feature", "properties": { "scope": ["/Madrid/A"] }, "scope": ["/Secret/X"] })
        );
    }

    #[test]
    fn a_geojson_feature_collection_is_filtered_in_every_feature() {
        let mut document = json!({ "type": "FeatureCollection", "features": [
            { "type": "Feature", "properties": { "scope": ["/Madrid/A", "/Secret/X"] } },
            { "type": "Feature", "properties": { "scope": "/Secret/Y" } }
        ] });

        assert_eq!(filter_document(&mut document, &allowed(), MediaType::GeoJson), Ok(()));

        assert_eq!(
            document,
            json!({ "type": "FeatureCollection", "features": [
                { "type": "Feature", "properties": { "scope": ["/Madrid/A"] } },
                { "type": "Feature", "properties": {} }
            ] })
        );
    }

    #[test]
    fn an_entity_of_type_feature_under_plain_json_is_not_read_as_geojson() {
        let mut document = json!({ "type": "Feature", "properties": { "type": "Property", "value": 1 }, "scope": ["/Madrid/A", "/Secret/X"] });

        assert_eq!(filter_document(&mut document, &allowed(), MediaType::Json), Ok(()));

        assert_eq!(
            document,
            json!({ "type": "Feature", "properties": { "type": "Property", "value": 1 }, "scope": ["/Madrid/A"] })
        );
    }

    #[test]
    fn a_nested_attribute_named_scope_is_not_touched() {
        let mut document = json!({ "scope": ["/Madrid/A"], "area": { "type": "Property", "value": { "scope": ["/Secret/X"] } } });

        assert_eq!(filter_document(&mut document, &allowed(), MediaType::Json), Ok(()));

        assert_eq!(
            document,
            json!({ "scope": ["/Madrid/A"], "area": { "type": "Property", "value": { "scope": ["/Secret/X"] } } })
        );
    }

    #[test]
    fn a_linked_entity_with_no_allowed_scope_is_withheld() {
        let mut document = json!({ "id": "a", "scope": "/Madrid/A",
            "isParked": { "object": "p", "entity": { "id": "p", "type": "OffStreetParking", "scope": "/Berlin/Centre" } } });

        let withheld = judge_linked(&mut document, MediaType::Json, JoinMode::Inline, |entity| judge_entity(entity, &allowed()));

        assert_eq!(withheld, Ok(1));
        assert_eq!(document, json!({ "id": "a", "scope": "/Madrid/A", "isParked": { "object": "p" } }));
    }

    #[test]
    fn a_linked_entity_with_one_allowed_scope_is_kept_with_only_that_one() {
        let mut document = json!([{ "id": "p", "type": "OffStreetParking", "scope": ["/Madrid/A", "/Berlin/B"] }]);

        let withheld = judge_linked(&mut document, MediaType::Json, JoinMode::Flat, |entity| judge_entity(entity, &allowed()));

        assert_eq!(withheld, Ok(0));
        assert_eq!(document, json!([{ "id": "p", "type": "OffStreetParking", "scope": ["/Madrid/A"] }]));
    }

    #[test]
    fn a_linked_entity_without_a_scope_is_withheld() {
        let mut document = json!([{ "id": "p", "type": "OffStreetParking" }]);

        let withheld = judge_linked(&mut document, MediaType::Json, JoinMode::Flat, |entity| judge_entity(entity, &allowed()));

        assert_eq!(withheld, Ok(1));
        assert_eq!(document, json!([]));
    }

    #[test]
    fn an_entity_naming_its_scope_twice_withholds_the_answer() {
        let mut entity = Object::new();
        entity.push(Key::from("id"), json!("a"));
        entity.push(Key::from("scope"), json!("/Madrid/A"));
        entity.push(Key::from("scope"), json!("/Secret/X"));
        let mut document = Value::Array(vec![Value::Object(entity)].into());

        assert_eq!(filter_document(&mut document, &allowed(), MediaType::Json), Err(Unwalkable::RepeatedMember));
    }
}
