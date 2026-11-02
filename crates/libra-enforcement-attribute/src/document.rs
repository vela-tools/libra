//! Removing from a response what the policy does not allow.
//!
//! Filtering is applied at the level of an entity's own members, and no deeper. Recursing into
//! attribute values would delete any nested key that happens to share a name with a restricted
//! attribute, and corrupt an inline `@context` by removing the very terms the rest of the
//! document still uses. An entity nested in
//! another by a join (NGSI-LD clause 4.5.23) is not an attribute value but an entity of its own, and
//! is filtered as one by [`filter_entity`] when the layer walks the answer's linked entities.
//!
//! An entity's own members are not always where an entity keeps them. Under `application/geo+json`
//! the same entity is a `GeoJSON` Feature: its attributes sit inside `properties`, and the attribute
//! a geospatial query was about is *also* projected to a top-level `geometry`. Filtering such a
//! document as though it were an ordinary entity finds two members called `geometry` and
//! `properties`, decides that neither is the restricted attribute, and returns the whole thing,
//! including the attribute the policy hid, twice over.
//!
//! Which of the two a document is comes from the response's media type, not from the document.
//! `type` and `properties` are perfectly ordinary things for an NGSI-LD entity to carry: an entity
//! whose type is literally `Feature`, with an attribute named `properties`, is indistinguishable
//! from a `GeoJSON` Feature by shape alone, and reading it as one hides the wrong members and
//! leaves the right ones in place.

use crate::names::is_structural;
use jstrict::{Value, object::Object};
use libra_jsonld_term_expansion::{name::Term, resolved::ResolvedContext};
use libra_ngsi_ld_entity_document::{
    entities::{Entity, for_each_entity},
    geojson::{GEOMETRY_MEMBER, PROPERTIES_MEMBER},
    unwalkable::Unwalkable,
};
use libra_ngsi_ld_representation::accept::MediaType;
use libra_policy_model::attribute::CompiledAttributeRestriction;
use std::mem;

/// Removes every member of every entity in `document` that `restriction` does not allow.
///
/// `geoproperty` is the attribute a `GeoJSON` `geometry` was projected from: the one the request
/// named, or `location` when it named none. It is passed in rather than guessed because the
/// document does not record which attribute its geometry came from.
///
/// `media_type` is the type the broker actually answered with, which is what decides whether the
/// document is an entity or a `GeoJSON` Feature. It is not guessed from the body: the two shapes
/// are not distinguishable by shape.
///
/// Returns how many members were removed, which is what the caller logs: a filter that silently
/// removed nothing and a filter that was never applied look identical otherwise.
///
/// # Errors
///
/// Returns [`Unwalkable::RepeatedMember`] when a member that says where an entity's attributes
/// are occurs more than once. Entities filtered before it may already have been edited, so the
/// caller withholds the whole document.
pub fn filter(
    document: &mut Value,
    restriction: &CompiledAttributeRestriction,
    context: &ResolvedContext,
    geoproperty: &Term,
    media_type: MediaType,
) -> Result<usize, Unwalkable> {
    let mut removed = 0;
    let mut failure = Ok(());

    for_each_entity(document, media_type, |entity| {
        if failure.is_ok() {
            match filter_entity(entity, restriction, context, geoproperty) {
                Ok(count) => removed += count,
                Err(unwalkable) => failure = Err(unwalkable),
            }
        }
    })?;

    failure.map(|()| removed)
}

/// Removes the members of one entity that are not allowed, whichever shape it arrived in.
///
/// The same for a top-level entity and a linked one: a linked entity's attributes are attributes,
/// and a restriction that hides `location` hides it on every entity of the answer.
///
/// # Errors
///
/// Returns [`Unwalkable::RepeatedMember`] for a Feature that repeats its `geometry` or its
/// `properties`: which of them the caller reads is not something this filter can know.
pub fn filter_entity(
    entity: Entity<'_>,
    restriction: &CompiledAttributeRestriction,
    context: &ResolvedContext,
    geoproperty: &Term,
) -> Result<usize, Unwalkable> {
    match entity {
        Entity::Plain(members) => Ok(filter_members(members, restriction, context)),
        Entity::Feature(feature) => filter_feature(feature, restriction, context, geoproperty),
    }
}

/// Removes the disallowed members of one object, treating its keys as attribute names.
///
/// Every occurrence of a name is judged by that name, so a repeated member is removed or kept as a
/// whole and no occurrence survives a judgement another one failed.
fn filter_members(members: &mut Object, restriction: &CompiledAttributeRestriction, context: &ResolvedContext) -> usize {
    let before = members.len();

    *members = mem::take(members)
        .into_iter()
        .filter(|entry| is_structural(&entry.key) || allows(restriction, &entry.key, context))
        .collect();

    before - members.len()
}

/// Filters one `GeoJSON` Feature.
///
/// Two places carry attribute values. `properties` holds the entity's own members, and `geometry`
/// holds a copy of one of them (the geoproperty) lifted to the top level so an ordinary `GeoJSON`
/// client can read it. Removing the attribute from `properties` and leaving `geometry` behind
/// would hide the name and publish the value.
fn filter_feature(
    feature: &mut Object,
    restriction: &CompiledAttributeRestriction,
    context: &ResolvedContext,
    geoproperty: &Term,
) -> Result<usize, Unwalkable> {
    let mut removed = 0;

    if !context.expand(geoproperty).is_some_and(|iri| restriction.allows(&iri))
        && feature.remove_unique(GEOMETRY_MEMBER).map_err(|_| Unwalkable::RepeatedMember)?.is_some()
    {
        removed += 1;
    }

    if let Some(Value::Object(properties)) = feature.get_unique_mut(PROPERTIES_MEMBER).map_err(|_| Unwalkable::RepeatedMember)? {
        removed += filter_members(properties, restriction, context);
    }

    Ok(removed)
}

/// Whether the restriction allows a member, by what it means rather than by what it is called.
///
/// A member whose name cannot be expanded is removed. That is the fail-closed reading: the
/// alternative is keeping a value whose meaning is unknown, which is the same as not having applied
/// the policy to it.
pub(crate) fn allows(restriction: &CompiledAttributeRestriction, member: &str, context: &ResolvedContext) -> bool {
    context.expand(&Term::new(member)).is_some_and(|iri| restriction.allows(&iri))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pointer::at;
    use jstrict::json;
    use libra_jsonld_term_expansion::name::ExpandedIri;
    use libra_policy_model::attribute::AttributeAction;
    use pretty_assertions::assert_eq;

    fn context() -> ResolvedContext {
        ResolvedContext::from_json(
            r#"{
                "@vocab": "https://uri.etsi.org/ngsi-ld/default-context/",
                "speed": "https://uri.fiware.org/ns/data-models#speed",
                "location": "https://uri.etsi.org/ngsi-ld/location"
            }"#,
        )
        .expect("the test context should process")
    }

    fn iri(term: &str) -> ExpandedIri {
        context().expand(&Term::new(term)).expect("the term should expand")
    }

    fn omitting(terms: &[&str]) -> CompiledAttributeRestriction {
        CompiledAttributeRestriction::new(AttributeAction::Omit, terms.iter().map(|term| iri(term)).collect())
    }

    fn picking(terms: &[&str]) -> CompiledAttributeRestriction {
        CompiledAttributeRestriction::new(AttributeAction::Pick, terms.iter().map(|term| iri(term)).collect())
    }

    /// [`filter`] over a document every test here can walk.
    fn filtered(
        document: &mut Value,
        restriction: &CompiledAttributeRestriction,
        context: &ResolvedContext,
        geoproperty: &Term,
        media_type: MediaType,
    ) -> usize {
        filter(document, restriction, context, geoproperty, media_type).expect("the test document is walkable")
    }

    #[test]
    fn an_omitted_attribute_is_removed_from_an_entity() {
        let mut document = json!({
            "id": "urn:ngsi-ld:Vehicle:1",
            "type": "Vehicle",
            "speed": { "type": "Property", "value": 42 },
            "location": { "type": "GeoProperty", "value": { "type": "Point", "coordinates": [0, 0] } }
        });

        assert_eq!(
            filtered(&mut document, &omitting(&["location"]), &context(), &Term::new("location"), MediaType::Json),
            1
        );
        assert!(at(&document, "/speed").is_some());
        assert!(at(&document, "/location").is_none(), "a policy that omits location must omit location");
    }

    #[test]
    fn an_omitted_core_attribute_spelled_over_http_is_removed() {
        // A broker answering a caller that sent no context names the attribute by its IRI, and a
        // context such as Smart Data Models' writes the core namespace over `http`.
        let mut document = json!({
            "id": "urn:ngsi-ld:Vehicle:1",
            "type": "Vehicle",
            "speed": { "type": "Property", "value": 42 },
            "http://uri.etsi.org/ngsi-ld/location": { "type": "GeoProperty", "value": { "type": "Point", "coordinates": [0, 0] } }
        });

        assert_eq!(
            filtered(&mut document, &omitting(&["location"]), &context(), &Term::new("location"), MediaType::Json),
            1
        );
        assert!(at(&document, "/speed").is_some());
        assert!(at(&document, "/http:~1~1uri.etsi.org~1ngsi-ld~1location").is_none());
    }

    #[test]
    fn structural_members_survive_every_restriction() {
        // Removing `id` or `type` produces a document no NGSI-LD client can read, and `@context`
        // is what the rest of the document means.
        let mut document = json!({
            "id": "urn:ngsi-ld:Vehicle:1",
            "type": "Vehicle",
            "@context": ["https://example.test/ctx.jsonld"],
            "speed": { "type": "Property", "value": 42 }
        });

        filtered(&mut document, &picking(&[]), &context(), &Term::new("location"), MediaType::JsonLd);

        assert!(at(&document, "/id").is_some());
        assert!(at(&document, "/type").is_some());
        assert!(at(&document, "/@context").is_some());
        assert!(at(&document, "/speed").is_none());
    }

    #[test]
    fn an_inline_context_is_left_intact_rather_than_edited() {
        // Recursing into `@context` would delete the term whose name matches an omitted attribute,
        // leaving a document that still uses that term.
        let mut document = json!({
            "id": "urn:ngsi-ld:Vehicle:1",
            "type": "Vehicle",
            "@context": { "location": "https://example.test/location", "speed": "https://example.test/speed" },
            "speed": { "type": "Property", "value": 42 }
        });

        filtered(&mut document, &omitting(&["location"]), &context(), &Term::new("location"), MediaType::JsonLd);

        assert_eq!(
            at(&document, "/@context"),
            Some(&json!({ "location": "https://example.test/location", "speed": "https://example.test/speed" }))
        );
    }

    #[test]
    fn a_nested_value_that_shares_a_name_with_a_restricted_attribute_is_left_alone() {
        // Over-masking: a data key called `location` inside another attribute's value stays in the
        // payload, because filtering does not recurse into values.
        let mut document = json!({
            "id": "urn:ngsi-ld:Vehicle:1",
            "type": "Vehicle",
            "speed": { "type": "Property", "value": { "location": "inside a value", "reading": 42 } }
        });

        filtered(&mut document, &omitting(&["location"]), &context(), &Term::new("location"), MediaType::Json);

        assert_eq!(at(&document, "/speed/value/location"), Some(&json!("inside a value")));
    }

    #[test]
    fn an_array_of_entities_is_filtered_entity_by_entity() {
        let mut document = json!([
            { "id": "urn:ngsi-ld:Vehicle:1", "type": "Vehicle", "location": { "type": "GeoProperty" } },
            { "id": "urn:ngsi-ld:Vehicle:2", "type": "Vehicle", "location": { "type": "GeoProperty" } }
        ]);

        assert_eq!(
            filtered(&mut document, &omitting(&["location"]), &context(), &Term::new("location"), MediaType::Json),
            2
        );
        assert!(at(&document, "/0/location").is_none());
        assert!(at(&document, "/1/location").is_none());
    }

    #[test]
    fn a_temporal_entity_keeps_its_instance_arrays() {
        // Temporal representation puts an array of instances under the attribute name. Filtering
        // is still at the entity's own members, so an allowed attribute keeps every instance.
        let mut document = json!({
            "id": "urn:ngsi-ld:Vehicle:1",
            "type": "Vehicle",
            "speed": [{ "type": "Property", "value": 40 }, { "type": "Property", "value": 42 }],
            "location": [{ "type": "GeoProperty" }]
        });

        filtered(&mut document, &picking(&["speed"]), &context(), &Term::new("location"), MediaType::Json);

        assert_eq!(at(&document, "/speed").and_then(Value::as_array).map(<[Value]>::len), Some(2));
        assert!(at(&document, "/location").is_none());
    }

    #[test]
    fn an_entity_whose_type_is_feature_is_not_mistaken_for_geojson() {
        // `Feature` is a type an ordinary NGSI-LD entity may have, and `properties` is a name an
        // ordinary attribute may carry. Recognising the pair as `GeoJSON` (which is what a filter
        // that reads the body rather than the media type does) sends this document down the
        // Feature branch, where `properties` is the container rather than an attribute and the
        // policy that named it does nothing.
        let mut document = json!({
            "id": "urn:ngsi-ld:Sighting:1",
            "type": "Feature",
            "properties": { "type": "Property", "value": "hidden" },
            "speed": { "type": "Property", "value": 42 }
        });

        let removed = filtered(&mut document, &omitting(&["properties"]), &context(), &Term::new("location"), MediaType::JsonLd);

        assert_eq!(removed, 1);
        assert!(at(&document, "/properties").is_none(), "the restricted attribute must go");
        assert!(at(&document, "/speed").is_some(), "everything else survives");
        assert_eq!(at(&document, "/type"), Some(&json!("Feature")), "the entity's type is not the document's shape");
    }

    #[test]
    fn a_geojson_feature_is_filtered_in_both_places_it_carries_values() {
        // Under `application/geo+json` the hidden attribute is in `properties` *and* projected to
        // `geometry`, and a filter that walks the top-level members sees only `geometry` and
        // `properties`, decides neither is `location`, and returns both.
        let mut document = json!({
            "type": "Feature",
            "id": "urn:ngsi-ld:Vehicle:1",
            "geometry": { "type": "Point", "coordinates": [1, 2] },
            "properties": {
                "type": "Vehicle",
                "speed": { "type": "Property", "value": 42 },
                "location": { "type": "GeoProperty", "value": { "type": "Point", "coordinates": [1, 2] } }
            }
        });

        let removed = filtered(&mut document, &omitting(&["location"]), &context(), &Term::new("location"), MediaType::GeoJson);

        assert_eq!(removed, 2, "the geometry and the property it was projected from");
        assert!(at(&document, "/geometry").is_none(), "the projected copy must go too");
        assert!(at(&document, "/properties/location").is_none());
        assert!(at(&document, "/properties/speed").is_some(), "everything else survives");
    }

    #[test]
    fn a_geojson_feature_keeps_its_geometry_when_the_geoproperty_is_allowed() {
        let mut document = json!({
            "type": "Feature",
            "id": "urn:ngsi-ld:Vehicle:1",
            "geometry": { "type": "Point", "coordinates": [1, 2] },
            "properties": { "type": "Vehicle", "location": { "type": "GeoProperty", "value": {} } }
        });

        let removed = filtered(&mut document, &omitting(&["speed"]), &context(), &Term::new("location"), MediaType::GeoJson);

        assert_eq!(removed, 0);
        assert!(at(&document, "/geometry").is_some());
    }

    #[test]
    fn a_feature_collection_is_filtered_feature_by_feature() {
        let mut document = json!({
            "type": "FeatureCollection",
            "features": [
                { "type": "Feature", "id": "a", "geometry": { "type": "Point", "coordinates": [1, 2] },
                  "properties": { "type": "Vehicle", "location": { "type": "GeoProperty", "value": {} } } },
                { "type": "Feature", "id": "b", "geometry": { "type": "Point", "coordinates": [3, 4] },
                  "properties": { "type": "Vehicle", "speed": { "type": "Property", "value": 1 } } }
            ]
        });

        let removed = filtered(&mut document, &omitting(&["location"]), &context(), &Term::new("location"), MediaType::GeoJson);

        assert_eq!(removed, 3, "two geometries and one location property");
        assert!(at(&document, "/features/0/geometry").is_none());
        assert!(at(&document, "/features/1/geometry").is_none());
        assert!(at(&document, "/features/1/properties/speed").is_some());
    }

    #[test]
    fn a_geometry_projected_from_another_geoproperty_is_judged_by_that_one() {
        // A request naming `observationSpace` gets a geometry projected from it, not from
        // `location`, so that is the attribute whose permission decides.
        let mut document = json!({
            "type": "Feature",
            "id": "a",
            "geometry": { "type": "Point", "coordinates": [1, 2] },
            "properties": { "type": "Vehicle", "speed": { "type": "Property", "value": 1 } }
        });

        let removed = filtered(
            &mut document,
            &omitting(&["observationSpace"]),
            &context(),
            &Term::new("observationSpace"),
            MediaType::GeoJson,
        );

        assert_eq!(removed, 1);
        assert!(at(&document, "/geometry").is_none());
    }

    #[test]
    fn a_member_whose_name_cannot_be_resolved_is_removed() {
        // Keeping a value whose meaning is unknown is the same as not having applied the policy to
        // it. `@` prefixes are keywords, which expand to nothing.
        let bare = ResolvedContext::from_json(r#"{"speed": "https://uri.fiware.org/ns/data-models#speed"}"#).expect("the context should process");
        let mut document = json!({ "id": "x", "type": "Vehicle", "speed": 1, "mystery": 2 });

        filtered(
            &mut document,
            &CompiledAttributeRestriction::new(AttributeAction::Omit, vec![ExpandedIri::new("https://example.test/nothing")]),
            &bare,
            &Term::new("location"),
            MediaType::Json,
        );

        assert!(at(&document, "/speed").is_some());
        assert!(at(&document, "/mystery").is_none(), "an unresolvable name is not allowed");
    }

    #[test]
    fn a_pick_that_allows_nothing_removes_every_attribute() {
        // The engine can produce this: every attribute a policy picked was omitted by another. It
        // is a restriction that allows nothing, not an absent restriction.
        let mut document = json!({ "id": "x", "type": "Vehicle", "speed": 1, "location": 2 });

        assert_eq!(filtered(&mut document, &picking(&[]), &context(), &Term::new("location"), MediaType::Json), 2);
        assert_eq!(document, json!({ "id": "x", "type": "Vehicle" }));
    }

    #[test]
    fn every_occurrence_of_a_repeated_restricted_member_is_removed() {
        // Removing one occurrence and keeping the other would publish exactly what the policy hid
        // to a caller whose parser keeps the last member.
        let mut document = json!({ "id": "x", "type": "Vehicle", "location": 1, "speed": 2, "location": 3 });

        assert_eq!(
            filtered(&mut document, &omitting(&["location"]), &context(), &Term::new("location"), MediaType::Json),
            2
        );
        assert_eq!(document, json!({ "id": "x", "type": "Vehicle", "speed": 2 }));
    }

    #[test]
    fn a_feature_that_repeats_its_geometry_is_not_filtered() {
        let mut document = json!({
            "type": "Feature",
            "id": "a",
            "geometry": { "type": "Point", "coordinates": [1, 2] },
            "geometry": { "type": "Point", "coordinates": [3, 4] },
            "properties": { "type": "Vehicle" }
        });

        assert_eq!(
            filter(&mut document, &omitting(&["location"]), &context(), &Term::new("location"), MediaType::GeoJson),
            Err(Unwalkable::RepeatedMember)
        );
    }

    #[test]
    fn a_feature_that_repeats_its_properties_is_not_filtered() {
        let mut document = json!({
            "type": "Feature",
            "id": "a",
            "properties": { "type": "Vehicle", "location": 1 },
            "properties": { "type": "Vehicle", "speed": 2 }
        });

        assert_eq!(
            filter(&mut document, &omitting(&["location"]), &context(), &Term::new("location"), MediaType::GeoJson),
            Err(Unwalkable::RepeatedMember)
        );
    }
}
