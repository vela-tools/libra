//! Narrowing the type/attribute metadata index to the attributes a policy allows.
//!
//! `/types`, `/types/{type}`, `/attributes` and `/attributes/{attr}` (NGSI-LD 5.7.5 to 5.7.10)
//! answer with names aggregated over every entity instance in the system, not with entity data. The
//! aggregate still discloses what data exists: an omit or pick restriction that keeps an attribute out of
//! every entity read would otherwise be undone by an index that lists the attribute's name, states
//! which types carry it, and, for a single attribute, counts its instances.
//!
//! This module edits only the attribute dimension of that aggregate: the attribute-name lists in
//! `AttributeList` (5.2.27) and `EntityType` (5.2.25), and the `Attribute` entries (5.2.28) of a
//! detailed attribute list or of an `EntityTypeInfo` (5.2.26). The type dimension (the type-name
//! lists and the `typeNames` of an attribute) belongs to the entity-type enforcement crate and is
//! narrowed there, so a build carrying both allows narrows both.
//!
//! Fail closed, twice over. A name whose term does not expand under the request context is
//! removed, matching the reading the response filter uses for an entity member: a name Libra cannot
//! resolve is a name it cannot prove the restriction allows. And a document that is not one of the
//! index's shapes is not narrowed at all but reported as unrecognised, so the layer withholds it.

use crate::document::allows;
use jstrict::{Array, Value};
use libra_jsonld_term_expansion::resolved::ResolvedContext;
use libra_ngsi_ld_metadata_index::{index_member::IndexMember, index_type::IndexType, name_list::retain_names};
use libra_policy_model::attribute::CompiledAttributeRestriction;

/// Removes from a metadata-index response every attribute name the restriction does not allow.
///
/// The document is either a single index object or, for a detailed list, an array of them. Returns
/// the number of names and entries removed, for the same logging the entity response filter emits,
/// or `None` when the document is not a shape the index answers with.
#[must_use]
pub fn filter(document: &mut Value, restriction: &CompiledAttributeRestriction, context: &ResolvedContext) -> Option<usize> {
    let allowed = |name: &str| allows(restriction, name, context);

    match document {
        Value::Array(entries) => filter_list(entries, allowed),
        Value::Object(_) => filter_object(document, allowed),
        Value::Null | Value::Boolean(_) | Value::Number(_) | Value::String(_) => None,
    }
}

/// Filters a detailed list, dropping a forbidden `Attribute` entry outright.
///
/// A detailed attribute list is an array of `Attribute` objects; a detailed type list is an array of
/// `EntityType` objects. Only the former is dropped wholesale: a forbidden attribute must not be
/// listed at all, while an `EntityType` stays and has its own attribute names narrowed. A list
/// holding anything else is not one the index answers with.
fn filter_list(entries: &mut Array, allows: impl Fn(&str) -> bool) -> Option<usize> {
    let mut narrowed = 0;

    for entry in entries.iter_mut() {
        narrowed += match IndexType::of(entry) {
            Some(IndexType::EntityType) => retain_names(entry, IndexMember::AttributeNames, &allows)?,
            Some(IndexType::Attribute) => 0,
            Some(IndexType::EntityTypeList | IndexType::EntityTypeInfo | IndexType::AttributeList) | None => return None,
        };
    }

    let before = entries.len();
    entries.retain(|entry| IndexType::of(entry) != Some(IndexType::Attribute) || attribute_allowed(entry, &allows));

    Some(narrowed + before - entries.len())
}

/// Filters the attribute-name members of a single index object, by its `type`.
fn filter_object(document: &mut Value, allows: impl Fn(&str) -> bool) -> Option<usize> {
    match IndexType::of(document)? {
        IndexType::AttributeList => retain_names(document, IndexMember::AttributeList, allows),
        IndexType::EntityTypeInfo => filter_details(document, allows),
        // `/attributes/{attr}` is refused at request time when the attribute is forbidden, so a
        // forbidden one here means the path and the answer disagree about which attribute this is.
        IndexType::Attribute => attribute_allowed(document, allows).then_some(0),
        // Carries type names only, which are the entity-type enforcement crate's to narrow.
        IndexType::EntityTypeList => Some(0),
        // The index returns an `EntityType` only as an entry of a detailed list. Alone, it is not a
        // document this module can show it has narrowed.
        IndexType::EntityType => None,
    }
}

/// Removes forbidden `Attribute` entries from an `EntityTypeInfo`'s `attributeDetails`.
fn filter_details(document: &mut Value, allows: impl Fn(&str) -> bool) -> Option<usize> {
    let is_attribute = |detail: &Value| IndexType::of(detail) == Some(IndexType::Attribute);

    match IndexMember::AttributeDetails.of_mut(document) {
        Ok(None) => Some(0),
        Ok(Some(Value::Array(details))) => {
            if !details.iter().all(is_attribute) {
                return None;
            }

            let before = details.len();
            details.retain(|detail| attribute_allowed(detail, &allows));

            Some(before - details.len())
        }
        // JSON-LD compaction writes a one-element set as the element itself.
        Ok(Some(detail @ Value::Object(_))) => {
            if !is_attribute(detail) {
                return None;
            }
            if attribute_allowed(detail, &allows) {
                return Some(0);
            }

            *detail = Value::Array(Array::new());
            Some(1)
        }
        // A repeated `attributeDetails` is refused: the occurrence narrowed here need not be the
        // one the caller reads.
        Ok(Some(Value::Null | Value::Boolean(_) | Value::Number(_) | Value::String(_))) | Err(_) => None,
    }
}

/// Whether the restriction allows the attribute an `Attribute` entry describes.
///
/// `attributeName` is the attribute's full URI (5.2.28); `id` carries it too and is the fallback. An
/// entry naming neither cannot be shown to be allowed and is removed. So is one that repeats
/// `attributeName`, rather than falling back to `id`: the repeated member is still the one a caller
/// reads, and `id` says nothing about which occurrence that is.
fn attribute_allowed(entry: &Value, allows: impl Fn(&str) -> bool) -> bool {
    let name = IndexMember::AttributeName
        .of(entry)
        .and_then(|name| name.map_or_else(|| IndexMember::Id.of(entry), |name| Ok(Some(name))));

    name.ok().flatten().and_then(Value::as_str).is_some_and(allows)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pointer::at;
    use jstrict::json;
    use libra_jsonld_term_expansion::name::{ExpandedIri, Term};
    use libra_policy_model::attribute::AttributeAction;
    use pretty_assertions::assert_eq;
    use std::sync::Arc;

    fn context() -> Arc<ResolvedContext> {
        Arc::new(
            ResolvedContext::from_json(
                r#"{
                    "@vocab": "https://uri.etsi.org/ngsi-ld/default-context/",
                    "speed": "https://uri.fiware.org/ns/data-models#speed",
                    "location": "https://uri.etsi.org/ngsi-ld/location"
                }"#,
            )
            .expect("the test context should process"),
        )
    }

    fn iri(term: &str) -> ExpandedIri {
        context().expand(&Term::new(term)).expect("the term should expand")
    }

    fn restriction(action: AttributeAction, terms: &[&str]) -> CompiledAttributeRestriction {
        CompiledAttributeRestriction::new(action, terms.iter().map(|term| iri(term)).collect())
    }

    #[test]
    fn an_omitted_attribute_name_leaves_the_attribute_list() {
        let mut document = json!({
            "id": "urn:ngsi-ld:AttributeList:1",
            "type": "AttributeList",
            "attributeList": ["speed", "location"]
        });

        let removed = filter(&mut document, &restriction(AttributeAction::Omit, &["location"]), &context()).expect("a metadata-index document");

        assert_eq!(removed, 1);
        assert_eq!(at(&document, "/attributeList"), Some(&json!(["speed"])));
    }

    #[test]
    fn a_pick_leaves_only_the_listed_attribute_names() {
        let mut document = json!({
            "id": "urn:ngsi-ld:AttributeList:1",
            "type": "AttributeList",
            "attributeList": ["speed", "location"]
        });

        let removed = filter(&mut document, &restriction(AttributeAction::Pick, &["speed"]), &context()).expect("a metadata-index document");

        assert_eq!(removed, 1);
        assert_eq!(at(&document, "/attributeList"), Some(&json!(["speed"])));
    }

    #[test]
    fn a_hidden_attribute_name_leaves_a_detailed_type_entry() {
        // GET /types with details: an array of EntityType, each listing the attribute names its
        // instances carry.
        let mut document = json!([
            {
                "id": "https://uri.fiware.org/ns/data-models#Vehicle",
                "type": "EntityType",
                "typeName": "Vehicle",
                "attributeNames": ["speed", "location"]
            }
        ]);

        let removed = filter(&mut document, &restriction(AttributeAction::Omit, &["location"]), &context()).expect("a metadata-index document");

        assert_eq!(removed, 1);
        assert_eq!(at(&document, "/0/attributeNames"), Some(&json!(["speed"])));
    }

    #[test]
    fn a_forbidden_attribute_entry_is_dropped_from_a_detailed_attribute_list() {
        // GET /attributes with details: an array of Attribute, one per attribute name.
        let mut document = json!([
            { "id": "https://uri.fiware.org/ns/data-models#speed", "type": "Attribute", "attributeName": "https://uri.fiware.org/ns/data-models#speed" },
            { "id": "https://uri.etsi.org/ngsi-ld/location", "type": "Attribute", "attributeName": "https://uri.etsi.org/ngsi-ld/location" }
        ]);

        let removed = filter(&mut document, &restriction(AttributeAction::Omit, &["location"]), &context()).expect("a metadata-index document");

        assert_eq!(removed, 1);
        let names: Vec<&str> = document
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|item| at(item, "/attributeName").and_then(Value::as_str))
            .collect();
        assert_eq!(names, vec!["https://uri.fiware.org/ns/data-models#speed"]);
    }

    #[test]
    fn a_forbidden_attribute_detail_is_dropped_from_entity_type_info() {
        // GET /types/{type}: EntityTypeInfo whose attributeDetails is an array of Attribute.
        let mut document = json!({
            "id": "https://uri.fiware.org/ns/data-models#Vehicle",
            "type": "EntityTypeInfo",
            "typeName": "Vehicle",
            "entityCount": 7,
            "attributeDetails": [
                { "id": "https://uri.fiware.org/ns/data-models#speed", "type": "Attribute", "attributeName": "https://uri.fiware.org/ns/data-models#speed" },
                { "id": "https://uri.etsi.org/ngsi-ld/location", "type": "Attribute", "attributeName": "https://uri.etsi.org/ngsi-ld/location" }
            ]
        });

        let removed = filter(&mut document, &restriction(AttributeAction::Pick, &["speed"]), &context()).expect("a metadata-index document");

        assert_eq!(removed, 1);
        assert_eq!(at(&document, "/attributeDetails").and_then(Value::as_array).map(<[Value]>::len), Some(1));
        assert_eq!(at(&document, "/entityCount"), Some(&json!(7)), "the count is not this dimension's to edit");
    }

    #[test]
    fn a_name_that_does_not_expand_is_removed() {
        // Fail closed: a name whose term has no meaning under the context cannot be shown allowed.
        let mut document = json!({
            "id": "urn:ngsi-ld:AttributeList:1",
            "type": "AttributeList",
            "attributeList": ["speed", 42, "@nonsense"]
        });

        let removed = filter(&mut document, &restriction(AttributeAction::Omit, &["location"]), &context()).expect("a metadata-index document");

        assert_eq!(removed, 2, "the number and the keyword-shaped name both go");
        assert_eq!(at(&document, "/attributeList"), Some(&json!(["speed"])));
    }

    #[test]
    fn a_document_that_is_not_an_index_shape_is_not_passed_through() {
        let unrecognised = [
            json!({ "attributeList": ["speed", "location"] }),
            json!({ "type": "Vehicle", "attributeList": ["location"] }),
            json!({ "type": "EntityType", "attributeNames": ["location"] }),
            json!([{ "type": "Attribute", "attributeName": "speed" }, { "attributeName": "location" }]),
            json!({ "type": "AttributeList", "attributeList": { "location": 1 } }),
            json!({ "type": "EntityTypeInfo", "attributeDetails": [{ "attributeName": "location" }] }),
            json!(42),
        ];

        for mut document in unrecognised {
            assert_eq!(
                filter(&mut document, &restriction(AttributeAction::Omit, &["location"]), &context()),
                None,
                "{document}"
            );
        }
    }

    #[test]
    fn a_lone_attribute_the_restriction_forbids_is_not_passed_through() {
        let mut document = json!({ "id": "https://uri.etsi.org/ngsi-ld/location", "type": "Attribute", "attributeName": "location" });

        assert_eq!(filter(&mut document, &restriction(AttributeAction::Omit, &["location"]), &context()), None);
    }

    #[test]
    fn an_entity_type_list_carries_no_attribute_members_and_is_left_alone() {
        let mut document = json!({
            "id": "urn:ngsi-ld:EntityTypeList:1",
            "type": "EntityTypeList",
            "typeList": ["Vehicle", "Building"]
        });

        let removed = filter(&mut document, &restriction(AttributeAction::Omit, &["location"]), &context()).expect("a metadata-index document");

        assert_eq!(removed, 0);
        assert_eq!(
            at(&document, "/typeList"),
            Some(&json!(["Vehicle", "Building"])),
            "the type dimension is not this crate's to touch"
        );
    }

    #[test]
    fn an_attribute_entry_that_repeats_its_name_is_dropped_rather_than_judged_by_its_id() {
        // The `id` names an allowed attribute, but the caller reads one of the two
        // `attributeName`s, and either may be the forbidden one.
        let mut document = json!([
            {
                "id": "https://uri.fiware.org/ns/data-models#speed",
                "type": "Attribute",
                "attributeName": "https://uri.fiware.org/ns/data-models#speed",
                "attributeName": "https://uri.etsi.org/ngsi-ld/location"
            }
        ]);

        let removed = filter(&mut document, &restriction(AttributeAction::Omit, &["location"]), &context()).expect("a metadata-index document");

        assert_eq!(removed, 1);
        assert_eq!(document, json!([]));
    }

    #[test]
    fn entity_type_info_that_repeats_its_details_is_not_passed_through() {
        let mut document = json!({
            "type": "EntityTypeInfo",
            "attributeDetails": [],
            "attributeDetails": [{ "type": "Attribute", "attributeName": "location" }]
        });

        assert_eq!(filter(&mut document, &restriction(AttributeAction::Omit, &["location"]), &context()), None);
    }

    #[test]
    fn a_single_attribute_detail_written_as_an_object_is_judged_like_a_one_entry_list() {
        // JSON-LD compaction writes a one-element set as the element itself.
        let speed = || json!({ "id": "https://uri.fiware.org/ns/data-models#speed", "type": "Attribute", "attributeName": "https://uri.fiware.org/ns/data-models#speed" });
        let info = |detail: Value| json!({ "type": "EntityTypeInfo", "typeName": "Vehicle", "attributeDetails": detail });

        let mut allowed = info(speed());
        assert_eq!(filter(&mut allowed, &restriction(AttributeAction::Pick, &["speed"]), &context()), Some(0));
        assert_eq!(allowed, info(speed()));

        let mut forbidden = info(speed());
        assert_eq!(filter(&mut forbidden, &restriction(AttributeAction::Omit, &["speed"]), &context()), Some(1));
        assert_eq!(forbidden, info(json!([])));

        let mut not_an_attribute = info(json!({ "type": "EntityType", "attributeNames": ["speed"] }));
        assert_eq!(filter(&mut not_an_attribute, &restriction(AttributeAction::Pick, &["speed"]), &context()), None);
    }
}
