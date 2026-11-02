//! Narrowing the type/attribute metadata index to the entity types a policy allows.
//!
//! `/types`, `/types/{type}`, `/attributes` and `/attributes/{attr}` (NGSI-LD 5.7.5 to 5.7.10)
//! answer with an aggregate over every entity instance in the system. A type restriction that keeps a
//! caller out of a type's entities would otherwise be undone by an index that names the type, lists
//! the types an attribute belongs to, and, for a single type, reports its instance count. A
//! forbidden single type is refused in the layer at request time, by the type in the path; this
//! module edits the aggregates returned for `/types`, `/attributes` and their detailed forms.
//!
//! Only the type dimension is edited here: the type-name list of an `EntityTypeList` (5.2.24), the
//! `EntityType` entries (5.2.25) of a detailed type list, and the `typeNames` of an `Attribute`
//! (5.2.28), whether it stands alone, is an entry of a detailed list, or is one of an
//! `EntityTypeInfo`'s `attributeDetails` (5.2.26). The attribute dimension (attribute-name lists
//! and attribute entries) belongs to the attribute enforcement crate and is narrowed there, so a build
//! carrying both allows narrows both.
//!
//! Fail closed, twice over. A name whose term does not expand under the request context is
//! removed: a name Libra cannot resolve is one it cannot compare with the restriction. And a document
//! that is not one of the index's shapes is not narrowed at all but reported as unrecognised, so
//! the layer withholds it: an index must not disclose what cannot be shown to be allowed.

use jstrict::Value;
use libra_jsonld_term_expansion::{name::Term, resolved::ResolvedContext};
use libra_ngsi_ld_metadata_index::{index_member::IndexMember, index_type::IndexType, name_list::retain_names};
use libra_policy_model::entity_type::CompiledTypeRestriction;

/// Removes from a metadata-index response every entity type the restriction does not allow.
///
/// The document is either a single index object or, for a detailed list, an array of them. Returns
/// the number of names and entries removed, or `None` when the document is not a shape the index
/// answers with.
#[must_use]
pub fn filter(document: &mut Value, restriction: &CompiledTypeRestriction, context: &ResolvedContext) -> Option<usize> {
    let allowed = |name: &str| allows(name, restriction, context);

    match document {
        Value::Array(entries) => filter_list(entries, allowed),
        Value::Object(_) => filter_object(document, allowed),
        Value::Null | Value::Boolean(_) | Value::Number(_) | Value::String(_) => None,
    }
}

/// Filters a detailed list, dropping a forbidden `EntityType` entry outright.
///
/// A detailed type list is an array of `EntityType` objects; a detailed attribute list is an array
/// of `Attribute` objects. Only the former is dropped wholesale: a forbidden type must not be
/// listed at all, while an `Attribute` stays and has its own `typeNames` narrowed. A list holding
/// anything else is not one the index answers with.
fn filter_list(entries: &mut Vec<Value>, allows: impl Fn(&str) -> bool) -> Option<usize> {
    let mut narrowed = 0;

    for entry in entries.iter_mut() {
        narrowed += match IndexType::of(entry) {
            Some(IndexType::EntityType) => 0,
            Some(IndexType::Attribute) => retain_names(entry, IndexMember::TypeNames, &allows)?,
            Some(IndexType::EntityTypeList | IndexType::EntityTypeInfo | IndexType::AttributeList) | None => return None,
        };
    }

    let before = entries.len();
    entries.retain(|entry| IndexType::of(entry) != Some(IndexType::EntityType) || type_allowed(entry, &allows));

    Some(narrowed + before - entries.len())
}

/// Filters the type members of a single index object, by its `type`.
fn filter_object(document: &mut Value, allows: impl Fn(&str) -> bool) -> Option<usize> {
    match IndexType::of(document)? {
        IndexType::EntityTypeList => retain_names(document, IndexMember::TypeList, allows),
        IndexType::Attribute => retain_names(document, IndexMember::TypeNames, allows),
        IndexType::EntityTypeInfo => filter_details(document, allows),
        // Carries attribute names only, which are the attribute enforcement crate's to narrow.
        IndexType::AttributeList => Some(0),
        // The index returns an `EntityType` only as an entry of a detailed list. Alone, it is not a
        // document this module can show it has narrowed.
        IndexType::EntityType => None,
    }
}

/// Narrows the `typeNames` of every `Attribute` in an `EntityTypeInfo`'s `attributeDetails`.
///
/// The type the document describes was checked against the restriction at request time, but each of its
/// attributes lists every type that carries it (NGSI-LD 5.2.26 and 5.2.28), and those include types
/// the restriction forbids.
fn filter_details(document: &mut Value, allows: impl Fn(&str) -> bool) -> Option<usize> {
    let narrow = |detail: &mut Value| match IndexType::of(detail) {
        Some(IndexType::Attribute) => retain_names(detail, IndexMember::TypeNames, &allows),
        Some(IndexType::EntityTypeList | IndexType::EntityType | IndexType::EntityTypeInfo | IndexType::AttributeList) | None => None,
    };

    match IndexMember::AttributeDetails.of_mut(document) {
        Ok(None) => Some(0),
        Ok(Some(Value::Array(details))) => details.iter_mut().map(narrow).sum(),
        // JSON-LD compaction writes a one-element set as the element itself.
        Ok(Some(detail @ Value::Object(_))) => narrow(detail),
        // A repeated `attributeDetails` is one whose narrowing the broker's reader might not see.
        Ok(Some(Value::Null | Value::Boolean(_) | Value::Number(_) | Value::String(_))) | Err(_) => None,
    }
}

/// Whether the restriction allows the type an `EntityType` entry describes.
///
/// `id` is the fully qualified type name (5.2.25) and is preferred; `typeName` is the short name and
/// the fallback. An entry naming neither cannot be shown allowed and is removed, and so is one
/// naming either twice: the fallback is for an entry without an `id`, not for one whose `id` cannot
/// be read.
fn type_allowed(entry: &Value, allows: impl Fn(&str) -> bool) -> bool {
    let name = match IndexMember::Id.of(entry) {
        Ok(Some(id)) => Some(id),
        Ok(None) => IndexMember::TypeName.of(entry).ok().flatten(),
        Err(_) => None,
    };

    name.and_then(Value::as_str).is_some_and(allows)
}

/// Whether the restriction allows a name, by what it expands to rather than by how it is spelled.
fn allows(name: &str, restriction: &CompiledTypeRestriction, context: &ResolvedContext) -> bool {
    context.expand(&Term::new(name)).is_some_and(|iri| restriction.allows(&iri))
}

#[cfg(test)]
mod tests {
    use super::*;
    use jstrict::{
        json,
        object::{Key, Object},
    };
    use libra_policy_model::{entity_type::TypeRestriction, member_on_write::MemberOnWrite, policy::PolicyId};
    use pretty_assertions::assert_eq;
    use std::sync::Arc;

    const CONTEXT: &str = r#"{
        "@vocab": "https://uri.etsi.org/ngsi-ld/default-context/",
        "Vehicle": "https://uri.fiware.org/ns/data-models#Vehicle",
        "Building": "https://uri.fiware.org/ns/data-models#Building",
        "speed": "https://uri.fiware.org/ns/data-models#speed"
    }"#;

    fn context() -> Arc<ResolvedContext> {
        Arc::new(ResolvedContext::from_json(CONTEXT).expect("the test context should process"))
    }

    /// A member of an index object, read as the code under test reads it.
    fn member<'v>(document: &'v Value, name: &str) -> Option<&'v Value> {
        document.as_object()?.get_unique(name).ok()?
    }

    /// The first entry of a list.
    fn first(document: &Value) -> Option<&Value> {
        document.as_array()?.first()
    }

    fn restriction(allowed: &[&str]) -> CompiledTypeRestriction {
        TypeRestriction {
            allowed: allowed.iter().map(|name| Term::new(*name)).collect(),
            type_on_write: MemberOnWrite::Optional,
        }
        .compile(&PolicyId::new("test").unwrap(), &context())
        .expect("the test restriction should compile")
    }

    #[test]
    fn a_forbidden_type_leaves_the_type_list() {
        let mut document = json!({
            "id": "urn:ngsi-ld:EntityTypeList:1",
            "type": "EntityTypeList",
            "typeList": ["Vehicle", "Building"]
        });

        let removed = filter(&mut document, &restriction(&["Vehicle"]), &context()).expect("a metadata-index document");

        assert_eq!(removed, 1);
        assert_eq!(member(&document, "typeList"), Some(&json!(["Vehicle"])));
    }

    #[test]
    fn a_forbidden_type_entry_is_dropped_from_a_detailed_type_list() {
        let mut document = json!([
            { "id": "https://uri.fiware.org/ns/data-models#Vehicle", "type": "EntityType", "typeName": "Vehicle", "attributeNames": ["speed"] },
            { "id": "https://uri.fiware.org/ns/data-models#Building", "type": "EntityType", "typeName": "Building", "attributeNames": ["floors"] }
        ]);

        let removed = filter(&mut document, &restriction(&["Vehicle"]), &context()).expect("a metadata-index document");

        assert_eq!(removed, 1);
        let names: Vec<&str> = document
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|item| member(item, "typeName").and_then(Value::as_str))
            .collect();
        assert_eq!(names, vec!["Vehicle"]);
    }

    #[test]
    fn a_forbidden_type_leaves_an_attributes_type_names() {
        // GET /attributes with details: each Attribute names the types that have it.
        let mut document = json!([
            {
                "id": "https://uri.fiware.org/ns/data-models#speed",
                "type": "Attribute",
                "attributeName": "https://uri.fiware.org/ns/data-models#speed",
                "typeNames": ["Vehicle", "Building"]
            }
        ]);

        let removed = filter(&mut document, &restriction(&["Vehicle"]), &context()).expect("a metadata-index document");

        assert_eq!(removed, 1);
        assert_eq!(first(&document).and_then(|entry| member(entry, "typeNames")), Some(&json!(["Vehicle"])));
        assert_eq!(
            first(&document).and_then(|entry| member(entry, "attributeName")),
            Some(&json!("https://uri.fiware.org/ns/data-models#speed")),
            "the attribute dimension is left to its own crate"
        );
    }

    #[test]
    fn an_entry_named_by_fully_qualified_id_is_matched() {
        let mut document = json!([
            { "id": "https://uri.fiware.org/ns/data-models#Building", "type": "EntityType", "typeName": "Building" }
        ]);

        let removed = filter(&mut document, &restriction(&["Vehicle"]), &context()).expect("a metadata-index document");

        assert_eq!(removed, 1, "the forbidden type is dropped by its FQN id");
        assert_eq!(document.as_array().map(<[Value]>::len), Some(0));
    }

    #[test]
    fn a_name_that_does_not_expand_is_removed() {
        let mut document = json!({
            "id": "urn:ngsi-ld:EntityTypeList:1",
            "type": "EntityTypeList",
            "typeList": ["Vehicle", "@nonsense", 7]
        });

        let removed = filter(&mut document, &restriction(&["Vehicle"]), &context()).expect("a metadata-index document");

        assert_eq!(removed, 2);
        assert_eq!(member(&document, "typeList"), Some(&json!(["Vehicle"])));
    }

    #[test]
    fn a_forbidden_type_leaves_the_type_names_of_a_types_attribute_details() {
        // GET /types/Vehicle: Vehicle is allowed, but its `speed` attribute is shared with Building.
        let mut document = json!({
            "id": "https://uri.fiware.org/ns/data-models#Vehicle",
            "type": "EntityTypeInfo",
            "typeName": "Vehicle",
            "entityCount": 3,
            "attributeDetails": [
                {
                    "id": "https://uri.fiware.org/ns/data-models#speed",
                    "type": "Attribute",
                    "attributeName": "speed",
                    "typeNames": ["Vehicle", "Building"]
                }
            ]
        });

        let removed = filter(&mut document, &restriction(&["Vehicle"]), &context()).expect("a metadata-index document");

        assert_eq!(removed, 1);
        assert_eq!(
            member(&document, "attributeDetails")
                .and_then(first)
                .and_then(|detail| member(detail, "typeNames")),
            Some(&json!(["Vehicle"]))
        );
    }

    #[test]
    fn a_document_that_is_not_an_index_shape_is_not_passed_through() {
        let unrecognised = [
            json!({ "typeList": ["Vehicle", "Building"] }),
            json!({ "type": "Vehicle", "typeList": ["Building"] }),
            json!({ "type": "EntityType", "typeName": "Building" }),
            json!([{ "type": "EntityType", "typeName": "Vehicle" }, { "typeName": "Building" }]),
            json!({ "type": "Attribute", "typeNames": { "Building": 1 } }),
            json!({ "type": "EntityTypeInfo", "typeName": "Vehicle", "attributeDetails": [{ "typeNames": ["Building"] }] }),
            json!("Building"),
        ];

        for mut document in unrecognised {
            assert_eq!(filter(&mut document, &restriction(&["Vehicle"]), &context()), None, "{document}");
        }
    }

    #[test]
    fn an_attribute_list_carries_no_type_members_and_is_left_alone() {
        let mut document = json!({
            "id": "urn:ngsi-ld:AttributeList:1",
            "type": "AttributeList",
            "attributeList": ["speed", "location"]
        });

        let removed = filter(&mut document, &restriction(&["Vehicle"]), &context()).expect("a metadata-index document");

        assert_eq!(removed, 0);
        assert_eq!(
            member(&document, "attributeList"),
            Some(&json!(["speed", "location"])),
            "the attribute dimension is not this crate's to touch"
        );
    }

    #[test]
    fn an_entry_naming_its_id_twice_is_removed_rather_than_judged_by_its_type_name() {
        let mut entry = Object::new();
        entry.push(Key::from("id"), json!("https://uri.fiware.org/ns/data-models#Vehicle"));
        entry.push(Key::from("id"), json!("https://uri.fiware.org/ns/data-models#Building"));
        entry.push(Key::from("type"), json!("EntityType"));
        entry.push(Key::from("typeName"), json!("Vehicle"));
        let mut document = Value::Array(vec![Value::Object(entry)].into());

        assert_eq!(filter(&mut document, &restriction(&["Vehicle"]), &context()), Some(1));
        assert_eq!(document.as_array().map(<[Value]>::len), Some(0));
    }
}
