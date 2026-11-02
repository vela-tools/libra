//! The `type` of a metadata-index document.

use crate::{index_member::IndexMember, repeated_member::RepeatedMember};
use jstrict::Value;
use strum::{EnumString, IntoStaticStr};

/// The JSON-LD `@type` of a document the metadata index answers with (NGSI-LD 5.2.24 to 5.2.28).
///
/// Spelled exactly as the specification names the types, which is how the core context compacts
/// them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumString, IntoStaticStr)]
pub enum IndexType {
    /// A list of entity type names, answering `/types` (5.2.24).
    EntityTypeList,
    /// One entry of a detailed type list, answering `/types?details=true` (5.2.25).
    EntityType,
    /// One type in detail, answering `/types/{type}` (5.2.26).
    EntityTypeInfo,
    /// A list of attribute names, answering `/attributes` (5.2.27).
    AttributeList,
    /// One attribute, answering `/attributes/{attr}` or as an entry of a detailed list (5.2.28).
    Attribute,
}

impl IndexType {
    /// The type of an index document, or `None` when it names no type, one the index does not
    /// use, or its `type` member twice.
    #[must_use]
    pub fn of(document: &Value) -> Option<IndexType> {
        match IndexMember::Type.of(document) {
            Ok(member) => member.and_then(Value::as_str).and_then(|name| name.parse().ok()),
            // A document naming two types is not one shape or the other, and every caller already
            // refuses a document whose shape it does not recognise.
            Err(RepeatedMember { .. }) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jstrict::json;
    use pretty_assertions::assert_eq;

    #[test]
    fn a_document_is_known_by_its_type_member() {
        assert_eq!(IndexType::of(&json!({ "type": "EntityTypeInfo" })), Some(IndexType::EntityTypeInfo));
        assert_eq!(IndexType::of(&json!({ "type": "Attribute" })), Some(IndexType::Attribute));
    }

    #[test]
    fn a_document_without_a_type_the_index_uses_is_not_recognised() {
        assert_eq!(IndexType::of(&json!({ "typeList": ["Vehicle"] })), None);
        assert_eq!(IndexType::of(&json!({ "type": "Vehicle" })), None);
        assert_eq!(
            IndexType::of(&json!({ "type": "entitytypelist" })),
            None,
            "the type is spelled as the specification spells it"
        );
        assert_eq!(IndexType::of(&json!({ "type": ["EntityTypeList"] })), None);
        assert_eq!(IndexType::of(&json!("EntityTypeList")), None);
    }

    #[test]
    fn a_document_naming_its_type_twice_is_not_recognised() {
        assert_eq!(IndexType::of(&json!({ "type": "Attribute", "type": "Attribute" })), None);
        assert_eq!(IndexType::of(&json!({ "type": "EntityTypeList", "type": "Attribute" })), None);
    }
}
