//! The members of a metadata-index document that name types and attributes.

use crate::repeated_member::RepeatedMember;
use jstrict::Value;
use strum::{Display, IntoStaticStr};

/// A member of a metadata-index document (NGSI-LD 5.2.24 to 5.2.28), spelled as the specification
/// spells it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Display, IntoStaticStr)]
#[strum(serialize_all = "camelCase")]
pub enum IndexMember {
    /// The document's identifier; the fully qualified name of the type or attribute an entry describes.
    Id,
    /// The JSON-LD `@type`, which says which document shape this is.
    Type,
    /// The entity type names of an `EntityTypeList` (5.2.24).
    TypeList,
    /// The short name of the type an `EntityType` or `EntityTypeInfo` describes (5.2.25, 5.2.26).
    TypeName,
    /// The entity types an `Attribute` occurs in (5.2.28).
    TypeNames,
    /// The attribute names of an `AttributeList` (5.2.27).
    AttributeList,
    /// The attribute names an `EntityType` carries (5.2.25).
    AttributeNames,
    /// The full name of the attribute an `Attribute` describes (5.2.28).
    AttributeName,
    /// The `Attribute` entries of an `EntityTypeInfo` (5.2.26).
    AttributeDetails,
}

impl IndexMember {
    /// The member's name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        self.into()
    }

    /// This member of a document, or `None` when the document is not an object or lacks it.
    ///
    /// # Errors
    ///
    /// Returns [`RepeatedMember`] when the document names the member more than once.
    pub fn of(self, document: &Value) -> Result<Option<&Value>, RepeatedMember> {
        match document.as_object() {
            Some(object) => object.get_unique(self.as_str()).map_err(|_| RepeatedMember { member: self }),
            None => Ok(None),
        }
    }

    /// This member of a document, for editing in place, or `None` when the document is not an
    /// object or lacks it.
    ///
    /// # Errors
    ///
    /// Returns [`RepeatedMember`] when the document names the member more than once.
    pub fn of_mut(self, document: &mut Value) -> Result<Option<&mut Value>, RepeatedMember> {
        match document.as_object_mut() {
            Some(object) => object.get_unique_mut(self.as_str()).map_err(|_| RepeatedMember { member: self }),
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jstrict::json;
    use pretty_assertions::assert_eq;

    #[test]
    fn members_are_spelled_as_the_specification_spells_them() {
        assert_eq!(IndexMember::Id.as_str(), "id");
        assert_eq!(IndexMember::TypeList.as_str(), "typeList");
        assert_eq!(IndexMember::TypeNames.as_str(), "typeNames");
        assert_eq!(IndexMember::AttributeDetails.as_str(), "attributeDetails");
    }

    #[test]
    fn a_member_is_read_from_an_object_and_is_absent_from_anything_else() {
        assert_eq!(IndexMember::Id.of(&json!({ "id": "urn:a" })), Ok(Some(&json!("urn:a"))));
        assert_eq!(IndexMember::Id.of(&json!({ "type": "Attribute" })), Ok(None));
        assert_eq!(IndexMember::Id.of(&json!(["id"])), Ok(None));
    }

    #[test]
    fn a_repeated_member_is_reported_rather_than_read() {
        let mut document = json!({ "id": "urn:a", "id": "urn:b" });
        let repeated = RepeatedMember { member: IndexMember::Id };

        assert_eq!(IndexMember::Id.of(&document), Err(repeated));
        assert_eq!(IndexMember::Id.of_mut(&mut document).err(), Some(repeated));
    }
}
