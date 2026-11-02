//! Which entity types a registration registers.

use crate::{
    error::Unreadable,
    registration::{ENTITIES_MEMBER, INFORMATION_MEMBER, objects, unique},
};
use jstrict::{Object, Value};
use libra_jsonld_term_expansion::name::Term;

/// The member of an `EntityInfo` that names its entity type or types (NGSI-LD 5.2.8).
const TYPE_MEMBER: &str = "type";

/// The entity types a registration registers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Coverage {
    /// Entities of these types, and of no other, as authored.
    Types(Vec<Term>),
    /// Entities of every type: some `RegistrationInfo` names no `entities`, so it registers its
    /// attributes for whatever entity has them (NGSI-LD 5.2.10).
    Every,
}

/// The entity types a registration, or an update fragment carrying `information`, registers.
///
/// Every `EntityInfo` of every `RegistrationInfo` contributes its `type`, which NGSI-LD allows to
/// be one name or several. One `RegistrationInfo` without `entities` makes the coverage
/// [`Coverage::Every`].
///
/// # Errors
///
/// Returns [`Unreadable`] when `information` is absent, empty or not a list of objects, when an
/// `entities` member is empty or not a list of objects, and when an `EntityInfo` has no `type` or
/// one that is neither a string nor a non-empty list of strings, and when any of the members it
/// reads is named twice.
pub fn entity_types(registration: &Object) -> Result<Coverage, Unreadable> {
    let information = objects(
        unique(registration, INFORMATION_MEMBER)?,
        "its information is not a list of RegistrationInfo objects",
    )?
    .ok_or(Unreadable {
        reason: "it carries no information",
    })?;

    let mut types = Vec::new();

    for info in information {
        let Some(entities) = objects(unique(info, ENTITIES_MEMBER)?, "its entities are not a list of EntityInfo objects")? else {
            return Ok(Coverage::Every);
        };

        for entity in entities {
            types.extend(types_of(entity)?);
        }
    }

    Ok(Coverage::Types(types))
}

/// The types one `EntityInfo` names.
fn types_of(entity: &Object) -> Result<Vec<Term>, Unreadable> {
    let unreadable = Unreadable {
        reason: "an EntityInfo type is not an entity type name or a list of them",
    };

    match unique(entity, TYPE_MEMBER)? {
        Some(Value::String(name)) => Ok(vec![Term::new(name.as_str())]),
        Some(Value::Array(names)) if !names.is_empty() => names.iter().map(|name| name.as_str().map(Term::new).ok_or(unreadable)).collect(),
        None | Some(Value::Null | Value::Boolean(_) | Value::Number(_) | Value::Array(_) | Value::Object(_)) => Err(unreadable),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jstrict::json;
    use pretty_assertions::assert_eq;

    fn coverage(registration: &Value) -> Result<Coverage, Unreadable> {
        entity_types(registration.as_object().expect("the test registration is an object"))
    }

    fn types(names: &[&str]) -> Coverage {
        Coverage::Types(names.iter().map(|name| Term::new(*name)).collect())
    }

    #[test]
    fn the_types_of_the_entity_selectors_are_the_coverage() {
        assert_eq!(
            coverage(&json!({ "information": [{ "entities": [{ "type": "Vehicle" }] }] })),
            Ok(types(&["Vehicle"]))
        );
    }

    #[test]
    fn several_infos_and_several_types_are_one_union() {
        let registration = json!({ "information": [
            { "entities": [{ "type": "Vehicle" }, { "type": ["Building", "Sensor"], "idPattern": ".*" }] },
            { "entities": [{ "type": "Garage" }], "propertyNames": ["name"] }
        ] });

        assert_eq!(coverage(&registration), Ok(types(&["Vehicle", "Building", "Sensor", "Garage"])));
    }

    #[test]
    fn an_info_compacted_out_of_its_array_is_read_as_one() {
        assert_eq!(
            coverage(&json!({ "information": { "entities": { "type": "Vehicle" } } })),
            Ok(types(&["Vehicle"]))
        );
    }

    #[test]
    fn an_info_without_entities_registers_every_type() {
        let registration = json!({ "information": [
            { "entities": [{ "type": "Vehicle" }] },
            { "propertyNames": ["speed"] }
        ] });

        assert_eq!(coverage(&registration), Ok(Coverage::Every));
    }

    #[test]
    fn a_registration_whose_types_cannot_be_read_is_unreadable() {
        for registration in [
            json!({ "information": [{ "entities": [{ "type": 7 }] }] }),
            json!({ "information": [{ "entities": [{ "id": "urn:e:1" }] }] }),
            json!({ "information": [{ "entities": [{ "type": [] }] }] }),
            json!({ "information": [{ "entities": [{ "type": ["Vehicle", 1] }] }] }),
            json!({ "information": [{ "entities": [] }] }),
            json!({ "information": [] }),
            json!({ "information": "Vehicle" }),
            json!({ "endpoint": "http://source.test" }),
            json!({ "information": [{ "entities": [{ "type": "Vehicle", "type": "Building" }] }] }),
            json!({ "information": [{ "entities": [{ "type": "Vehicle" }], "entities": [{ "type": "Building" }] }] }),
            json!({ "information": [], "information": [{ "entities": [{ "type": "Vehicle" }] }] }),
        ] {
            assert!(coverage(&registration).is_err(), "{registration}");
        }
    }
}
