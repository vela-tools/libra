//! The entities a write that may overwrite stored ones names, each of which is pre-flighted.
//!
//! A batch upsert, update or merge (NGSI-LD clauses 5.6.8, 5.6.9 and 5.6.20) and a temporal create
//! (clause 5.6.11) carry whole entities, with the `type` and `scope` the caller declares. Judging
//! the declared members alone lets a caller declare an allowed type over an entity stored under a
//! forbidden one and change it. Each entity is therefore judged as stored, as a by-id write is; an
//! entity the broker does not hold is created by the write, with the members the body declares,
//! which the body check already judged.

use crate::error::PreflightError;
use http::StatusCode;
use jstrict::{Value, object::Object};
use libra_ngsi_ld_operation::resource::ResourceId;
use thiserror::Error;

/// The member an entity carries its identifier in.
const ID_MEMBER: &str = "id";

/// A write body whose entities do not each carry one identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("every entity of the write carries one string 'id'")]
pub struct MalformedEntityWrite;

/// What the broker holds for one entity a write names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoredEntity {
    /// The entity as stored.
    Held(Value),
    /// Nothing: the broker answered 404, so the write creates the entity.
    Absent,
}

impl StoredEntity {
    /// Reads one pre-flight answer.
    ///
    /// # Errors
    ///
    /// Returns the [`PreflightError`] of any failure other than a 404: an entity whose existence
    /// cannot be established is one the write might overwrite.
    pub fn of(answer: Result<Value, PreflightError>) -> Result<Self, PreflightError> {
        match answer {
            Ok(entity) => Ok(Self::Held(entity)),
            Err(PreflightError::Status { status: StatusCode::NOT_FOUND }) => Ok(Self::Absent),
            Err(error) => Err(error),
        }
    }
}

/// The identifiers of the entities a write body carries: one entity, or an array of them.
///
/// # Errors
///
/// Returns [`MalformedEntityWrite`] when the body is neither, or an entity carries no `id`, one
/// that is not a string, or `id` twice.
pub fn identifiers_of(document: &Value) -> Result<Vec<ResourceId>, MalformedEntityWrite> {
    match document {
        Value::Object(entity) => Ok(vec![identifier_of(entity)?]),
        Value::Array(items) => items
            .iter()
            .map(|item| match item {
                Value::Object(entity) => identifier_of(entity),
                Value::Null | Value::Boolean(_) | Value::Number(_) | Value::String(_) | Value::Array(_) => Err(MalformedEntityWrite),
            })
            .collect(),
        Value::Null | Value::Boolean(_) | Value::Number(_) | Value::String(_) => Err(MalformedEntityWrite),
    }
}

/// The identifier of one entity.
fn identifier_of(entity: &Object) -> Result<ResourceId, MalformedEntityWrite> {
    match entity.get_unique(ID_MEMBER).map_err(|_| MalformedEntityWrite)? {
        Some(Value::String(id)) => Ok(ResourceId::new(id.as_str())),
        Some(Value::Null | Value::Boolean(_) | Value::Number(_) | Value::Array(_) | Value::Object(_)) | None => Err(MalformedEntityWrite),
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        batch_write::{MalformedEntityWrite, StoredEntity, identifiers_of},
        error::PreflightError,
    };
    use http::StatusCode;
    use jstrict::{
        Value,
        json,
        object::{Key, Object},
    };
    use libra_ngsi_ld_operation::resource::ResourceId;
    use pretty_assertions::assert_eq;

    #[test]
    fn a_batch_names_the_identifier_of_each_entity() {
        assert_eq!(
            identifiers_of(&json!([{ "id": "urn:a", "type": "T" }, { "id": "urn:b" }])),
            Ok(vec![ResourceId::new("urn:a"), ResourceId::new("urn:b")])
        );
    }

    #[test]
    fn a_single_entity_names_its_own_identifier() {
        assert_eq!(identifiers_of(&json!({ "id": "urn:a", "type": "T" })), Ok(vec![ResourceId::new("urn:a")]));
    }

    #[test]
    fn an_entity_without_a_string_identifier_is_malformed() {
        assert_eq!(identifiers_of(&json!([{ "type": "T" }])), Err(MalformedEntityWrite));
        assert_eq!(identifiers_of(&json!([{ "id": 7 }])), Err(MalformedEntityWrite));
        assert_eq!(identifiers_of(&json!(["urn:a"])), Err(MalformedEntityWrite));
        assert_eq!(identifiers_of(&json!("urn:a")), Err(MalformedEntityWrite));
    }

    #[test]
    fn a_repeated_identifier_member_is_malformed_rather_than_one_occurrence_read() {
        let mut entity = Object::new();
        entity.push(Key::from("id"), json!("urn:allowed"));
        entity.push(Key::from("id"), json!("urn:other"));

        assert_eq!(identifiers_of(&Value::Array(vec![Value::Object(entity)].into())), Err(MalformedEntityWrite));
    }

    #[test]
    fn a_not_found_answer_is_an_absent_entity_and_every_other_failure_an_error() {
        assert_eq!(
            StoredEntity::of(Err(PreflightError::Status { status: StatusCode::NOT_FOUND })),
            Ok(StoredEntity::Absent)
        );
        assert_eq!(StoredEntity::of(Ok(json!({ "id": "urn:a" }))), Ok(StoredEntity::Held(json!({ "id": "urn:a" }))));
        assert_eq!(
            StoredEntity::of(Err(PreflightError::Status {
                status: StatusCode::INTERNAL_SERVER_ERROR
            })),
            Err(PreflightError::Status {
                status: StatusCode::INTERNAL_SERVER_ERROR
            })
        );
        assert_eq!(StoredEntity::of(Err(PreflightError::TooLarge)), Err(PreflightError::TooLarge));
    }
}
