//! The entities a batch delete names, each of which is pre-flighted.

use jstrict::Value;
use libra_ngsi_ld_operation::resource::ResourceId;
use thiserror::Error;

/// A batch delete body that is not an array of entity identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("a batch delete body is an array of entity identifiers")]
pub struct MalformedBatchDelete;

/// The identifiers a batch delete names.
///
/// `POST /entityOperations/delete` sends an array of entity identifiers, not entities (NGSI-LD
/// clause 5.6.10). An entity check finds no `type` or `scope` member on a string, so judged as
/// entities, every batch delete under a policy requiring either on write would be refused.
///
/// # Errors
///
/// Returns [`MalformedBatchDelete`] if the body is not an array of strings.
pub fn identifiers_of(document: &Value) -> Result<Vec<ResourceId>, MalformedBatchDelete> {
    let Value::Array(items) = document else {
        return Err(MalformedBatchDelete);
    };

    items
        .iter()
        .map(|item| match item {
            Value::String(id) => Ok(ResourceId::new(id.as_str())),
            Value::Null | Value::Boolean(_) | Value::Number(_) | Value::Array(_) | Value::Object(_) => Err(MalformedBatchDelete),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::batch_delete::{MalformedBatchDelete, identifiers_of};
    use jstrict::json;
    use libra_ngsi_ld_operation::resource::ResourceId;
    use pretty_assertions::assert_eq;

    #[test]
    fn a_batch_delete_body_is_a_list_of_identifiers() {
        assert_eq!(
            identifiers_of(&json!(["urn:ngsi-ld:Vehicle:1", "urn:ngsi-ld:Vehicle:2"])),
            Ok(vec![ResourceId::new("urn:ngsi-ld:Vehicle:1"), ResourceId::new("urn:ngsi-ld:Vehicle:2")])
        );
    }

    #[test]
    fn an_array_of_entities_is_not_a_batch_delete_body() {
        assert_eq!(identifiers_of(&json!([{ "id": "urn:e:1" }])), Err(MalformedBatchDelete));
    }

    #[test]
    fn a_body_that_is_not_an_array_is_not_a_batch_delete_body() {
        assert_eq!(identifiers_of(&json!("urn:e:1")), Err(MalformedBatchDelete));
    }

    #[test]
    fn an_empty_array_names_nothing() {
        assert_eq!(identifiers_of(&json!([])), Ok(Vec::new()));
    }
}
