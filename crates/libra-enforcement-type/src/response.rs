//! Filtering a successful answer to the allowed entity types.
//!
//! Three answers carry types the request side cannot narrow. A metadata index aggregates over every
//! instance (see [`crate::index`]). A join answer (NGSI-LD clause 4.5.23) holds the entities the
//! queried ones link to, of whatever type those are. And a list of entities answering a query holds
//! whatever the broker matched: an entity of two types is matched by a selection naming either
//! (clause 4.17), so `type=Vehicle` answers with an entity that is also of a forbidden type. All
//! three are filtered here on the way back, and withheld whole when they cannot be read.

use crate::{document::types_of, error::TypeError, index, names};
use axum::response::Response;
use libra_enforcement_member::{location::Location, unfilterable::unfilterable_reason};
use libra_jsonld_term_expansion::resolved::ResolvedContext;
use libra_ngsi_ld_entity_document::{
    entities::{Entity, retain_entities},
    linked::{Visibility, judge_linked},
    unwalkable::Unwalkable,
};
use libra_ngsi_ld_query::linked_entity::JoinMode;
use libra_policy_model::entity_type::CompiledTypeRestriction;
use libra_response_json::{error::RewriteError, rewrite::rewrite};
use tracing::debug;

/// The edit of a metadata-index answer that is not an index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NotAnIndex;

/// Removes from a metadata-index response every entity type the restriction does not allow.
///
/// # Errors
///
/// Returns [`TypeError::Unfilterable`] when the body cannot be read or is not an index document.
pub async fn filter_index_response(
    response: Response,
    restriction: &CompiledTypeRestriction,
    context: &ResolvedContext,
    max_body_bytes: usize,
) -> Result<Response, TypeError> {
    rewrite(response, max_body_bytes, |document, _media_type| {
        let removed = index::filter(document, restriction, context).ok_or(NotAnIndex)?;
        debug!(removed, "narrowed the metadata index to the allowed types");

        Ok(())
    })
    .await
    .map_err(|error| TypeError::Unfilterable {
        reason: match error {
            RewriteError::Unreadable(unreadable) => unreadable.reason(),
            RewriteError::Edit(NotAnIndex) => "the response is not a metadata-index document",
        },
    })
}

/// Withholds every linked entity of a join answer that is not of an allowed type.
///
/// # Errors
///
/// Returns [`TypeError::Unfilterable`] when the body cannot be read or its linked entities cannot
/// be walked.
pub async fn filter_join_response(
    response: Response,
    restriction: &CompiledTypeRestriction,
    context: &ResolvedContext,
    mode: JoinMode,
    max_body_bytes: usize,
) -> Result<Response, TypeError> {
    rewrite(response, max_body_bytes, |document, media_type| {
        let withheld = judge_linked(document, media_type, mode, |entity| judge_entity(entity, restriction, context))?;
        debug!(withheld, "withheld the linked entities outside the allowed types");

        Ok::<(), Unwalkable>(())
    })
    .await
    .map_err(|error| TypeError::Unfilterable {
        reason: unfilterable_reason(&error),
    })
}

/// Withholds every entity of a query answer that is not of an allowed type, and every linked entity
/// of it too when the query asked for a `join`.
///
/// Each entity is judged as a read of it by identifier is: shown only when every one of its types
/// is allowed. A `FeatureCollection` is judged Feature by Feature.
///
/// # Errors
///
/// Returns [`TypeError::Unfilterable`] when the body cannot be read, its entities cannot be walked,
/// or it is a single entity of a type outside the restriction rather than a list.
pub async fn filter_query_response(
    response: Response,
    restriction: &CompiledTypeRestriction,
    context: &ResolvedContext,
    join: Option<JoinMode>,
    max_body_bytes: usize,
) -> Result<Response, TypeError> {
    rewrite(response, max_body_bytes, |document, media_type| {
        let withheld = retain_entities(document, media_type, |entity| judge_entity(entity, restriction, context))?;
        debug!(withheld, "withheld the entities outside the allowed types");

        if let Some(mode) = join {
            let withheld = judge_linked(document, media_type, mode, |entity| judge_entity(entity, restriction, context))?;
            debug!(withheld, "withheld the linked entities outside the allowed types");
        }

        Ok::<(), Unwalkable>(())
    })
    .await
    .map_err(|error| TypeError::Unfilterable {
        reason: unfilterable_reason(&error),
    })
}

/// Judges one entity of an answer by its types: shown when every one of them, expanded under the
/// request's context, is allowed, and withheld otherwise.
///
/// Every type is required for the reason a write is checked against every type: an entity of two
/// types, one of them forbidden, is an entity of the forbidden type. One whose type is missing,
/// unreadable or meaningless under the context cannot be shown to be allowed, and neither can one
/// whose members cannot be read without picking one of two occurrences.
fn judge_entity(mut entity: Entity<'_>, restriction: &CompiledTypeRestriction, context: &ResolvedContext) -> Visibility {
    let Ok(Some(members)) = entity.members() else {
        return Visibility::Withhold;
    };

    let Ok(types) = types_of(members, &Location::LinkedEntity) else {
        return Visibility::Withhold;
    };

    let allowed = !types.is_empty() && types.iter().all(|name| names::allows(restriction, name, context).unwrap_or(false));

    if allowed { Visibility::Show } else { Visibility::Withhold }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jstrict::{Value, json};
    use libra_jsonld_term_expansion::name::Term;
    use libra_ngsi_ld_representation::accept::MediaType;
    use libra_policy_model::{entity_type::TypeRestriction, member_on_write::MemberOnWrite, policy::PolicyId};
    use pretty_assertions::assert_eq;

    fn context() -> ResolvedContext {
        ResolvedContext::from_json(
            r#"{
                "@vocab": "https://uri.etsi.org/ngsi-ld/default-context/",
                "Vehicle": "https://uri.fiware.org/ns/data-models#Vehicle",
                "Building": "https://uri.fiware.org/ns/data-models#Building"
            }"#,
        )
        .expect("the test context should process")
    }

    fn vehicles() -> CompiledTypeRestriction {
        TypeRestriction {
            allowed: vec![Term::new("Vehicle")],
            type_on_write: MemberOnWrite::Optional,
        }
        .compile(&PolicyId::new("test").unwrap(), &context())
        .expect("the test restriction should compile")
    }

    fn judge(document: &mut Value, mode: JoinMode) -> Result<usize, Unwalkable> {
        let (restriction, context) = (vehicles(), context());

        judge_linked(document, MediaType::Json, mode, |entity| judge_entity(entity, &restriction, &context))
    }

    #[test]
    fn a_linked_entity_of_a_forbidden_type_is_withheld_and_its_relationship_kept() {
        let mut document = json!([{ "id": "urn:v", "type": "Vehicle",
            "locatedIn": { "type": "Relationship", "object": "urn:b", "entity": { "id": "urn:b", "type": "Building" } } }]);

        assert_eq!(judge(&mut document, JoinMode::Inline), Ok(1));
        assert_eq!(
            document,
            json!([{ "id": "urn:v", "type": "Vehicle", "locatedIn": { "type": "Relationship", "object": "urn:b" } }])
        );
    }

    #[test]
    fn a_linked_entity_of_an_allowed_type_is_shown_by_whatever_name_it_has() {
        let mut document = json!([
            { "id": "urn:v", "type": "Vehicle" },
            { "id": "urn:w", "type": "https://uri.fiware.org/ns/data-models#Vehicle" },
            { "id": "urn:b", "type": "Building" }
        ]);

        assert_eq!(judge(&mut document, JoinMode::Flat), Ok(1));
        assert_eq!(
            document,
            json!([{ "id": "urn:v", "type": "Vehicle" }, { "id": "urn:w", "type": "https://uri.fiware.org/ns/data-models#Vehicle" }])
        );
    }

    #[test]
    fn a_linked_entity_without_a_readable_allowed_type_is_withheld() {
        let mut document = json!([
            { "id": "urn:none" },
            { "id": "urn:number", "type": 7 },
            { "id": "urn:both", "type": ["Vehicle", "Building"] }
        ]);

        assert_eq!(judge(&mut document, JoinMode::Flat), Ok(3));
        assert_eq!(document, json!([]));
    }
}
