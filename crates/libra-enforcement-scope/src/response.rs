//! Rewriting the successful answer to a scoped read.
//!
//! The response step of the layer: a read allowed on any one scope is only safe if the answer is
//! cut down to the scopes the restriction covers, a query answer only if every entity in it is in an
//! allowed scope, a join answer only if every linked entity in it is, and a body that cannot be cut
//! down is not forwarded.

use crate::{
    error::ScopeError,
    filtering::{filter_document, judge_entity},
};
use axum::response::Response;
use jstrict::Value;
use libra_enforcement_member::unfilterable::unfilterable_reason;
use libra_ngsi_ld_entity_document::{entities::retain_entities, linked::judge_linked, unwalkable::Unwalkable};
use libra_ngsi_ld_query::linked_entity::JoinMode;
use libra_ngsi_ld_representation::accept::MediaType;
use libra_policy_model::scope::ScopePattern;
use libra_response_json::rewrite::rewrite;
use tracing::debug;

/// Reduces the `scope` member of a successful answer to a read by identifier to the scopes `allowed`
/// covers, and withholds every linked entity of a `join` answer that no allowed scope covers.
///
/// The entity itself was judged by its pre-flight before the read was sent.
///
/// # Errors
///
/// Returns [`ScopeError::ResponseUnfilterable`] when the success body is content-encoded, larger
/// than `max_body_bytes`, not a JSON media type, not parsable as JSON, an answer whose entities
/// cannot be walked, or a join answer whose linked entities cannot be.
pub async fn filter_response(response: Response, allowed: &[ScopePattern], join: Option<JoinMode>, max_body_bytes: usize) -> Result<Response, ScopeError> {
    rewrite(response, max_body_bytes, |document, media_type| {
        filter_document(document, allowed, media_type)?;

        judge_join(document, media_type, allowed, join)
    })
    .await
    .map_err(|error| ScopeError::ResponseUnfilterable {
        reason: unfilterable_reason(&error),
    })
}

/// Withholds every entity of a query answer that no allowed scope covers, reduces the `scope` of the
/// others to the allowed scopes, and does the same to every linked entity of a `join` answer.
///
/// Each entity is judged as a read of it by identifier is, except that one is withheld from the
/// answer rather than refused: a query may still answer with the entities it may show. A broker
/// that ignored the injected `scopeQ` therefore leaks nothing, neither an entity in another scope
/// nor one in no scope at all. A `FeatureCollection` is judged Feature by Feature.
///
/// # Errors
///
/// As [`filter_response`], and when the answer is a single entity no allowed scope covers rather
/// than a list.
pub async fn filter_query_response(
    response: Response,
    allowed: &[ScopePattern],
    join: Option<JoinMode>,
    max_body_bytes: usize,
) -> Result<Response, ScopeError> {
    rewrite(response, max_body_bytes, |document, media_type| {
        let withheld = retain_entities(document, media_type, |entity| judge_entity(entity, allowed))?;
        debug!(withheld, "withheld the entities outside the allowed scopes");

        judge_join(document, media_type, allowed, join)
    })
    .await
    .map_err(|error| ScopeError::ResponseUnfilterable {
        reason: unfilterable_reason(&error),
    })
}

/// Withholds every linked entity of a `join` answer that no allowed scope covers.
fn judge_join(document: &mut Value, media_type: MediaType, allowed: &[ScopePattern], join: Option<JoinMode>) -> Result<(), Unwalkable> {
    if let Some(mode) = join {
        let withheld = judge_linked(document, media_type, mode, |entity| judge_entity(entity, allowed))?;
        debug!(withheld, "withheld the linked entities outside the allowed scopes");
    }

    Ok(())
}
