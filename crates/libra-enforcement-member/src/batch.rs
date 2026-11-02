//! Judging every entity a batch names by the member it is stored with.
//!
//! A batch delete names identifiers and nothing else, and a batch upsert, update or merge, like a
//! temporal create, names entities whose stored member its body need not repeat. Each named entity
//! is pre-flighted, within the bounds `libra-entity-preflight` sets: identifiers de-duplicated, at
//! most [`MAX_BATCH_ENTITIES`](libra_entity_preflight::batch::MAX_BATCH_ENTITIES) of them, refused
//! before any pre-flight is sent past that, and a few in flight at a time. How one stored entity is
//! judged is the restriction's own, and is handed in.

use http::request::Parts;
use jstrict::Value;
use libra_entity_preflight::{
    batch::{BatchTooLarge, distinct},
    batch_delete::{self, MalformedBatchDelete},
    batch_write::{self, MalformedEntityWrite, StoredEntity},
    error::PreflightError,
    preflight::{EntityEndpoint, Preflight},
};
use libra_json_body::{error::DocumentError, request_body::RequestBody};
use libra_ngsi_ld_operation::resource::ResourceId;
use thiserror::Error;

/// What a batch delete's body is expected to be, phrased for the caller.
const IDENTIFIERS: &str = "an array of entity identifiers";

/// What a write that may overwrite stored entities is expected to carry, phrased for the caller.
const ENTITIES: &str = "an entity or an array of entities, each with one string 'id'";

/// Why a batch's entities could not be named, before any of them was pre-flighted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum BatchError {
    /// The body does not name its entities the way the operation takes them.
    #[error("the request body is not {expected}")]
    MalformedBody {
        /// What the operation expects, phrased for the caller.
        expected: &'static str,
    },

    /// The batch names more distinct entities than Libra pre-flights.
    #[error(transparent)]
    TooLarge(#[from] BatchTooLarge),

    /// The request's body could not be read from the extensions.
    ///
    /// [`DocumentError::Unread`] is a wiring error: the context layer above reads every body once,
    /// and a batch whose identifiers this layer cannot see is one it cannot judge.
    #[error(transparent)]
    Body(#[from] DocumentError),
}

/// Pre-flights every identifier a batch delete names, and hands each answer to `judge`.
///
/// `judge` refuses an identifier the broker does not hold exactly as one outside the restriction,
/// so the refusal does not say which identifiers exist.
///
/// # Errors
///
/// Returns [`BatchError::MalformedBody`] for a body that is not an array of identifiers,
/// [`BatchError::TooLarge`] for one naming too many, [`BatchError::Body`] for a body no layer above
/// read or that is not JSON, and the first refusal `judge` returns.
pub async fn check_deleted<E>(
    parts: &Parts,
    preflight: &Preflight,
    judge: impl FnMut(&ResourceId, Result<Value, PreflightError>) -> Result<(), E>,
) -> Result<(), E>
where
    E: From<BatchError>,
{
    let malformed = || BatchError::MalformedBody { expected: IDENTIFIERS };
    let document = RequestBody::document_in(parts).map_err(BatchError::from)?.ok_or_else(malformed)?;
    let named = batch_delete::identifiers_of(document).map_err(|MalformedBatchDelete| malformed())?;
    let identifiers = distinct(named).map_err(BatchError::from)?;

    preflight.each_entity(&identifiers, EntityEndpoint::Current, &parts.headers, judge).await
}

/// Pre-flights every entity a write that may overwrite stored ones carries, and hands each one the
/// broker holds to `judge`.
///
/// An entity the broker answers 404 for is skipped: the write creates it, with the member its body
/// declares, which the body check has judged. A request without a body names no entity.
///
/// # Errors
///
/// Returns [`BatchError::MalformedBody`] for a body whose entities do not each carry one string
/// `id`, [`BatchError::TooLarge`] for one naming too many, [`BatchError::Body`] for a body no layer
/// above read or that is not JSON, the [`PreflightError`] of a pre-flight that failed otherwise than
/// with 404, and the first refusal `judge` returns.
pub async fn check_stored<E>(
    parts: &Parts,
    preflight: &Preflight,
    endpoint: EntityEndpoint,
    mut judge: impl FnMut(&ResourceId, Value) -> Result<(), E>,
) -> Result<(), E>
where
    E: From<BatchError> + From<PreflightError>,
{
    let Some(document) = RequestBody::document_in(parts).map_err(BatchError::from)? else {
        return Ok(());
    };
    let named = batch_write::identifiers_of(document).map_err(|MalformedEntityWrite| BatchError::MalformedBody { expected: ENTITIES })?;
    let identifiers = distinct(named).map_err(BatchError::from)?;

    preflight
        .each_entity(&identifiers, endpoint, &parts.headers, |id, answer| match StoredEntity::of(answer)? {
            StoredEntity::Held(stored) => judge(id, stored),
            StoredEntity::Absent => Ok(()),
        })
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::Request;
    use libra_entity_preflight::batch::MAX_BATCH_ENTITIES;
    use pretty_assertions::assert_eq;
    use url::Url;

    /// A refusal of a judged entity, standing in for a restriction's own error.
    #[derive(Debug, PartialEq, Eq, Error)]
    enum Refusal {
        #[error(transparent)]
        Batch(#[from] BatchError),
        #[error(transparent)]
        Preflight(#[from] PreflightError),
        #[error("the judge refused the entity")]
        Judged,
    }

    /// A pre-flight client whose broker never answers: every test here is decided before one is sent.
    fn unreachable() -> Preflight {
        Preflight::new(Url::parse("http://127.0.0.1:1").expect("the test URL should parse"), 64 * 1024).expect("the test client should build")
    }

    /// Request parts as the context layer leaves them, with `body` read from `bytes`.
    fn parts(bytes: &str) -> Parts {
        let (mut parts, ()) = Request::new(()).into_parts();
        parts.extensions.insert(RequestBody::read(bytes.as_bytes()).expect("the test body should read"));
        parts
    }

    fn refuse_every_entity(_: &ResourceId, _: Result<Value, PreflightError>) -> Result<(), Refusal> {
        Err(Refusal::Judged)
    }

    fn refuse_every_stored_entity(_: &ResourceId, _: Value) -> Result<(), Refusal> {
        Err(Refusal::Judged)
    }

    /// A body naming `count` distinct identifiers.
    fn identifiers(count: usize) -> String {
        let named: Vec<String> = (0..count).map(|index| format!("\"urn:ngsi-ld:Vehicle:{index}\"")).collect();
        format!("[{}]", named.join(","))
    }

    #[tokio::test]
    async fn a_delete_body_that_is_not_an_array_of_identifiers_is_refused() {
        for body in [r#"{"id":"urn:ngsi-ld:Vehicle:1"}"#, "[1]", ""] {
            assert_eq!(
                check_deleted(&parts(body), &unreachable(), refuse_every_entity).await,
                Err(Refusal::Batch(BatchError::MalformedBody { expected: IDENTIFIERS })),
                "{body:?}"
            );
        }
    }

    #[tokio::test]
    async fn a_delete_naming_too_many_entities_is_refused_before_any_pre_flight() {
        assert_eq!(
            check_deleted(&parts(&identifiers(MAX_BATCH_ENTITIES + 1)), &unreachable(), refuse_every_entity).await,
            Err(Refusal::Batch(BatchError::TooLarge(BatchTooLarge { count: MAX_BATCH_ENTITIES + 1 })))
        );
    }

    #[tokio::test]
    async fn a_delete_whose_body_no_layer_read_is_refused() {
        let (parts, ()) = Request::new(()).into_parts();

        assert_eq!(
            check_deleted(&parts, &unreachable(), refuse_every_entity).await,
            Err(Refusal::Batch(BatchError::Body(DocumentError::Unread)))
        );
    }

    #[tokio::test]
    async fn an_empty_delete_names_no_entity_and_asks_the_broker_nothing() {
        assert_eq!(check_deleted(&parts("[]"), &unreachable(), refuse_every_entity).await, Ok(()));
    }

    #[tokio::test]
    async fn a_write_without_a_body_names_no_entity() {
        assert_eq!(
            check_stored(&parts(""), &unreachable(), EntityEndpoint::Current, refuse_every_stored_entity).await,
            Ok(())
        );
    }

    #[tokio::test]
    async fn a_write_whose_entities_carry_no_identifier_is_refused() {
        assert_eq!(
            check_stored(
                &parts(r#"[{"type":"Vehicle"}]"#),
                &unreachable(),
                EntityEndpoint::Current,
                refuse_every_stored_entity
            )
            .await,
            Err(Refusal::Batch(BatchError::MalformedBody { expected: ENTITIES }))
        );
    }

    #[tokio::test]
    async fn a_write_naming_too_many_entities_is_refused_before_any_pre_flight() {
        let entities: Vec<String> = (0..=MAX_BATCH_ENTITIES)
            .map(|index| format!(r#"{{"id":"urn:ngsi-ld:Vehicle:{index}"}}"#))
            .collect();

        assert_eq!(
            check_stored(
                &parts(&format!("[{}]", entities.join(","))),
                &unreachable(),
                EntityEndpoint::Temporal,
                refuse_every_stored_entity
            )
            .await,
            Err(Refusal::Batch(BatchError::TooLarge(BatchTooLarge { count: MAX_BATCH_ENTITIES + 1 })))
        );
    }

    #[tokio::test]
    async fn a_write_whose_pre_flight_fails_is_refused_and_never_judged() {
        let refused = check_stored(
            &parts(r#"{"id":"urn:ngsi-ld:Vehicle:1"}"#),
            &unreachable(),
            EntityEndpoint::Current,
            refuse_every_stored_entity,
        )
        .await;

        assert!(matches!(refused, Err(Refusal::Preflight(_))), "{refused:?}");
    }

    #[test]
    fn a_malformed_body_is_refused_in_the_words_of_the_operation() {
        assert_eq!(
            BatchError::MalformedBody { expected: IDENTIFIERS }.to_string(),
            "the request body is not an array of entity identifiers"
        );
    }
}
