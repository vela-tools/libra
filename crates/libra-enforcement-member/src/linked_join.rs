//! Which join, if any, a member restriction judges the answer to a request in.
//!
//! Linked Entity Retrieval (NGSI-LD 4.5.23) returns entities reached through a Relationship,
//! whatever their members, and a restriction that narrows a request reaches only the queried
//! entities. A read is served by judging each linked entity on the way back; a subscription's
//! notification never comes back, so anything linked in it is refused.

use http::Extensions;
use libra_linked_entity_layer::servable::{LinkedEntityError, LinkedFilterJudgement, requested, servable_join};
use libra_ngsi_ld_operation::operation::{Mode, Operation};
use libra_ngsi_ld_query::{entity_member::EntityMember, linked_entity::JoinMode};
use thiserror::Error;

/// Whether a restriction judges the answer to an operation entity by entity on the way back.
///
/// Each restriction keeps its own definition of which answers those are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    /// The answer's entities are judged, so its linked entities are judged with them.
    Judged,
    /// The answer is forwarded as the broker gives it.
    Unjudged,
}

/// Why a request's join cannot be served under a member restriction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum LinkedJoinError {
    /// The request reaches linked entities in a way that cannot be served, or reached enforcement
    /// without them resolved.
    #[error(transparent)]
    LinkedEntity(#[from] LinkedEntityError),

    /// A projection removes the restricted member from the entities of a judged answer.
    ///
    /// Every entity of the answer, queried or linked, is judged by that member, and one stripped of
    /// it could only be withheld whatever it was: the caller would get an empty answer and no
    /// reason for it.
    #[error("the projection removes '{member}' from the entities of the answer")]
    ProjectionRemovesMember {
        /// The member the restriction judges entities by.
        member: EntityMember,
    },
}

/// The join whose answer this request is to be judged in, if it asks for one.
///
/// `member` is what the restriction judges an entity by, and `answer` says whether it judges the
/// answer to this operation. `None` means there is no join to judge: the answer holds no linked
/// entities, is not judged, or is a subscription's, whose linked entities were checked servable.
///
/// # Errors
///
/// Returns [`LinkedJoinError::ProjectionRemovesMember`] when a judged answer is projected without
/// `member`, and [`LinkedJoinError::LinkedEntity`] when the join cannot be served or was not
/// resolved above.
pub fn linked_join(extensions: &Extensions, operation: &Operation, member: EntityMember, answer: Answer) -> Result<Option<JoinMode>, LinkedJoinError> {
    let notifies = operation.resource.is_subscription() && operation.mode == Mode::Write;

    if answer == Answer::Unjudged && !notifies {
        return Ok(None);
    }

    if answer == Answer::Judged && requested(extensions)?.removes(member) {
        return Err(LinkedJoinError::ProjectionRemovesMember { member });
    }

    let Some(join) = servable_join(extensions, LinkedFilterJudgement::Refused)? else {
        return Ok(None);
    };

    match answer {
        Answer::Judged => Ok(Some(join.mode())),
        Answer::Unjudged => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::Method;
    use libra_ngsi_ld_query::parameters::QueryParameters;
    use pretty_assertions::assert_eq;

    fn classify(method: &Method, path: &str) -> Operation {
        Operation::classify(method, path)
            .expect("the request should classify")
            .expect("the path should be under the API root")
    }

    #[test]
    fn an_unjudged_answer_that_notifies_nothing_has_no_join_and_reads_nothing() {
        let operation = classify(&Method::POST, "/ngsi-ld/v1/entities");

        assert_eq!(linked_join(&Extensions::new(), &operation, EntityMember::Scope, Answer::Unjudged), Ok(None));
    }

    #[test]
    fn a_judged_answer_without_the_linked_entity_request_resolved_is_refused() {
        let operation = classify(&Method::GET, "/ngsi-ld/v1/entities");

        assert_eq!(
            linked_join(&Extensions::new(), &operation, EntityMember::Type, Answer::Judged),
            Err(LinkedJoinError::LinkedEntity(LinkedEntityError::Unresolved))
        );
    }

    /// Extensions as the linked entity layer leaves them for a request with `query`.
    fn resolved(query: &str) -> Extensions {
        let mut extensions = Extensions::new();
        extensions.insert(
            QueryParameters::parse(query)
                .expect("the test query should parse")
                .linked_entity_request()
                .expect("the test query should resolve"),
        );
        extensions
    }

    #[test]
    fn a_judged_answer_projected_without_the_member_is_refused() {
        let operation = classify(&Method::GET, "/ngsi-ld/v1/entities");

        assert_eq!(
            linked_join(&resolved("type=Vehicle&omit=type"), &operation, EntityMember::Type, Answer::Judged),
            Err(LinkedJoinError::ProjectionRemovesMember { member: EntityMember::Type })
        );
    }

    #[test]
    fn an_unjudged_answer_projected_without_the_member_is_not_refused_for_it() {
        let operation = classify(&Method::POST, "/ngsi-ld/v1/subscriptions");

        assert_eq!(
            linked_join(&resolved("omit=scope"), &operation, EntityMember::Scope, Answer::Unjudged),
            Ok(None)
        );
    }

    #[test]
    fn a_subscription_create_without_the_linked_entity_request_resolved_is_refused() {
        let operation = classify(&Method::POST, "/ngsi-ld/v1/subscriptions");

        assert_eq!(
            linked_join(&Extensions::new(), &operation, EntityMember::Scope, Answer::Unjudged),
            Err(LinkedJoinError::LinkedEntity(LinkedEntityError::Unresolved))
        );
    }
}
