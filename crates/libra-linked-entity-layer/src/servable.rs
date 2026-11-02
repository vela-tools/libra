//! Whether a restricted caller can be served the linked entities a request asks for.
//!
//! A join answer is judged entity by entity on its way back, and that is only possible for an
//! answer whose shape is known. The rule is the same for every restriction, so it lives here and
//! each enforcement layer applies it when, and only when, its own restriction is in force.

use axum::http::Extensions;
use libra_ngsi_ld_query::linked_entity::{Join, JoinMode, LinkedAnswer, LinkedEntityRequest, LinkedEntityRetrieval, LinkedFilter};
use libra_ngsi_ld_representation::representation::{Representation, TemporalRepresentation};
use libra_ngsi_ld_representation_layer::RequestRepresentation;
use strum::Display;
use thiserror::Error;

/// Why a join cannot be served to a restricted caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Display)]
pub enum JoinRefusal {
    /// The request reaches linked entities in a way no answer can be judged against.
    #[strum(to_string = "{0}")]
    Unservable(LinkedEntityRetrieval),
    /// A `q` filter that follows a Relationship (clause 4.9), under a restriction that cannot check
    /// it.
    ///
    /// The linked entities' values decide which entities come back, yet never appear in the answer,
    /// so a restriction that judges an entity by its type or scope has nothing to judge them by.
    #[strum(to_string = "a linked-entity path in the q filter")]
    FilterPath,
    /// An inline join in the simplified representation.
    ///
    /// In `keyValues` an inline join replaces the Relationship's value with the linked entity itself
    /// (clause 4.5.4, examples 9, 10 and 17), so a linked entity cannot be told from a Property
    /// whose value merely looks like one, and a withheld one cannot be removed without removing the
    /// Relationship too.
    #[strum(to_string = "an inline join in the keyValues representation")]
    InlineSimplified,
    /// A join whose answer is in a shape this proxy cannot describe: `temporalValues`,
    /// `aggregatedValues`, or a representation the request did not settle.
    #[strum(to_string = "a join in a representation whose linked entities cannot be found")]
    UndescribableRepresentation,
}

/// Why the linked-entity rule could not be applied to a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum LinkedEntityError {
    /// The join cannot be served to a restricted caller.
    #[error("linked entity retrieval is not allowed for a restricted caller; requested via {0}")]
    Refused(JoinRefusal),
    /// The request reached enforcement without what the layers above resolve.
    ///
    /// A wiring error rather than anything about the request: the linked-entity and representation
    /// layers run above authorization, and judging a request without their answers is guessing.
    #[error("linked entity retrieval or the response representation was not resolved before enforcement")]
    Unresolved,
}

/// Who answers for a `q` filter that follows a Relationship.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkedFilterJudgement {
    /// The restriction cannot judge a linked filter, so one is refused.
    Refused,
    /// The restriction checks every name a linked filter path carries itself.
    CheckedByCaller,
}

/// What the request asks for in Linked Entity Retrieval, as resolved above authorization.
///
/// # Errors
///
/// Returns [`LinkedEntityError::Unresolved`] when the extension is absent.
pub fn requested(extensions: &Extensions) -> Result<&LinkedEntityRequest, LinkedEntityError> {
    extensions.get::<LinkedEntityRequest>().ok_or(LinkedEntityError::Unresolved)
}

/// The join a restricted caller is to be served, if the request asks for one.
///
/// `None` means the answer holds no linked entities. A join is servable when its answer can be
/// judged: the request names a representation, that representation is not a temporal format, and
/// an inline join is not in `keyValues`. A linked `q` filter is refused unless `filter` says the
/// caller checks it.
///
/// # Errors
///
/// Returns [`LinkedEntityError::Refused`] when the request reaches linked entities in a way that
/// cannot be served, and [`LinkedEntityError::Unresolved`] when an extension it is read from is
/// absent.
pub fn servable_join(extensions: &Extensions, filter: LinkedFilterJudgement) -> Result<Option<&Join>, LinkedEntityError> {
    let requested = requested(extensions)?;

    match (requested.filter, filter) {
        (LinkedFilter::Paths, LinkedFilterJudgement::Refused) => return Err(LinkedEntityError::Refused(JoinRefusal::FilterPath)),
        (LinkedFilter::None, LinkedFilterJudgement::Refused | LinkedFilterJudgement::CheckedByCaller)
        | (LinkedFilter::Paths, LinkedFilterJudgement::CheckedByCaller) => {}
    }

    let join = match &requested.answer {
        LinkedAnswer::NotRequested => return Ok(None),
        LinkedAnswer::Unservable(reason) => return Err(LinkedEntityError::Refused(JoinRefusal::Unservable(*reason))),
        LinkedAnswer::Join(join) => join,
    };

    let representation = match extensions.get::<RequestRepresentation>() {
        None => return Err(LinkedEntityError::Unresolved),
        Some(RequestRepresentation::Unresolvable(_)) => return Err(LinkedEntityError::Refused(JoinRefusal::UndescribableRepresentation)),
        Some(RequestRepresentation::Resolved(representation)) => representation,
    };

    match representation.temporal() {
        TemporalRepresentation::Instances => {}
        TemporalRepresentation::Simplified | TemporalRepresentation::Aggregated => {
            return Err(LinkedEntityError::Refused(JoinRefusal::UndescribableRepresentation));
        }
    }

    match (join.mode(), representation.representation()) {
        (JoinMode::Inline, Representation::Simplified) => Err(LinkedEntityError::Refused(JoinRefusal::InlineSimplified)),
        (JoinMode::Inline | JoinMode::Flat, Representation::Normalized | Representation::Concise) | (JoinMode::Flat, Representation::Simplified) => {
            Ok(Some(join))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libra_ngsi_ld_query::{parameter_name::ParameterName, parameters::QueryParameters};
    use libra_ngsi_ld_representation::{error::RepresentationError, selection::ResponseRepresentation};
    use pretty_assertions::assert_eq;

    fn extensions(query: &str, accept: Option<&str>) -> Extensions {
        let parameters = QueryParameters::parse(query).unwrap();
        let mut extensions = Extensions::new();

        extensions.insert(parameters.linked_entity_request().unwrap());
        extensions.insert(
            match ResponseRepresentation::parse(accept, parameters.get(&ParameterName::OPTIONS), parameters.get(&ParameterName::FORMAT)) {
                Ok(representation) => RequestRepresentation::Resolved(representation),
                Err(error) => RequestRepresentation::Unresolvable(error),
            },
        );

        extensions
    }

    fn mode(query: &str, accept: Option<&str>) -> Result<Option<JoinMode>, LinkedEntityError> {
        servable_join(&extensions(query, accept), LinkedFilterJudgement::Refused).map(|join| join.map(Join::mode))
    }

    #[test]
    fn a_request_without_a_join_is_served_without_linked_entities() {
        assert_eq!(mode("type=Vehicle", None), Ok(None));
    }

    #[test]
    fn a_join_in_a_describable_representation_is_servable() {
        assert_eq!(mode("join=inline", None), Ok(Some(JoinMode::Inline)));
        assert_eq!(mode("join=inline&options=concise", Some("application/geo+json")), Ok(Some(JoinMode::Inline)));
        assert_eq!(mode("join=flat&options=keyValues", None), Ok(Some(JoinMode::Flat)));
    }

    #[test]
    fn an_inline_join_in_key_values_is_refused() {
        for query in ["join=inline&options=keyValues", "join=inline&format=keyValues"] {
            assert_eq!(mode(query, None), Err(LinkedEntityError::Refused(JoinRefusal::InlineSimplified)), "{query}");
        }
    }

    #[test]
    fn a_join_in_a_temporal_format_or_an_unsettled_representation_is_refused() {
        for (query, accept) in [
            ("join=flat&options=temporalValues", None),
            ("join=inline&format=aggregatedValues", None),
            ("join=inline&options=keyValues,concise", None),
            ("join=flat", Some("text/html")),
        ] {
            assert_eq!(
                mode(query, accept),
                Err(LinkedEntityError::Refused(JoinRefusal::UndescribableRepresentation)),
                "{query}"
            );
        }
    }

    #[test]
    fn an_unservable_request_is_refused_with_its_reason() {
        assert_eq!(
            mode("joinLevel=2", None),
            Err(LinkedEntityError::Refused(JoinRefusal::Unservable(LinkedEntityRetrieval::JoinLevelWithoutJoin)))
        );
        assert_eq!(
            LinkedEntityError::Refused(JoinRefusal::Unservable(LinkedEntityRetrieval::JoinLevelWithoutJoin)).to_string(),
            "linked entity retrieval is not allowed for a restricted caller; requested via the joinLevel parameter without a join"
        );
    }

    #[test]
    fn a_linked_filter_is_refused_unless_the_caller_checks_it() {
        // Clause 4.9: the linked values decide the results but never appear in the answer.
        assert_eq!(mode("q=isParked{name}==\"x\"", None), Err(LinkedEntityError::Refused(JoinRefusal::FilterPath)));
        assert_eq!(
            servable_join(&extensions("q=isParked{name}==\"x\"", None), LinkedFilterJudgement::CheckedByCaller),
            Ok(None)
        );
        assert_eq!(
            servable_join(&extensions("join=flat&q=a{b}==1", None), LinkedFilterJudgement::CheckedByCaller).map(|join| join.map(Join::mode)),
            Ok(Some(JoinMode::Flat)),
            "a checked filter leaves the join to be judged as any other"
        );
        assert_eq!(
            servable_join(&extensions("joinLevel=2&q=a{b}==1", None), LinkedFilterJudgement::CheckedByCaller),
            Err(LinkedEntityError::Refused(JoinRefusal::Unservable(LinkedEntityRetrieval::JoinLevelWithoutJoin)))
        );
    }

    #[test]
    fn a_request_the_layers_above_did_not_resolve_is_a_wiring_error() {
        assert_eq!(
            servable_join(&Extensions::new(), LinkedFilterJudgement::Refused),
            Err(LinkedEntityError::Unresolved)
        );

        let mut joined = Extensions::new();
        joined.insert(QueryParameters::parse("join=flat").unwrap().linked_entity_request().unwrap());
        assert_eq!(servable_join(&joined, LinkedFilterJudgement::Refused), Err(LinkedEntityError::Unresolved));

        let mut unrepresented = Extensions::new();
        unrepresented.insert(LinkedEntityRequest::NOTHING);
        assert_eq!(
            servable_join(&unrepresented, LinkedFilterJudgement::Refused),
            Ok(None),
            "no join, so no representation is needed"
        );
    }

    #[test]
    fn an_unresolvable_representation_names_its_own_error_elsewhere() {
        // The representation layer records why; this rule only needs to know that it could not.
        let mut extensions = Extensions::new();
        extensions.insert(QueryParameters::parse("join=inline").unwrap().linked_entity_request().unwrap());
        extensions.insert(RequestRepresentation::Unresolvable(RepresentationError::UnknownFormat {
            format: "x".to_owned(),
        }));

        assert_eq!(
            servable_join(&extensions, LinkedFilterJudgement::Refused),
            Err(LinkedEntityError::Refused(JoinRefusal::UndescribableRepresentation))
        );
    }
}
