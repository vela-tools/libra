//! Why a request could not be brought inside the entity types a policy allows.
//!
//! Every variant is a refusal. Continuing when the layer cannot answer is not an answer: a
//! pre-flight whose response is not a success is not permission, an empty allow list is not
//! turned into a magic type name handed to the broker in the hope that nothing would match it,
//! and a batch delete is not skipped.

use libra_enforcement_member::{
    batch::BatchError,
    linked_join::LinkedJoinError,
    location::Location,
    query_parameter::AmbiguousParameter,
    unnarrowable::Unnarrowable,
};
use libra_entity_preflight::error::PreflightError;
use libra_json_body::error::DocumentError;
use libra_jsonld_term_expansion::name::Term;
use libra_linked_entity_layer::servable::LinkedEntityError;
use libra_ngsi_ld_operation::resource::ResourceId;
use libra_ngsi_ld_operation_layer::classified::Unclassified;
use libra_ngsi_ld_query::error::QueryError;
use libra_ngsi_ld_query_layer::parsed::Unparsed;
use libra_ngsi_ld_registration::error::Unreadable;
use libra_problem_details::problem::Problem;
use thiserror::Error;

/// Entity type enforcement could not be carried out, or found the request outside its bounds.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TypeError {
    /// A type named by the request is not one the policy allows.
    #[error("entity type '{entity_type}' is not one this policy allows")]
    TypeDenied {
        /// The type, as the caller wrote it.
        entity_type: Term,
    },

    /// The entity or registration a request addresses is one this caller may not see, or the
    /// broker does not hold it.
    ///
    /// Both answer alike, with what the broker says of an identifier it does not hold (NGSI-LD
    /// clause 5.7.1). A refusal that differed from the broker's own 404 would tell the caller which
    /// identifiers exist under a type the restriction keeps from them, and one that named the
    /// stored type would tell them which.
    #[error("'{id}' was not found")]
    Withheld {
        /// The identifier the request addressed.
        id: ResourceId,
    },

    /// A write carries no type and the policy requires one.
    #[error("{at} carries no entity type and this policy requires one on write")]
    MissingType {
        /// Where the type was looked for.
        at: Location,
    },

    /// A `type` member is present but in a shape Libra cannot read.
    #[error("the entity type in {at} is not a form Libra can read")]
    UnreadableType {
        /// Where the type was read from.
        at: Location,
    },

    /// A name in the request has no meaning under the request's context.
    ///
    /// Refused rather than treated as a type that matches nothing. A name whose meaning is unknown
    /// cannot be compared with a policy's IRI, and guessing is what the JSON-LD layer exists to
    /// stop.
    #[error("entity type '{name}' cannot be resolved under the request context")]
    Unresolvable {
        /// The name, as the caller wrote it.
        name: Term,
    },

    /// The request asked for Linked Entity Retrieval in a form a type-restricted caller cannot be
    /// served, reached this layer without it resolved, or projects `type` away from an answer
    /// whose entities are judged by it.
    ///
    /// Linked Entity Retrieval (NGSI-LD 4.5.23) follows a Relationship and returns the entity it
    /// points at, of whatever type that entity is. The `type` narrowing this layer applies reaches
    /// only the queried entities, so a join answer is judged linked entity by linked entity on the
    /// way back, which needs an answer whose linked entities can be found.
    #[error(transparent)]
    LinkedJoin(#[from] LinkedJoinError),

    /// A context source registration a write names registers an entity type outside the
    /// restriction, or every type.
    ///
    /// A registration whose `RegistrationInfo` names no entities registers its attributes for every
    /// entity type (NGSI-LD 5.2.10), which no restriction of named types covers.
    #[error("the context source registration registers entity types this policy does not allow")]
    RegistrationDenied,

    /// A context source registration in a request body could not be read.
    #[error(transparent)]
    UnreadableRegistration(#[from] Unreadable),

    /// The request reaches a route no narrowing of its `type` reaches: a context source
    /// subscription, an entity map, by path or named in `NGSILD-EntityMap` (NGSI-LD table
    /// 6.4.3.2-2), or an existing subscription. Creating a subscription stays possible, narrowed to
    /// the restriction.
    #[error("{0} under an entity type restriction")]
    Unnarrowable(#[from] Unnarrowable),

    /// A batch's entities could not be named before they were pre-flighted.
    #[error(transparent)]
    Batch(#[from] BatchError),

    /// A type selection expression does not fit the grammar.
    ///
    /// NGSI-LD 1.8 allows `A;B`, `A|B` and parentheses in a type selection, not only a comma list.
    /// An expression Libra cannot read is one whose type references it cannot check, while the
    /// broker behind it would apply the expression whole, so it is refused rather than forwarded.
    #[error(transparent)]
    MalformedSelection(#[from] QueryError),

    /// The query carries more than one spelling of `type`.
    #[error(transparent)]
    AmbiguousParameter(#[from] AmbiguousParameter),

    /// The request reached this layer without its operation classified above.
    #[error(transparent)]
    Unclassified(#[from] Unclassified),

    /// The request reached this layer without its query parsed above.
    #[error(transparent)]
    Unparsed(#[from] Unparsed),

    /// The body is not the JSON document this operation takes.
    #[error("the request body is not {expected}")]
    MalformedBody {
        /// What the operation expects, phrased for the caller.
        expected: &'static str,
    },

    /// The narrowed request could not be put back together.
    #[error("the narrowed request could not be rebuilt")]
    Unrebuildable,

    /// A metadata-index response or a join answer could not be narrowed, so it is withheld rather
    /// than forwarded.
    ///
    /// A response Libra cannot read is one it cannot narrow, and forwarding it whole is the
    /// disclosure the narrowing exists to prevent, so an encoded, oversized or non-JSON body, an
    /// index of an unknown shape and a join answer whose linked entities cannot be found all fail
    /// closed here.
    #[error("the upstream response could not be filtered: {reason}")]
    Unfilterable {
        /// Why the response could not be narrowed.
        reason: &'static str,
    },

    /// The pre-flight did not produce an answer the layer can act on.
    #[error("the type of the addressed entity could not be established: {0}")]
    Unenforceable(#[from] PreflightError),

    /// The request reached this layer without a resolved context.
    ///
    /// A wiring error rather than anything about the request: the context layer runs above this
    /// one, and comparing type names without a context is the very mistake this crate exists to
    /// prevent.
    #[error("the request context was not resolved before entity type enforcement")]
    Unresolved,

    /// The request's body could not be read from the extensions.
    ///
    /// [`DocumentError::Unread`] is a wiring error rather than anything about the request: the
    /// context layer above reads every body once, and a body this layer cannot see is one whose types
    /// it cannot check, so the request is refused rather than forwarded unchecked.
    /// [`DocumentError::NotJson`] is a body that is not the JSON document the operation takes.
    #[error(transparent)]
    Body(#[from] DocumentError),

    /// A restriction reached enforcement allowing no type at all.
    ///
    /// The model refuses an empty allow list when a policy loads. It is stated here rather than
    /// assumed because the alternative, injecting a literal type name and relying on no entity ever
    /// having it, is a guess about data the proxy has never seen.
    #[error("an entity type restriction reached enforcement allowing no type at all")]
    EmptyAllowList,

    /// The request reached this layer without an authorization decision.
    ///
    /// A wiring error rather than anything about the request: the authorization layer above
    /// attaches a decision to every request it lets through, so a request without one is one
    /// nobody authorized, and passing it through would turn a misplaced layer into an open door.
    #[error("the request reached entity type enforcement without an authorization decision")]
    Undecided,
}

impl TypeError {
    /// The response a caller sees.
    #[must_use]
    pub fn to_problem(&self) -> Problem {
        match self {
            Self::Withheld { .. } => Problem::NotFound(self.to_string()),
            Self::TypeDenied { .. }
            | Self::MissingType { .. }
            | Self::LinkedJoin(LinkedJoinError::LinkedEntity(LinkedEntityError::Refused(_)))
            | Self::RegistrationDenied
            | Self::Unnarrowable(_) => Problem::Forbidden(self.to_string()),
            Self::UnreadableType { .. }
            | Self::Unresolvable { .. }
            | Self::MalformedSelection(_)
            | Self::AmbiguousParameter(_)
            | Self::MalformedBody { .. }
            | Self::Body(DocumentError::NotJson)
            | Self::UnreadableRegistration(_)
            | Self::LinkedJoin(LinkedJoinError::ProjectionRemovesMember { .. })
            | Self::Batch(BatchError::MalformedBody { .. } | BatchError::TooLarge(_) | BatchError::Body(DocumentError::NotJson)) => {
                Problem::BadRequest(self.to_string())
            }
            // Not the caller's fault, and not something they may proceed past.
            Self::Unenforceable(_) | Self::Unrebuildable | Self::Unfilterable { .. } => Problem::BadGateway(self.to_string()),
            // An invariant failure rather than anything about this request.
            Self::EmptyAllowList
            | Self::Undecided
            | Self::Unclassified(_)
            | Self::Unparsed(_)
            | Self::Unresolved
            | Self::Body(DocumentError::Unread)
            | Self::Batch(BatchError::Body(DocumentError::Unread))
            | Self::LinkedJoin(LinkedJoinError::LinkedEntity(LinkedEntityError::Unresolved)) => Problem::Internal(self.to_string()),
        }
    }
}
