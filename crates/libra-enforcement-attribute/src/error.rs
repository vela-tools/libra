//! Why a request or a response could not be filtered.

use libra_json_body::error::DocumentError;
use libra_jsonld_term_expansion::name::Term;
use libra_linked_entity_layer::servable::LinkedEntityError;
use libra_ngsi_ld_operation::resource::ResourceId;
use libra_ngsi_ld_operation_layer::classified::Unclassified;
use libra_ngsi_ld_query_layer::parsed::Unparsed;
use libra_ngsi_ld_registration::error::Unreadable;
use libra_problem_details::problem::Problem;
use thiserror::Error;

/// Filtering could not be carried out.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum FilterError {
    /// The caller named an attribute the policy does not allow.
    #[error("access to attribute '{attribute}' is denied")]
    AttributeDenied {
        /// The attribute, as the caller wrote it.
        attribute: Term,
    },

    /// The caller asked only for attributes the policy does not allow.
    #[error("none of the requested attributes are allowed")]
    NothingAllowed,

    /// A name in the request has no meaning under the request's context.
    #[error("attribute name '{name}' cannot be resolved under the request context")]
    Unresolvable {
        /// The name, as the caller wrote it.
        name: Term,
    },

    /// An attribute the policy allows or hides has no name under the request's context that
    /// expands back to it, so it cannot be written into a selector the broker reads the same way.
    ///
    /// The attribute is not named: it is the policy's, not something the caller wrote.
    #[error("an attribute this policy restricts has no name under the request context that reads back as it")]
    Inexpressible,

    /// A `q` expression could not be parsed.
    #[error("the q filter is malformed: {reason}")]
    MalformedFilter {
        /// What the parser said.
        reason: String,
    },

    /// An `orderBy` could not be parsed (NGSI-LD clause 4.23.3).
    #[error("the orderBy is malformed: {reason}")]
    MalformedOrdering {
        /// What the parser said.
        reason: String,
    },

    /// The request addresses an entity map.
    ///
    /// An entity map (NGSI-LD 5.14) lists the entities a distributed query found, and creating one
    /// runs a query whose `q` no answer narrowing reaches, so a caller under an attribute
    /// restriction is refused entity maps altogether.
    #[error("entity maps are not available under an attribute restriction")]
    EntityMapDenied,

    /// The request addresses a context source subscription, whose notifications reach an endpoint
    /// Libra never sees.
    #[error("context source subscriptions are not available under an attribute restriction")]
    ContextSourceSubscriptionDenied,

    /// The request reads, changes or deletes subscriptions that already exist.
    ///
    /// The broker answers a listing with every subscription of the tenant, and changing one changes
    /// what its notifications disclose to an endpoint Libra never sees.
    #[error("existing subscriptions may not be read, changed or deleted under an attribute restriction")]
    SubscriptionsRefused,

    /// The request deletes or replaces whole entities, which takes every attribute with it,
    /// including the ones the restriction hides from the caller.
    #[error("deleting or replacing a whole entity is not allowed under an attribute restriction")]
    WholeEntityRefused,

    /// The request reached this layer without its operation classified above.
    #[error(transparent)]
    Unclassified(#[from] Unclassified),

    /// The request reached this layer without its query parsed above.
    #[error(transparent)]
    Unparsed(#[from] Unparsed),

    /// The request reached this layer without a decision.
    ///
    /// A wiring fault: authorization runs above every enforcement layer and attaches a decision to
    /// every request it lets through, so a request without one is one nothing authorized.
    #[error("the request reached attribute filtering without an authorization decision")]
    Undecided,

    /// The request body is not the JSON it claims to be, or names a member it is read for more
    /// than once.
    #[error("the request body is not a JSON document that reads one way only")]
    MalformedBody,

    /// The request's body could not be read from the extensions: no layer above read it, which is
    /// a wiring fault that refuses the request rather than forwarding it unchecked, or it is not
    /// JSON.
    #[error(transparent)]
    Body(#[from] DocumentError),

    /// A context source registration in the request body could not be read.
    #[error(transparent)]
    UnreadableRegistration(#[from] Unreadable),

    /// A context source registration retrieved by identifier registers no attribute the policy
    /// allows, or the broker does not hold it.
    ///
    /// Both answer alike, with what the broker says of an identifier it does not hold (NGSI-LD
    /// clause 5.7.1). A refusal that differed from the broker's own 404 would tell the caller which
    /// registrations exist outside what the restriction lets them see.
    #[error("'{id}' was not found")]
    Withheld {
        /// The identifier the request addressed.
        id: ResourceId,
    },

    /// The request asked for Linked Entity Retrieval in a form an attribute-restricted caller
    /// cannot be served, or reached this layer without it resolved.
    ///
    /// Linked Entity Retrieval (NGSI-LD 4.5.23) returns entities reached through Relationships, and
    /// the attribute narrowing of the request reaches only the queried entities. A join answer has
    /// every linked entity filtered on the way back, which needs an answer whose linked entities
    /// can be found.
    #[error(transparent)]
    LinkedEntity(#[from] LinkedEntityError),

    /// The response could not be filtered, so it must not be forwarded.
    ///
    /// An unparseable or compressed body returned unfiltered because filtering could not be applied
    /// to it is precisely the case where the caller receives what the policy was hiding.
    #[error("the upstream response could not be filtered and has been withheld: {reason}")]
    Unfilterable {
        /// Why it could not be filtered.
        reason: &'static str,
    },

    /// The request reached this layer without a resolved context.
    ///
    /// Every name here is a term, and a term without a context is not a name. The context layer
    /// runs above this one, so this is a wiring error rather than anything about the request.
    #[error("the request context was not resolved before attribute filtering")]
    Unresolved,
}

impl FilterError {
    /// The response a caller sees.
    #[must_use]
    pub fn to_problem(&self) -> Problem {
        match self {
            Self::AttributeDenied { .. }
            | Self::NothingAllowed
            | Self::EntityMapDenied
            | Self::ContextSourceSubscriptionDenied
            | Self::SubscriptionsRefused
            | Self::WholeEntityRefused
            | Self::LinkedEntity(LinkedEntityError::Refused(_)) => Problem::Forbidden(self.to_string()),
            Self::Unresolvable { .. }
            | Self::Inexpressible
            | Self::MalformedFilter { .. }
            | Self::MalformedOrdering { .. }
            | Self::MalformedBody
            | Self::Body(DocumentError::NotJson)
            | Self::UnreadableRegistration(_) => Problem::BadRequest(self.to_string()),
            Self::Withheld { .. } => Problem::NotFound(self.to_string()),
            // Not the caller's fault, and not something they may see around.
            Self::Unfilterable { .. } => Problem::BadGateway(self.to_string()),
            // A wiring error rather than anything about this request.
            Self::LinkedEntity(LinkedEntityError::Unresolved)
            | Self::Body(DocumentError::Unread)
            | Self::Unclassified(_)
            | Self::Unparsed(_)
            | Self::Unresolved
            | Self::Undecided => Problem::Internal(self.to_string()),
        }
    }
}
