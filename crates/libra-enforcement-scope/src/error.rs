//! Why a request could not be brought inside the scopes a policy allows.
//!
//! Every variant is a refusal. Carrying on when the layer cannot answer (a pre-flight that did not
//! return 2xx, a `scope` member in a shape it does not recognise, a path it did not think to check)
//! would be a way past the restriction rather than a gap in it.

use libra_enforcement_member::{
    batch::BatchError,
    linked_join::LinkedJoinError,
    location::Location,
    query_parameter::AmbiguousParameter,
    unnarrowable::Unnarrowable,
};
use libra_entity_preflight::error::PreflightError;
use libra_json_body::error::DocumentError;
use libra_linked_entity_layer::servable::LinkedEntityError;
use libra_ngsi_ld_operation::resource::ResourceId;
use libra_ngsi_ld_operation_layer::classified::Unclassified;
use libra_ngsi_ld_query_layer::parsed::Unparsed;
use libra_policy_model::scope::ScopePattern;
use libra_problem_details::problem::Problem;
use thiserror::Error;

/// Scope enforcement could not be carried out, or found the request outside its bounds.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ScopeError {
    /// A scope named by the request lies outside every scope the policy allows.
    #[error("scope '{scope}' is outside the scopes this policy allows")]
    ScopeDenied {
        /// The scope, as the caller wrote it.
        scope: ScopePattern,
    },

    /// The entity or registration a request addresses is one this caller may not see or change, or
    /// the broker does not hold it.
    ///
    /// Both answer alike, with what the broker says of an identifier it does not hold (NGSI-LD
    /// clause 5.7.1). A refusal that differed from the broker's own 404 would tell the caller which
    /// identifiers exist outside the allowed scopes, and one that named the stored scope, or said
    /// there is none, would tell them where.
    #[error("'{id}' was not found")]
    Withheld {
        /// The identifier the request addressed.
        id: ResourceId,
    },

    /// A write addresses an entity the caller may read through one of its scopes, but which also
    /// carries a scope the policy does not allow.
    ///
    /// Forbidden rather than withheld, because the caller can already fetch the entity. The stored
    /// scopes are still not named: the caller is shown only the ones the policy allows.
    #[error("'{id}' carries a scope this policy does not allow, and a write needs every one of its scopes allowed")]
    OutsideScopesOnWrite {
        /// The identifier the request addressed.
        id: ResourceId,
    },

    /// A write carries no scope and the policy requires one.
    #[error("{at} carries no scope and this policy requires one on write")]
    MissingScope {
        /// Where the scope was looked for.
        at: Location,
    },

    /// A `scope` member is present but in a shape Libra cannot read.
    ///
    /// Refused rather than ignored. A scope the proxy cannot read is one it cannot compare, and letting
    /// an unrecognised shape through would include the normalised `{"type": "Property", "value": ...}`
    /// form, which is ordinary NGSI-LD.
    #[error("the scope in {at} is not a form Libra can read")]
    UnreadableScope {
        /// Where the scope was read from.
        at: Location,
    },

    /// The request asked for Linked Entity Retrieval in a form a scope-restricted caller cannot be
    /// served, reached this layer without it resolved, or projects `scope` away from an answer
    /// whose entities are judged by it.
    ///
    /// Linked Entity Retrieval (NGSI-LD 4.5.23) follows a Relationship and returns the entity it
    /// points at, in whatever scope that entity is. The `scopeQ` narrowing this layer applies reaches
    /// only the queried entities, so a join answer is judged linked entity by linked entity on the
    /// way back, which needs an answer whose linked entities can be found.
    #[error(transparent)]
    LinkedJoin(#[from] LinkedJoinError),

    /// The request reaches a route no narrowing of its `scopeQ` reaches: a context source
    /// subscription, an entity map, by path or named in `NGSILD-EntityMap` (NGSI-LD table
    /// 6.4.3.2-2), or an existing subscription. Creating a subscription stays possible, narrowed to
    /// the restriction.
    #[error("{0} under a scope restriction")]
    Unnarrowable(#[from] Unnarrowable),

    /// A batch's entities could not be named before they were pre-flighted.
    #[error(transparent)]
    Batch(#[from] BatchError),

    /// A scope in the request is not a well-formed scope path.
    ///
    /// The value is written escaped, so a control character in it reaches no log or response raw.
    #[error("scope {value:?} is not a usable scope: {reason}")]
    MalformedScope {
        /// The scope, as the caller wrote it.
        value: String,
        /// What was wrong with it.
        reason: String,
    },

    /// A `scopeQ` expression does not fit the grammar.
    #[error("malformed scopeQ expression at offset {offset}: {reason}")]
    MalformedExpression {
        /// Byte offset the parser gave up at.
        offset: usize,
        /// What went wrong.
        reason: String,
    },

    /// The query carries more than one spelling of `scopeQ`.
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

    /// The pre-flight did not produce an answer the layer can act on.
    ///
    /// This is the variant that closes the largest hole: a pre-flight that failed, timed out, or
    /// answered with anything but a usable entity is never treated as permission.
    #[error("the scope of the addressed entity could not be established: {0}")]
    Unenforceable(#[from] PreflightError),

    /// The broker's successful answer could not be reduced to the allowed scopes.
    ///
    /// Refused rather than forwarded: an answer Libra cannot read is one it cannot prove free of
    /// scopes the restriction excludes.
    #[error("the upstream response cannot be reduced to the allowed scopes: {reason}")]
    ResponseUnfilterable {
        /// Why the response could not be rewritten.
        reason: &'static str,
    },

    /// The request's body could not be read from the extensions.
    ///
    /// [`DocumentError::Unread`] is a wiring error rather than anything about the request: the
    /// context layer above reads every body once, and a body this layer cannot see is one whose
    /// scopes it cannot check, so the request is refused rather than forwarded unchecked.
    /// [`DocumentError::NotJson`] is a body that is not the JSON document the operation takes.
    #[error(transparent)]
    Body(#[from] DocumentError),

    /// A restriction reached enforcement allowing no scope at all.
    ///
    /// The model refuses an empty allow list when a policy loads, so this cannot come from a
    /// policy file. It is stated here rather than assumed because the alternative, emitting `scopeQ=`,
    /// is read by brokers as no filter at all, which turns "allows nothing" into "allows everything".
    #[error("a scope restriction reached enforcement allowing no scope at all")]
    EmptyAllowList,

    /// The request reached this layer without an authorization decision.
    ///
    /// A wiring error rather than anything about the request: the authorization layer above
    /// attaches a decision to every request it lets through, so a request without one is one
    /// nobody authorized, and passing it through would turn a misplaced layer into an open door.
    #[error("the request reached scope enforcement without an authorization decision")]
    Undecided,
}

impl ScopeError {
    /// The response a caller sees.
    #[must_use]
    pub fn to_problem(&self) -> Problem {
        match self {
            Self::Withheld { .. } => Problem::NotFound(self.to_string()),
            Self::ScopeDenied { .. }
            | Self::MissingScope { .. }
            | Self::OutsideScopesOnWrite { .. }
            | Self::LinkedJoin(LinkedJoinError::LinkedEntity(LinkedEntityError::Refused(_)))
            | Self::Unnarrowable(_) => Problem::Forbidden(self.to_string()),
            Self::UnreadableScope { .. }
            | Self::MalformedScope { .. }
            | Self::MalformedExpression { .. }
            | Self::AmbiguousParameter(_)
            | Self::MalformedBody { .. }
            | Self::Body(DocumentError::NotJson)
            | Self::LinkedJoin(LinkedJoinError::ProjectionRemovesMember { .. })
            | Self::Batch(BatchError::MalformedBody { .. } | BatchError::TooLarge(_) | BatchError::Body(DocumentError::NotJson)) => {
                Problem::BadRequest(self.to_string())
            }
            // Not the caller's fault, and not something they may proceed past.
            Self::Unenforceable(_) | Self::Unrebuildable | Self::ResponseUnfilterable { .. } => Problem::BadGateway(self.to_string()),
            // A wiring or invariant failure rather than anything about this request.
            Self::EmptyAllowList
            | Self::Undecided
            | Self::Unclassified(_)
            | Self::Unparsed(_)
            | Self::Body(DocumentError::Unread)
            | Self::Batch(BatchError::Body(DocumentError::Unread))
            | Self::LinkedJoin(LinkedJoinError::LinkedEntity(LinkedEntityError::Unresolved)) => Problem::Internal(self.to_string()),
        }
    }
}
