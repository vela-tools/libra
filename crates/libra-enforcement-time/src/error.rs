//! Why a temporal request could not be brought inside the window a policy allows.

use libra_json_body::error::DocumentError;
use libra_linked_entity_layer::servable::LinkedEntityError;
use libra_ngsi_ld_operation_layer::classified::Unclassified;
use libra_ngsi_ld_query::temporal_selector::TimeRelation;
use libra_ngsi_ld_query_layer::parsed::Unparsed;
use libra_problem_details::problem::Problem;
use thiserror::Error;

/// Time enforcement refused, or could not read, a request.
///
/// The split that matters here is between "the policy does not allow this" and "the request was
/// malformed". An unparseable `timeAt` is the second: replacing it with the policy's own bound is
/// fail-safe with respect to the policy and tells the caller nothing about the timestamp they got
/// wrong.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TimeError {
    /// The requested window and the allowed window do not meet.
    #[error("the requested time window lies outside the one this policy allows")]
    OutsideWindow,

    /// The query evaluates its window against a temporal property other than `observedAt`.
    ///
    /// The restriction's window is a window of observations. `createdAt`, `modifiedAt` and
    /// `deletedAt` (NGSI-LD clause 4.8) are when the broker stored a value, not when it was observed,
    /// so a window narrowed on one of them reaches observations outside the policy's window.
    #[error("a time-restricted query may only be evaluated against observedAt, not '{property}'")]
    TimePropertyRefused {
        /// The temporal property, as the caller wrote it.
        property: String,
    },

    /// The window narrowed for an aggregated read under a minimum aggregation period holds no whole
    /// period of the grid every aggregated window has to sit on.
    #[error("the allowed time window holds no whole aggregation period on the grid this policy requires")]
    NoWholePeriod,

    /// The request reads, changes or deletes subscriptions that already exist.
    ///
    /// A subscription's notifications reach their endpoint without passing through Libra, and the
    /// broker answers a listing with every subscription of the tenant, so no window can be held to
    /// what they disclose.
    #[error("existing subscriptions may not be read, changed or deleted under a time restriction")]
    SubscriptionsRefused,

    /// The request reached this layer without a decision.
    ///
    /// A wiring fault: authorization runs above every enforcement layer and attaches a decision to
    /// every request it lets through, so a request without one is one nothing authorized.
    #[error("the request reached time enforcement without an authorization decision")]
    Undecided,

    /// A relative window cannot be applied to the resource that was addressed.
    #[error("a relative time restriction cannot be enforced on this resource; only a temporal query carries a window to narrow")]
    Unenforceable,

    /// The restriction refuses current-state reads (`current-state = "refuse"`).
    #[error("this policy's time restriction does not allow current-state reads; only a temporal query carries a window to narrow")]
    CurrentStateRefused,

    /// A current-state read under `current-state = "values-in-window"` whose answer cannot be dated.
    #[error("the answer to this current-state read cannot be held to the allowed time window: {reason}")]
    CurrentStateUnjudgeable {
        /// Why the answer cannot be dated, phrased for the caller.
        reason: &'static str,
    },

    /// A current-state read under `current-state = "values-in-window"` that filters or orders on
    /// attribute values.
    ///
    /// A filter or an ordering is evaluated against the current values whatever their age, so which
    /// entities come back, or in what order, would disclose a value outside the window that the
    /// answer itself withholds.
    #[error("a current-state read under a values-in-window time restriction may not filter or order on attribute values with q, a geospatial query or orderBy")]
    CurrentStateFilter,

    /// A temporal read asked for Linked Entity Retrieval (NGSI-LD 4.5.23).
    ///
    /// The window narrows the instances of the queried entities, not those of the entities their
    /// Relationships point at, and nothing in a temporal join answer is narrowed to the window on
    /// the way back. Refused rather than let a linked entity's history outside the window through.
    #[error("linked entity retrieval on a temporal endpoint is not allowed for a time-restricted caller")]
    TemporalJoin,

    /// The linked-entity rule could not be applied to the request.
    #[error(transparent)]
    LinkedEntity(#[from] LinkedEntityError),

    /// `timerel` was not one of the three the specification defines.
    #[error("'{relation}' is not a temporal relation; expected 'before', 'after' or 'between'")]
    UnknownRelation {
        /// The relation, as the caller wrote it.
        relation: String,
    },

    /// A bound was present but is not a timestamp.
    #[error("'{parameter}' is not an RFC 3339 timestamp: '{value}'")]
    MalformedInstant {
        /// Which bound.
        parameter: &'static str,
        /// The value, as the caller wrote it.
        value: String,
    },

    /// A bound the relation requires was not supplied.
    #[error("'{parameter}' is required when timerel is '{relation}'")]
    MissingBound {
        /// The bound that is missing.
        parameter: &'static str,
        /// The relation that requires it.
        relation: TimeRelation,
    },

    /// The requested window ends before it begins.
    #[error("the requested time window ends before it begins")]
    BackwardsWindow,

    /// The query string could not be read.
    #[error("the query string could not be read: {reason}")]
    MalformedQuery {
        /// What the parser said.
        reason: String,
    },

    /// The body of a temporal batch query is not a document this layer can narrow.
    #[error("the request body is not a temporal query document: {reason}")]
    MalformedBody {
        /// Why it could not be read.
        reason: &'static str,
    },

    /// The request reached this layer without its operation classified above.
    #[error(transparent)]
    Unclassified(#[from] Unclassified),

    /// The request reached this layer without its query parsed above.
    #[error(transparent)]
    Unparsed(#[from] Unparsed),

    /// The narrowed request could not be put back together.
    ///
    /// Libra's own failure, not the caller's. A variant rather than an `unwrap` on the reparsed URI,
    /// which would turn a rebuilding bug into a panic on the request path.
    #[error("the narrowed request could not be rebuilt")]
    Unrewritable,

    /// A current-state answer could not be held to the window, so it is withheld rather than
    /// forwarded.
    #[error("the upstream response could not be held to the allowed time window: {reason}")]
    Unfilterable {
        /// Why the response could not be filtered.
        reason: &'static str,
    },

    /// The request's body could not be read from the extensions.
    ///
    /// [`DocumentError::Unread`] is a wiring error: a body this layer has to judge or narrow is never
    /// read here, so without the context layer's one parse the request cannot be judged, and is
    /// refused rather than forwarded unjudged. [`DocumentError::NotJson`] is a body that is not a
    /// JSON document.
    #[error(transparent)]
    Body(#[from] DocumentError),

    /// The request reached this layer without its response representation resolved.
    ///
    /// A wiring error rather than anything about the request: the representation layer runs above
    /// authorization, and judging an answer without knowing its shape is guessing.
    #[error("the response representation was not resolved before time enforcement")]
    Unresolved,
}

impl TimeError {
    /// The response a caller sees.
    #[must_use]
    pub fn to_problem(&self) -> Problem {
        match self {
            Self::OutsideWindow
            | Self::Unenforceable
            | Self::CurrentStateRefused
            | Self::CurrentStateUnjudgeable { .. }
            | Self::CurrentStateFilter
            | Self::TemporalJoin
            | Self::TimePropertyRefused { .. }
            | Self::NoWholePeriod
            | Self::SubscriptionsRefused
            | Self::LinkedEntity(LinkedEntityError::Refused(_)) => Problem::Forbidden(self.to_string()),
            Self::UnknownRelation { .. }
            | Self::MalformedInstant { .. }
            | Self::MissingBound { .. }
            | Self::BackwardsWindow
            | Self::MalformedQuery { .. }
            | Self::MalformedBody { .. }
            | Self::Body(DocumentError::NotJson) => Problem::BadRequest(self.to_string()),
            Self::Unfilterable { .. } => Problem::BadGateway(self.to_string()),
            Self::Unrewritable
            | Self::Body(DocumentError::Unread)
            | Self::Unclassified(_)
            | Self::Unparsed(_)
            | Self::Unresolved
            | Self::Undecided
            | Self::LinkedEntity(LinkedEntityError::Unresolved) => Problem::Internal(self.to_string()),
        }
    }
}
