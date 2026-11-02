//! Why a temporal read did not meet the aggregation its policy requires.

use libra_json_body::error::DocumentError;
use libra_ngsi_ld_operation_layer::classified::Unclassified;
use libra_ngsi_ld_query::{aggregation::AggregationMethod, error::QueryError};
use libra_ngsi_ld_query_layer::parsed::Unparsed;
use libra_policy_model::duration::IsoDuration;
use libra_problem_details::problem::Problem;
use thiserror::Error;

/// Aggregation enforcement refused, or could not read, a request.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AggregationError {
    /// The policy disallows unaggregated reads and the read does not ask for `aggregatedValues`.
    ///
    /// NGSI-LD clause 6.18.3.2: `aggrMethods` applies only when `aggregatedValues` is in `format`
    /// or `options`, so methods named without it are ignored and every instance comes back.
    #[error("this policy allows temporal reads only as aggregatedValues; name it in format or options, with aggrMethods")]
    UnaggregatedDisallowed,

    /// The caller named a method the policy does not list.
    #[error("aggregation method '{method}' is not allowed by policy")]
    MethodDisallowed {
        /// The method that was refused.
        method: AggregationMethod,
    },

    /// An aggregated read named no method (NGSI-LD clause 5.2.44 gives `aggrMethods` cardinality 1).
    #[error("an aggregatedValues read has to name its aggrMethods")]
    MethodsMissing,

    /// The policy sets a minimum period and the caller named none.
    #[error("aggrPeriodDuration is required by policy and must be at least '{minimum}'")]
    PeriodMissing {
        /// The policy minimum, as the policy wrote it.
        minimum: IsoDuration,
    },

    /// The caller's period is finer than the policy's minimum.
    #[error("aggrPeriodDuration is finer than the minimum of '{minimum}' this policy requires")]
    PeriodTooShort {
        /// The policy minimum, as the policy wrote it.
        minimum: IsoDuration,
    },

    /// The caller's period is not a whole number of the policy's minimum periods, so its buckets
    /// would end between the grid points every boundary has to sit on.
    #[error("aggrPeriodDuration has to be a whole multiple of the minimum of '{minimum}' this policy requires")]
    PeriodOffGrid {
        /// The policy minimum, as the policy wrote it.
        minimum: IsoDuration,
    },

    /// A boundary of the aggregated window is not a whole multiple of the minimum period since the
    /// Unix epoch, in UTC.
    #[error("timeAt and endTimeAt have to sit on the UTC grid of the minimum period of '{minimum}' counted from the Unix epoch")]
    WindowOffGrid {
        /// The policy minimum, as the policy wrote it.
        minimum: IsoDuration,
    },

    /// The aggregated window spans less than one minimum period.
    #[error("the aggregated time window has to span at least the minimum period of '{minimum}' this policy requires")]
    WindowTooShort {
        /// The policy minimum, as the policy wrote it.
        minimum: IsoDuration,
    },

    /// An aggregated read under a minimum period leaves an end of its window open, and nothing below
    /// closes it on the grid.
    ///
    /// An open end moves with the moment of the request, so two reads made at different moments
    /// hold buckets that partially overlap.
    #[error("an aggregated read under a minimum period has to name a between window with timeAt and endTimeAt on the grid")]
    OpenWindow,

    /// The window of an aggregated read could not be read.
    #[error("the time window of the aggregated read could not be read: {reason}")]
    MalformedWindow {
        /// Why it could not be read.
        reason: &'static str,
    },

    /// The request reads, changes or deletes subscriptions that already exist.
    ///
    /// A subscription's notifications reach their endpoint without passing through Libra, and the
    /// broker answers a listing with every subscription of the tenant, so no aggregation can be
    /// held to what they disclose.
    #[error("existing subscriptions may not be read, changed or deleted under an aggregation restriction")]
    SubscriptionsRefused,

    /// The request reached this layer without a decision.
    ///
    /// A wiring fault: authorization runs above every enforcement layer and attaches a decision to
    /// every request it lets through, so a request without one is one nothing authorized.
    #[error("the request reached aggregation enforcement without an authorization decision")]
    Undecided,

    /// The caller's period is written in years or months, which have no fixed length.
    #[error("aggrPeriodDuration '{period}' uses years or months, which cannot be compared with the policy minimum; use weeks, days, hours, minutes or seconds")]
    IncomparablePeriod {
        /// The period, in ISO 8601.
        period: String,
    },

    /// The resource returns entity data the policy says must be aggregated first.
    #[error("this resource returns unaggregated entity data, which this policy does not allow")]
    RawValues,

    /// An aggregation parameter, or the query string it sits in, could not be read.
    #[error("an aggregation parameter could not be read: {0}")]
    UnreadableParameter(#[from] QueryError),

    /// The body of a temporal batch query is not a document this layer can check.
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

    /// The request's `format` and `options` do not settle whether the answer is aggregated.
    #[error("the requested representation could not be resolved, so whether the answer is aggregated cannot be told")]
    UnresolvableRepresentation,

    /// The request's body could not be read from the extensions.
    ///
    /// [`DocumentError::Unread`] is a wiring error: a temporal batch query's aggregation is in its
    /// body, and a body nothing read is one nothing checked, so the request is refused rather than
    /// forwarded. [`DocumentError::NotJson`] is a body that is not a JSON document.
    #[error(transparent)]
    Body(#[from] DocumentError),

    /// The request reached this layer without its response representation resolved.
    ///
    /// A wiring error rather than anything about the request: the representation layer runs above
    /// authorization, and judging whether an answer aggregates without knowing its shape is
    /// guessing.
    #[error("the response representation was not resolved before aggregation enforcement")]
    Unresolved,

    /// The rewritten request could not be put back together.
    #[error("the rewritten request could not be rebuilt")]
    Unrewritable,
}

impl AggregationError {
    /// The response a caller sees.
    #[must_use]
    pub fn to_problem(&self) -> Problem {
        match self {
            Self::UnaggregatedDisallowed
            | Self::MethodDisallowed { .. }
            | Self::PeriodMissing { .. }
            | Self::PeriodTooShort { .. }
            | Self::PeriodOffGrid { .. }
            | Self::WindowOffGrid { .. }
            | Self::WindowTooShort { .. }
            | Self::OpenWindow
            | Self::SubscriptionsRefused
            | Self::RawValues => Problem::Forbidden(self.to_string()),
            Self::MethodsMissing
            | Self::IncomparablePeriod { .. }
            | Self::UnreadableParameter(_)
            | Self::MalformedBody { .. }
            | Self::Body(DocumentError::NotJson)
            | Self::MalformedWindow { .. }
            | Self::UnresolvableRepresentation => Problem::BadRequest(self.to_string()),
            Self::Body(DocumentError::Unread) | Self::Unclassified(_) | Self::Unparsed(_) | Self::Unresolved | Self::Unrewritable | Self::Undecided => {
                Problem::Internal(self.to_string())
            }
        }
    }
}
