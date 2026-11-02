//! Why a response representation could not be decided.
//!
//! Every variant is a refusal. Deciding a representation is deciding what a response contains, so
//! a request that names two of them has to be answered with an error rather than with whichever
//! one this crate happened to check first: the broker behind Libra resolves the same ambiguity on
//! its own terms, and any layer that rewrites a body would then be editing a shape nobody agreed
//! on.

use crate::representation::{Representation, TemporalRepresentation};
use thiserror::Error;

/// A representation could not be decided from the request.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RepresentationError {
    /// The `options` parameter named two different representations.
    ///
    /// `options=keyValues,concise` is the case that matters. Brokers do not agree on it: some
    /// take the first token, some the last, so the response shape depends on which broker is
    /// behind the proxy. Refusing keeps Libra and the broker describing the same response.
    #[error("the options parameter asks for both '{first}' and '{second}'")]
    ContradictoryOptions {
        /// The representation named first.
        first: Representation,
        /// The representation named second, which disagrees with it.
        second: Representation,
    },

    /// The `options` parameter named both temporal formats.
    ///
    /// NGSI-LD clause 6.3.12 allows only one of `temporalValues` and `aggregatedValues` in `options`.
    #[error("the options parameter asks for both '{first}' and '{second}'")]
    ContradictoryTemporalOptions {
        /// The temporal representation named first.
        first: TemporalRepresentation,
        /// The temporal representation named second, which disagrees with it.
        second: TemporalRepresentation,
    },

    /// The `options` and `format` parameters named different representations.
    ///
    /// NGSI-LD 1.8 added `format` as a replacement for the representation tokens in `options`. A
    /// request carrying both, disagreeing, has the same problem as the case above.
    #[error("the options parameter asks for '{options}' while the format parameter asks for '{format}'")]
    ContradictoryFormat {
        /// What `options` asked for.
        options: Representation,
        /// What `format` asked for.
        format: Representation,
    },

    /// An option differs from a known one only in case.
    ///
    /// The tokens are fixed strings in ETSI GS CIM 009 and brokers compare them exactly, so
    /// `keyvalues` is not `keyValues` to them. Ignoring it here would leave Libra describing a
    /// normalized response while the broker was asked for a simplified one, a difference no
    /// reader of the two would notice until a body rewrite produced nonsense.
    #[error("option '{option}' is not spelled the way NGSI-LD spells it")]
    MisspelledOption {
        /// The option as it arrived.
        option: String,
    },

    /// The `format` parameter carried something that is not a representation.
    #[error("the format parameter does not accept '{format}'")]
    UnknownFormat {
        /// The value as it arrived.
        format: String,
    },

    /// Nothing in the `Accept` header is a media type Libra can produce.
    ///
    /// Answered as 406 rather than served as JSON anyway: a client that asked only for a type the
    /// proxy cannot produce is better told so than handed a body it will not parse.
    #[error("no media type in '{accept}' can be produced")]
    NotAcceptable {
        /// The header as it arrived.
        accept: String,
    },
}
