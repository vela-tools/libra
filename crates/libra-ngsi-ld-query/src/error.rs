//! Why a query string could not be understood.
//!
//! Every variant is a refusal. A query Libra cannot parse is a query whose filters it cannot see,
//! and a filter it cannot see is one it cannot check a policy against, while the broker behind it
//! will happily apply the filter anyway.

use crate::parameter_name::ParameterName;
use libra_jsonld_term_expansion::name::Term;
use thiserror::Error;

/// A query string could not be turned into a query.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum QueryError {
    /// A parameter appeared more than once.
    ///
    /// NGSI-LD defines each parameter as occurring at most once, and implementations disagree
    /// about which copy wins: first, last, or a concatenation. A duplicate is therefore a way to
    /// show the proxy one filter and the broker another.
    #[error("query parameter '{name}' appears more than once")]
    DuplicateParameter {
        /// The repeated parameter.
        name: ParameterName,
    },

    /// A parameter is written in another case than one Libra reads, or two parameters differ only
    /// in case.
    ///
    /// Libra compares names exactly; a broker that compares them case-insensitively would read
    /// `Q=` as the `q` filter Libra never checked.
    #[error("query parameter '{name}' differs only in case from '{other}'")]
    CaseVariantParameter {
        /// The parameter as written.
        name: ParameterName,
        /// The parameter it would be confused with.
        other: ParameterName,
    },

    /// A parameter or value is not valid UTF-8 once decoded.
    #[error("query parameter '{name}' is not valid UTF-8 when decoded")]
    UndecodableParameter {
        /// The offending parameter, still percent-encoded, because it may be the name that did not
        /// decode.
        name: String,
    },

    /// A `q` or `scopeQ` expression is malformed.
    #[error("malformed {parameter} expression at offset {offset}: {reason}")]
    MalformedFilter {
        /// Which parameter the expression came from.
        parameter: ParameterName,
        /// Byte offset the parser gave up at.
        offset: usize,
        /// What went wrong.
        reason: String,
    },

    /// A `type` selection expression is malformed or too large to read safely.
    #[error("malformed type selection at offset {offset}: {reason}")]
    MalformedTypeSelection {
        /// Byte offset the parser gave up at.
        offset: usize,
        /// What went wrong.
        reason: String,
    },

    /// A projection (`attrs`, `pick`, `omit`) does not fit the attribute projection language of
    /// NGSI-LD clause 4.21.
    #[error("malformed attribute projection at offset {offset}: {reason}")]
    MalformedProjection {
        /// Byte offset the parser gave up at.
        offset: usize,
        /// What went wrong.
        reason: String,
    },

    /// An `orderBy` does not fit the Entity Ordering Language of NGSI-LD clause 4.23.3.
    #[error("malformed entity ordering at offset {offset}: {reason}")]
    MalformedOrdering {
        /// Byte offset of the ordering term the parser gave up at.
        offset: usize,
        /// What went wrong.
        reason: &'static str,
    },

    /// A selector holds a control character, which no NGSI-LD name, IRI or quoted value admits.
    ///
    /// The selector is not repeated: the character is what the refusal exists to keep out of the
    /// log.
    #[error("a selector holds a control character at offset {offset}")]
    ControlCharacter {
        /// Byte offset of the first control character.
        offset: usize,
    },

    /// A parameter that must be a number is not one.
    #[error("query parameter '{name}' expects a number, got '{value}'")]
    NotANumber {
        /// The offending parameter.
        name: ParameterName,
        /// What arrived instead.
        value: String,
    },

    /// A parameter with a fixed set of legal values carried something else.
    #[error("query parameter '{name}' does not accept '{value}'")]
    UnknownValue {
        /// The offending parameter.
        name: ParameterName,
        /// What arrived instead.
        value: String,
    },

    /// A term in the query has no meaning under the request's context.
    ///
    /// Not "matches nothing": a name whose meaning is unknown cannot be compared with a policy's
    /// name, so the request has to fail rather than be evaluated against a guess.
    #[error("term '{term}' in query parameter '{parameter}' cannot be expanded under the request context")]
    UnexpandableTerm {
        /// Which parameter the term came from.
        parameter: ParameterName,
        /// The term as authored.
        term: Term,
    },

    /// A member of a `Query` body that has to be a string is something else.
    #[error("member '{member}' is not a string")]
    NotAString {
        /// The member name.
        member: ParameterName,
    },

    /// A member of a `Query` body or a subscription that carries selectors occurs more than once.
    ///
    /// RFC 8259 section 4 leaves the meaning of a repeated member name unpredictable, so the
    /// occurrence Libra read need not be the one the broker acts on.
    #[error("member '{member}' appears more than once")]
    RepeatedMember {
        /// The repeated member name.
        member: String,
    },
}
