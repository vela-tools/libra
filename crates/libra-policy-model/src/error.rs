//! Why a policy could not be read, or could not be compiled against a context.
//!
//! Both kinds are load-time failures. A policy that cannot be turned into IRIs is not a policy
//! that matches nothing: it is a policy whose author believed it was in force. Refusing to start
//! is the only outcome that does not quietly widen access.

use crate::policy::PolicyId;
use libra_jsonld_term_expansion::name::Term;
use libra_ngsi_ld_query::error::QueryError;
use thiserror::Error;

/// A policy could not be compiled.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CompileError {
    /// A term in the policy has no meaning under the policy's declared context.
    #[error("policy '{policy}': term '{term}' in {field} cannot be expanded under the declared context")]
    UnexpandableTerm {
        /// The policy that named it.
        policy: PolicyId,
        /// Which part of the policy the term came from.
        field: &'static str,
        /// The term as authored.
        term: Term,
    },

    /// A restriction's allow list is empty.
    ///
    /// Refused by the deserializer too, but the model's fields are public and serde is not the only
    /// way one of these is built. An empty list reaching enforcement is a restriction that allows
    /// nothing while reading as one that allows something.
    #[error("policy '{policy}': {field} has an empty allow list")]
    EmptyRestriction {
        /// The policy that carries it.
        policy: PolicyId,
        /// Which restriction.
        field: &'static str,
    },

    /// A policy carries a restriction but names only resources no restriction is enforced on.
    ///
    /// The restriction would never narrow anything, so the policy would read as restricted while
    /// allowing what it names in full.
    #[error(
        "policy '{policy}': it carries a restriction but names no resource a restriction applies to (entities, temporal, discovery, subscriptions or registrations)"
    )]
    RestrictionNeverApplies {
        /// The policy.
        policy: PolicyId,
    },

    /// A policy carries a restriction and names `snapshots`.
    ///
    /// A snapshot copies the broker's entities, and nothing narrows what is read from the copy.
    #[error("policy '{policy}': it carries a restriction and names snapshots, which copy entity data no restriction narrows")]
    RestrictedSnapshots {
        /// The policy.
        policy: PolicyId,
    },

    /// A deny names `queries`.
    ///
    /// A query condition matches the canonical query exactly, so a caller adds any parameter to step
    /// around the deny.
    #[error("policy '{policy}': a deny cannot be conditioned on queries, which a caller steps around by adding a parameter")]
    DenyByQuery {
        /// The policy.
        policy: PolicyId,
    },

    /// A deny carries a restriction.
    ///
    /// A deny refuses everything its condition matches; a restriction on it would read as a partial
    /// deny that no layer enforces.
    #[error("policy '{policy}': a deny refuses everything it matches and cannot carry a restriction")]
    RestrictedDeny {
        /// The policy.
        policy: PolicyId,
    },

    /// A `q` selector in a condition could not be parsed or expanded.
    #[error("policy '{policy}': {source}")]
    Query {
        /// The policy that named it.
        policy: PolicyId,
        /// What the query model reported.
        #[source]
        source: QueryError,
    },
}

/// A value in a policy file is not a legal value of its type.
///
/// Reported through serde, so it arrives with the file and line already attached.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ValueError {
    /// A policy identifier is empty, too long, or contains something that cannot appear in a URL.
    ///
    /// The management API addresses policies by identifier in a path segment, so an identifier
    /// that needs escaping is one that can be addressed two ways.
    #[error("'{value}' is not a valid policy id: {reason}")]
    PolicyId {
        /// What was written.
        value: String,
        /// Why it was refused.
        reason: &'static str,
    },

    /// A tenant name is empty, too long, or contains a character Libra will not carry.
    #[error("'{value}' is not a valid tenant: {reason}")]
    Tenant {
        /// What was written.
        value: String,
        /// Why it was refused.
        reason: &'static str,
    },

    /// A scope pattern does not fit the NGSI-LD scope grammar.
    ///
    /// The value is written escaped, so a control character in it reaches no log or response raw.
    #[error("{value:?} is not a valid scope pattern: {reason}")]
    ScopePattern {
        /// What was written.
        value: String,
        /// Why it was refused.
        reason: &'static str,
    },

    /// A duration is not an ISO 8601 duration Libra can compare.
    #[error("'{value}' is not a usable ISO 8601 duration: {reason}")]
    Duration {
        /// What was written.
        value: String,
        /// Why it was refused.
        reason: &'static str,
    },

    /// A restriction's allow list is empty.
    ///
    /// An empty allow list reads as "allow nothing", but the enforcement it produces is an empty
    /// filter, which most brokers read as "no filter at all". Refusing it at load removes the gap
    /// between what the policy says and what the broker does; a policy that allows nothing is
    /// written as a deny.
    #[error("{restriction} has an empty allow list; write a deny instead")]
    EmptyAllowList {
        /// Which restriction.
        restriction: &'static str,
    },
}

/// An identity name was refused.
///
/// The name itself is not carried. An identity name also arrives in a token, where the identity
/// provider chose it, and an error that repeated it would carry a control character or a forged
/// field into the log line the check exists to protect. A name in a policy file is located by the
/// file parser's position instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("not a valid {kind}: {reason}")]
pub struct IdentityError {
    /// Which kind of name: `group`, `role`, `subject` and so on.
    pub kind: &'static str,
    /// Why it was refused.
    pub reason: &'static str,
}
